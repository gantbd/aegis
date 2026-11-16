#![cfg(unix)]

use aegis_authority::{
    ActionSetV1 as CoreActions, ActionV1 as CoreAction, AuthorityEpoch, AuthorizationRequestV1,
    Engine, EngineId, EngineNamespaceV1 as CoreNamespace, GrantDescriptorV1, Limits, LogicalTime,
    PrincipalId, ResourceId, ResourceScopeV1, SessionId,
};
use aegis_client::{Client as AegisClient, ServicePort};
use aegis_host::DurableAuthority;
use aegis_local_daemon::unix::{Authenticator, Daemon, connect};
use aegis_protocol::{
    ActionV1, CommandV1, EngineNamespaceV1, GrantHandleV1, OutcomeV1, RefusalV1, ReplyV1, ScopeV1,
};
use aegis_service::{AuthenticatedSessionV1, Service, ServiceLimitsV1};
use aegis_wire::{LimitsV1, RequestFrameV1, decode_reply, decode_session_opened, encode_request};
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::{
    convert::Infallible,
    fs,
    io::{ErrorKind, Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

#[derive(Default)]
struct Store(Option<Checkpoint>);
impl CheckpointStore for Store {
    type Error = Infallible;
    fn load(&self, _: &str) -> Result<Option<Checkpoint>, Self::Error> {
        Ok(self.0.clone())
    }
    fn compare_exchange(
        &mut self,
        _: &str,
        expected: Option<Revision>,
        bytes: &[u8],
    ) -> Result<CommitOutcome, Self::Error> {
        let actual = self.0.as_ref().map(|checkpoint| checkpoint.revision);
        if actual != expected {
            return Ok(CommitOutcome::Refused(StoreRefusal::RevisionConflict {
                expected,
                actual,
            }));
        }
        let revision = Revision(actual.map_or(0, |revision| revision.0 + 1));
        self.0 = Some(Checkpoint {
            revision,
            bytes: bytes.to_vec(),
            strength: AcknowledgementStrength::Durable,
        });
        Ok(CommitOutcome::Committed(CommitReceipt {
            revision,
            mechanism: "listener-test",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

struct Authentication;
impl Authenticator for Authentication {
    type Error = Infallible;
    fn authenticate(&mut self, _: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error> {
        Ok(AuthenticatedSessionV1 {
            principal: PrincipalId::new([2; 16]),
            session: SessionId::new([3; 16]),
            administrator: true,
        })
    }
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

fn socket_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "aegis-daemon-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn write_request(
    stream: &mut UnixStream,
    session: aegis_protocol::SessionHandleV1,
    command: CommandV1,
) {
    let bytes = encode_request(&RequestFrameV1 { session, command }, LimitsV1::default()).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
}

struct SocketPort(UnixStream);

impl ServicePort for SocketPort {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        session: aegis_protocol::SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        let bytes = encode_request(&RequestFrameV1 { session, command }, LimitsV1::default())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "request frame"))?;
        self.0.write_all(&(bytes.len() as u32).to_be_bytes())?;
        self.0.write_all(&bytes)?;
        decode_reply(&read_frame(&mut self.0), LimitsV1::default())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "reply frame"))
    }
}

fn connect_when_ready(path: &Path, child: &mut std::process::Child) -> UnixStream {
    let mut last_error = None;
    for _ in 0..1000 {
        match UnixStream::connect(path) {
            Ok(stream) => return stream,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) =>
            {
                last_error = Some(error);
            }
            Err(error) => panic!("daemon socket connection failed: {error}"),
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            if let Some(pipe) = child.stderr.as_mut() {
                pipe.read_to_string(&mut stderr).unwrap();
            }
            panic!("daemon exited before its socket was ready ({status}): {stderr}");
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("daemon socket was not ready: {last_error:?}");
}

fn spawn_daemon(mode: &str, store: &Path, socket: &Path) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .arg("process_daemon_helper")
        .arg("--exact")
        .arg("--nocapture")
        .env("AEGIS_DAEMON_HELPER", "1")
        .env("AEGIS_DAEMON_MODE", mode)
        .env("AEGIS_DAEMON_STORE", store)
        .env("AEGIS_DAEMON_SOCKET", socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn process_daemon_helper() {
    if std::env::var_os("AEGIS_DAEMON_HELPER").is_none() {
        return;
    }
    let store = PathBuf::from(std::env::var_os("AEGIS_DAEMON_STORE").unwrap());
    let socket = PathBuf::from(std::env::var_os("AEGIS_DAEMON_SOCKET").unwrap());
    let authority_id = EngineId::new([1; 16]);
    let authority = match std::env::var("AEGIS_DAEMON_MODE").unwrap().as_str() {
        "create" => aegis_local::create_new(&store, authority_id, Limits::default()).unwrap(),
        "open" => aegis_local::open_existing(&store, authority_id, Limits::default()).unwrap(),
        mode => panic!("unknown daemon helper mode {mode}"),
    };
    let service = Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap();
    let mut daemon = Daemon::bind_new(
        socket,
        service,
        Authentication,
        LimitsV1::default(),
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    let _ = daemon.serve_next();
}

#[test]
fn real_private_socket_runs_handshake_request_reply_and_teardown() {
    let authority_id = EngineId::new([1; 16]);
    let principal = PrincipalId::new([2; 16]);
    let session_id = SessionId::new([3; 16]);
    let mut embedded = Engine::try_new(authority_id, Limits::default()).unwrap();
    let embedded_grant = embedded
        .issue(
            GrantDescriptorV1::new(
                principal,
                Some(session_id),
                authority_id,
                AuthorityEpoch(0),
                LogicalTime(10),
                vec![ResourceScopeV1::new(
                    CoreNamespace::Hermes,
                    ResourceId::new([7; 16]),
                    CoreActions::singleton(CoreAction::Observe),
                )],
            ),
            LogicalTime(1),
        )
        .unwrap();
    let embedded_decision = embedded
        .validate(
            &embedded_grant,
            &AuthorizationRequestV1::new(
                principal,
                Some(session_id),
                CoreNamespace::Hermes,
                ResourceId::new([7; 16]),
                CoreAction::Observe,
            ),
            LogicalTime(2),
        )
        .unwrap();
    let authority =
        DurableAuthority::create_new(Store::default(), authority_id, Limits::default()).unwrap();
    let service = Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap();
    let path = socket_path();
    let mut daemon = Daemon::bind_new(
        &path,
        service,
        Authentication,
        LimitsV1::default(),
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let client_path = path.clone();
    let client = thread::spawn(move || {
        let (session, port) =
            connect(client_path, LimitsV1::default(), Duration::from_secs(2)).unwrap();
        let mut client = AegisClient::new(session, port);
        let ReplyV1::Accepted(OutcomeV1::GrantIssued(grant)) = client
            .execute(CommandV1::Issue {
                expected_epoch: 0,
                now: 1,
                expires_at: 10,
                scopes: vec![ScopeV1 {
                    engine: EngineNamespaceV1::Hermes,
                    resource: [7; 16],
                    actions: 1 << ActionV1::Observe as u8,
                }],
            })
            .unwrap()
        else {
            panic!("grant response expected");
        };
        let reply = client
            .execute(CommandV1::Authorize {
                grant: grant.handle,
                now: 2,
                engine: EngineNamespaceV1::Hermes,
                resource: [7; 16],
                action: ActionV1::Observe,
            })
            .unwrap();
        drop(client);
        (grant, reply)
    });
    daemon.serve_next().unwrap();
    assert!(matches!(
        client.join().unwrap(),
        (grant, ReplyV1::Accepted(OutcomeV1::Authorized(decision)))
            if grant.epoch == 0 && grant.expires_at == 10
                && decision.epoch == embedded.epoch().0
                && decision.expires_at == embedded_decision.expires_at().0
    ));
    let health = daemon.health();
    assert!(health.ready);
    assert_eq!(health.active_connections, 0);
    assert_eq!(health.accepted_connections, 1);
    drop(daemon);
    assert!(!path.exists());
}

fn run_subprocess_revocation_cycle() {
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "aegis-daemon-process-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let store = root.join("authority");
    let socket = root.join("daemon.sock");

    let mut first = spawn_daemon("create", &store, &socket);
    let mut stream = connect_when_ready(&socket, &mut first);
    let session = decode_session_opened(&read_frame(&mut stream), LimitsV1::default()).unwrap();
    let mut client = AegisClient::new(session, SocketPort(stream));
    let ReplyV1::Accepted(OutcomeV1::GrantIssued(grant)) = client
        .execute(CommandV1::Issue {
            expected_epoch: 0,
            now: 1,
            expires_at: 20,
            scopes: vec![ScopeV1 {
                engine: EngineNamespaceV1::Moira,
                resource: [0x41; 16],
                actions: 1 << ActionV1::Administer as u8,
            }],
        })
        .unwrap()
    else {
        panic!("initial grant expected")
    };
    assert!(matches!(
        client
            .execute(CommandV1::Authorize {
                grant: grant.handle,
                now: 2,
                engine: EngineNamespaceV1::Moira,
                resource: [0x41; 16],
                action: ActionV1::Administer,
            },)
            .unwrap(),
        ReplyV1::Accepted(OutcomeV1::Authorized(_))
    ));
    let mut port = client.into_port();
    write_request(
        &mut port.0,
        session,
        CommandV1::RevokeEpoch { expected_epoch: 0 },
    );
    // Deliberately discard the reply. The caller has outcome-unknown evidence;
    // it must reconcile after restart instead of replaying revocation blindly.
    drop(port);
    let first_output = first.wait_with_output().unwrap();
    assert!(
        first_output.status.success(),
        "first daemon failed: {}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    assert!(!socket.exists());

    let mut second = spawn_daemon("open", &store, &socket);
    let mut stream = connect_when_ready(&socket, &mut second);
    let recovered_session =
        decode_session_opened(&read_frame(&mut stream), LimitsV1::default()).unwrap();
    let mut client = AegisClient::new(recovered_session, SocketPort(stream));
    assert!(matches!(
        client.execute(CommandV1::Status).unwrap(),
        ReplyV1::Accepted(OutcomeV1::Status(status))
            if status.epoch == 2
                && status.active_grants == 0
                && status.retained_decisions == 0
    ));
    assert_eq!(
        client
            .execute(CommandV1::Authorize {
                grant: GrantHandleV1(grant.handle.0),
                now: 3,
                engine: EngineNamespaceV1::Moira,
                resource: [0x41; 16],
                action: ActionV1::Administer,
            },)
            .unwrap(),
        ReplyV1::Refused(RefusalV1::UnknownGrant)
    );
    let ReplyV1::Accepted(OutcomeV1::GrantIssued(fresh)) = client
        .execute(CommandV1::Issue {
            expected_epoch: 2,
            now: 3,
            expires_at: 30,
            scopes: vec![ScopeV1 {
                engine: EngineNamespaceV1::Moira,
                resource: [0x41; 16],
                actions: 1 << ActionV1::Administer as u8,
            }],
        })
        .unwrap()
    else {
        panic!("fresh post-recovery grant expected")
    };
    assert!(matches!(
        client.execute(
            CommandV1::Authorize {
                grant: fresh.handle,
                now: 4,
                engine: EngineNamespaceV1::Moira,
                resource: [0x41; 16],
                action: ActionV1::Administer,
            },
        ).unwrap(),
        ReplyV1::Accepted(OutcomeV1::Authorized(decision)) if decision.epoch == 2
    ));
    drop(client);
    let second_output = second.wait_with_output().unwrap();
    assert!(
        second_output.status.success(),
        "second daemon failed: {}",
        String::from_utf8_lossy(&second_output.stderr)
    );
    assert!(!socket.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn subprocess_revocation_lost_reply_and_recovery_reject_old_handles() {
    run_subprocess_revocation_cycle();
}

#[test]
#[ignore = "opt-in durable 32-cycle two-process authority soak"]
fn thirty_two_process_recovery_cycles_preserve_epoch_fencing() {
    for cycle in 0..32 {
        run_subprocess_revocation_cycle();
        eprintln!("completed_cycle={cycle}");
    }
}
