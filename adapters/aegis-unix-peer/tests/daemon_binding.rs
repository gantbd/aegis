#![cfg(unix)]

use aegis_authority::{EngineId, Limits, PrincipalId};
use aegis_client::AuthorityClient;
use aegis_host::DurableAuthority;
use aegis_local_daemon::unix::{Daemon, DaemonErrorV1, connect};
use aegis_protocol::{ActionV1, EngineNamespaceV1, OutcomeV1, ReplyV1, ScopeV1};
use aegis_service::{Service, ServiceLimitsV1};
use aegis_unix_peer::{AuthenticationErrorV1, MappingV1, UnixPeerAuthenticatorV1};
use aegis_wire::LimitsV1;
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::{
    convert::Infallible,
    fs,
    path::PathBuf,
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
        let revision = Revision(actual.map_or(0, |current| current.0 + 1));
        self.0 = Some(Checkpoint {
            revision,
            bytes: bytes.to_vec(),
            strength: AcknowledgementStrength::Durable,
        });
        Ok(CommitOutcome::Committed(CommitReceipt {
            revision,
            mechanism: "unix-peer-test",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

fn socket_path(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "aegis-peer-{label}-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn mapping(uid_offset: u32) -> MappingV1 {
    MappingV1 {
        effective_uid: nix::unistd::geteuid().as_raw().wrapping_add(uid_offset),
        effective_gid: nix::unistd::getegid().as_raw(),
        principal: PrincipalId::new([7; 16]),
        administrator: true,
    }
}

fn service() -> Service<Store> {
    let authority_id = EngineId::new([1; 16]);
    let authority =
        DurableAuthority::create_new(Store::default(), authority_id, Limits::default()).unwrap();
    Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap()
}

#[test]
fn daemon_accepts_the_mapped_kernel_peer_and_rejects_an_unknown_peer() {
    let path = socket_path("accepted");
    let authenticator = UnixPeerAuthenticatorV1::new(1, vec![mapping(0)], [3; 8]).unwrap();
    let mut daemon = Daemon::bind_new(
        &path,
        service(),
        authenticator,
        LimitsV1::default(),
        Duration::from_secs(2),
        2,
    )
    .unwrap();
    let client_path = path.clone();
    let client = thread::spawn(move || {
        let (session, port) =
            connect(client_path, LimitsV1::default(), Duration::from_secs(2)).unwrap();
        let mut authority = AuthorityClient::new(session, port);
        authority
            .issue(
                0,
                1,
                10,
                vec![ScopeV1 {
                    engine: EngineNamespaceV1::Hermes,
                    resource: [4; 16],
                    actions: 1 << ActionV1::Observe as u8,
                }],
            )
            .unwrap()
    });
    daemon.serve_next().unwrap();
    assert!(matches!(
        client.join().unwrap(),
        ReplyV1::Accepted(OutcomeV1::GrantIssued(_))
    ));
    drop(daemon);
    assert!(!path.exists());

    let path = socket_path("unknown");
    let authenticator = UnixPeerAuthenticatorV1::new(1, vec![mapping(1)], [3; 8]).unwrap();
    let mut daemon = Daemon::bind_new(
        &path,
        service(),
        authenticator,
        LimitsV1::default(),
        Duration::from_secs(2),
        1,
    )
    .unwrap();
    let client_path = path.clone();
    let client = thread::spawn(move || {
        connect(client_path, LimitsV1::default(), Duration::from_secs(2)).is_err()
    });
    assert!(matches!(
        daemon.serve_next(),
        Err(DaemonErrorV1::Authentication(
            AuthenticationErrorV1::UnknownPeer
        ))
    ));
    assert!(client.join().unwrap());
    drop(daemon);
    assert!(!path.exists());
    let _ = fs::remove_file(path);
}
