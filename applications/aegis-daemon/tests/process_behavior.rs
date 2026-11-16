#![cfg(unix)]

use aegis_client::Client;
use aegis_local_daemon::unix::connect;
use aegis_protocol::{CommandV1, OutcomeV1, RefusalV1, ReplyV1};
use aegis_wire::LimitsV1;
use nix::{
    sys::signal::{Signal, kill},
    unistd::{Pid, getegid, geteuid},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

fn unique(kind: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "aegis-application-{kind}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn spawn(mode: &str, directory: &Path, socket: &Path, role: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_aegis-daemon"))
        .args([
            mode,
            directory.to_str().unwrap(),
            socket.to_str().unwrap(),
            "01010101010101010101010101010101",
            &geteuid().as_raw().to_string(),
            &getegid().as_raw().to_string(),
            "02020202020202020202020202020202",
            "0303030303030303",
            role,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_for_socket(child: &mut Child, socket: &Path) {
    for _ in 0..400 {
        if socket.exists() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("Aegis daemon stopped before readiness: {status}");
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("Aegis daemon did not publish {}", socket.display());
}

fn stop(child: Child) {
    kill(
        Pid::from_raw(i32::try_from(child.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Aegis daemon shutdown failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn standalone_create_and_reopen_preserve_explicit_peer_role_and_clean_ownership() {
    let directory = unique("authority");
    let socket = unique("service.sock");
    let mut created = spawn("create", &directory, &socket, "principal");
    wait_for_socket(&mut created, &socket);
    let (session, port) = connect(&socket, LimitsV1::default(), Duration::from_secs(2)).unwrap();
    let mut client = Client::new(session, port);
    assert_eq!(
        client.execute(CommandV1::Status).unwrap(),
        ReplyV1::Refused(RefusalV1::NotAdministrator)
    );
    assert_eq!(
        client
            .execute(CommandV1::RevokeEpoch { expected_epoch: 0 })
            .unwrap(),
        ReplyV1::Refused(RefusalV1::NotAdministrator)
    );
    drop(client);
    stop(created);
    assert!(!socket.exists());

    let mut reopened = spawn("open", &directory, &socket, "administrator");
    wait_for_socket(&mut reopened, &socket);
    let (session, port) = connect(&socket, LimitsV1::default(), Duration::from_secs(2)).unwrap();
    let mut client = Client::new(session, port);
    assert!(matches!(
        client.execute(CommandV1::Status).unwrap(),
        ReplyV1::Accepted(OutcomeV1::Status(status)) if status.epoch == 1
    ));
    assert_eq!(
        client
            .execute(CommandV1::RevokeEpoch { expected_epoch: 1 })
            .unwrap(),
        ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 2 })
    );
    drop(client);
    stop(reopened);
    assert!(!socket.exists());
    fs::remove_dir_all(directory).unwrap();
}
