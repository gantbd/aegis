#![cfg(unix)]

use aegis_authority::{EngineId, Limits, PrincipalId, SessionId};
use aegis_local_daemon::unix::{Authenticator, Daemon};
use aegis_service::{AuthenticatedSessionV1, Service, ServiceLimitsV1};
use aegis_wire::LimitsV1;
use std::{convert::Infallible, os::unix::net::UnixStream, path::PathBuf, time::Duration};

struct Authentication;

impl Authenticator for Authentication {
    type Error = Infallible;

    fn authenticate(&mut self, _: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error> {
        Ok(AuthenticatedSessionV1 {
            principal: PrincipalId::new([5; 16]),
            session: SessionId::new([3; 16]),
            administrator: true,
        })
    }
}

fn main() {
    let root = PathBuf::from(std::env::var_os("AEGIS_CHAIN_ROOT").expect("AEGIS_CHAIN_ROOT"));
    let connections = std::env::var("AEGIS_CHAIN_CONNECTIONS")
        .map_or(Ok(1), |value| value.parse::<usize>())
        .expect("AEGIS_CHAIN_CONNECTIONS must be a positive integer");
    assert!((1..=8).contains(&connections));
    let authority_id = EngineId::new([1; 16]);
    let authority =
        aegis_local::create_new(root.join("authority"), authority_id, Limits::default()).unwrap();
    let service = Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap();
    let mut daemon = Daemon::bind_new(
        root.join("aegis.sock"),
        service,
        Authentication,
        LimitsV1::default(),
        Duration::from_secs(5),
        8,
    )
    .unwrap();
    for _ in 0..connections {
        let _ = daemon.serve_next();
    }
}
