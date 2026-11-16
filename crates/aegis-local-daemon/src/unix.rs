//! Private Unix listener with explicit authentication and connection lifetime.

use crate::{ConnectionErrorV1, serve_up_to};
use aegis_host::HostError;
use aegis_protocol::{RefusalV1, SessionHandleV1};
use aegis_service::{AuthenticatedSessionV1, Service};
use aegis_wire::{LimitsV1, encode_session_opened};
use keystone_storage::CheckpointStore;
use keystone_unix_listener::OwnedUnixListener;
use std::{
    io::{self, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub trait Authenticator {
    type Error;
    fn authenticate(&mut self, stream: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error>;
}

pub use aegis_local_client::{ClientErrorV1, UnixPort, connect};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HealthV1 {
    pub ready: bool,
    pub active_connections: u64,
    pub accepted_connections: u64,
    pub refused_connections: u64,
    pub outcome_unknown: u64,
    pub saturated: bool,
}

#[derive(Debug)]
pub enum DaemonErrorV1<A, S> {
    Io(io::Error),
    Authentication(A),
    Session(RefusalV1),
    Connection(ConnectionErrorV1<HostError<S>>),
}

pub struct Daemon<S: CheckpointStore, A: Authenticator> {
    listener: OwnedUnixListener,
    service: Service<S>,
    authenticator: A,
    wire_limits: LimitsV1,
    io_timeout: Duration,
    max_requests_per_connection: usize,
    health: HealthV1,
}

impl<S: CheckpointStore, A: Authenticator> Daemon<S, A> {
    pub fn bind_new(
        socket_path: impl AsRef<Path>,
        service: Service<S>,
        authenticator: A,
        wire_limits: LimitsV1,
        io_timeout: Duration,
        max_requests_per_connection: usize,
    ) -> io::Result<Self> {
        if io_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero I/O timeout",
            ));
        }
        if max_requests_per_connection == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero request limit",
            ));
        }
        let listener = OwnedUnixListener::bind_new(socket_path)?;
        Ok(Self {
            listener,
            service,
            authenticator,
            wire_limits,
            io_timeout,
            max_requests_per_connection,
            health: HealthV1 {
                ready: true,
                ..HealthV1::default()
            },
        })
    }

    pub fn health(&self) -> HealthV1 {
        self.health
    }

    /// Accepts one authenticated connection, executes a bounded request
    /// sequence and closes the session regardless of reply success.
    pub fn serve_next(&mut self) -> Result<(), DaemonErrorV1<A::Error, S::Error>> {
        let (mut stream, _) = self.listener.accept().map_err(DaemonErrorV1::Io)?;
        self.serve_accepted(&mut stream)
    }

    /// Serves complete authenticated connections until a caller-owned stop
    /// flag is set. A shutdown requester wakes the blocking accept with a
    /// local connection after setting the flag; that wake connection is never
    /// authenticated or dispatched.
    pub fn serve_until(
        &mut self,
        stop: &AtomicBool,
    ) -> Result<(), DaemonErrorV1<A::Error, S::Error>> {
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            let (mut stream, _) = self.listener.accept().map_err(DaemonErrorV1::Io)?;
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            self.serve_accepted(&mut stream)?;
        }
    }

    fn serve_accepted(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<(), DaemonErrorV1<A::Error, S::Error>> {
        increment(
            &mut self.health.active_connections,
            &mut self.health.saturated,
        );
        let result = self.serve_stream(stream);
        self.health.active_connections = self.health.active_connections.saturating_sub(1);
        if result.is_err() {
            increment(
                &mut self.health.refused_connections,
                &mut self.health.saturated,
            );
        }
        if matches!(
            &result,
            Err(DaemonErrorV1::Connection(
                ConnectionErrorV1::OutcomeUnknown(_)
            ))
        ) {
            increment(&mut self.health.outcome_unknown, &mut self.health.saturated);
        }
        result
    }

    fn serve_stream(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<(), DaemonErrorV1<A::Error, S::Error>> {
        stream
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
            .map_err(DaemonErrorV1::Io)?;
        let facts = self
            .authenticator
            .authenticate(stream)
            .map_err(DaemonErrorV1::Authentication)?;
        let session = self
            .service
            .open_session(facts)
            .map_err(DaemonErrorV1::Session)?;
        let result = (|| {
            write_handshake(stream, session, self.wire_limits).map_err(DaemonErrorV1::Io)?;
            serve_up_to(
                stream,
                session,
                &mut self.service,
                self.wire_limits,
                self.max_requests_per_connection,
            )
            .map(|_| ())
            .map_err(DaemonErrorV1::Connection)
        })();
        self.service.close_session(session);
        if result.is_ok() {
            increment(
                &mut self.health.accepted_connections,
                &mut self.health.saturated,
            );
        }
        result
    }
}

fn write_handshake(
    stream: &mut UnixStream,
    session: SessionHandleV1,
    limits: LimitsV1,
) -> io::Result<()> {
    let bytes = encode_session_opened(session, limits)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "session frame"))?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "session frame length"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

fn increment(value: &mut u64, saturated: &mut bool) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *saturated = true;
    }
}
