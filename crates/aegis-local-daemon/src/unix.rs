//! Private Unix listener with explicit authentication and connection lifetime.

use crate::{ConnectionErrorV1, serve_up_to};
use aegis_client::ServicePort as ClientServicePort;
use aegis_host::HostError;
use aegis_protocol::{CommandV1, RefusalV1, ReplyV1, SessionHandleV1};
use aegis_service::{AuthenticatedSessionV1, Service};
use aegis_wire::{
    CodecErrorV1, LimitsV1, RequestFrameV1, decode_reply, decode_session_opened, encode_request,
    encode_session_opened,
};
use keystone_storage::CheckpointStore;
use keystone_unix_listener::OwnedUnixListener;
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub trait Authenticator {
    type Error;
    fn authenticate(&mut self, stream: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error>;
}

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

#[derive(Debug)]
pub enum ClientErrorV1 {
    NotSent(io::Error),
    OutcomeUnknown(io::Error),
    Wire(CodecErrorV1),
    SessionMismatch,
}

pub struct UnixPort {
    stream: UnixStream,
    session: SessionHandleV1,
    limits: LimitsV1,
}

/// Opens one authenticated connection and returns the server-selected session
/// plus a transport-neutral Aegis service port.
pub fn connect(
    path: impl AsRef<Path>,
    limits: LimitsV1,
    io_timeout: Duration,
) -> Result<(SessionHandleV1, UnixPort), ClientErrorV1> {
    if io_timeout.is_zero() {
        return Err(ClientErrorV1::NotSent(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero I/O timeout",
        )));
    }
    let stream = UnixStream::connect(path).map_err(ClientErrorV1::NotSent)?;
    stream
        .set_read_timeout(Some(io_timeout))
        .and_then(|()| stream.set_write_timeout(Some(io_timeout)))
        .map_err(ClientErrorV1::NotSent)?;
    let mut port = UnixPort {
        stream,
        session: SessionHandleV1(0),
        limits,
    };
    let bytes =
        read_frame(&mut port.stream, limits.max_frame_bytes).map_err(ClientErrorV1::NotSent)?;
    let session = decode_session_opened(&bytes, limits).map_err(ClientErrorV1::Wire)?;
    port.session = session;
    Ok((session, port))
}

impl ClientServicePort for UnixPort {
    type Error = ClientErrorV1;

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        if session != self.session {
            return Err(ClientErrorV1::SessionMismatch);
        }
        let request = encode_request(&RequestFrameV1 { session, command }, self.limits)
            .map_err(ClientErrorV1::Wire)?;
        write_frame(&mut self.stream, &request).map_err(ClientErrorV1::OutcomeUnknown)?;
        let reply = read_frame(&mut self.stream, self.limits.max_frame_bytes)
            .map_err(ClientErrorV1::OutcomeUnknown)?;
        decode_reply(&reply, self.limits).map_err(ClientErrorV1::Wire)
    }
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()
}

fn read_frame(stream: &mut UnixStream, maximum: usize) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length"))?;
    if length == 0 || length > maximum {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame limit"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("frame capacity"))?;
    bytes.resize(length, 0);
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn increment(value: &mut u64, saturated: &mut bool) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *saturated = true;
    }
}
