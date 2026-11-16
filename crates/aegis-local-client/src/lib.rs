//! Public private-Unix client for Aegis.
//!
//! The client owns only connection, framing, the server-selected session, and
//! transport certainty. It imports no Aegis authority engine, host, service,
//! credential mapping, persistence, or daemon lifecycle.

#[cfg(not(unix))]
compile_error!("aegis-local-client currently qualifies only Unix hosts");

use aegis_client::ServicePort;
use aegis_protocol::{CommandV1, ReplyV1, SessionHandleV1};
use aegis_wire::{
    CodecErrorV1, LimitsV1, RequestFrameV1, decode_reply, decode_session_opened, encode_request,
};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

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

impl ServicePort for UnixPort {
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
