//! Bounded local connection boundary for Aegis.
//!
//! A listener/authentication adapter establishes the connection's verified
//! session handle. This layer bounds frames, rejects handle substitution before
//! dispatch and distinguishes input failure from reply loss after execution.

use aegis_protocol::{RefusalV1, ReplyV1, SessionHandleV1};
use aegis_wire::{CodecErrorV1, LimitsV1, decode_request, encode_reply};
use keystone_framing::FrameError;
use std::io::{Read, Write};

#[cfg(unix)]
pub mod unix;

pub trait ServicePort {
    type Error;
    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: aegis_protocol::CommandV1,
    ) -> Result<ReplyV1, Self::Error>;
}

impl<S: keystone_storage::CheckpointStore> ServicePort for aegis_service::Service<S> {
    type Error = aegis_host::HostError<S::Error>;

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: aegis_protocol::CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        aegis_service::Service::execute(self, session, command)
    }
}

pub type ConnectionErrorV1<E> = keystone_framing::ConnectionError<CodecErrorV1, E>;

/// Reads, executes and writes exactly one length-prefixed frame.
pub fn serve_one<IO: Read + Write, P: ServicePort>(
    io: &mut IO,
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: LimitsV1,
) -> Result<(), ConnectionErrorV1<P::Error>> {
    keystone_framing::serve_one(
        io,
        limits.max_frame_bytes,
        |bytes| decode_request(bytes, limits),
        |frame| {
            if frame.session != connection_session {
                Ok(ReplyV1::Refused(RefusalV1::UnknownSession))
            } else {
                service.execute(connection_session, frame.command)
            }
        },
        |reply| encode_reply(reply, limits),
        map_frame_error,
    )
}

/// Serves up to `max_requests` complete requests on one authenticated session.
/// A clean EOF between frames closes the session successfully; partial frames
/// remain `BeforeDispatch` failures.
pub fn serve_up_to<IO: Read + Write, P: ServicePort>(
    io: &mut IO,
    connection_session: SessionHandleV1,
    service: &mut P,
    limits: LimitsV1,
    max_requests: usize,
) -> Result<usize, ConnectionErrorV1<P::Error>> {
    keystone_framing::serve_up_to(
        io,
        limits.max_frame_bytes,
        max_requests,
        |bytes| decode_request(bytes, limits),
        |frame| {
            if frame.session != connection_session {
                Ok(ReplyV1::Refused(RefusalV1::UnknownSession))
            } else {
                service.execute(connection_session, frame.command)
            }
        },
        |reply| encode_reply(reply, limits),
        map_frame_error,
    )
}

fn map_frame_error(error: FrameError) -> CodecErrorV1 {
    match error {
        FrameError::Capacity => CodecErrorV1::Capacity,
        FrameError::RequestLimit | FrameError::FrameLimit => CodecErrorV1::Limit,
    }
}
