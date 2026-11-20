//! Canonical bounded V1 codec for Aegis protocol requests and replies.

use aegis_protocol::*;

const MAGIC: &[u8; 8] = b"AEGISW01";
const REQUEST: u8 = 1;
const REPLY: u8 = 2;
const SESSION_OPENED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitsV1 {
    pub max_frame_bytes: usize,
    pub max_scopes: usize,
    pub max_page_entries: usize,
}

impl Default for LimitsV1 {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_scopes: 64,
            max_page_entries: 256,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecErrorV1 {
    Limit,
    Malformed,
    Unsupported,
    Capacity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestFrameV1 {
    pub session: SessionHandleV1,
    pub command: CommandV1,
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Writer {
    fn new(limit: usize, kind: u8) -> Result<Self, CodecErrorV1> {
        let mut writer = Self {
            bytes: Vec::new(),
            limit,
        };
        writer.raw(MAGIC)?;
        writer.byte(kind)?;
        Ok(writer)
    }
    fn raw(&mut self, value: &[u8]) -> Result<(), CodecErrorV1> {
        if value.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(CodecErrorV1::Limit);
        }
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| CodecErrorV1::Capacity)?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    fn byte(&mut self, value: u8) -> Result<(), CodecErrorV1> {
        self.raw(&[value])
    }
    fn u32(&mut self, value: usize) -> Result<(), CodecErrorV1> {
        self.raw(
            &u32::try_from(value)
                .map_err(|_| CodecErrorV1::Limit)?
                .to_be_bytes(),
        )
    }
    fn u64(&mut self, value: u64) -> Result<(), CodecErrorV1> {
        self.raw(&value.to_be_bytes())
    }
    fn option_u64(&mut self, value: Option<u64>) -> Result<(), CodecErrorV1> {
        match value {
            None => self.byte(0),
            Some(value) => {
                self.byte(1)?;
                self.u64(value)
            }
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    limits: LimitsV1,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: LimitsV1, kind: u8) -> Result<Self, CodecErrorV1> {
        if bytes.len() > limits.max_frame_bytes {
            return Err(CodecErrorV1::Limit);
        }
        if bytes.get(..8) != Some(MAGIC.as_slice()) || bytes.get(8) != Some(&kind) {
            return Err(CodecErrorV1::Unsupported);
        }
        Ok(Self {
            bytes,
            position: 9,
            limits,
        })
    }
    fn raw<const N: usize>(&mut self) -> Result<[u8; N], CodecErrorV1> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(CodecErrorV1::Malformed)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CodecErrorV1::Malformed)?;
        self.position = end;
        value.try_into().map_err(|_| CodecErrorV1::Malformed)
    }
    fn byte(&mut self) -> Result<u8, CodecErrorV1> {
        Ok(self.raw::<1>()?[0])
    }
    fn u32(&mut self) -> Result<usize, CodecErrorV1> {
        usize::try_from(u32::from_be_bytes(self.raw()?)).map_err(|_| CodecErrorV1::Limit)
    }
    fn u64(&mut self) -> Result<u64, CodecErrorV1> {
        Ok(u64::from_be_bytes(self.raw()?))
    }
    fn option_u64(&mut self) -> Result<Option<u64>, CodecErrorV1> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(CodecErrorV1::Malformed),
        }
    }
    fn finish(self) -> Result<(), CodecErrorV1> {
        (self.position == self.bytes.len())
            .then_some(())
            .ok_or(CodecErrorV1::Malformed)
    }
}

pub fn encode_request(frame: &RequestFrameV1, limits: LimitsV1) -> Result<Vec<u8>, CodecErrorV1> {
    let mut writer = Writer::new(limits.max_frame_bytes, REQUEST)?;
    writer.u64(frame.session.0)?;
    encode_command(&mut writer, &frame.command, limits)?;
    Ok(writer.bytes)
}

pub fn decode_request(bytes: &[u8], limits: LimitsV1) -> Result<RequestFrameV1, CodecErrorV1> {
    let mut reader = Reader::new(bytes, limits, REQUEST)?;
    let session = SessionHandleV1(reader.u64()?);
    let command = decode_command(&mut reader)?;
    reader.finish()?;
    Ok(RequestFrameV1 { session, command })
}

pub fn encode_reply(reply: &ReplyV1, limits: LimitsV1) -> Result<Vec<u8>, CodecErrorV1> {
    let mut writer = Writer::new(limits.max_frame_bytes, REPLY)?;
    match reply {
        ReplyV1::Accepted(outcome) => {
            writer.byte(0)?;
            encode_outcome(&mut writer, outcome, limits)?;
        }
        ReplyV1::Refused(refusal) => {
            writer.byte(1)?;
            encode_refusal(&mut writer, *refusal)?;
        }
    }
    Ok(writer.bytes)
}

pub fn decode_reply(bytes: &[u8], limits: LimitsV1) -> Result<ReplyV1, CodecErrorV1> {
    let mut reader = Reader::new(bytes, limits, REPLY)?;
    let reply = match reader.byte()? {
        0 => ReplyV1::Accepted(decode_outcome(&mut reader)?),
        1 => ReplyV1::Refused(decode_refusal(&mut reader)?),
        _ => return Err(CodecErrorV1::Malformed),
    };
    reader.finish()?;
    Ok(reply)
}

pub fn encode_session_opened(
    session: SessionHandleV1,
    limits: LimitsV1,
) -> Result<Vec<u8>, CodecErrorV1> {
    let mut writer = Writer::new(limits.max_frame_bytes, SESSION_OPENED)?;
    writer.u64(session.0)?;
    Ok(writer.bytes)
}

pub fn decode_session_opened(
    bytes: &[u8],
    limits: LimitsV1,
) -> Result<SessionHandleV1, CodecErrorV1> {
    let mut reader = Reader::new(bytes, limits, SESSION_OPENED)?;
    let session = SessionHandleV1(reader.u64()?);
    reader.finish()?;
    Ok(session)
}

fn encode_command(
    writer: &mut Writer,
    value: &CommandV1,
    limits: LimitsV1,
) -> Result<(), CodecErrorV1> {
    match value {
        CommandV1::CurrentPrincipal => writer.byte(8),
        CommandV1::Issue {
            expected_epoch,
            now,
            expires_at,
            scopes,
        } => {
            writer.byte(1)?;
            writer.u64(*expected_epoch)?;
            writer.u64(*now)?;
            writer.u64(*expires_at)?;
            encode_scopes(writer, scopes, limits)
        }
        CommandV1::Attenuate {
            parent,
            expected_epoch,
            now,
            expires_at,
            scopes,
        } => {
            writer.byte(2)?;
            writer.u64(parent.0)?;
            writer.u64(*expected_epoch)?;
            writer.u64(*now)?;
            writer.u64(*expires_at)?;
            encode_scopes(writer, scopes, limits)
        }
        CommandV1::Authorize {
            grant,
            now,
            engine,
            resource,
            action,
        } => {
            writer.byte(3)?;
            writer.u64(grant.0)?;
            writer.u64(*now)?;
            writer.byte(namespace_tag(*engine))?;
            writer.raw(resource)?;
            writer.byte(action_tag(*action))
        }
        CommandV1::RevokeEpoch { expected_epoch } => {
            writer.byte(4)?;
            writer.u64(*expected_epoch)
        }
        CommandV1::Status => writer.byte(5),
        CommandV1::GrantPage { after, limit } => {
            writer.byte(6)?;
            writer.option_u64(after.map(|v| v.0))?;
            writer.u64(u64::try_from(*limit).map_err(|_| CodecErrorV1::Limit)?)
        }
        CommandV1::DecisionPage { after, limit } => {
            writer.byte(7)?;
            writer.option_u64(after.map(|v| v.0))?;
            writer.u64(u64::try_from(*limit).map_err(|_| CodecErrorV1::Limit)?)
        }
    }
}

fn decode_command(reader: &mut Reader<'_>) -> Result<CommandV1, CodecErrorV1> {
    match reader.byte()? {
        1 => Ok(CommandV1::Issue {
            expected_epoch: reader.u64()?,
            now: reader.u64()?,
            expires_at: reader.u64()?,
            scopes: decode_scopes(reader)?,
        }),
        2 => Ok(CommandV1::Attenuate {
            parent: GrantHandleV1(reader.u64()?),
            expected_epoch: reader.u64()?,
            now: reader.u64()?,
            expires_at: reader.u64()?,
            scopes: decode_scopes(reader)?,
        }),
        3 => Ok(CommandV1::Authorize {
            grant: GrantHandleV1(reader.u64()?),
            now: reader.u64()?,
            engine: namespace(reader.byte()?)?,
            resource: reader.raw()?,
            action: action(reader.byte()?)?,
        }),
        4 => Ok(CommandV1::RevokeEpoch {
            expected_epoch: reader.u64()?,
        }),
        5 => Ok(CommandV1::Status),
        6 => Ok(CommandV1::GrantPage {
            after: reader.option_u64()?.map(GrantHandleV1),
            limit: usize::try_from(reader.u64()?).map_err(|_| CodecErrorV1::Limit)?,
        }),
        7 => Ok(CommandV1::DecisionPage {
            after: reader.option_u64()?.map(DecisionHandleV1),
            limit: usize::try_from(reader.u64()?).map_err(|_| CodecErrorV1::Limit)?,
        }),
        8 => Ok(CommandV1::CurrentPrincipal),
        _ => Err(CodecErrorV1::Unsupported),
    }
}

fn encode_scopes(
    writer: &mut Writer,
    scopes: &[ScopeV1],
    limits: LimitsV1,
) -> Result<(), CodecErrorV1> {
    if scopes.len() > limits.max_scopes {
        return Err(CodecErrorV1::Limit);
    }
    writer.u32(scopes.len())?;
    for scope in scopes {
        writer.byte(namespace_tag(scope.engine))?;
        writer.raw(&scope.resource)?;
        writer.byte(scope.actions)?;
    }
    Ok(())
}

fn decode_scopes(reader: &mut Reader<'_>) -> Result<Vec<ScopeV1>, CodecErrorV1> {
    let count = reader.u32()?;
    if count > reader.limits.max_scopes {
        return Err(CodecErrorV1::Limit);
    }
    let mut scopes = Vec::new();
    scopes
        .try_reserve_exact(count)
        .map_err(|_| CodecErrorV1::Capacity)?;
    for _ in 0..count {
        scopes.push(ScopeV1 {
            engine: namespace(reader.byte()?)?,
            resource: reader.raw()?,
            actions: reader.byte()?,
        });
    }
    Ok(scopes)
}

fn encode_outcome(
    writer: &mut Writer,
    value: &OutcomeV1,
    limits: LimitsV1,
) -> Result<(), CodecErrorV1> {
    match value {
        OutcomeV1::CurrentPrincipal(binding) => {
            writer.byte(7)?;
            writer.raw(&binding.principal)
        }
        OutcomeV1::GrantIssued(summary) => {
            writer.byte(1)?;
            encode_grant(writer, summary)
        }
        OutcomeV1::Authorized(summary) => {
            writer.byte(2)?;
            encode_decision(writer, summary)
        }
        OutcomeV1::EpochRevoked { epoch } => {
            writer.byte(3)?;
            writer.u64(*epoch)
        }
        OutcomeV1::Status(status) => {
            writer.byte(4)?;
            writer.u64(status.epoch)?;
            writer.u64(status.active_grants as u64)?;
            writer.u64(status.retained_decisions as u64)
        }
        OutcomeV1::GrantPage {
            entries,
            next_after,
        } => {
            if entries.len() > limits.max_page_entries {
                return Err(CodecErrorV1::Limit);
            }
            writer.byte(5)?;
            writer.u32(entries.len())?;
            for entry in entries {
                encode_grant(writer, entry)?;
            }
            writer.option_u64(next_after.map(|v| v.0))
        }
        OutcomeV1::DecisionPage {
            entries,
            next_after,
        } => {
            if entries.len() > limits.max_page_entries {
                return Err(CodecErrorV1::Limit);
            }
            writer.byte(6)?;
            writer.u32(entries.len())?;
            for entry in entries {
                encode_decision(writer, entry)?;
            }
            writer.option_u64(next_after.map(|v| v.0))
        }
    }
}

fn decode_outcome(reader: &mut Reader<'_>) -> Result<OutcomeV1, CodecErrorV1> {
    match reader.byte()? {
        1 => Ok(OutcomeV1::GrantIssued(decode_grant(reader)?)),
        2 => Ok(OutcomeV1::Authorized(decode_decision(reader)?)),
        3 => Ok(OutcomeV1::EpochRevoked {
            epoch: reader.u64()?,
        }),
        4 => Ok(OutcomeV1::Status(AuthorityStatusV1 {
            epoch: reader.u64()?,
            active_grants: usize::try_from(reader.u64()?).map_err(|_| CodecErrorV1::Limit)?,
            retained_decisions: usize::try_from(reader.u64()?).map_err(|_| CodecErrorV1::Limit)?,
        })),
        5 => {
            let count = page_count(reader)?;
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(count)
                .map_err(|_| CodecErrorV1::Capacity)?;
            for _ in 0..count {
                entries.push(decode_grant(reader)?);
            }
            Ok(OutcomeV1::GrantPage {
                entries,
                next_after: reader.option_u64()?.map(GrantHandleV1),
            })
        }
        6 => {
            let count = page_count(reader)?;
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(count)
                .map_err(|_| CodecErrorV1::Capacity)?;
            for _ in 0..count {
                entries.push(decode_decision(reader)?);
            }
            Ok(OutcomeV1::DecisionPage {
                entries,
                next_after: reader.option_u64()?.map(DecisionHandleV1),
            })
        }
        7 => Ok(OutcomeV1::CurrentPrincipal(CurrentPrincipalV1 {
            principal: reader.raw()?,
        })),
        _ => Err(CodecErrorV1::Unsupported),
    }
}

fn page_count(reader: &mut Reader<'_>) -> Result<usize, CodecErrorV1> {
    let count = reader.u32()?;
    if count > reader.limits.max_page_entries {
        Err(CodecErrorV1::Limit)
    } else {
        Ok(count)
    }
}
fn encode_grant(w: &mut Writer, v: &GrantSummaryV1) -> Result<(), CodecErrorV1> {
    w.u64(v.handle.0)?;
    w.option_u64(v.parent.map(|v| v.0))?;
    w.u64(v.epoch)?;
    w.u64(v.expires_at)?;
    w.u64(v.scope_count as u64)?;
    w.byte(v.delegation_depth)
}
fn decode_grant(r: &mut Reader<'_>) -> Result<GrantSummaryV1, CodecErrorV1> {
    Ok(GrantSummaryV1 {
        handle: GrantHandleV1(r.u64()?),
        parent: r.option_u64()?.map(GrantHandleV1),
        epoch: r.u64()?,
        expires_at: r.u64()?,
        scope_count: usize::try_from(r.u64()?).map_err(|_| CodecErrorV1::Limit)?,
        delegation_depth: r.byte()?,
    })
}
fn encode_decision(w: &mut Writer, v: &DecisionSummaryV1) -> Result<(), CodecErrorV1> {
    w.u64(v.handle.0)?;
    w.u64(v.epoch)?;
    w.u64(v.expires_at)?;
    w.byte(namespace_tag(v.engine))?;
    w.byte(action_tag(v.action))
}
fn decode_decision(r: &mut Reader<'_>) -> Result<DecisionSummaryV1, CodecErrorV1> {
    Ok(DecisionSummaryV1 {
        handle: DecisionHandleV1(r.u64()?),
        epoch: r.u64()?,
        expires_at: r.u64()?,
        engine: namespace(r.byte()?)?,
        action: action(r.byte()?)?,
    })
}

fn namespace_tag(v: EngineNamespaceV1) -> u8 {
    match v {
        EngineNamespaceV1::Agora => 0,
        EngineNamespaceV1::Chronos => 1,
        EngineNamespaceV1::Vellum => 2,
        EngineNamespaceV1::Moira => 3,
        EngineNamespaceV1::Hermes => 4,
        EngineNamespaceV1::Daimon => 5,
        EngineNamespaceV1::Aegis => 6,
    }
}
fn namespace(v: u8) -> Result<EngineNamespaceV1, CodecErrorV1> {
    match v {
        0 => Ok(EngineNamespaceV1::Agora),
        1 => Ok(EngineNamespaceV1::Chronos),
        2 => Ok(EngineNamespaceV1::Vellum),
        3 => Ok(EngineNamespaceV1::Moira),
        4 => Ok(EngineNamespaceV1::Hermes),
        5 => Ok(EngineNamespaceV1::Daimon),
        6 => Ok(EngineNamespaceV1::Aegis),
        _ => Err(CodecErrorV1::Unsupported),
    }
}
fn action_tag(v: ActionV1) -> u8 {
    match v {
        ActionV1::Observe => 0,
        ActionV1::Submit => 1,
        ActionV1::Modify => 2,
        ActionV1::Execute => 3,
        ActionV1::Delegate => 4,
        ActionV1::Administer => 5,
    }
}
fn action(v: u8) -> Result<ActionV1, CodecErrorV1> {
    match v {
        0 => Ok(ActionV1::Observe),
        1 => Ok(ActionV1::Submit),
        2 => Ok(ActionV1::Modify),
        3 => Ok(ActionV1::Execute),
        4 => Ok(ActionV1::Delegate),
        5 => Ok(ActionV1::Administer),
        _ => Err(CodecErrorV1::Unsupported),
    }
}
fn encode_refusal(writer: &mut Writer, v: RefusalV1) -> Result<(), CodecErrorV1> {
    let tag = match v {
        RefusalV1::UnknownSession => 0,
        RefusalV1::UnknownGrant => 1,
        RefusalV1::GrantOwnedByAnotherSession => 2,
        RefusalV1::NotAdministrator => 3,
        RefusalV1::InvalidScope => 4,
        RefusalV1::InvalidPageLimit => 5,
        RefusalV1::StaleEpoch { .. } => 12,
        RefusalV1::Capacity => 6,
        RefusalV1::Exhausted => 7,
        RefusalV1::Revoked => 8,
        RefusalV1::Expired => 9,
        RefusalV1::NotAuthorized => 10,
        RefusalV1::InvalidInput => 11,
    };
    writer.byte(tag)?;
    if let RefusalV1::StaleEpoch { actual } = v {
        writer.u64(actual)?;
    }
    Ok(())
}
fn decode_refusal(reader: &mut Reader<'_>) -> Result<RefusalV1, CodecErrorV1> {
    match reader.byte()? {
        0 => Ok(RefusalV1::UnknownSession),
        1 => Ok(RefusalV1::UnknownGrant),
        2 => Ok(RefusalV1::GrantOwnedByAnotherSession),
        3 => Ok(RefusalV1::NotAdministrator),
        4 => Ok(RefusalV1::InvalidScope),
        5 => Ok(RefusalV1::InvalidPageLimit),
        6 => Ok(RefusalV1::Capacity),
        7 => Ok(RefusalV1::Exhausted),
        8 => Ok(RefusalV1::Revoked),
        9 => Ok(RefusalV1::Expired),
        10 => Ok(RefusalV1::NotAuthorized),
        11 => Ok(RefusalV1::InvalidInput),
        12 => Ok(RefusalV1::StaleEpoch {
            actual: reader.u64()?,
        }),
        _ => Err(CodecErrorV1::Unsupported),
    }
}
