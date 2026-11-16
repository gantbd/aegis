//! Fixed-size state codec and private transition preparation. No grant material,
//! scopes, principals, sessions, decisions, credentials or secrets are persisted.
//! Recovery keeps the namespace/frontiers and advances the epoch, never reviving
//! old capabilities. A durable host must persist this fence before using it.

use crate::*;

pub const CHECKPOINT_BYTES_V1: usize = 48;
const MAGIC: &[u8; 8] = b"AEGISCP\x01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointErrorV1 {
    Malformed,
    UnsupportedVersion,
    WrongNamespace,
    Disabled,
    EpochExhausted,
}

/// A prepared native transition contains its unreleased outcome. It is not
/// cloneable. Only the trusted persistence host publishes it after a receipt.
pub struct PreparedV1<T> {
    engine: Engine,
    outcome: T,
}

impl<T> PreparedV1<T> {
    pub fn checkpoint(&self) -> [u8; CHECKPOINT_BYTES_V1] {
        self.engine.checkpoint()
    }
    pub fn publish(self) -> (Engine, T) {
        (self.engine, self.outcome)
    }
}

impl Engine {
    pub fn checkpoint(&self) -> [u8; CHECKPOINT_BYTES_V1] {
        let mut bytes = [0; CHECKPOINT_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.engine_id.0);
        bytes[24..32].copy_from_slice(&self.epoch.0.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.next_grant.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.next_decision.to_be_bytes());
        bytes
    }

    /// Pure staged recovery, not evidence of durable publication. Namespace is
    /// supplied independently by the host; limits cannot be enlarged by input.
    pub fn recover_checkpoint(
        bytes: &[u8],
        expected: EngineId,
        limits: Limits,
    ) -> Result<Self, CheckpointErrorV1> {
        if bytes.len() != CHECKPOINT_BYTES_V1 || bytes[..7] != MAGIC[..7] {
            return Err(CheckpointErrorV1::Malformed);
        }
        if bytes[7] != 1 {
            return Err(CheckpointErrorV1::UnsupportedVersion);
        }
        if bytes[8..24] != expected.0 {
            return Err(CheckpointErrorV1::WrongNamespace);
        }
        let number = |range: std::ops::Range<usize>| -> Result<u64, CheckpointErrorV1> {
            Ok(u64::from_be_bytes(
                bytes[range]
                    .try_into()
                    .map_err(|_| CheckpointErrorV1::Malformed)?,
            ))
        };
        let mut engine =
            Self::try_new(expected, limits).map_err(|_| CheckpointErrorV1::Disabled)?;
        engine.epoch = AuthorityEpoch(
            number(24..32)?
                .checked_add(1)
                .ok_or(CheckpointErrorV1::EpochExhausted)?,
        );
        engine.next_grant = number(32..40)?;
        engine.next_decision = number(40..48)?;
        Ok(engine)
    }

    // Duplicate only private bounded counters, never a bearer capability. No
    // public Engine/Grant Clone implementation or unfenced decoder is exposed.
    fn prepare<T>(
        &self,
        run: impl FnOnce(&mut Self) -> Result<T, RefusalV1>,
    ) -> Result<PreparedV1<T>, RefusalV1> {
        let mut engine = Self {
            engine_id: self.engine_id,
            limits: self.limits,
            epoch: self.epoch,
            next_grant: self.next_grant,
            next_decision: self.next_decision,
        };
        let outcome = run(&mut engine)?;
        Ok(PreparedV1 { engine, outcome })
    }

    pub fn prepare_issue(
        &self,
        descriptor: GrantDescriptorV1,
        now: LogicalTime,
    ) -> Result<PreparedV1<GrantV1>, RefusalV1> {
        self.prepare(|engine| engine.issue(descriptor, now))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_attenuation(
        &self,
        parent: &GrantV1,
        subject: PrincipalId,
        session: Option<SessionId>,
        expires_at: LogicalTime,
        scopes: Vec<ResourceScopeV1>,
        now: LogicalTime,
    ) -> Result<PreparedV1<GrantV1>, RefusalV1> {
        self.prepare(|engine| engine.attenuate(parent, subject, session, expires_at, scopes, now))
    }

    pub fn prepare_validation(
        &self,
        grant: &GrantV1,
        request: &AuthorizationRequestV1,
        now: LogicalTime,
    ) -> Result<PreparedV1<DecisionEvidenceV1>, RefusalV1> {
        self.prepare(|engine| engine.validate(grant, request, now))
    }

    pub fn prepare_revocation(&self) -> Result<PreparedV1<AuthorityEpoch>, RefusalV1> {
        self.prepare(Self::revoke_epoch)
    }
}
