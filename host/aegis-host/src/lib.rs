//! Privileged in-process persistence boundary, not credential authentication.
#![forbid(unsafe_code)]
use aegis_authority::{
    AuthorityEpoch, AuthorizationRequestV1, DecisionEvidenceV1, Engine, EngineId,
    GrantDescriptorV1, GrantV1, Limits, LogicalTime, PrincipalId, RefusalV1, ResourceScopeV1,
    SessionId,
    persistence::{CHECKPOINT_BYTES_V1, CheckpointErrorV1, PreparedV1},
};
use keystone_observe::{DurationAccumulator, SaturatingCounter};
use keystone_storage::{
    AcknowledgementStrength, CheckpointStore, CommitGate, CommitGateFailure, CommitGateRefusal,
    Revision, StoreRefusal,
};
use std::time::{Duration, Instant};

const KEY: &str = "aegis-authority-v1";
const MAGIC: &[u8; 8] = b"AEGISST\x01";
const HEADER: usize = 16;
pub const STORAGE_VALUE_BYTES_V1: usize = HEADER + CHECKPOINT_BYTES_V1;

pub enum HostError<E> {
    Domain(RefusalV1),
    Checkpoint(CheckpointErrorV1),
    Store(E),
    StoreRefused(StoreRefusal),
    MissingState,
    AlreadyInitialized,
    InvalidRecovery,
    InvalidReceipt,
    Indeterminate,
    RevisionExhausted,
    Fenced,
}
impl<E> std::fmt::Debug for HostError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(e) => f.debug_tuple("Domain").field(e).finish(),
            Self::Checkpoint(e) => f.debug_tuple("Checkpoint").field(e).finish(),
            Self::Store(_) => f.write_str("Store(<redacted>)"),
            Self::StoreRefused(e) => f.debug_tuple("StoreRefused").field(e).finish(),
            Self::MissingState => f.write_str("MissingState"),
            Self::AlreadyInitialized => f.write_str("AlreadyInitialized"),
            Self::InvalidRecovery => f.write_str("InvalidRecovery"),
            Self::InvalidReceipt => f.write_str("InvalidReceipt"),
            Self::Indeterminate => f.write_str("Indeterminate"),
            Self::RevisionExhausted => f.write_str("RevisionExhausted"),
            Self::Fenced => f.write_str("Fenced"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum OperationV1 {
    Issue = 0,
    Attenuate = 1,
    Validate = 2,
    Revoke = 3,
}
impl OperationV1 {
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Last-confirmed gauges are not live authorization after fencing. Initialization
/// and the mandatory recovery fence are included in commit counters and timing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignalsV1 {
    pub offers: [u64; 4],
    pub residence: [Duration; 4],
    pub domain_refusals: u64,
    pub admission_refusals: u64,
    pub commits: u64,
    pub commit_failures: u64,
    pub commit_time: Duration,
    pub epoch: u64,
    pub next_grant: u64,
    pub next_decision: u64,
    pub checkpoint_bytes: usize,
    pub fenced: bool,
    pub saturated: bool,
}
fn increment(value: &mut u64, saturated: &mut bool) {
    let mut counter = SaturatingCounter::from_value(*value);
    let _ = counter.increment();
    *value = counter.value();
    *saturated |= counter.is_saturated();
}
fn add_time(value: &mut Duration, delta: Duration, saturated: &mut bool) {
    let mut total = DurationAccumulator::from_value(*value);
    let _ = total.add(delta);
    *value = total.value();
    *saturated |= total.is_saturated();
}

pub struct DurableAuthority<S: CheckpointStore> {
    engine: Option<Engine>,
    store: S,
    commit_gate: CommitGate,
    signals: SignalsV1,
    observing: bool,
}

impl<S: CheckpointStore> DurableAuthority<S> {
    /// Returns the selected store to privileged lifecycle wiring.
    ///
    /// This transfers mechanism ownership only. It does not export grants,
    /// decisions, sessions, or authority from the live engine.
    pub fn into_store(self) -> S {
        self.store
    }

    /// The host reserves this namespace for this store and authenticates callers.
    /// This method never imports opaque grants or derives rights from IDs.
    pub fn create_new(
        store: S,
        namespace: EngineId,
        limits: Limits,
    ) -> Result<Self, HostError<S::Error>> {
        if store.load(KEY).map_err(HostError::Store)?.is_some() {
            return Err(HostError::AlreadyInitialized);
        }
        let engine = Engine::try_new(namespace, limits)
            .map_err(|_| HostError::Checkpoint(CheckpointErrorV1::Disabled))?;
        let mut host = Self {
            engine: Some(engine),
            store,
            commit_gate: CommitGate::new(None),
            signals: SignalsV1::default(),
            observing: true,
        };
        let checkpoint = host.engine.as_ref().ok_or(HostError::Fenced)?.checkpoint();
        host.persist(checkpoint)?;
        host.refresh();
        Ok(host)
    }

    /// Reopening ALWAYS advances and commits the authority epoch before returning.
    /// Old runtime grants cannot resume; fresh authenticated issuance is required.
    pub fn open(
        store: S,
        namespace: EngineId,
        limits: Limits,
    ) -> Result<Self, HostError<S::Error>> {
        let saved = store
            .load(KEY)
            .map_err(HostError::Store)?
            .ok_or(HostError::MissingState)?;
        if saved.strength != AcknowledgementStrength::Durable
            || saved.bytes.len() != STORAGE_VALUE_BYTES_V1
            || &saved.bytes[..8] != MAGIC
        {
            return Err(HostError::InvalidRecovery);
        }
        let revision = Revision(u64::from_be_bytes(
            saved.bytes[8..HEADER]
                .try_into()
                .map_err(|_| HostError::InvalidRecovery)?,
        ));
        if revision != saved.revision {
            return Err(HostError::InvalidRecovery);
        }
        let engine = Engine::recover_checkpoint(&saved.bytes[HEADER..], namespace, limits)
            .map_err(HostError::Checkpoint)?;
        let checkpoint = engine.checkpoint();
        let mut host = Self {
            engine: Some(engine),
            store,
            commit_gate: CommitGate::new(Some(revision)),
            signals: SignalsV1::default(),
            observing: true,
        };
        host.persist(checkpoint)?;
        host.refresh();
        Ok(host)
    }

    pub fn signals(&self) -> SignalsV1 {
        self.signals
    }
    pub fn set_observation(&mut self, enabled: bool) {
        self.observing = enabled;
    }
    pub fn revision(&self) -> Option<Revision> {
        self.commit_gate.confirmed_revision()
    }
    pub fn epoch(&self) -> Result<AuthorityEpoch, HostError<S::Error>> {
        Ok(self.engine.as_ref().ok_or(HostError::Fenced)?.epoch())
    }

    pub fn issue(
        &mut self,
        descriptor: GrantDescriptorV1,
        now: LogicalTime,
    ) -> Result<GrantV1, HostError<S::Error>> {
        self.execute(OperationV1::Issue, |engine| {
            engine.prepare_issue(descriptor, now)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attenuate(
        &mut self,
        parent: &GrantV1,
        subject: PrincipalId,
        session: Option<SessionId>,
        expires_at: LogicalTime,
        scopes: Vec<ResourceScopeV1>,
        now: LogicalTime,
    ) -> Result<GrantV1, HostError<S::Error>> {
        self.execute(OperationV1::Attenuate, |engine| {
            engine.prepare_attenuation(parent, subject, session, expires_at, scopes, now)
        })
    }

    pub fn validate(
        &mut self,
        grant: &GrantV1,
        request: &AuthorizationRequestV1,
        now: LogicalTime,
    ) -> Result<DecisionEvidenceV1, HostError<S::Error>> {
        self.execute(OperationV1::Validate, |engine| {
            engine.prepare_validation(grant, request, now)
        })
    }

    pub fn revoke_epoch(&mut self) -> Result<AuthorityEpoch, HostError<S::Error>> {
        self.execute(OperationV1::Revoke, Engine::prepare_revocation)
    }

    fn execute<T>(
        &mut self,
        operation: OperationV1,
        prepare: impl FnOnce(&Engine) -> Result<PreparedV1<T>, RefusalV1>,
    ) -> Result<T, HostError<S::Error>> {
        let started = self.observing.then(Instant::now);
        let result = (|| {
            let engine = self.engine.as_ref().ok_or(HostError::Fenced)?;
            let candidate = prepare(engine).map_err(HostError::Domain)?;
            self.persist(candidate.checkpoint())?;
            let (engine, outcome) = candidate.publish();
            self.engine = Some(engine);
            self.refresh();
            Ok(outcome)
        })();
        if let Some(started) = started {
            increment(
                &mut self.signals.offers[operation.index()],
                &mut self.signals.saturated,
            );
            add_time(
                &mut self.signals.residence[operation.index()],
                started.elapsed(),
                &mut self.signals.saturated,
            );
            match &result {
                Err(HostError::Domain(_)) => increment(
                    &mut self.signals.domain_refusals,
                    &mut self.signals.saturated,
                ),
                Err(_) => increment(
                    &mut self.signals.admission_refusals,
                    &mut self.signals.saturated,
                ),
                Ok(_) => {}
            }
        }
        result
    }

    fn persist(
        &mut self,
        checkpoint: [u8; CHECKPOINT_BYTES_V1],
    ) -> Result<(), HostError<S::Error>> {
        let next = self
            .commit_gate
            .next_revision()
            .map_err(|error| match error {
                CommitGateRefusal::Fenced => HostError::Fenced,
                CommitGateRefusal::RevisionExhausted => HostError::RevisionExhausted,
            })?;
        let mut value = [0; STORAGE_VALUE_BYTES_V1];
        value[..8].copy_from_slice(MAGIC);
        value[8..HEADER].copy_from_slice(&next.0.to_be_bytes());
        value[HEADER..].copy_from_slice(&checkpoint);
        let started = self.observing.then(Instant::now);
        let outcome =
            self.store
                .compare_exchange(KEY, self.commit_gate.confirmed_revision(), &value);
        let result = self
            .commit_gate
            .resolve(next, outcome)
            .map_err(|error| match error {
                CommitGateFailure::Store(error) => HostError::Store(error),
                CommitGateFailure::Refused(reason) => HostError::StoreRefused(reason),
                CommitGateFailure::Indeterminate => HostError::Indeterminate,
                CommitGateFailure::InvalidReceipt => HostError::InvalidReceipt,
            });
        if let Some(started) = started {
            add_time(
                &mut self.signals.commit_time,
                started.elapsed(),
                &mut self.signals.saturated,
            );
            if result.is_ok() {
                increment(&mut self.signals.commits, &mut self.signals.saturated);
            } else {
                increment(
                    &mut self.signals.commit_failures,
                    &mut self.signals.saturated,
                );
            }
        }
        if result.is_err() {
            self.engine = None;
            self.signals.fenced = self.commit_gate.is_fenced();
        } else {
            self.signals.checkpoint_bytes = STORAGE_VALUE_BYTES_V1;
        }
        result
    }

    fn refresh(&mut self) {
        if let Some(engine) = &self.engine {
            self.signals.epoch = engine.epoch().0;
            (self.signals.next_grant, self.signals.next_decision) = engine.allocation_frontiers();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signals_saturate_and_store_errors_do_not_disclose_content() {
        let mut value = u64::MAX;
        let mut saturated = false;
        increment(&mut value, &mut saturated);
        assert_eq!(value, u64::MAX);
        assert!(saturated);
        let mut time = Duration::MAX;
        saturated = false;
        add_time(&mut time, Duration::from_nanos(1), &mut saturated);
        assert!(saturated);
        assert_eq!(time, Duration::MAX);
        assert_eq!(
            format!("{:?}", HostError::Store("private credential")),
            "Store(<redacted>)"
        );
    }
}
