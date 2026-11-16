//! Optional fail-closed rollback witness profile for Aegis checkpoints.
//!
//! The witness is an independently provisioned continuity mechanism. It does
//! not authenticate principals, grant authority, interpret Aegis checkpoint
//! bytes or make a local store durable. `Confirmed` means the witness has
//! durably matched or advanced to the exact supplied checkpoint.

#![forbid(unsafe_code)]

use keystone_storage::{AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessDecisionV1 {
    /// Absence or the exact checkpoint is durably confirmed.
    Confirmed,
    /// The local state is older than, or absent behind, the witness.
    Rollback,
    /// The same revision is bound to different checkpoint bytes.
    Conflict,
    /// Ordering or durable witness publication cannot be established.
    Indeterminate,
}

/// Deployment-owned external continuity contract.
///
/// `verify(None)` must return `Rollback` when the witness already retains state.
/// `advance` may return `Confirmed` only after the exact revision and bytes are
/// durably retained by the independent witness mechanism.
pub trait RollbackWitnessV1 {
    type Error;

    fn verify(&self, checkpoint: Option<&Checkpoint>) -> Result<WitnessDecisionV1, Self::Error>;

    fn advance(&mut self, checkpoint: &Checkpoint) -> Result<WitnessDecisionV1, Self::Error>;
}

pub enum WitnessedStoreError<S, W> {
    Store(S),
    Witness(W),
    Rollback,
    Conflict,
    Indeterminate,
}

impl<S, W> std::fmt::Debug for WitnessedStoreError<S, W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(_) => formatter.write_str("Store(<redacted>)"),
            Self::Witness(_) => formatter.write_str("Witness(<redacted>)"),
            Self::Rollback => formatter.write_str("Rollback"),
            Self::Conflict => formatter.write_str("Conflict"),
            Self::Indeterminate => formatter.write_str("Indeterminate"),
        }
    }
}

/// Checkpoint-store decorator that gates both recovery and publication on an
/// independently owned rollback witness.
pub struct WitnessedCheckpointStore<S, W> {
    store: S,
    witness: W,
}

impl<S, W> WitnessedCheckpointStore<S, W> {
    pub const fn new(store: S, witness: W) -> Self {
        Self { store, witness }
    }

    pub fn into_parts(self) -> (S, W) {
        (self.store, self.witness)
    }
}

impl<S, W> CheckpointStore for WitnessedCheckpointStore<S, W>
where
    S: CheckpointStore,
    W: RollbackWitnessV1,
{
    type Error = WitnessedStoreError<S::Error, W::Error>;

    fn load(&self, key: &str) -> Result<Option<Checkpoint>, Self::Error> {
        let checkpoint = self.store.load(key).map_err(WitnessedStoreError::Store)?;
        match self
            .witness
            .verify(checkpoint.as_ref())
            .map_err(WitnessedStoreError::Witness)?
        {
            WitnessDecisionV1::Confirmed => Ok(checkpoint),
            WitnessDecisionV1::Rollback => Err(WitnessedStoreError::Rollback),
            WitnessDecisionV1::Conflict => Err(WitnessedStoreError::Conflict),
            WitnessDecisionV1::Indeterminate => Err(WitnessedStoreError::Indeterminate),
        }
    }

    fn compare_exchange(
        &mut self,
        key: &str,
        expected: Option<keystone_storage::Revision>,
        bytes: &[u8],
    ) -> Result<CommitOutcome, Self::Error> {
        let outcome = self
            .store
            .compare_exchange(key, expected, bytes)
            .map_err(WitnessedStoreError::Store)?;
        let CommitOutcome::Committed(receipt) = &outcome else {
            return Ok(outcome);
        };
        if receipt.strength != AcknowledgementStrength::Durable {
            return Ok(outcome);
        }
        let checkpoint = Checkpoint {
            revision: receipt.revision,
            bytes: bytes.to_vec(),
            strength: receipt.strength,
        };
        match self
            .witness
            .advance(&checkpoint)
            .map_err(WitnessedStoreError::Witness)?
        {
            WitnessDecisionV1::Confirmed => Ok(outcome),
            // The local commit may already be durable. Never report a refusal
            // or pretend the previous state remains authoritative.
            WitnessDecisionV1::Rollback
            | WitnessDecisionV1::Conflict
            | WitnessDecisionV1::Indeterminate => Ok(CommitOutcome::Indeterminate),
        }
    }
}
