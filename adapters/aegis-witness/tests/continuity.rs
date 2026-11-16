use aegis_authority::{
    ActionSetV1, AuthorityEpoch, EngineId, EngineNamespaceV1, GrantDescriptorV1, Limits,
    LogicalTime, PrincipalId, ResourceId, ResourceScopeV1,
};
use aegis_host::{DurableAuthority, HostError};
use aegis_witness::{
    RollbackWitnessV1, WitnessDecisionV1, WitnessedCheckpointStore, WitnessedStoreError,
};
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::{cell::RefCell, convert::Infallible, rc::Rc};

#[derive(Clone, Default)]
struct Store(Rc<RefCell<Option<Checkpoint>>>);

impl CheckpointStore for Store {
    type Error = Infallible;

    fn load(&self, _: &str) -> Result<Option<Checkpoint>, Self::Error> {
        Ok(self.0.borrow().clone())
    }

    fn compare_exchange(
        &mut self,
        _: &str,
        expected: Option<Revision>,
        bytes: &[u8],
    ) -> Result<CommitOutcome, Self::Error> {
        let actual = self.0.borrow().as_ref().map(|value| value.revision);
        if actual != expected {
            return Ok(CommitOutcome::Refused(StoreRefusal::RevisionConflict {
                expected,
                actual,
            }));
        }
        let revision = Revision(actual.map_or(0, |value| value.0 + 1));
        *self.0.borrow_mut() = Some(Checkpoint {
            revision,
            bytes: bytes.to_vec(),
            strength: AcknowledgementStrength::Durable,
        });
        Ok(CommitOutcome::Committed(CommitReceipt {
            revision,
            mechanism: "witness-test-store",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

#[derive(Clone, Default)]
struct Witness {
    anchor: Rc<RefCell<Option<Checkpoint>>>,
    fail_next_advance: Rc<RefCell<bool>>,
}

impl RollbackWitnessV1 for Witness {
    type Error = Infallible;

    fn verify(&self, checkpoint: Option<&Checkpoint>) -> Result<WitnessDecisionV1, Self::Error> {
        let anchor = self.anchor.borrow();
        Ok(match (anchor.as_ref(), checkpoint) {
            (None, None) => WitnessDecisionV1::Confirmed,
            (None, Some(_)) | (Some(_), None) => WitnessDecisionV1::Rollback,
            (Some(anchor), Some(value)) if anchor == value => WitnessDecisionV1::Confirmed,
            (Some(anchor), Some(value)) if value.revision < anchor.revision => {
                WitnessDecisionV1::Rollback
            }
            (Some(anchor), Some(value)) if value.revision == anchor.revision => {
                WitnessDecisionV1::Conflict
            }
            _ => WitnessDecisionV1::Indeterminate,
        })
    }

    fn advance(&mut self, checkpoint: &Checkpoint) -> Result<WitnessDecisionV1, Self::Error> {
        if std::mem::take(&mut *self.fail_next_advance.borrow_mut()) {
            return Ok(WitnessDecisionV1::Indeterminate);
        }
        let mut anchor = self.anchor.borrow_mut();
        let decision = match anchor.as_ref() {
            None if checkpoint.revision == Revision(0) => WitnessDecisionV1::Confirmed,
            Some(value) if value == checkpoint => WitnessDecisionV1::Confirmed,
            Some(value) if checkpoint.revision < value.revision => WitnessDecisionV1::Rollback,
            Some(value) if checkpoint.revision == value.revision => WitnessDecisionV1::Conflict,
            Some(value) if value.revision.0.checked_add(1) == Some(checkpoint.revision.0) => {
                WitnessDecisionV1::Confirmed
            }
            _ => WitnessDecisionV1::Indeterminate,
        };
        if decision == WitnessDecisionV1::Confirmed {
            *anchor = Some(checkpoint.clone());
        }
        Ok(decision)
    }
}

fn descriptor(namespace: EngineId) -> GrantDescriptorV1 {
    GrantDescriptorV1::new(
        PrincipalId::new([2; 16]),
        None,
        namespace,
        AuthorityEpoch(0),
        LogicalTime(10),
        vec![ResourceScopeV1::new(
            EngineNamespaceV1::Daimon,
            ResourceId::new([3; 16]),
            ActionSetV1::singleton(aegis_authority::ActionV1::Execute),
        )],
    )
}

#[test]
fn restored_older_valid_checkpoint_is_refused_before_recovery() {
    let store = Store::default();
    let witness = Witness::default();
    let namespace = EngineId::new([1; 16]);
    let mut authority = DurableAuthority::create_new(
        WitnessedCheckpointStore::new(store.clone(), witness.clone()),
        namespace,
        Limits::default(),
    )
    .unwrap();
    let old = store.0.borrow().clone().unwrap();
    authority
        .issue(descriptor(namespace), LogicalTime(1))
        .unwrap();
    assert!(store.0.borrow().as_ref().unwrap().revision > old.revision);
    drop(authority);

    *store.0.borrow_mut() = Some(old);
    assert!(matches!(
        DurableAuthority::open(
            WitnessedCheckpointStore::new(store, witness),
            namespace,
            Limits::default(),
        ),
        Err(HostError::Store(WitnessedStoreError::Rollback))
    ));
}

#[test]
fn witness_uncertainty_after_local_commit_fences_publication_and_recovery() {
    let store = Store::default();
    let witness = Witness::default();
    let namespace = EngineId::new([4; 16]);
    let mut authority = DurableAuthority::create_new(
        WitnessedCheckpointStore::new(store.clone(), witness.clone()),
        namespace,
        Limits::default(),
    )
    .unwrap();
    *witness.fail_next_advance.borrow_mut() = true;
    assert!(matches!(
        authority.issue(descriptor(namespace), LogicalTime(1)),
        Err(HostError::Indeterminate)
    ));
    assert!(matches!(authority.epoch(), Err(HostError::Fenced)));
    drop(authority);

    assert!(matches!(
        DurableAuthority::open(
            WitnessedCheckpointStore::new(store, witness),
            namespace,
            Limits::default(),
        ),
        Err(HostError::Store(WitnessedStoreError::Indeterminate))
    ));
}

#[test]
fn missing_state_and_same_revision_fork_are_distinct_fail_closed_evidence() {
    let store = Store::default();
    let witness = Witness::default();
    let namespace = EngineId::new([5; 16]);
    let authority = DurableAuthority::create_new(
        WitnessedCheckpointStore::new(store.clone(), witness.clone()),
        namespace,
        Limits::default(),
    )
    .unwrap();
    drop(authority);
    let original = store.0.borrow().clone().unwrap();

    *store.0.borrow_mut() = None;
    assert!(matches!(
        DurableAuthority::open(
            WitnessedCheckpointStore::new(store.clone(), witness.clone()),
            namespace,
            Limits::default(),
        ),
        Err(HostError::Store(WitnessedStoreError::Rollback))
    ));

    let mut fork = original;
    let last = fork.bytes.last_mut().unwrap();
    *last ^= 1;
    *store.0.borrow_mut() = Some(fork);
    assert!(matches!(
        DurableAuthority::open(
            WitnessedCheckpointStore::new(store, witness),
            namespace,
            Limits::default(),
        ),
        Err(HostError::Store(WitnessedStoreError::Conflict))
    ));
}
