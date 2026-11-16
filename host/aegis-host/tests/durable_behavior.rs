use aegis_authority::{
    ActionSetV1, ActionV1, AuthorityEpoch, AuthorizationRequestV1, EngineId, EngineNamespaceV1,
    GrantDescriptorV1, Limits, LogicalTime, PrincipalId, RefusalV1, ResourceId, ResourceScopeV1,
};
use aegis_host::{DurableAuthority, HostError};
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Before,
    After,
    Weak,
    WrongRevision,
    Error,
    Refused,
}
#[derive(Default)]
struct State {
    saved: Option<Checkpoint>,
    calls: u64,
    fault: Fault,
}
#[derive(Clone, Default)]
struct Store(Arc<Mutex<State>>);
impl Store {
    fn arm(&self, fault: Fault) {
        self.0.lock().unwrap().fault = fault;
    }
    fn calls(&self) -> u64 {
        self.0.lock().unwrap().calls
    }
    fn saved(&self) -> Checkpoint {
        self.0.lock().unwrap().saved.clone().unwrap()
    }
}
impl CheckpointStore for Store {
    type Error = &'static str;
    fn load(&self, _: &str) -> Result<Option<Checkpoint>, Self::Error> {
        Ok(self.0.lock().unwrap().saved.clone())
    }
    fn compare_exchange(
        &mut self,
        _: &str,
        expected: Option<Revision>,
        bytes: &[u8],
    ) -> Result<CommitOutcome, Self::Error> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        assert_eq!(expected, state.saved.as_ref().map(|cp| cp.revision));
        let fault = std::mem::take(&mut state.fault);
        match fault {
            Fault::Before => return Ok(CommitOutcome::Indeterminate),
            Fault::Error => return Err("credential must not be logged"),
            Fault::Refused => return Ok(CommitOutcome::Refused(StoreRefusal::ValueLimit)),
            _ => {}
        }
        let revision = Revision(expected.map_or(0, |rev| rev.0 + 1));
        let strength = if matches!(fault, Fault::Weak) {
            AcknowledgementStrength::Volatile
        } else {
            AcknowledgementStrength::Durable
        };
        state.saved = Some(Checkpoint {
            revision,
            bytes: bytes.to_vec(),
            strength,
        });
        if matches!(fault, Fault::After) {
            return Ok(CommitOutcome::Indeterminate);
        }
        Ok(CommitOutcome::Committed(CommitReceipt {
            revision: if matches!(fault, Fault::WrongRevision) {
                Revision(revision.0 + 1)
            } else {
                revision
            },
            strength,
            mechanism: "synthetic",
        }))
    }
}
fn namespace() -> EngineId {
    EngineId::new([1; 16])
}
fn scope() -> ResourceScopeV1 {
    ResourceScopeV1::new(
        EngineNamespaceV1::Daimon,
        ResourceId::new([3; 16]),
        ActionSetV1::top(),
    )
}
fn descriptor(epoch: AuthorityEpoch) -> GrantDescriptorV1 {
    GrantDescriptorV1::new(
        PrincipalId::new([2; 16]),
        None,
        namespace(),
        epoch,
        LogicalTime(50),
        vec![scope()],
    )
}
fn request() -> AuthorizationRequestV1 {
    AuthorizationRequestV1::new(
        PrincipalId::new([2; 16]),
        None,
        EngineNamespaceV1::Daimon,
        ResourceId::new([3; 16]),
        ActionV1::Execute,
    )
}
fn create(store: Store) -> DurableAuthority<Store> {
    DurableAuthority::create_new(store, namespace(), Limits::default()).unwrap()
}

#[test]
fn every_successful_authority_operation_waits_for_commit_and_restart_requires_fresh_issuance() {
    let store = Store::default();
    let mut host = create(store.clone());
    let parent = host
        .issue(descriptor(host.epoch().unwrap()), LogicalTime(1))
        .unwrap();
    let child = host
        .attenuate(
            &parent,
            PrincipalId::new([2; 16]),
            None,
            LogicalTime(40),
            vec![scope()],
            LogicalTime(2),
        )
        .unwrap();
    let evidence = host.validate(&child, &request(), LogicalTime(3)).unwrap();
    assert_eq!(store.calls(), 4);
    assert_eq!(
        (host.signals().next_grant, host.signals().next_decision),
        (2, 1)
    );
    assert_eq!(host.revoke_epoch().unwrap(), AuthorityEpoch(1));
    assert!(matches!(
        host.validate(&child, &request(), LogicalTime(3)),
        Err(HostError::Domain(RefusalV1::Revoked))
    ));
    assert_eq!(store.calls(), 5);
    drop(host);
    let mut recovered =
        DurableAuthority::open(store.clone(), namespace(), Limits::default()).unwrap();
    assert_eq!(
        store.calls(),
        6,
        "recovery fence must be committed before returning"
    );
    assert_eq!(recovered.epoch().unwrap(), AuthorityEpoch(2));
    assert!(matches!(
        recovered.validate(&parent, &request(), LogicalTime(3)),
        Err(HostError::Domain(RefusalV1::Revoked))
    ));
    let fresh = recovered
        .issue(descriptor(recovered.epoch().unwrap()), LogicalTime(3))
        .unwrap();
    let next = recovered
        .validate(&fresh, &request(), LogicalTime(3))
        .unwrap();
    assert_ne!(evidence.decision_id_bytes(), next.decision_id_bytes());
    assert_eq!(
        (
            recovered.signals().next_grant,
            recovered.signals().next_decision
        ),
        (3, 2)
    );
}

#[test]
fn uncertain_issue_delegate_validate_and_revoke_release_no_success_and_fence_all_uses() {
    for operation in 0..4 {
        for fault in [Fault::Before, Fault::After] {
            let store = Store::default();
            let mut host = create(store.clone());
            let parent = host
                .issue(descriptor(host.epoch().unwrap()), LogicalTime(1))
                .unwrap();
            store.arm(fault);
            let failed = match operation {
                0 => host
                    .issue(descriptor(host.epoch().unwrap()), LogicalTime(2))
                    .map(|_| ()),
                1 => host
                    .attenuate(
                        &parent,
                        PrincipalId::new([2; 16]),
                        None,
                        LogicalTime(40),
                        vec![scope()],
                        LogicalTime(2),
                    )
                    .map(|_| ()),
                2 => host
                    .validate(&parent, &request(), LogicalTime(2))
                    .map(|_| ()),
                3 => host.revoke_epoch().map(|_| ()),
                _ => unreachable!(),
            };
            assert!(matches!(failed, Err(HostError::Indeterminate)));
            assert!(matches!(
                host.validate(&parent, &request(), LogicalTime(2)),
                Err(HostError::Fenced)
            ));
            assert!(matches!(
                host.issue(descriptor(AuthorityEpoch(0)), LogicalTime(2)),
                Err(HostError::Fenced)
            ));
            assert!(matches!(host.revoke_epoch(), Err(HostError::Fenced)));
            assert!(matches!(host.epoch(), Err(HostError::Fenced)));
            assert!(host.signals().fenced);
            drop(host);
            let mut recovered =
                DurableAuthority::open(store, namespace(), Limits::default()).unwrap();
            assert!(matches!(
                recovered.validate(&parent, &request(), LogicalTime(2)),
                Err(HostError::Domain(RefusalV1::Revoked))
            ));
        }
    }
}

#[test]
fn weak_wrong_receipts_store_errors_and_refusals_all_fence() {
    for fault in [
        Fault::Weak,
        Fault::WrongRevision,
        Fault::Error,
        Fault::Refused,
    ] {
        let store = Store::default();
        let mut host = create(store.clone());
        store.arm(fault);
        assert!(
            host.issue(descriptor(AuthorityEpoch(0)), LogicalTime(1))
                .is_err()
        );
        assert!(matches!(host.epoch(), Err(HostError::Fenced)));
        assert_eq!(host.signals().commit_failures, 1);
        assert_eq!(host.signals().next_grant, 0);
        if matches!(fault, Fault::Weak) {
            assert!(matches!(
                DurableAuthority::open(store, namespace(), Limits::default()),
                Err(HostError::InvalidRecovery)
            ));
        }
    }
}

#[test]
fn uncertain_recovery_never_exposes_an_uncommitted_fence_and_next_reopen_advances_again() {
    for fault in [Fault::Before, Fault::After] {
        let store = Store::default();
        drop(create(store.clone()));
        store.arm(fault);
        assert!(matches!(
            DurableAuthority::open(store.clone(), namespace(), Limits::default()),
            Err(HostError::Indeterminate)
        ));
        let host = DurableAuthority::open(store, namespace(), Limits::default()).unwrap();
        assert_eq!(
            host.epoch().unwrap(),
            AuthorityEpoch(if matches!(fault, Fault::Before) { 1 } else { 2 })
        );
    }
}

#[test]
fn refusal_before_store_offer_preserves_state_and_does_not_fence() {
    let store = Store::default();
    let mut host = create(store.clone());
    let before = store.saved();
    assert!(matches!(
        host.issue(descriptor(AuthorityEpoch(0)), LogicalTime(50)),
        Err(HostError::Domain(RefusalV1::AlreadyExpired))
    ));
    assert_eq!(store.saved(), before);
    assert_eq!(store.calls(), 1);
    assert_eq!(host.epoch().unwrap(), AuthorityEpoch(0));
}

#[test]
fn explicit_creation_recovery_namespace_and_revision_are_checked_before_commit() {
    let store = Store::default();
    assert!(matches!(
        DurableAuthority::open(store.clone(), namespace(), Limits::default()),
        Err(HostError::MissingState)
    ));
    drop(create(store.clone()));
    assert!(matches!(
        DurableAuthority::create_new(store.clone(), namespace(), Limits::default()),
        Err(HostError::AlreadyInitialized)
    ));
    assert!(matches!(
        DurableAuthority::open(store.clone(), EngineId::new([9; 16]), Limits::default()),
        Err(HostError::Checkpoint(_))
    ));
    assert_eq!(store.calls(), 1);
    store.0.lock().unwrap().saved.as_mut().unwrap().revision = Revision(99);
    assert!(matches!(
        DurableAuthority::open(store.clone(), namespace(), Limits::default()),
        Err(HostError::InvalidRecovery)
    ));
    assert_eq!(store.calls(), 1);
}

#[test]
fn epoch_exhaustion_refuses_recovery_without_rewriting_and_storage_revision_cannot_wrap() {
    let store = Store::default();
    drop(create(store.clone()));
    store.0.lock().unwrap().saved.as_mut().unwrap().bytes[40..48]
        .copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        DurableAuthority::open(store.clone(), namespace(), Limits::default()),
        Err(HostError::Checkpoint(_))
    ));
    assert_eq!(store.calls(), 1);
    let store = Store::default();
    drop(create(store.clone()));
    {
        let mut state = store.0.lock().unwrap();
        let saved = state.saved.as_mut().unwrap();
        saved.revision = Revision(u64::MAX);
        saved.bytes[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    }
    assert!(matches!(
        DurableAuthority::open(store.clone(), namespace(), Limits::default()),
        Err(HostError::RevisionExhausted)
    ));
    assert_eq!(store.calls(), 1);
}

#[test]
fn disabling_observation_changes_neither_checkpoint_nor_results() {
    let enabled = Store::default();
    let disabled = Store::default();
    let mut a = create(enabled.clone());
    let mut b = create(disabled.clone());
    let initial = b.signals();
    b.set_observation(false);
    for host in [&mut a, &mut b] {
        let grant = host
            .issue(descriptor(AuthorityEpoch(0)), LogicalTime(1))
            .unwrap();
        host.validate(&grant, &request(), LogicalTime(2)).unwrap();
        host.revoke_epoch().unwrap();
    }
    assert_eq!(enabled.saved(), disabled.saved());
    assert_eq!(b.signals().offers, initial.offers);
    assert_eq!(b.signals().commit_time, initial.commit_time);
    assert_eq!(b.signals().commits, initial.commits);
    assert_eq!(b.signals().epoch, 1);
}
