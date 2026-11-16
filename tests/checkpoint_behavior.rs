use aegis_authority::{
    ActionSetV1, ActionV1, AuthorityEpoch, AuthorizationRequestV1, Engine, EngineId,
    EngineNamespaceV1, GrantDescriptorV1, Limits, LogicalTime, PrincipalId, RefusalV1, ResourceId,
    ResourceScopeV1,
    persistence::{CHECKPOINT_BYTES_V1, CheckpointErrorV1},
};

fn id() -> EngineId {
    EngineId::new([1; 16])
}
fn decode_fixture(source: &str) -> Vec<u8> {
    let source = source.trim();
    assert_eq!(source.len() % 2, 0);
    source
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}
fn descriptor(epoch: AuthorityEpoch) -> GrantDescriptorV1 {
    GrantDescriptorV1::new(
        PrincipalId::new([2; 16]),
        None,
        id(),
        epoch,
        LogicalTime(50),
        vec![ResourceScopeV1::new(
            EngineNamespaceV1::Hermes,
            ResourceId::new([3; 16]),
            ActionSetV1::top(),
        )],
    )
}
fn request() -> AuthorizationRequestV1 {
    AuthorizationRequestV1::new(
        PrincipalId::new([2; 16]),
        None,
        EngineNamespaceV1::Hermes,
        ResourceId::new([3; 16]),
        ActionV1::Observe,
    )
}

#[test]
fn fixed_golden_checkpoint_contains_only_namespace_epoch_and_frontiers() {
    let engine = Engine::try_new(id(), Limits::default()).unwrap();
    let cp = engine.checkpoint();
    let fixture = decode_fixture(include_str!("fixtures/checkpoint-v1-empty.hex"));
    assert_eq!(cp.len(), CHECKPOINT_BYTES_V1);
    assert_eq!(cp.as_slice(), fixture);
    let recovered = Engine::recover_checkpoint(&fixture, id(), Limits::default()).unwrap();
    assert_eq!(recovered.epoch(), AuthorityEpoch(1));
    assert_eq!(recovered.allocation_frontiers(), (0, 0));
}

#[test]
fn recovery_fences_old_grants_retains_frontiers_and_requires_fresh_issue() {
    let mut engine = Engine::try_new(id(), Limits::default()).unwrap();
    let grant = engine
        .issue(descriptor(engine.epoch()), LogicalTime(1))
        .unwrap();
    let evidence = engine.validate(&grant, &request(), LogicalTime(2)).unwrap();
    let cp = engine.checkpoint();
    assert_eq!(
        cp.as_slice(),
        decode_fixture(include_str!("fixtures/checkpoint-v1-live.hex"))
    );
    let mut recovered = Engine::recover_checkpoint(&cp, id(), Limits::default()).unwrap();
    assert_eq!(recovered.epoch(), AuthorityEpoch(1));
    assert_eq!(recovered.allocation_frontiers(), (1, 1));
    assert_eq!(
        recovered.validate(&grant, &request(), LogicalTime(2)),
        Err(RefusalV1::Revoked)
    );
    assert_eq!(
        recovered.issue(descriptor(AuthorityEpoch(0)), LogicalTime(2)),
        Err(RefusalV1::InvalidEpoch)
    );
    let fresh = recovered
        .issue(descriptor(recovered.epoch()), LogicalTime(2))
        .unwrap();
    let fresh_evidence = recovered
        .validate(&fresh, &request(), LogicalTime(2))
        .unwrap();
    assert_ne!(
        evidence.decision_id_bytes(),
        fresh_evidence.decision_id_bytes()
    );
    let again =
        Engine::recover_checkpoint(&recovered.checkpoint(), id(), Limits::default()).unwrap();
    assert_eq!(again.epoch(), AuthorityEpoch(2));
    assert_eq!(again.allocation_frontiers(), (2, 2));
}

#[test]
fn preparation_does_not_publish_and_refusals_leave_canonical_state_unchanged() {
    let engine = Engine::try_new(id(), Limits::default()).unwrap();
    let original = engine.checkpoint();
    let prepared = engine
        .prepare_issue(descriptor(engine.epoch()), LogicalTime(1))
        .unwrap();
    assert_eq!(engine.checkpoint(), original);
    assert_ne!(prepared.checkpoint(), original);
    drop(prepared);
    assert_eq!(engine.checkpoint(), original);
    assert!(
        engine
            .prepare_issue(descriptor(engine.epoch()), LogicalTime(50))
            .is_err()
    );
    assert_eq!(engine.checkpoint(), original);
    let (next, _) = engine.prepare_revocation().unwrap().publish();
    assert_eq!(next.epoch(), AuthorityEpoch(1));
    assert_eq!(engine.epoch(), AuthorityEpoch(0));
}

#[test]
fn every_truncation_unknown_version_wrong_namespace_and_epoch_wrap_refuse() {
    let cp = Engine::try_new(id(), Limits::default())
        .unwrap()
        .checkpoint();
    for size in 0..cp.len() {
        assert!(Engine::recover_checkpoint(&cp[..size], id(), Limits::default()).is_err());
    }
    let mut trailing = cp.to_vec();
    trailing.push(0);
    assert!(Engine::recover_checkpoint(&trailing, id(), Limits::default()).is_err());
    let mut version = cp;
    version[7] = 2;
    assert_eq!(
        Engine::recover_checkpoint(&version, id(), Limits::default()).unwrap_err(),
        CheckpointErrorV1::UnsupportedVersion
    );
    assert_eq!(
        Engine::recover_checkpoint(&cp, EngineId::new([2; 16]), Limits::default()).unwrap_err(),
        CheckpointErrorV1::WrongNamespace
    );
    let mut exhausted = cp;
    exhausted[24..32].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        Engine::recover_checkpoint(&exhausted, id(), Limits::default()).unwrap_err(),
        CheckpointErrorV1::EpochExhausted
    );
    assert_eq!(
        Engine::recover_checkpoint(
            &cp,
            id(),
            Limits {
                max_scopes_per_grant: 0,
                ..Limits::default()
            }
        )
        .unwrap_err(),
        CheckpointErrorV1::Disabled
    );
}

#[test]
fn exhausted_identity_frontiers_cannot_wrap_or_partially_change_state() {
    let mut cp = Engine::try_new(id(), Limits::default())
        .unwrap()
        .checkpoint();
    cp[32..40].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut engine = Engine::recover_checkpoint(&cp, id(), Limits::default()).unwrap();
    let before = engine.checkpoint();
    assert_eq!(
        engine.issue(descriptor(engine.epoch()), LogicalTime(1)),
        Err(RefusalV1::IdentityExhausted)
    );
    assert_eq!(engine.checkpoint(), before);
}

#[test]
fn finite_recovery_programs_preserve_frontiers_and_strictly_advance_epoch() {
    // Independently calculate expected counters for all 4^5 bounded programs.
    for program in 0..1024_u32 {
        let mut encoded = program;
        let mut engine = Engine::try_new(id(), Limits::default()).unwrap();
        let (mut epoch, mut grants) = (0_u64, 0_u64);
        for _ in 0..5 {
            match encoded % 4 {
                0 => {
                    engine
                        .issue(descriptor(AuthorityEpoch(epoch)), LogicalTime(1))
                        .unwrap();
                    grants += 1;
                }
                1 => {
                    engine.revoke_epoch().unwrap();
                    epoch += 1;
                }
                2 => {
                    engine =
                        Engine::recover_checkpoint(&engine.checkpoint(), id(), Limits::default())
                            .unwrap();
                    epoch += 1;
                }
                3 => {
                    assert!(
                        engine
                            .issue(descriptor(AuthorityEpoch(epoch)), LogicalTime(50))
                            .is_err()
                    );
                }
                _ => unreachable!(),
            }
            encoded /= 4;
            assert_eq!(engine.epoch(), AuthorityEpoch(epoch));
            assert_eq!(engine.allocation_frontiers(), (grants, 0));
        }
    }
}
