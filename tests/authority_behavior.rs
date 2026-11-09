use aegis_authority::{
    ActionSetV1, ActionV1, AuthorityEpoch, AuthorizationRequestV1, Engine, EngineId,
    EngineNamespaceV1, GrantDescriptorV1, Limits, LogicalTime, PrincipalId, RefusalV1, ResourceId,
    ResourceScopeV1,
};

fn scope(actions: ActionSetV1) -> ResourceScopeV1 {
    ResourceScopeV1::new(EngineNamespaceV1::Daimon, ResourceId::new([4; 16]), actions)
}

#[test]
fn action_sets_form_a_bounded_lattice() {
    let execute = ActionSetV1::singleton(ActionV1::Execute);
    let observe = ActionSetV1::singleton(ActionV1::Observe);
    let joined = execute.join(observe);

    assert_eq!(execute.meet(observe), ActionSetV1::bottom());
    assert!(execute.is_subset_of(joined));
    assert_eq!(joined.meet(execute), execute);
    assert_eq!(execute.join(ActionSetV1::top()), ActionSetV1::top());
}

#[test]
fn validation_issues_redacted_attributable_evidence_and_epoch_revocation_fences_it() {
    let engine_id = EngineId::new([1; 16]);
    let subject = PrincipalId::new([2; 16]);
    let mut engine = Engine::try_new(engine_id, Limits::default()).unwrap();
    let grant = engine
        .issue(
            GrantDescriptorV1::new(
                subject,
                None,
                engine_id,
                AuthorityEpoch(0),
                LogicalTime(20),
                vec![scope(ActionSetV1::singleton(ActionV1::Execute))],
            ),
            LogicalTime(10),
        )
        .unwrap();
    let request = AuthorizationRequestV1::new(
        subject,
        None,
        EngineNamespaceV1::Daimon,
        ResourceId::new([4; 16]),
        ActionV1::Execute,
    );
    let evidence = engine.validate(&grant, &request, LogicalTime(11)).unwrap();
    assert_eq!(evidence.subject(), subject);
    assert!(!format!("{evidence:?}").contains("1, 1, 1"));

    engine.revoke_epoch().unwrap();
    assert_eq!(
        engine.validate(&grant, &request, LogicalTime(11)),
        Err(RefusalV1::Revoked)
    );
}

#[test]
fn attenuation_cannot_amplify_action_or_expiry() {
    let engine_id = EngineId::new([1; 16]);
    let mut engine = Engine::try_new(engine_id, Limits::default()).unwrap();
    let parent = engine
        .issue(
            GrantDescriptorV1::new(
                PrincipalId::new([2; 16]),
                None,
                engine_id,
                AuthorityEpoch(0),
                LogicalTime(20),
                vec![scope(
                    ActionSetV1::singleton(ActionV1::Observe)
                        .join(ActionSetV1::singleton(ActionV1::Delegate)),
                )],
            ),
            LogicalTime(10),
        )
        .unwrap();

    assert_eq!(
        engine.attenuate(
            &parent,
            PrincipalId::new([3; 16]),
            None,
            LogicalTime(19),
            vec![scope(ActionSetV1::singleton(ActionV1::Execute))],
            LogicalTime(11),
        ),
        Err(RefusalV1::ScopeAmplification)
    );
    assert_eq!(
        engine.attenuate(
            &parent,
            PrincipalId::new([3; 16]),
            None,
            LogicalTime(21),
            vec![scope(ActionSetV1::singleton(ActionV1::Observe))],
            LogicalTime(11),
        ),
        Err(RefusalV1::ExpiryAmplification)
    );
}

#[test]
fn attenuation_requires_explicit_delegate_authority() {
    let engine_id = EngineId::new([1; 16]);
    let mut engine = Engine::try_new(engine_id, Limits::default()).unwrap();
    let parent = engine
        .issue(
            GrantDescriptorV1::new(
                PrincipalId::new([2; 16]),
                None,
                engine_id,
                AuthorityEpoch(0),
                LogicalTime(20),
                vec![scope(ActionSetV1::singleton(ActionV1::Observe))],
            ),
            LogicalTime(10),
        )
        .unwrap();

    assert_eq!(
        engine.attenuate(
            &parent,
            PrincipalId::new([3; 16]),
            None,
            LogicalTime(19),
            vec![scope(ActionSetV1::singleton(ActionV1::Observe))],
            LogicalTime(11),
        ),
        Err(RefusalV1::NotAuthorized)
    );
}
