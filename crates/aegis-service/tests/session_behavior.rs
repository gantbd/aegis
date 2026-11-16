use aegis_authority::{EngineId, Limits, PrincipalId, SessionId};
use aegis_host::DurableAuthority;
use aegis_protocol::{
    ActionV1, CommandV1, EngineNamespaceV1, OutcomeV1, RefusalV1, ReplyV1, ScopeV1,
};
use aegis_service::{AuthenticatedSessionV1, Service, ServiceLimitsV1};
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::{
    convert::Infallible,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Store(Option<Checkpoint>);

impl CheckpointStore for Store {
    type Error = Infallible;

    fn load(&self, _: &str) -> Result<Option<Checkpoint>, Self::Error> {
        Ok(self.0.clone())
    }

    fn compare_exchange(
        &mut self,
        _: &str,
        expected: Option<Revision>,
        bytes: &[u8],
    ) -> Result<CommitOutcome, Self::Error> {
        let actual = self.0.as_ref().map(|checkpoint| checkpoint.revision);
        if actual != expected {
            return Ok(CommitOutcome::Refused(StoreRefusal::RevisionConflict {
                expected,
                actual,
            }));
        }
        let revision = Revision(actual.map_or(0, |revision| revision.0 + 1));
        self.0 = Some(Checkpoint {
            revision,
            bytes: bytes.to_vec(),
            strength: AcknowledgementStrength::Durable,
        });
        Ok(CommitOutcome::Committed(CommitReceipt {
            revision,
            mechanism: "test-strong-store",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

fn issue() -> CommandV1 {
    CommandV1::Issue {
        expected_epoch: 0,
        now: 1,
        expires_at: 10,
        scopes: vec![ScopeV1 {
            engine: EngineNamespaceV1::Hermes,
            resource: [7; 16],
            actions: (1 << ActionV1::Observe as u8) | (1 << ActionV1::Delegate as u8),
        }],
    }
}

#[test]
fn handles_are_session_local_paged_and_destroyed_by_epoch_or_disconnect() {
    let authority_id = EngineId::new([1; 16]);
    let authority =
        DurableAuthority::create_new(Store::default(), authority_id, Limits::default()).unwrap();
    let mut service = Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap();
    let admin = service
        .open_session(AuthenticatedSessionV1 {
            principal: PrincipalId::new([2; 16]),
            session: SessionId::new([3; 16]),
            administrator: true,
        })
        .unwrap();
    let user = service
        .open_session(AuthenticatedSessionV1 {
            principal: PrincipalId::new([4; 16]),
            session: SessionId::new([5; 16]),
            administrator: false,
        })
        .unwrap();

    assert_eq!(
        service.execute(user, issue()).unwrap(),
        ReplyV1::Refused(RefusalV1::NotAdministrator)
    );
    let ReplyV1::Accepted(OutcomeV1::GrantIssued(root)) = service.execute(admin, issue()).unwrap()
    else {
        panic!("admin issue must return a server-held handle");
    };
    assert_eq!(
        service
            .execute(
                user,
                CommandV1::Authorize {
                    grant: root.handle,
                    now: 2,
                    engine: EngineNamespaceV1::Hermes,
                    resource: [7; 16],
                    action: ActionV1::Observe,
                },
            )
            .unwrap(),
        ReplyV1::Refused(RefusalV1::GrantOwnedByAnotherSession)
    );
    assert!(matches!(
        service
            .execute(
                admin,
                CommandV1::Authorize {
                    grant: root.handle,
                    now: 2,
                    engine: EngineNamespaceV1::Hermes,
                    resource: [7; 16],
                    action: ActionV1::Observe,
                },
            )
            .unwrap(),
        ReplyV1::Accepted(OutcomeV1::Authorized(_))
    ));
    let ReplyV1::Accepted(OutcomeV1::GrantIssued(child)) = service
        .execute(
            admin,
            CommandV1::Attenuate {
                parent: root.handle,
                expected_epoch: 0,
                now: 2,
                expires_at: 8,
                scopes: vec![ScopeV1 {
                    engine: EngineNamespaceV1::Hermes,
                    resource: [7; 16],
                    actions: 1 << ActionV1::Observe as u8,
                }],
            },
        )
        .unwrap()
    else {
        panic!("attenuation must return a child handle");
    };
    assert_eq!(child.parent, Some(root.handle));
    assert_eq!(child.delegation_depth, 1);

    let ReplyV1::Accepted(OutcomeV1::GrantPage { entries, .. }) = service
        .execute(
            admin,
            CommandV1::GrantPage {
                after: None,
                limit: 8,
            },
        )
        .unwrap()
    else {
        panic!("admin page expected");
    };
    assert_eq!(entries, vec![root, child]);
    assert!(matches!(
        service.execute(admin, CommandV1::Status).unwrap(),
        ReplyV1::Accepted(OutcomeV1::Status(status))
            if status.epoch == 0 && status.active_grants == 2 && status.retained_decisions == 1
    ));

    assert!(matches!(
        service
            .execute(admin, CommandV1::RevokeEpoch { expected_epoch: 0 })
            .unwrap(),
        ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 1 })
    ));
    assert_eq!(
        service
            .execute(
                admin,
                CommandV1::Authorize {
                    grant: root.handle,
                    now: 2,
                    engine: EngineNamespaceV1::Hermes,
                    resource: [7; 16],
                    action: ActionV1::Observe,
                },
            )
            .unwrap(),
        ReplyV1::Refused(RefusalV1::UnknownGrant)
    );
    assert!(service.close_session(admin));
    assert_eq!(
        service
            .execute(
                admin,
                CommandV1::DecisionPage {
                    after: None,
                    limit: 1,
                },
            )
            .unwrap(),
        ReplyV1::Refused(RefusalV1::UnknownSession)
    );
}

#[test]
fn stale_epoch_guards_refuse_without_mutating_authority_or_handles() {
    let authority_id = EngineId::new([1; 16]);
    let authority =
        DurableAuthority::create_new(Store::default(), authority_id, Limits::default()).unwrap();
    let mut service = Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap();
    let admin = service
        .open_session(AuthenticatedSessionV1 {
            principal: PrincipalId::new([2; 16]),
            session: SessionId::new([3; 16]),
            administrator: true,
        })
        .unwrap();

    let mut stale_issue = issue();
    if let CommandV1::Issue { expected_epoch, .. } = &mut stale_issue {
        *expected_epoch = 9;
    }
    assert_eq!(
        service.execute(admin, stale_issue).unwrap(),
        ReplyV1::Refused(RefusalV1::StaleEpoch { actual: 0 })
    );
    assert_eq!(
        service
            .execute(admin, CommandV1::RevokeEpoch { expected_epoch: 9 })
            .unwrap(),
        ReplyV1::Refused(RefusalV1::StaleEpoch { actual: 0 })
    );
    let ReplyV1::Accepted(OutcomeV1::GrantIssued(root)) = service.execute(admin, issue()).unwrap()
    else {
        panic!("fresh issue expected");
    };
    assert_eq!(root.handle.0, 0);
    assert_eq!(
        service
            .execute(
                admin,
                CommandV1::Attenuate {
                    parent: root.handle,
                    expected_epoch: 9,
                    now: 2,
                    expires_at: 8,
                    scopes: vec![ScopeV1 {
                        engine: EngineNamespaceV1::Hermes,
                        resource: [7; 16],
                        actions: 1 << ActionV1::Observe as u8,
                    }],
                },
            )
            .unwrap(),
        ReplyV1::Refused(RefusalV1::StaleEpoch { actual: 0 })
    );
    assert!(matches!(
        service.execute(admin, CommandV1::Status).unwrap(),
        ReplyV1::Accepted(OutcomeV1::Status(status))
            if status.epoch == 0 && status.active_grants == 1
    ));
}

#[test]
#[ignore = "opt-in deterministic authenticated-service lifecycle soak"]
fn five_thousand_service_lifecycles_preserve_authority_and_session_boundaries() {
    for cycle in 0_u64..5_000 {
        let authority_id = EngineId::new([1; 16]);
        let authority =
            DurableAuthority::create_new(Store::default(), authority_id, Limits::default())
                .unwrap();
        let mut service =
            Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap();
        let admin = service
            .open_session(AuthenticatedSessionV1 {
                principal: PrincipalId::new([2; 16]),
                session: SessionId::new([3; 16]),
                administrator: true,
            })
            .unwrap();
        let ReplyV1::Accepted(OutcomeV1::GrantIssued(grant)) =
            service.execute(admin, issue()).unwrap()
        else {
            panic!("cycle {cycle}: grant issuance expected")
        };
        assert!(matches!(
            service
                .execute(
                    admin,
                    CommandV1::Authorize {
                        grant: grant.handle,
                        now: 2,
                        engine: EngineNamespaceV1::Hermes,
                        resource: [7; 16],
                        action: ActionV1::Observe,
                    },
                )
                .unwrap(),
            ReplyV1::Accepted(OutcomeV1::Authorized(_))
        ));
        assert!(matches!(
            service
                .execute(admin, CommandV1::RevokeEpoch { expected_epoch: 0 })
                .unwrap(),
            ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 1 })
        ));
        assert_eq!(
            service
                .execute(
                    admin,
                    CommandV1::Authorize {
                        grant: grant.handle,
                        now: 2,
                        engine: EngineNamespaceV1::Hermes,
                        resource: [7; 16],
                        action: ActionV1::Observe,
                    },
                )
                .unwrap(),
            ReplyV1::Refused(RefusalV1::UnknownGrant),
            "cycle {cycle}"
        );
        assert!(service.close_session(admin));
    }
}

fn percentile(samples: &mut [Duration], percent: usize) -> Duration {
    assert!(!samples.is_empty());
    assert!((1..=100).contains(&percent));
    samples.sort_unstable();
    samples[(samples.len() * percent).div_ceil(100) - 1]
}

fn report(operation: &str, samples: &mut [Duration]) {
    let p50 = percentile(samples, 50);
    let p95 = percentile(samples, 95);
    let p99 = percentile(samples, 99);
    println!(
        "operation={operation} count={} p50_ns={} p95_ns={} p99_ns={} max_ns={}",
        samples.len(),
        p50.as_nanos(),
        p95.as_nanos(),
        p99.as_nanos(),
        samples.last().unwrap().as_nanos()
    );
    assert!(
        p95 <= Duration::from_millis(10),
        "{operation}: provisional p95 engineering budget exceeded"
    );
    assert!(
        p99 <= Duration::from_millis(25),
        "{operation}: provisional p99 engineering budget exceeded"
    );
}

#[test]
#[ignore = "explicit optimized reference-host performance acceptance gate"]
fn local_candidate_performance_gate() {
    if cfg!(debug_assertions) {
        panic!("qualification requires --release");
    }
    const SAMPLES: usize = 64;
    println!(
        "profile=receipt_gated_in_memory samples={SAMPLES} os={} arch={} optimized=true p95_budget_ms=10 p99_budget_ms=25",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let mut issues = Vec::with_capacity(SAMPLES);
    let mut authorizations = Vec::with_capacity(SAMPLES);
    let mut revocations = Vec::with_capacity(SAMPLES);
    let mut recoveries = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let authority_id = EngineId::new([1; 16]);
        let authority =
            DurableAuthority::create_new(Store::default(), authority_id, Limits::default())
                .unwrap();
        let mut service =
            Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap();
        let admin = service
            .open_session(AuthenticatedSessionV1 {
                principal: PrincipalId::new([2; 16]),
                session: SessionId::new([3; 16]),
                administrator: true,
            })
            .unwrap();

        let started = Instant::now();
        let ReplyV1::Accepted(OutcomeV1::GrantIssued(grant)) =
            service.execute(admin, issue()).unwrap()
        else {
            panic!("grant issuance expected")
        };
        issues.push(started.elapsed());

        let started = Instant::now();
        assert!(matches!(
            service
                .execute(
                    admin,
                    CommandV1::Authorize {
                        grant: grant.handle,
                        now: 2,
                        engine: EngineNamespaceV1::Hermes,
                        resource: [7; 16],
                        action: ActionV1::Observe,
                    },
                )
                .unwrap(),
            ReplyV1::Accepted(OutcomeV1::Authorized(_))
        ));
        authorizations.push(started.elapsed());

        let started = Instant::now();
        assert!(matches!(
            service
                .execute(admin, CommandV1::RevokeEpoch { expected_epoch: 0 })
                .unwrap(),
            ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 1 })
        ));
        revocations.push(started.elapsed());

        let store = service.into_authority().into_store();
        let started = Instant::now();
        let recovered = DurableAuthority::open(store, authority_id, Limits::default()).unwrap();
        recoveries.push(started.elapsed());
        assert_eq!(recovered.epoch().unwrap().0, 2);
    }

    report("issue", &mut issues);
    report("authorize", &mut authorizations);
    report("revoke_epoch", &mut revocations);
    report("recover_and_advance_epoch", &mut recoveries);
}
