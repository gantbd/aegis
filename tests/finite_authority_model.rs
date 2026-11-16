//! Independent lifecycle model over a closed nine-command family.
//! Exhaustive finite programs are evidence for this domain, not a proof of
//! arbitrary histories, credential authentication or durable storage.
use aegis_authority::{
    ActionSetV1, ActionV1, AuthorityEpoch, AuthorizationRequestV1, Engine, EngineId,
    EngineNamespaceV1, GrantDescriptorV1, GrantV1, Limits, LogicalTime, PrincipalId, RefusalV1,
    ResourceId, ResourceScopeV1, SessionId,
};

#[derive(Clone, Copy)]
struct Fact {
    epoch: u64,
    expires: u64,
    depth: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Observation {
    Accepted,
    Unavailable,
    Refused(RefusalV1),
}

#[derive(Default)]
struct Reference {
    epoch: u64,
    next_grant: u64,
    next_decision: u64,
    root: Option<Fact>,
    child: Option<Fact>,
}

impl Reference {
    fn validate(&mut self, fact: Option<Fact>, now: u64) -> Observation {
        let Some(fact) = fact else {
            return Observation::Unavailable;
        };
        if fact.epoch != self.epoch {
            return Observation::Refused(RefusalV1::Revoked);
        }
        if fact.expires <= now {
            return Observation::Refused(RefusalV1::Expired);
        }
        if self.next_decision == u64::MAX {
            return Observation::Refused(RefusalV1::IdentityExhausted);
        }
        self.next_decision += 1;
        Observation::Accepted
    }

    fn apply(&mut self, action: u32) -> Observation {
        match action {
            0 => {
                if self.next_grant == u64::MAX {
                    return Observation::Refused(RefusalV1::IdentityExhausted);
                }
                self.root = Some(Fact {
                    epoch: self.epoch,
                    expires: 3,
                    depth: 0,
                });
                self.next_grant += 1;
                Observation::Accepted
            }
            1 => {
                let Some(parent) = self.root else {
                    return Observation::Unavailable;
                };
                if parent.epoch != self.epoch {
                    return Observation::Refused(RefusalV1::Revoked);
                }
                if parent.expires <= 1 {
                    return Observation::Refused(RefusalV1::Expired);
                }
                if self.next_grant == u64::MAX {
                    return Observation::Refused(RefusalV1::IdentityExhausted);
                }
                self.child = Some(Fact {
                    epoch: self.epoch,
                    expires: 2,
                    depth: parent.depth + 1,
                });
                self.next_grant += 1;
                Observation::Accepted
            }
            2 => self.validate(self.root, 1),
            3 => self.validate(self.child, 1),
            4 => self.validate(self.root, 3),
            5 => {
                if self.epoch == u64::MAX {
                    Observation::Refused(RefusalV1::IdentityExhausted)
                } else {
                    self.epoch += 1;
                    Observation::Accepted
                }
            }
            6 => {
                self.epoch += 1;
                Observation::Accepted
            }
            7 => {
                self.epoch += 1;
                self.next_grant = u64::MAX;
                Observation::Accepted
            }
            8 => {
                self.epoch += 1;
                self.next_decision = u64::MAX;
                Observation::Accepted
            }
            _ => unreachable!("closed model command family"),
        }
    }
}

struct Actual {
    engine: Engine,
    root: Option<GrantV1>,
    child: Option<GrantV1>,
}

fn engine_id() -> EngineId {
    EngineId::new([1; 16])
}

fn descriptor(epoch: AuthorityEpoch) -> GrantDescriptorV1 {
    GrantDescriptorV1::new(
        PrincipalId::new([2; 16]),
        Some(SessionId::new([3; 16])),
        engine_id(),
        epoch,
        LogicalTime(3),
        vec![ResourceScopeV1::new(
            EngineNamespaceV1::Hermes,
            ResourceId::new([4; 16]),
            ActionSetV1::singleton(ActionV1::Observe)
                .join(ActionSetV1::singleton(ActionV1::Delegate)),
        )],
    )
}

fn request() -> AuthorizationRequestV1 {
    AuthorizationRequestV1::new(
        PrincipalId::new([2; 16]),
        Some(SessionId::new([3; 16])),
        EngineNamespaceV1::Hermes,
        ResourceId::new([4; 16]),
        ActionV1::Observe,
    )
}

fn observe<T>(result: Result<T, RefusalV1>) -> Observation {
    match result {
        Ok(_) => Observation::Accepted,
        Err(error) => Observation::Refused(error),
    }
}

impl Actual {
    fn apply(&mut self, action: u32) -> Observation {
        match action {
            0 => match self
                .engine
                .issue(descriptor(self.engine.epoch()), LogicalTime(0))
            {
                Ok(grant) => {
                    self.root = Some(grant);
                    Observation::Accepted
                }
                Err(error) => Observation::Refused(error),
            },
            1 => {
                let Some(parent) = self.root.as_ref() else {
                    return Observation::Unavailable;
                };
                match self.engine.attenuate(
                    parent,
                    PrincipalId::new([2; 16]),
                    Some(SessionId::new([3; 16])),
                    LogicalTime(2),
                    vec![ResourceScopeV1::new(
                        EngineNamespaceV1::Hermes,
                        ResourceId::new([4; 16]),
                        ActionSetV1::singleton(ActionV1::Observe),
                    )],
                    LogicalTime(1),
                ) {
                    Ok(grant) => {
                        self.child = Some(grant);
                        Observation::Accepted
                    }
                    Err(error) => Observation::Refused(error),
                }
            }
            2 => self
                .root
                .as_ref()
                .map_or(Observation::Unavailable, |grant| {
                    observe(self.engine.validate(grant, &request(), LogicalTime(1)))
                }),
            3 => self
                .child
                .as_ref()
                .map_or(Observation::Unavailable, |grant| {
                    observe(self.engine.validate(grant, &request(), LogicalTime(1)))
                }),
            4 => self
                .root
                .as_ref()
                .map_or(Observation::Unavailable, |grant| {
                    observe(self.engine.validate(grant, &request(), LogicalTime(3)))
                }),
            5 => observe(self.engine.revoke_epoch()),
            6..=8 => {
                let mut checkpoint = self.engine.checkpoint();
                if action == 7 {
                    checkpoint[32..40].copy_from_slice(&u64::MAX.to_be_bytes());
                } else if action == 8 {
                    checkpoint[40..48].copy_from_slice(&u64::MAX.to_be_bytes());
                }
                self.engine =
                    Engine::recover_checkpoint(&checkpoint, engine_id(), Limits::default())
                        .expect("the model never reaches epoch exhaustion");
                Observation::Accepted
            }
            _ => unreachable!("closed model command family"),
        }
    }
}

#[test]
fn all_five_step_lifecycle_programs_match_the_independent_model() {
    for program in 0_u32..9_u32.pow(5) {
        let mut reference = Reference::default();
        let mut actual = Actual {
            engine: Engine::try_new(engine_id(), Limits::default()).unwrap(),
            root: None,
            child: None,
        };
        let mut word = program;
        for step in 0..5 {
            let action = word % 9;
            word /= 9;
            assert_eq!(
                actual.apply(action),
                reference.apply(action),
                "program {program}, step {step}, action {action}"
            );
            assert_eq!(actual.engine.epoch(), AuthorityEpoch(reference.epoch));
            assert_eq!(
                actual.engine.allocation_frontiers(),
                (reference.next_grant, reference.next_decision)
            );
        }
    }
}
