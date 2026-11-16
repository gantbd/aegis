use std::collections::BTreeMap;

use aegis_client::{Client, ServicePort};
use aegis_protocol::{
    ActionV1, CommandV1, DecisionSummaryV1, EngineNamespaceV1, GrantHandleV1, OutcomeV1, RefusalV1,
    ReplyV1, ScopeV1, SessionHandleV1,
};

use crate::{action_name, engine_name};

pub const MANAGED_CAPABILITY: &str = "authority.manage-session.v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperationIdV1([u8; 16]);

impl OperationIdV1 {
    pub const fn new(value: [u8; 16]) -> Self {
        Self(value)
    }

    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedLimitsV1 {
    pub max_grants: usize,
    pub max_scopes_per_grant: usize,
}

impl Default for ManagedLimitsV1 {
    fn default() -> Self {
        Self {
            max_grants: 64,
            max_scopes_per_grant: 16,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedSessionStateV1 {
    Ready,
    Fenced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueGrantV1 {
    pub operation: OperationIdV1,
    pub expected_epoch: u64,
    pub now: u64,
    pub expires_at: u64,
    pub scopes: Vec<ScopeV1>,
}

impl IssueGrantV1 {
    pub fn confirmation(&self) -> String {
        format!(
            "ISSUE AEGIS OP {} EPOCH {} UNTIL {} SCOPES {}",
            operation_hex(self.operation),
            self.expected_epoch,
            self.expires_at,
            scopes_text(&self.scopes)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttenuateGrantV1 {
    pub operation: OperationIdV1,
    pub parent: OperationIdV1,
    pub expected_epoch: u64,
    pub now: u64,
    pub expires_at: u64,
    pub scopes: Vec<ScopeV1>,
}

impl AttenuateGrantV1 {
    pub fn confirmation(&self) -> String {
        format!(
            "ATTENUATE AEGIS OP {} FROM {} EPOCH {} UNTIL {} SCOPES {}",
            operation_hex(self.operation),
            operation_hex(self.parent),
            self.expected_epoch,
            self.expires_at,
            scopes_text(&self.scopes)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizeGrantV1 {
    pub operation: OperationIdV1,
    pub now: u64,
    pub engine: EngineNamespaceV1,
    pub resource: [u8; 16],
    pub action: ActionV1,
}

impl AuthorizeGrantV1 {
    pub fn confirmation(self) -> String {
        format!(
            "AUTHORIZE AEGIS OP {} {} {} {}",
            operation_hex(self.operation),
            engine_name(self.engine),
            bytes_hex(self.resource),
            action_name(self.action)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedGrantV1 {
    pub operation: OperationIdV1,
    pub parent: Option<OperationIdV1>,
    pub epoch: u64,
    pub expires_at: u64,
    pub scope_count: usize,
    pub delegation_depth: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedDecisionV1 {
    pub operation: OperationIdV1,
    pub epoch: u64,
    pub expires_at: u64,
    pub engine: EngineNamespaceV1,
    pub action: ActionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedPhaseV1 {
    Observe,
    Issue,
    Attenuate,
    Authorize,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ManagedErrorV1<E> {
    InvalidLimits,
    InvalidRequest,
    ConfirmationMismatch {
        required: String,
    },
    SessionFenced,
    OperationExists,
    OperationMissing,
    Capacity,
    StaleEpoch {
        expected: u64,
        actual: u64,
    },
    Transport {
        phase: ManagedPhaseV1,
        error: E,
    },
    Refused {
        phase: ManagedPhaseV1,
        refusal: RefusalV1,
    },
    InvalidReply {
        phase: ManagedPhaseV1,
    },
}

#[derive(Clone, Copy)]
struct RetainedGrantV1 {
    handle: GrantHandleV1,
    public: ManagedGrantV1,
}

/// Owns a bounded set of named, session-local grants on one authenticated
/// public-client connection. Numeric handles never leave this value. Any
/// transport uncertainty or impossible reply terminally fences the owner;
/// callers must drop it, reconnect, and explicitly rebuild authority.
pub struct ManagedSessionV1<P: ServicePort> {
    client: Client<P>,
    limits: ManagedLimitsV1,
    state: ManagedSessionStateV1,
    grants: BTreeMap<OperationIdV1, RetainedGrantV1>,
}

impl<P: ServicePort> ManagedSessionV1<P> {
    pub fn new(
        session: SessionHandleV1,
        port: P,
        limits: ManagedLimitsV1,
    ) -> Result<Self, ManagedErrorV1<P::Error>> {
        if limits.max_grants == 0 || limits.max_scopes_per_grant == 0 {
            return Err(ManagedErrorV1::InvalidLimits);
        }
        Ok(Self {
            client: Client::new(session, port),
            limits,
            state: ManagedSessionStateV1::Ready,
            grants: BTreeMap::new(),
        })
    }

    pub const fn state(&self) -> ManagedSessionStateV1 {
        self.state
    }

    pub fn retained(&self) -> Vec<ManagedGrantV1> {
        self.grants.values().map(|grant| grant.public).collect()
    }

    pub fn issue(
        &mut self,
        request: IssueGrantV1,
        confirmation: &str,
    ) -> Result<ManagedGrantV1, ManagedErrorV1<P::Error>> {
        self.require_ready()?;
        confirm(&request.confirmation(), confirmation)?;
        self.validate_new(
            request.operation,
            request.now,
            request.expires_at,
            &request.scopes,
        )?;
        self.observe_epoch(request.expected_epoch)?;
        let command = CommandV1::Issue {
            expected_epoch: request.expected_epoch,
            now: request.now,
            expires_at: request.expires_at,
            scopes: request.scopes.clone(),
        };
        let reply = self.execute_mutation(ManagedPhaseV1::Issue, command)?;
        let ReplyV1::Accepted(OutcomeV1::GrantIssued(summary)) = reply else {
            return self.classify_non_grant(ManagedPhaseV1::Issue, reply);
        };
        if summary.parent.is_some()
            || summary.epoch != request.expected_epoch
            || summary.expires_at != request.expires_at
            || summary.scope_count != request.scopes.len()
            || summary.delegation_depth != 0
            || self
                .grants
                .values()
                .any(|grant| grant.handle == summary.handle)
        {
            return self.fence_invalid(ManagedPhaseV1::Issue);
        }
        let public = ManagedGrantV1 {
            operation: request.operation,
            parent: None,
            epoch: summary.epoch,
            expires_at: summary.expires_at,
            scope_count: summary.scope_count,
            delegation_depth: summary.delegation_depth,
        };
        self.grants.insert(
            request.operation,
            RetainedGrantV1 {
                handle: summary.handle,
                public,
            },
        );
        Ok(public)
    }

    pub fn attenuate(
        &mut self,
        request: AttenuateGrantV1,
        confirmation: &str,
    ) -> Result<ManagedGrantV1, ManagedErrorV1<P::Error>> {
        self.require_ready()?;
        confirm(&request.confirmation(), confirmation)?;
        self.validate_new(
            request.operation,
            request.now,
            request.expires_at,
            &request.scopes,
        )?;
        let parent = self
            .grants
            .get(&request.parent)
            .copied()
            .ok_or(ManagedErrorV1::OperationMissing)?;
        self.observe_epoch(request.expected_epoch)?;
        let command = CommandV1::Attenuate {
            parent: parent.handle,
            expected_epoch: request.expected_epoch,
            now: request.now,
            expires_at: request.expires_at,
            scopes: request.scopes.clone(),
        };
        let reply = self.execute_mutation(ManagedPhaseV1::Attenuate, command)?;
        let ReplyV1::Accepted(OutcomeV1::GrantIssued(summary)) = reply else {
            return self.classify_non_grant(ManagedPhaseV1::Attenuate, reply);
        };
        let Some(expected_depth) = parent.public.delegation_depth.checked_add(1) else {
            return self.fence_invalid(ManagedPhaseV1::Attenuate);
        };
        if summary.parent != Some(parent.handle)
            || summary.epoch != request.expected_epoch
            || summary.expires_at != request.expires_at
            || summary.scope_count != request.scopes.len()
            || summary.delegation_depth != expected_depth
            || self
                .grants
                .values()
                .any(|grant| grant.handle == summary.handle)
        {
            return self.fence_invalid(ManagedPhaseV1::Attenuate);
        }
        let public = ManagedGrantV1 {
            operation: request.operation,
            parent: Some(request.parent),
            epoch: summary.epoch,
            expires_at: summary.expires_at,
            scope_count: summary.scope_count,
            delegation_depth: summary.delegation_depth,
        };
        self.grants.insert(
            request.operation,
            RetainedGrantV1 {
                handle: summary.handle,
                public,
            },
        );
        Ok(public)
    }

    pub fn authorize(
        &mut self,
        request: AuthorizeGrantV1,
        confirmation: &str,
    ) -> Result<ManagedDecisionV1, ManagedErrorV1<P::Error>> {
        self.require_ready()?;
        confirm(&request.confirmation(), confirmation)?;
        let grant = self
            .grants
            .get(&request.operation)
            .copied()
            .ok_or(ManagedErrorV1::OperationMissing)?;
        let command = CommandV1::Authorize {
            grant: grant.handle,
            now: request.now,
            engine: request.engine,
            resource: request.resource,
            action: request.action,
        };
        let reply = self.execute_mutation(ManagedPhaseV1::Authorize, command)?;
        match reply {
            ReplyV1::Accepted(OutcomeV1::Authorized(decision))
                if valid_decision(request, grant.public, decision) =>
            {
                Ok(ManagedDecisionV1 {
                    operation: request.operation,
                    epoch: decision.epoch,
                    expires_at: decision.expires_at,
                    engine: decision.engine,
                    action: decision.action,
                })
            }
            ReplyV1::Refused(refusal) => Err(ManagedErrorV1::Refused {
                phase: ManagedPhaseV1::Authorize,
                refusal,
            }),
            _ => self.fence_invalid(ManagedPhaseV1::Authorize),
        }
    }

    fn validate_new(
        &self,
        operation: OperationIdV1,
        now: u64,
        expires_at: u64,
        scopes: &[ScopeV1],
    ) -> Result<(), ManagedErrorV1<P::Error>> {
        if self.grants.contains_key(&operation) {
            return Err(ManagedErrorV1::OperationExists);
        }
        if self.grants.len() >= self.limits.max_grants {
            return Err(ManagedErrorV1::Capacity);
        }
        if now >= expires_at
            || scopes.is_empty()
            || scopes.len() > self.limits.max_scopes_per_grant
            || scopes
                .iter()
                .any(|scope| scope.actions == 0 || scope.actions & !0b00_111111 != 0)
        {
            return Err(ManagedErrorV1::InvalidRequest);
        }
        Ok(())
    }

    fn observe_epoch(&mut self, expected: u64) -> Result<(), ManagedErrorV1<P::Error>> {
        let reply = self.client.execute(CommandV1::Status).map_err(|error| {
            self.state = ManagedSessionStateV1::Fenced;
            ManagedErrorV1::Transport {
                phase: ManagedPhaseV1::Observe,
                error,
            }
        })?;
        match reply {
            ReplyV1::Accepted(OutcomeV1::Status(status)) if status.epoch == expected => Ok(()),
            ReplyV1::Accepted(OutcomeV1::Status(status)) => Err(ManagedErrorV1::StaleEpoch {
                expected,
                actual: status.epoch,
            }),
            ReplyV1::Refused(refusal) => Err(ManagedErrorV1::Refused {
                phase: ManagedPhaseV1::Observe,
                refusal,
            }),
            _ => self.fence_invalid(ManagedPhaseV1::Observe),
        }
    }

    fn execute_mutation(
        &mut self,
        phase: ManagedPhaseV1,
        command: CommandV1,
    ) -> Result<ReplyV1, ManagedErrorV1<P::Error>> {
        self.client.execute(command).map_err(|error| {
            self.state = ManagedSessionStateV1::Fenced;
            ManagedErrorV1::Transport { phase, error }
        })
    }

    fn classify_non_grant<T>(
        &mut self,
        phase: ManagedPhaseV1,
        reply: ReplyV1,
    ) -> Result<T, ManagedErrorV1<P::Error>> {
        match reply {
            ReplyV1::Refused(refusal) => Err(ManagedErrorV1::Refused { phase, refusal }),
            _ => self.fence_invalid(phase),
        }
    }

    fn fence_invalid<T>(&mut self, phase: ManagedPhaseV1) -> Result<T, ManagedErrorV1<P::Error>> {
        self.state = ManagedSessionStateV1::Fenced;
        Err(ManagedErrorV1::InvalidReply { phase })
    }

    fn require_ready(&self) -> Result<(), ManagedErrorV1<P::Error>> {
        if self.state == ManagedSessionStateV1::Ready {
            Ok(())
        } else {
            Err(ManagedErrorV1::SessionFenced)
        }
    }
}

fn confirm<E>(required: &str, actual: &str) -> Result<(), ManagedErrorV1<E>> {
    if actual == required {
        Ok(())
    } else {
        Err(ManagedErrorV1::ConfirmationMismatch {
            required: required.to_owned(),
        })
    }
}

fn valid_decision(
    request: AuthorizeGrantV1,
    grant: ManagedGrantV1,
    decision: DecisionSummaryV1,
) -> bool {
    decision.epoch == grant.epoch
        && decision.expires_at <= grant.expires_at
        && decision.engine == request.engine
        && decision.action == request.action
}

fn scopes_text(scopes: &[ScopeV1]) -> String {
    scopes
        .iter()
        .map(|scope| {
            format!(
                "{}:{}:{}",
                engine_name(scope.engine),
                bytes_hex(scope.resource),
                actions_text(scope.actions)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn actions_text(actions: u8) -> String {
    [
        ActionV1::Observe,
        ActionV1::Submit,
        ActionV1::Modify,
        ActionV1::Execute,
        ActionV1::Delegate,
        ActionV1::Administer,
    ]
    .into_iter()
    .filter(|action| actions & (1 << *action as u8) != 0)
    .map(action_name)
    .collect::<Vec<_>>()
    .join("+")
}

fn operation_hex(operation: OperationIdV1) -> String {
    bytes_hex(operation.into_bytes())
}

fn bytes_hex<const N: usize>(bytes: [u8; N]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    use aegis_protocol::{AuthorityStatusV1, GrantSummaryV1};

    use super::*;

    struct Port {
        replies: VecDeque<Result<ReplyV1, &'static str>>,
        commands: Rc<RefCell<Vec<CommandV1>>>,
    }

    impl ServicePort for Port {
        type Error = &'static str;

        fn execute(
            &mut self,
            _: SessionHandleV1,
            command: CommandV1,
        ) -> Result<ReplyV1, Self::Error> {
            self.commands.borrow_mut().push(command);
            self.replies.pop_front().expect("scripted reply")
        }
    }

    fn operation(value: u8) -> OperationIdV1 {
        OperationIdV1::new([value; 16])
    }

    fn scope(actions: u8) -> ScopeV1 {
        ScopeV1 {
            engine: EngineNamespaceV1::Hermes,
            resource: [7; 16],
            actions,
        }
    }

    fn status(epoch: u64) -> ReplyV1 {
        ReplyV1::Accepted(OutcomeV1::Status(AuthorityStatusV1 {
            epoch,
            active_grants: 0,
            retained_decisions: 0,
        }))
    }

    fn grant(handle: u64, parent: Option<u64>, depth: u8, expires_at: u64) -> ReplyV1 {
        ReplyV1::Accepted(OutcomeV1::GrantIssued(GrantSummaryV1 {
            handle: GrantHandleV1(handle),
            parent: parent.map(GrantHandleV1),
            epoch: 4,
            expires_at,
            scope_count: 1,
            delegation_depth: depth,
        }))
    }

    fn manager(
        replies: Vec<Result<ReplyV1, &'static str>>,
    ) -> (ManagedSessionV1<Port>, Rc<RefCell<Vec<CommandV1>>>) {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let manager = ManagedSessionV1::new(
            SessionHandleV1(3),
            Port {
                replies: replies.into(),
                commands: Rc::clone(&commands),
            },
            ManagedLimitsV1 {
                max_grants: 2,
                max_scopes_per_grant: 1,
            },
        )
        .unwrap();
        (manager, commands)
    }

    #[test]
    fn named_issue_and_attenuation_keep_handles_private_across_commands() {
        let (mut manager, commands) = manager(vec![
            Ok(status(4)),
            Ok(grant(10, None, 0, 30)),
            Ok(status(4)),
            Ok(grant(11, Some(10), 1, 20)),
        ]);
        let issue = IssueGrantV1 {
            operation: operation(1),
            expected_epoch: 4,
            now: 5,
            expires_at: 30,
            scopes: vec![scope(
                (1 << ActionV1::Observe as u8) | (1 << ActionV1::Delegate as u8),
            )],
        };
        assert_eq!(
            manager
                .issue(issue.clone(), &issue.confirmation())
                .unwrap()
                .parent,
            None
        );
        let child = AttenuateGrantV1 {
            operation: operation(2),
            parent: operation(1),
            expected_epoch: 4,
            now: 6,
            expires_at: 20,
            scopes: vec![scope(1 << ActionV1::Observe as u8)],
        };
        assert_eq!(
            manager
                .attenuate(child.clone(), &child.confirmation())
                .unwrap()
                .parent,
            Some(operation(1))
        );
        assert_eq!(manager.retained().len(), 2);
        assert!(matches!(
            commands.borrow()[3],
            CommandV1::Attenuate {
                parent: GrantHandleV1(10),
                ..
            }
        ));
    }

    #[test]
    fn uncertain_mutation_terminally_fences_without_retry_or_handle_publication() {
        let (mut manager, commands) = manager(vec![Ok(status(4)), Err("outcome_unknown")]);
        let issue = IssueGrantV1 {
            operation: operation(1),
            expected_epoch: 4,
            now: 5,
            expires_at: 30,
            scopes: vec![scope(1 << ActionV1::Observe as u8)],
        };
        assert_eq!(
            manager.issue(issue.clone(), &issue.confirmation()),
            Err(ManagedErrorV1::Transport {
                phase: ManagedPhaseV1::Issue,
                error: "outcome_unknown"
            })
        );
        assert_eq!(manager.state(), ManagedSessionStateV1::Fenced);
        assert!(manager.retained().is_empty());
        assert_eq!(
            manager.issue(issue.clone(), &issue.confirmation()),
            Err(ManagedErrorV1::SessionFenced)
        );
        assert_eq!(commands.borrow().len(), 2);
    }

    #[test]
    fn named_authorization_returns_only_redacted_decision_facts() {
        let decision = DecisionSummaryV1 {
            handle: aegis_protocol::DecisionHandleV1(91),
            epoch: 4,
            expires_at: 30,
            engine: EngineNamespaceV1::Hermes,
            action: ActionV1::Observe,
        };
        let (mut manager, commands) = manager(vec![
            Ok(status(4)),
            Ok(grant(10, None, 0, 30)),
            Ok(ReplyV1::Accepted(OutcomeV1::Authorized(decision))),
        ]);
        let issue = IssueGrantV1 {
            operation: operation(1),
            expected_epoch: 4,
            now: 5,
            expires_at: 30,
            scopes: vec![scope(1 << ActionV1::Observe as u8)],
        };
        manager.issue(issue.clone(), &issue.confirmation()).unwrap();
        let authorize = AuthorizeGrantV1 {
            operation: operation(1),
            now: 6,
            engine: EngineNamespaceV1::Hermes,
            resource: [7; 16],
            action: ActionV1::Observe,
        };
        assert_eq!(
            manager
                .authorize(authorize, &authorize.confirmation())
                .unwrap(),
            ManagedDecisionV1 {
                operation: operation(1),
                epoch: 4,
                expires_at: 30,
                engine: EngineNamespaceV1::Hermes,
                action: ActionV1::Observe,
            }
        );
        assert!(matches!(
            commands.borrow()[2],
            CommandV1::Authorize {
                grant: GrantHandleV1(10),
                ..
            }
        ));
    }

    #[test]
    fn exact_confirmation_epoch_operation_and_capacity_fence_before_mutation() {
        let (mut manager, commands) = manager(vec![Ok(status(5))]);
        let issue = IssueGrantV1 {
            operation: operation(1),
            expected_epoch: 4,
            now: 5,
            expires_at: 30,
            scopes: vec![scope(1 << ActionV1::Observe as u8)],
        };
        assert!(matches!(
            manager.issue(issue.clone(), "issue"),
            Err(ManagedErrorV1::ConfirmationMismatch { .. })
        ));
        assert_eq!(commands.borrow().len(), 0);
        assert_eq!(
            manager.issue(issue.clone(), &issue.confirmation()),
            Err(ManagedErrorV1::StaleEpoch {
                expected: 4,
                actual: 5
            })
        );
        assert_eq!(commands.borrow().as_slice(), [CommandV1::Status]);
    }

    #[test]
    fn impossible_handle_reuse_terminally_fences_the_owner() {
        let (mut manager, commands) = manager(vec![
            Ok(status(4)),
            Ok(grant(10, None, 0, 30)),
            Ok(status(4)),
            Ok(grant(10, Some(10), 1, 20)),
        ]);
        let parent = IssueGrantV1 {
            operation: operation(1),
            expected_epoch: 4,
            now: 5,
            expires_at: 30,
            scopes: vec![scope(
                (1 << ActionV1::Observe as u8) | (1 << ActionV1::Delegate as u8),
            )],
        };
        manager
            .issue(parent.clone(), &parent.confirmation())
            .unwrap();
        let child = AttenuateGrantV1 {
            operation: operation(2),
            parent: operation(1),
            expected_epoch: 4,
            now: 6,
            expires_at: 20,
            scopes: vec![scope(1 << ActionV1::Observe as u8)],
        };
        assert_eq!(
            manager.attenuate(child.clone(), &child.confirmation()),
            Err(ManagedErrorV1::InvalidReply {
                phase: ManagedPhaseV1::Attenuate
            })
        );
        assert_eq!(manager.state(), ManagedSessionStateV1::Fenced);
        assert_eq!(manager.retained().len(), 1);
        assert_eq!(commands.borrow().len(), 4);
    }
}
