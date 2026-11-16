//! Serialized server-owned Aegis sessions and opaque grant handles.
//!
//! Authentication adapters create `AuthenticatedSessionV1` only after verifying
//! credentials. This crate never receives, stores or interprets credentials.

use aegis_authority as core;
use aegis_host::{DurableAuthority, HostError};
use aegis_protocol as protocol;
use keystone_storage::CheckpointStore;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedSessionV1 {
    pub principal: core::PrincipalId,
    pub session: core::SessionId,
    pub administrator: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceLimitsV1 {
    pub max_sessions: usize,
    pub max_grants: usize,
    pub max_decisions: usize,
    pub max_page: usize,
}

impl Default for ServiceLimitsV1 {
    fn default() -> Self {
        Self {
            max_sessions: 1_024,
            max_grants: 65_536,
            max_decisions: 65_536,
            max_page: 256,
        }
    }
}

#[derive(Clone, Copy)]
struct SessionEntry {
    facts: AuthenticatedSessionV1,
}

struct GrantEntry {
    owner: protocol::SessionHandleV1,
    grant: core::GrantV1,
    summary: protocol::GrantSummaryV1,
}

struct GrantMetadata {
    parent: Option<protocol::GrantHandleV1>,
    epoch: u64,
    expires_at: u64,
    scope_count: usize,
    delegation_depth: u8,
}

pub struct Service<S: CheckpointStore> {
    authority: DurableAuthority<S>,
    authority_id: core::EngineId,
    limits: ServiceLimitsV1,
    sessions: BTreeMap<protocol::SessionHandleV1, SessionEntry>,
    grants: BTreeMap<protocol::GrantHandleV1, GrantEntry>,
    decisions: BTreeMap<protocol::DecisionHandleV1, protocol::DecisionSummaryV1>,
    next_session: u64,
    next_grant: u64,
    next_decision: u64,
}

impl<S: CheckpointStore> Service<S> {
    /// Consumes the volatile service boundary and returns its durable authority.
    /// Session-local handles and decision summaries are deliberately destroyed.
    pub fn into_authority(self) -> DurableAuthority<S> {
        self.authority
    }

    pub fn new(
        authority: DurableAuthority<S>,
        authority_id: core::EngineId,
        limits: ServiceLimitsV1,
    ) -> Option<Self> {
        if limits.max_sessions == 0
            || limits.max_grants == 0
            || limits.max_decisions == 0
            || limits.max_page == 0
        {
            return None;
        }
        Some(Self {
            authority,
            authority_id,
            limits,
            sessions: BTreeMap::new(),
            grants: BTreeMap::new(),
            decisions: BTreeMap::new(),
            next_session: 0,
            next_grant: 0,
            next_decision: 0,
        })
    }

    /// Accepts verified facts from the selected authentication adapter.
    pub fn open_session(
        &mut self,
        facts: AuthenticatedSessionV1,
    ) -> Result<protocol::SessionHandleV1, protocol::RefusalV1> {
        if self.sessions.len() >= self.limits.max_sessions {
            return Err(protocol::RefusalV1::Capacity);
        }
        let handle = protocol::SessionHandleV1(self.next_session);
        self.next_session = self
            .next_session
            .checked_add(1)
            .ok_or(protocol::RefusalV1::Exhausted)?;
        self.sessions.insert(handle, SessionEntry { facts });
        Ok(handle)
    }

    /// Closing a session destroys every grant handle it owns.
    pub fn close_session(&mut self, session: protocol::SessionHandleV1) -> bool {
        if self.sessions.remove(&session).is_none() {
            return false;
        }
        self.grants.retain(|_, entry| entry.owner != session);
        true
    }

    pub fn execute(
        &mut self,
        session: protocol::SessionHandleV1,
        command: protocol::CommandV1,
    ) -> Result<protocol::ReplyV1, HostError<S::Error>> {
        let Some(entry) = self.sessions.get(&session).copied() else {
            return Ok(protocol::ReplyV1::Refused(
                protocol::RefusalV1::UnknownSession,
            ));
        };
        match command {
            protocol::CommandV1::Issue {
                expected_epoch,
                now,
                expires_at,
                scopes,
            } => {
                if !entry.facts.administrator {
                    return Ok(refused(protocol::RefusalV1::NotAdministrator));
                }
                let epoch = self.authority.epoch()?;
                if epoch.0 != expected_epoch {
                    return Ok(refused(protocol::RefusalV1::StaleEpoch { actual: epoch.0 }));
                }
                if self.next_grant == u64::MAX {
                    return Ok(refused(protocol::RefusalV1::Exhausted));
                }
                if self.grants.len() >= self.limits.max_grants {
                    return Ok(refused(protocol::RefusalV1::Capacity));
                }
                let scopes = match scopes.into_iter().map(scope).collect::<Result<Vec<_>, _>>() {
                    Ok(scopes) => scopes,
                    Err(error) => return Ok(refused(error)),
                };
                let scope_count = scopes.len();
                let grant = match self.authority.issue(
                    core::GrantDescriptorV1::new(
                        entry.facts.principal,
                        Some(entry.facts.session),
                        self.authority_id,
                        epoch,
                        core::LogicalTime(expires_at),
                        scopes,
                    ),
                    core::LogicalTime(now),
                ) {
                    Ok(grant) => grant,
                    Err(HostError::Domain(error)) => return Ok(refused(domain(error))),
                    Err(error) => return Err(error),
                };
                let summary = self.insert_grant(
                    session,
                    GrantMetadata {
                        parent: None,
                        epoch: epoch.0,
                        expires_at,
                        scope_count,
                        delegation_depth: 0,
                    },
                    grant,
                )?;
                Ok(accepted(protocol::OutcomeV1::GrantIssued(summary)))
            }
            protocol::CommandV1::Attenuate {
                parent,
                expected_epoch,
                now,
                expires_at,
                scopes,
            } => {
                if self.next_grant == u64::MAX {
                    return Ok(refused(protocol::RefusalV1::Exhausted));
                }
                if self.grants.len() >= self.limits.max_grants {
                    return Ok(refused(protocol::RefusalV1::Capacity));
                }
                let Some(parent_entry) = self.grants.get(&parent) else {
                    return Ok(refused(protocol::RefusalV1::UnknownGrant));
                };
                if parent_entry.owner != session {
                    return Ok(refused(protocol::RefusalV1::GrantOwnedByAnotherSession));
                }
                let epoch = self.authority.epoch()?;
                if epoch.0 != expected_epoch {
                    return Ok(refused(protocol::RefusalV1::StaleEpoch { actual: epoch.0 }));
                }
                let depth = parent_entry.summary.delegation_depth.saturating_add(1);
                let scopes = match scopes.into_iter().map(scope).collect::<Result<Vec<_>, _>>() {
                    Ok(scopes) => scopes,
                    Err(error) => return Ok(refused(error)),
                };
                let scope_count = scopes.len();
                let grant = match self.authority.attenuate(
                    &parent_entry.grant,
                    entry.facts.principal,
                    Some(entry.facts.session),
                    core::LogicalTime(expires_at),
                    scopes,
                    core::LogicalTime(now),
                ) {
                    Ok(grant) => grant,
                    Err(HostError::Domain(error)) => return Ok(refused(domain(error))),
                    Err(error) => return Err(error),
                };
                let summary = self.insert_grant(
                    session,
                    GrantMetadata {
                        parent: Some(parent),
                        epoch: epoch.0,
                        expires_at,
                        scope_count,
                        delegation_depth: depth,
                    },
                    grant,
                )?;
                Ok(accepted(protocol::OutcomeV1::GrantIssued(summary)))
            }
            protocol::CommandV1::Authorize {
                grant,
                now,
                engine,
                resource,
                action,
            } => {
                if self.next_decision == u64::MAX {
                    return Ok(refused(protocol::RefusalV1::Exhausted));
                }
                if self.decisions.len() >= self.limits.max_decisions {
                    return Ok(refused(protocol::RefusalV1::Capacity));
                }
                let Some(grant_entry) = self.grants.get(&grant) else {
                    return Ok(refused(protocol::RefusalV1::UnknownGrant));
                };
                if grant_entry.owner != session {
                    return Ok(refused(protocol::RefusalV1::GrantOwnedByAnotherSession));
                }
                let evidence = match self.authority.validate(
                    &grant_entry.grant,
                    &core::AuthorizationRequestV1::new(
                        entry.facts.principal,
                        Some(entry.facts.session),
                        namespace(engine),
                        core::ResourceId::new(resource),
                        action_core(action),
                    ),
                    core::LogicalTime(now),
                ) {
                    Ok(evidence) => evidence,
                    Err(HostError::Domain(error)) => return Ok(refused(domain(error))),
                    Err(error) => return Err(error),
                };
                let handle = protocol::DecisionHandleV1(self.next_decision);
                self.next_decision = self
                    .next_decision
                    .checked_add(1)
                    .ok_or(HostError::Domain(core::RefusalV1::IdentityExhausted))?;
                let summary = protocol::DecisionSummaryV1 {
                    handle,
                    epoch: self.authority.epoch()?.0,
                    expires_at: evidence.expires_at().0,
                    engine,
                    action,
                };
                self.decisions.insert(handle, summary);
                Ok(accepted(protocol::OutcomeV1::Authorized(summary)))
            }
            protocol::CommandV1::RevokeEpoch { expected_epoch } => {
                if !entry.facts.administrator {
                    return Ok(refused(protocol::RefusalV1::NotAdministrator));
                }
                let actual = self.authority.epoch()?.0;
                if actual != expected_epoch {
                    return Ok(refused(protocol::RefusalV1::StaleEpoch { actual }));
                }
                let epoch = match self.authority.revoke_epoch() {
                    Ok(epoch) => epoch,
                    Err(HostError::Domain(error)) => return Ok(refused(domain(error))),
                    Err(error) => return Err(error),
                };
                self.grants.clear();
                Ok(accepted(protocol::OutcomeV1::EpochRevoked {
                    epoch: epoch.0,
                }))
            }
            protocol::CommandV1::Status => {
                if !entry.facts.administrator {
                    return Ok(refused(protocol::RefusalV1::NotAdministrator));
                }
                Ok(accepted(protocol::OutcomeV1::Status(
                    protocol::AuthorityStatusV1 {
                        epoch: self.authority.epoch()?.0,
                        active_grants: self.grants.len(),
                        retained_decisions: self.decisions.len(),
                    },
                )))
            }
            protocol::CommandV1::GrantPage { after, limit } => {
                if !entry.facts.administrator {
                    return Ok(refused(protocol::RefusalV1::NotAdministrator));
                }
                let Some(limit) = page_limit(limit, self.limits.max_page) else {
                    return Ok(refused(protocol::RefusalV1::InvalidPageLimit));
                };
                let entries = self
                    .grants
                    .range(after.map_or(protocol::GrantHandleV1(0).., |after| {
                        protocol::GrantHandleV1(after.0.saturating_add(1))..
                    }))
                    .take(limit)
                    .map(|(_, entry)| entry.summary)
                    .collect::<Vec<_>>();
                let next_after = (entries.len() == limit).then(|| entries.last().unwrap().handle);
                Ok(accepted(protocol::OutcomeV1::GrantPage {
                    entries,
                    next_after,
                }))
            }
            protocol::CommandV1::DecisionPage { after, limit } => {
                if !entry.facts.administrator {
                    return Ok(refused(protocol::RefusalV1::NotAdministrator));
                }
                let Some(limit) = page_limit(limit, self.limits.max_page) else {
                    return Ok(refused(protocol::RefusalV1::InvalidPageLimit));
                };
                let entries = self
                    .decisions
                    .range(after.map_or(protocol::DecisionHandleV1(0).., |after| {
                        protocol::DecisionHandleV1(after.0.saturating_add(1))..
                    }))
                    .take(limit)
                    .map(|(_, summary)| *summary)
                    .collect::<Vec<_>>();
                let next_after = (entries.len() == limit).then(|| entries.last().unwrap().handle);
                Ok(accepted(protocol::OutcomeV1::DecisionPage {
                    entries,
                    next_after,
                }))
            }
        }
    }

    fn insert_grant(
        &mut self,
        owner: protocol::SessionHandleV1,
        metadata: GrantMetadata,
        grant: core::GrantV1,
    ) -> Result<protocol::GrantSummaryV1, HostError<S::Error>> {
        let handle = protocol::GrantHandleV1(self.next_grant);
        self.next_grant = self
            .next_grant
            .checked_add(1)
            .ok_or(HostError::Domain(core::RefusalV1::IdentityExhausted))?;
        let summary = protocol::GrantSummaryV1 {
            handle,
            parent: metadata.parent,
            epoch: metadata.epoch,
            expires_at: metadata.expires_at,
            scope_count: metadata.scope_count,
            delegation_depth: metadata.delegation_depth,
        };
        self.grants.insert(
            handle,
            GrantEntry {
                owner,
                grant,
                summary,
            },
        );
        Ok(summary)
    }
}

fn page_limit(limit: usize, maximum: usize) -> Option<usize> {
    (limit > 0 && limit <= maximum).then_some(limit)
}

fn accepted(outcome: protocol::OutcomeV1) -> protocol::ReplyV1 {
    protocol::ReplyV1::Accepted(outcome)
}

fn refused(refusal: protocol::RefusalV1) -> protocol::ReplyV1 {
    protocol::ReplyV1::Refused(refusal)
}

fn namespace(value: protocol::EngineNamespaceV1) -> core::EngineNamespaceV1 {
    match value {
        protocol::EngineNamespaceV1::Agora => core::EngineNamespaceV1::Agora,
        protocol::EngineNamespaceV1::Chronos => core::EngineNamespaceV1::Chronos,
        protocol::EngineNamespaceV1::Vellum => core::EngineNamespaceV1::Vellum,
        protocol::EngineNamespaceV1::Moira => core::EngineNamespaceV1::Moira,
        protocol::EngineNamespaceV1::Hermes => core::EngineNamespaceV1::Hermes,
        protocol::EngineNamespaceV1::Daimon => core::EngineNamespaceV1::Daimon,
        protocol::EngineNamespaceV1::Aegis => core::EngineNamespaceV1::Aegis,
    }
}

fn action_core(value: protocol::ActionV1) -> core::ActionV1 {
    match value {
        protocol::ActionV1::Observe => core::ActionV1::Observe,
        protocol::ActionV1::Submit => core::ActionV1::Submit,
        protocol::ActionV1::Modify => core::ActionV1::Modify,
        protocol::ActionV1::Execute => core::ActionV1::Execute,
        protocol::ActionV1::Delegate => core::ActionV1::Delegate,
        protocol::ActionV1::Administer => core::ActionV1::Administer,
    }
}

fn scope(value: protocol::ScopeV1) -> Result<core::ResourceScopeV1, protocol::RefusalV1> {
    if value.actions == 0 || value.actions & !0b00_111111 != 0 {
        return Err(protocol::RefusalV1::InvalidScope);
    }
    let actions = [
        protocol::ActionV1::Observe,
        protocol::ActionV1::Submit,
        protocol::ActionV1::Modify,
        protocol::ActionV1::Execute,
        protocol::ActionV1::Delegate,
        protocol::ActionV1::Administer,
    ]
    .into_iter()
    .enumerate()
    .filter(|(index, _)| value.actions & (1 << index) != 0)
    .fold(core::ActionSetV1::bottom(), |set, (_, action)| {
        set.join(core::ActionSetV1::singleton(action_core(action)))
    });
    Ok(core::ResourceScopeV1::new(
        namespace(value.engine),
        core::ResourceId::new(value.resource),
        actions,
    ))
}

fn domain(value: core::RefusalV1) -> protocol::RefusalV1 {
    match value {
        core::RefusalV1::IdentityExhausted => protocol::RefusalV1::Exhausted,
        core::RefusalV1::Revoked | core::RefusalV1::InvalidEpoch | core::RefusalV1::WrongEngine => {
            protocol::RefusalV1::Revoked
        }
        core::RefusalV1::Expired | core::RefusalV1::AlreadyExpired => protocol::RefusalV1::Expired,
        core::RefusalV1::NotAuthorized => protocol::RefusalV1::NotAuthorized,
        core::RefusalV1::ScopeLimit | core::RefusalV1::DelegationLimit => {
            protocol::RefusalV1::Capacity
        }
        core::RefusalV1::EmptyScope
        | core::RefusalV1::SubjectMismatch
        | core::RefusalV1::SessionMismatch
        | core::RefusalV1::ScopeAmplification
        | core::RefusalV1::ExpiryAmplification => protocol::RefusalV1::InvalidInput,
    }
}
