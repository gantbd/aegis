//! Deterministic bounded authority reference core.
//!
//! Credential authentication remains a host responsibility. Calling `issue` is
//! a privileged adapter operation; validation never treats a public ID alone as
//! authority.

pub const PROJECT_STAGE: &str = "volatile-authority-reference";

pub mod persistence;

macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn new(value: [u8; 16]) -> Self {
                Self(value)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }
    };
}

id!(PrincipalId);
id!(SessionId);
id!(EngineId);
id!(ResourceId);

impl PrincipalId {
    /// Projects only the authenticated principal identity needed by bounded
    /// owner-observation adapters. Other authority identities remain opaque.
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKindV1 {
    Human,
    Agent,
    Service,
    System,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineNamespaceV1 {
    Agora,
    Chronos,
    Vellum,
    Moira,
    Hermes,
    Daimon,
    Aegis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActionV1 {
    Observe = 0,
    Submit = 1,
    Modify = 2,
    Execute = 3,
    Delegate = 4,
    Administer = 5,
}

/// Finite bounded lattice of actions: subset is the order, intersection is
/// meet, union is join, empty is bottom, and all admitted actions is top.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActionSetV1(u8);

impl ActionSetV1 {
    const ALL: u8 = 0b00_111111;

    pub const fn bottom() -> Self {
        Self(0)
    }

    pub const fn top() -> Self {
        Self(Self::ALL)
    }

    pub const fn singleton(action: ActionV1) -> Self {
        Self(1 << action as u8)
    }

    pub const fn meet(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn join(self, other: Self) -> Self {
        Self((self.0 | other.0) & Self::ALL)
    }

    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    pub const fn contains(self, action: ActionV1) -> bool {
        self.0 & (1 << action as u8) != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceScopeV1 {
    pub engine: EngineNamespaceV1,
    pub resource: ResourceId,
    pub actions: ActionSetV1,
}

impl ResourceScopeV1 {
    pub const fn new(
        engine: EngineNamespaceV1,
        resource: ResourceId,
        actions: ActionSetV1,
    ) -> Self {
        Self {
            engine,
            resource,
            actions,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuthorityEpoch(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogicalTime(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantDescriptorV1 {
    subject: PrincipalId,
    session: Option<SessionId>,
    engine: EngineId,
    epoch: AuthorityEpoch,
    expires_at: LogicalTime,
    scopes: Vec<ResourceScopeV1>,
}

impl GrantDescriptorV1 {
    pub fn new(
        subject: PrincipalId,
        session: Option<SessionId>,
        engine: EngineId,
        epoch: AuthorityEpoch,
        expires_at: LogicalTime,
        scopes: Vec<ResourceScopeV1>,
    ) -> Self {
        Self {
            subject,
            session,
            engine,
            epoch,
            expires_at,
            scopes,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_scopes_per_grant: usize,
    pub max_delegation_depth: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_scopes_per_grant: 64,
            max_delegation_depth: 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitsError {
    Disabled,
}

/// Opaque native capability, deliberately not cloneable or serializable.
///
/// ```compile_fail
/// use aegis_authority::GrantV1;
/// fn duplicate(grant: &GrantV1) -> GrantV1 { grant.clone() }
/// ```
#[derive(Eq, PartialEq)]
pub struct GrantV1 {
    grant_id: [u8; 16],
    descriptor: GrantDescriptorV1,
    delegation_depth: u8,
}

impl std::fmt::Debug for GrantV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrantV1")
            .field("grant_id", &"<redacted>")
            .field("subject", &self.descriptor.subject)
            .field("expires_at", &self.descriptor.expires_at)
            .field("delegation_depth", &self.delegation_depth)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationRequestV1 {
    subject: PrincipalId,
    session: Option<SessionId>,
    engine: EngineNamespaceV1,
    resource: ResourceId,
    action: ActionV1,
}

impl AuthorizationRequestV1 {
    pub const fn new(
        subject: PrincipalId,
        session: Option<SessionId>,
        engine: EngineNamespaceV1,
        resource: ResourceId,
        action: ActionV1,
    ) -> Self {
        Self {
            subject,
            session,
            engine,
            resource,
            action,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DecisionEvidenceV1 {
    decision_id: [u8; 16],
    subject: PrincipalId,
    expires_at: LogicalTime,
    epoch: AuthorityEpoch,
    request: AuthorizationRequestV1,
}

impl DecisionEvidenceV1 {
    pub const fn subject(&self) -> PrincipalId {
        self.subject
    }

    pub const fn decision_id_bytes(&self) -> [u8; 16] {
        self.decision_id
    }

    pub const fn expires_at(&self) -> LogicalTime {
        self.expires_at
    }
}

impl std::fmt::Debug for DecisionEvidenceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecisionEvidenceV1")
            .field("decision_id", &"<redacted>")
            .field("subject", &self.subject)
            .field("expires_at", &self.expires_at)
            .field("epoch", &self.epoch)
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalV1 {
    InvalidEpoch,
    AlreadyExpired,
    ScopeLimit,
    EmptyScope,
    IdentityExhausted,
    WrongEngine,
    Revoked,
    Expired,
    SubjectMismatch,
    SessionMismatch,
    NotAuthorized,
    DelegationLimit,
    ScopeAmplification,
    ExpiryAmplification,
}

pub struct Engine {
    engine_id: EngineId,
    limits: Limits,
    epoch: AuthorityEpoch,
    next_grant: u64,
    next_decision: u64,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("engine_id", &self.engine_id)
            .field("epoch", &self.epoch)
            .finish()
    }
}

impl Engine {
    pub const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }

    pub const fn allocation_frontiers(&self) -> (u64, u64) {
        (self.next_grant, self.next_decision)
    }

    pub fn try_new(engine_id: EngineId, limits: Limits) -> Result<Self, LimitsError> {
        if limits.max_scopes_per_grant == 0 || limits.max_delegation_depth == 0 {
            return Err(LimitsError::Disabled);
        }
        Ok(Self {
            engine_id,
            limits,
            epoch: AuthorityEpoch(0),
            next_grant: 0,
            next_decision: 0,
        })
    }

    pub fn issue(
        &mut self,
        descriptor: GrantDescriptorV1,
        now: LogicalTime,
    ) -> Result<GrantV1, RefusalV1> {
        self.validate_descriptor(&descriptor, now)?;
        let grant_id = identity_bytes(b'g', self.next_grant);
        self.next_grant = self
            .next_grant
            .checked_add(1)
            .ok_or(RefusalV1::IdentityExhausted)?;
        Ok(GrantV1 {
            grant_id,
            descriptor,
            delegation_depth: 0,
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
    ) -> Result<GrantV1, RefusalV1> {
        self.validate_grant(parent, now)?;
        let depth = parent
            .delegation_depth
            .checked_add(1)
            .ok_or(RefusalV1::DelegationLimit)?;
        if depth > self.limits.max_delegation_depth {
            return Err(RefusalV1::DelegationLimit);
        }
        if expires_at > parent.descriptor.expires_at {
            return Err(RefusalV1::ExpiryAmplification);
        }
        if !parent
            .descriptor
            .scopes
            .iter()
            .any(|scope| scope.actions.contains(ActionV1::Delegate))
        {
            return Err(RefusalV1::NotAuthorized);
        }
        if scopes.len() > self.limits.max_scopes_per_grant {
            return Err(RefusalV1::ScopeLimit);
        }
        if scopes.iter().any(|child| {
            !parent.descriptor.scopes.iter().any(|ancestor| {
                child.engine == ancestor.engine
                    && child.resource == ancestor.resource
                    && child.actions.is_subset_of(ancestor.actions)
            })
        }) {
            return Err(RefusalV1::ScopeAmplification);
        }
        let descriptor = GrantDescriptorV1::new(
            subject,
            session,
            self.engine_id,
            self.epoch,
            expires_at,
            scopes,
        );
        self.validate_descriptor(&descriptor, now)?;
        let grant_id = identity_bytes(b'g', self.next_grant);
        self.next_grant = self
            .next_grant
            .checked_add(1)
            .ok_or(RefusalV1::IdentityExhausted)?;
        Ok(GrantV1 {
            grant_id,
            descriptor,
            delegation_depth: depth,
        })
    }

    pub fn validate(
        &mut self,
        grant: &GrantV1,
        request: &AuthorizationRequestV1,
        now: LogicalTime,
    ) -> Result<DecisionEvidenceV1, RefusalV1> {
        self.validate_grant(grant, now)?;
        if grant.descriptor.subject != request.subject {
            return Err(RefusalV1::SubjectMismatch);
        }
        if grant.descriptor.session != request.session {
            return Err(RefusalV1::SessionMismatch);
        }
        if !grant.descriptor.scopes.iter().any(|scope| {
            scope.engine == request.engine
                && scope.resource == request.resource
                && scope.actions.contains(request.action)
        }) {
            return Err(RefusalV1::NotAuthorized);
        }
        let decision_id = identity_bytes(b'd', self.next_decision);
        self.next_decision = self
            .next_decision
            .checked_add(1)
            .ok_or(RefusalV1::IdentityExhausted)?;
        Ok(DecisionEvidenceV1 {
            decision_id,
            subject: request.subject,
            expires_at: grant.descriptor.expires_at,
            epoch: self.epoch,
            request: *request,
        })
    }

    pub fn revoke_epoch(&mut self) -> Result<AuthorityEpoch, RefusalV1> {
        self.epoch = AuthorityEpoch(
            self.epoch
                .0
                .checked_add(1)
                .ok_or(RefusalV1::IdentityExhausted)?,
        );
        Ok(self.epoch)
    }

    fn validate_descriptor(
        &self,
        descriptor: &GrantDescriptorV1,
        now: LogicalTime,
    ) -> Result<(), RefusalV1> {
        if descriptor.engine != self.engine_id || descriptor.epoch != self.epoch {
            return Err(RefusalV1::InvalidEpoch);
        }
        if descriptor.expires_at <= now {
            return Err(RefusalV1::AlreadyExpired);
        }
        if descriptor.scopes.len() > self.limits.max_scopes_per_grant {
            return Err(RefusalV1::ScopeLimit);
        }
        if descriptor.scopes.is_empty()
            || descriptor
                .scopes
                .iter()
                .any(|scope| scope.actions.is_empty())
        {
            return Err(RefusalV1::EmptyScope);
        }
        Ok(())
    }

    fn validate_grant(&self, grant: &GrantV1, now: LogicalTime) -> Result<(), RefusalV1> {
        if grant.descriptor.engine != self.engine_id {
            return Err(RefusalV1::WrongEngine);
        }
        if grant.descriptor.epoch != self.epoch {
            return Err(RefusalV1::Revoked);
        }
        if grant.descriptor.expires_at <= now {
            return Err(RefusalV1::Expired);
        }
        Ok(())
    }
}

const fn identity_bytes(kind: u8, sequence: u64) -> [u8; 16] {
    let bytes = sequence.to_le_bytes();
    [
        b'a', b'e', b'g', b'i', b's', kind, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
        bytes[5], bytes[6], bytes[7],
    ]
}
