//! Transport-neutral values for the native Aegis service contract.
//!
//! Grant handles are session-local references. They contain no authority and a
//! service must reject their use from every other session or authority epoch.

macro_rules! number {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub u64);
    };
}

number!(SessionHandleV1);
number!(GrantHandleV1);
number!(DecisionHandleV1);

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
pub enum ActionV1 {
    Observe,
    Submit,
    Modify,
    Execute,
    Delegate,
    Administer,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ScopeV1 {
    pub engine: EngineNamespaceV1,
    pub resource: [u8; 16],
    pub actions: u8,
}

impl std::fmt::Debug for ScopeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScopeV1")
            .field("engine", &self.engine)
            .field("resource", &"<redacted>")
            .field("action_count", &self.actions.count_ones())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum CommandV1 {
    /// Observe the principal owned by the exact session carrying this command.
    /// No caller-supplied identity is accepted and no authority is granted.
    CurrentPrincipal,
    Issue {
        expected_epoch: u64,
        now: u64,
        expires_at: u64,
        scopes: Vec<ScopeV1>,
    },
    Attenuate {
        parent: GrantHandleV1,
        expected_epoch: u64,
        now: u64,
        expires_at: u64,
        scopes: Vec<ScopeV1>,
    },
    Authorize {
        grant: GrantHandleV1,
        now: u64,
        engine: EngineNamespaceV1,
        resource: [u8; 16],
        action: ActionV1,
    },
    RevokeEpoch {
        expected_epoch: u64,
    },
    Status,
    GrantPage {
        after: Option<GrantHandleV1>,
        limit: usize,
    },
    DecisionPage {
        after: Option<DecisionHandleV1>,
        limit: usize,
    },
}

impl std::fmt::Debug for CommandV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentPrincipal => formatter.write_str("CurrentPrincipal"),
            Self::Issue {
                expected_epoch,
                now,
                expires_at,
                scopes,
            } => formatter
                .debug_struct("Issue")
                .field("expected_epoch", expected_epoch)
                .field("now", now)
                .field("expires_at", expires_at)
                .field("scope_count", &scopes.len())
                .finish(),
            Self::Attenuate {
                parent,
                expected_epoch,
                now,
                expires_at,
                scopes,
            } => formatter
                .debug_struct("Attenuate")
                .field("parent", parent)
                .field("expected_epoch", expected_epoch)
                .field("now", now)
                .field("expires_at", expires_at)
                .field("scope_count", &scopes.len())
                .finish(),
            Self::Authorize {
                grant,
                now,
                engine,
                action,
                ..
            } => formatter
                .debug_struct("Authorize")
                .field("grant", grant)
                .field("now", now)
                .field("engine", engine)
                .field("resource", &"<redacted>")
                .field("action", action)
                .finish(),
            Self::RevokeEpoch { expected_epoch } => formatter
                .debug_struct("RevokeEpoch")
                .field("expected_epoch", expected_epoch)
                .finish(),
            Self::Status => formatter.write_str("Status"),
            Self::GrantPage { after, limit } => formatter
                .debug_struct("GrantPage")
                .field("after", after)
                .field("limit", limit)
                .finish(),
            Self::DecisionPage { after, limit } => formatter
                .debug_struct("DecisionPage")
                .field("after", after)
                .field("limit", limit)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CurrentPrincipalV1 {
    pub principal: [u8; 16],
}

impl std::fmt::Debug for CurrentPrincipalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CurrentPrincipalV1")
            .field("principal", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantSummaryV1 {
    pub handle: GrantHandleV1,
    pub parent: Option<GrantHandleV1>,
    pub epoch: u64,
    pub expires_at: u64,
    pub scope_count: usize,
    pub delegation_depth: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionSummaryV1 {
    pub handle: DecisionHandleV1,
    pub epoch: u64,
    pub expires_at: u64,
    pub engine: EngineNamespaceV1,
    pub action: ActionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityStatusV1 {
    pub epoch: u64,
    pub active_grants: usize,
    pub retained_decisions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutcomeV1 {
    CurrentPrincipal(CurrentPrincipalV1),
    GrantIssued(GrantSummaryV1),
    Authorized(DecisionSummaryV1),
    EpochRevoked {
        epoch: u64,
    },
    Status(AuthorityStatusV1),
    GrantPage {
        entries: Vec<GrantSummaryV1>,
        next_after: Option<GrantHandleV1>,
    },
    DecisionPage {
        entries: Vec<DecisionSummaryV1>,
        next_after: Option<DecisionHandleV1>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalV1 {
    UnknownSession,
    UnknownGrant,
    GrantOwnedByAnotherSession,
    NotAdministrator,
    InvalidScope,
    InvalidPageLimit,
    StaleEpoch { actual: u64 },
    Capacity,
    Exhausted,
    Revoked,
    Expired,
    NotAuthorized,
    InvalidInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyV1 {
    Accepted(OutcomeV1),
    Refused(RefusalV1),
}
