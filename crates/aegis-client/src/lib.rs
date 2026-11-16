//! Capability-shaped transport-neutral clients bound to one service session.

use aegis_protocol::{
    ActionV1, CommandV1, EngineNamespaceV1, GrantHandleV1, ReplyV1, ScopeV1, SessionHandleV1,
};

pub trait ServicePort {
    type Error;
    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error>;
}

pub struct Client<P> {
    session: SessionHandleV1,
    port: P,
}

impl<P: ServicePort> Client<P> {
    pub const fn new(session: SessionHandleV1, port: P) -> Self {
        Self { session, port }
    }

    pub fn execute(&mut self, command: CommandV1) -> Result<ReplyV1, P::Error> {
        self.port.execute(self.session, command)
    }

    pub fn into_port(self) -> P {
        self.port
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ClientError<E> {
    Limit,
    Transport(E),
}

/// Mutation facade. Authentication and authorization remain service decisions.
pub struct AuthorityClient<P>(Client<P>);

impl<P: ServicePort> AuthorityClient<P> {
    pub const fn new(session: SessionHandleV1, port: P) -> Self {
        Self(Client::new(session, port))
    }

    pub fn issue(
        &mut self,
        expected_epoch: u64,
        now: u64,
        expires_at: u64,
        scopes: Vec<ScopeV1>,
    ) -> Result<ReplyV1, P::Error> {
        self.0.execute(CommandV1::Issue {
            expected_epoch,
            now,
            expires_at,
            scopes,
        })
    }

    pub fn attenuate(
        &mut self,
        parent: GrantHandleV1,
        expected_epoch: u64,
        now: u64,
        expires_at: u64,
        scopes: Vec<ScopeV1>,
    ) -> Result<ReplyV1, P::Error> {
        self.0.execute(CommandV1::Attenuate {
            parent,
            expected_epoch,
            now,
            expires_at,
            scopes,
        })
    }

    pub fn authorize(
        &mut self,
        grant: GrantHandleV1,
        now: u64,
        engine: EngineNamespaceV1,
        resource: [u8; 16],
        action: ActionV1,
    ) -> Result<ReplyV1, P::Error> {
        self.0.execute(CommandV1::Authorize {
            grant,
            now,
            engine,
            resource,
            action,
        })
    }

    pub fn into_port(self) -> P {
        self.0.into_port()
    }
}

/// Administrative mutation facade. Constructing it grants no authority; the
/// authenticated service session must still carry administrator facts.
pub struct AdminClient<P>(Client<P>);

impl<P: ServicePort> AdminClient<P> {
    pub const fn new(session: SessionHandleV1, port: P) -> Self {
        Self(Client::new(session, port))
    }

    pub fn revoke_epoch(&mut self, expected_epoch: u64) -> Result<ReplyV1, P::Error> {
        self.0.execute(CommandV1::RevokeEpoch { expected_epoch })
    }

    pub fn into_port(self) -> P {
        self.0.into_port()
    }
}

/// Read-only administrative projection with a client-side page ceiling.
pub struct ReadOnlyClient<P> {
    client: Client<P>,
    max_page: usize,
}

impl<P: ServicePort> ReadOnlyClient<P> {
    pub fn new(
        session: SessionHandleV1,
        port: P,
        max_page: usize,
    ) -> Result<Self, ClientError<P::Error>> {
        if max_page == 0 {
            return Err(ClientError::Limit);
        }
        Ok(Self {
            client: Client::new(session, port),
            max_page,
        })
    }

    pub fn status(&mut self) -> Result<ReplyV1, ClientError<P::Error>> {
        self.client
            .execute(CommandV1::Status)
            .map_err(ClientError::Transport)
    }

    pub fn grant_page(
        &mut self,
        after: Option<GrantHandleV1>,
        limit: usize,
    ) -> Result<ReplyV1, ClientError<P::Error>> {
        self.page_limit(limit)?;
        self.client
            .execute(CommandV1::GrantPage { after, limit })
            .map_err(ClientError::Transport)
    }

    pub fn decision_page(
        &mut self,
        after: Option<aegis_protocol::DecisionHandleV1>,
        limit: usize,
    ) -> Result<ReplyV1, ClientError<P::Error>> {
        self.page_limit(limit)?;
        self.client
            .execute(CommandV1::DecisionPage { after, limit })
            .map_err(ClientError::Transport)
    }

    pub fn into_port(self) -> P {
        self.client.into_port()
    }

    fn page_limit(&self, limit: usize) -> Result<(), ClientError<P::Error>> {
        if limit == 0 || limit > self.max_page {
            Err(ClientError::Limit)
        } else {
            Ok(())
        }
    }
}
