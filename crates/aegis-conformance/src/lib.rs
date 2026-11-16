//! Public-protocol-only continuity and non-amplification qualification.
//!
//! This crate is test infrastructure. It owns no credentials, authenticator,
//! policy, durable store, peer mapping, or retry behavior.
#![forbid(unsafe_code)]

use aegis_protocol::{
    ActionV1, CommandV1, EngineNamespaceV1, OutcomeV1, RefusalV1, ReplyV1, ScopeV1, SessionHandleV1,
};
use std::fmt::Debug;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionProfileV1 {
    AdministratorA,
    AdministratorB,
    NonAdministrator,
}

/// Qualification control over authenticated sessions and one durable service.
///
/// Profiles must map to distinct verified principal/session facts. `restart`
/// consumes the volatile service, reopens the same durable authority, and does
/// not create a replacement session implicitly.
pub trait ConformanceHarnessV1 {
    type Error: Debug;

    fn open_session(&mut self, profile: SessionProfileV1) -> Result<SessionHandleV1, Self::Error>;
    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error>;
    fn restart(&mut self) -> Result<(), Self::Error>;
}

fn scope(resource: [u8; 16], actions: &[ActionV1]) -> ScopeV1 {
    ScopeV1 {
        engine: EngineNamespaceV1::Moira,
        resource,
        actions: actions
            .iter()
            .fold(0, |bits, action| bits | (1 << *action as u8)),
    }
}

/// Proves session ownership, scope/expiry non-amplification, decision
/// non-bearer behavior, epoch revocation, and fail-closed recovery.
pub fn qualify_authority_continuity_v1<H: ConformanceHarnessV1>(harness: &mut H) {
    let admin = harness
        .open_session(SessionProfileV1::AdministratorA)
        .unwrap();
    let other_admin = harness
        .open_session(SessionProfileV1::AdministratorB)
        .unwrap();
    let user = harness
        .open_session(SessionProfileV1::NonAdministrator)
        .unwrap();
    let resource = [0x31; 16];
    let wrong_resource = [0x32; 16];

    let issue = CommandV1::Issue {
        expected_epoch: 0,
        now: 1,
        expires_at: 20,
        scopes: vec![scope(resource, &[ActionV1::Administer, ActionV1::Delegate])],
    };
    assert_eq!(
        harness.execute(user, issue.clone()).unwrap(),
        ReplyV1::Refused(RefusalV1::NotAdministrator)
    );
    let ReplyV1::Accepted(OutcomeV1::GrantIssued(root)) = harness.execute(admin, issue).unwrap()
    else {
        panic!("administrator issue must return a server-held grant handle")
    };
    assert_eq!(
        harness
            .execute(
                other_admin,
                CommandV1::Authorize {
                    grant: root.handle,
                    now: 2,
                    engine: EngineNamespaceV1::Moira,
                    resource,
                    action: ActionV1::Administer,
                },
            )
            .unwrap(),
        ReplyV1::Refused(RefusalV1::GrantOwnedByAnotherSession)
    );
    assert_eq!(
        harness
            .execute(
                admin,
                CommandV1::Attenuate {
                    parent: root.handle,
                    expected_epoch: 0,
                    now: 2,
                    expires_at: 21,
                    scopes: vec![scope(resource, &[ActionV1::Administer])],
                },
            )
            .unwrap(),
        ReplyV1::Refused(RefusalV1::InvalidInput)
    );
    assert_eq!(
        harness
            .execute(
                admin,
                CommandV1::Attenuate {
                    parent: root.handle,
                    expected_epoch: 0,
                    now: 2,
                    expires_at: 19,
                    scopes: vec![scope(resource, &[ActionV1::Administer, ActionV1::Execute],)],
                },
            )
            .unwrap(),
        ReplyV1::Refused(RefusalV1::InvalidInput)
    );
    let ReplyV1::Accepted(OutcomeV1::GrantIssued(child)) = harness
        .execute(
            admin,
            CommandV1::Attenuate {
                parent: root.handle,
                expected_epoch: 0,
                now: 2,
                expires_at: 19,
                scopes: vec![scope(resource, &[ActionV1::Administer])],
            },
        )
        .unwrap()
    else {
        panic!("strict attenuation must return a child handle")
    };
    assert_eq!(
        harness
            .execute(
                admin,
                CommandV1::Authorize {
                    grant: child.handle,
                    now: 3,
                    engine: EngineNamespaceV1::Moira,
                    resource: wrong_resource,
                    action: ActionV1::Administer,
                },
            )
            .unwrap(),
        ReplyV1::Refused(RefusalV1::NotAuthorized)
    );
    let ReplyV1::Accepted(OutcomeV1::Authorized(decision)) = harness
        .execute(
            admin,
            CommandV1::Authorize {
                grant: child.handle,
                now: 3,
                engine: EngineNamespaceV1::Moira,
                resource,
                action: ActionV1::Administer,
            },
        )
        .unwrap()
    else {
        panic!("exact attenuated scope must authorize")
    };
    assert_eq!(decision.engine, EngineNamespaceV1::Moira);
    assert_eq!(decision.action, ActionV1::Administer);

    assert_eq!(
        harness
            .execute(admin, CommandV1::RevokeEpoch { expected_epoch: 0 })
            .unwrap(),
        ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 1 })
    );
    assert_eq!(
        harness
            .execute(
                admin,
                CommandV1::Authorize {
                    grant: child.handle,
                    now: 4,
                    engine: EngineNamespaceV1::Moira,
                    resource,
                    action: ActionV1::Administer,
                },
            )
            .unwrap(),
        ReplyV1::Refused(RefusalV1::UnknownGrant)
    );
    assert!(matches!(
        harness
            .execute(
                admin,
                CommandV1::DecisionPage {
                    after: None,
                    limit: 8,
                },
            )
            .unwrap(),
        ReplyV1::Accepted(OutcomeV1::DecisionPage { entries, .. })
            if entries == vec![decision]
    ));

    harness.restart().unwrap();
    assert_eq!(
        harness.execute(admin, CommandV1::Status).unwrap(),
        ReplyV1::Refused(RefusalV1::UnknownSession)
    );
    let recovered = harness
        .open_session(SessionProfileV1::AdministratorA)
        .unwrap();
    assert!(matches!(
        harness.execute(recovered, CommandV1::Status).unwrap(),
        ReplyV1::Accepted(OutcomeV1::Status(status))
            if status.epoch == 2
                && status.active_grants == 0
                && status.retained_decisions == 0
    ));
}
