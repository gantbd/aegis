use std::convert::Infallible;

use aegis_admin_command::{
    AttenuateGrantV1, AuthorizeGrantV1, IssueGrantV1, ManagedDecisionV1, ManagedLimitsV1,
    ManagedSessionV1, OperationIdV1,
};
use aegis_authority::{EngineId, Limits, PrincipalId, SessionId};
use aegis_client::ServicePort;
use aegis_host::{DurableAuthority, HostError};
use aegis_protocol::{ActionV1, CommandV1, EngineNamespaceV1, ReplyV1, ScopeV1, SessionHandleV1};
use aegis_service::{AuthenticatedSessionV1, Service, ServiceLimitsV1};
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};

#[derive(Default)]
struct Store(Option<Checkpoint>);

struct Port(Service<Store>);

impl ServicePort for Port {
    type Error = HostError<Infallible>;

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        self.0.execute(session, command)
    }
}

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
            mechanism: "managed-session-test",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

#[test]
fn public_service_retains_named_parent_and_child_without_exporting_handles() {
    let authority_id = EngineId::new([1; 16]);
    let authority =
        DurableAuthority::create_new(Store::default(), authority_id, Limits::default()).unwrap();
    let mut service = Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap();
    let session = service
        .open_session(AuthenticatedSessionV1 {
            principal: PrincipalId::new([2; 16]),
            session: SessionId::new([3; 16]),
            administrator: true,
        })
        .unwrap();
    let parent = OperationIdV1::new([4; 16]);
    let child = OperationIdV1::new([5; 16]);
    let resource = [6; 16];
    let mut manager =
        ManagedSessionV1::new(session, Port(service), ManagedLimitsV1::default()).unwrap();

    let issue = IssueGrantV1 {
        operation: parent,
        expected_epoch: 0,
        now: 10,
        expires_at: 40,
        scopes: vec![ScopeV1 {
            engine: EngineNamespaceV1::Hermes,
            resource,
            actions: (1 << ActionV1::Observe as u8) | (1 << ActionV1::Delegate as u8),
        }],
    };
    manager.issue(issue.clone(), &issue.confirmation()).unwrap();
    let attenuation = AttenuateGrantV1 {
        operation: child,
        parent,
        expected_epoch: 0,
        now: 11,
        expires_at: 30,
        scopes: vec![ScopeV1 {
            engine: EngineNamespaceV1::Hermes,
            resource,
            actions: 1 << ActionV1::Observe as u8,
        }],
    };
    manager
        .attenuate(attenuation.clone(), &attenuation.confirmation())
        .unwrap();
    let authorize = AuthorizeGrantV1 {
        operation: child,
        now: 12,
        engine: EngineNamespaceV1::Hermes,
        resource,
        action: ActionV1::Observe,
    };
    assert_eq!(
        manager
            .authorize(authorize, &authorize.confirmation())
            .unwrap(),
        ManagedDecisionV1 {
            operation: child,
            epoch: 0,
            expires_at: 30,
            engine: EngineNamespaceV1::Hermes,
            action: ActionV1::Observe,
        }
    );
    assert_eq!(manager.retained().len(), 2);
}
