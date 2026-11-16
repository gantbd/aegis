use std::{convert::Infallible, io::Cursor};

use aegis_authority::{EngineId, Limits, PrincipalId, SessionId};
use aegis_client::ServicePort;
use aegis_host::{DurableAuthority, HostError};
use aegis_protocol::{CommandV1, ReplyV1, SessionHandleV1};
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
            mechanism: "admin-session-test",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

#[test]
fn ndjson_application_uses_the_real_public_service_without_handle_export() {
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
    let input = concat!(
        "{\"version\":1,\"command\":\"issue\",",
        "\"operation\":\"04040404040404040404040404040404\",",
        "\"expected_epoch\":0,\"now\":10,\"expires_at\":40,",
        "\"scopes\":[{\"engine\":\"hermes\",",
        "\"resource\":\"06060606060606060606060606060606\",",
        "\"actions\":[\"observe\"]}],",
        "\"confirmation\":\"ISSUE AEGIS OP 04040404040404040404040404040404 EPOCH 0 UNTIL 40 SCOPES hermes:06060606060606060606060606060606:observe\"}\n",
        "{\"version\":1,\"command\":\"list\"}\n",
        "{\"version\":1,\"command\":\"close\"}\n"
    );
    let mut output = Vec::new();

    assert_eq!(
        aegis_admin_session::run(
            session,
            Port(service),
            Cursor::new(input),
            &mut output,
            aegis_admin_session::LimitsV1::default(),
        )
        .unwrap(),
        aegis_admin_session::EndV1::Closed
    );
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("\"status\":\"issued\""));
    assert!(output.contains("\"status\":\"current\""));
    assert!(!output.contains("\"handle\""));
}
