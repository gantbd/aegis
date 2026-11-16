use aegis_authority::{EngineId, Limits, PrincipalId, SessionId};
use aegis_conformance::{ConformanceHarnessV1, SessionProfileV1, qualify_authority_continuity_v1};
use aegis_host::DurableAuthority;
use aegis_protocol::{CommandV1, ReplyV1, SessionHandleV1};
use aegis_service::{AuthenticatedSessionV1, Service, ServiceLimitsV1};
use keystone_storage::{
    AcknowledgementStrength, Checkpoint, CheckpointStore, CommitOutcome, CommitReceipt, Revision,
    StoreRefusal,
};
use std::convert::Infallible;

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
        let revision = Revision(actual.map_or(0, |value| value.0 + 1));
        self.0 = Some(Checkpoint {
            revision,
            bytes: bytes.to_vec(),
            strength: AcknowledgementStrength::Durable,
        });
        Ok(CommitOutcome::Committed(CommitReceipt {
            revision,
            mechanism: "aegis-conformance",
            strength: AcknowledgementStrength::Durable,
        }))
    }
}

type PublicService = Service<Store>;

struct Harness {
    service: Option<PublicService>,
    authority_id: EngineId,
}

impl Harness {
    fn new() -> Self {
        let authority_id = EngineId::new([0x11; 16]);
        let authority =
            DurableAuthority::create_new(Store::default(), authority_id, Limits::default())
                .unwrap();
        Self {
            service: Some(
                Service::new(authority, authority_id, ServiceLimitsV1::default()).unwrap(),
            ),
            authority_id,
        }
    }
}

impl ConformanceHarnessV1 for Harness {
    type Error = aegis_host::HostError<Infallible>;

    fn open_session(&mut self, profile: SessionProfileV1) -> Result<SessionHandleV1, Self::Error> {
        let (principal, session, administrator) = match profile {
            SessionProfileV1::AdministratorA => ([0x21; 16], [0x31; 16], true),
            SessionProfileV1::AdministratorB => ([0x22; 16], [0x32; 16], true),
            SessionProfileV1::NonAdministrator => ([0x23; 16], [0x33; 16], false),
        };
        Ok(self
            .service
            .as_mut()
            .expect("service is present")
            .open_session(AuthenticatedSessionV1 {
                principal: PrincipalId::new(principal),
                session: SessionId::new(session),
                administrator,
            })
            .expect("conformance limits admit three sessions"))
    }

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        self.service
            .as_mut()
            .expect("service is present")
            .execute(session, command)
    }

    fn restart(&mut self) -> Result<(), Self::Error> {
        let service = self.service.take().expect("service is present");
        let store = service.into_authority().into_store();
        let authority = DurableAuthority::open(store, self.authority_id, Limits::default())?;
        self.service =
            Some(Service::new(authority, self.authority_id, ServiceLimitsV1::default()).unwrap());
        Ok(())
    }
}

#[test]
fn public_service_passes_continuity_and_non_amplification_contract() {
    qualify_authority_continuity_v1(&mut Harness::new());
}
