use aegis_client::{AdminClient, ClientError, ReadOnlyClient, ServicePort};
use aegis_protocol::{CommandV1, OutcomeV1, ReplyV1, SessionHandleV1};

#[derive(Default)]
struct Port(Vec<CommandV1>);

impl ServicePort for Port {
    type Error = ();

    fn execute(&mut self, _: SessionHandleV1, command: CommandV1) -> Result<ReplyV1, Self::Error> {
        self.0.push(command);
        Ok(ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 2 }))
    }
}

#[test]
fn facades_expose_only_their_projection_and_bound_pages() {
    let mut admin = AdminClient::new(SessionHandleV1(1), Port::default());
    admin.revoke_epoch(1).unwrap();
    assert_eq!(
        admin.into_port().0,
        vec![CommandV1::RevokeEpoch { expected_epoch: 1 }]
    );

    let mut reader = ReadOnlyClient::new(SessionHandleV1(1), Port::default(), 8).unwrap();
    assert_eq!(reader.grant_page(None, 9), Err(ClientError::Limit));
    assert_eq!(reader.decision_page(None, 0), Err(ClientError::Limit));
    reader.status().unwrap();
    reader.grant_page(None, 8).unwrap();
    assert_eq!(
        reader.into_port().0,
        vec![
            CommandV1::Status,
            CommandV1::GrantPage {
                after: None,
                limit: 8
            }
        ]
    );
}
