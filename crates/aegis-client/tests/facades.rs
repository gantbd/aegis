use aegis_client::{
    AdminClient, AuthorityClient, Client, ClientError, ReadOnlyClient, ServicePort,
};
use aegis_protocol::{CommandV1, OutcomeV1, ReplyV1, ScopeV1, SessionHandleV1};

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
fn mutation_facade_can_borrow_a_live_port_without_owning_its_connection() {
    let mut port = Port::default();
    let scopes = vec![ScopeV1 {
        engine: aegis_protocol::EngineNamespaceV1::Agora,
        resource: [3; 16],
        actions: 1 << aegis_protocol::ActionV1::Submit as u8,
    }];
    {
        let mut authority = AuthorityClient::new(SessionHandleV1(7), &mut port);
        authority.current_principal().unwrap();
        authority.issue(2, 10, 20, scopes.clone()).unwrap();
    }
    assert_eq!(
        port.0,
        vec![
            CommandV1::CurrentPrincipal,
            CommandV1::Issue {
                expected_epoch: 2,
                now: 10,
                expires_at: 20,
                scopes,
            }
        ]
    );
}

#[test]
fn session_client_observes_only_its_current_principal() {
    let mut client = Client::new(SessionHandleV1(7), Port::default());
    client.current_principal().unwrap();
    assert_eq!(client.into_port().0, vec![CommandV1::CurrentPrincipal]);
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
