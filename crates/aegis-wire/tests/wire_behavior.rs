use aegis_protocol::*;
use aegis_wire::{
    CodecErrorV1, LimitsV1, RequestFrameV1, decode_reply, decode_request, decode_session_opened,
    encode_reply, encode_request, encode_session_opened,
};

fn scope() -> ScopeV1 {
    ScopeV1 {
        engine: EngineNamespaceV1::Hermes,
        resource: [9; 16],
        actions: 0b01_0001,
    }
}

#[test]
fn every_command_roundtrips_and_resource_debug_is_redacted() {
    let commands = vec![
        CommandV1::Issue {
            expected_epoch: 0,
            now: 1,
            expires_at: 9,
            scopes: vec![scope()],
        },
        CommandV1::Attenuate {
            parent: GrantHandleV1(3),
            expected_epoch: 0,
            now: 2,
            expires_at: 8,
            scopes: vec![scope()],
        },
        CommandV1::Authorize {
            grant: GrantHandleV1(3),
            now: 2,
            engine: EngineNamespaceV1::Hermes,
            resource: [9; 16],
            action: ActionV1::Observe,
        },
        CommandV1::RevokeEpoch { expected_epoch: 2 },
        CommandV1::Status,
        CommandV1::GrantPage {
            after: Some(GrantHandleV1(2)),
            limit: 7,
        },
        CommandV1::DecisionPage {
            after: Some(DecisionHandleV1(4)),
            limit: 8,
        },
    ];
    for command in commands {
        let frame = RequestFrameV1 {
            session: SessionHandleV1(5),
            command,
        };
        let bytes = encode_request(&frame, LimitsV1::default()).unwrap();
        assert_eq!(decode_request(&bytes, LimitsV1::default()).unwrap(), frame);
        for end in 0..bytes.len() {
            assert!(decode_request(&bytes[..end], LimitsV1::default()).is_err());
        }
    }
    assert!(!format!("{:?}", scope()).contains("9, 9"));
}

#[test]
fn replies_roundtrip_and_limits_refuse_before_allocation() {
    let grant = GrantSummaryV1 {
        handle: GrantHandleV1(1),
        parent: None,
        epoch: 2,
        expires_at: 9,
        scope_count: 1,
        delegation_depth: 0,
    };
    let decision = DecisionSummaryV1 {
        handle: DecisionHandleV1(2),
        epoch: 2,
        expires_at: 9,
        engine: EngineNamespaceV1::Hermes,
        action: ActionV1::Observe,
    };
    let replies = vec![
        ReplyV1::Accepted(OutcomeV1::GrantIssued(grant)),
        ReplyV1::Accepted(OutcomeV1::Authorized(decision)),
        ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 3 }),
        ReplyV1::Accepted(OutcomeV1::Status(AuthorityStatusV1 {
            epoch: 3,
            active_grants: 1,
            retained_decisions: 1,
        })),
        ReplyV1::Accepted(OutcomeV1::GrantPage {
            entries: vec![grant],
            next_after: Some(grant.handle),
        }),
        ReplyV1::Accepted(OutcomeV1::DecisionPage {
            entries: vec![decision],
            next_after: None,
        }),
        ReplyV1::Refused(RefusalV1::GrantOwnedByAnotherSession),
        ReplyV1::Refused(RefusalV1::StaleEpoch { actual: 7 }),
    ];
    for reply in replies {
        let bytes = encode_reply(&reply, LimitsV1::default()).unwrap();
        assert_eq!(decode_reply(&bytes, LimitsV1::default()).unwrap(), reply);
    }
    let frame = RequestFrameV1 {
        session: SessionHandleV1(1),
        command: CommandV1::Issue {
            expected_epoch: 0,
            now: 0,
            expires_at: 1,
            scopes: vec![scope(), scope()],
        },
    };
    assert_eq!(
        encode_request(
            &frame,
            LimitsV1 {
                max_scopes: 1,
                ..LimitsV1::default()
            }
        ),
        Err(CodecErrorV1::Limit)
    );
    let bytes = encode_request(&frame, LimitsV1::default()).unwrap();
    assert_eq!(
        decode_request(
            &bytes,
            LimitsV1 {
                max_scopes: 1,
                ..LimitsV1::default()
            }
        ),
        Err(CodecErrorV1::Limit)
    );
}

#[test]
fn authenticated_session_handshake_is_closed_and_bounded() {
    let session = SessionHandleV1(42);
    let bytes = encode_session_opened(session, LimitsV1::default()).unwrap();
    assert_eq!(
        decode_session_opened(&bytes, LimitsV1::default()),
        Ok(session)
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        decode_session_opened(&trailing, LimitsV1::default()),
        Err(CodecErrorV1::Malformed)
    );
}
