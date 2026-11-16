use aegis_protocol::*;
use aegis_wire::{
    CodecErrorV1, LimitsV1, RequestFrameV1, decode_reply, decode_request, decode_session_opened,
    encode_reply, encode_request, encode_session_opened,
};

fn scope() -> ScopeV1 {
    ScopeV1 {
        engine: EngineNamespaceV1::Daimon,
        resource: [0x31; 16],
        actions: 1 << ActionV1::Execute as u8,
    }
}

fn assert_mutation_canonical<T: std::fmt::Debug>(
    canonical: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, CodecErrorV1>,
    encode: impl Fn(&T) -> Result<Vec<u8>, CodecErrorV1>,
) {
    let mut rejected = 0_usize;
    let mut checked = 0_usize;
    let mut check = |mutated: Vec<u8>| {
        checked += 1;
        match decode(&mutated) {
            Ok(value) => assert_eq!(encode(&value).unwrap(), mutated),
            Err(_) => rejected += 1,
        }
    };

    for index in 0..canonical.len() {
        for bit in 0..8 {
            let mut mutated = canonical.to_vec();
            mutated[index] ^= 1 << bit;
            check(mutated);
        }
        let mut deleted = canonical.to_vec();
        deleted.remove(index);
        check(deleted);
    }
    for index in 0..=canonical.len() {
        let mut inserted = canonical.to_vec();
        inserted.insert(index, 0xff);
        check(inserted);
    }
    assert!(checked > 0);
    assert!(
        rejected > 0,
        "mutation corpus unexpectedly accepted everything"
    );
}

#[test]
fn every_request_shape_has_canonical_single_byte_and_bit_mutation_behavior() {
    let commands = vec![
        CommandV1::Issue {
            expected_epoch: 1,
            now: 2,
            expires_at: 9,
            scopes: vec![scope()],
        },
        CommandV1::Attenuate {
            parent: GrantHandleV1(3),
            expected_epoch: 1,
            now: 2,
            expires_at: 8,
            scopes: vec![scope()],
        },
        CommandV1::Authorize {
            grant: GrantHandleV1(3),
            now: 2,
            engine: EngineNamespaceV1::Daimon,
            resource: [0x31; 16],
            action: ActionV1::Execute,
        },
        CommandV1::RevokeEpoch { expected_epoch: 2 },
        CommandV1::Status,
        CommandV1::GrantPage {
            after: Some(GrantHandleV1(4)),
            limit: 7,
        },
        CommandV1::DecisionPage {
            after: Some(DecisionHandleV1(5)),
            limit: 7,
        },
    ];
    for command in commands {
        let frame = RequestFrameV1 {
            session: SessionHandleV1(6),
            command,
        };
        let bytes = encode_request(&frame, LimitsV1::default()).unwrap();
        assert_mutation_canonical(
            &bytes,
            |value| decode_request(value, LimitsV1::default()),
            |value| encode_request(value, LimitsV1::default()),
        );
    }
}

#[test]
fn every_reply_shape_has_canonical_single_byte_and_bit_mutation_behavior() {
    let grant = GrantSummaryV1 {
        handle: GrantHandleV1(1),
        parent: Some(GrantHandleV1(2)),
        epoch: 3,
        expires_at: 9,
        scope_count: 1,
        delegation_depth: 1,
    };
    let decision = DecisionSummaryV1 {
        handle: DecisionHandleV1(4),
        epoch: 3,
        expires_at: 9,
        engine: EngineNamespaceV1::Daimon,
        action: ActionV1::Execute,
    };
    let replies = vec![
        ReplyV1::Accepted(OutcomeV1::GrantIssued(grant)),
        ReplyV1::Accepted(OutcomeV1::Authorized(decision)),
        ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 4 }),
        ReplyV1::Accepted(OutcomeV1::Status(AuthorityStatusV1 {
            epoch: 4,
            active_grants: 1,
            retained_decisions: 1,
        })),
        ReplyV1::Accepted(OutcomeV1::GrantPage {
            entries: vec![grant],
            next_after: Some(grant.handle),
        }),
        ReplyV1::Accepted(OutcomeV1::DecisionPage {
            entries: vec![decision],
            next_after: Some(decision.handle),
        }),
        ReplyV1::Refused(RefusalV1::UnknownSession),
        ReplyV1::Refused(RefusalV1::StaleEpoch { actual: 7 }),
    ];
    for reply in replies {
        let bytes = encode_reply(&reply, LimitsV1::default()).unwrap();
        assert_mutation_canonical(
            &bytes,
            |value| decode_reply(value, LimitsV1::default()),
            |value| encode_reply(value, LimitsV1::default()),
        );
    }
}

#[test]
fn session_handshake_has_canonical_single_byte_and_bit_mutation_behavior() {
    let bytes = encode_session_opened(SessionHandleV1(8), LimitsV1::default()).unwrap();
    assert_mutation_canonical(
        &bytes,
        |value| decode_session_opened(value, LimitsV1::default()),
        |value| encode_session_opened(*value, LimitsV1::default()),
    );
}
