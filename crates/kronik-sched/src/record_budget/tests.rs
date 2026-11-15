use super::*;

fn tagged(bytes: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: Some("user:1".into()),
        value: Some(pb::sealable::Value::Plain(bytes.to_vec())),
    })
}

fn message(bytes: &[u8]) -> pb::Message {
    pb::Message {
        name: "m".into(),
        content_type: "text/plain".into(),
        body: tagged(bytes),
        ..Default::default()
    }
}

fn effect(ordinal: u32, response: usize) -> pb::EffectRecord {
    pb::EffectRecord {
        ordinal,
        kind: "http.fetch".into(),
        fingerprint: vec![1; 32],
        request: tagged(b"GET https://example.com/"),
        response: tagged(&vec![b'r'; response]),
        status: pb::EffectStatus::Ok as i32,
        grounding: pb::Grounding::Live as i32,
        duration_us: u64::MAX,
        offset_us: 1234,
        ..Default::default()
    }
}

fn compensation() -> pb::OutboundMessage {
    pb::OutboundMessage {
        to: Some(pb::ActorRef {
            kind: "ledger".into(),
            key: "a".into(),
        }),
        msg: Some(message(b"undo")),
        ordinal: 3,
        message_id: "c".repeat(32),
    }
}

/// A compensation of `bytes` bytes, as a successful call of `ordinal`
/// records it.
fn big_compensation(ordinal: u32, bytes: usize) -> pb::OutboundMessage {
    let mut compensation = compensation();
    compensation.ordinal = ordinal;
    compensation.message_id = format!("{ordinal:032x}");
    compensation.msg = Some(message(&vec![b'c'; bytes]));
    compensation
}

/// A committed turn with every kind of user data.
fn turn(writes: usize, value: usize) -> pb::TurnRecord {
    pb::TurnRecord {
        execution_id: "e".repeat(32),
        actor: Some(pb::ActorRef {
            kind: "counter".into(),
            key: "a".into(),
        }),
        code_hash: vec![7; 32],
        engine_version: "kronik-0.5.0+wasmtime-30.0.0".into(),
        causal_key: Some(pb::CausalKey {
            root: "r".repeat(32),
            path: vec![],
        }),
        logical_time_ms: 1_761_400_000_000,
        random_seed: vec![9; 32],
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                msg: Some(message(b"hello")),
                message_id: "i".repeat(32),
                ..Default::default()
            })),
        }),
        effects: vec![effect(0, 100), effect(1, 200)],
        writes: (0..writes)
            .map(|i| pb::StateWrite {
                op: pb::StateOp::Set as i32,
                key: format!("k{i}"),
                value: tagged(&vec![b'v'; value]),
            })
            .collect(),
        messages: vec![pb::OutboundMessage {
            msg: Some(message(b"out")),
            ..compensation()
        }],
        timers: vec![pb::TimerOp {
            kind: pb::TimerOpKind::Schedule as i32,
            timer_id: 5,
            due_ms: 1_761_400_000_500,
            msg: Some(message(b"tick")),
            ..Default::default()
        }],
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            output: Some(pb::outcome::Output::Reply(message(b"ok"))),
            ..Default::default()
        }),
        fuel_used: 1_000_000,
        sql_changes: vec![pb::SqlChangeset {
            changeset: tagged(&[3; 40]),
        }],
        sql_schema: vec![pb::SqlSchemaChange {
            statement: "CREATE TABLE t (x)".into(),
        }],
        config_epoch: 4,
        memory_peak_bytes: 1 << 20,
        schema_version: 1,
        duration_us: u64::MAX,
        ..Default::default()
    }
}

/// [`input_cost`] of a record's (plain) input.
fn ic(t: &mut pb::TurnRecord) -> usize {
    input_cost(t.input.as_mut().unwrap())
}

/// Seals every value the way the sealer does: the largest key version, a
/// 24-byte nonce and a 16-byte tag.
fn sealed(mut record: pb::TurnRecord) -> pb::TurnRecord {
    sealables::turn_mut(&mut record, &mut |s| {
        if let Some(pb::sealable::Value::Plain(bytes)) = s.value.take() {
            let mut ciphertext = bytes;
            ciphertext.extend_from_slice(&[0xee; 16]);
            s.value = Some(pb::sealable::Value::Sealed(pb::Sealed {
                key_version: u32::MAX,
                nonce: vec![0xaa; 24],
                ciphertext,
            }));
        }
    });
    record
}

#[test]
fn the_cost_covers_the_sealed_record_and_its_envelope_fields() {
    for (writes, value) in [(0, 0), (1, 1), (50, 1), (3, 127), (3, 128), (200, 16_400)] {
        let mut plain = turn(writes, value);
        let input = ic(&mut plain);
        let cost = turn_cost(&mut plain, input);
        let sealed = sealed(plain.clone());
        assert!(
            sealed.encoded_len() <= cost + TURN_RESERVE,
            "{writes} writes of {value}: sealed {} > cost {cost} + reserve",
            sealed.encoded_len()
        );
        // The same record in a StateRebase still fits (M13).
        let wrapped = kronik_proto::Record::StateRebase(pb::StateRebase {
            rebase_id: "r".repeat(40),
            part: Some(pb::state_rebase::Part::Turn(pb::RebasedTurn {
                fork_lsn: u64::MAX,
                record: Some(sealed),
            })),
        });
        assert!(wrapped.encoded_len() <= cost + TURN_RESERVE);
    }
}

#[test]
fn the_cost_ignores_what_a_replay_does_not_reproduce() {
    let mut production = turn(3, 10);
    let mut replay = production.clone();
    replay.execution_id.clear();
    replay.engine_version = "kronik-9.9.9+wasmtime-99.9.9-other".into();
    replay.duration_us = 0;
    for e in &mut replay.effects {
        e.duration_us = 0;
        e.offset_us = 0;
    }
    let input = ic(&mut production);
    assert_eq!(
        turn_cost(&mut production, input),
        turn_cost(&mut replay, input)
    );
    // A production turn may hold its input sealed (a message from the
    // mailbox) where its replay holds it plain: both are charged its
    // plaintext cost.
    let mut sealed_input = sealed(production.clone());
    sealed_input.effects = production.effects.clone();
    sealed_input.writes = production.writes.clone();
    sealed_input.messages = production.messages.clone();
    sealed_input.timers = production.timers.clone();
    sealed_input.sql_changes = production.sql_changes.clone();
    sealed_input.outcome = production.outcome.clone();
    assert_ne!(sealed_input.input, production.input);
    assert_eq!(
        turn_cost(&mut sealed_input, input),
        turn_cost(&mut production, input)
    );
    // Measuring leaves the record as it was.
    assert_eq!(production, turn(3, 10));
    let mut e = effect(0, 10);
    let before = e.clone();
    let cost = effect_cost(&mut e);
    assert_eq!(e, before);
    e.duration_us = 0;
    e.offset_us = 0;
    assert_eq!(effect_cost(&mut e), cost);
}

#[test]
fn a_record_over_the_limit_becomes_a_failed_turn_that_fits() {
    let mut fits = turn(2, 10);
    let input = ic(&mut fits);
    let limit = turn_cost(&mut fits, input);
    let before = fits.clone();
    assert_eq!(fit(&mut fits, &[compensation()], limit, input), Fit::Fits);
    assert_eq!(fits, before);

    let mut big = turn(100, 1_000);
    assert!(turn_cost(&mut big, input) > limit);
    assert_eq!(fit(&mut big, &[compensation()], limit, input), Fit::Failed);
    assert!(turn_cost(&mut big, input) <= limit);
    assert!(big.writes.is_empty() && big.messages.is_empty() && big.timers.is_empty());
    assert!(big.sql_changes.is_empty() && big.sql_schema.is_empty());
    assert_eq!(big.schema_version, 0);
    // Input, effects and compensations stay: they happened.
    assert_eq!(big.input, before.input);
    assert_eq!(big.effects, before.effects);
    assert_eq!(big.compensations, vec![compensation()]);
    let outcome = big.outcome.clone().unwrap();
    assert_eq!(outcome.kind, pb::OutcomeKind::Trap as i32);
    assert_eq!(outcome.error_code, "TURN_TOO_LARGE");
    assert!(outcome.output.is_none());

    // A replay of the same turn decides the same and says the same.
    let mut replayed = turn(100, 1_000);
    replayed.execution_id.clear();
    replayed.duration_us = 0;
    assert_eq!(
        fit(&mut replayed, &[compensation()], limit, input),
        Fit::Failed
    );
    assert_eq!(replayed.outcome, big.outcome);
}

/// The gate admits effects and compensations up to the byte; the failed
/// record of that turn still fits without leaving anything out, because the
/// budget started with room for its outcome.
#[test]
fn the_failed_record_of_a_turn_whose_effects_filled_the_budget_fits() {
    let mut record = turn(200, 1_000);
    record.fuel_used = u64::MAX;
    record.memory_peak_bytes = u64::MAX;
    record.schema_version = u32::MAX;
    let input = ic(&mut record);
    let base = base_cost(
        record.actor.as_ref().unwrap(),
        &record.code_hash,
        record.causal_key.as_ref().unwrap(),
        record.logical_time_ms,
        &record.random_seed,
        input,
        record.config_epoch,
    );
    let mut effects: Vec<pb::EffectRecord> = (0..3).map(|o| effect(o, 5_000)).collect();
    let mut comp = compensation();
    let used: usize = effects.iter_mut().map(effect_cost).sum::<usize>() + message_cost(&mut comp);
    // The budget the gate had: exactly what it admitted.
    let limit = base + used;
    let mut budget = Budget::new(limit, base);
    for e in &mut effects {
        let cost = effect_cost(e);
        budget.take(cost, e.ordinal, &e.kind).unwrap();
    }
    budget.charge(message_cost(&mut comp));
    assert_eq!(budget.remaining(), 0);
    record.effects = effects.clone();
    assert_eq!(fit(&mut record, &[comp.clone()], limit, input), Fit::Failed);
    assert_eq!(record.effects, effects, "nothing was left out");
    assert_eq!(record.compensations, vec![comp]);
    assert!(turn_cost(&mut record, input) <= limit);
}

#[test]
fn effects_an_earlier_release_recorded_past_the_budget_are_left_out_last() {
    let mut record = turn(0, 0);
    record.effects = (0..10).map(|o| effect(o, 10_000)).collect();
    let limit = 20_000;
    let input = ic(&mut record);
    assert_eq!(fail(&mut record, &[], limit, input), Fit::Stripped);
    assert_eq!(record.effects.len(), 10);
    assert!(
        record
            .effects
            .iter()
            .all(|e| e.request.is_none() && e.response.is_none())
    );
    assert!(turn_cost(&mut record, input) <= limit);
    assert_eq!(record.outcome.unwrap().error_code, "TURN_TOO_LARGE");
}

/// Issue #87: a pre-0.5 turn can record compensation messages that, alone
/// and after its effects' payloads are left out, take its failed record past
/// the budget. They are the last rung before the effects: left out, the
/// successful calls become orphans; leaving them in would make the log
/// refuse the record and keep the turn open at every start.
#[test]
fn an_earlier_releases_compensations_are_left_out_last() {
    let effects = || (0..2).map(|o| effect(o, 100)).collect::<Vec<_>>();
    let compensations: Vec<pb::OutboundMessage> =
        (0..2).map(|o| big_compensation(o, 40_000)).collect();
    let limit = 60_000;

    let mut record = turn(0, 0);
    record.effects = effects();
    let input = ic(&mut record);
    assert_eq!(
        fail(&mut record, &compensations, limit, input),
        Fit::Stripped
    );
    assert!(record.compensations.is_empty());
    assert_eq!(
        record.effects.len(),
        2,
        "the effects' own records stay: their results are still in the log"
    );
    assert!(
        record
            .effects
            .iter()
            .all(|e| e.request.is_none() && e.response.is_none()),
        "the effects' payloads go before their records do"
    );
    assert!(turn_cost(&mut record, input) <= limit);
    let outcome = record.outcome.clone().unwrap();
    assert_eq!(outcome.error_code, "TURN_TOO_LARGE");
    assert!(
        outcome
            .message
            .contains("; its 2 compensations are not recorded: their calls are orphans"),
        "{outcome:?}"
    );

    // fit_closing, the re-run that closes a turn without running its guest,
    // applies the same ladder to compensations already in its record.
    let mut closing = turn(0, 0);
    closing.writes.clear();
    closing.messages.clear();
    closing.timers.clear();
    closing.effects = effects();
    closing.compensations = compensations;
    closing.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Failed as i32,
        error_code: "TURN_TOO_LARGE".into(),
        ..Default::default()
    });
    let input = ic(&mut closing);
    assert_eq!(fit_closing(&mut closing, limit, input), Fit::Stripped);
    assert!(closing.compensations.is_empty());
    assert_eq!(closing.effects.len(), 2);
    assert!(turn_cost(&mut closing, input) <= limit);
    assert!(
        closing
            .outcome
            .as_ref()
            .unwrap()
            .message
            .contains("its 2 compensations are not recorded"),
        "{:?}",
        closing.outcome
    );
}

/// `Fit::Stripped` promises a record that fits: when leaving out the
/// payloads of what an earlier release recorded is not enough, the effects
/// themselves go too (their results stay in the log), and when even that is
/// over the limit the answer says so instead of claiming it fits.
#[test]
fn a_stripped_record_fits_or_says_it_does_not() {
    // Many effects whose bodies are small: the payloads are not the bulk.
    let mut record = turn(0, 0);
    record.effects = (0..2_000)
        .map(|o| pb::EffectRecord {
            target: "t".repeat(200),
            ..effect(o, 1)
        })
        .collect();
    let input = ic(&mut record);
    let limit = 60_000;
    assert_eq!(fail(&mut record, &[], limit, input), Fit::Stripped);
    assert!(turn_cost(&mut record, input) <= limit);
    assert!(record.effects.is_empty());
    let message = record.outcome.as_ref().unwrap().message.clone();
    assert!(
        message.contains("its 2000 effects are only in its effect results"),
        "{message}"
    );

    // fit_closing applies the same ladder to a record that closes a turn.
    let mut closing = turn(0, 0);
    closing.writes.clear();
    closing.messages.clear();
    closing.timers.clear();
    closing.effects = (0..2_000)
        .map(|o| pb::EffectRecord {
            target: "t".repeat(200),
            ..effect(o, 1)
        })
        .collect();
    let input = ic(&mut closing);
    assert_eq!(fit_closing(&mut closing, limit, input), Fit::Stripped);
    assert!(turn_cost(&mut closing, input) <= limit);

    // An input over the limit cannot be left out: Over, not Stripped.
    let mut over = turn(0, 0);
    let input = ic(&mut over) + limit;
    assert_eq!(fail(&mut over, &[], limit, input), Fit::Over);
    let mut over = turn(0, 0);
    assert_eq!(fit_closing(&mut over, limit, input), Fit::Over);
}

/// A turn that fails after an effect whose outcome is unknown ends with
/// EFFECT_OUTCOME_UNKNOWN also when its record was too large: the effect's
/// record stays, and so does the code a client acts on. A committed turn
/// keeps its outcome, and a failed turn without such an effect is
/// TURN_TOO_LARGE as before.
#[test]
fn an_unknown_outcome_survives_a_record_that_is_too_large() {
    let unknown = |mut record: pb::TurnRecord| {
        record.effects[1].status = pb::EffectStatus::OutcomeUnknown as i32;
        record.effects[1].response = None;
        record
    };
    let mut big = unknown(turn(100, 1_000));
    big.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Failed as i32,
        error_code: "TURN_FAILED".into(),
        ..Default::default()
    });
    let input = ic(&mut big);
    let mut small = turn(2, 10);
    let limit = turn_cost(&mut small, input);
    assert_eq!(fit(&mut big, &[], limit, input), Fit::Failed);
    let outcome = big.outcome.clone().unwrap();
    assert_eq!(outcome.kind, pb::OutcomeKind::EffectOutcomeUnknown as i32);
    assert_eq!(outcome.error_code, "EFFECT_OUTCOME_UNKNOWN");
    assert!(
        outcome.message.contains("does not fit in one log record"),
        "{outcome:?}"
    );
    assert!(
        big.effects
            .iter()
            .any(|e| e.status == pb::EffectStatus::OutcomeUnknown as i32)
    );
    assert!(turn_cost(&mut big, input) <= limit);

    // `fail` (an output too large) decides the same.
    let mut output = unknown(turn(2, 10));
    assert_eq!(fail(&mut output, &[], limit * 4, input), Fit::Failed);
    assert_eq!(output.outcome.unwrap().error_code, "EFFECT_OUTCOME_UNKNOWN");

    // A record that fits and did not commit is marked as well; one that
    // committed is not.
    let mut failed = unknown(turn(2, 10));
    failed.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Trap as i32,
        error_code: "TURN_FAILED".into(),
        ..Default::default()
    });
    assert_eq!(fit(&mut failed, &[], limit * 4, input), Fit::Fits);
    assert_eq!(failed.outcome.unwrap().error_code, "EFFECT_OUTCOME_UNKNOWN");
    let mut committed = unknown(turn(2, 10));
    let before = committed.outcome.clone();
    assert_eq!(fit(&mut committed, &[], limit * 4, input), Fit::Fits);
    assert_eq!(committed.outcome, before);

    // Without such an effect, TURN_TOO_LARGE as before.
    let mut plain = turn(100, 1_000);
    assert_eq!(fit(&mut plain, &[], limit, input), Fit::Failed);
    assert_eq!(plain.outcome.unwrap().error_code, "TURN_TOO_LARGE");
}

#[test]
fn the_budget_refuses_what_does_not_fit_and_charges_what_happened() {
    let mut budget = Budget::new(1_000, 400);
    assert_eq!(budget.remaining(), 600);
    budget.take(600, 0, "http.fetch").unwrap();
    assert_eq!(budget.remaining(), 0);
    let err = budget.take(1, 1, "actor.call").unwrap_err();
    assert!(
        matches!(&err, GateError::TurnTooLarge(m) if m.contains("effect 1 (actor.call)")),
        "{err:?}"
    );
    // A recorded result a re-run replays is charged even past the limit.
    budget.charge(50);
    assert_eq!(budget.remaining(), 0);
    assert!(!budget.fits(1));
    // An unset budget has no room: a gate that forgot it refuses.
    assert!(!Budget::default().fits(1));
}

#[test]
fn a_response_may_take_what_is_left_after_its_need() {
    let budget = Budget::new(100_000, 10_000);
    let need = fetch_need(500);
    assert_eq!(
        response_room(&budget, need, u64::MAX),
        (90_000 - need) as u64
    );
    assert_eq!(response_room(&budget, need, 10), 10);
    assert_eq!(response_room(&budget, 200_000, u64::MAX), 0);
}

/// Review R-1: a turn whose record would not decode (here a reply naming a
/// `b3s:` reference without its subject) fails instead: what it wrote,
/// sent and answered goes, its effects stay, and the record decodes.
#[test]
fn an_undecodable_turn_record_fails_and_decodes() {
    use kronik_proto::Record;
    let mut t = turn(2, 10);
    if let Some(pb::input::Kind::Message(m)) = t.input.as_mut().and_then(|i| i.kind.as_mut()) {
        m.source = pb::MessageSource::Operator as i32;
    }
    t.effects = vec![effect(0, 10)];
    t.compensations.clear();
    Record::TurnRecord(t.clone())
        .validate()
        .expect("a valid record before the forged reply");
    let effects = t.effects.len();
    t.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Committed as i32,
        output: Some(pb::outcome::Output::Reply(pb::Message {
            name: "forged".into(),
            blobs: vec![pb::BlobRef {
                hash: format!("b3s:{}", "ab".repeat(32)),
                size: 10,
                subject: None,
                key_version: 0,
            }],
            ..message(b"")
        })),
        ..Default::default()
    });
    let wrapped = Record::TurnRecord(t);
    let why = wrapped.validate().expect_err("the forged reference");
    let Record::TurnRecord(mut t) = wrapped else {
        panic!("a turn record")
    };
    invalid(&mut t, &[compensation()], why.to_string());
    assert!(t.writes.is_empty() && t.messages.is_empty());
    assert_eq!(t.effects.len(), effects, "the effects stay");
    assert_eq!(t.compensations.len(), 1);
    let outcome = t.outcome.clone().unwrap();
    assert_eq!(outcome.error_code, "INTERNAL");
    assert!(outcome.output.is_none());
    Record::TurnRecord(t).validate().unwrap();
}

/// What an effect records inline (ADR 0145) is its request and its
/// response as recorded; a body stored as a blob is only its reference
/// there, and a result without either counts nothing.
#[test]
fn effect_bytes_are_the_request_and_response_as_recorded() {
    let e = effect(1, 1000);
    let request = e.request.as_ref().unwrap().encoded_len() as u64;
    let response = e.response.as_ref().unwrap().encoded_len() as u64;
    assert_eq!(effect_bytes(&e), request + response);
    assert!(effect_bytes(&e) > 1000);
    let refused = pb::EffectRecord {
        request: None,
        response: None,
        ..effect(2, 0)
    };
    assert_eq!(effect_bytes(&refused), 0);
    // A response stored as a blob: its reference, not its million bytes.
    let blob = pb::HttpEffectResponse {
        status: 200,
        headers: vec![],
        body: vec![],
        body_blob: Some(pb::BlobRef {
            hash: format!("b3:{}", "ab".repeat(32)),
            size: 1 << 20,
            subject: None,
            key_version: 0,
        }),
    };
    let blobbed = pb::EffectRecord {
        response: tagged(&blob.encode_to_vec()),
        ..effect(3, 0)
    };
    assert!(effect_bytes(&blobbed) < 200, "{}", effect_bytes(&blobbed));
}

/// The effect bytes take what fits up to their limit, exactly; a charge
/// (a result that happened) may pass it, and the refusals name the code.
#[test]
fn effect_bytes_fit_up_to_their_limit_and_charge_what_happened() {
    let mut bytes = EffectBytes::new(100);
    assert!(bytes.fits(100) && !bytes.fits(101));
    bytes.charge(60);
    assert_eq!(bytes.remaining(), 40);
    assert!(bytes.fits(40) && !bytes.fits(41));
    bytes.charge(60);
    assert_eq!(bytes.remaining(), 0);
    assert!(bytes.fits(0) && !bytes.fits(1));
    let refused = bytes.exceeded(false);
    assert!(refused.starts_with("EFFECT_BYTES_EXCEEDED: "), "{refused}");
    assert!(
        refused.contains("100 bytes") && refused.contains("not sent"),
        "{refused}"
    );
    assert!(bytes.exceeded(true).contains("not recorded"));
    assert_eq!(EffectBytes::default().remaining(), 0);
}
