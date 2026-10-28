//! Compatibility fixtures (SPEC, "Format changes"): bytes written by a
//! format version must keep decoding to the same values. Regenerate a
//! fixture only for a new record or field, with `KRONIK_WRITE_FIXTURES=1`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

fn fixture(name: &str, record: &Record) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}.hex", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("KRONIK_WRITE_FIXTURES").is_some() {
        let hex: String = record.encode().iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&path, hex + "\n").unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let text = text.trim();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// `SimulatorConfig`, kind 15 (M12, ADR 0014).
#[test]
fn simulator_config_v1() {
    let record = Record::SimulatorConfig(pb::SimulatorConfig {
        epoch: 7,
        target: "http:payments.internal".into(),
        stubs: vec![pb::StubRuleSpec {
            method: "GET".into(),
            url_prefix: "https://payments.internal/v1/charges/".into(),
            status: 200,
            headers: vec![pb::HeaderPair {
                name: "content-type".into(),
                value: "application/json".into(),
            }],
            body: br#"{"id":"ch_1"}"#.to_vec(),
            error: String::new(),
        }],
        contract: br#"{"openapi":"3.0.3"}"#.to_vec(),
        neighbor: true,
        model: false,
        audit: Some(pb::Audit {
            token_id: "admin".into(),
            reason: "payments contract".into(),
            wall_time_ms: 1_793_000_000_000,
        }),
    });
    let bytes = fixture("simulator-config-v1", &record);
    assert_eq!(
        Record::decode(kronik_proto::kind::SIMULATOR_CONFIG, &bytes).unwrap(),
        record
    );
}

/// `EffectRecord.simulator` (field 13, M12) inside a `TurnRecord`; a record
/// without it still decodes with the field empty.
#[test]
fn effect_record_simulator_v1() {
    let record = Record::TurnRecord(pb::TurnRecord {
        execution_id: "00112233445566778899aabbccddeeff".into(),
        actor: Some(pb::ActorRef {
            kind: "billing".into(),
            key: "a".into(),
        }),
        causal_key: Some(pb::CausalKey {
            root: "r1".into(),
            path: vec![],
        }),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(pb::Sealable {
                        subject: None,
                        value: Some(pb::sealable::Value::Plain(vec![])),
                    })),
                }),
                ..Default::default()
            })),
        }),
        effects: vec![pb::EffectRecord {
            ordinal: 1,
            kind: "http.fetch".into(),
            status: pb::EffectStatus::Ok as i32,
            grounding: pb::Grounding::Synthetic as i32,
            target: "http:payments.internal".into(),
            simulator: "contract".into(),
            ..Default::default()
        }],
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        ..Default::default()
    });
    let bytes = fixture("effect-record-simulator-v1", &record);
    assert_eq!(
        Record::decode(kronik_proto::kind::TURN_RECORD, &bytes).unwrap(),
        record
    );
}

/// A small committed turn record, as a rebase fork records one.
fn turn() -> pb::TurnRecord {
    pb::TurnRecord {
        execution_id: "ffeeddccbbaa99887766554433221100".into(),
        actor: Some(pb::ActorRef {
            kind: "billing".into(),
            key: "a".into(),
        }),
        causal_key: Some(pb::CausalKey {
            root: "r2".into(),
            path: vec![],
        }),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                method: "POST".into(),
                path: "/billing/a/increment".into(),
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(pb::Sealable {
                        subject: None,
                        value: Some(pb::sealable::Value::Plain(vec![])),
                    })),
                }),
                ..Default::default()
            })),
        }),
        writes: vec![pb::StateWrite {
            op: pb::StateOp::Set as i32,
            key: "n".into(),
            value: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(b"3".to_vec())),
            }),
        }],
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        config_epoch: 4,
        ..Default::default()
    }
}

/// `StateRebase`, kind 16 (M13, ADR 0017): a rebased turn.
#[test]
fn state_rebase_turn_v1() {
    let record = Record::StateRebase(pb::StateRebase {
        rebase_id: "r-0123456789ab".into(),
        part: Some(pb::state_rebase::Part::Turn(pb::RebasedTurn {
            fork_lsn: 13,
            record: Some(turn()),
        })),
    });
    let bytes = fixture("state-rebase-turn-v1", &record);
    let decoded = Record::decode(kronik_proto::kind::STATE_REBASE, &bytes).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.turn(), Some(&turn()));
}

/// `StateRebase`, kind 16: the switch.
#[test]
fn state_rebase_switch_v1() {
    let record = Record::StateRebase(pb::StateRebase {
        rebase_id: "r-0123456789ab".into(),
        part: Some(pb::state_rebase::Part::Switch(pb::RebaseSwitch {
            base_lsn: 10,
            rolled_back_epoch: 3,
            verified_through_lsn: 40,
            first_turn_lsn: 41,
            last_turn_lsn: 70,
            turns: 30,
            deployment: Some(pb::Deployment {
                epoch: 5,
                kinds: vec![pb::KindVersion {
                    kind: "billing".into(),
                    code_hash: vec![7; 32],
                    schema_version: 0,
                    manifest: Some(pb::Manifest {
                        kind: "billing".into(),
                        ..Default::default()
                    }),
                    code_size: 100,
                }],
                cause: pb::DeploymentCause::Rollback as i32,
                proposal_id: "r-0123456789ab".into(),
                rollback_of_epoch: 3,
                ..Default::default()
            }),
            diff_hash: "b3:00ff".into(),
            irreversible_effects: 2,
            audit: Some(pb::Audit {
                token_id: "admin".into(),
                reason: "undo the schema change".into(),
                wall_time_ms: 1_793_000_000_000,
            }),
        })),
    });
    let bytes = fixture("state-rebase-switch-v1", &record);
    let decoded = Record::decode(kronik_proto::kind::STATE_REBASE, &bytes).unwrap();
    assert_eq!(decoded, record);
    assert!(decoded.turn().is_none());
    assert_eq!(
        decoded.rebase_switch().map(|(id, s)| (id, s.turns)),
        Some(("r-0123456789ab", 30))
    );
}

/// `ForeignActor.fork_mode` (field 12, M14, ADR 0019); an older record
/// without it reads as empty (recorded).
#[test]
fn foreign_actor_fork_mode_v1() {
    let record = Record::ForeignActor(pb::ForeignActor {
        epoch: 3,
        op: pb::ForeignOp::Add as i32,
        name: "pg".into(),
        image: "oci-layout:/srv/foreign-pg.oci@sha256:".to_owned() + &"ab".repeat(32),
        port: 8080,
        cpu_millis: 1000,
        memory_bytes: 536_870_912,
        isolation: pb::Isolation::Gvisor as i32,
        platform: "systrap".into(),
        fork_mode: "sandbox".into(),
        ..Default::default()
    });
    let bytes = fixture("foreign-actor-fork-mode-v1", &record);
    assert_eq!(
        Record::decode(kronik_proto::kind::FOREIGN_ACTOR, &bytes).unwrap(),
        record
    );
}

/// `GROUNDING_FORKED` (5, M14, ADR 0020) on an effect of a fork turn.
#[test]
fn effect_record_forked_v1() {
    let mut t = turn();
    t.effects.push(pb::EffectRecord {
        ordinal: 1,
        kind: "foreign.http".into(),
        target: "foreign:pg".into(),
        status: pb::EffectStatus::Ok as i32,
        grounding: pb::Grounding::Forked as i32,
        ..Default::default()
    });
    let record = Record::TurnRecord(t);
    let bytes = fixture("effect-record-forked-v1", &record);
    assert_eq!(
        Record::decode(kronik_proto::kind::TURN_RECORD, &bytes).unwrap(),
        record
    );
}
