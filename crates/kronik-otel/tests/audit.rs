//! The audit line mapping (docs/design/m28-otel.md §4.1, §4.3): the
//! classifier covers every record message with an `Audit` field, one golden
//! line per kind, and what never leaves (ADR 0082).

// Test helpers outside #[test] functions may unwrap.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use kronik_otel::audit::{
    Class, Ctx, Expected, Line, REASON_MAX, class, expected, lines, record_hash, verify,
};
use kronik_otel::spans::ActorKeys;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use prost::Message as _;

const SECRET_VALUE: &str = "hunter2-NEEDLE-secret";
const SUBJECT: &str = "carol@example.com";
const BODY: &str = "NEEDLE-message-body";
const WALL: u64 = 1_761_500_000_123;

fn audit(reason: &str) -> Option<pb::Audit> {
    Some(pb::Audit {
        token_id: "token:ci".into(),
        reason: reason.into(),
        wall_time_ms: WALL,
    })
}

fn hashed(kind: &str, key: &str) -> String {
    format!(
        "kh:{}",
        &blake3::hash(format!("{kind}/{key}").as_bytes()).to_hex()[..12]
    )
}

fn subject(s: &str) -> String {
    format!("s:{}", &blake3::hash(s.as_bytes()).to_hex()[..12])
}

fn secrets() -> Vec<(String, Vec<u8>)> {
    vec![("api-key".into(), SECRET_VALUE.as_bytes().to_vec())]
}

fn export(lsn: u64, record: &Record) -> Vec<Line> {
    let keys = ActorKeys::Hashed(&hashed);
    let secrets = secrets();
    lines(
        lsn,
        record,
        &Ctx {
            branch: "main",
            keys: &keys,
            subject: &subject,
            secrets: &secrets,
        },
    )
    .unwrap()
}

fn expected_record(lsn: u64, record: &Record) -> Vec<Expected> {
    expected(
        lsn,
        record,
        &Ctx {
            branch: "main",
            keys: &ActorKeys::Omit,
            subject: &subject,
            secrets: &[],
        },
    )
    .unwrap()
}

fn all_expected() -> Vec<Expected> {
    samples()
        .iter()
        .enumerate()
        .flat_map(|(i, record)| expected_record(i as u64 + 1, record))
        .collect()
}

fn sealed_body(text: &str) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: Some(SUBJECT.into()),
        value: Some(pb::sealable::Value::Plain(text.as_bytes().to_vec())),
    })
}

fn operator_turn(source: pb::MessageSource, reveal: bool) -> pb::TurnRecord {
    let mut effects = Vec::new();
    if reveal {
        effects.push(pb::EffectRecord {
            ordinal: 2,
            kind: "secret.reveal".into(),
            target: "secret-reveal:api-key".into(),
            status: pb::EffectStatus::Ok as i32,
            request: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(
                    pb::RevealEffectRequest {
                        secret: Some(pb::SecretRef {
                            name: "api-key".into(),
                            version: 3,
                            ..Default::default()
                        }),
                    }
                    .encode_to_vec(),
                )),
            }),
            // Guest text can hold the value: never exported.
            error: SECRET_VALUE.into(),
            ..Default::default()
        });
    }
    pb::TurnRecord {
        actor: Some(pb::ActorRef {
            kind: "counter".into(),
            key: SUBJECT.into(),
        }),
        logical_time_ms: WALL + 7,
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: source as i32,
                msg: Some(pb::Message {
                    name: "increment".into(),
                    body: sealed_body(BODY),
                    ..Default::default()
                }),
                resend_of: if source == pb::MessageSource::DeadLetterResend {
                    "main:12".into()
                } else {
                    String::new()
                },
                audit: audit("operator nudge"),
                ..Default::default()
            })),
        }),
        effects,
        ..Default::default()
    }
}

/// One record of every exported kind, with marked values everywhere.
fn samples() -> Vec<Record> {
    vec![
        Record::Deployment(pb::Deployment {
            epoch: 7,
            kinds: vec![pb::KindVersion {
                kind: "counter".into(),
                code_hash: vec![0xab; 32],
                schema_version: 1,
                ..Default::default()
            }],
            cause: pb::DeploymentCause::Promote as i32,
            proposal_id: "p-1".into(),
            audit: audit("PR #12"),
            ..Default::default()
        }),
        Record::Grant(pb::Grant {
            epoch: 8,
            op: pb::GrantOp::Grant as i32,
            kind: "counter".into(),
            capability: "http:example.com".into(),
            delivery: Some(pb::Delivery::ReplaySafe as i32),
            rate: Some(pb::Rate {
                count: 10,
                per_ms: 1000,
            }),
            audit: audit("needs the API"),
        }),
        Record::Limits(pb::Limits {
            epoch: 9,
            kind: "counter".into(),
            fuel: Some(1_000_000),
            effect_timeout_ms: Some(5000),
            audit: audit("tighter"),
            ..Default::default()
        }),
        Record::Policy(pb::Policy {
            epoch: 10,
            rules_toml: "[[rule]]\nname = \"no-deletes\"\nwhen = \"true\"\naction = \"deny\"\n"
                .into(),
            audit: audit("policy v2"),
            ..Default::default()
        }),
        Record::Approval(pb::Approval {
            proposal_id: "p-1".into(),
            diff_hash: vec![0xcd; 32],
            verified_through_lsn: 40,
            audit: audit("looks good"),
            request: false,
            command: format!("kronik promote p-1 --token {SECRET_VALUE}"),
            verified_identity: None,
        }),
        Record::PrivacyMode(pb::PrivacyMode {
            epoch: 11,
            mode: pb::PrivacyState::On as i32,
            audit: audit("GDPR"),
            reseal_requested: false,
        }),
        Record::ForeignActor(pb::ForeignActor {
            epoch: 12,
            op: pb::ForeignOp::Add as i32,
            name: "pay".into(),
            image: "oci-layout:/srv/pay@sha256:00".into(),
            port: 8080,
            isolation: pb::Isolation::Gvisor as i32,
            secrets: vec!["api-key".into()],
            audit: audit("payments"),
            ..Default::default()
        }),
        Record::Erasure(pb::Erasure {
            epoch: 13,
            subject: SUBJECT.into(),
            key_version: 2,
            audit: audit(&format!("erase request from {SUBJECT}")),
        }),
        Record::EngineUpgrade(pb::EngineUpgrade {
            epoch: 14,
            from_engine_version: "0.5.0".into(),
            to_engine_version: "0.6.0".into(),
            audit: audit("upgrade"),
            ..Default::default()
        }),
        Record::AuditEvent(pb::AuditEvent {
            action: "fork.send".into(),
            target: "f1".into(),
            details: BTreeMap::from([
                ("actor".into(), format!("counter/{SUBJECT}")),
                ("message".into(), "increment".into()),
            ]),
            audit: audit(&format!("try it; the key was {SECRET_VALUE}")),
        }),
        Record::AuditEvent(pb::AuditEvent {
            action: "token.create".into(),
            target: "ci".into(),
            details: BTreeMap::from([
                ("scopes".into(), "read,operate".into()),
                ("token_id".into(), "token:ci".into()),
            ]),
            audit: audit("for CI"),
        }),
        Record::TurnRecord(operator_turn(pb::MessageSource::Operator, true)),
        Record::TurnRecord(operator_turn(pb::MessageSource::DeadLetterResend, false)),
        Record::SimulatorConfig(pb::SimulatorConfig {
            epoch: 15,
            target: "http:payments.internal".into(),
            stubs: vec![pb::StubRuleSpec {
                method: "GET".into(),
                url_prefix: format!("https://payments.internal/{SECRET_VALUE}"),
                status: 200,
                body: BODY.as_bytes().to_vec(),
                error: SECRET_VALUE.into(),
                ..Default::default()
            }],
            contract: SECRET_VALUE.as_bytes().to_vec(),
            neighbor: true,
            model: false,
            audit: audit("simulators"),
        }),
        Record::GuardTriggered(pb::GuardTriggered {
            deployment_epoch: 7,
            watch_id: "w-1".into(),
            guard: "error-rate".into(),
            action: pb::GuardAction::Rollback as i32,
            outcome: pb::GuardOutcome::RolledBack as i32,
            rollback_epoch: 16,
            reason: BODY.into(),
            audit: audit("guard rollback"),
            ..Default::default()
        }),
        Record::StateRebase(pb::StateRebase {
            rebase_id: "r-1".into(),
            part: Some(pb::state_rebase::Part::Switch(pb::RebaseSwitch {
                base_lsn: 10,
                rolled_back_epoch: 7,
                turns: 3,
                deployment: Some(pb::Deployment {
                    epoch: 16,
                    kinds: vec![pb::KindVersion {
                        kind: "counter".into(),
                        code_hash: vec![0xab; 32],
                        schema_version: 1,
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                diff_hash: "b3:00ff".into(),
                irreversible_effects: 2,
                audit: audit("rebase rollback"),
                ..Default::default()
            })),
        }),
        Record::StateRebase(pb::StateRebase {
            rebase_id: "r-1".into(),
            part: Some(pb::state_rebase::Part::Turn(pb::RebasedTurn {
                fork_lsn: 1,
                record: Some(operator_turn(pb::MessageSource::Operator, true)),
            })),
        }),
    ]
}

fn all_lines() -> Vec<Line> {
    samples()
        .iter()
        .enumerate()
        .flat_map(|(i, r)| export(i as u64 + 1, r))
        .collect()
}

/// One golden line per kind (§4.3).
/// `KRONIK_UPDATE_DOCS=1 cargo test -p kronik-otel --test audit golden`.
#[test]
fn golden_lines() {
    let got: String = all_lines().iter().map(|l| l.to_json() + "\n").collect();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/audit.jsonl");
    if std::env::var_os("KRONIK_UPDATE_DOCS").is_some() {
        std::fs::write(path, &got).unwrap();
    }
    assert_eq!(got, std::fs::read_to_string(path).unwrap());
}

/// Lines parse back to themselves, keys in §4.3's order.
#[test]
fn lines_round_trip_in_key_order() {
    for l in all_lines() {
        let json = l.to_json();
        assert_eq!(serde_json::from_str::<Line>(&json).unwrap(), l);
        let keys = [
            "\"schema\"",
            "\"lsn\"",
            "\"kind\"",
            "\"action\"",
            "\"at_wall_ms\"",
            "\"token_id\"",
            "\"reason\"",
            "\"branch\"",
            "\"details\"",
            "\"record_hash\"",
        ];
        let at: Vec<usize> = keys.iter().map(|k| json.find(k).unwrap()).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{json}");
    }
}

/// No secret value, subject id, message body or guest error text leaves;
/// the reason of a mutation and the secret's name do (ADR 0082).
#[test]
fn needles_never_leave() {
    let out: String = all_lines().iter().map(Line::to_json).collect();
    for needle in [SECRET_VALUE, SUBJECT, BODY] {
        assert!(!out.contains(needle), "{needle} leaked: {out}");
    }
    assert!(out.contains("PR #12"));
    assert!(out.contains("api-key"));
    assert!(out.contains(&subject(SUBJECT)));
}

#[test]
fn operator_names_and_free_text_scrub_values_and_tokens() {
    let token = format!("kronik_{}", "A".repeat(43));
    let text = format!("operate {SECRET_VALUE} {token}");
    for source in [
        pb::MessageSource::Operator,
        pb::MessageSource::DeadLetterResend,
    ] {
        let mut turn = operator_turn(source, false);
        let Some(pb::input::Kind::Message(message)) =
            turn.input.as_mut().and_then(|i| i.kind.as_mut())
        else {
            unreachable!()
        };
        message.msg.as_mut().unwrap().name = text.clone();
        message.audit = audit(&text);
        let line = export(1, &Record::TurnRecord(turn)).remove(0);
        assert_eq!(line.details["message"], "operate [secret:api-key] [token]");
        assert_eq!(line.reason, "operate [secret:api-key] [token]");
    }
    let event = Record::AuditEvent(pb::AuditEvent {
        action: "fork.send".into(),
        target: text.clone(),
        details: BTreeMap::from([
            ("message".into(), text.clone()),
            (text.clone(), text.clone()),
        ]),
        audit: audit(&text),
    });
    let output = export(1, &event).remove(0).to_json();
    assert!(!output.contains(SECRET_VALUE));
    assert!(!output.contains(&token));
    let deployment = Record::Deployment(pb::Deployment {
        kinds: vec![pb::KindVersion {
            kind: text,
            ..Default::default()
        }],
        ..Default::default()
    });
    let line = export(2, &deployment).remove(0);
    assert_eq!(
        line.details["kinds"][0]["kind"],
        "operate [secret:api-key] [token]"
    );
}

#[test]
fn simulator_guard_and_rebase_project_actual_records() {
    let records = samples();
    for kind in [15, 16, 17] {
        assert!(
            records
                .iter()
                .filter(|r| r.kind() == kind)
                .any(|r| !export(1, r).is_empty())
        );
    }
    let projected = all_lines();
    let guard = projected
        .iter()
        .find(|l| l.kind == "guard_triggered")
        .unwrap();
    assert_eq!(guard.details["outcome"], "rolled_back");
    let rebase = projected
        .iter()
        .find(|l| l.action == "rollback.rebase")
        .unwrap();
    assert_eq!(rebase.epoch, Some(16));
    assert_eq!(rebase.details["kinds"][0]["kind"], "counter");
    assert_eq!(
        rebase.details["kinds"][0]["code_hash"],
        format!("b3:{}", "ab".repeat(32))
    );
    let rebased = records.last().unwrap();
    assert!(export(1, rebased).is_empty());
    let Record::StateRebase(mut changed) = records.iter().find(|r| {
        matches!(r, Record::StateRebase(r) if matches!(r.part, Some(pb::state_rebase::Part::Switch(_))))
    }).unwrap().clone() else {
        unreachable!()
    };
    let Some(pb::state_rebase::Part::Switch(switch)) = changed.part.as_mut() else {
        unreachable!()
    };
    switch.deployment.as_mut().unwrap().kinds[0].code_hash = vec![0xcd; 32];
    let line = export(1, &Record::StateRebase(changed)).remove(0);
    assert_eq!(
        line.details["kinds"][0]["code_hash"],
        format!("b3:{}", "cd".repeat(32))
    );
}

/// Review H3: one line per reveal effect, after the send, keyed by the
/// effect's ordinal; a reveal by guest code outside an operator send too.
#[test]
fn reveals_get_a_line_each() {
    let mut t = operator_turn(pb::MessageSource::Operator, true);
    let ls = export(5, &Record::TurnRecord(t.clone()));
    let got: Vec<_> = ls.iter().map(|l| (l.action.as_str(), l.effect)).collect();
    assert_eq!(got, [("send", None), ("secret.reveal", Some(2))]);
    assert_eq!(ls[1].details["secret"], "api-key");
    assert_eq!(ls[1].details["version"], 3);
    assert_eq!(ls[0].record_hash, ls[1].record_hash);
    // An HTTP turn's reveal: the guest's, at the turn's time.
    t.input = Some(pb::Input {
        kind: Some(pb::input::Kind::Http(pb::HttpInput::default())),
    });
    let mut denied = t.effects[0].clone();
    denied.ordinal = 4;
    denied.status = pb::EffectStatus::Denied as i32;
    denied.request = None;
    t.effects.push(denied);
    let ls = export(6, &Record::TurnRecord(t));
    let got: Vec<_> = ls
        .iter()
        .map(|l| {
            (
                l.effect,
                l.token_id.as_str(),
                l.at_wall_ms,
                l.details["status"].clone(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (Some(2), "guest", WALL + 7, "ok".into()),
            (Some(4), "guest", WALL + 7, "denied".into())
        ]
    );
    // Ordinary turns and the records that only copy an audit export nothing.
    let plain = pb::TurnRecord::default();
    assert!(export(7, &Record::TurnRecord(plain)).is_empty());
    assert!(export(8, &Record::TurnBegin(pb::TurnBegin::default())).is_empty());
}

/// Review M2: a reseal rewrites sealed payloads only; the hash, over the
/// record with each sealable reduced to its subject tag, is unchanged.
#[test]
fn record_hash_ignores_sealed_payloads() {
    let t = operator_turn(pb::MessageSource::Operator, false);
    let mut resealed = t.clone();
    if let Some(pb::input::Kind::Message(m)) = resealed.input.as_mut().and_then(|i| i.kind.as_mut())
    {
        m.msg.as_mut().unwrap().body = Some(pb::Sealable {
            subject: Some(SUBJECT.into()),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed {
                key_version: 2,
                nonce: vec![1; 12],
                ciphertext: vec![9; 40],
            })),
        });
    }
    let a = record_hash(&Record::TurnRecord(t.clone()), &subject);
    assert_eq!(a, record_hash(&Record::TurnRecord(resealed), &subject));
    assert!(a.starts_with("b3:") && a.len() == 67, "{a}");
    // Anything else changes it.
    let mut other = t;
    other.logical_time_ms += 1;
    assert_ne!(a, record_hash(&Record::TurnRecord(other), &subject));
}

/// Review M6: an erasure's line leaves its subject out, and its hash covers
/// the subject's keyed label instead, so a backend cannot confirm a guessed
/// subject by rebuilding the record and hashing it.
#[test]
fn an_erasure_hash_confirms_no_guessed_subject() {
    let e = Record::Erasure(pb::Erasure {
        epoch: 13,
        subject: SUBJECT.into(),
        key_version: 2,
        audit: audit(&format!("erase request from {SUBJECT}")),
    });
    let line = export(5, &e).remove(0);
    // The right guess, hashed as a backend could: the plain canonical form.
    let guess = format!(
        "b3:{}",
        blake3::hash(&[&[e.kind()][..], &e.encode()].concat()).to_hex()
    );
    assert_ne!(line.record_hash, guess);
    // Stable under the same key (verify recomputes it), not under another.
    assert_eq!(line.record_hash, record_hash(&e, &subject));
    let other = |s: &str| subject(&format!("other key {s}"));
    assert_ne!(line.record_hash, record_hash(&e, &other));
}

#[test]
fn erasure_subject_spellings_share_the_canonical_hash_without_matching_other_ids() {
    for (id, spellings) in [
        (
            SUBJECT,
            vec![
                SUBJECT.to_owned(),
                "CAROL@EXAMPLE.COM".into(),
                "carol%40example.com".into(),
                "%63%61%72%6f%6c%40example.com".into(),
            ],
        ),
        ("42", vec!["42".into(), "%34%32".into()]),
        ("Élodie", vec!["ÉLODIE".into(), "%c3%a9LODIE".into()]),
    ] {
        let mut canonical = pb::Erasure {
            epoch: 13,
            subject: id.into(),
            key_version: 2,
            audit: audit(&format!("erase {} ; keep 142 and 420", subject(id))),
        };
        let expected_reason = canonical.audit.as_ref().unwrap().reason.clone();
        canonical.subject = subject(id);
        let canonical = Record::Erasure(canonical);
        let mut hash = blake3::Hasher::new();
        hash.update(b"kronik.audit/v2\0");
        hash.update(&[canonical.kind()]);
        hash.update(&canonical.encode());
        let expected_hash = format!("b3:{}", hash.finalize().to_hex());
        for spelling in spellings {
            let record = Record::Erasure(pb::Erasure {
                epoch: 13,
                subject: id.into(),
                key_version: 2,
                audit: audit(&format!("erase {spelling} ; keep 142 and 420")),
            });
            let line = export(1, &record).remove(0);
            assert_eq!(line.reason, expected_reason);
            assert_eq!(line.record_hash, expected_hash);
            assert_eq!(line.record_hash, record_hash(&record, &subject));
        }
    }
}

/// Review R1: a `fork.send` line hashes or omits its actor's key, and its
/// hash covers the key's keyed label instead, so a backend that rebuilds
/// the event from the line's other fields cannot confirm a guessed key.
#[test]
fn a_fork_send_hash_confirms_no_guessed_actor() {
    let e = Record::AuditEvent(pb::AuditEvent {
        action: "fork.send".into(),
        target: "f1".into(),
        details: BTreeMap::from([
            ("actor".into(), format!("counter/{SUBJECT}")),
            ("message".into(), "increment".into()),
        ]),
        audit: audit("try it"),
    });
    let line = export(5, &e).remove(0);
    assert_ne!(line.details["actor"], format!("counter/{SUBJECT}"));
    // The right guess, hashed as a backend could: the plain canonical form.
    let guess = format!(
        "b3:{}",
        blake3::hash(&[&[e.kind()][..], &e.encode()].concat()).to_hex()
    );
    assert_ne!(line.record_hash, guess);
    // Stable under the same key (verify recomputes it), not under another,
    // and it still covers the actor.
    assert_eq!(line.record_hash, record_hash(&e, &subject));
    let other = |s: &str| subject(&format!("other key {s}"));
    assert_ne!(line.record_hash, record_hash(&e, &other));
    let Record::AuditEvent(mut moved) = e.clone() else {
        unreachable!()
    };
    moved
        .details
        .insert("actor".into(), "counter/dave@example.com".into());
    assert_ne!(
        line.record_hash,
        record_hash(&Record::AuditEvent(moved), &subject)
    );
}

/// Reasons over 4 KiB are cut on a character boundary and marked.
#[test]
fn long_reasons_are_capped() {
    let r = Record::PrivacyMode(pb::PrivacyMode {
        epoch: 1,
        mode: pb::PrivacyState::Off as i32,
        audit: audit(&"é".repeat(REASON_MAX)),
        reseal_requested: false,
    });
    let l = &export(1, &r)[0];
    assert!(l.reason_truncated);
    assert!(l.reason.len() <= REASON_MAX && l.reason.len() > REASON_MAX - 2);
    assert!(l.to_json().contains("\"reason_truncated\":true"));
}

/// Review M4: every record message that carries an `Audit` (directly or
/// through a field) is classified, so a new audited kind cannot be missed.
/// The messages come from the compiled `.proto` files, not from a list.
#[test]
fn every_record_with_an_audit_is_classified() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let files = ["common", "input", "turn", "config", "branch", "effects"]
        .map(|n| root.join(format!("kronik/log/v1/{n}.proto")));
    let fds = protox::compile(&files, [&root]).unwrap();
    let fields: HashMap<String, Vec<String>> = fds
        .file
        .iter()
        .flat_map(|f| &f.message_type)
        .map(|m| {
            let types = m.field.iter().map(|f| f.type_name().to_owned()).collect();
            (format!(".kronik.log.v1.{}", m.name()), types)
        })
        .collect();
    fn audited(
        name: &str,
        fields: &HashMap<String, Vec<String>>,
        seen: &mut BTreeSet<String>,
    ) -> bool {
        if name == ".kronik.log.v1.Audit" {
            return true;
        }
        if !seen.insert(name.to_owned()) {
            return false;
        }
        fields
            .get(name)
            .is_some_and(|ts| ts.iter().any(|t| audited(t, fields, seen)))
    }
    // One default record per variant, named by its message type.
    macro_rules! each {
        ($($v:ident),* $(,)?) => { vec![$((Record::$v(pb::$v::default()), stringify!($v))),*] };
    }
    let all = each![
        TurnBegin,
        EffectResult,
        TurnRecord,
        Deployment,
        Grant,
        Limits,
        Policy,
        Approval,
        PrivacyMode,
        ForeignActor,
        BranchCreated,
        Erasure,
        EngineUpgrade,
        SnapshotMarker,
        SimulatorConfig,
        StateRebase,
        GuardTriggered,
        AuditEvent,
    ];
    let kinds: Vec<u8> = all.iter().map(|(r, _)| r.kind()).collect();
    assert_eq!(
        kinds,
        kronik_proto::kind::ALL,
        "a record kind is missing here"
    );
    for (record, name) in &all {
        let has = audited(
            &format!(".kronik.log.v1.{name}"),
            &fields,
            &mut BTreeSet::new(),
        );
        let c = class(record);
        assert_eq!(
            has,
            c != Class::None,
            "{name}: Audit field {has}, class {c:?}"
        );
    }
}

// ---- verify (§4.5) ----

fn restore_record(through: u64) -> Record {
    Record::AuditEvent(pb::AuditEvent {
        action: "restore".into(),
        details: BTreeMap::from([("through_lsn".into(), through.to_string())]),
        audit: audit("kronik restore"),
        ..Default::default()
    })
}

/// Complete when every item has a line; re-sent batches repeat lines.
#[test]
fn verify_accepts_a_complete_sink_with_repeats() {
    let want = all_lines();
    let mut sink = want.clone();
    sink.extend(want[3..6].iter().cloned());
    let r = verify(&all_expected(), &sink, 0, 16);
    assert!(r.complete, "{r:?}");
    assert_eq!((r.expected, r.lines), (want.len(), want.len()));
    // Outside (from, to] nothing counts.
    let r = verify(&all_expected(), &want[2..], 2, 16);
    assert!(r.complete, "{r:?}");
}

/// Missing, extra and conflicting lines are reported.
#[test]
fn verify_reports_missing_extra_and_conflicting_lines() {
    let want = all_lines();
    let mut sink: Vec<Line> = want.iter().filter(|l| l.lsn != 4).cloned().collect();
    let mut extra = want[0].clone();
    extra.lsn = 99;
    let mut conflict = want[1].clone();
    conflict.record_hash = format!("b3:{}", "0".repeat(64));
    let mut other_token = want[2].clone();
    other_token.token_id = "token:someone-else".into();
    sink.extend([extra, conflict, other_token]);
    let r = verify(&all_expected(), &sink, 0, 200);
    assert!(!r.complete);
    let lsns = |items: &[kronik_otel::audit::Item]| items.iter().map(|i| i.lsn).collect::<Vec<_>>();
    assert_eq!(lsns(&r.missing), [4]);
    assert_eq!(lsns(&r.extra), [99]);
    assert_eq!(lsns(&r.conflicting), [2, 3]);
}

/// Review H4: after a restore from an older ship point, LSNs past its
/// `through_lsn` come back with other records. The lines exported before
/// the restore line are superseded; the new ones are told apart by hash.
#[test]
fn verify_tells_a_restored_tail_apart_by_hash() {
    let old = all_lines();
    // The restored log ends at 9; LSN 10 is the restore event, 11.. new.
    let mut records: Vec<(u64, Record)> = samples()
        .into_iter()
        .take(9)
        .enumerate()
        .map(|(i, record)| (i as u64 + 1, record))
        .collect();
    records.push((10, restore_record(9)));
    records.push((
        11,
        Record::TurnRecord(operator_turn(pb::MessageSource::Operator, true)),
    ));
    let new: Vec<Line> = records
        .iter()
        .flat_map(|(lsn, record)| export(*lsn, record))
        .collect();
    let want: Vec<Expected> = records
        .iter()
        .flat_map(|(lsn, record)| expected_record(*lsn, record))
        .collect();
    // The sink: everything before the restore, then a re-export from 1.
    let mut sink = old.clone();
    sink.extend(new.iter().cloned());
    let r = verify(&want, &sink, 0, 11);
    assert!(r.complete, "{r:?}");
    assert_eq!(r.superseded, old.iter().filter(|l| l.lsn > 9).count());
    // LSN 10 and 11 were both used twice, with different hashes.
    let ten: BTreeSet<_> = sink
        .iter()
        .filter(|l| l.lsn == 10)
        .map(|l| &l.record_hash)
        .collect();
    assert_eq!(ten.len(), 2);
    // A conflicting line written after the restore is reported.
    let mut injected = new.last().unwrap().clone();
    injected.record_hash = format!("b3:{}", "1".repeat(64));
    sink.push(injected);
    let r = verify(&want, &sink, 0, 11);
    assert_eq!(r.conflicting.len(), 1, "{r:?}");
}

fn legacy_line(lsn: u64, record: &Record) -> Line {
    let mut canonical = record.clone();
    kronik_proto::sealables::record_mut(&mut canonical, &mut |value| value.value = None);
    match &mut canonical {
        Record::Erasure(erasure) => {
            let label = subject(&erasure.subject);
            if let Some(audit) = erasure
                .audit
                .as_mut()
                .filter(|_| !erasure.subject.is_empty())
            {
                audit.reason = audit.reason.replace(&erasure.subject, &label);
            }
            erasure.subject = label;
        }
        Record::AuditEvent(event) => {
            if let Some(actor) = event.details.get_mut("actor") {
                let (kind, key) = actor.split_once('/').unwrap_or((actor.as_str(), ""));
                *actor = format!("{kind}/{}", subject(key));
            }
        }
        _ => {}
    }
    let mut hash = blake3::Hasher::new();
    hash.update(&[canonical.kind()]);
    hash.update(&canonical.encode());
    let mut line = export(lsn, record).remove(0);
    line.schema = "kronik.audit/v1".into();
    line.record_hash = format!("b3:{}", hash.finalize().to_hex());
    if let Record::Erasure(erasure) = record {
        line.reason = erasure
            .audit
            .as_ref()
            .unwrap()
            .reason
            .replace(&erasure.subject, &subject(&erasure.subject));
    }
    if let Record::AuditEvent(event) = record
        && let Some(positions) =
            kronik_sched::scrub::AuditPositions::parse(&event.action, &event.details).unwrap()
    {
        for field in ["through_lsn", "from", "to"] {
            if positions.value(field).is_some() {
                line.details
                    .insert(field.into(), event.details[field].clone().into());
            }
        }
    }
    line
}

fn hash_version_records() -> Vec<Record> {
    [
        (SUBJECT, "erase CAROL@EXAMPLE.COM"),
        (SUBJECT, "erase carol%40example.com"),
        ("42", "erase 42; keep 142 and 420"),
    ]
    .into_iter()
    .map(|(subject, reason)| {
        Record::Erasure(pb::Erasure {
            epoch: 13,
            subject: subject.into(),
            key_version: 2,
            audit: audit(reason),
        })
    })
    .collect()
}

#[test]
fn golden_hash_versions_verify_historical_records_without_exporting_old_hashes() {
    let records = hash_version_records();
    let fixtures: Vec<Line> = records
        .iter()
        .enumerate()
        .flat_map(|(i, record)| {
            [
                legacy_line(i as u64 + 1, record),
                export(i as u64 + 1, record).remove(0),
            ]
        })
        .collect();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/audit-hash-versions.jsonl"
    );
    let text: String = fixtures.iter().map(|line| line.to_json() + "\n").collect();
    if std::env::var_os("KRONIK_UPDATE_DOCS").is_some() {
        std::fs::write(path, &text).unwrap();
    }
    assert_eq!(text, std::fs::read_to_string(path).unwrap());
    let stored: Vec<Line> = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let want: Vec<Expected> = records
        .iter()
        .enumerate()
        .flat_map(|(i, record)| expected_record(i as u64 + 1, record))
        .collect();
    let report = verify(&want, &stored, 0, 3);
    assert!(report.complete, "{report:?}");
    assert_eq!((report.expected, report.lines), (3, 3));
    let (pairs, remainder) = stored.as_chunks::<2>();
    assert!(remainder.is_empty());
    for pair in pairs {
        assert_eq!(pair[0].schema, "kronik.audit/v1");
        assert_eq!(pair[1].schema, "kronik.audit/v2");
        assert_ne!(pair[0].record_hash, pair[1].record_hash);
        assert!(
            pair[1]
                .reason
                .contains(&subject(if pair[1].lsn == 3 { "42" } else { SUBJECT }))
        );
        for (source, wrong_schema) in [
            (&pair[0], "kronik.audit/v2"),
            (&pair[1], "kronik.audit/v1"),
            (&pair[1], "kronik.audit/v999"),
        ] {
            let mut wrong = source.clone();
            wrong.schema = wrong_schema.into();
            assert!(!verify(&want, &[wrong], 0, 3).conflicting.is_empty());
        }
    }
}

#[test]
fn old_v1_export_is_readable_and_schema_hash_domains_always_differ() {
    let stored: Vec<Line> = include_str!("golden/audit-v1.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(verify(&all_expected(), &stored, 0, 13).complete);
    let record = &samples()[0];
    let new = export(1, record).remove(0);
    let old = legacy_line(1, record);
    assert_ne!(new.record_hash, old.record_hash);
    for mut wrong in [new.clone(), old] {
        wrong.schema = if wrong.schema == "kronik.audit/v1" {
            "kronik.audit/v2".into()
        } else {
            "kronik.audit/v1".into()
        };
        assert!(!verify(&expected_record(1, record), &[wrong], 0, 1).complete);
    }
    for mutate in [
        |line: &mut Line| line.branch = "other".into(),
        |line: &mut Line| line.epoch = Some(999),
        |line: &mut Line| line.kind = "erasure".into(),
        |line: &mut Line| line.action = "restore".into(),
        |line: &mut Line| line.token_id = "other".into(),
        |line: &mut Line| line.at_wall_ms += 1,
    ] {
        let mut wrong = new.clone();
        mutate(&mut wrong);
        assert!(!verify(&expected_record(1, record), &[wrong], 0, 1).complete);
    }
}

#[test]
fn only_source_matched_in_range_restores_can_supersede_a_tail() {
    let records = samples();
    let first = export(1, &records[0]).remove(0);
    let mut conflict = export(2, &records[1]).remove(0);
    conflict.token_id = "forged".into();
    let want: Vec<Expected> = [
        expected_record(1, &records[0]),
        expected_record(2, &records[1]),
    ]
    .concat();
    for mutate in [
        |line: &mut Line| line.lsn = 99,
        |line: &mut Line| line.schema = "kronik.audit/v999".into(),
        |line: &mut Line| line.record_hash = "b3:forged".into(),
    ] {
        let mut restore = export(3, &restore_record(0)).remove(0);
        mutate(&mut restore);
        let report = verify(&want, &[first.clone(), conflict.clone(), restore], 0, 3);
        assert!(!report.complete);
        assert_eq!(report.superseded, 0);
        assert!(!report.conflicting.is_empty());
    }
    let restore = restore_record(1);
    let want: Vec<Expected> = [
        expected_record(1, &records[0]),
        expected_record(2, &restore),
    ]
    .concat();
    let legitimate = export(2, &restore).remove(0);
    let mut altered = legitimate.clone();
    altered.details.insert("through_lsn".into(), 0.into());
    let report = verify(&want, &[first.clone(), conflict.clone(), altered], 0, 2);
    assert!(!report.complete);
    assert_eq!(report.superseded, 0);
    let report = verify(
        &want,
        &[first.clone(), conflict.clone(), legitimate.clone()],
        0,
        1,
    );
    assert!(report.complete);
    assert_eq!(report.superseded, 0);
    let old_restore = legacy_line(2, &restore);
    let mut sink = vec![first.clone(), conflict, old_restore, legitimate.clone()];
    sink.extend([first, legitimate]);
    let report = verify(&want, &sink, 0, 2);
    assert!(report.complete, "{report:?}");
    assert_eq!((report.expected, report.lines), (2, 2));
    assert_eq!(report.superseded, 1);
    for mut invalid in [sink[2].clone(), sink[3].clone()] {
        invalid.schema = if invalid.schema == "kronik.audit/v1" {
            "kronik.audit/v2".into()
        } else {
            "kronik.audit/v1".into()
        };
        let mut wrong_pair = sink.clone();
        wrong_pair.insert(1, invalid);
        assert!(!verify(&want, &wrong_pair, 0, 2).complete);
    }
    let mut altered_cut = sink[3].clone();
    altered_cut.details.insert("through_lsn".into(), 0.into());
    let mut corrupted = sink.clone();
    corrupted.insert(1, altered_cut);
    assert!(!verify(&want, &corrupted, 0, 2).complete);
    let mut unknown = sink[0].clone();
    unknown.schema = "kronik.audit/v999".into();
    unknown.lsn = 2;
    sink.insert(1, unknown);
    assert!(!verify(&want, &sink, 0, 2).complete);
}

#[test]
fn unsupported_schema_diagnostics_never_echo_sink_text_or_legacy_hashes() {
    let record = &hash_version_records()[0];
    let expected = expected_record(1, record);
    let mut injected = export(1, record).remove(0);
    let needle = "untrusted-NEEDLE-payload";
    injected.schema = needle.into();
    injected.kind = needle.into();
    injected.action = needle.into();
    injected.record_hash = needle.into();
    injected.token_id = needle.into();
    injected.branch = needle.into();
    injected.reason = needle.into();
    injected.details.insert(needle.into(), needle.into());
    let mut extra = injected.clone();
    extra.lsn = 2;
    let report = verify(&expected, &[injected, extra], 0, 2);
    assert!(!report.complete);
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains(needle));
    assert_eq!(
        report.conflicting[0].record_hash,
        record_hash(record, &subject)
    );
    assert!(report.extra[0].record_hash.is_empty());
    let mut historical = legacy_line(1, record);
    let legacy_hash = historical.record_hash.clone();
    historical.token_id = "forged".into();
    let report = verify(&expected, &[historical], 0, 1);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains(&legacy_hash)
    );
}

#[test]
fn typed_positions_survive_secret_coincidence_and_versions_have_explicit_types() {
    use kronik_sched::scrub::AuditPositions;
    let values = vec![("digits".into(), b"1234".to_vec())];
    let ctx = Ctx {
        branch: "main",
        keys: &ActorKeys::Omit,
        subject: &subject,
        secrets: &values,
    };
    for (action, details) in [
        (
            "restore",
            BTreeMap::from([("through_lsn".into(), "1234".into())]),
        ),
        (
            "audit.gap",
            BTreeMap::from([("from".into(), "1234".into()), ("to".into(), "1235".into())]),
        ),
    ] {
        let positions = AuditPositions::parse(action, &details).unwrap().unwrap();
        let mut details = details;
        details.insert("note".into(), "1234".into());
        let record = Record::AuditEvent(pb::AuditEvent {
            action: action.into(),
            details,
            audit: audit("position 1234"),
            ..Default::default()
        });
        let projected = lines(1, &record, &ctx).unwrap();
        let want = expected(1, &record, &ctx).unwrap();
        assert!(!projected[0].reason.contains("1234"));
        assert!(
            !projected[0].details["note"]
                .as_str()
                .unwrap()
                .contains("1234")
        );
        for field in ["through_lsn", "from", "to"] {
            if let Some(value) = positions.value(field) {
                assert_eq!(projected[0].details[field].as_u64(), Some(value));
                let mut wrong = projected[0].clone();
                wrong.details.insert(field.into(), value.to_string().into());
                assert!(!verify(&want, &[wrong], 0, 1).complete);
                let mut old = legacy_line(1, &record);
                assert_eq!(
                    old.details[field].as_str(),
                    Some(value.to_string().as_str())
                );
                assert!(verify(&want, &[old.clone()], 0, 1).complete);
                old.details.insert(field.into(), value.into());
                assert!(!verify(&want, &[old], 0, 1).complete);
            }
        }
        let report = verify(
            &want,
            &[legacy_line(1, &record), projected[0].clone()],
            0,
            1,
        );
        assert!(report.complete, "{report:?}");
        assert_eq!(report.lines, 1);
    }
    let ordinary = Record::AuditEvent(pb::AuditEvent {
        action: "operator.note".into(),
        details: BTreeMap::from([
            ("through_lsn".into(), "1234".into()),
            ("from".into(), "1234".into()),
            ("to".into(), "1234".into()),
        ]),
        audit: audit("1234"),
        ..Default::default()
    });
    let ordinary = lines(1, &ordinary, &ctx).unwrap().remove(0);
    for field in ["through_lsn", "from", "to"] {
        assert_eq!(ordinary.details[field], "[secret:digits]");
    }
    let mut turn = operator_turn(pb::MessageSource::Operator, false);
    let Some(pb::input::Kind::Message(input)) =
        turn.input.as_mut().and_then(|input| input.kind.as_mut())
    else {
        unreachable!()
    };
    input.msg.as_mut().unwrap().name = "1234".into();
    let line = lines(2, &Record::TurnRecord(turn), &ctx).unwrap().remove(0);
    assert_eq!(line.details["message"], "[secret:digits]");
}

#[test]
fn malformed_source_positions_are_corruption_not_empty_or_redacted_projections() {
    let ctx = Ctx {
        branch: "main",
        keys: &ActorKeys::Omit,
        subject: &subject,
        secrets: &[],
    };
    for (action, fields) in [
        ("restore", vec![]),
        ("restore", vec![("through_lsn", "")]),
        ("restore", vec![("through_lsn", "+1234")]),
        ("restore", vec![("through_lsn", " 1234")]),
        ("restore", vec![("through_lsn", "18446744073709551616")]),
        ("restore", vec![("through_lsn", "[secret:digits]")]),
        ("audit.gap", vec![("from", "1234")]),
        ("audit.gap", vec![("from", "0"), ("to", "1234")]),
        ("audit.gap", vec![("from", "1235"), ("to", "1234")]),
        (
            "audit.gap",
            vec![("from", "1234"), ("to", "invalid-NEEDLE")],
        ),
    ] {
        let record = Record::AuditEvent(pb::AuditEvent {
            action: action.into(),
            details: fields
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
            audit: audit("positions"),
            ..Default::default()
        });
        assert!(matches!(
            lines(1, &record, &ctx),
            Err(kronik_log::LogError::Corrupt(_))
        ));
        assert!(matches!(
            expected(1, &record, &ctx),
            Err(kronik_log::LogError::Corrupt(_))
        ));
    }
}
