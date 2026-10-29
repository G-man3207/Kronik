//! The audit line mapping (docs/design/m28-otel.md §4.1, §4.3): the
//! classifier covers every record message with an `Audit` field, one golden
//! line per kind, and what never leaves (ADR 0082).

// Test helpers outside #[test] functions may unwrap.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use kronik_otel::audit::{Class, Ctx, Line, REASON_MAX, class, lines, record_hash, verify};
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
        }),
        Record::PrivacyMode(pb::PrivacyMode {
            epoch: 11,
            mode: pb::PrivacyState::On as i32,
            audit: audit("GDPR"),
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

fn restore_line(lsn: u64, through: u64) -> Line {
    export(
        lsn,
        &Record::AuditEvent(pb::AuditEvent {
            action: "restore".into(),
            details: BTreeMap::from([("through_lsn".into(), through.to_string())]),
            audit: audit("kronik restore"),
            ..Default::default()
        }),
    )
    .remove(0)
}

/// Complete when every item has a line; re-sent batches repeat lines.
#[test]
fn verify_accepts_a_complete_sink_with_repeats() {
    let want = all_lines();
    let mut sink = want.clone();
    sink.extend(want[3..6].iter().cloned());
    let r = verify(&want, &sink, 0, 13);
    assert!(r.complete, "{r:?}");
    assert_eq!((r.expected, r.lines), (want.len(), want.len()));
    // Outside (from, to] nothing counts.
    let r = verify(&want, &want[2..], 2, 13);
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
    let r = verify(&want, &sink, 0, 200);
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
    let mut new: Vec<Line> = old.iter().filter(|l| l.lsn <= 9).cloned().collect();
    new.push(restore_line(10, 9));
    let mut tail = old.iter().find(|l| l.lsn == 12).unwrap().clone();
    tail.lsn = 11;
    new.push(tail);
    // The sink: everything before the restore, then a re-export from 1.
    let mut sink = old.clone();
    sink.extend(new.iter().cloned());
    let r = verify(&new, &sink, 0, 11);
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
    let r = verify(&new, &sink, 0, 11);
    assert_eq!(r.conflicting.len(), 1, "{r:?}");
}
