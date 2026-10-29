//! Every mutation requires a non-blank reason and a dry run writes nothing
//! (I12). The table is checked against the OpenAPI operation list, so a new
//! POST, PUT or DELETE that is not classified here fails the test. Each row
//! also names the audited record the route writes in main's log (M28
//! §4.2), and a real run of every route checks it.
//!
//! `POST /v1/policy/test` evaluates rules and writes nothing, so it is not a
//! mutation. `POST /v1/forks/{name}/replay` requires a reason but has no
//! dry run: it writes only in the fork (docs/reference/cli.md). A message
//! into a fork rejects `dry_run` rather than planning one; the call still
//! must not move the applied LSN.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;

use base64::Engine as _;
use kronik_api::openapi::OPERATIONS;
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{NodeConfig, start_local};
use serde_json::{Value, json};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

/// Writes nothing. Not a mutation.
const NOT_A_MUTATION: &[(&str, &str)] = &[("POST", "/v1/policy/test")];

/// Requires a reason. No dry run: it writes only in its fork (and its
/// `AuditEvent` in main's log).
const NO_DRY_RUN: &[(&str, &str)] = &[("POST", "/v1/forks/{name}/replay")];
const NO_DRY_RUN_WRITES: &str = "fork.replay";

struct Case {
    method: &'static str,
    path: &'static str,
    /// The audited record the call writes in main's log (M28 §4.2): a
    /// configuration record's kind, an `AuditEvent`'s action, or `send` /
    /// `resend` for an operator message's `TurnRecord`.
    writes: &'static str,
    /// Fields other than `reason` and `dry_run`, so the body deserializes
    /// and `reason()` runs before any other check.
    extra: Value,
}

fn cases() -> Vec<Case> {
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(COUNTER).unwrap());
    vec![
        Case {
            method: "POST",
            path: "/v1/deployments",
            writes: "Deployment",
            extra: json!({"wasm_base64": wasm.clone()}),
        },
        Case {
            method: "POST",
            path: "/v1/deployments/{epoch}/rollback",
            writes: "Deployment",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/deployments/{epoch}/rebase",
            writes: "rebase.create",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/deployments/{epoch}/watch",
            writes: "watch.start",
            extra: json!({"for_ms": 60_000}),
        },
        Case {
            method: "POST",
            path: "/v1/watches/{id}/stop",
            writes: "watch.stop",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/actors/{kind}/{key}/messages",
            writes: "send",
            extra: json!({"name": "increment"}),
        },
        Case {
            method: "POST",
            path: "/v1/dead-letters/{id}/resend",
            writes: "resend",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/grants",
            writes: "Grant",
            extra: json!({"kind": "counter", "capability": "http:example.com"}),
        },
        Case {
            method: "POST",
            path: "/v1/grants/revoke",
            writes: "Grant",
            extra: json!({"kind": "counter", "capability": "http:example.com"}),
        },
        Case {
            method: "POST",
            path: "/v1/limits",
            writes: "Limits",
            extra: json!({"kind": "counter", "fuel": 1000}),
        },
        Case {
            method: "PUT",
            path: "/v1/secrets/{name}",
            writes: "secret.set",
            extra: json!({"text": "value"}),
        },
        Case {
            method: "DELETE",
            path: "/v1/secrets/{name}",
            writes: "secret.delete",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/tokens",
            writes: "token.create",
            extra: json!({"name": "agent-1"}),
        },
        Case {
            method: "POST",
            path: "/v1/tokens/{name}/revoke",
            writes: "token.revoke",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/forks",
            writes: "fork.create",
            extra: json!({"at": "now"}),
        },
        Case {
            method: "DELETE",
            path: "/v1/forks/{name}",
            writes: "fork.delete",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/forks/{name}/deployments",
            writes: "fork.deploy",
            extra: json!({"wasm_base64": wasm.clone()}),
        },
        Case {
            method: "POST",
            path: "/v1/forks/{name}/actors/{kind}/{key}/messages",
            writes: "fork.send",
            extra: json!({"name": "increment"}),
        },
        Case {
            method: "POST",
            path: "/v1/previews",
            writes: "preview.create",
            extra: json!({"proposal": "p-000000000000"}),
        },
        Case {
            method: "DELETE",
            path: "/v1/previews/{id}",
            writes: "preview.delete",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/proposals",
            writes: "proposal.create",
            extra: json!({"wasm_base64": [wasm]}),
        },
        Case {
            method: "POST",
            path: "/v1/proposals/{id}/request-approval",
            writes: "Approval",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/proposals/{id}/approve",
            writes: "Approval",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/proposals/{id}/promote",
            writes: "Deployment",
            extra: json!({}),
        },
        Case {
            method: "PUT",
            path: "/v1/policy",
            writes: "Policy",
            extra: json!({"rules_toml": "[[rule]]\nname = \"quiet\"\nwhen = \"false\"\naction = \"allow\"\n"}),
        },
        Case {
            method: "POST",
            path: "/v1/foreign",
            writes: "ForeignActor",
            extra: json!({"name": "echo", "image": "not-an-image", "port": 8080}),
        },
        Case {
            method: "DELETE",
            path: "/v1/foreign/{name}",
            writes: "ForeignActor",
            extra: json!({}),
        },
        Case {
            method: "PUT",
            path: "/v1/simulators/{target}",
            writes: "SimulatorConfig",
            extra: json!({"neighbor": true}),
        },
        Case {
            method: "POST",
            path: "/v1/privacy/mode",
            writes: "PrivacyMode",
            extra: json!({"mode": "on"}),
        },
        Case {
            method: "POST",
            path: "/v1/privacy/erase",
            writes: "Erasure",
            extra: json!({"subject": "user:1"}),
        },
        Case {
            method: "POST",
            path: "/v1/privacy/reseal",
            writes: "privacy.reseal",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/snapshots",
            writes: "snapshot.create",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/export/{stream}/rewind",
            writes: "export.rewind",
            extra: json!({"to": 0}),
        },
    ]
}

fn concrete(path: &str) -> String {
    path.replace("{kind}", "counter")
        .replace("{key}", "a")
        .replace("{id}", "main:1")
        .replace("{name}", "try")
        .replace("{epoch}", "1")
        .replace("{target}", "http:example.com")
        .replace("{stream}", "audit")
}

fn with_reason(extra: &Value, reason: &str, dry_run: bool) -> Value {
    let mut body = extra.clone();
    body["reason"] = json!(reason);
    body["dry_run"] = json!(dry_run);
    body
}

async fn call(api: &Api, method: &str, path: &str, body: Value) -> (u16, Value) {
    let r = api
        .handle(ApiRequest {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            body: body.to_string().into_bytes(),
            token_id: "unix:uid=0".into(),
            bearer: None,
        })
        .await;
    (r.status, serde_json::from_slice(&r.body).unwrap())
}

async fn applied(api: &Api) -> u64 {
    let (status, body) = call(api, "GET", "/v1/health", Value::Null).await;
    assert_eq!(status, 200, "{body}");
    body["applied_lsn"].as_u64().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_mutation_requires_a_reason_and_a_dry_run_writes_nothing() {
    let writes: Vec<(&str, &str)> = OPERATIONS
        .iter()
        .filter(|op| matches!(op.method, "POST" | "PUT" | "DELETE"))
        .map(|op| (op.method, op.path))
        .collect();
    let cases = cases();
    let covered: Vec<(&str, &str)> = cases
        .iter()
        .map(|c| (c.method, c.path))
        .chain(NO_DRY_RUN.iter().copied())
        .chain(NOT_A_MUTATION.iter().copied())
        .collect();
    for op in &writes {
        assert!(
            covered.contains(op),
            "{op:?} is a POST, PUT or DELETE and is not classified: add it to the mutation table, NO_DRY_RUN, or NOT_A_MUTATION"
        );
    }
    for op in &covered {
        assert!(
            writes.contains(op),
            "{op:?} is classified but is not an OpenAPI POST, PUT or DELETE"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let proposals = Arc::new(
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf()).unwrap(),
    );
    let watches = kronik_fork::watch::Watches::open(
        node.clone(),
        proposals.clone(),
        dir.path().to_path_buf(),
    )
    .unwrap()
    .start();
    let api = Arc::new(
        Api::new(node)
            .with_proposals(proposals)
            .with_watches(watches)
            .with_exports(vec![kronik_otel::follow::Stream::new(
                "audit",
                true,
                "file://".into(),
                0,
            )]),
    );
    let start = applied(&api).await;

    for case in &cases {
        let (status, body) = call(
            &api,
            case.method,
            &concrete(case.path),
            with_reason(&case.extra, " ", false),
        )
        .await;
        assert_eq!(
            (status, body["error"]["code"].as_str()),
            (400, Some("REASON_REQUIRED")),
            "{} {} blank reason: {body}",
            case.method,
            case.path
        );
        assert_eq!(
            applied(&api).await,
            start,
            "blank reason wrote {}",
            case.path
        );
    }
    // Replay requires a reason too, and has no dry run.
    let (status, body) = call(&api, "POST", "/v1/forks/try/replay", json!({"reason": ""})).await;
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (400, Some("REASON_REQUIRED")),
        "{body}"
    );
    assert_eq!(applied(&api).await, start);

    for case in &cases {
        let before = applied(&api).await;
        let (status, body) = call(
            &api,
            case.method,
            &concrete(case.path),
            with_reason(&case.extra, "dry run", true),
        )
        .await;
        assert_eq!(
            applied(&api).await,
            before,
            "dry_run wrote {} {} (HTTP {status}): {body}",
            case.method,
            case.path
        );
        if status == 200 {
            assert_eq!(
                body["dry_run"], true,
                "{} {} answered 200 without dry_run: {body}",
                case.method, case.path
            );
        }
    }
}

/// The file names and bytes under `dir`, so a rejected call can be proven
/// to have written nothing.
fn tree_snapshot(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            p.is_file()
                .then(|| Some((p.clone(), std::fs::read(&p).ok()?)))
                .flatten()
                .map(|(p, b)| (p.file_name().unwrap().into(), b))
        })
        .collect();
    out.sort();
    out
}

/// A message into a fork rejects `dry_run` outright — a fork has no live
/// effects to plan — and the rejection writes nothing: not to main, and not
/// to the fork's log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fork_message_rejects_dry_run_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let proposals =
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf()).unwrap();
    let api = Arc::new(Api::new(node).with_proposals(Arc::new(proposals)));
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(COUNTER).unwrap());
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks",
        json!({"at": 1, "name": "try", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    // One real message opens the fork's log.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks/try/actors/counter/a/messages",
        json!({"name": "increment", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let fork_log = dir.path().join("branches/try/log");
    let before = tree_snapshot(&fork_log);
    assert!(!before.is_empty(), "the fork's log exists");
    let applied_before = applied(&api).await;

    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks/try/actors/counter/a/messages",
        json!({"name": "increment", "reason": "r", "dry_run": true}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("BAD_REQUEST")),
        "{v}"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("dry_run is not supported for fork messages"),
        "{v}"
    );
    assert_eq!(applied(&api).await, applied_before, "main moved");
    assert_eq!(tree_snapshot(&fork_log), before, "the fork's log moved");
}

/// The audited record of `record` (M28 §4.1), labelled as the table's
/// `writes` column names it; None for records the audit export skips.
fn audited(record: &Record) -> Option<String> {
    Some(match record {
        Record::Deployment(_) => "Deployment".into(),
        Record::Grant(_) => "Grant".into(),
        Record::Limits(_) => "Limits".into(),
        Record::Policy(_) => "Policy".into(),
        Record::Approval(_) => "Approval".into(),
        Record::PrivacyMode(_) => "PrivacyMode".into(),
        Record::ForeignActor(_) => "ForeignActor".into(),
        Record::Erasure(_) => "Erasure".into(),
        Record::EngineUpgrade(_) => "EngineUpgrade".into(),
        Record::SimulatorConfig(_) => "SimulatorConfig".into(),
        Record::GuardTriggered(_) => "GuardTriggered".into(),
        Record::StateRebase(r) if matches!(r.part, Some(pb::state_rebase::Part::Switch(_))) => {
            "StateRebase".into()
        }
        Record::AuditEvent(e) => e.action.clone(),
        Record::TurnRecord(t) => match t.input.as_ref().and_then(|i| i.kind.as_ref()) {
            Some(pb::input::Kind::Message(m)) if m.source == pb::MessageSource::Operator as i32 => {
                "send".into()
            }
            Some(pb::input::Kind::Message(m))
                if m.source == pb::MessageSource::DeadLetterResend as i32 =>
            {
                "resend".into()
            }
            _ => return None,
        },
        _ => return None,
    })
}

/// The audited records main's log gained after `after`.
async fn audited_since(node: &kronik_sched::Node, after: u64) -> Vec<String> {
    let mut out = Vec::new();
    node.reader()
        .read(after + 1, node.applied_lsn(), |c| {
            out.extend(audited(&c.record));
            Ok(())
        })
        .await
        .unwrap();
    out
}

/// Routes this harness cannot run to success: `foreign add` needs runsc
/// and an image (`crates/kronik/tests/foreign.rs` covers its record). They
/// are still called, and a failed call must write nothing.
// shortcut: foreign add/remove are only checked to write nothing on failure here, extend once a test harness for foreign actors exists in kronik-api.
const UNDRIVEN: &[(&str, &str)] = &[("POST", "/v1/foreign"), ("DELETE", "/v1/foreign/{name}")];

/// Every mutating route, run once for real, writes exactly the audited
/// record its `writes` column names in main's log (M28 §4.2), and the
/// AuditEvent never holds a secret value or a token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_mutation_writes_its_audited_record() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let proposals = Arc::new(
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf()).unwrap(),
    );
    let watches = kronik_fork::watch::Watches::open(
        node.clone(),
        proposals.clone(),
        dir.path().to_path_buf(),
    )
    .unwrap()
    .start();
    let tokens = kronik_api::tokens::TokenStore::open_file(&dir.path().join("tokens.db")).unwrap();
    let api = Arc::new(
        Api::new(node.clone())
            .with_proposals(proposals)
            .with_watches(watches)
            .with_tokens(Arc::new(tokens))
            // A stream without a follower: the rewind is only requested.
            .with_exports(vec![kronik_otel::follow::Stream::new(
                "audit",
                true,
                "file://".into(),
                0,
            )]),
    );
    let b64 = |p: &str| base64::engine::general_purpose::STANDARD.encode(std::fs::read(p).unwrap());
    let step2 = b64(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/counter-step2.wasm"
    ));
    let mut writes: std::collections::BTreeMap<(&str, &str), &str> = cases()
        .iter()
        .map(|c| ((c.method, c.path), c.writes))
        .collect();
    writes.insert(NO_DRY_RUN[0], NO_DRY_RUN_WRITES);

    // (method, template, concrete path, body without reason); `{id}` and
    // `{epoch}` are filled from earlier answers.
    let steps: Vec<(&str, &str, &str, Value)> = vec![
        (
            "POST",
            "/v1/deployments",
            "/v1/deployments",
            json!({"wasm_base64": b64(COUNTER)}),
        ),
        // A failing turn, so that there is a dead letter to resend.
        (
            "POST",
            "/v1/actors/{kind}/{key}/messages",
            "/v1/actors/counter/a/messages",
            json!({"name": "fail"}),
        ),
        (
            "POST",
            "/v1/dead-letters/{id}/resend",
            "/v1/dead-letters/{id}/resend",
            json!({}),
        ),
        (
            "POST",
            "/v1/grants",
            "/v1/grants",
            json!({"kind": "counter", "capability": "http:example.com"}),
        ),
        (
            "POST",
            "/v1/grants/revoke",
            "/v1/grants/revoke",
            json!({"kind": "counter", "capability": "http:example.com"}),
        ),
        (
            "POST",
            "/v1/limits",
            "/v1/limits",
            json!({"kind": "counter", "fuel": 100_000_000}),
        ),
        (
            "PUT",
            "/v1/policy",
            "/v1/policy",
            json!({"rules_toml": "[[rule]]\nname = \"quiet\"\nwhen = \"false\"\naction = \"allow\"\n"}),
        ),
        (
            "PUT",
            "/v1/secrets/{name}",
            "/v1/secrets/db",
            json!({"text": "s3cr3t-value"}),
        ),
        ("DELETE", "/v1/secrets/{name}", "/v1/secrets/db", json!({})),
        (
            "POST",
            "/v1/tokens",
            "/v1/tokens",
            json!({"name": "agent-1"}),
        ),
        (
            "POST",
            "/v1/tokens/{name}/revoke",
            "/v1/tokens/agent-1/revoke",
            json!({}),
        ),
        (
            "POST",
            "/v1/forks",
            "/v1/forks",
            json!({"at": 1, "name": "try"}),
        ),
        (
            "POST",
            "/v1/forks/{name}/deployments",
            "/v1/forks/try/deployments",
            json!({"wasm_base64": step2.clone()}),
        ),
        (
            "POST",
            "/v1/forks/{name}/actors/{kind}/{key}/messages",
            "/v1/forks/try/actors/counter/a/messages",
            json!({"name": "increment"}),
        ),
        (
            "POST",
            "/v1/forks/{name}/replay",
            "/v1/forks/try/replay",
            json!({}),
        ),
        ("DELETE", "/v1/forks/{name}", "/v1/forks/try", json!({})),
        (
            "POST",
            "/v1/proposals",
            "/v1/proposals",
            json!({"wasm_base64": [step2], "threads": 2}),
        ),
        (
            "POST",
            "/v1/previews",
            "/v1/previews",
            json!({"proposal": "{id}"}),
        ),
        (
            "DELETE",
            "/v1/previews/{id}",
            "/v1/previews/{preview}",
            json!({}),
        ),
        (
            "POST",
            "/v1/proposals/{id}/request-approval",
            "/v1/proposals/{id}/request-approval",
            json!({}),
        ),
        (
            "POST",
            "/v1/proposals/{id}/approve",
            "/v1/proposals/{id}/approve",
            json!({}),
        ),
        (
            "POST",
            "/v1/proposals/{id}/promote",
            "/v1/proposals/{id}/promote",
            json!({}),
        ),
        (
            "POST",
            "/v1/deployments/{epoch}/watch",
            "/v1/deployments/{epoch}/watch",
            json!({"for_ms": 60_000, "async": true}),
        ),
        (
            "POST",
            "/v1/watches/{id}/stop",
            "/v1/watches/{watch}/stop",
            json!({}),
        ),
        // Before the rollback: a rollback via replay undoes main's newest
        // deployment only.
        (
            "POST",
            "/v1/deployments/{epoch}/rebase",
            "/v1/deployments/{epoch}/rebase",
            json!({}),
        ),
        (
            "POST",
            "/v1/deployments/{epoch}/rollback",
            "/v1/deployments/{epoch}/rollback",
            json!({}),
        ),
        (
            "PUT",
            "/v1/simulators/{target}",
            "/v1/simulators/http:example.com",
            json!({"neighbor": true}),
        ),
        (
            "POST",
            "/v1/privacy/mode",
            "/v1/privacy/mode",
            json!({"mode": "on"}),
        ),
        (
            "POST",
            "/v1/privacy/erase",
            "/v1/privacy/erase",
            json!({"subject": "user:1"}),
        ),
        (
            "POST",
            "/v1/privacy/reseal",
            "/v1/privacy/reseal",
            json!({}),
        ),
        ("POST", "/v1/snapshots", "/v1/snapshots", json!({})),
        (
            "POST",
            "/v1/export/{stream}/rewind",
            "/v1/export/audit/rewind",
            json!({"to": 0}),
        ),
        (
            "POST",
            "/v1/foreign",
            "/v1/foreign",
            json!({"name": "echo", "image": "not-an-image", "port": 8080}),
        ),
        (
            "DELETE",
            "/v1/foreign/{name}",
            "/v1/foreign/echo",
            json!({}),
        ),
    ];
    let run: std::collections::BTreeSet<(&str, &str)> =
        steps.iter().map(|(m, t, _, _)| (*m, *t)).collect();
    let all: std::collections::BTreeSet<(&str, &str)> = writes.keys().copied().collect();
    assert_eq!(run, all, "every mutating route runs once");

    let (mut dead_letter, mut proposal, mut epoch) = (String::new(), String::new(), String::new());
    let (mut preview, mut watch) = (String::new(), String::new());
    for (method, template, path, mut extra) in steps {
        if extra["proposal"] == "{id}" {
            extra["proposal"] = json!(proposal);
        }
        let path = path
            .replace("{preview}", &preview)
            .replace("{watch}", &watch)
            .replace(
                "{id}",
                if template.contains("dead-letters") {
                    &dead_letter
                } else {
                    &proposal
                },
            )
            .replace("{epoch}", &epoch);
        let before = node.applied_lsn();
        let (status, v) = call(&api, method, &path, with_reason(&extra, "audit", false)).await;
        let got = audited_since(&node, before).await;
        if UNDRIVEN.contains(&(method, template)) {
            assert_ne!(status, 200, "{method} {path}: {v}");
            assert_eq!(got, Vec::<String>::new(), "a failed {method} {path} wrote");
            continue;
        }
        assert_eq!(status, 200, "{method} {path}: {v}");
        assert_eq!(got, [writes[&(method, template)]], "{method} {path}: {v}");
        match template {
            "/v1/actors/{kind}/{key}/messages" => {
                dead_letter = v["turn_id"].as_str().unwrap().into()
            }
            "/v1/proposals" => proposal = v["proposal"]["id"].as_str().unwrap().into(),
            "/v1/proposals/{id}/promote" => epoch = v["deployment"]["epoch"].to_string(),
            "/v1/previews" => preview = v["preview"]["id"].as_str().unwrap().into(),
            "/v1/deployments/{epoch}/watch" => watch = v["watch"]["id"].as_str().unwrap().into(),
            _ => {}
        }
    }

    // What the AuditEvents hold: never the secret value or the token.
    let mut events = Vec::new();
    node.reader()
        .read(1, node.applied_lsn(), |c| {
            if let Record::AuditEvent(e) = &c.record {
                events.push(e.clone());
            }
            Ok(())
        })
        .await
        .unwrap();
    let text = format!("{events:?}");
    assert!(!text.contains("s3cr3t-value"), "{text}");
    assert!(!text.contains("kronik_"), "a token leaked: {text}");
    let token = events.iter().find(|e| e.action == "token.create").unwrap();
    assert_eq!(token.target, "agent-1");
    assert_eq!(token.details["token_id"], "token:agent-1");
    let send = events.iter().find(|e| e.action == "fork.send").unwrap();
    assert_eq!(
        (send.target.as_str(), send.details["actor"].as_str()),
        ("try", "counter/a")
    );
    assert!(
        events
            .iter()
            .all(|e| e.audit.as_ref().unwrap().reason == "audit")
    );
}

/// Secrets and tokens write their `AuditEvent` before the change, and a
/// change that fails after it adds `<action>.failed` with the error code
/// (M28 review M3). The token store is opened read-only, so the
/// validation passes and the insert fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_token_create_writes_its_intent_and_failed() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let path = dir.path().join("tokens.db");
    drop(kronik_api::tokens::TokenStore::open_file(&path).unwrap());
    let read_only =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let tokens = kronik_api::tokens::TokenStore::open(read_only).unwrap();
    let api = Api::new(node.clone()).with_tokens(Arc::new(tokens));
    let before = node.applied_lsn();
    let (status, v) = call(
        &api,
        "POST",
        "/v1/tokens",
        json!({"name": "agent-1", "reason": "audit"}),
    )
    .await;
    assert_eq!(status, 500, "{v}");
    let mut events = Vec::new();
    node.reader()
        .read(before + 1, node.applied_lsn(), |c| {
            if let Record::AuditEvent(e) = &c.record {
                events.push(e.clone());
            }
            Ok(())
        })
        .await
        .unwrap();
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, ["token.create", "token.create.failed"]);
    assert_eq!(events[1].details["code"], "INTERNAL");
    assert_eq!(events[1].details["token_id"], "token:agent-1");
    assert_eq!(events[1].target, "agent-1");
}

/// The `AuditEvent`s of `action` in main's log, with their LSNs.
async fn events_of(node: &kronik_sched::Node, action: &str) -> Vec<(u64, pb::AuditEvent)> {
    let mut out = Vec::new();
    node.reader()
        .read(1, node.applied_lsn(), |c| {
            if let Record::AuditEvent(e) = &c.record
                && e.action == action
            {
                out.push((c.lsn, e.clone()));
            }
            Ok(())
        })
        .await
        .unwrap();
    out
}

fn guest(name: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(
        std::fs::read(format!(
            "{}/../../tests/guests/{name}.wasm",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
}

/// Perf review P3: a synchronous watch writes `watch.start` before it
/// waits, so the event precedes the rollback its guard makes (and a caller
/// that stops waiting cannot lose it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_synchronous_watch_is_audited_before_its_guard_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let proposals = Arc::new(
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf()).unwrap(),
    );
    let watches = kronik_fork::watch::Watches::open(
        node.clone(),
        proposals.clone(),
        dir.path().to_path_buf(),
    )
    .unwrap()
    .with_interval(std::time::Duration::from_millis(50))
    .start();
    let api = Api::new(node.clone())
        .with_proposals(proposals)
        .with_watches(watches);
    let post = |path: &'static str, body: Value| {
        let api = &api;
        async move {
            let (s, v) = call(api, "POST", path, with_reason(&body, "r", false)).await;
            assert_eq!(s, 200, "{path}: {v}");
            v
        }
    };
    post("/v1/deployments", json!({"wasm_base64": guest("counter")})).await;
    for _ in 0..20 {
        post(
            "/v1/actors/counter/a/messages",
            json!({"name": "increment"}),
        )
        .await;
    }
    let v = post(
        "/v1/proposals",
        json!({"wasm_base64": [guest("counter-fail-get")]}),
    )
    .await;
    let id = v["proposal"]["id"].as_str().unwrap().to_owned();
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/proposals/{id}/promote"),
        with_reason(&json!({}), "r", false),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let epoch = v["deployment"]["epoch"].as_u64().unwrap();
    // Every `get` fails in the new build.
    for _ in 0..25 {
        post("/v1/actors/counter/a/messages", json!({"name": "get"})).await;
    }
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/deployments/{epoch}/watch"),
        with_reason(&json!({"for_ms": 60_000}), "r", false),
    )
    .await;
    assert_eq!(
        (s, &v["watch"]["status"]),
        (200, &json!("rolled_back")),
        "{v}"
    );
    let (rollback_lsn, d) = node.store().db().deployments().unwrap().pop().unwrap();
    assert_eq!(d.cause, pb::DeploymentCause::Rollback as i32);
    let [(start_lsn, start)] = events_of(&node, "watch.start").await.try_into().unwrap();
    assert_eq!(start.target, v["watch"]["id"].as_str().unwrap());
    assert!(
        start_lsn < rollback_lsn,
        "watch.start at {start_lsn}, the rollback at {rollback_lsn}"
    );
}

/// Perf review P3: a synchronous propose writes `proposal.create` before
/// it waits for the replay, so a request dropped while waiting (a client
/// timeout, MCP's `propose_change`) still leaves it in the log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_synchronous_propose_dropped_while_waiting_is_still_audited() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    // The test gate holds the job's replay at its first root input.
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let proposals = Arc::new(
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_test_gate(gate.clone()),
    );
    let api = Api::new(node.clone()).with_proposals(proposals.clone());
    for (path, body) in [
        ("/v1/deployments", json!({"wasm_base64": guest("counter")})),
        (
            "/v1/actors/counter/a/messages",
            json!({"name": "increment"}),
        ),
    ] {
        let (s, v) = call(&api, "POST", path, with_reason(&body, "r", false)).await;
        assert_eq!(s, 200, "{path}: {v}");
    }
    let body = with_reason(
        &json!({"wasm_base64": [guest("counter-step2")]}),
        "r",
        false,
    );
    let dropped = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        call(&api, "POST", "/v1/proposals", body),
    )
    .await;
    assert!(dropped.is_err(), "the propose did not wait: {dropped:?}");
    gate.add_permits(1000);
    let mut list = Vec::new();
    for _ in 0..600 {
        list = proposals.list().await;
        if list.iter().all(|p| p.status != "running") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let [p] = list.try_into().unwrap();
    assert_eq!(p.status, "evaluated", "{p:?}");
    let [(_, event)] = events_of(&node, "proposal.create")
        .await
        .try_into()
        .unwrap();
    assert_eq!(event.target, p.id);
}
