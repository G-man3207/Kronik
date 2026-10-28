//! Every mutation requires a non-blank reason and a dry run writes nothing
//! (I12). The table is checked against the OpenAPI operation list, so a new
//! POST, PUT or DELETE that is not classified here fails the test.
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
use kronik_sched::{NodeConfig, start_local};
use serde_json::{Value, json};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

/// Writes nothing. Not a mutation.
const NOT_A_MUTATION: &[(&str, &str)] = &[("POST", "/v1/policy/test")];

/// Requires a reason. No dry run: it writes only in its fork.
const NO_DRY_RUN: &[(&str, &str)] = &[("POST", "/v1/forks/{name}/replay")];

struct Case {
    method: &'static str,
    path: &'static str,
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
            extra: json!({"wasm_base64": wasm.clone()}),
        },
        Case {
            method: "POST",
            path: "/v1/deployments/{epoch}/rollback",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/deployments/{epoch}/rebase",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/deployments/{epoch}/watch",
            extra: json!({"for_ms": 60_000}),
        },
        Case {
            method: "POST",
            path: "/v1/watches/{id}/stop",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/actors/{kind}/{key}/messages",
            extra: json!({"name": "increment"}),
        },
        Case {
            method: "POST",
            path: "/v1/dead-letters/{id}/resend",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/grants",
            extra: json!({"kind": "counter", "capability": "http:example.com"}),
        },
        Case {
            method: "POST",
            path: "/v1/grants/revoke",
            extra: json!({"kind": "counter", "capability": "http:example.com"}),
        },
        Case {
            method: "POST",
            path: "/v1/limits",
            extra: json!({"kind": "counter", "fuel": 1000}),
        },
        Case {
            method: "PUT",
            path: "/v1/secrets/{name}",
            extra: json!({"text": "value"}),
        },
        Case {
            method: "DELETE",
            path: "/v1/secrets/{name}",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/tokens",
            extra: json!({"name": "agent-1"}),
        },
        Case {
            method: "POST",
            path: "/v1/tokens/{name}/revoke",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/forks",
            extra: json!({"at": "now"}),
        },
        Case {
            method: "DELETE",
            path: "/v1/forks/{name}",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/forks/{name}/deployments",
            extra: json!({"wasm_base64": wasm.clone()}),
        },
        Case {
            method: "POST",
            path: "/v1/forks/{name}/actors/{kind}/{key}/messages",
            extra: json!({"name": "increment"}),
        },
        Case {
            method: "POST",
            path: "/v1/previews",
            extra: json!({"proposal": "p-000000000000"}),
        },
        Case {
            method: "DELETE",
            path: "/v1/previews/{id}",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/proposals",
            extra: json!({"wasm_base64": [wasm]}),
        },
        Case {
            method: "POST",
            path: "/v1/proposals/{id}/request-approval",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/proposals/{id}/approve",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/proposals/{id}/promote",
            extra: json!({}),
        },
        Case {
            method: "PUT",
            path: "/v1/policy",
            extra: json!({"rules_toml": "[[rule]]\nname = \"quiet\"\nwhen = \"false\"\naction = \"allow\"\n"}),
        },
        Case {
            method: "POST",
            path: "/v1/foreign",
            extra: json!({"name": "echo", "image": "not-an-image", "port": 8080}),
        },
        Case {
            method: "DELETE",
            path: "/v1/foreign/{name}",
            extra: json!({}),
        },
        Case {
            method: "PUT",
            path: "/v1/simulators/{target}",
            extra: json!({"neighbor": true}),
        },
        Case {
            method: "POST",
            path: "/v1/privacy/mode",
            extra: json!({"mode": "on"}),
        },
        Case {
            method: "POST",
            path: "/v1/privacy/erase",
            extra: json!({"subject": "user:1"}),
        },
        Case {
            method: "POST",
            path: "/v1/privacy/reseal",
            extra: json!({}),
        },
        Case {
            method: "POST",
            path: "/v1/snapshots",
            extra: json!({}),
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
            .with_watches(watches),
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
