//! `POST /v1/deployments/{epoch}/rebase` and the promote of a rebase
//! (docs/design/m13-rebase.md §7).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;

use base64::Engine as _;
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_sched::{NodeConfig, start_local};
use serde_json::{Value, json};

const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests");

async fn call(api: &Api, method: &str, path: &str, body: Value) -> (u16, Value) {
    let r = api
        .handle(ApiRequest {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            body: if body.is_null() {
                vec![]
            } else {
                body.to_string().into_bytes()
            },
            token_id: "unix:uid=0".into(),
            bearer: None,
        })
        .await;
    (r.status, serde_json::from_slice(&r.body).unwrap())
}

fn wasm(name: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(format!("{GUESTS}/{name}.wasm")).unwrap())
}

async fn increment(api: &Api) -> Value {
    let (s, v) = call(
        api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "increment", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebase_endpoints() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let proposals =
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf()).unwrap();
    let api = Arc::new(Api::new(node.clone()).with_proposals(Arc::new(proposals)));
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm("counter"), "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = call(
        &api,
        "PUT",
        "/v1/policy",
        json!({"rules_toml": "[[rule]]\nname = \"quiet\"\nwhen = \"false\"\naction = \"allow\"\n", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    for _ in 0..2 {
        increment(&api).await;
    }
    let (s, v) = call(
        &api,
        "POST",
        "/v1/proposals",
        json!({"wasm_base64": [wasm("counter-schema1")], "reason": "schema 1"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let id = v["proposal"]["id"].as_str().unwrap().to_owned();
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/proposals/{id}/promote"),
        json!({"reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(v.get("rebase").is_none(), "{v}");
    let epoch = v["deployment"]["epoch"].as_u64().unwrap();
    assert_eq!(increment(&api).await["reply"]["text"], "3");

    // Refusals: an unknown epoch, isolated replay alone.
    let path = format!("/v1/deployments/{epoch}/rebase");
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments/99/rebase",
        json!({"reason": "r"}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (404, Some("DEPLOYMENT_NOT_FOUND")),
        "{v}"
    );
    let (s, v) = call(
        &api,
        "POST",
        &path,
        json!({"mode": "isolated", "reason": "r"}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("BAD_REQUEST")),
        "{v}"
    );

    // A dry run, then the rebase proposal.
    let (s, v) = call(
        &api,
        "POST",
        &path,
        json!({"reason": "undo", "dry_run": true}),
    )
    .await;
    assert_eq!((s, &v["dry_run"]), (200, &json!(true)), "{v}");
    let (s, v) = call(&api, "POST", &path, json!({"reason": "undo"})).await;
    assert_eq!(s, 200, "{v}");
    let p = &v["proposal"];
    let rid = p["id"].as_str().unwrap().to_owned();
    assert!(rid.starts_with("r-"), "{rid}");
    assert_eq!(p["rebase"]["rolled_back_epoch"], epoch, "{p}");
    assert_eq!(p["rebase"]["irreversible_effects"], 0, "{p}");
    // The creation is audited once, naming the rebase (M28 §4.2); the
    // refusals and the dry run write nothing.
    let mut events = Vec::new();
    node.reader()
        .read(1, node.applied_lsn(), |c| {
            if let kronik_proto::Record::AuditEvent(e) = &c.record
                && e.action == "rebase.create"
            {
                events.push(e.clone());
            }
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].target, rid);
    assert_eq!(
        events[0].details["rolled_back_epoch"],
        epoch.to_string(),
        "{events:?}"
    );
    assert_eq!(
        events[0].details["base_lsn"],
        p["rebase"]["base_lsn"].to_string(),
        "{events:?}"
    );
    assert_eq!(events[0].audit.as_ref().unwrap().reason, "undo");
    let (_, d) = call(
        &api,
        "GET",
        &format!("/v1/proposals/{rid}/diff"),
        Value::Null,
    )
    .await;
    assert_eq!(d["irreversible"]["count"], 0, "{d}");

    // The switch needs an approval, then rebases.
    let promote = format!("/v1/proposals/{rid}/promote");
    let (s, v) = call(&api, "POST", &promote, json!({"reason": "undo"})).await;
    assert_eq!(v["error"]["code"], "APPROVAL_REQUIRED", "{s} {v}");
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/proposals/{rid}/approve"),
        json!({"reason": "read it"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = call(
        &api,
        "POST",
        &promote,
        json!({"reason": "undo", "dry_run": true}),
    )
    .await;
    assert_eq!((s, &v["rebase"]["lsn"]), (200, &json!(0)), "{v}");
    let (s, v) = call(&api, "POST", &promote, json!({"reason": "undo"})).await;
    assert_eq!(s, 200, "{v}");
    let lsn = v["rebase"]["lsn"].as_u64().unwrap();
    assert!(lsn > 0, "{v}");
    assert!(v["rebase"]["turns"].as_u64().unwrap() > 0, "{v}");
    let (_, p) = call(&api, "GET", &format!("/v1/proposals/{rid}"), Value::Null).await;
    assert_eq!(
        (&p["status"], &p["rebase"]["switch_lsn"]),
        (&json!("promoted"), &json!(lsn)),
        "{p}"
    );
    // The old code runs on the old code's state: no migration key.
    assert_eq!(increment(&api).await["reply"]["text"], "4");
    let (_, a) = call(&api, "GET", "/v1/actors/counter/a", Value::Null).await;
    let keys: Vec<&str> = a["state"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["n"], "{a}");
    let (_, d) = call(&api, "GET", "/v1/deployments", Value::Null).await;
    let last = d["deployments"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(
        (&last["cause"], &last["lsn"]),
        (&json!("rollback"), &json!(lsn)),
        "{last}"
    );
}
