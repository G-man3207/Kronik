//! The M6 storage endpoints: snapshots and integrity.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;

use base64::Engine as _;
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_sched::{NodeConfig, start_local};
use serde_json::{Value, json};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

async fn call(api: &Api, method: &str, path: &str, body: Value) -> (u16, Value) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let r = api
        .handle(ApiRequest {
            method: method.into(),
            path: path.into(),
            query: query.into(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshots_and_integrity() {
    let dir = tempfile::Builder::new()
        .prefix("api-m6-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let api = Arc::new(Api::new(node.clone()));
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(COUNTER).unwrap());
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    for _ in 0..3 {
        let (s, v) = call(
            &api,
            "POST",
            "/v1/actors/counter/a/messages",
            json!({"name": "increment", "reason": "r"}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
    }

    let (s, v) = call(&api, "GET", "/v1/snapshots", Value::Null).await;
    assert_eq!((s, v["snapshots"].as_array().unwrap().len()), (200, 0));
    let (s, v) = call(&api, "POST", "/v1/snapshots", json!({"reason": ""})).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("REASON_REQUIRED"))
    );
    let (s, v) = call(
        &api,
        "POST",
        "/v1/snapshots",
        json!({"reason": "r", "dry_run": true}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["snapshot"], Value::Null);
    let applied = node.applied_lsn();
    assert_eq!(v["lsn"], applied);

    let (_, at_applied) = call(&api, "GET", "/v1/integrity", Value::Null).await;
    assert_eq!(at_applied["through_lsn"], applied);
    let (s, v) = call(&api, "POST", "/v1/snapshots", json!({"reason": "r"})).await;
    assert_eq!(s, 200, "{v}");
    let snap = v["snapshot"].clone();
    assert_eq!(snap["lsn"], applied);
    assert_eq!(snap["reason"], "manual");
    assert_eq!(snap["shipped"], false);
    let (_, list) = call(&api, "GET", "/v1/snapshots", Value::Null).await;
    assert_eq!(list["snapshots"][0], snap);

    // The integrity hashes: the state hash equals the snapshot's at its
    // LSN; the snapshot marker and the `snapshot.create` AuditEvent (M28)
    // moved the applied LSN by two, and neither changed the state (applied
    // right after they are logged, so wait for them).
    for _ in 0..500 {
        if node.applied_lsn() >= applied + 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let (s, i) = call(&api, "GET", "/v1/integrity", Value::Null).await;
    assert_eq!(s, 200, "{i}");
    assert_eq!(i["applied_lsn"], node.applied_lsn());
    assert_eq!(i["applied_lsn"], applied + 2);
    assert_eq!(i["state_hash"], snap["state_hash"]);
    assert_eq!(i["log_first_lsn"], 1);
    assert_eq!(i["retention_history_ms"], 7 * 86_400 * 1_000);
    assert!(i["newest_logical_time_ms"].as_u64().unwrap() > 0);
    assert!(i["retention_cutoff_ms"].as_u64().unwrap() > 0);
    let (_, again) = call(&api, "GET", "/v1/integrity", Value::Null).await;
    assert_eq!(again, i);
    // Through an earlier LSN: the hash the log had then, though records
    // followed (as a restored node's `restore` event follows the source's
    // last record).
    let (s, through) = call(
        &api,
        "GET",
        &format!("/v1/integrity?through={applied}"),
        Value::Null,
    )
    .await;
    assert_eq!(s, 200, "{through}");
    assert_eq!(through["through_lsn"], applied);
    assert_eq!(through["log_hash"], at_applied["log_hash"]);
    assert_ne!(through["log_hash"], i["log_hash"]);
    for bad in [0, applied + 3] {
        let (s, v) = call(
            &api,
            "GET",
            &format!("/v1/integrity?through={bad}"),
            Value::Null,
        )
        .await;
        assert_eq!(s, 400, "through {bad}: {v}");
    }
}
