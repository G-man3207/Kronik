//! API service-function tests on the real environment.

// Test helpers outside #[test] functions may unwrap too, and tests poll
// with tokio's sleep.
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
const NOTES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/notes.wasm");

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

fn wasm(path: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(std::fs::read(path).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn endpoints() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let api = Arc::new(Api::new(node));

    let (s, v) = call(&api, "GET", "/v1/health", Value::Null).await;
    assert_eq!(s, 200);
    assert_eq!(v["status"], "ok");

    // Mutations need a reason.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(COUNTER), "reason": " "}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("REASON_REQUIRED"))
    );
    // Dry run writes nothing.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(COUNTER), "reason": "r", "dry_run": true}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["dry_run"], true);
    let (_, v) = call(&api, "GET", "/v1/deployments", Value::Null).await;
    assert_eq!(v["deployments"].as_array().unwrap().len(), 0);

    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(COUNTER), "reason": "first deploy"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["deployment"]["kind"], "counter");
    assert_eq!(
        v["deployment"]["routes"][0]["pattern"],
        "/counter/{key}/{op}"
    );
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(NOTES), "reason": "notes"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");

    let (s, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "increment", "reason": "test"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["outcome"]["kind"], "committed");
    assert_eq!(v["reply"]["text"], "1");
    let turn_id = v["turn_id"].as_str().unwrap().to_owned();

    let (s, v) = call(
        &api,
        "POST",
        "/v1/actors/notes/n/messages",
        json!({"name": "add", "text": "hello", "subject": "user:9", "reason": "test"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");

    let (_, v) = call(&api, "GET", "/v1/actors", Value::Null).await;
    let names: Vec<String> = v["actors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            format!(
                "{}/{}",
                a["kind"].as_str().unwrap(),
                a["key"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(names, ["counter/a", "notes/n"]);

    let (s, v) = call(&api, "GET", "/v1/actors/counter/a", Value::Null).await;
    assert_eq!(s, 200);
    assert_eq!(v["state"][0]["key"], "n");
    assert_eq!(v["state"][0]["text"], "1");
    let (_, v) = call(&api, "GET", "/v1/actors/notes/n", Value::Null).await;
    assert_eq!(v["sql"]["tables"][0], json!({"name": "notes", "rows": 1}));

    let (_, v) = call(&api, "GET", "/v1/actors/notes/n/history", Value::Null).await;
    let turns = v["turns"].as_array().unwrap();
    assert_eq!(turns.len(), 2);
    assert_eq!(turns[0]["input"]["summary"], "add from operator");
    assert_eq!(turns[1]["input"]["type"], "migrate");

    let (s, v) = call(&api, "GET", &format!("/v1/turns/{turn_id}"), Value::Null).await;
    assert_eq!(s, 200);
    assert_eq!(v["actor"], "counter/a");
    assert_eq!(v["writes"][0]["value"]["value"]["text"], "1");
    assert_eq!(v["input"]["reason"], "test");

    let (_, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "fail", "reason": "test"}),
    )
    .await;
    assert_eq!(v["outcome"]["error_code"], "TURN_FAILED");
    let failed = v["turn_id"].as_str().unwrap().to_owned();
    let (_, v) = call(&api, "GET", "/v1/dead-letters", Value::Null).await;
    assert_eq!(v["dead_letters"][0]["id"], failed.as_str());
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/dead-letters/{failed}/resend"),
        json!({"reason": "retry", "dry_run": true}),
    )
    .await;
    assert_eq!((s, &v["dry_run"]), (200, &json!(true)));
    let (s, _) = call(
        &api,
        "POST",
        &format!("/v1/dead-letters/{failed}/resend"),
        json!({"reason": "retry"}),
    )
    .await;
    assert_eq!(s, 200);
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/dead-letters/{failed}/resend"),
        json!({"reason": "retry"}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (409, Some("DEAD_LETTER_ALREADY_RESENT"))
    );

    let (s, v) = call(&api, "GET", "/v1/actors/counter/zzz", Value::Null).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (404, Some("ACTOR_NOT_FOUND"))
    );
    assert_eq!(v["error"]["docs"], "kronik explain ACTOR_NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m2_endpoints() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let api = Arc::new(Api::new(node).with_http_listen("127.0.0.1:1".into()));
    let (_, v) = call(&api, "GET", "/v1/health", Value::Null).await;
    assert_eq!(v["http_listen"], "127.0.0.1:1");
    call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(COUNTER), "reason": "r"}),
    )
    .await;

    // Denied effect: history shows the exact grant command.
    let (_, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "fetch-ok", "text": "GET http://127.0.0.1:9/x", "reason": "t"}),
    )
    .await;
    assert!(
        v["reply"]["text"]
            .as_str()
            .unwrap()
            .contains("CAPABILITY_NOT_GRANTED"),
        "{v}"
    );
    let (_, v) = call(&api, "GET", "/v1/actors/counter/a/history", Value::Null).await;
    let e = &v["turns"][0]["effects"][0];
    assert_eq!(e["status"], "denied");
    assert_eq!(
        e["hint"],
        "kronik grant counter http:127.0.0.1 --reason '...'"
    );

    // Grants.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "http:*.Example.com",
        "delivery": "idempotency-keyed", "rate": "2/s", "reason": "r", "dry_run": true}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["grant"]["lsn"], 0);
    let (_, v) = call(&api, "GET", "/v1/grants", Value::Null).await;
    assert_eq!(v["grants"].as_array().unwrap().len(), 0);
    let (s, v) = call(
        &api,
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "http:*.Example.com",
        "delivery": "idempotency-keyed", "rate": "2/s", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["grant"]["capability"], "http:*.example.com");
    let (_, v) = call(&api, "GET", "/v1/grants?kind=counter", Value::Null).await;
    assert_eq!(v["grants"][0]["rate"], "2/s");
    assert_eq!(v["grants"][0]["delivery"], "idempotency-keyed");
    assert!(v["grants"][0]["lsn"].as_u64().unwrap() > 0);
    let (s, v) = call(
        &api,
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "ftp:x", "reason": "r"}),
    )
    .await;
    assert_eq!((s, v["error"]["code"].as_str()), (400, Some("BAD_REQUEST")));
    let (s, _) = call(
        &api,
        "POST",
        "/v1/grants/revoke",
        json!({"kind": "counter", "capability": "http:*.example.com", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200);
    let (s, v) = call(
        &api,
        "POST",
        "/v1/grants/revoke",
        json!({"kind": "counter", "capability": "http:*.example.com", "reason": "r"}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (403, Some("CAPABILITY_NOT_GRANTED"))
    );

    // Limits.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/limits",
        json!({"kind": "counter", "fuel": 1000000, "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["limits"]["fuel"], 1_000_000);
    assert_eq!(v["limits"]["memory_bytes"], 64 << 20);
    let (_, v) = call(&api, "GET", "/v1/limits?kind=counter", Value::Null).await;
    assert_eq!(v["limits"][0]["fuel"], 1_000_000);
    let (_, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "spin", "text": "x", "reason": "t"}),
    )
    .await;
    assert_eq!(v["outcome"]["error_code"], "FUEL_EXHAUSTED");

    // Secrets: values are never returned.
    let (s, v) = call(
        &api,
        "PUT",
        "/v1/secrets/api-key",
        json!({"text": "s3cr3t-value", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["secret"]["version"], 1);
    let (_, v) = call(&api, "GET", "/v1/secrets", Value::Null).await;
    assert_eq!(v["secrets"][0]["name"], "api-key");
    assert!(!v.to_string().contains("s3cr3t-value"));
    let (s, v) = call(
        &api,
        "DELETE",
        "/v1/secrets/api-key",
        json!({"reason": "r"}),
    )
    .await;
    assert_eq!((s, v["deleted"]["versions"].as_u64()), (200, Some(1)));
    let (s, v) = call(
        &api,
        "DELETE",
        "/v1/secrets/api-key",
        json!({"reason": "r"}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (404, Some("SECRET_NOT_FOUND"))
    );

    // Orphans and timers.
    call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "call-fail", "text": "counter/b increment", "reason": "t"}),
    )
    .await;
    let (_, v) = call(&api, "GET", "/v1/orphans", Value::Null).await;
    assert_eq!(v["orphans"][0]["actor"], "counter/b");
    assert_eq!(v["orphans"][0]["caller"], "counter/a");
    assert!(v["orphans"][0]["compensation"].is_null());
    call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "schedule", "text": "100000 increment", "reason": "t"}),
    )
    .await;
    let (_, v) = call(&api, "GET", "/v1/actors/counter/a/timers", Value::Null).await;
    assert_eq!(v["timers"][0]["name"], "increment");
}

async fn raw(api: &Api, method: &str, path: &str) -> (u16, &'static str, Vec<u8>) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let r = api
        .handle(ApiRequest {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            body: vec![],
            token_id: "unix:uid=0".into(),
            bearer: None,
        })
        .await;
    (r.status, r.content_type, r.body)
}

/// The M3 endpoints (m3-fork §9): forks, replay, diffs, proposals,
/// approval, promote, rollback and policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m3_endpoints() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let proposals =
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf()).unwrap();
    let api = Arc::new(Api::new(node.clone()).with_proposals(Arc::new(proposals)));
    let step2 = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/counter-step2.wasm"
    );
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(COUNTER), "reason": "r"}),
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

    // A fork at the deployment, new code in it, replay, diff.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks",
        json!({"at": 1, "name": "try", "reason": "r"}),
    )
    .await;
    assert_eq!(
        (s, &v["fork"]["name"], &v["fork"]["fork_lsn"]),
        (200, &json!("try"), &json!(1)),
        "{v}"
    );
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks/try/deployments",
        json!({"wasm_base64": wasm(step2), "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["deployment"]["kind"], "counter");
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks/try/replay",
        json!({"reason": "r", "threads": 2}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["summary"]["root_inputs"], 3);
    assert_eq!(v["summary"]["changed"], true);
    let (s, ct, body) = raw(&api, "GET", "/v1/forks/try/diff?format=md").await;
    assert_eq!((s, ct), (200, "text/markdown; charset=utf-8"));
    assert!(
        String::from_utf8(body)
            .unwrap()
            .contains("# Behavior diff: try")
    );
    let (s, v) = call(&api, "GET", "/v1/forks/try/diff", Value::Null).await;
    assert_eq!((s, &v["schema"]), (200, &json!("kronik.diff/v1")));
    // The diff's isolated sample turns can be traced, also after a restart
    // (a fresh Proposals over the same data directory).
    let sample = v["samples"]["origins"][0].as_str().unwrap().to_owned();
    assert!(sample.starts_with("try:r"), "{sample}");
    let restarted = Api::new(node.clone()).with_proposals(Arc::new(
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf()).unwrap(),
    ));
    for a in [&api, &restarted] {
        let (s, t) = call(a, "GET", &format!("/v1/turns/{sample}"), Value::Null).await;
        assert_eq!((s, &t["turn_id"]), (200, &json!(sample)), "{t}");
        let (s, t) = call(a, "GET", &format!("/v1/turns/{sample}/trace"), Value::Null).await;
        assert_eq!((s, &t["turn"]["turn_id"]), (200, &json!(sample)), "{t}");
        assert_eq!(t["actor"], "counter/a");
    }
    let (s, _) = call(&restarted, "GET", "/v1/turns/try:r999.0", Value::Null).await;
    assert_eq!(s, 404);
    let (_, v) = call(&api, "GET", "/v1/forks", Value::Null).await;
    assert_eq!(v["forks"][0]["name"], "try");
    let (s, v) = call(&api, "GET", "/v1/forks/nope/diff", Value::Null).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (404, Some("FORK_NOT_FOUND"))
    );

    // A message into the fork runs on its continuous state (3 x 2 = 6).
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks/try/actors/counter/a/messages",
        json!({"name": "increment", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["reply"]["text"], "8", "{v}");
    let fork_turn = v["turn_id"].as_str().unwrap().to_owned();
    assert!(fork_turn.starts_with("try:"));
    // The fork's turn is in the fork's log.
    let (s, v) = call(&api, "GET", &format!("/v1/turns/{fork_turn}"), Value::Null).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["turn_id"], fork_turn.as_str());
    let (s, v) = call(
        &api,
        "GET",
        &format!("/v1/turns/{fork_turn}/trace"),
        Value::Null,
    )
    .await;
    assert_eq!((s, &v["turn"]["turn_id"]), (200, &json!(fork_turn)), "{v}");
    let (s, _) = call(&api, "GET", "/v1/turns/try:999999", Value::Null).await;
    assert_eq!(s, 404);
    // Main is untouched.
    let (_, v) = call(&api, "GET", "/v1/actors/counter/a", Value::Null).await;
    let n = v["state"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["key"] == "n")
        .unwrap()["text"]
        .clone();
    assert_eq!(n, "3");

    // Trace: a forward and the increment it caused.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/t/messages",
        json!({"name": "forward", "text": "u", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let root = v["turn_id"].as_str().unwrap().to_owned();
    let mut child = None;
    for _ in 0..200 {
        let (_, h) = call(&api, "GET", "/v1/actors/counter/u/history", Value::Null).await;
        if let Some(t) = h["turns"].as_array().and_then(|t| t.first()) {
            child = Some(t["turn_id"].as_str().unwrap().to_owned());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let child = child.expect("the forwarded increment ran");
    let (s, v) = call(&api, "GET", &format!("/v1/turns/{root}/trace"), Value::Null).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["ancestors"].as_array().unwrap().len(), 0);
    assert_eq!(v["descendants"][0]["turn_id"], child.as_str());
    assert_eq!(v["descendants"][0]["actor"], "counter/u");
    let (_, v) = call(
        &api,
        "GET",
        &format!("/v1/turns/{child}/trace"),
        Value::Null,
    )
    .await;
    assert_eq!(v["ancestors"][0]["turn_id"], root.as_str());
    assert_eq!(v["root"]["lsn"], v["ancestors"][0]["lsn"]);

    // Policy: defaults, test, set.
    let (_, v) = call(&api, "GET", "/v1/policy", Value::Null).await;
    assert_eq!(v["default"], true);
    // Review W-M5: `policy show` shows the guards in force.
    assert_eq!(v["default_guards"], true, "{v}");
    assert_eq!(v["guards"][0]["name"], "error-rate-up", "{v}");
    assert_eq!(v["guards"][0]["action"], "rollback", "{v}");
    let (s, v) = call(&api, "POST", "/v1/policy/test", json!({"proposal": "try"})).await;
    assert_eq!((s, &v["outcome"]), (200, &json!("allow")), "{v}");
    let strict = "[[rule]]\nname = \"any-change\"\nwhen = \"diff.summary.changed\"\naction = \"require_approval\"\n";
    let (s, v) = call(
        &api,
        "POST",
        "/v1/policy/test",
        json!({"proposal": "try", "rules_toml": strict}),
    )
    .await;
    assert_eq!((s, &v["outcome"]), (200, &json!("require_approval")), "{v}");
    let (s, v) = call(
        &api,
        "PUT",
        "/v1/policy",
        json!({"rules_toml": "[[rule]]\nname = 1", "reason": "r"}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("BAD_REQUEST")),
        "{v}"
    );
    let (s, v) = call(
        &api,
        "PUT",
        "/v1/policy",
        json!({"rules_toml": strict, "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (_, v) = call(&api, "GET", "/v1/policy", Value::Null).await;
    assert_eq!(
        (&v["default"], &v["rules_toml"]),
        (&json!(false), &json!(strict))
    );
    // Rules only: the default guards still apply. `guard = []`: none.
    assert_eq!(
        (&v["default_guards"], v["guards"].as_array().map(Vec::len)),
        (&json!(true), Some(2))
    );
    let no_guards = format!("guard = []\n\n{strict}");
    let (s, v) = call(
        &api,
        "PUT",
        "/v1/policy",
        json!({"rules_toml": no_guards, "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (_, v) = call(&api, "GET", "/v1/policy", Value::Null).await;
    assert_eq!(
        (&v["default_guards"], &v["guards"]),
        (&json!(false), &json!([])),
        "{v}"
    );

    // Propose under the stricter policy: approval, then promote.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/proposals",
        json!({"wasm_base64": [wasm(step2)], "reason": "r", "threads": 2}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let id = v["proposal"]["id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("p-"));
    assert_eq!(v["proposal"]["policy"]["outcome"], "require_approval");
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/proposals/{id}/request-approval"),
        json!({"reason": "please"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        v["request"]["command"],
        format!("kronik approve {id} --reason '...'")
    );
    let (_, v) = call(&api, "GET", &format!("/v1/proposals/{id}"), Value::Null).await;
    assert_eq!(v["approval_requests"][0]["pending"], true, "{v}");
    assert_eq!(v["approval_requests"][0]["reason"], "please");
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/proposals/{id}/promote"),
        json!({"reason": "r"}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (403, Some("APPROVAL_REQUIRED")),
        "{v}"
    );
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/proposals/{id}/approve"),
        json!({"reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(v["approval"]["lsn"].as_u64().unwrap() > 0);
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/proposals/{id}/promote"),
        json!({"reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let epoch = v["deployment"]["epoch"].as_u64().unwrap();
    assert_eq!(v["deployment"]["kinds"][0]["kind"], "counter");
    let (_, v) = call(&api, "GET", &format!("/v1/proposals/{id}"), Value::Null).await;
    assert_eq!(v["status"], "promoted");
    assert_eq!(v["approval_requests"][0]["pending"], false);
    let (_, v) = call(&api, "GET", "/v1/proposals", Value::Null).await;
    assert_eq!(v["proposals"].as_array().unwrap().len(), 1);
    let (s, v) = call(&api, "GET", "/v1/proposals/p-000000000000", Value::Null).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (404, Some("PROPOSAL_NOT_FOUND"))
    );

    // Rollback, and an unknown epoch.
    let (s, v) = call(
        &api,
        "POST",
        &format!("/v1/deployments/{epoch}/rollback"),
        json!({"reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["deployment"]["epoch"].as_u64().unwrap(), epoch + 1);
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments/99/rollback",
        json!({"reason": "r"}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (404, Some("DEPLOYMENT_NOT_FOUND"))
    );
    let (_, v) = call(&api, "GET", "/v1/deployments", Value::Null).await;
    let causes: Vec<&str> = v["deployments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["cause"].as_str().unwrap())
        .collect();
    assert_eq!(causes.last(), Some(&"rollback"), "{causes:?}");

    let (s, v) = call(&api, "DELETE", "/v1/forks/try", json!({"reason": "r"})).await;
    assert_eq!((s, &v["deleted"]), (200, &json!("try")));
}

/// Review H6 (v0.1): API scrubbing covers the `base64` twin of every
/// payload, not only its `text`: a stored value equal to a Kronik secret is
/// shown as the placeholder in both, in inspect and turn views.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_values_are_scrubbed_from_base64_payloads_too() {
    const SECRET: &str = "hunter2-db-password";
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let api = Arc::new(Api::new(node));
    call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(COUNTER), "reason": "r"}),
    )
    .await;
    call(
        &api,
        "PUT",
        "/v1/secrets/db-password",
        json!({"text": SECRET, "reason": "r"}),
    )
    .await;
    let (_, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "store", "text": SECRET, "reason": "r"}),
    )
    .await;
    let turn = v["turn_id"].as_str().unwrap().to_owned();
    let b64 = base64::engine::general_purpose::STANDARD.encode(SECRET);
    let placeholder = base64::engine::general_purpose::STANDARD.encode("[secret:db-password]");
    for path in [
        "/v1/actors/counter/a".to_owned(),
        format!("/v1/turns/{turn}"),
    ] {
        let (s, v) = call(&api, "GET", &path, Value::Null).await;
        assert_eq!(s, 200, "{path}: {v}");
        let text = v.to_string();
        assert!(!text.contains(SECRET), "{path}: {text}");
        assert!(!text.contains(&b64), "{path}: {text}");
        assert!(text.contains(&placeholder), "{path}: {text}");
    }
}

/// Review M5: audit text is scrubbed when it is written, so secrets deleted
/// before an export reads the log are not in it: the new value of a
/// `secret.set` in its own reason, and stored values in the reasons of a
/// grant and of a `secret.delete`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secret_deleted_before_the_export_is_not_in_the_audit_log() {
    const SECRET: &str = "hunter2-db-password";
    const OTHER: &str = "sk-live-other-9931";
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let api = Arc::new(Api::new(node.clone()));
    for (method, path, body) in [
        (
            "PUT",
            "/v1/secrets/db-password",
            json!({"text": SECRET, "reason": format!("rotate to {SECRET}")}),
        ),
        (
            "PUT",
            "/v1/secrets/other",
            json!({"text": OTHER, "reason": "r"}),
        ),
        (
            "POST",
            "/v1/grants",
            json!({"kind": "counter", "capability": "http:example.com", "reason": format!("key {OTHER}")}),
        ),
        (
            "DELETE",
            "/v1/secrets/other",
            json!({"reason": format!("leaked {OTHER}")}),
        ),
        ("DELETE", "/v1/secrets/db-password", json!({"reason": "r"})),
    ] {
        let (s, v) = call(&api, method, path, body).await;
        assert_eq!(s, 200, "{method} {path}: {v}");
    }
    let mut text = String::new();
    node.reader()
        .read(1, node.applied_lsn(), |c| {
            text.push_str(&format!("{:?}\n", c.record));
            Ok(())
        })
        .await
        .unwrap();
    assert!(text.contains("[secret:other]"), "{text}");
    assert!(!text.contains(SECRET) && !text.contains(OTHER), "{text}");
}

/// Token secrets never reach the log (ADR 0082), and a scrub that cannot
/// load the stored secrets withholds the reason instead of writing it
/// unscrubbed: the reason of a `Grant`, and of an `AuditEvent`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_secrets_are_scrubbed_and_an_unloadable_scrub_withholds_the_reason() {
    const SECRET: &str = "hunter2-db-password";
    let token = format!("kronik_{}", "Ab-_".repeat(10) + "xyz");
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let api = Arc::new(Api::new(node.clone()));
    let grant = |reason: String| json!({"kind": "counter", "capability": "http:example.com", "reason": reason});
    let log = || async {
        let mut text = String::new();
        node.reader()
            .read(1, node.applied_lsn(), |c| {
                text.push_str(&format!("{:?}\n", c.record));
                Ok(())
            })
            .await
            .unwrap();
        text
    };
    for (method, path, body) in [
        ("POST", "/v1/grants", grant(format!("leaked {token}"))),
        (
            "PUT",
            "/v1/secrets/db-password",
            json!({"text": SECRET, "reason": format!("was {token}")}),
        ),
    ] {
        let (s, v) = call(&api, method, path, body).await;
        assert_eq!(s, 200, "{method} {path}: {v}");
    }
    let text = log().await;
    assert!(!text.contains(&token), "{text}");
    assert_eq!(text.matches("[token]").count(), 2, "{text}");

    // One undecryptable row: the stored values cannot be loaded.
    rusqlite::Connection::open(dir.path().join("keys/secrets.db"))
        .unwrap()
        .execute("UPDATE secrets SET ciphertext = x'00'", [])
        .unwrap();
    for (method, path, body) in [
        ("POST", "/v1/grants", grant(format!("key {SECRET}"))),
        (
            "PUT",
            "/v1/secrets/other",
            json!({"text": "v", "reason": format!("key {SECRET}")}),
        ),
    ] {
        let (s, v) = call(&api, method, path, body).await;
        assert_eq!(s, 200, "{method} {path}: {v}");
    }
    let text = log().await;
    assert!(!text.contains(SECRET), "{text}");
    // The grant's reason and the secret.set event's reason; the event's
    // target (the secret's name) stays, so the line says what changed.
    assert_eq!(
        text.matches(kronik_sched::scrub::WITHHELD).count(),
        2,
        "{text}"
    );
    assert!(
        text.contains("\"other\""),
        "the target was withheld: {text}"
    );
}

/// Re-review #6 (v0.1): with privacy mode on, a subject's failed turn after
/// a successful call leaves an orphan that still names the callee's turn
/// (the sealed reply is not read; the callee's delivery gives it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_orphan_of_a_sealed_call_keeps_the_callee_turn() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let api = Arc::new(Api::new(node));
    call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(COUNTER), "reason": "r"}),
    )
    .await;
    let (s, v) = call(
        &api,
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (_, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "call-fail", "text": "counter/b increment", "subject": "user:1", "reason": "r"}),
    )
    .await;
    assert_eq!(v["outcome"]["kind"], "failed", "{v}");
    let (_, v) = call(&api, "GET", "/v1/orphans", Value::Null).await;
    let turn = v["orphans"][0]["turn_id"].as_str().unwrap_or_default();
    assert!(turn.starts_with("main:"), "{v}");
}
