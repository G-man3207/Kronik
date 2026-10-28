//! `/v1/simulators` and the simulator labels in `trace`
//! (docs/design/m12-simulators.md §6, §7).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
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

/// An HTTP server answering 200 "ok" to everything.
fn server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 {
                    break;
                }
                let h = h.trim_end().to_ascii_lowercase();
                if h.is_empty() {
                    break;
                }
                if let Some(v) = h.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; len];
            let _ = r.read_exact(&mut body);
            let _ =
                w.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trace_shows_simulator_labels() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let proposals =
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf()).unwrap();
    let api = Arc::new(Api::new(node.clone()).with_proposals(Arc::new(proposals)));
    let addr = server();
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
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "http:127.0.0.1", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let at = node.applied_lsn();
    for i in 0..2 {
        let (s, v) = call(
            &api,
            "POST",
            "/v1/actors/counter/pay/messages",
            json!({"name": "fetch-ok", "text": format!("POST http://{addr}/v1/charges/{i}\n\namount=1"),
                   "reason": "r"}),
        )
        .await;
        assert_eq!(s, 200, "{v}");
    }

    // Nothing configured yet.
    let (s, v) = call(&api, "GET", "/v1/simulators", Value::Null).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["targets"], json!([]));
    assert_eq!(v["model"]["configured"], false);
    let names: Vec<&str> = v["simulators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "recorded",
            "stub",
            "contract",
            "neighbor",
            "model",
            "fail-closed",
            "placeholder"
        ]
    );

    // Validation: a stub on another host, a contract that is not OpenAPI.
    let path = "/v1/simulators/http:127.0.0.1";
    let (s, v) = call(
        &api,
        "PUT",
        path,
        json!({"stubs": [{"url_prefix": "https://example.com/", "body": "x"}], "reason": "r"}),
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
        path,
        json!({"contract": {"a": 1}, "reason": "r"}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("BAD_REQUEST")),
        "{v}"
    );
    let (s, v) = call(&api, "PUT", path, json!({"neighbor": true})).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("REASON_REQUIRED")),
        "{v}"
    );

    // A dry run writes nothing.
    let contract = json!({
        "openapi": "3.0.3",
        "info": {"title": "Charges", "version": "1"},
        "paths": {"/v1/charges/{id}/extra": {"get": {"responses": {"200": {
            "description": "ok",
            "content": {"application/json": {"schema": {"type": "object",
                "required": ["ok"], "properties": {"ok": {"type": "boolean"}}}}}}}}}}
    });
    let (s, v) = call(
        &api,
        "PUT",
        path,
        json!({"contract": contract, "reason": "fake charges", "dry_run": true}),
    )
    .await;
    assert_eq!(
        (s, &v["dry_run"], &v["lsn"]),
        (200, &json!(true), &json!(0)),
        "{v}"
    );
    let (_, v) = call(&api, "GET", "/v1/simulators", Value::Null).await;
    assert_eq!(v["targets"], json!([]));

    let (s, v) = call(
        &api,
        "PUT",
        path,
        json!({"contract": contract, "reason": "fake charges"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(v["lsn"].as_u64().unwrap() > 0, "{v}");
    let (_, v) = call(&api, "GET", "/v1/simulators", Value::Null).await;
    let t = &v["targets"][0];
    assert_eq!(
        (
            &t["target"],
            &t["contract"]["title"],
            &t["reason"],
            &t["stubs"]
        ),
        (
            &json!("http:127.0.0.1"),
            &json!("Charges"),
            &json!("fake charges"),
            &json!(0)
        ),
        "{v}"
    );

    // A fork of the fetch-extra build: its extra GETs are answered by the
    // contract, and trace says so.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks",
        json!({"at": at, "name": "try", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks/try/deployments",
        json!({"wasm_base64": wasm("counter-fetch-extra"), "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    // The contract was set after the fork point (I5): the fork fails closed.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks/try/replay",
        json!({"reason": "r", "threads": 2}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (_, d) = call(&api, "GET", "/v1/forks/try/diff", Value::Null).await;
    assert_eq!(
        d["summary"]["synthetic_by"],
        json!({"fail-closed": 2}),
        "{d}"
    );
    // An override in the replay request: invalid ones are refused, a valid
    // one applies.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks/try/replay",
        json!({"reason": "r", "threads": 2,
               "simulator_overrides": [{"target": "http:127.0.0.1", "contract": {"a": 1}}]}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("BAD_REQUEST")),
        "{v}"
    );
    let (s, v) = call(
        &api,
        "POST",
        "/v1/forks/try/replay",
        json!({"reason": "r", "threads": 2,
               "simulator_overrides": [{"target": "http:127.0.0.1", "contract": contract}]}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (_, d) = call(&api, "GET", "/v1/forks/try/diff", Value::Null).await;
    assert_eq!(d["summary"]["synthetic_by"], json!({"contract": 2}), "{d}");
    let turn = d["effects"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["grounding"] == "synthetic" && e["simulator"] == "contract")
        .and_then(|e| e["turn_fork"].as_str())
        .unwrap()
        .to_owned();
    let (s, t) = call(&api, "GET", &format!("/v1/turns/{turn}/trace"), Value::Null).await;
    assert_eq!(s, 200, "{t}");
    let groundings: Vec<(&Value, &Value)> = t["turn"]["effects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (&e["grounding"], &e["simulator"]))
        .collect();
    assert_eq!(
        groundings,
        [
            (&json!("exact"), &Value::Null),
            (&json!("synthetic"), &json!("contract"))
        ],
        "{t}"
    );
    // Production turns carry no grounding.
    let (_, h) = call(&api, "GET", "/v1/actors/counter/pay/history", Value::Null).await;
    let effects = h["turns"][0]["effects"].as_array().unwrap();
    assert!(!effects.is_empty(), "{h}");
    assert!(effects.iter().all(|e| e.get("grounding").is_none()), "{h}");
}
