//! M23, criterion 3 (docs/design/m23-secret-backends.md §5.2): rotating a
//! secret shows up as a new version in an actor's `history`, and the turns
//! before the rotation keep the version they used. Each effect that used a
//! secret names it (`secrets`: name, version and the first 8 hex characters
//! of the version hash, never a value), also in the turn JSON and in a trace,
//! and a request sealed for a data subject, or erased with it, shows none.
//!
//! The effects run for real on a node with the built-in secret store:
//! `crypto.hmac-sha256`, `secret.reveal` and an `http.fetch` with a secret
//! header, made by the counter test guest. The erasure of a subject, with real
//! keys, is a unit test of `kronik-api` (`sealed_request_secrets_...`).

// Test helpers outside #[test] functions may unwrap too, and the HTTP target
// is a harness thread.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use base64::Engine as _;
use kronik_api::auth::{Authenticator, Caller, Scope};
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_core::error::ApiError;
use kronik_sched::{Node, NodeConfig, start_local};
use serde_json::{Value, json};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

const FIRST: &str = "first-value-1111";
const SECOND: &str = "second-value-2222";
const THIRD: &str = "third-value-3333";

/// A caller with `read` only: no `pii:read`, no `operate`.
struct Reader(Arc<Node>);

impl Authenticator for Reader {
    fn caller(&self, _req: &ApiRequest) -> Result<Caller, ApiError> {
        Ok(Caller {
            token_id: "token:reader".into(),
            scopes: BTreeSet::from([Scope::Read]),
        })
    }

    fn authority(
        &self,
        _req: &ApiRequest,
        _required: Scope,
    ) -> Result<kronik_core::authority::AuthLease, ApiError> {
        self.0.local_operator_authority()
    }
}

async fn call(api: &Api, method: &str, path: &str, body: Value) -> Value {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    // The secret-coverage window of a rotation answers 503 SECRET_UNAVAILABLE
    // for a moment (ADR 0108); a bounded retry is what a client does.
    for _ in 0..200 {
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
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        if r.status == 200 {
            return v;
        }
        assert_eq!(
            v["error"]["code"], "SECRET_UNAVAILABLE",
            "{method} {path}: {v}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("{method} {path}: SECRET_UNAVAILABLE did not clear");
}

/// A GET as a caller with the `read` scope only.
async fn read_only(api: &Api, path: &str) -> Value {
    let r = api
        .handle(ApiRequest {
            method: "GET".into(),
            path: path.into(),
            query: String::new(),
            body: Vec::new(),
            token_id: "token:reader".into(),
            bearer: Some("not-checked-by-the-test-authenticator".into()),
        })
        .await;
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(r.status, 200, "GET {path}: {v}");
    v
}

/// A plain HTTP server on a free port that answers every request with 200
/// and the body `pong`, until the test process exits. Returns its address.
fn http_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
            );
        }
    });
    addr
}

/// A node with the counter deployed and the grants its effects need.
async fn node_with_grants(dir: &std::path::Path) -> (Api, Arc<Node>) {
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir,
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let api = Api::new(node.clone());
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(COUNTER).unwrap());
    call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "deploy"}),
    )
    .await;
    for capability in ["http:127.0.0.1", "secret:signing", "secret-reveal:signing"] {
        call(
            &api,
            "POST",
            "/v1/grants",
            json!({"kind": "counter", "capability": capability, "reason": "grant"}),
        )
        .await;
    }
    (api, node)
}

async fn set_secret(api: &Api, value: &str) -> Value {
    let v = call(
        api,
        "PUT",
        "/v1/secrets/signing",
        json!({"text": value, "reason": "rotate"}),
    )
    .await;
    v["secret"].clone()
}

/// Sends `name` to `counter/a` and returns the turn id.
async fn send(api: &Api, name: &str, text: &str, subject: Option<&str>) -> String {
    let v = call(
        api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": name, "text": text, "subject": subject, "reason": "test"}),
    )
    .await;
    assert_eq!(v["outcome"]["kind"], "committed", "{name}: {v}");
    v["turn_id"].as_str().unwrap().to_owned()
}

/// `fetch-ok`: a POST with the secret in a header, to `target`.
async fn send_fetch(api: &Api, target: &str, subject: Option<&str>) -> String {
    let spec = format!("POST http://{target}/hook\nS x-signature signing {{}}\n\nbody");
    let turn = send(api, "fetch-ok", &spec, subject).await;
    let v = call(api, "GET", &format!("/v1/turns/{turn}"), Value::Null).await;
    assert_eq!(v["effects"][0]["kind"], "http.fetch", "{v}");
    assert_eq!(v["effects"][0]["status"], "ok", "{v}");
    turn
}

/// The summary of `turn` in an actor's history.
fn history_turn(history: &Value, turn: &str) -> Value {
    history["turns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["turn_id"] == turn)
        .unwrap_or_else(|| panic!("{turn} is not in {history}"))
        .clone()
}

fn secrets_of(effect: &Value) -> Value {
    effect.get("secrets").cloned().unwrap_or(Value::Null)
}

fn hash8(secret: &Value) -> String {
    secret["version_hash"].as_str().unwrap()[..8].to_owned()
}

fn used(version: u64, hash8: &str) -> Value {
    json!([{"name": "signing", "version": version, "version_hash": hash8}])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rotation_shows_as_a_new_version_in_history_and_old_turns_keep_theirs() {
    let dir = tempfile::tempdir().unwrap();
    let (api, _node) = node_with_grants(dir.path()).await;
    let target = http_target();

    // Version 1 is used by an HMAC, a reveal and a fetch with a secret header.
    let v1 = set_secret(&api, FIRST).await;
    assert_eq!(v1["version"], 1);
    let hash1 = hash8(&v1);
    let hmac1 = send(&api, "hmac", "signing\npayload", None).await;
    let reveal1 = send(&api, "reveal", "signing", None).await;
    let fetch1 = send_fetch(&api, &target, None).await;

    // The rotation: version 2.
    let v2 = set_secret(&api, SECOND).await;
    assert_eq!(v2["version"], 2);
    let hash2 = hash8(&v2);
    assert_ne!(hash1, hash2);
    let hmac2 = send(&api, "hmac", "signing\npayload", None).await;
    let fetch2 = send_fetch(&api, &target, None).await;
    // A turn that uses no secret has no `secrets`.
    let plain2 = send(&api, "increment", "", None).await;

    let history = call(&api, "GET", "/v1/actors/counter/a/history", Value::Null).await;
    let effect_of = |turn: &str| history_turn(&history, turn)["effects"][0].clone();
    for (turn, kind, version, hash) in [
        (&hmac1, "crypto.hmac-sha256", 1, &hash1),
        (&reveal1, "secret.reveal", 1, &hash1),
        (&fetch1, "http.fetch", 1, &hash1),
        (&hmac2, "crypto.hmac-sha256", 2, &hash2),
        (&fetch2, "http.fetch", 2, &hash2),
    ] {
        let effect = effect_of(turn);
        assert_eq!(effect["kind"], kind, "{turn}: {effect}");
        assert_eq!(
            secrets_of(&effect),
            used(version, hash),
            "{turn} ({kind}): {effect}"
        );
    }
    assert!(
        history_turn(&history, &plain2)["effects"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    // The fetch's request line is still there, next to its secret.
    assert!(
        effect_of(&fetch1)["request"]
            .as_str()
            .unwrap()
            .starts_with("POST 127.0.0.1:")
    );

    // A further rotation changes nothing about the turns that are over.
    let v3 = set_secret(&api, THIRD).await;
    assert_eq!(v3["version"], 3);
    let hmac3 = send(&api, "hmac", "signing\npayload", None).await;
    let after = call(&api, "GET", "/v1/actors/counter/a/history", Value::Null).await;
    for (turn, version, hash) in [
        (&hmac1, 1, &hash1),
        (&fetch1, 1, &hash1),
        (&hmac2, 2, &hash2),
        (&fetch2, 2, &hash2),
        (&hmac3, 3, &hash8(&v3)),
    ] {
        assert_eq!(
            secrets_of(&history_turn(&after, turn)["effects"][0]),
            used(version, hash),
            "{turn}"
        );
    }
    for turn in [&hmac1, &reveal1, &fetch1, &hmac2, &fetch2] {
        assert_eq!(
            history_turn(&after, turn),
            history_turn(&history, turn),
            "the summary of {turn} did not change with the rotation"
        );
    }

    // The same names, versions and hash prefixes as `secret history` and
    // `secret list` show for the versions, and the turn JSON and a trace
    // agree with the history.
    let versions = call(&api, "GET", "/v1/secrets/signing/history", Value::Null).await;
    let full: Vec<(u64, String)> = versions["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["version"].as_u64().unwrap(),
                v["version_hash"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    for (version, hash) in [(1, &hash1), (2, &hash2)] {
        let row = full.iter().find(|(v, _)| *v == version).unwrap();
        assert_eq!(row.1.len(), 32, "{full:?}");
        assert!(row.1.starts_with(hash.as_str()), "{full:?}");
    }
    let listed = call(&api, "GET", "/v1/secrets", Value::Null).await;
    assert_eq!(listed["secrets"][0]["version"], 3);
    for (turn, version, hash) in [(&hmac1, 1, &hash1), (&hmac2, 2, &hash2)] {
        let json = call(&api, "GET", &format!("/v1/turns/{turn}"), Value::Null).await;
        assert_eq!(
            secrets_of(&json["effects"][0]),
            used(version, hash),
            "{turn}"
        );
        let trace = call(&api, "GET", &format!("/v1/turns/{turn}/trace"), Value::Null).await;
        assert_eq!(
            secrets_of(&trace["turn"]["effects"][0]),
            used(version, hash),
            "trace of {turn}"
        );
    }

    // A secret is a handle: no response holds a value.
    for response in [&history, &after, &versions, &listed] {
        let text = response.to_string();
        for value in [FIRST, SECOND, THIRD] {
            assert!(!text.contains(value), "{value} is in {text}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_sealed_for_a_data_subject_shows_no_secrets_to_a_caller_who_may_not_read_it() {
    let dir = tempfile::tempdir().unwrap();
    let (api, node) = node_with_grants(dir.path()).await;
    let target = http_target();
    let v1 = set_secret(&api, FIRST).await;
    let hash1 = hash8(&v1);
    call(
        &api,
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "seal"}),
    )
    .await;

    // The same fetch with a secret header for nobody and for a subject: the
    // subject's request is sealed in the log.
    let open = send_fetch(&api, &target, None).await;
    let sealed = send_fetch(&api, &target, Some("user:1")).await;

    let reader = Api::new(node.clone()).with_authenticator(Arc::new(Reader(node)));
    let check = |history: Value, who: &str| {
        let open_effect = history_turn(&history, &open)["effects"][0].clone();
        assert_eq!(
            secrets_of(&open_effect),
            used(1, &hash1),
            "{who}: {open_effect}"
        );
        assert!(open_effect["request"].is_string(), "{who}: {open_effect}");
        // Sealed: neither the request line nor the secrets, like `request`.
        let sealed_effect = history_turn(&history, &sealed)["effects"][0].clone();
        assert!(
            sealed_effect.get("request").is_none(),
            "{who}: {sealed_effect}"
        );
        assert!(
            sealed_effect.get("secrets").is_none(),
            "{who}: {sealed_effect}"
        );
        assert_eq!(sealed_effect["kind"], "http.fetch");
    };
    check(
        call(&api, "GET", "/v1/actors/counter/a/history", Value::Null).await,
        "operator",
    );
    check(
        read_only(&reader, "/v1/actors/counter/a/history").await,
        "reader",
    );

    // The turn JSON: a caller without pii:read gets the `[sealed]` request
    // and no secrets; one with pii:read, who may open it, gets them.
    let turn = format!("/v1/turns/{sealed}");
    let without = read_only(&reader, &turn).await;
    assert!(without["effects"][0].get("secrets").is_none(), "{without}");
    let with = call(&api, "GET", &turn, Value::Null).await;
    assert_eq!(secrets_of(&with["effects"][0]), used(1, &hash1), "{with}");
    let trace = format!("{turn}/trace");
    let without = read_only(&reader, &trace).await;
    assert!(
        without["turn"]["effects"][0].get("secrets").is_none(),
        "{without}"
    );
    let with = call(&api, "GET", &trace, Value::Null).await;
    assert_eq!(
        secrets_of(&with["turn"]["effects"][0]),
        used(1, &hash1),
        "{with}"
    );
}
