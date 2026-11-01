//! Read-time I8 redaction of retained data through the actual API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_sched::{NodeConfig, start_local};
use serde_json::{Value, json};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

async fn call(api: &Api, method: &str, path: &str, body: Value) -> Value {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let response = api
        .handle(ApiRequest {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            body: if body.is_null() {
                Vec::new()
            } else {
                serde_json::to_vec(&body).unwrap()
            },
            token_id: "unix:uid=0".into(),
            bearer: None,
        })
        .await;
    let value: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response.status, 200, "{method} {path}: {value}");
    value
}

fn decoded(value: &Value) -> Vec<u8> {
    STANDARD.decode(value["base64"].as_str().unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_free_data_is_scrubbed_without_corrupting_typed_api_fields() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let api = Api::new(node);

    call(
        &api,
        "POST",
        "/v1/deployments",
        json!({
            "wasm_base64": STANDARD.encode(std::fs::read(COUNTER).unwrap()),
            "reason": "install fixture"
        }),
    )
    .await;

    let original = b"a|true|false|null|7|\xce\xbb|\xff|secret";
    let sent = call(
        &api,
        "POST",
        "/v1/actors/counter/a7/messages",
        json!({
            "name": "store",
            "base64": STANDARD.encode(original),
            "reason": "retain original bytes"
        }),
    )
    .await;
    let turn_id = sent["turn_id"].as_str().unwrap().to_owned();
    assert_eq!(sent["outcome"]["kind"], "committed");

    for (name, bytes) in [
        ("letter", b"a".as_slice()),
        ("yes", b"true".as_slice()),
        ("no", b"false".as_slice()),
        ("nil", b"null".as_slice()),
        ("digit", b"7".as_slice()),
        ("utf8", "λ".as_bytes()),
        ("binary", b"\xff".as_slice()),
        ("word", b"secret".as_slice()),
    ] {
        call(
            &api,
            "PUT",
            &format!("/v1/secrets/{name}"),
            json!({
                "base64": STANDARD.encode(bytes),
                "reason": "register scrub value"
            }),
        )
        .await;
    }

    // The old byte remains required by retained state/turn data.
    call(
        &api,
        "PUT",
        "/v1/secrets/letter",
        json!({"text": "z", "reason": "rotate fixture"}),
    )
    .await;

    let expected = b"[secret:letter]|[secret:yes]|[secret:no]|[secret:nil]|\
          [secret:digit]|[secret:utf8]|[secret:binary]|[secret:word]";

    // Deletion must not remove scrub coverage for retained data.
    for delete_digit in [false, true] {
        if delete_digit {
            call(
                &api,
                "DELETE",
                "/v1/secrets/digit",
                json!({"reason": "delete operational fixture"}),
            )
            .await;
        }

        let inspect = call(&api, "GET", "/v1/actors/counter/a7", Value::Null).await;
        assert_eq!(inspect["actor"]["kind"], "counter");
        assert_eq!(inspect["actor"]["key"], "a7");
        assert_eq!(inspect["actor"]["last_turn_id"], turn_id);
        let stored = inspect["state"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["key"] == "stored")
            .unwrap();
        assert_eq!(decoded(stored), expected);

        let turn = call(&api, "GET", &format!("/v1/turns/{turn_id}"), Value::Null).await;
        assert_eq!(turn["turn_id"], turn_id);
        assert_eq!(turn["actor"], "counter/a7");
        assert_eq!(turn["input"]["type"], "message");
        assert_eq!(turn["outcome"]["kind"], "committed");
        assert_eq!(decoded(&turn["input"]["msg"]["body"]["value"]), expected);
        let stored_write = turn["writes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["key"] == "stored")
            .unwrap();
        assert_eq!(stored_write["op"], "set");
        assert_eq!(decoded(&stored_write["value"]["value"]), expected);

        let history = call(&api, "GET", "/v1/actors/counter/a7/history", Value::Null).await;
        let summary = history["turns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["turn_id"] == turn_id)
            .unwrap();
        assert_eq!(summary["lsn"], turn["lsn"]);
        assert_eq!(summary["code_hash"], turn["code_hash"]);
        assert_eq!(summary["input"]["type"], "message");
        assert_eq!(summary["outcome"]["kind"], "committed");

        let trace = call(
            &api,
            "GET",
            &format!("/v1/turns/{turn_id}/trace"),
            Value::Null,
        )
        .await;
        assert_eq!(trace["turn"]["turn_id"], turn_id);
        assert_eq!(trace["actor"], "counter/a7");
        assert_eq!(trace["root"]["root_id"], turn["causal_key"]["root"]);
        assert_eq!(trace["turn"]["outcome"]["kind"], "committed");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persisted_audit_reasons_withhold_ambiguous_markers_and_later_secret_matches() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let mut tokens =
        kronik_api::tokens::TokenStore::open_file(&dir.path().join("tokens.db")).unwrap();
    tokens
        .bind_before_any_issuer(node.publication_domain())
        .unwrap();
    let tokens = std::sync::Arc::new(tokens);
    let api = Api::new(node.clone()).with_tokens(tokens.clone()).unwrap();
    call(
        &api,
        "PUT",
        "/v1/secrets/short",
        json!({"base64": STANDARD.encode(b"a"), "reason": "register value"}),
    )
    .await;
    call(
        &api,
        "PUT",
        "/v1/secrets/candidate",
        json!({"base64": STANDARD.encode(b"new-needle"), "reason": "prefix|new-needle|suffix"}),
    )
    .await;
    let original = node.secret_history("candidate").await.unwrap();
    let audit = original[0].audit.as_ref().unwrap();
    assert_eq!(audit.reason, "prefix|[secret:candidate]|suffix");
    let mut admitted_phases = Vec::new();
    node.reader()
        .read(1, node.applied_lsn(), |committed| {
            if let kronik_proto::Record::SecretVersion(version) = &committed.record
                && version.name == "candidate"
            {
                admitted_phases.push((version.phase, version.audit.clone().unwrap()));
            }
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        admitted_phases,
        vec![
            (
                kronik_proto::log::v1::secret_version::Phase::Reserved as i32,
                audit.clone()
            ),
            (
                kronik_proto::log::v1::secret_version::Phase::Active as i32,
                audit.clone()
            ),
        ]
    );
    let before_read = node.applied_lsn();
    let view = call(&api, "GET", "/v1/secrets/candidate/history", Value::Null).await;
    let version = &view["versions"][0];
    assert_eq!(version["reason"], kronik_sched::scrub::WITHHELD);
    assert_eq!(version["version"], original[0].version);
    assert_eq!(
        version["version_hash"],
        kronik_core::ids::hex(&original[0].version_hash)
    );
    assert_eq!(version["token_id"], audit.token_id);
    assert_eq!(version["created_wall_ms"], audit.wall_time_ms);
    assert_eq!(node.applied_lsn(), before_read);
    assert_eq!(node.secret_history("candidate").await.unwrap(), original);

    call(
        &api,
        "PUT",
        "/v1/secrets/seed",
        json!({"base64": STANDARD.encode(b"zz-secret"), "reason": "old-note"}),
    )
    .await;
    let original = node.secret_history("seed").await.unwrap();
    assert_eq!(original[0].audit.as_ref().unwrap().reason, "old-note");
    let clear = call(&api, "GET", "/v1/secrets/seed/history", Value::Null).await;
    assert_eq!(clear["versions"][0]["reason"], "old-note");
    call(
        &api,
        "POST",
        "/v1/tokens",
        json!({"name": "observer", "scopes": ["read"], "reason": "old-note"}),
    )
    .await;
    let clear_tokens = call(&api, "GET", "/v1/tokens", Value::Null).await;
    assert_eq!(clear_tokens["tokens"][0]["reason"], "old-note");
    call(
        &api,
        "PUT",
        "/v1/secrets/later",
        json!({"base64": STANDARD.encode(b"old-note"), "reason": "register value"}),
    )
    .await;
    let before_read = node.applied_lsn();
    let protected = call(&api, "GET", "/v1/secrets/seed/history", Value::Null).await;
    let mut expected = clear;
    expected["versions"][0]["reason"] = json!(kronik_sched::scrub::WITHHELD);
    assert_eq!(protected, expected);
    let protected_tokens = call(&api, "GET", "/v1/tokens", Value::Null).await;
    let mut expected_tokens = clear_tokens;
    expected_tokens["tokens"][0]["reason"] = json!(kronik_sched::scrub::WITHHELD);
    assert_eq!(protected_tokens, expected_tokens);
    assert_eq!(tokens.list().unwrap()[0].reason, "old-note");
    assert_eq!(node.applied_lsn(), before_read);
    assert_eq!(node.secret_history("seed").await.unwrap(), original);
}
