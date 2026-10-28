//! Reseal (docs/design/m8-privacy.md §8): history written in `off` is sealed
//! once the mode is on, an identity replay of the rewritten log is empty,
//! and a dry run writes nothing.

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

fn wasm() -> String {
    base64::engine::general_purpose::STANDARD.encode(std::fs::read(COUNTER).unwrap())
}

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

fn closed_segments(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let log = dir.join("branches/main/log");
    let mut files: Vec<_> = std::fs::read_dir(&log)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "seg"))
        .collect();
    files.sort();
    files.pop();
    files
}

fn contains_personal(files: &[std::path::PathBuf]) -> bool {
    files.iter().any(|p| {
        std::fs::read(p)
            .unwrap()
            .windows(b"personal".len())
            .any(|w| w == b"personal")
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reseal_seals_off_mode_history_and_an_identity_replay_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let mut storage = kronik_sched::snapshots::StorageConfig::new(dir.path().to_path_buf());
    storage.history = std::time::Duration::from_millis(u64::MAX);
    let node = start_local(
        env,
        dir.path(),
        NodeConfig {
            segment_max_bytes: Some(1),
            storage: Some(storage),
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    let proposals =
        kronik_fork::proposal::Proposals::open(node.clone(), dir.path().to_path_buf()).unwrap();
    let api = Arc::new(Api::new(node).with_proposals(Arc::new(proposals)));

    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(), "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    // Tagged values, written while the mode is off.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "subject", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    // Closes the segment that holds those values.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "increment", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");

    let (s, v) = call(
        &api,
        "POST",
        "/v1/privacy/reseal",
        json!({"reason": " ", "dry_run": true}),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("REASON_REQUIRED")),
        "{v}"
    );
    let (s, v) = call(
        &api,
        "POST",
        "/v1/privacy/reseal",
        json!({"reason": "seal history"}),
    )
    .await;
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["error"]["code"], "BAD_REQUEST");
    assert!(
        v["error"]["hint"]
            .as_str()
            .unwrap_or("")
            .contains("privacy mode on"),
        "{v}"
    );

    let (s, v) = call(
        &api,
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "seal history"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");

    let before = closed_segments(dir.path());
    assert!(
        contains_personal(&before),
        "off-mode history should still be plain"
    );
    let before_bytes: Vec<_> = before.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let (s, dry) = call(
        &api,
        "POST",
        "/v1/privacy/reseal",
        json!({"reason": "seal history", "dry_run": true}),
    )
    .await;
    assert_eq!(s, 200, "{dry}");
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["started"], false);
    assert!(dry["segments"].as_u64().unwrap() >= 1, "{dry}");
    let after_dry: Vec<_> = closed_segments(dir.path())
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    assert_eq!(before_bytes, after_dry, "a dry run writes nothing");

    let (s, done) = call(
        &api,
        "POST",
        "/v1/privacy/reseal",
        json!({"reason": "seal history"}),
    )
    .await;
    assert_eq!(s, 200, "{done}");
    assert_eq!(done["dry_run"], false);
    assert_eq!(done["started"], true);
    assert!(done["segments"].as_u64().unwrap() >= 1, "{done}");
    let sealed = closed_segments(dir.path());
    assert!(
        !contains_personal(&sealed),
        "a rewritten segment still holds the tagged plaintext"
    );

    let (s, again) = call(
        &api,
        "POST",
        "/v1/privacy/reseal",
        json!({"reason": "seal history"}),
    )
    .await;
    assert_eq!(s, 200, "{again}");
    assert_eq!(again["started"], false);
    assert_eq!(again["segments"], 0, "a second reseal rewrites nothing");

    let status = call(&api, "GET", "/v1/privacy", Value::Null).await.1;
    assert_eq!(status["mode"], "on");
    assert!(
        status["reseal"]["segments_done"].as_u64().unwrap() >= 1,
        "{status}"
    );
    assert!(status.get("pending_erasures").is_some(), "{status}");

    let (s, fork) = call(
        &api,
        "POST",
        "/v1/forks",
        json!({"at": 1, "reason": "identity after reseal"}),
    )
    .await;
    assert_eq!(s, 200, "{fork}");
    let name = fork["fork"]["name"].as_str().unwrap();
    let (s, replay) = call(
        &api,
        "POST",
        &format!("/v1/forks/{name}/replay"),
        json!({"mode": "both", "reason": "identity after reseal"}),
    )
    .await;
    assert_eq!(s, 200, "{replay}");
    assert_eq!(
        replay["summary"]["changed"], false,
        "identity replay differs: {replay}"
    );
}

/// v0.1 review H9: reseal also seals what `state.db` keeps of the rewritten
/// records, here a dead letter written in `off` mode, and leaves no plain
/// copy in `state.db`'s files.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reseal_seals_dead_letters_in_state_db() {
    const MARK: &str = "DEADPLAIN-zq81";
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let mut storage = kronik_sched::snapshots::StorageConfig::new(dir.path().to_path_buf());
    storage.history = std::time::Duration::from_millis(u64::MAX);
    let node = start_local(
        env,
        dir.path(),
        NodeConfig {
            segment_max_bytes: Some(1),
            storage: Some(storage),
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    let api = Api::new(node.clone());
    let (s, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm(), "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    // A failing message of a subject in `off` mode: a plain dead letter.
    call(
        &api,
        "POST",
        "/v1/actors/counter/d/messages",
        json!({"name": "fail", "text": MARK, "subject": "user:7", "reason": "r"}),
    )
    .await;
    // Closes the segment that holds it.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/d/messages",
        json!({"name": "increment", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let body = |node: &kronik_sched::Node| {
        let dl = node.store().db().dead_letters(0, 10).unwrap();
        assert_eq!(dl.len(), 1, "{dl:?}");
        match dl[0].input.kind.clone() {
            Some(kronik_proto::log::v1::input::Kind::Message(m)) => m.msg.unwrap().body.unwrap(),
            other => panic!("not a message: {other:?}"),
        }
    };
    assert!(matches!(
        body(&node).value,
        Some(kronik_proto::log::v1::sealable::Value::Plain(_))
    ));
    for (path, req) in [
        (
            "/v1/privacy/mode",
            json!({"mode": "on", "reason": "seal history"}),
        ),
        ("/v1/privacy/reseal", json!({"reason": "seal history"})),
    ] {
        let (s, v) = call(&api, "POST", path, req).await;
        assert_eq!(s, 200, "{v}");
    }
    let b = body(&node);
    assert_eq!(b.subject.as_deref(), Some("user:7"));
    assert!(
        matches!(
            b.value,
            Some(kronik_proto::log::v1::sealable::Value::Sealed(_))
        ),
        "the dead letter's input is still plain: {b:?}"
    );
    for f in ["state.db", "state.db-wal"] {
        let bytes = std::fs::read(dir.path().join("branches/main").join(f)).unwrap_or_default();
        assert!(
            !bytes.windows(MARK.len()).any(|w| w == MARK.as_bytes()),
            "{f} still holds the plain dead letter"
        );
    }
}
