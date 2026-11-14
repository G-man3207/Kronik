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

    // The fork point after the deployments and before the privacy work. A
    // fresh log now starts with a SecretVersion record and a startup
    // AuditEvent, so the counter deployment is not at lsn 1.
    let setup = call(&api, "GET", "/v1/health", Value::Null).await.1["applied_lsn"]
        .as_u64()
        .unwrap();

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
        json!({"at": setup, "reason": "identity after reseal"}),
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

/// The real clock, moved forward by a test: `wall_ms` and `monotonic` gain
/// `offset` (ms), and a sleep that a move ends returns within 20 ms. A timer
/// set an hour ahead then fires when the test says so, not when a loaded
/// machine happens to get there.
struct SteppedClock {
    inner: Arc<dyn kronik_core::env::Clock>,
    offset: Arc<std::sync::atomic::AtomicU64>,
}

impl kronik_core::env::Clock for SteppedClock {
    fn wall_ms(&self) -> u64 {
        self.inner.wall_ms() + self.offset.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn monotonic(&self) -> std::time::Duration {
        self.inner.monotonic()
            + std::time::Duration::from_millis(
                self.offset.load(std::sync::atomic::Ordering::SeqCst),
            )
    }

    fn sleep(&self, d: std::time::Duration) -> kronik_core::env::BoxFuture<'static, ()> {
        let inner = self.inner.clone();
        let offset = self.offset.clone();
        let now = move || {
            inner.monotonic()
                + std::time::Duration::from_millis(offset.load(std::sync::atomic::Ordering::SeqCst))
        };
        let target = now() + d;
        let real = self.inner.clone();
        Box::pin(async move {
            loop {
                let left = target.saturating_sub(now());
                if left.is_zero() {
                    return;
                }
                real.sleep(left.min(std::time::Duration::from_millis(20)))
                    .await;
            }
        })
    }
}

/// A node with closed segments after every record, snapshots and a
/// deployed counter, behind the API, on a [`SteppedClock`]: the offset
/// moves it forward.
async fn stepped_counter_node(
    dir: &std::path::Path,
) -> (
    Arc<kronik_sched::Node>,
    Api,
    Arc<std::sync::atomic::AtomicU64>,
) {
    let mut env = Env::real(tokio::runtime::Handle::current());
    let offset = Arc::new(std::sync::atomic::AtomicU64::new(0));
    env.clock = Arc::new(SteppedClock {
        inner: env.clock.clone(),
        offset: offset.clone(),
    });
    let (node, api) = counter_node_with(dir, env).await;
    (node, api, offset)
}

/// An hour: the delay of the tests' timers, which only a step of the clock
/// reaches.
const TIMER_DELAY_MS: u64 = 3_600_000;

/// Moves the clock past the tests' timers.
fn fire_timers(offset: &std::sync::atomic::AtomicU64) {
    offset.fetch_add(TIMER_DELAY_MS + 1_000, std::sync::atomic::Ordering::SeqCst);
}

async fn counter_node_with(dir: &std::path::Path, env: Env) -> (Arc<kronik_sched::Node>, Api) {
    let mut storage = kronik_sched::snapshots::StorageConfig::new(dir.to_path_buf());
    storage.history = std::time::Duration::from_millis(u64::MAX);
    let node = start_local(
        env,
        dir,
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
    (node, api)
}

/// The body of the pending timer `id` of `counter/t`, as `state.db` holds it.
fn timer_body(node: &kronik_sched::Node, id: u64) -> Option<kronik_proto::log::v1::Sealable> {
    node.store()
        .db()
        .timers(None)
        .unwrap()
        .into_iter()
        .find(|t| t.actor.key == "t" && t.timer_id == id)
        .and_then(|t| t.msg.body)
}

/// Waits for the timer's turn and returns its dead letter.
async fn timer_dead_letter(node: &kronik_sched::Node) -> kronik_store::db::DeadLetterRow {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let letters = node.store().db().dead_letters(0, 100).unwrap();
        if let Some(d) = letters.into_iter().find(|d| d.actor.key == "t") {
            return d;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the timer of counter/t did not fire"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Whether `state.db` or its WAL holds `mark`.
fn state_db_holds(dir: &std::path::Path, mark: &str) -> bool {
    ["state.db", "state.db-wal"].iter().any(|f| {
        std::fs::read(dir.join("branches/main").join(f))
            .unwrap_or_default()
            .windows(mark.len())
            .any(|w| w == mark.as_bytes())
    })
}

/// Issue #31: a timer scheduled in `off` mode waits in `state.db` with its
/// subject's body in plain text. Reseal seals that body with the records,
/// so `state.db` keeps no copy, and once the subject is erased the timer's
/// turn meets an erased input: a `SUBJECT_ERASED` dead letter. The value is
/// not handed to the guest again, nor sealed again under a new key version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reseal_seals_a_pending_timer_and_after_erasure_it_fires_as_a_dead_letter() {
    const MARK: &str = "NEEDLE-TIMER-9c1";
    let dir = tempfile::tempdir().unwrap();
    let (node, api, clock) = stepped_counter_node(dir.path()).await;
    // In `off` mode: `store` the mark in an hour, for user:1. Only the
    // test's step of the clock fires it, after the erasure, however slow the
    // steps before are.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/t/messages",
        json!({"name": "schedule", "text": format!("{TIMER_DELAY_MS} store\n{MARK}"), "subject": "user:1", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let id: u64 = v["reply"]["text"].as_str().unwrap().parse().unwrap();
    // Closes the segment that holds it.
    let (s, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/d/messages",
        json!({"name": "increment", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let body = timer_body(&node, id).unwrap();
    assert_eq!(body.subject.as_deref(), Some("user:1"));
    assert!(matches!(
        body.value,
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
    let body = timer_body(&node, id).expect("the timer fired before the clock moved");
    assert!(
        matches!(
            body.value,
            Some(kronik_proto::log::v1::sealable::Value::Sealed(_))
        ),
        "the pending timer's body is still plain after reseal: {body:?}"
    );
    assert!(
        !state_db_holds(dir.path(), MARK),
        "state.db still holds the timer's plain body"
    );
    let (s, v) = call(
        &api,
        "POST",
        "/v1/privacy/erase",
        json!({"subject": "user:1", "reason": "erasure request"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["plain_values"], 0, "{v}");
    assert!(
        timer_body(&node, id).is_some(),
        "the timer fired before the clock moved"
    );
    let status = call(&api, "GET", "/v1/privacy", Value::Null).await.1;
    assert_eq!(status["pending_erasures"], 0, "{status}");
    fire_timers(&clock);
    let dead = timer_dead_letter(&node).await;
    assert_eq!(dead.error_code, "SUBJECT_ERASED", "{dead:?}");
    assert!(
        node.store()
            .db()
            .kv_get("counter", "t", "stored")
            .unwrap()
            .is_none(),
        "the erased value reached the guest"
    );
    assert!(!state_db_holds(dir.path(), MARK));
}

/// Issue #31, the other order: the subject is erased before any reseal.
/// The erasure itself turns the pending timer's plain body into a
/// tombstone, so the timer's turn is a `SUBJECT_ERASED` dead letter as
/// well, and `privacy status` counts the erasure as pending while the log
/// still holds the subject's plain values.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erasure_before_any_reseal_stops_a_pending_timer_too() {
    const MARK: &str = "NEEDLE-TIMER-41d";
    let dir = tempfile::tempdir().unwrap();
    let (node, api, clock) = stepped_counter_node(dir.path()).await;
    let (s, v) = call(
        &api,
        "POST",
        "/v1/actors/counter/t/messages",
        json!({"name": "schedule", "text": format!("{TIMER_DELAY_MS} store\n{MARK}"), "subject": "user:1", "reason": "r"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let id: u64 = v["reply"]["text"].as_str().unwrap().parse().unwrap();
    let (s, v) = call(
        &api,
        "POST",
        "/v1/privacy/erase",
        json!({"subject": "user:1", "reason": "erasure request"}),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(v["plain_values"].as_u64().unwrap() > 0, "{v}");
    let body = timer_body(&node, id).expect("the timer fired before the clock moved");
    assert!(
        matches!(
            body.value,
            Some(kronik_proto::log::v1::sealable::Value::Sealed(_))
        ),
        "the erasure left the pending timer's body plain: {body:?}"
    );
    let status = call(&api, "GET", "/v1/privacy", Value::Null).await.1;
    assert_eq!(status["pending_erasures"], 1, "{status}");
    fire_timers(&clock);
    let dead = timer_dead_letter(&node).await;
    assert_eq!(dead.error_code, "SUBJECT_ERASED", "{dead:?}");
    assert!(
        node.store()
            .db()
            .kv_get("counter", "t", "stored")
            .unwrap()
            .is_none(),
        "the erased value reached the guest"
    );
}
