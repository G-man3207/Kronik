//! Erasing a data subject, and the outputs that scrub secrets.
//!
//! `POST /v1/privacy/erase` destroys a subject's key. The sealed requests of
//! its turns can then never be opened again, by anyone, and that is not a loss
//! of secret coverage: history, inspect, a turn and a secret's history keep
//! answering, after the erasure, after a crash and after a rescan of the whole
//! log. A key that is missing but was never erased is a loss of coverage: those
//! outputs stay unavailable until the key is back (invariant I8).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_sched::{NodeConfig, start_local};
use serde_json::{Value, json};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const COVERAGE: &str = "secret-coverage.json";
const SECRET: &str = "the-value-of-the-api-key";

async fn raw(api: &Api, method: &str, path: &str, body: Value) -> (u16, Value) {
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

/// A local HTTP target that answers every request with `pong`.
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

/// A node over `dir` on a runtime of its own. Dropping the site drops the
/// runtime with everything the node spawned: a crash.
struct Site {
    runtime: tokio::runtime::Runtime,
    api: Arc<Api>,
}

type Answers = Vec<(&'static str, u16, Value)>;

impl Site {
    fn start(dir: &Path) -> Site {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let api = runtime.block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            Arc::new(Api::new(
                start_local(env, dir, NodeConfig::default()).await.unwrap(),
            ))
        });
        Site { runtime, api }
    }

    /// One call, as it answers: the tests below look at 503s themselves.
    fn call(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        self.runtime.block_on(raw(&self.api, method, path, body))
    }

    /// A call that has to succeed. A change of the inventory (a deployment, a
    /// grant, a secret, the privacy mode) answers 503 SECRET_UNAVAILABLE for a
    /// moment, in the documented coverage window (ADR 0108); a client retries
    /// that, for a bounded time.
    fn ok(&self, method: &str, path: &str, body: Value) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (status, value) = self.call(method, path, body.clone());
            if status == 200 {
                return value;
            }
            assert!(
                status == 503 && Instant::now() < deadline,
                "{method} {path}: {status} {value}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The deployment, the grants, the secret and the privacy mode.
    fn set_up(&self) {
        let wasm =
            base64::engine::general_purpose::STANDARD.encode(std::fs::read(COUNTER).unwrap());
        self.ok(
            "POST",
            "/v1/deployments",
            json!({"wasm_base64": wasm, "reason": "r"}),
        );
        for capability in ["http:127.0.0.1", "secret:api-key"] {
            self.ok(
                "POST",
                "/v1/grants",
                json!({"kind": "counter", "capability": capability, "reason": "r"}),
            );
        }
        self.ok(
            "PUT",
            "/v1/secrets/api-key",
            json!({"text": SECRET, "reason": "r"}),
        );
        self.ok(
            "POST",
            "/v1/privacy/mode",
            json!({"mode": "on", "reason": "r"}),
        );
    }

    /// A turn of `subject` whose `http.fetch` sends the secret in a header: its
    /// request is sealed for the subject and cites the secret's version.
    /// Returns the turn's id.
    fn fetch(&self, target: &str, actor: &str, subject: &str) -> String {
        let answer = self.ok(
            "POST",
            &format!("/v1/actors/counter/{actor}/messages"),
            json!({
                "name": "fetch-ok",
                "text": format!("POST http://{target}/hook\nS x-secret api-key {{}}\n\nbody"),
                "subject": subject,
                "reason": "r",
            }),
        );
        assert_eq!(answer["outcome"]["kind"], "committed", "{answer}");
        answer["turn_id"].as_str().unwrap().to_owned()
    }

    fn erase(&self, subject: &str) {
        self.ok(
            "POST",
            "/v1/privacy/erase",
            json!({"subject": subject, "reason": "r"}),
        );
    }

    /// Everything that needs complete secret coverage to answer: an actor's
    /// history and state, a turn, and a secret's history.
    fn scrubbed(&self, turn: &str) -> Answers {
        [
            ("history", "/v1/actors/counter/a/history".to_owned()),
            ("turn", format!("/v1/turns/{turn}")),
            ("inspect", "/v1/actors/counter/a".to_owned()),
            ("secret history", "/v1/secrets/api-key/history".to_owned()),
        ]
        .into_iter()
        .map(|(name, path)| {
            let (status, value) = self.call("GET", &path, Value::Null);
            (name, status, value)
        })
        .collect()
    }

    /// Waits for the node's start-up work, then asserts that every output
    /// that scrubs answers.
    fn assert_available(&self, turn: &str, when: &str) -> Answers {
        let waiting = Instant::now();
        loop {
            let answers = self.scrubbed(turn);
            if answers.iter().all(|(_, status, _)| *status == 200) {
                assert_eq!(self.call("GET", "/v1/health", Value::Null).0, 200, "{when}");
                return answers;
            }
            assert!(
                waiting.elapsed() < Duration::from_secs(10),
                "{when}: {answers:?}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn watermark(dir: &Path) -> std::path::PathBuf {
    dir.join(COVERAGE)
}

/// The effect of the turn `turn` in the history answer among `answers`, and
/// the effect in the turn answer.
fn effects(answers: &Answers, turn: &str) -> [Value; 2] {
    let in_history = answers[0].2["turns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["turn_id"] == turn)
        .unwrap_or_else(|| panic!("{turn} is not in {}", answers[0].2))["effects"][0]
        .clone();
    [in_history, answers[1].2["effects"][0].clone()]
}

#[test]
fn erasing_a_subject_with_a_sealed_http_effect_leaves_scrubbed_outputs_available() {
    let dir = tempfile::tempdir().unwrap();
    let target = http_target();
    let site = Site::start(dir.path());
    site.set_up();
    let turn = site.fetch(&target, "a", "user:1");

    // History never opens a sealed request. The operator, who may read what
    // the subject's turn sent, sees in the turn which secret version it used.
    let before = site.assert_available(&turn, "before the erasure");
    let [in_history, in_turn] = effects(&before, &turn);
    assert!(in_history.get("secrets").is_none(), "{in_history}");
    assert_eq!(in_turn["kind"], "http.fetch", "{in_turn}");
    assert_eq!(in_turn["secrets"][0]["name"], "api-key", "{in_turn}");
    assert_eq!(in_turn["secrets"][0]["version"], 1, "{in_turn}");

    site.erase("user:1");
    let after = site.assert_available(&turn, "after the erasure");

    // What the erasure destroyed stays destroyed, for the operator too: the
    // effect is still there, with no request and no secret version, and
    // nothing of the request or its answer is in any output.
    for effect in effects(&after, &turn) {
        assert_eq!(effect["kind"], "http.fetch", "{effect}");
        assert!(effect.get("request").is_none(), "{effect}");
        assert!(effect.get("secrets").is_none(), "{effect}");
    }
    for (name, _, value) in &after {
        let text = value.to_string();
        for content in ["pong", "/hook", SECRET] {
            assert!(!text.contains(content), "{name} shows {content}: {text}");
        }
    }
}

#[test]
fn a_crash_after_an_erasure_does_not_leave_scrubbed_outputs_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let target = http_target();
    let turn = {
        let site = Site::start(dir.path());
        site.set_up();
        let turn = site.fetch(&target, "a", "user:1");
        site.erase("user:1");
        turn
        // The runtime is dropped here: a crash.
    };
    Site::start(dir.path()).assert_available(&turn, "after the erasure and a crash");
}

#[test]
fn a_rescan_of_the_whole_log_after_an_erasure_certifies() {
    // The request lies after the watermark, or before it: the first start
    // reads it, the second does not, the third has no watermark to start from.
    for restart_before_erasure in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let target = http_target();
        let turn = {
            let site = Site::start(dir.path());
            site.set_up();
            let turn = site.fetch(&target, "a", "user:1");
            site.fetch(&target, "b", "user:2");
            turn
        };
        if restart_before_erasure {
            // This start certifies the log with the requests readable, and
            // writes a watermark behind them.
            let site = Site::start(dir.path());
            site.assert_available(&turn, "after a restart, before the erasure");
            site.erase("user:1");
            site.assert_available(&turn, "after the erasure");
        } else {
            let site = Site::start(dir.path());
            site.erase("user:1");
        }
        Site::start(dir.path()).assert_available(&turn, "after the erasure and a restart");
        // A node upgraded from v0.4.0 finds the manifest of that release, and
        // trusts none of it: it reads the whole log, the erased request
        // included.
        let manifest = std::fs::read_to_string(watermark(dir.path())).unwrap();
        assert!(manifest.contains("secret-coverage/v2"), "{manifest}");
        std::fs::write(
            watermark(dir.path()),
            manifest.replace("secret-coverage/v2", "secret-coverage/v1"),
        )
        .unwrap();
        Site::start(dir.path()).assert_available(&turn, "after the erasure and a v0.4.0 manifest");
        // Nothing to start from: a node that has lost its watermark reads the
        // whole log too.
        std::fs::remove_file(watermark(dir.path())).unwrap();
        Site::start(dir.path())
            .assert_available(&turn, "after the erasure and without a watermark");
    }
}

#[test]
fn a_keystore_without_the_key_keeps_scrubbed_outputs_unavailable_until_it_is_back() {
    let dir = tempfile::tempdir().unwrap();
    let target = http_target();
    let turn = {
        let site = Site::start(dir.path());
        site.set_up();
        let turn = site.fetch(&target, "a", "user:1");
        site.assert_available(&turn, "before the keystore is lost");
        turn
    };
    // Not erased, only lost: the keystore of another node, or a restore that
    // left it out. Its sealed requests cannot be opened, and nobody has said
    // that they are gone.
    let keys = dir.path().join("keys");
    let kept = dir.path().join("keys.kept");
    copy_dir(&keys, &kept);
    for entry in std::fs::read_dir(&keys).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("keystore.db"))
        {
            std::fs::remove_file(path).unwrap();
        }
    }
    {
        let site = Site::start(dir.path());
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(site.call("GET", "/v1/health", Value::Null).0, 200);
        for (name, status, value) in site.scrubbed(&turn) {
            assert_eq!(
                (status, &value["error"]["code"]),
                (503, &json!("SECRET_UNAVAILABLE")),
                "{name} answered while the key was missing: {value}"
            );
        }
    }
    // The keystore is back.
    std::fs::remove_dir_all(&keys).unwrap();
    std::fs::rename(&kept, &keys).unwrap();
    Site::start(dir.path()).assert_available(&turn, "after the keystore is back");
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}
