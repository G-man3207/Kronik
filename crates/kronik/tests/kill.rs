//! M2 acceptance with a real `kronik serve` process, killed with SIGKILL at
//! the trigger point for the crash tests: the test HTTP server tells the harness when
//! the daemon's request arrives, the harness `kill -9`s the daemon, restarts
//! it on the same data directory and checks the log, the API and what the
//! target server saw.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use kronik_proto::Record;
use serde_json::{Value, json};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

// ---------------------------------------------------------------- test server

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Default)]
struct ServerState {
    seen: Vec<Seen>,
    released: bool,
}

struct Server {
    addr: String,
    state: Arc<(Mutex<ServerState>, Condvar)>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let state = Arc::new((Mutex::new(ServerState::default()), Condvar::new()));
        let st = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let st = st.clone();
                std::thread::spawn(move || serve(stream, st));
            }
        });
        Server { addr, state }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn seen(&self, path: &str) -> Vec<Seen> {
        let g = self.state.0.lock().unwrap();
        g.seen.iter().filter(|s| s.path == path).cloned().collect()
    }

    fn wait_for(&self, path: &str, n: usize) {
        let (m, cv) = &*self.state;
        let mut g = m.lock().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while g.seen.iter().filter(|s| s.path == path).count() < n {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "request {n} to {path} never arrived");
            g = cv.wait_timeout(g, left).unwrap().0;
        }
    }

    fn release(&self) {
        let (m, cv) = &*self.state;
        m.lock().unwrap().released = true;
        cv.notify_all();
    }
}

fn serve(stream: TcpStream, st: Arc<(Mutex<ServerState>, Condvar)>) {
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("").to_owned();
        let path = parts.next().unwrap_or("").to_owned();
        let mut headers = BTreeMap::new();
        loop {
            let mut h = String::new();
            if r.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
            }
        }
        let len: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; len];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        let (m, cv) = &*st;
        let count = {
            let mut g = m.lock().unwrap();
            g.seen.push(Seen {
                method,
                path: path.clone(),
                headers,
                body,
            });
            cv.notify_all();
            g.seen.iter().filter(|s| s.path == path).count()
        };
        if path == "/hang" {
            let mut g = m.lock().unwrap();
            while !g.released {
                g = cv.wait(g).unwrap();
            }
        }
        let reply = format!("ok {count}");
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{reply}",
            reply.len()
        );
        if w.write_all(resp.as_bytes()).is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------- daemon

struct Daemon {
    dir: PathBuf,
    child: Option<Child>,
}

impl Daemon {
    fn sock(&self) -> PathBuf {
        self.dir.join("api.sock")
    }

    fn start(dir: &Path, extra: &[&str]) -> Daemon {
        Daemon::start_logging(dir, extra, "warn")
    }

    fn start_logging(dir: &Path, extra: &[&str], level: &str) -> Daemon {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_kronik"))
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .arg("--data-dir")
            .arg(dir.join("data"))
            .args(["--http-listen", "127.0.0.1:0", "--api-socket"])
            .arg(dir.join("api.sock"))
            .args(extra)
            .env("KRONIK_LOG", level)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon {
            dir: dir.to_path_buf(),
            child: Some(child),
        };
        for _ in 0..400 {
            if d.try_api("GET", "/v1/health", Value::Null)
                .is_some_and(|(s, _)| s == 200)
            {
                return d;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "daemon did not start: {}",
            std::fs::read_to_string(dir.join("serve.log")).unwrap_or_default()
        );
    }

    /// SIGKILL.
    fn kill9(&mut self) {
        if let Some(mut c) = self.child.take() {
            c.kill().unwrap();
            c.wait().unwrap();
        }
    }

    fn try_api(&self, method: &str, path: &str, body: Value) -> Option<(u16, Value)> {
        let mut s = UnixStream::connect(self.sock()).ok()?;
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nhost: kronik\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .ok()?;
        let mut r = BufReader::new(s);
        let mut line = String::new();
        r.read_line(&mut line).ok()?;
        let status: u16 = line.split_whitespace().nth(1)?.parse().ok()?;
        let mut len = 0;
        loop {
            let mut h = String::new();
            r.read_line(&mut h).ok()?;
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':')
                && k.eq_ignore_ascii_case("content-length")
            {
                len = v.trim().parse().ok()?;
            }
        }
        let mut buf = vec![0; len];
        r.read_exact(&mut buf).ok()?;
        Some((status, serde_json::from_slice(&buf).ok()?))
    }

    fn api(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        self.try_api(method, path, body)
            .unwrap_or_else(|| panic!("API {method} {path} failed"))
    }

    fn deploy(&self) {
        let wasm =
            base64::engine::general_purpose::STANDARD.encode(std::fs::read(COUNTER).unwrap());
        let (s, v) = self.api(
            "POST",
            "/v1/deployments",
            json!({"wasm_base64": wasm, "reason": "kill test"}),
        );
        assert_eq!(s, 200, "{v}");
    }

    fn grant(&self, cap: &str, delivery: Option<&str>) {
        let (s, v) = self.api(
            "POST",
            "/v1/grants",
            json!({"kind": "counter", "capability": cap, "delivery": delivery, "reason": "kill test"}),
        );
        assert_eq!(s, 200, "{v}");
    }

    /// Sends a message on a background thread (the daemon may die first).
    fn send_detached(&self, actor: &str, name: &str, text: &str) {
        let sock = self.sock();
        let path = format!("/v1/actors/{actor}/messages");
        let body = json!({"name": name, "text": text, "reason": "kill test"}).to_string();
        std::thread::spawn(move || {
            if let Ok(mut s) = UnixStream::connect(sock) {
                let _ = write!(
                    s,
                    "POST {path} HTTP/1.1\r\nhost: kronik\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let mut sink = Vec::new();
                let _ = s.read_to_end(&mut sink);
            }
        });
    }

    fn wait_until(&self, what: &str, f: impl Fn(&Daemon) -> bool) {
        for _ in 0..1200 {
            if f(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("timed out waiting for {what}");
    }

    fn history(&self, actor: &str) -> Vec<Value> {
        let (s, v) = self.api("GET", &format!("/v1/actors/{actor}/history"), Value::Null);
        if s != 200 {
            return Vec::new();
        }
        v["turns"].as_array().cloned().unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill9();
    }
}

/// Every record of the log, read after the daemon died.
fn log_records(dir: &Path) -> Vec<Record> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
        let reader = kronik_log::LogReader::new(env, dir.join("data/branches/main/log"), "main");
        let mut out = Vec::new();
        reader
            .read(1, u64::MAX, |c| {
                out.push(c.record);
                Ok(())
            })
            .await
            .unwrap();
        out
    })
}

/// The re-run rebuilt the recorded request byte-for-byte: method, URL,
/// every header and the body match the first attempt.
fn assert_same_wire_request(seen: &[Seen]) {
    for (i, s) in seen.iter().enumerate().skip(1) {
        assert_eq!(
            (
                &seen[0].method,
                &seen[0].path,
                &seen[0].headers,
                &seen[0].body
            ),
            (&s.method, &s.path, &s.headers, &s.body),
            "attempt {} rebuilt a different request",
            i
        );
    }
}

fn committed(turn: &Value) -> bool {
    turn["outcome"]["kind"] == "committed"
}

// ---------------------------------------------------------------- tests

#[test]
fn kill9_after_the_request_left_turn_begin_is_durable_and_replay_safe_reruns() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let mut d = Daemon::start(dir.path(), &[]);
    d.deploy();
    d.grant("http:127.0.0.1", None);
    d.send_detached(
        "counter/a",
        "fetch",
        &format!("GET {}", server.url("/hang")),
    );
    server.wait_for("/hang", 1);
    d.kill9();
    let records = log_records(dir.path());
    let begin = records.iter().find_map(|r| match r {
        Record::TurnBegin(b) => Some(b.clone()),
        _ => None,
    });
    let begin = begin.expect("a TurnBegin must be fsynced before the request is sent");
    assert!(!records.iter().any(|r| matches!(r, Record::EffectResult(_))));
    server.release();
    let d = Daemon::start(dir.path(), &[]);
    server.wait_for("/hang", 2);
    d.wait_until("the re-run's commit", |d| {
        d.history("counter/a").iter().any(committed)
    });
    let seen = server.seen("/hang");
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[0].headers.get("idempotency-key"),
        seen[1].headers.get("idempotency-key")
    );
    assert_eq!(
        (&seen[0].method, &seen[0].body),
        (&seen[1].method, &seen[1].body)
    );
    assert_same_wire_request(&seen);
    let after = log_records_alive(&d);
    assert!(
        after
            .iter()
            .any(|r| matches!(r, Record::TurnRecord(t) if t.execution_id == begin.execution_id))
    );
}

/// Reads the log while the daemon runs (only fsynced records exist).
fn log_records_alive(d: &Daemon) -> Vec<Record> {
    log_records(&d.dir)
}

#[test]
fn kill9_after_a_recorded_result_sends_nothing_twice_and_reruns_identically() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let mut d = Daemon::start(dir.path(), &[]);
    d.deploy();
    d.grant("http:127.0.0.1", Some("idempotency-keyed"));
    let spec = format!(
        "POST {}\n\nfirst\n---\nPOST {}\n\nsecond",
        server.url("/ok"),
        server.url("/hang")
    );
    d.send_detached("counter/a", "fetch2", &spec);
    server.wait_for("/hang", 1);
    d.kill9();
    server.release();
    let d = Daemon::start(dir.path(), &[]);
    server.wait_for("/hang", 2);
    d.wait_until("the re-run's commit", |d| {
        d.history("counter/a").iter().any(committed)
    });
    assert_eq!(
        server.seen("/ok").len(),
        1,
        "the recorded effect must not be sent again"
    );
    let hang = server.seen("/hang");
    assert_eq!(hang[0].body, hang[1].body);
    assert_eq!(
        hang[0].headers.get("idempotency-key"),
        hang[1].headers.get("idempotency-key")
    );
    assert_same_wire_request(&hang);
}

#[test]
fn kill9_before_the_result_idempotency_keyed_retries_with_the_same_key() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let mut d = Daemon::start(dir.path(), &[]);
    d.deploy();
    d.grant("http:127.0.0.1", Some("idempotency-keyed"));
    d.send_detached(
        "counter/a",
        "fetch",
        &format!("POST {}\n\npay 10", server.url("/hang")),
    );
    server.wait_for("/hang", 1);
    d.kill9();
    server.release();
    let d = Daemon::start(dir.path(), &[]);
    server.wait_for("/hang", 2);
    d.wait_until("the re-run's commit", |d| {
        d.history("counter/a").iter().any(committed)
    });
    let seen = server.seen("/hang");
    let key = seen[0].headers.get("idempotency-key").cloned().unwrap();
    assert_eq!(key.len(), 64);
    assert_eq!(seen[1].headers.get("idempotency-key"), Some(&key));
    assert_eq!(seen[0].body, seen[1].body);
    assert_same_wire_request(&seen);
}

#[test]
fn kill9_before_the_result_unsafe_is_not_retried_and_dead_letters() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let mut d = Daemon::start(dir.path(), &[]);
    d.deploy();
    d.grant("http:127.0.0.1", None); // POST defaults to unsafe
    d.send_detached(
        "counter/a",
        "fetch",
        &format!("POST {}\n\ncharge 10", server.url("/hang")),
    );
    server.wait_for("/hang", 1);
    d.kill9();
    server.release();
    let d = Daemon::start(dir.path(), &[]);
    d.wait_until("the dead letter", |d| {
        d.api("GET", "/v1/dead-letters", Value::Null).1["dead_letters"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    });
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        server.seen("/hang").len(),
        1,
        "an unsafe effect must not be sent again"
    );
    let (_, v) = d.api("GET", "/v1/dead-letters", Value::Null);
    assert_eq!(v["dead_letters"][0]["error_code"], "EFFECT_OUTCOME_UNKNOWN");
    let turn = &d.history("counter/a")[0];
    assert_eq!(turn["outcome"]["kind"], "effect_outcome_unknown");
    assert_eq!(turn["effects"][0]["status"], "outcome_unknown");
    assert_eq!(turn["effects"][0]["delivery"], "unsafe");
    // The dead letter's turn holds the request that was not sent again.
    let id = v["dead_letters"][0]["id"].as_str().unwrap().to_owned();
    let (_, t) = d.api("GET", &format!("/v1/turns/{id}"), Value::Null);
    assert_eq!(t["effects"][0]["target"], "http:127.0.0.1");
}

#[test]
fn kill9_after_the_callee_committed_reuses_its_saved_response() {
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(dir.path(), &["--test-hold-after-call"]);
    d.deploy();
    d.send_detached("counter/a", "call", "counter/b increment");
    d.wait_until("the callee's commit", |d| {
        d.history("counter/b").iter().any(committed)
    });
    d.kill9();
    let d = Daemon::start(dir.path(), &[]);
    d.wait_until("the caller's re-run", |d| {
        d.history("counter/a").iter().any(committed)
    });
    let b = d.history("counter/b");
    assert_eq!(b.len(), 1, "the callee must not run again: {b:?}");
    let a = &d.history("counter/a")[0];
    assert_eq!(a["effects"][0]["kind"], "actor.call");
    assert_eq!(a["effects"][0]["status"], "ok");
    let (_, inspect) = d.api("GET", "/v1/actors/counter/b", Value::Null);
    assert_eq!(inspect["state"][0]["text"], "1");
}

#[test]
fn revealed_secret_is_scrubbed_from_the_daemon_log_and_every_file() {
    const SECRET: &str = "serve-scrub-value-3d81aa";
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start_logging(dir.path(), &[], "info");
    d.deploy();
    let (s, v) = d.api(
        "PUT",
        "/v1/secrets/db-password",
        json!({"text": SECRET, "reason": "test"}),
    );
    assert_eq!(s, 200, "{v}");
    d.grant("secret-reveal:db-password", None);
    let (s, v) = d.api(
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "reveal-persist", "text": "db-password", "reason": "test"}),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["reply"]["text"], "value [secret:db-password]");
    d.wait_until("the sink", |d| !d.history("counter/sink").is_empty());
    d.kill9();
    let log = std::fs::read_to_string(dir.path().join("serve.log")).unwrap();
    assert!(
        log.contains("revealed [secret:db-password]"),
        "the guest log event is missing:\n{log}"
    );
    let mut hits = Vec::new();
    scan(dir.path(), SECRET.as_bytes(), &mut hits);
    assert!(hits.is_empty(), "the revealed value is in {hits:?}");
}

fn scan(dir: &Path, needle: &[u8], hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            scan(&p, needle, hits);
        } else if let Ok(bytes) = std::fs::read(&p)
            && bytes.windows(needle.len()).any(|w| w == needle)
        {
            hits.push(p.display().to_string());
        }
    }
}
