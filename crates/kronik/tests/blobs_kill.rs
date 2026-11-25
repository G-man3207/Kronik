//! Crashes around a turn that writes a blob or changes what its actor holds
//! (docs/design/m26-blobs.md §11, §17; criteria 3, 4, 8 and 9), with a real
//! `kronik serve`, its hidden `--test-hold` and `kill -9`: after the blob's
//! finish and before the record, the bytes are loose, the dry run says so
//! and two passes delete them; before the commit, a release leaves the hold
//! and a retain or a put adds none, its bytes loose; after the record's sync
//! and before its apply, the restart applies it (also from the log alone),
//! the hold exists and a pass keeps its blob.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

#[path = "support/blob_fixtures.rs"]
mod blob_fixtures;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use blob_fixtures::{hash, pattern, pattern_sum};
use serde_json::{Value, json};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

/// The daemon: this build's, or `KRONIK_M26_KRONIK` (the test machine runs
/// the test binary and a static `kronik` away from the checkout,
/// scripts/acceptance-m26.sh).
fn kronik_bin() -> PathBuf {
    std::env::var_os("KRONIK_M26_KRONIK").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_kronik")),
        PathBuf::from,
    )
}

/// The test guest: the checkout's, or `KRONIK_M26_MEDIA`.
fn media_wasm() -> Vec<u8> {
    let path =
        std::env::var_os("KRONIK_M26_MEDIA").map_or_else(|| PathBuf::from(MEDIA), PathBuf::from);
    std::fs::read(path).unwrap()
}

struct Daemon {
    dir: PathBuf,
    child: Option<Child>,
    http: String,
}

impl Daemon {
    fn start(dir: &Path, args: &[&str]) -> Daemon {
        let config = dir.join("kronik.toml");
        std::fs::write(
            &config,
            format!("[server]\ndata_dir = {:?}\n", dir.join("data")),
        )
        .unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = Command::new(kronik_bin())
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .arg("--config")
            .arg(&config)
            .args([
                "--http-listen",
                "127.0.0.1:0",
                "--admin-listen",
                "127.0.0.1:0",
                "--api-socket",
            ])
            .arg(dir.join("api.sock"))
            .args(args)
            .env("KRONIK_LOG", "info")
            .env_remove("KRONIK_TOKEN")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut d = Daemon {
            dir: dir.to_path_buf(),
            child: Some(child),
            http: String::new(),
        };
        for _ in 0..800 {
            if let Some((200, v)) = d.try_api("GET", "/v1/health", Value::Null) {
                d.http = v["http_listen"].as_str().unwrap().to_owned();
                return d;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("kronik serve did not start: {}", d.log());
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    fn data(&self) -> PathBuf {
        self.dir.join("data")
    }

    fn try_api(&self, method: &str, path: &str, body: Value) -> Option<(u16, Value)> {
        let mut s = UnixStream::connect(self.dir.join("api.sock")).ok()?;
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nhost: kronik\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
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

    fn api(&self, method: &str, path: &str, body: Value) -> Value {
        let (status, v) = self
            .try_api(method, path, body)
            .unwrap_or_else(|| panic!("{method} {path} failed: {}", self.log()));
        assert_eq!(status, 200, "{method} {path}: {v}");
        v
    }

    fn media(&self) {
        let wasm = base64::engine::general_purpose::STANDARD.encode(media_wasm());
        self.api(
            "POST",
            "/v1/deployments",
            json!({"wasm_base64": wasm, "reason": "blob crash test"}),
        );
    }

    /// The turns of `media/a` in the log (none: the actor has no turns).
    fn turns(&self) -> Vec<Value> {
        let (status, v) = self
            .try_api("GET", "/v1/actors/media/a/history", Value::Null)
            .unwrap_or_else(|| panic!("history failed: {}", self.log()));
        if status == 404 && v["error"]["code"] == "ACTOR_NOT_FOUND" {
            return Vec::new();
        }
        assert_eq!(status, 200, "{v}");
        v["turns"].as_array().cloned().unwrap_or_default()
    }

    /// The text answer of `POST /media/a/<op>?<query>`, which must be 200.
    fn ok(&self, op: &str, query: &str) -> String {
        let (status, body) = call(&self.http, &request(op, query));
        let text = String::from_utf8_lossy(&body).into_owned();
        assert_eq!(status, 200, "{op}?{query}: {text}");
        text
    }

    /// The hashes `media/a` holds (M26 §12).
    fn holds(&self) -> Vec<String> {
        let (status, v) = self
            .try_api("GET", "/v1/actors/media/a/blobs", Value::Null)
            .unwrap_or_else(|| panic!("holds failed: {}", self.log()));
        assert_eq!(status, 200, "{v}");
        let mut out: Vec<String> = v["blobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["hash"].as_str().unwrap().to_owned())
            .collect();
        out.sort();
        out
    }

    /// The collector's dry run: each file without a root and its reason.
    fn plan(&self) -> Vec<(String, String)> {
        let v = self.api("GET", "/v1/blobs/gc", Value::Null);
        let mut out: Vec<(String, String)> = v["blobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| {
                (
                    b["hash"].as_str().unwrap().to_owned(),
                    b["reason"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        out.sort();
        out
    }

    /// A pass of the collector now.
    fn gc(&self, immediate: bool) -> Value {
        self.api(
            "POST",
            "/v1/blobs/gc",
            json!({"reason": "blob crash test", "immediate": immediate}),
        )
    }

    /// Arms the hold, sends `request` on a thread of its own (it never gets
    /// an answer), waits until a turn waits at the hold, then kills the
    /// daemon with SIGKILL.
    fn crash_at_hold(&mut self, request: impl Into<Vec<u8>>) {
        let request = request.into();
        std::fs::write(self.data().join("test-hold-armed"), b"").unwrap();
        let http = self.http.clone();
        std::thread::spawn(move || {
            if let Ok(mut s) = TcpStream::connect(http) {
                let _ = s.write_all(&request);
                let mut sink = Vec::new();
                let _ = s.read_to_end(&mut sink);
            }
        });
        let reached = self.data().join("test-hold-reached");
        for _ in 0..800 {
            if reached.exists() {
                let mut child = self.child.take().unwrap();
                child.kill().unwrap();
                child.wait().unwrap();
                std::fs::remove_file(self.data().join("test-hold-armed")).unwrap();
                std::fs::remove_file(reached).unwrap();
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("no turn reached the hold: {}", self.log());
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// `POST /media/a/write?size=<n>` with an Idempotency-Key.
fn write_request(size: u64, key: &str) -> String {
    format!(
        "POST /media/a/write?size={size} HTTP/1.1\r\nhost: x\r\nidempotency-key: {key}\r\n\
         content-length: 0\r\nconnection: close\r\n\r\n"
    )
}

/// The status and body of a request.
fn call(http: &str, request: &str) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(http).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&out[..split]).to_string();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, out[split + 4..].to_vec())
}

/// `POST /media/a/<op>?<query>` without a body.
fn request(op: &str, query: &str) -> String {
    format!(
        "POST /media/a/{op}?{query} HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\
         connection: close\r\n\r\n"
    )
}

/// The files of the blob store's objects.
fn objects(data: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            if e.path().is_dir() {
                walk(&e.path(), out);
            } else {
                out.push(e.path());
            }
        }
    }
    let mut out = Vec::new();
    walk(&data.join("blobs/objects"), &mut out);
    out
}

/// Criterion 8, up to what M25 holds: after the blob's finish and before
/// the turn's record, the bytes are on disk and no record refers to them;
/// the request runs again from scratch.
#[test]
fn a_crash_after_the_blob_leaves_loose_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(dir.path(), &["--test-hold", "blob-finished"]);
    d.media();
    d.crash_at_hold(write_request(300_000, "k1"));
    let d = Daemon::start(dir.path(), &[]);
    assert_eq!(objects(&d.data()).len(), 1, "the finished blob's file");
    assert!(d.turns().is_empty(), "no record of the turn");
    // M26: the dry run lists it as loose, and two passes delete it.
    let loose = hash(&pattern(300_000));
    assert_eq!(d.plan(), [(loose, "loose".to_owned())]);
    let first = d.gc(false);
    assert_eq!(first["deleted"], 0, "{first}");
    assert_eq!(first["candidates"], 1, "{first}");
    let second = d.gc(false);
    assert_eq!(second["deleted"], 1, "{second}");
    assert!(objects(&d.data()).is_empty());
    let (status, body) = call(&d.http, &write_request(300_000, "k1"));
    assert_eq!(status, 200);
    assert!(body == pattern(300_000), "the retry's answer");
    assert_eq!(d.turns().len(), 1);
}

/// Before the commit the turn's blob is durable and nothing records it.
#[test]
fn a_crash_before_commit_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(dir.path(), &["--test-hold", "before-commit"]);
    d.media();
    d.crash_at_hold(write_request(200_000, "k2"));
    let d = Daemon::start(dir.path(), &[]);
    assert_eq!(objects(&d.data()).len(), 1);
    assert!(d.turns().is_empty());
}

/// Criterion 9, up to what M25 holds: the record was synced, not applied;
/// the restart applies it, from the log alone too, and a retry of the
/// request gets its saved answer, the blob, byte for byte.
#[test]
fn a_crash_before_apply_applies_the_record_at_restart() {
    for drop_state in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Daemon::start(dir.path(), &["--test-hold", "record-appended"]);
        d.media();
        d.crash_at_hold(write_request(250_000, "k3"));
        if drop_state {
            let state = dir.path().join("data/branches/main/state.db");
            if state.exists() {
                std::fs::remove_file(&state).unwrap();
            }
            for suffix in ["-wal", "-shm"] {
                let _ = std::fs::remove_file(
                    dir.path()
                        .join(format!("data/branches/main/state.db{suffix}")),
                );
            }
        }
        let d = Daemon::start(dir.path(), &[]);
        assert_eq!(d.turns().len(), 1, "the record was applied ({drop_state})");
        let (status, body) = call(&d.http, &write_request(250_000, "k3"));
        assert_eq!(status, 200);
        assert!(
            body == pattern(250_000),
            "the saved answer streams its blob"
        );
        assert_eq!(d.turns().len(), 1, "no second execution");
    }
}

/// Criterion 3: the actor holds a blob; a turn that releases it is killed
/// before its commit. After the restart the actor still holds it, and a new
/// turn reads it.
#[test]
fn a_crash_before_commit_keeps_a_released_hold() {
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(dir.path(), &["--test-hold", "before-commit"]);
    d.media();
    let put = d.ok("put", "size=3000");
    let held = hash(&pattern(3000));
    assert_eq!(put, format!("blob {held} 3000"));
    assert_eq!(d.holds(), std::slice::from_ref(&held));
    d.crash_at_hold(request("release", ""));
    let d = Daemon::start(dir.path(), &[]);
    assert_eq!(d.holds(), [held], "the release did not commit");
    assert_eq!(d.ok("held-sum", ""), pattern_sum(3000));
}

/// Criterion 4: a turn that retains a borrowed blob (an upload), and one
/// that puts a blob, are killed before their commits. After each restart
/// the actor holds nothing new, and the bytes those turns left are loose.
#[test]
fn a_crash_before_commit_adds_no_hold() {
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(dir.path(), &["--test-hold", "before-commit"]);
    d.media();
    // A body above the blob threshold (1 MiB) is an upload: the turn
    // borrows it, and `retain` would make the actor hold it.
    let body = vec![b'u'; (1 << 20) + 4096];
    let mut retain = format!(
        "POST /media/a/retain HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    retain.extend_from_slice(&body);
    d.crash_at_hold(retain);
    let mut d = Daemon::start(dir.path(), &["--test-hold", "before-commit"]);
    assert!(d.holds().is_empty(), "the retain did not commit");
    let upload = hash(&body);
    assert_eq!(d.plan(), [(upload.clone(), "loose".to_owned())]);

    d.crash_at_hold(request("put", "size=5000"));
    let d = Daemon::start(dir.path(), &[]);
    assert!(d.holds().is_empty(), "the put did not commit");
    let put = hash(&pattern(5000));
    let mut expected = vec![(upload, "loose".to_owned()), (put, "loose".to_owned())];
    expected.sort();
    assert_eq!(d.plan(), expected);
}

/// Criterion 9: a put's record is in the log and not applied when the
/// daemon is killed. The restart applies it, also from the log alone
/// (`state.db` deleted): the actor holds the blob, a new turn reads it, and
/// a pass keeps it.
#[test]
fn a_crash_before_apply_rebuilds_the_edge() {
    for drop_state in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Daemon::start(dir.path(), &["--test-hold", "record-appended"]);
        d.media();
        d.crash_at_hold(request("put", "size=4000"));
        if drop_state {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(
                    dir.path()
                        .join(format!("data/branches/main/state.db{suffix}")),
                );
            }
        }
        let d = Daemon::start(dir.path(), &[]);
        let held = hash(&pattern(4000));
        assert_eq!(
            d.holds(),
            std::slice::from_ref(&held),
            "state.db deleted: {drop_state}"
        );
        assert_eq!(d.ok("held-sum", ""), pattern_sum(4000));
        let pass = d.gc(true);
        assert_eq!(pass["deleted"], 0, "{pass}");
        let inspect = d.api("GET", &format!("/v1/blobs/{held}"), Value::Null);
        assert_eq!(inspect["state"], "live", "{inspect}");
        assert!(
            inspect["roots"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["kind"] == "held" && r["actor"] == "media/a"),
            "{inspect}"
        );
    }
}
