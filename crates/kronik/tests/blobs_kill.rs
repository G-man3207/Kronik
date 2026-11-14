//! Crashes around a turn that writes a blob (docs/design/m26-blobs.md §11,
//! §17), with a real `kronik serve`, its hidden `--test-hold` and `kill -9`:
//! after the blob's finish and before the record, the bytes are loose and
//! nothing records them; before the commit, the blob is durable and nothing
//! records it; after the record's sync and before its apply, the restart
//! applies it (also from the log alone) and its blob answers.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

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
            format!(
                "[server]\ndata_dir = {:?}\n\n[blobs]\nenabled = true\n",
                dir.join("data")
            ),
        )
        .unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_kronik"))
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
        let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(MEDIA).unwrap());
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

    /// Arms the hold, sends `request` on a thread of its own (it never gets
    /// an answer), waits until a turn waits at the hold, then kills the
    /// daemon with SIGKILL.
    fn crash_at_hold(&mut self, request: String) {
        std::fs::write(self.data().join("test-hold-armed"), b"").unwrap();
        let http = self.http.clone();
        std::thread::spawn(move || {
            if let Ok(mut s) = TcpStream::connect(http) {
                let _ = s.write_all(request.as_bytes());
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

fn pattern(n: u64) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 7) % 251) as u8).collect()
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
