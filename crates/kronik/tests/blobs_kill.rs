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
mod common;
#[path = "support/media_daemon.rs"]
mod media_daemon;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use blob_fixtures::{hash, pattern, pattern_sum};
use common::Daemon;
use media_daemon::{call, kronik_bin, request};
use serde_json::Value;

impl Daemon {
    fn start(dir: &Path, args: &[&str]) -> Daemon {
        let mut command = Daemon::command(kronik_bin(), dir, Some(""));
        command.args(args);
        Daemon::spawn(dir, command)
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

/// `POST /media/a/write?size=<n>` with an Idempotency-Key.
fn write_request(size: u64, key: &str) -> String {
    format!(
        "POST /media/a/write?size={size} HTTP/1.1\r\nhost: x\r\nidempotency-key: {key}\r\n\
         content-length: 0\r\nconnection: close\r\n\r\n"
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
