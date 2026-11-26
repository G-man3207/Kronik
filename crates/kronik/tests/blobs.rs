//! What a timer keeps through the retention window, with a real `kronik
//! serve` whose window is seconds long (docs/design/m26-blobs.md §17;
//! criteria 6 and 13): a blob whose only root is a timer survives the
//! compaction of every record that referenced it and the collector's
//! passes, and the timer's turn reads it when it fires; shipped and
//! restored with `kronik restore` into a new directory, the restored
//! node's timer does the same.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

#[path = "support/blob_fixtures.rs"]
mod blob_fixtures;
mod common;
#[path = "support/media_daemon.rs"]
mod media_daemon;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use blob_fixtures::{hash, pattern, pattern_sum};
use common::Daemon;
use media_daemon::kronik_bin;
use serde_json::{Value, json};

/// A window of seconds: segments close after a second, a snapshot every
/// two seconds, and retention keeps two seconds of history.
const SHORT_RETENTION: &str = "[log]\nsegment_max_age_s = 1\n\n[retention]\nhistory = \"2s\"\n\
                               snapshot_interval = \"2s\"\nsnapshots_kept = 1\n";

impl Daemon {
    /// `kronik serve` on `<dir>/data`, with blobs and the window of seconds
    /// of [`SHORT_RETENTION`].
    fn start(dir: &Path, args: &[&str]) -> Daemon {
        let mut command = Daemon::command(kronik_bin(), dir, Some(SHORT_RETENTION));
        command.args(args);
        Daemon::spawn(dir, command)
    }
}

impl Daemon {
    /// The floor of the blob collector: records at or after it keep their
    /// blobs.
    fn floor(&self) -> u64 {
        self.api("GET", "/v1/blobs", Value::Null)["floor"]
            .as_u64()
            .unwrap()
    }

    /// The LSN of `media/a`'s newest turn.
    fn last_turn_lsn(&self) -> u64 {
        let v = self.api("GET", "/v1/actors/media/a/history?limit=1", Value::Null);
        let id = v["turns"][0]["turn_id"].as_str().unwrap();
        id.rsplit(':').next().unwrap().parse().unwrap()
    }

    /// Turns go on until retention has moved the floor past `lsn`: no
    /// record at or before it keeps a blob any more.
    fn past_the_window(&self, lsn: u64) {
        let started = Instant::now();
        while self.floor() <= lsn {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "retention did not move the floor past lsn {lsn}: {}",
                self.log()
            );
            self.ok("info", "");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Waits until `media/a` holds `hash` (a timer's `retain` ran).
    fn wait_held(&self, hash: &str, within: Duration) {
        let started = Instant::now();
        while !self.holds().iter().any(|h| h == hash) {
            assert!(
                started.elapsed() < within,
                "the timer never retained {hash}: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// How long the timers of these tests wait: longer than the window takes to
/// pass on a loaded machine, so that the timer is still pending when the
/// test checks what keeps its blob.
const TIMER_DELAY: Duration = Duration::from_secs(90);

/// `media/a` puts a blob, schedules a timer whose message carries it, due
/// after `delay`, and releases it: the timer is the blob's only root.
/// Returns the blob's identity, the LSN of the release and when the timer
/// was scheduled.
fn timer_only_blob(d: &Daemon, size: u64, delay: Duration) -> (String, u64, Instant) {
    d.media();
    let blob = hash(&pattern(size));
    assert_eq!(
        d.ok("put", &format!("size={size}")),
        format!("blob {blob} {size}")
    );
    let scheduled = Instant::now();
    assert_eq!(
        d.ok(
            "schedule",
            &format!("delay={}&op=retain", delay.as_millis())
        ),
        "scheduled"
    );
    assert_eq!(d.ok("release", ""), "released");
    assert!(d.holds().is_empty());
    (blob, d.last_turn_lsn(), scheduled)
}

/// The timer must still be pending: the test's steps since it was
/// scheduled took less than its delay.
fn timer_pending(d: &Daemon, scheduled: Instant, delay: Duration) {
    assert!(
        d.holds().is_empty(),
        "the timer fired {:?} after it was scheduled, before the test's checks \
         (its delay is {delay:?}): the machine is too loaded for this test",
        scheduled.elapsed()
    );
}

/// Criterion 6: a blob whose only root is a timer survives the window: the
/// records that created and referenced it leave the log, two immediate
/// passes run, and it is still there, kept by the timer; when the timer
/// fires, its turn retains it and the actor reads the right bytes.
#[test]
fn a_timer_outlives_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), &[]);
    let (blob, released, scheduled) = timer_only_blob(&d, 4000, TIMER_DELAY);
    d.past_the_window(released);
    assert!(
        !d.plan().iter().any(|(h, _)| *h == blob),
        "the dry run would delete the timer's blob"
    );
    for _ in 0..2 {
        d.gc(true);
    }
    let inspect = d.api("GET", &format!("/v1/blobs/{blob}"), Value::Null);
    assert_eq!(inspect["state"], "live", "{inspect}");
    let roots = inspect["roots"].as_array().unwrap();
    assert!(
        roots
            .iter()
            .any(|r| r["kind"] == "pin" && r["source"] == "timer"),
        "{inspect}"
    );
    assert!(!roots.iter().any(|r| r["kind"] == "log"), "{inspect}");
    timer_pending(&d, scheduled, TIMER_DELAY);
    d.wait_held(&blob, TIMER_DELAY + Duration::from_secs(60));
    assert_eq!(d.ok("held-sum", ""), pattern_sum(4000));
}

/// Criterion 13, with the release's binary: the same timer-only blob,
/// shipped to a `file://` bucket after its records left the log, restored
/// with `kronik restore` into a new directory; the restore reports no
/// missing blob, and the restored node's timer retains it and the actor
/// reads the right bytes.
#[test]
fn restore_keeps_a_timer_only_blob() {
    let dir = tempfile::tempdir().unwrap();
    let bucket = tempfile::tempdir().unwrap();
    let url = format!("file://{}", bucket.path().display());
    let d = Daemon::start(dir.path(), &[]);
    // The restore comes after the window too: a longer delay.
    let delay = TIMER_DELAY + Duration::from_secs(30);
    let (blob, released, scheduled) = timer_only_blob(&d, 6000, delay);
    d.past_the_window(released);
    d.api(
        "POST",
        "/v1/snapshots",
        json!({"reason": "before the restore"}),
    );
    timer_pending(&d, scheduled, delay);
    let data = d.data();
    drop(d);
    ship_now(&data, &url);

    let dest = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dest.path().join("data/keys")).unwrap();
    std::fs::copy(
        data.join("keys/master.key"),
        dest.path().join("data/keys/master.key"),
    )
    .unwrap();
    let restored = kronik(&[
        "--json",
        "restore",
        "--from",
        &url,
        "--data-dir",
        dest.path().join("data").to_str().unwrap(),
    ]);
    assert!(restored.status.success(), "{restored:?}");
    let v: Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(v["blobs"]["missing"], json!([]), "{v}");
    let r = Daemon::start(dest.path(), &[]);
    let id = blob.strip_prefix("b3:").unwrap();
    assert_eq!(
        objects_named(&r.data(), id).len(),
        1,
        "the restore brought the blob's file into main's store"
    );
    r.wait_held(&blob, delay + Duration::from_secs(60));
    assert_eq!(r.ok("held-sum", ""), pattern_sum(6000));
}

/// The files of main's blob store whose name holds the digest `id`.
fn objects_named(data: &Path, id: &str) -> Vec<PathBuf> {
    fn walk(dir: &Path, id: &str, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            if e.path().is_dir() {
                walk(&e.path(), id, out);
            } else if e.file_name().to_string_lossy().contains(id) {
                out.push(e.path());
            }
        }
    }
    let mut out = Vec::new();
    walk(&data.join("blobs/objects"), id, &mut out);
    out
}

/// `kronik` with `args`, without the settings the environment could add.
fn kronik(args: &[&str]) -> Output {
    Command::new(kronik_bin())
        .args(args)
        .env_remove("KRONIK_TOKEN")
        .env_remove("KRONIK_CONFIG")
        .env_remove("KRONIK_DATA_DIR")
        .env_remove("KRONIK_MASTER_KEY_FILE")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// One shipping round of the stopped daemon's directory into `url`.
fn ship_now(data: &Path, url: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let remote = kronik_ship::Remote::open(url, None).unwrap();
        let mut state = kronik_ship::ShipState::load(data).unwrap();
        kronik_ship::ship_once(&remote, data, "main", &mut state)
            .await
            .unwrap();
    });
}
