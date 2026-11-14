//! What a timer keeps through the retention window, with a real `kronik
//! serve` whose window is seconds long (docs/design/m26-blobs.md §17;
//! criteria 6 and 13): a blob whose only root is a timer survives the
//! compaction of every record that referenced it and the collector's
//! passes, and the timer's turn reads it when it fires; shipped and
//! restored with `kronik restore` into a new directory, the restored
//! node's timer does the same.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Value, json};

/// A window of seconds: segments close after a second, a snapshot every
/// two seconds, and retention keeps two seconds of history.
const SHORT_RETENTION: &str = "[log]\nsegment_max_age_s = 1\n\n[retention]\nhistory = \"2s\"\n\
                               snapshot_interval = \"2s\"\nsnapshots_kept = 1\n";

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
    /// `kronik serve` on `<dir>/data`, with blobs and the window of seconds
    /// of [`SHORT_RETENTION`].
    fn start(dir: &Path, args: &[&str]) -> Daemon {
        let config = dir.join("kronik.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\n\n{SHORT_RETENTION}",
                dir.join("data")
            ),
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
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
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

/// `POST /media/a/<op>?<query>` without a body.
fn request(op: &str, query: &str) -> String {
    format!(
        "POST /media/a/{op}?{query} HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\
         connection: close\r\n\r\n"
    )
}

/// The identity of a blob without a subject: `b3:` and its BLAKE3.
fn hash(bytes: &[u8]) -> String {
    format!("b3:{}", blake3::hash(bytes).to_hex())
}

/// What the media guest's `sum` and `held-sum` answer for `size` bytes of
/// the pattern: the size and its FNV-1a 64 digest.
fn pattern_sum(size: u64) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in pattern(size) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{size} {h:016x}")
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

    fn stop(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
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
    d.stop();
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
