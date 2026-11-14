//! M25 acceptance (docs/design/m25-streaming-bodies.md §17, criteria 1-4)
//! with a real `kronik serve` and the test guest `media`: an upload becomes
//! a blob with constant memory; a fetched PDF is a blob and a fork replays
//! it to the same hash; the log holds only hashes above the threshold; a
//! large response streams with constant memory. Criterion 5 is
//! `kronik-sched`'s `tests/blobs.rs` (and `kronik-fork`'s for the replay).
//!
//! Memory is the daemon's peak RSS (`VmHWM`): two sizes a factor of ten
//! apart grow it by the same amount within 16 MiB, and neither by more than
//! the threshold + 48 MiB over a warm-up request. CI runs the scaled sizes;
//! `KRONIK_M25_FULL=1` runs the test VPS's (`scripts/acceptance-m25.sh`),
//! and the peaks are printed for `docs/perf.md`.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");
const MB: u64 = 1_000_000;
const MIB: u64 = 1 << 20;
/// The default blob threshold.
const THRESHOLD: u64 = MIB;

/// The test VPS's sizes instead of CI's.
fn full() -> bool {
    std::env::var_os("KRONIK_M25_FULL").is_some()
}

/// The daemon: this build's, or `KRONIK_M25_KRONIK` (a test machine runs
/// the test binary and a static `kronik` away from the checkout).
fn kronik_bin() -> PathBuf {
    std::env::var_os("KRONIK_M25_KRONIK").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_kronik")),
        PathBuf::from,
    )
}

/// The test guest: the checkout's, or `KRONIK_M25_MEDIA`.
fn media_wasm() -> Vec<u8> {
    let path =
        std::env::var_os("KRONIK_M25_MEDIA").map_or_else(|| PathBuf::from(MEDIA), PathBuf::from);
    std::fs::read(path).unwrap()
}

struct Daemon {
    dir: PathBuf,
    child: Option<Child>,
    http: String,
}

impl Daemon {
    fn start(dir: &Path) -> Daemon {
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

    /// Deploys `media`, with fuel for megabytes of byte-at-a-time work, room
    /// for large responses and uploads, and `http:127.0.0.1`.
    fn media(&self) {
        let wasm = base64::engine::general_purpose::STANDARD.encode(media_wasm());
        self.api(
            "POST",
            "/v1/deployments",
            json!({"wasm_base64": wasm, "reason": "M25 acceptance"}),
        );
        self.api(
            "POST",
            "/v1/limits",
            json!({
                "kind": "media",
                "fuel": 40_000_000_000u64,
                "upload_bytes": 2u64 << 30,
                "effect_response_bytes": 2u64 << 30,
                "reason": "M25 acceptance",
            }),
        );
        self.api(
            "POST",
            "/v1/grants",
            json!({"kind": "media", "capability": "http:127.0.0.1", "reason": "M25 acceptance"}),
        );
    }

    /// The daemon's peak resident memory so far, in bytes.
    fn peak(&self) -> u64 {
        let pid = self.child.as_ref().unwrap().id();
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        status
            .lines()
            .find_map(|l| l.strip_prefix("VmHWM:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            .unwrap()
            * 1024
    }

    /// SIGTERM, then waits for the daemon to exit.
    fn stop(&mut self) {
        let mut child = self.child.take().unwrap();
        Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status()
            .unwrap();
        for _ in 0..400 {
            if child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        panic!("kronik serve did not stop: {}", self.log());
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

/// Seeded bytes (xorshift64*), generated as they are needed.
struct Seeded(u64);

impl Seeded {
    fn new(seed: u64) -> Seeded {
        Seeded(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            let v = self.0.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// `len` seeded bytes in 64 KiB chunks (a multiple of 8, so the stream is
/// the same whatever reads it); `pdf` puts `%PDF-1.7\n` first.
fn each_chunk(seed: u64, len: u64, pdf: bool, mut f: impl FnMut(&[u8])) {
    let mut source = Seeded::new(seed);
    let mut buf = vec![0u8; 64 << 10];
    let mut sent = 0u64;
    while sent < len {
        let n = (len - sent).min(buf.len() as u64) as usize;
        source.fill(&mut buf[..n]);
        if pdf && sent == 0 {
            let head = b"%PDF-1.7\n";
            let k = head.len().min(n);
            buf[..k].copy_from_slice(&head[..k]);
        }
        f(&buf[..n]);
        sent += n as u64;
    }
}

/// The BLAKE3 identity of a body without a subject.
fn identity(seed: u64, len: u64, pdf: bool) -> String {
    let mut h = blake3::Hasher::new();
    each_chunk(seed, len, pdf, |c| {
        h.update(c);
    });
    format!("b3:{}", h.finalize().to_hex())
}

/// A request body for [`call`].
enum Send {
    Bytes(Vec<u8>),
    Seeded { seed: u64, len: u64 },
}

/// An answer: its status and headers, its body's size and BLAKE3 identity,
/// and the body itself when it is small.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    len: u64,
    hash: String,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The LSN of the turn that answered.
    fn lsn(&self) -> u64 {
        let id = self.header("kronik-turn-id").unwrap();
        id.rsplit(':').next().unwrap().parse().unwrap()
    }
}

/// One request through the gateway; the answer is read as it arrives.
fn call(http: &str, method: &str, target: &str, body: Send) -> Reply {
    let mut s = TcpStream::connect(http).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(600))).unwrap();
    let len = match &body {
        Send::Bytes(b) => b.len() as u64,
        Send::Seeded { len, .. } => *len,
    };
    write!(
        s,
        "{method} {target} HTTP/1.1\r\nhost: x\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n"
    )
    .unwrap();
    match body {
        Send::Bytes(b) => s.write_all(&b).unwrap(),
        Send::Seeded { seed, len } => each_chunk(seed, len, false, |c| s.write_all(c).unwrap()),
    }
    let mut r = BufReader::with_capacity(64 << 10, s);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut headers = Vec::new();
    let mut length = None;
    loop {
        let mut h = String::new();
        r.read_line(&mut h).unwrap();
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':').unwrap();
        if k.eq_ignore_ascii_case("content-length") {
            length = v.trim().parse::<u64>().ok();
        }
        headers.push((k.to_owned(), v.trim().to_owned()));
    }
    let mut hasher = blake3::Hasher::new();
    let mut body = Vec::new();
    let mut read = 0u64;
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let want = match length {
            Some(n) if read >= n => break,
            Some(n) => (n - read).min(buf.len() as u64) as usize,
            None => buf.len(),
        };
        let n = r.read(&mut buf[..want]).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if read < MIB {
            body.extend_from_slice(&buf[..n]);
        }
        read += n as u64;
    }
    Reply {
        status,
        headers,
        len: read,
        hash: format!("b3:{}", hasher.finalize().to_hex()),
        body,
    }
}

/// Serves `GET /doc/<seed>/<len>` as a generated PDF, streamed, and counts
/// the requests.
fn doc_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap_or(0);
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                    line.clear();
                }
                seen.fetch_add(1, Ordering::SeqCst);
                let path = first.split_whitespace().nth(1).unwrap_or("");
                let mut parts = path.trim_start_matches("/doc/").split('/');
                let seed: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                let len: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                let mut stream = stream;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/pdf\r\ncontent-length: {len}\r\n\
                     connection: close\r\n\r\n"
                );
                each_chunk(seed, len, true, |c| {
                    let _ = stream.write_all(c);
                });
            });
        }
    });
    (addr, count)
}

/// Asserts the memory rule of §17 for the peak growths of two sizes a
/// factor of ten apart, and prints them.
fn constant_memory(what: &str, sizes: [u64; 2], growth: [u64; 2]) {
    for (size, g) in sizes.iter().zip(growth) {
        eprintln!(
            "M25 {what}: {} MB -> peak RSS +{:.1} MiB",
            size / MB,
            g as f64 / MIB as f64
        );
    }
    let limit = THRESHOLD + 48 * MIB;
    assert!(
        growth.iter().all(|g| *g <= limit),
        "{what}: the peak grew by {growth:?} bytes, more than {limit}"
    );
    assert!(
        growth[1].abs_diff(growth[0]) <= 16 * MIB,
        "{what}: the peak grew by {growth:?} bytes, not the same within 16 MiB"
    );
}

fn diff_summary(d: &Daemon, fork: &str, at: u64) -> Value {
    d.api(
        "POST",
        "/v1/forks",
        json!({"at": at, "name": fork, "reason": "M25 acceptance"}),
    );
    d.api(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"options": {"mode": "both"}, "reason": "M25 acceptance"}),
    );
    let diff = d.api("GET", &format!("/v1/forks/{fork}/diff"), Value::Null);
    let summary = diff
        .get("summary")
        .or_else(|| diff.get("diff").and_then(|d| d.get("summary")))
        .cloned()
        .unwrap_or_else(|| panic!("no summary: {diff}"));
    assert_eq!(summary["divergent_turns"], 0, "{diff}");
    summary
}

/// Criterion 1: an upload is a blob whose identity is the client's BLAKE3,
/// with constant memory.
#[test]
fn an_upload_is_a_blob_with_constant_memory() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path());
    d.media();
    let warm = call(
        &d.http,
        "POST",
        "/media/a/info",
        Send::Seeded {
            seed: 1,
            len: 2 * MIB + 8,
        },
    );
    assert!(warm.text().starts_with("blob "), "{}", warm.text());
    let base = d.peak();
    let sizes = if full() {
        [30 * MB, 300 * MB]
    } else {
        [8 * MB, 80 * MB]
    };
    let mut growth = [0; 2];
    for (i, size) in sizes.into_iter().enumerate() {
        let seed = 2 + i as u64;
        let r = call(
            &d.http,
            "POST",
            "/media/a/info",
            Send::Seeded { seed, len: size },
        );
        assert_eq!(r.status, 200, "{}", r.text());
        assert_eq!(
            r.text(),
            format!("blob {} {size}", identity(seed, size, false))
        );
        growth[i] = d.peak().saturating_sub(base);
    }
    constant_memory("upload", sizes, growth);
}

/// Criterion 2: a fetched PDF is a blob; a fork replays it, in both modes,
/// to the same hash with no difference, and the server saw one request per
/// production fetch.
#[test]
fn a_fetched_pdf_is_a_blob_and_replays_to_the_same_hash() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path());
    d.media();
    let (server, requests) = doc_server();
    let fetch = |seed: u64, len: u64| {
        call(
            &d.http,
            "POST",
            "/media/a/fetch",
            Send::Bytes(format!("http://{server}/doc/{seed}/{len}").into_bytes()),
        )
    };
    let warm = fetch(1, 2 * MIB);
    assert!(warm.text().contains(" blob "), "{}", warm.text());
    let base = d.peak();
    let sizes = [4 * MB, 40 * MB];
    let mut growth = [0; 2];
    let mut first = None;
    for (i, size) in sizes.into_iter().enumerate() {
        let seed = 7 + i as u64;
        let r = fetch(seed, size);
        assert_eq!(
            r.text(),
            format!("status 200 blob {} {size}", identity(seed, size, true))
        );
        first.get_or_insert(r.lsn());
        growth[i] = d.peak().saturating_sub(base);
    }
    constant_memory("fetch", sizes, growth);
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    let summary = diff_summary(&d, "pdf", first.unwrap() - 1);
    assert!(summary["replayed"].as_u64().unwrap() >= 2, "{summary}");
    assert_eq!(
        requests.load(Ordering::SeqCst),
        3,
        "the replay served the recordings"
    );
}

/// Every 4 KiB window at sixteen offsets of a body of `len` seeded bytes.
fn windows(seed: u64, len: u64, pdf: bool) -> Vec<Vec<u8>> {
    let mut all = Vec::with_capacity(len as usize);
    each_chunk(seed, len, pdf, |c| all.extend_from_slice(c));
    (0..16)
        .map(|k| {
            let at = (len - 4096) * k / 15;
            all[at as usize..at as usize + 4096].to_vec()
        })
        .collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    let head = &needle[..8];
    hay.windows(needle.len())
        .any(|w| &w[..8] == head && w == needle)
}

fn records(dir: &Path) -> Vec<kronik_proto::Record> {
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

/// Criterion 3: the log holds only the hash above the threshold; a body of
/// the threshold stays inline and one byte more does not; an identity
/// replay of a turn that reads three ranges has no difference.
#[test]
fn the_log_holds_only_the_hash_above_the_threshold() {
    use kronik_proto::log::v1 as pb;
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(dir.path());
    d.media();
    let (server, _) = doc_server();
    let upload = call(
        &d.http,
        "POST",
        "/media/a/info",
        Send::Seeded {
            seed: 11,
            len: 4 * MB,
        },
    );
    let upload_hash = identity(11, 4 * MB, false);
    assert_eq!(upload.text(), format!("blob {upload_hash} {}", 4 * MB));
    let fetched = call(
        &d.http,
        "POST",
        "/media/a/fetch",
        Send::Bytes(format!("http://{server}/doc/12/{}", 4 * MB).into_bytes()),
    );
    let pdf_hash = identity(12, 4 * MB, true);
    assert_eq!(
        fetched.text(),
        format!("status 200 blob {pdf_hash} {}", 4 * MB)
    );
    let at = call(
        &d.http,
        "POST",
        "/media/a/info",
        Send::Seeded {
            seed: 13,
            len: THRESHOLD,
        },
    );
    assert_eq!(at.text(), format!("inline {THRESHOLD}"));
    let over = call(
        &d.http,
        "POST",
        "/media/a/info",
        Send::Seeded {
            seed: 14,
            len: THRESHOLD + 1,
        },
    );
    assert!(over.text().starts_with("blob "), "{}", over.text());
    let ranges = call(
        &d.http,
        "POST",
        "/media/a/ranges?at=0:1000,1500000:4096,2999000:1000",
        Send::Seeded {
            seed: 15,
            len: 3 * MB,
        },
    );
    assert_eq!(ranges.status, 200, "{}", ranges.text());
    assert_eq!(ranges.text().lines().count(), 3, "{}", ranges.text());
    diff_summary(&d, "ranges", ranges.lsn() - 1);
    d.stop();

    // No 4 KiB window of a body above the threshold is in the log.
    let log_dir = dir.path().join("data/branches/main/log");
    let segments: Vec<Vec<u8>> = std::fs::read_dir(&log_dir)
        .unwrap()
        .flatten()
        .map(|e| std::fs::read(e.path()).unwrap())
        .collect();
    for (seed, len, pdf) in [
        (11, 4 * MB, false),
        (12, 4 * MB, true),
        (14, THRESHOLD + 1, false),
        (15, 3 * MB, false),
    ] {
        for w in windows(seed, len, pdf) {
            assert!(
                !segments.iter().any(|s| contains(s, &w)),
                "a window of body {seed} is in the log"
            );
        }
    }
    // The records hold the references.
    let mut inputs = Vec::new();
    let mut responses = Vec::new();
    for record in records(dir.path()) {
        let kronik_proto::Record::TurnRecord(t) = record else {
            continue;
        };
        if let Some(pb::input::Kind::Http(h)) = t.input.as_ref().and_then(|i| i.kind.as_ref())
            && let Some(pb::body::Value::Blob(b)) = h.body.as_ref().and_then(|b| b.value.as_ref())
        {
            inputs.push((b.hash.clone(), b.size));
        }
        for e in &t.effects {
            if let Some(pb::sealable::Value::Plain(bytes)) =
                e.response.as_ref().and_then(|r| r.value.as_ref())
                && let Ok(resp) =
                    <pb::HttpEffectResponse as prost::Message>::decode(bytes.as_slice())
                && let Some(b) = resp.body_blob
            {
                assert!(resp.body.is_empty());
                responses.push((b.hash.clone(), b.size));
            }
        }
    }
    assert!(inputs.contains(&(upload_hash, 4 * MB)), "{inputs:?}");
    assert_eq!(inputs.len(), 3, "{inputs:?}");
    assert_eq!(responses, [(pdf_hash, 4 * MB)]);
}

/// Criterion 4: a large response streams with constant memory: a fetched
/// document answered as the response, and 16 MiB written with `writer`.
#[test]
fn a_large_response_streams_with_constant_memory() {
    large_responses(if full() {
        [100 * MB, 1000 * MB]
    } else {
        [12 * MB, 120 * MB]
    });
}

fn large_responses(sizes: [u64; 2]) {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path());
    d.media();
    let (server, requests) = doc_server();
    let echo = |seed: u64, len: u64| {
        call(
            &d.http,
            "POST",
            "/media/a/fetch-echo",
            Send::Bytes(format!("http://{server}/doc/{seed}/{len}").into_bytes()),
        )
    };
    let warm = echo(1, 2 * MIB);
    assert_eq!(warm.len, 2 * MIB);
    let base = d.peak();
    let mut growth = [0; 2];
    for (i, size) in sizes.into_iter().enumerate() {
        let seed = 20 + i as u64;
        let r = echo(seed, size);
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-length"), Some(size.to_string().as_str()));
        assert_eq!((r.len, r.hash), (size, identity(seed, size, true)));
        growth[i] = d.peak().saturating_sub(base);
    }
    constant_memory("response", sizes, growth);
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    // Written by the actor and answered: the `write` pattern.
    let size = 16 * MIB;
    let r = call(
        &d.http,
        "POST",
        &format!("/media/a/write?size={size}"),
        Send::Bytes(Vec::new()),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let mut h = blake3::Hasher::new();
    let pattern: Vec<u8> = (0..size).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    h.update(&pattern);
    assert_eq!(
        (r.len, r.hash),
        (size, format!("b3:{}", h.finalize().to_hex()))
    );
}
