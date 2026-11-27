//! Shared helpers of the tests that run the `kronik` binary.

// Each test binary uses only part of this module.
#![allow(dead_code)]

use std::collections::hash_map::RandomState;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions, Permissions};
use std::hash::{BuildHasher, Hasher};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

/// The settings `kronik` reads from the environment, removed from every
/// command the tests run so that the developer's shell cannot change
/// them: the union of the lists the test files kept on their own.
pub const SETTINGS_ENV: [&str; 14] = [
    "KRONIK_CONFIG",
    "KRONIK_DATA_DIR",
    "KRONIK_HTTP_LISTEN",
    "KRONIK_ADMIN_LISTEN",
    "KRONIK_API_SOCKET",
    "KRONIK_API_LISTEN",
    "KRONIK_MASTER_KEY_FILE",
    "KRONIK_MASTER_KEY",
    "KRONIK_TOKEN",
    "KRONIK_URL",
    "KRONIK_OTEL_ENDPOINT",
    "KRONIK_AUDIT_SINK",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// `kronik` without the developer's settings, with no disk reserve (the
/// tests' file system may have less than the reserve) and stdin null.
pub fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kronik"));
    for var in SETTINGS_ENV {
        command.env_remove(var);
    }
    command.env("KRONIK_DISK_RESERVE", "0B");
    command.stdin(Stdio::null());
    command
}

/// What a `kronik` run printed and how it exited.
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl std::fmt::Debug for Out {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit {}\nstdout:\n{}\nstderr:\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

impl Out {
    /// stdout as JSON; panics with the whole output when it is not.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("{e}: {self:?}"))
    }
}

impl From<Output> for Out {
    fn from(out: Output) -> Out {
        Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }
}

/// Where every test process claims the ports it hands out, whatever its
/// target directory.
const CLAIMS_DIR: &str = "/var/tmp/kronik-test-ports";

/// The claims of this process, held until it exits.
static CLAIMS: Mutex<Vec<File>> = Mutex::new(Vec::new());

/// A port for `kronik serve` to bind later.
///
/// A port that `bind(127.0.0.1:0)` found free can be taken before the
/// daemon binds it, by a concurrent test or by the kernel, which hands the
/// ports of its ephemeral range to other `bind(0)` and `connect` calls; the
/// daemon then stops with "Address already in use". So the port comes from
/// below the ephemeral range, which the kernel never hands out. It is free
/// now, and it is claimed with a lock in [`CLAIMS_DIR`] that every test
/// process honours until this one exits.
pub fn free_port() -> u16 {
    let dir = Path::new(CLAIMS_DIR);
    std::fs::create_dir_all(dir).unwrap();
    // Every user's test runs share it, as they share /tmp.
    let _ = std::fs::set_permissions(dir, Permissions::from_mode(0o1777));
    let (low, high) = below_ephemeral();
    for _ in 0..10_000 {
        let port =
            low + (RandomState::new().build_hasher().finish() % u64::from(high - low)) as u16;
        // A claim another user's run made can't be opened here: taken too.
        let Ok(claim) = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(port.to_string()))
        else {
            continue;
        };
        if claim.try_lock().is_ok() && TcpListener::bind(("127.0.0.1", port)).is_ok() {
            CLAIMS.lock().unwrap().push(claim);
            return port;
        }
    }
    panic!("no free port in {low}..{high}");
}

/// The ports below the kernel's ephemeral range (32768 to 60999 by
/// default), down to half its start.
fn below_ephemeral() -> (u16, u16) {
    let start: u16 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse().ok())
        .unwrap_or(32768);
    assert!(
        start >= 4096,
        "the ephemeral port range starts at {start}: no room below it for test ports"
    );
    (start / 2, start)
}

/// A plain HTTP server on `ip`, on a port of its own, that answers every
/// request with 200 and `body` until the test process exits: its
/// address (`ip:port`) and how many requests it accepted.
// A test harness thread, not daemon code (ADR 0004).
#[allow(clippy::disallowed_methods)]
pub fn http_target(ip: &str, body: &'static str) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((ip, 0)).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            counted.fetch_add(1, Ordering::SeqCst);
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (addr, hits)
}

/// One request to the API on the Unix socket `socket`, as `token` when
/// given; `Value::Null` sends no body. The status and the JSON body;
/// `None` when the socket refuses, the answer is cut short or its body
/// is not JSON.
pub fn try_api(
    socket: &Path,
    method: &str,
    path: &str,
    body: &Value,
    token: Option<&str>,
) -> Option<(u16, Value)> {
    let mut s = UnixStream::connect(socket).ok()?;
    let body = if body.is_null() {
        String::new()
    } else {
        body.to_string()
    };
    let auth = token.map_or(String::new(), |t| format!("authorization: Bearer {t}\r\n"));
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nhost: kronik\r\n{auth}content-length: {}\r\n\
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

/// One HTTP answer, parsed by [`read_answer`].
pub struct Answer {
    pub status: u16,
    /// Lower-case names, trimmed values, in order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Answer {
    /// The first value of header `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One HTTP/1.1 answer from `reader`: a chunked body, a `content-length`
/// one, or everything to the end. Panics on a malformed answer.
pub fn read_answer(reader: impl std::io::Read) -> Answer {
    let mut reader = BufReader::new(reader);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or_else(|| panic!("no status in {head:?}"));
    let headers: Vec<(String, String)> = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let header = |name: &str| {
        headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    };
    let mut body = Vec::new();
    if header("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).unwrap();
            let size = usize::from_str_radix(size.trim(), 16).unwrap();
            let mut chunk = vec![0; size + 2];
            reader.read_exact(&mut chunk).unwrap();
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(len) = header("content-length") {
        body = vec![0; len.parse().unwrap()];
        reader.read_exact(&mut body).unwrap();
    } else {
        reader.read_to_end(&mut body).unwrap();
    }
    Answer {
        status,
        headers,
        body,
    }
}

/// Every record of the `main` branch's log under `<dir>/data`, read while
/// the daemon runs (only fsynced records exist) or after it died.
pub fn log_records(dir: &Path) -> Vec<kronik_proto::Record> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
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

/// Every file under `dir`, recursively, whose bytes contain `needle`.
pub fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(p) = todo.pop() {
        if p.is_dir() {
            todo.extend(std::fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
        } else if std::fs::read(&p).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle)) {
            out.push(p);
        }
    }
    out
}

/// Ships the data directory `data` to the bucket `url` once, the way a
/// node does every few seconds (`kronik_ship::ship_once`), without a
/// running node.
pub fn ship_now(data: &Path, url: &str) {
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

/// Whether the snapshot at `lsn`, the code and the active segment as it
/// is now reach the bucket, by `<data>/ship.json`: polls every 200 ms, up
/// to 225 times (45 s).
pub fn wait_until_shipped(data: &Path, lsn: u64) -> bool {
    for _ in 0..225 {
        if let Ok(text) = std::fs::read_to_string(data.join("ship.json"))
            && let Ok(v) = serde_json::from_str::<Value>(&text)
            && v["snapshots"]
                .as_array()
                .is_some_and(|a| a.iter().any(|n| n.as_u64() == Some(lsn)))
            && v["code"].as_array().is_some_and(|a| !a.is_empty())
            && let Some(start) = v["active"][0].as_u64()
            && let Some(size) = v["active"][1].as_u64()
            && std::fs::metadata(data.join(format!("branches/main/log/{start:020}.seg")))
                .is_ok_and(|m| m.len() == size)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// `kronik serve` as a child process, with its data in `<dir>/data`, its
/// API socket at `<dir>/api.sock` and its stderr appended to
/// `<dir>/serve.log`; killed when dropped.
pub struct Daemon {
    pub dir: PathBuf,
    pub child: Option<Child>,
    /// The gateway's address, from `GET /v1/health`'s `http_listen`.
    pub http: String,
}

impl Daemon {
    /// `<bin> serve` for `dir`. With `Some(config)`: writes
    /// `<dir>/kronik.toml` as `format!("[server]\ndata_dir = {:?}\n\n{config}", dir.join("data"))`
    /// and passes `--config` with it; with `None`: `--data-dir <dir>/data`.
    /// Always: `--http-listen 127.0.0.1:0 --admin-listen 127.0.0.1:0
    /// --api-socket <dir>/api.sock`, `KRONIK_DISK_RESERVE=0B`,
    /// `KRONIK_LOG=info`, [`SETTINGS_ENV`] removed, stdin and stdout null.
    /// Callers add arguments or override env before `spawn`.
    pub fn command(bin: impl AsRef<OsStr>, dir: &Path, config: Option<&str>) -> Command {
        let mut command = Command::new(bin);
        command
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .env("KRONIK_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        for var in SETTINGS_ENV {
            command.env_remove(var);
        }
        match config {
            Some(config) => {
                let path = dir.join("kronik.toml");
                std::fs::write(
                    &path,
                    format!("[server]\ndata_dir = {:?}\n\n{config}", dir.join("data")),
                )
                .unwrap();
                command.arg("--config").arg(path);
            }
            None => {
                command.arg("--data-dir").arg(dir.join("data"));
            }
        }
        command
            .args([
                "--http-listen",
                "127.0.0.1:0",
                "--admin-listen",
                "127.0.0.1:0",
                "--api-socket",
            ])
            .arg(dir.join("api.sock"));
        command
    }

    /// Spawns `command` with stderr appended to `<dir>/serve.log` and
    /// waits until `GET /v1/health` answers 200: polls every 25 ms, up to
    /// 4800 times (120 s, the longest wait any copy uses); panics with the
    /// log at once if the process exits first, or after the last poll.
    /// Sets `http` from the answer's `http_listen` (`unwrap_or_default`).
    pub fn spawn(dir: &Path, mut command: Command) -> Daemon {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = command.stderr(log).spawn().unwrap();
        let mut d = Daemon {
            dir: dir.to_path_buf(),
            child: Some(child),
            http: String::new(),
        };
        for _ in 0..4800 {
            if let Some((200, v)) = d.try_api("GET", "/v1/health", Value::Null) {
                d.http = v["http_listen"].as_str().unwrap_or_default().to_owned();
                return d;
            }
            if d.child.as_mut().unwrap().try_wait().unwrap().is_some() {
                panic!("kronik serve exited: {}", d.log());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("kronik serve did not start: {}", d.log());
    }

    pub fn socket(&self) -> PathBuf {
        self.dir.join("api.sock")
    }

    pub fn data(&self) -> PathBuf {
        self.dir.join("data")
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    pub fn try_api(&self, method: &str, path: &str, body: Value) -> Option<(u16, Value)> {
        try_api(&self.socket(), method, path, &body, None)
    }

    pub fn api(&self, method: &str, path: &str, body: Value) -> Value {
        let (status, v) = self
            .try_api(method, path, body)
            .unwrap_or_else(|| panic!("{method} {path} failed: {}", self.log()));
        assert_eq!(status, 200, "{method} {path}: {v}");
        v
    }

    /// One request; any status. Panics with the log when there is no answer.
    pub fn call(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        self.try_api(method, path, body)
            .unwrap_or_else(|| panic!("API {method} {path} failed: {}", self.log()))
    }

    /// Polls `f` every 50 ms, up to 1800 times (90 s, secret_backends.rs's
    /// bound); panics with `what` and the log if it never holds.
    pub fn wait_until(&self, what: &str, f: impl Fn(&Daemon) -> bool) {
        for _ in 0..1800 {
            if f(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for {what}: {}", self.log());
    }

    /// SIGKILL and wait; errors ignored; no-op when already stopped.
    pub fn kill9(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// SIGTERM, then waits up to 10 s for the exit; panics with the log
    /// if it does not stop.
    pub fn term(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
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
        self.kill9();
    }
}
