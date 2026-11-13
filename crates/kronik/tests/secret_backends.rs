//! M23 acceptance with a real `kronik serve` and a fake OpenBao server
//! (docs/design/m23-secret-backends.md §9, criteria 2 and 3):
//!
//! - **2**, a secret from an external backend gets a version hash in the log
//!   just as with the built-in store: the hash of a linked name equals the one
//!   a `file` node with the same master key computes for the same value, the
//!   effect records the same hash, and the value is in no file and in no
//!   answer of the API, the CLI or MCP;
//! - **3**, rotation shows up as a new version in `history`, while the old
//!   turn keeps its version and a fork replays the old turns identically; a
//!   crash re-run of a recorded `secret.reveal` gets the value of the recorded
//!   `source_version`, and `SECRET_VERSION_GONE` once the backend destroyed it,
//!   never the value of a later version;
//! - **I10**, a backend that hangs stops only the turns that need its secrets;
//!   a turn that meets the outage ends with a recorded `SECRET_UNAVAILABLE`
//!   and leaves no open `TurnBegin` for the next start to run, and a fork
//!   replays the recorded error without asking the backend.
//!
//! The backend is a local HTTP server that speaks the KV v2 shape of the
//! OpenBao client (`lookup-self`, `data/<path>?version=N`, `metadata/<path>`).

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use prost::Message as _;
use rmcp::model::{CallToolRequestParams, ReadResourceRequestParams};
use rmcp::service::{RoleClient, RunningService, ServiceExt as _};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, UnixSocketHttpClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests");

/// The master key of every node of these tests (64 hex characters): a `file`
/// node with the same key computes the same version hashes.
const MASTER_KEY: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
/// The token the fake backend accepts.
const BAO_TOKEN: &str = "bao-token-for-the-tests";

/// The values behind `secret/payments#stripe`, by KV version.
const VALUE_1: &str = "needle-one-5f3a9c21e7b04d68";
const VALUE_2: &str = "needle-two-91d0c4a7236be5f0";

// ------------------------------------------------------------- small servers

#[derive(Debug, Clone)]
struct Req {
    method: String,
    /// The path and the query.
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct Resp {
    status: u16,
    body: Vec<u8>,
}

impl Resp {
    fn json(status: u16, body: &Value) -> Resp {
        Resp {
            status,
            body: serde_json::to_vec(body).unwrap(),
        }
    }
}

type Handler = Arc<dyn Fn(&Req) -> Resp + Send + Sync>;

/// Serves `handler` on a free loopback port, one request per connection, on
/// threads that live until the test process exits. Returns the address.
fn serve(handler: Handler) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let handler = handler.clone();
            std::thread::spawn(move || connection(stream, &*handler));
        }
    });
    addr
}

fn connection(stream: TcpStream, handler: &(dyn Fn(&Req) -> Resp + Send + Sync)) {
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let target = parts.next().unwrap_or("").to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 {
            return;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let response = handler(&Req {
        method,
        target,
        headers,
        body,
    });
    let reason = match response.status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Service Unavailable",
    };
    let head = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response.status,
        response.body.len()
    );
    let _ = writer.write_all(head.as_bytes());
    let _ = writer.write_all(&response.body);
}

// -------------------------------------------------------------- fake OpenBao

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// Answers.
    Up,
    /// Answers 503 to everything.
    Unavailable,
    /// Answers 403 to everything, as a backend does for credentials it refuses.
    Forbidden,
    /// Holds every request until the mode changes.
    Hang,
}

struct Version {
    fields: BTreeMap<String, String>,
    destroyed: bool,
}

struct BaoState {
    mode: Mode,
    /// The versions of each path of the `secret` mount, oldest first.
    kv: BTreeMap<String, Vec<Version>>,
    /// Every request, as `METHOD target`.
    seen: Vec<String>,
}

/// A local server with the wire shape of OpenBao's KV v2 engine at the mount
/// `secret`, with token authentication.
struct Bao {
    addr: String,
    state: Arc<(Mutex<BaoState>, Condvar)>,
}

impl Bao {
    fn start() -> Bao {
        let state = Arc::new((
            Mutex::new(BaoState {
                mode: Mode::Up,
                kv: BTreeMap::new(),
                seen: Vec::new(),
            }),
            Condvar::new(),
        ));
        let shared = state.clone();
        let addr = serve(Arc::new(move |request: &Req| Bao::answer(&shared, request)));
        Bao { addr, state }
    }

    fn answer(state: &(Mutex<BaoState>, Condvar), request: &Req) -> Resp {
        let (mutex, changed) = state;
        let mut g = mutex.lock().unwrap();
        g.seen
            .push(format!("{} {}", request.method, request.target));
        let deadline = Instant::now() + Duration::from_secs(120);
        while g.mode == Mode::Hang {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            g = changed.wait_timeout(g, left).unwrap().0;
        }
        if g.mode == Mode::Unavailable {
            return Resp::json(503, &json!({"errors": ["Vault is sealed"]}));
        }
        if g.mode == Mode::Forbidden {
            return Resp::json(403, &json!({"errors": ["permission denied"]}));
        }
        if request.headers.get("x-vault-token").map(String::as_str) != Some(BAO_TOKEN) {
            return Resp::json(403, &json!({"errors": ["permission denied"]}));
        }
        let (path, query) = request
            .target
            .split_once('?')
            .unwrap_or((request.target.as_str(), ""));
        if path == "/v1/auth/token/lookup-self" {
            return Resp::json(200, &json!({"data": {"ttl": 0, "renewable": false}}));
        }
        if let Some(secret) = path.strip_prefix("/v1/secret/metadata/") {
            let Some(versions) = g.kv.get(secret) else {
                return Resp::json(404, &json!({"errors": []}));
            };
            let listed: serde_json::Map<String, Value> = versions
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    (
                        (i + 1).to_string(),
                        json!({"destroyed": v.destroyed, "deletion_time": ""}),
                    )
                })
                .collect();
            return Resp::json(
                200,
                &json!({"data": {
                    "current_version": versions.len(),
                    "oldest_version": 1,
                    "versions": listed
                }}),
            );
        }
        if let Some(secret) = path.strip_prefix("/v1/secret/data/") {
            let Some(versions) = g.kv.get(secret) else {
                return Resp::json(404, &json!({"errors": []}));
            };
            let wanted: usize = query
                .strip_prefix("version=")
                .map_or(versions.len(), |v| v.parse().unwrap_or(0));
            let Some(version) = wanted.checked_sub(1).and_then(|i| versions.get(i)) else {
                return Resp::json(404, &json!({"errors": []}));
            };
            if version.destroyed {
                return Resp::json(
                    404,
                    &json!({"data": {"data": null, "metadata": {
                        "version": wanted, "destroyed": true, "deletion_time": ""
                    }}}),
                );
            }
            return Resp::json(
                200,
                &json!({"data": {"data": version.fields, "metadata": {
                    "version": wanted, "destroyed": false, "deletion_time": ""
                }}}),
            );
        }
        Resp::json(404, &json!({"errors": []}))
    }

    /// Writes a new KV version of `secret/<path>` holding `field`; returns
    /// its number.
    fn put(&self, path: &str, field: &str, value: &str) -> usize {
        let mut g = self.state.0.lock().unwrap();
        let versions = g.kv.entry(path.to_owned()).or_default();
        versions.push(Version {
            fields: BTreeMap::from([(field.to_owned(), value.to_owned())]),
            destroyed: false,
        });
        versions.len()
    }

    /// `vault kv destroy -versions=N`: the value is gone for good.
    fn destroy(&self, path: &str, version: usize) {
        let mut g = self.state.0.lock().unwrap();
        let v = &mut g.kv.get_mut(path).unwrap()[version - 1];
        v.destroyed = true;
        v.fields.clear();
    }

    fn set_mode(&self, mode: Mode) {
        self.state.0.lock().unwrap().mode = mode;
        self.state.1.notify_all();
    }

    /// How many requests so far had a target that contains `part`.
    fn count(&self, part: &str) -> usize {
        let g = self.state.0.lock().unwrap();
        g.seen.iter().filter(|s| s.contains(part)).count()
    }

    fn requests(&self) -> usize {
        self.state.0.lock().unwrap().seen.len()
    }

    /// The `[secrets.backends.bao]` table the daemon is given.
    fn config(&self, token_file: &Path) -> String {
        format!(
            "[secrets.backends.bao]\ntype = \"openbao\"\naddress = \"http://{}\"\n\
             allowed_refs = [\"secret/\"]\nauth = \"token\"\ntoken_file = {:?}\n",
            self.addr, token_file
        )
    }
}

// ------------------------------------------------------- the target of fetches

struct TargetState {
    seen: Vec<Req>,
    released: bool,
}

/// A server for the fetches of the guests: `/hang...` answers only after
/// `release`, every other path at once. It records every request.
struct Target {
    addr: String,
    state: Arc<(Mutex<TargetState>, Condvar)>,
}

impl Target {
    fn start() -> Target {
        let state = Arc::new((
            Mutex::new(TargetState {
                seen: Vec::new(),
                released: false,
            }),
            Condvar::new(),
        ));
        let shared = state.clone();
        let addr = serve(Arc::new(move |request: &Req| {
            let (mutex, changed) = &*shared;
            let mut g = mutex.lock().unwrap();
            g.seen.push(request.clone());
            changed.notify_all();
            if request.target.starts_with("/hang") {
                let deadline = Instant::now() + Duration::from_secs(120);
                while !g.released {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    g = changed.wait_timeout(g, left).unwrap().0;
                }
            }
            Resp::json(200, &json!({"ok": true}))
        }));
        Target { addr, state }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// The requests whose target starts with `prefix`.
    fn seen(&self, prefix: &str) -> Vec<Req> {
        let g = self.state.0.lock().unwrap();
        g.seen
            .iter()
            .filter(|r| r.target.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn wait_for(&self, prefix: &str, n: usize) {
        let (mutex, changed) = &*self.state;
        let mut g = mutex.lock().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while g
            .seen
            .iter()
            .filter(|r| r.target.starts_with(prefix))
            .count()
            < n
        {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "request {n} to {prefix} never arrived");
            g = changed.wait_timeout(g, left).unwrap().0;
        }
    }

    fn release(&self) {
        self.state.0.lock().unwrap().released = true;
        self.state.1.notify_all();
    }
}

// -------------------------------------------------------------------- daemon

#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

struct Daemon {
    dir: PathBuf,
    child: Option<Child>,
}

impl Daemon {
    fn sock(&self) -> PathBuf {
        self.dir.join("api.sock")
    }

    /// Starts `kronik serve` on `dir` with the master key of the tests, the
    /// `bao` backend of `bao` if there is one, and the given
    /// `[secrets] fetch_timeout`. Waits until the API answers.
    ///
    /// The refresher's tick is an hour, so that the backend sees only the
    /// requests the test makes. The daemon logs at `info`, into `serve.log`
    /// next to its data directory: guest log events are in it, and the
    /// needle search covers it.
    fn start(dir: &Path, bao: Option<&Bao>, fetch_timeout: &str) -> Daemon {
        Daemon::start_with(dir, bao, fetch_timeout, "")
    }

    /// [`Daemon::start`] with `extra` lines appended to the configuration.
    fn start_with(dir: &Path, bao: Option<&Bao>, fetch_timeout: &str, extra: &str) -> Daemon {
        let token = dir.join("bao.token");
        std::fs::write(&token, BAO_TOKEN).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut config = format!(
            "[server]\ndata_dir = {:?}\n\n[secrets]\nrefresh = \"1h\"\nfetch_timeout = \"{fetch_timeout}\"\n\n",
            dir.join("data")
        );
        if let Some(bao) = bao {
            config.push_str(&bao.config(&token));
        }
        config.push_str(extra);
        let config_file = dir.join("kronik.toml");
        std::fs::write(&config_file, config).unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = Command::new(KRONIK)
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .env("KRONIK_MASTER_KEY", MASTER_KEY)
            .env_remove("KRONIK_MASTER_KEY_FILE")
            .env_remove("KRONIK_TOKEN")
            .arg("--config")
            .arg(&config_file)
            .args(["--http-listen", "127.0.0.1:0", "--api-socket"])
            .arg(dir.join("api.sock"))
            .env("KRONIK_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon {
            dir: dir.to_path_buf(),
            child: Some(child),
        };
        for _ in 0..4800 {
            if d.try_api("GET", "/v1/health", Value::Null)
                .is_some_and(|(status, _)| status == 200)
            {
                return d;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("daemon did not start: {}", d.serve_log());
    }

    fn serve_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    /// SIGKILL: no shutdown, no flush.
    fn kill9(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().unwrap();
            child.wait().unwrap();
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
        let mut length = 0;
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
                length = v.trim().parse().ok()?;
            }
        }
        let mut buf = vec![0; length];
        r.read_exact(&mut buf).ok()?;
        Some((status, serde_json::from_slice(&buf).ok()?))
    }

    /// One request; any status.
    fn api(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        self.try_api(method, path, body)
            .unwrap_or_else(|| panic!("API {method} {path} failed: {}", self.serve_log()))
    }

    /// A read that waits out the fail-closed window of the secret coverage
    /// (503 SECRET_UNAVAILABLE) and answers 200.
    fn get(&self, path: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let (status, v) = self.api("GET", path, Value::Null);
            if status == 200 {
                return v;
            }
            assert!(
                status == 503 && v["error"]["code"] == "SECRET_UNAVAILABLE",
                "GET {path}: {status} {v}"
            );
            assert!(
                Instant::now() < deadline,
                "GET {path} stayed unavailable: {}",
                self.serve_log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// A mutation that must answer 200. A 503 before the commit is retried;
    /// one that says the mutation is committed waits for the coverage and
    /// answers `Null`: read the state back.
    fn mutate(&self, method: &str, path: &str, body: Value) -> Value {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let (status, v) = self.api(method, path, body.clone());
            if status == 200 {
                return v;
            }
            assert!(
                status == 503 && v["error"]["code"] == "SECRET_UNAVAILABLE",
                "{method} {path}: {status} {v}"
            );
            if v["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("already committed"))
            {
                self.settle();
                return Value::Null;
            }
            assert!(
                Instant::now() < deadline,
                "{method} {path} stayed unavailable: {}",
                self.serve_log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Waits until the secret coverage is complete again.
    fn settle(&self) {
        self.get("/v1/secrets/stripe/history");
    }

    fn cli(&self, args: &[&str]) -> Out {
        let out = Command::new(KRONIK)
            .arg("--socket")
            .arg(self.sock())
            .args(args)
            .env_remove("KRONIK_API_SOCKET")
            .env_remove("KRONIK_TOKEN")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }

    fn deploy(&self, guest: &str) {
        let wasm = base64::engine::general_purpose::STANDARD
            .encode(std::fs::read(Path::new(GUESTS).join(guest)).unwrap());
        self.mutate(
            "POST",
            "/v1/deployments",
            json!({"wasm_base64": wasm, "reason": "secret backends"}),
        );
    }

    fn grant(&self, kind: &str, capability: &str, delivery: Option<&str>) {
        self.mutate(
            "POST",
            "/v1/grants",
            json!({"kind": kind, "capability": capability, "delivery": delivery,
                   "reason": "secret backends"}),
        );
    }

    fn link(&self, name: &str, reference: &str) {
        self.mutate(
            "PUT",
            &format!("/v1/secrets/{name}/link"),
            json!({"backend": "bao", "ref": reference, "reason": "secret backends"}),
        );
        self.settle();
    }

    /// `secret refresh`; the Kronik version it answers with.
    fn refresh(&self, name: &str) -> u64 {
        self.mutate(
            "POST",
            &format!("/v1/secrets/{name}/refresh"),
            json!({"reason": "secret backends"}),
        );
        self.settle();
        self.versions(name).last().unwrap().version
    }

    /// The versions `secret history` lists, oldest first.
    fn versions(&self, name: &str) -> Vec<SecretVersion> {
        let v = self.get(&format!("/v1/secrets/{name}/history"));
        v["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| SecretVersion {
                version: row["version"].as_u64().unwrap(),
                hash: row["version_hash"].as_str().unwrap().to_owned(),
                source_version: row["source_version"].as_str().unwrap().to_owned(),
                backend: row["backend"].as_str().unwrap().to_owned(),
                phase: row["phase"].as_str().unwrap().to_owned(),
            })
            .collect()
    }

    /// A message to `actor` whose turn must be answered with 200; the answer.
    fn send(&self, actor: &str, name: &str, text: &str) -> Value {
        let (status, v) = self.api(
            "POST",
            &format!("/v1/actors/{actor}/messages"),
            json!({"name": name, "text": text, "reason": "secret backends"}),
        );
        assert_eq!(status, 200, "{name}: {v}");
        v
    }

    /// Sends on a background thread: the daemon may die first.
    fn send_detached(&self, actor: &str, name: &str, text: &str) {
        let socket = self.sock();
        let path = format!("/v1/actors/{actor}/messages");
        let body = json!({"name": name, "text": text, "reason": "secret backends"}).to_string();
        std::thread::spawn(move || {
            if let Ok(mut s) = UnixStream::connect(socket) {
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

    fn history(&self, actor: &str) -> Vec<Value> {
        self.get(&format!("/v1/actors/{actor}/history"))["turns"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn applied_lsn(&self) -> u64 {
        self.get("/v1/health")["applied_lsn"].as_u64().unwrap()
    }

    fn wait_until(&self, what: &str, f: impl Fn(&Daemon) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if f(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for {what}: {}", self.serve_log());
    }

    /// Waits until neither the log nor the backend has moved for 200 ms.
    ///
    /// A link, an unlink or a rotation starts a background rebuild of the
    /// secret inventory, and that rebuild reads the backend. A request count
    /// taken while one is still in flight measures the rebuild rather than the
    /// operation under test, so a test that counts requests across a quiet
    /// daemon drains here first. A test with a backend that is down must not
    /// use this: there, the retries keep the count moving.
    fn quiet(&self, bao: &Bao) {
        let mut last = (self.applied_lsn(), bao.requests());
        let mut still = 0;
        for _ in 0..120 {
            std::thread::sleep(Duration::from_millis(50));
            let now = (self.applied_lsn(), bao.requests());
            if now == last {
                still += 1;
                if still == 4 {
                    return;
                }
            } else {
                last = now;
                still = 0;
            }
        }
        panic!(
            "the daemon never went quiet: at lsn {} the backend had seen {} requests: {}",
            last.0,
            last.1,
            self.serve_log()
        );
    }

    /// The text of every answer a client can get about `actors` and the
    /// secrets, from the API, from the CLI and from MCP.
    fn answers(&self, actors: &[&str], turns: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let mut cli = |args: &[&str]| {
            let o = self.cli(args);
            assert_eq!(o.code, 0, "kronik {args:?}: {o:?}");
            out_push(&mut out, o);
        };
        fn out_push(out: &mut Vec<String>, o: Out) {
            out.push(o.stdout);
            out.push(o.stderr);
        }
        for &actor in actors {
            cli(&["history", actor]);
            cli(&["actors", "inspect", actor]);
        }
        cli(&["secret", "history", "stripe"]);
        cli(&["secret", "list"]);
        for &actor in actors {
            out.push(self.get(&format!("/v1/actors/{actor}")).to_string());
            out.push(self.get(&format!("/v1/actors/{actor}/history")).to_string());
        }
        for turn in turns {
            out.push(self.get(&format!("/v1/turns/{turn}")).to_string());
            out.push(self.get(&format!("/v1/turns/{turn}/trace")).to_string());
        }
        for path in [
            "/v1/secrets",
            "/v1/secrets/stripe/history",
            "/v1/dead-letters",
            "/v1/grants",
            "/v1/deployments",
        ] {
            out.push(self.get(path).to_string());
        }
        out.extend(self.mcp(actors, turns));
        out
    }

    /// What MCP answers for the same questions.
    fn mcp(&self, actors: &[&str], turns: &[String]) -> Vec<String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            const ENDPOINT: &str = "http://localhost/mcp";
            let client = UnixSocketHttpClient::new(&self.sock().to_string_lossy(), ENDPOINT);
            let config = StreamableHttpClientTransportConfig::with_uri(ENDPOINT);
            let transport = StreamableHttpClientTransport::with_client(client, config);
            let client: RunningService<RoleClient, ()> = ().serve(transport).await.unwrap();
            let mut out = Vec::new();
            let ask = async |name: &'static str, arguments: Value| {
                let Value::Object(arguments) = arguments else {
                    panic!("arguments must be an object");
                };
                let result = client
                    .call_tool(CallToolRequestParams::new(name).with_arguments(arguments))
                    .await
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                serde_json::to_string(&result).unwrap()
            };
            for &actor in actors {
                out.push(ask("inspect_actor", json!({"actor": actor})).await);
                out.push(ask("query_history", json!({"actor": actor, "limit": 100})).await);
            }
            for turn in turns {
                out.push(ask("trace_turn", json!({"turn_id": turn})).await);
            }
            out.push(ask("list_dead_letters", json!({})).await);
            let config = client
                .read_resource(ReadResourceRequestParams::new("kronik://config"))
                .await
                .unwrap();
            out.push(serde_json::to_string(&config).unwrap());
            out
        })
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill9();
    }
}

struct SecretVersion {
    version: u64,
    /// 32 hex characters.
    hash: String,
    source_version: String,
    backend: String,
    phase: String,
}

// ------------------------------------------------------------------- the log

/// Every record of the log, read while the daemon runs (only fsynced records
/// exist) or after it died.
fn log_records(dir: &Path) -> Vec<Record> {
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

/// The `SecretVersion` records of `name` that describe a usable value.
fn recorded_versions(records: &[Record], name: &str) -> Vec<pb::SecretVersion> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::SecretVersion(v)
                if v.name == name
                    && v.phase == pb::secret_version::Phase::Active as i32
                    && !v.deleted =>
            {
                Some(v.clone())
            }
            _ => None,
        })
        .collect()
}

/// The `SecretRef` of every `crypto.hmac-sha256` effect of the log, in order.
fn hmac_secret_refs(records: &[Record]) -> Vec<pb::SecretRef> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::TurnRecord(t) => Some(t),
            _ => None,
        })
        .flat_map(|t| t.effects.iter())
        .filter(|e| e.kind == "crypto.hmac-sha256")
        .filter_map(|e| match e.request.as_ref()?.value.as_ref()? {
            pb::sealable::Value::Plain(bytes) => {
                pb::CryptoEffectRequest::decode(bytes.as_slice())
                    .ok()?
                    .secret
            }
            pb::sealable::Value::Sealed(_) => None,
        })
        .collect()
}

// ----------------------------------------------------------------- needles

/// The forms in which a value could sit in a file or an answer.
fn forms(value: &str) -> Vec<Vec<u8>> {
    vec![
        value.as_bytes().to_vec(),
        kronik_core::ids::hex(value.as_bytes()).into_bytes(),
        base64::engine::general_purpose::STANDARD
            .encode(value)
            .into_bytes(),
    ]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The files under `dir` that hold `value` in any form.
fn files_with(dir: &Path, value: &str) -> Vec<PathBuf> {
    fn walk(dir: &Path, forms: &[Vec<u8>], hits: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                walk(&path, forms, hits);
            } else if kind.is_file()
                && let Ok(bytes) = std::fs::read(&path)
                && forms.iter().any(|f| contains(&bytes, f))
            {
                hits.push(path);
            }
        }
    }
    let mut hits = Vec::new();
    walk(dir, &forms(value), &mut hits);
    hits
}

/// Asserts that none of `values` is in a file under `dir` or in `answers`.
fn assert_no_needle(dir: &Path, answers: &[String], values: &[&str]) {
    for value in values {
        let files = files_with(dir, value);
        assert!(files.is_empty(), "{value} is in the files {files:?}");
        for form in forms(value) {
            for answer in answers {
                assert!(
                    !contains(answer.as_bytes(), &form),
                    "{value} is in an answer: {answer}"
                );
            }
        }
    }
}

/// HMAC-SHA256 as lowercase hex.
fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let mut inner = Sha256::new();
    inner.update(pad(0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(pad(0x5c));
    outer.update(inner.finalize());
    kronik_core::ids::hex(&outer.finalize())
}

// ---------------------------------------------------------------- fixtures

/// A daemon with `counter` deployed, `secret:stripe` granted to it, and the
/// name `stripe` linked to `secret/payments#stripe` (KV version 1 holds
/// `VALUE_1`); the first HMAC turn has not run.
struct Linked {
    // Dropped in this order: the daemon first, its directory last.
    d: Daemon,
    bao: Bao,
    dir: tempfile::TempDir,
}

fn linked() -> Linked {
    let bao = Bao::start();
    assert_eq!(bao.put("payments", "stripe", VALUE_1), 1);
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), Some(&bao), "2s");
    d.deploy("counter.wasm");
    d.grant("counter", "secret:stripe", None);
    d.link("stripe", "secret/payments#stripe");
    Linked { d, bao, dir }
}

/// The first 8 hex characters of a 32-character hash.
fn hash8(hash: &str) -> &str {
    &hash[..8]
}

// ------------------------------------------------------------------- tests

/// The helpers of the tests are not vacuous: the needle search finds a value
/// as it is, in hex and in base64, in nested files and in an answer, and
/// `hmac_hex` is HMAC-SHA256 (RFC 4231, test case 2).
#[test]
fn the_needle_search_and_the_hmac_helper_work() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
    let one = forms(VALUE_1);
    let with_context = [b"xx".as_slice(), one[0].as_slice(), b"yy"].concat();
    std::fs::write(dir.path().join("raw"), with_context).unwrap();
    std::fs::write(dir.path().join("a/hex"), &one[1]).unwrap();
    std::fs::write(dir.path().join("a/b/base64"), &one[2]).unwrap();
    std::fs::write(dir.path().join("a/clean"), b"nothing here").unwrap();
    let mut found: Vec<_> = files_with(dir.path(), VALUE_1)
        .iter()
        .map(|p| p.strip_prefix(dir.path()).unwrap().to_owned())
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            PathBuf::from("a/b/base64"),
            PathBuf::from("a/hex"),
            PathBuf::from("raw")
        ]
    );
    assert!(files_with(dir.path(), VALUE_2).is_empty());

    // An answer that holds the value, in any form, fails the search; one that
    // does not, passes.
    assert_no_needle(dir.path(), &["nothing here".to_owned()], &[VALUE_2]);
    for form in forms(VALUE_2) {
        let answer = format!("{{\"text\":\"{}\"}}", String::from_utf8(form).unwrap());
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_no_needle(dir.path(), std::slice::from_ref(&answer), &[VALUE_2]);
        }));
        assert!(caught.is_err(), "{answer} was not found");
    }

    assert_eq!(
        hmac_hex(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// Criterion 2.
#[test]
fn an_external_secret_gets_the_built_in_version_hash_and_its_value_stays_out_of_every_view() {
    let Linked { dir, bao, d } = linked();
    // The link only checked the reference; no value has been used.
    assert!(
        bao.count("/v1/secret/data/payments") >= 1,
        "the link fetched the reference once"
    );

    // A turn uses it in an HMAC, with the value the backend holds.
    let turn = d.send("counter/h", "hmac", "stripe\npayload");
    assert_eq!(turn["outcome"]["kind"], "committed", "{turn}");
    assert_eq!(
        turn["reply"]["text"],
        hmac_hex(VALUE_1.as_bytes(), b"payload"),
        "{turn}"
    );
    let turn_id = turn["turn_id"].as_str().unwrap().to_owned();

    // The log has the version, with the backend, the reference and the KV
    // version, and the effect's SecretRef carries the same number and hash.
    let records = log_records(dir.path());
    let rows = recorded_versions(&records, "stripe");
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(
        (
            row.version,
            row.backend.as_str(),
            row.source_version.as_str(),
            row.r#ref.as_str(),
            row.version_hash.len()
        ),
        (1, "bao", "1", "secret/payments#stripe", 16),
        "{row:?}"
    );
    let refs = hmac_secret_refs(&records);
    assert_eq!(refs.len(), 1, "{refs:?}");
    assert_eq!(refs[0].version, 1);
    assert_eq!(refs[0].version_hash, row.version_hash);
    let logged = kronik_core::ids::hex(&row.version_hash);

    // The same value under the same name on a `file` node with the same
    // master key has the same hash: it is the built-in one.
    let file_dir = tempfile::tempdir().unwrap();
    let file_node = Daemon::start(file_dir.path(), None, "2s");
    let set = file_node.mutate(
        "PUT",
        "/v1/secrets/stripe",
        json!({"text": VALUE_1, "reason": "the same value on a file node"}),
    );
    assert_eq!(set["secret"]["version"], 1, "{set}");
    assert_eq!(set["secret"]["version_hash"], logged, "{set}");
    // `secret history` and `secret list` say it too.
    let versions = d.versions("stripe");
    assert_eq!(versions.len(), 1);
    assert_eq!(
        (
            versions[0].hash.as_str(),
            versions[0].backend.as_str(),
            versions[0].source_version.as_str(),
            versions[0].phase.as_str()
        ),
        (logged.as_str(), "bao", "1", "active")
    );
    assert_eq!(d.get("/v1/secrets")["secrets"][0]["version_hash"], logged);

    // Actor history shows the version and the first 8 hex of the hash.
    let history = d.history("counter/h");
    assert_eq!(
        history[0]["effects"][0]["secrets"],
        json!([{"name": "stripe", "version": 1, "version_hash": hash8(&logged)}]),
        "{history:?}"
    );
    let shown = d.cli(&["history", "counter/h"]);
    assert!(
        shown
            .stdout
            .contains(&format!("secret:stripe@v1 ({})", hash8(&logged))),
        "{shown:?}"
    );

    // The value is in no file and in no answer.
    let answers = d.answers(&["counter/h"], &[turn_id]);
    assert_no_needle(dir.path(), &answers, &[VALUE_1]);
    assert_no_needle(file_dir.path(), &[], &[VALUE_1]);
    assert_closed_when_quiet(&d, "an external secret");
}

/// Criterion 3, steps 1 to 4: a new KV version, `secret refresh`, the version
/// in `secret history`, in actor history, and a fork before the rotation.
#[test]
fn a_rotation_in_the_backend_shows_as_a_new_version_and_a_fork_before_it_replays_identically() {
    let Linked { dir, bao, d } = linked();
    // The fork point is after the link and before the first use.
    let fork_point = d.applied_lsn();
    let first = d.send("counter/h", "hmac", "stripe\npayload");
    assert_eq!(
        first["reply"]["text"],
        hmac_hex(VALUE_1.as_bytes(), b"payload"),
        "{first}"
    );
    let first_id = first["turn_id"].as_str().unwrap().to_owned();
    let old_hash = d.versions("stripe")[0].hash.clone();

    // 1. A new KV version in the backend, then `secret refresh`.
    assert_eq!(bao.put("payments", "stripe", VALUE_2), 2);
    assert_eq!(d.refresh("stripe"), 2);

    // 2. SecretVersion 2 appears, and `secret history` shows v1 and v2; the
    // record of v1 is as it was.
    let versions = d.versions("stripe");
    let listed: Vec<_> = versions
        .iter()
        .map(|v| (v.version, v.source_version.as_str(), v.backend.as_str()))
        .collect();
    assert_eq!(listed, [(1, "1", "bao"), (2, "2", "bao")]);
    assert_eq!(versions[0].hash, old_hash);
    let new_hash = versions[1].hash.clone();
    assert_ne!(new_hash, old_hash);
    let rows = recorded_versions(&log_records(dir.path()), "stripe");
    let in_log: Vec<_> = rows
        .iter()
        .map(|r| (r.version, r.source_version.as_str()))
        .collect();
    assert_eq!(in_log, [(1, "1"), (2, "2")]);
    assert_eq!(kronik_core::ids::hex(&rows[1].version_hash), new_hash);
    let shown = d.cli(&["secret", "history", "stripe"]);
    assert_eq!(shown.code, 0, "{shown:?}");
    let lines: Vec<String> = shown
        .stdout
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    for want in [
        format!("1 active {old_hash} bao secret/payments#stripe 1"),
        format!("2 active {new_hash} bao secret/payments#stripe 2"),
    ] {
        assert!(
            lines.iter().any(|l| l.starts_with(&want)),
            "{want}: {shown:?}"
        );
    }
    assert_eq!(d.get("/v1/secrets")["secrets"][0]["version"], 2);

    // 3. A new turn's history shows `secret:stripe@v2`, the old one `@v1`.
    let second = d.send("counter/h", "hmac", "stripe\npayload");
    assert_eq!(
        second["reply"]["text"],
        hmac_hex(VALUE_2.as_bytes(), b"payload"),
        "the new turn used the new value: {second}"
    );
    let second_id = second["turn_id"].as_str().unwrap().to_owned();
    let history = d.history("counter/h");
    let used = |turn: &str| -> Value {
        history.iter().find(|t| t["turn_id"] == turn).unwrap()["effects"][0]["secrets"].clone()
    };
    assert_eq!(
        used(&first_id),
        json!([{"name": "stripe", "version": 1, "version_hash": hash8(&old_hash)}])
    );
    assert_eq!(
        used(&second_id),
        json!([{"name": "stripe", "version": 2, "version_hash": hash8(&new_hash)}])
    );
    let table = d.cli(&["history", "counter/h"]);
    let effect_rows: Vec<&str> = table
        .stdout
        .lines()
        .filter(|l| l.contains("crypto.hmac-sha256"))
        .collect();
    assert_eq!(effect_rows.len(), 2, "{table:?}");
    assert!(
        effect_rows[0].starts_with(&second_id)
            && effect_rows[0].ends_with(&format!("secret:stripe@v2 ({})", hash8(&new_hash))),
        "{table:?}"
    );
    assert!(
        effect_rows[1].starts_with(&first_id)
            && effect_rows[1].ends_with(&format!("secret:stripe@v1 ({})", hash8(&old_hash))),
        "{table:?}"
    );

    // 4. A fork before the rotation replays the turns on both sides of it
    // identically: same outcomes, every effect matched, and no request to the
    // backend (a fork never fetches).
    // The rotation rebuilt the inventory in the background; let its fetch land
    // before the count that the fork is measured against is taken.
    d.quiet(&bao);
    let requests = bao.requests();
    let fork = d.mutate(
        "POST",
        "/v1/forks",
        json!({"at": fork_point, "reason": "identity across a rotation"}),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    d.mutate(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"reason": "identity across a rotation"}),
    );
    let diff = d.get(&format!("/v1/forks/{fork}/diff"));
    let summary = &diff["summary"];
    assert_eq!(summary["changed"], false, "{diff}");
    assert_eq!(summary["divergent_turns"], 0, "{diff}");
    assert_eq!(
        (
            &diff["effects"]["added"],
            &diff["effects"]["removed"],
            &diff["effects"]["changed"]
        ),
        (&json!(0), &json!(0), &json!(0)),
        "{diff}"
    );
    assert!(summary["exact"].as_u64() >= Some(2), "{diff}");
    for kind in ["approximate", "synthetic", "live"] {
        assert_eq!(summary[kind], 0, "{kind}: {diff}");
    }
    assert_eq!(bao.requests(), requests, "the fork asked the backend");

    // I8: neither value is anywhere.
    let answers = d.answers(&["counter/h"], &[first_id, second_id]);
    assert_no_needle(dir.path(), &answers, &[VALUE_1, VALUE_2]);
    assert_closed_when_quiet(&d, "a rotation");
}

/// A linked node whose `leaky` guest may reveal `stripe` and POST to the
/// loopback with a `replay-safe` grant, so that a re-run sends the request
/// again; and a server for its fetches.
fn linked_with_leaky() -> (Linked, Target) {
    let linked = linked();
    let target = Target::start();
    linked.d.deploy("leaky.wasm");
    linked.d.grant("leaky", "secret-reveal:stripe", None);
    linked
        .d
        .grant("leaky", "http:127.0.0.1", Some("replay-safe"));
    (linked, target)
}

/// A turn of the leaky guest that reveals `stripe` and then fetches
/// `<target>/hang` with the revealed value in the URL, a header and the body.
fn reveal_in_flight(d: &Daemon, target: &Target, actor: &str) {
    d.send_detached(
        actor,
        "reveal-fetch",
        &format!("stripe {}", target.url("/hang")),
    );
}

/// The turn records of `actor` whose input is the message `name`.
fn message_turns(dir: &Path, actor: &str, name: &str) -> Vec<pb::TurnRecord> {
    log_records(dir)
        .into_iter()
        .filter_map(|r| match r {
            Record::TurnRecord(t) => Some(t),
            _ => None,
        })
        .filter(|t| {
            t.actor
                .as_ref()
                .is_some_and(|a| format!("{}/{}", a.kind, a.key) == actor)
                && matches!(
                    t.input.as_ref().and_then(|i| i.kind.as_ref()),
                    Some(pb::input::Kind::Message(m))
                        if m.msg.as_ref().is_some_and(|m| m.name == name)
                )
        })
        .collect()
}

/// How many turns of `actor` committed for the message `name`.
fn committed_messages(dir: &Path, actor: &str, name: &str) -> usize {
    message_turns(dir, actor, name)
        .iter()
        .filter(|t| {
            t.outcome
                .as_ref()
                .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32)
        })
        .count()
}

/// Criterion 3, step 5, and I10 for a re-run: the crash re-run of a turn that
/// revealed version 1 gets version 1's value from the backend by its KV
/// version although the backend's current version is 2, waits while the
/// backend is down (and only that turn waits), and sends version 2's value
/// nowhere.
#[test]
fn a_crash_re_run_of_a_reveal_gets_the_recorded_version_and_waits_while_the_backend_is_down() {
    let (Linked { mut d, bao, dir }, target) = linked_with_leaky();

    // A turn reveals version 1 and has a fetch in flight with its value.
    reveal_in_flight(&d, &target, "leaky/a");
    target.wait_for("/hang", 1);
    assert_eq!(
        target.seen("/hang")[0].target,
        format!("/hang?key={VALUE_1}"),
        "the first attempt went out with version 1"
    );
    // The secret rotates while it is in flight, then the daemon dies.
    assert_eq!(bao.put("payments", "stripe", VALUE_2), 2);
    assert_eq!(d.refresh("stripe"), 2);
    d.kill9();

    // It starts again with the backend down: the re-run of the turn waits for
    // the recorded value, and nothing else does.
    bao.set_mode(Mode::Unavailable);
    d = Daemon::start(dir.path(), Some(&bao), "1s");
    let others = committed_messages(dir.path(), "counter/a", "increment");
    let (status, answer) = d.api(
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "increment", "reason": "a turn without a secret"}),
    );
    println!("increment while the backend is down: {status} {answer}");
    d.wait_until("a turn without a secret", |d| {
        committed_messages(&d.dir, "counter/a", "increment") > others
    });
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        target.seen("/hang").len(),
        1,
        "the re-run went on without the recorded value"
    );
    assert!(message_turns(dir.path(), "leaky/a", "reveal-fetch").is_empty());

    // The backend is back: the re-run gets version 1's value although the
    // backend's current version is 2.
    bao.set_mode(Mode::Up);
    target.release();
    d.wait_until("the re-run's commit", |d| {
        committed_messages(&d.dir, "leaky/a", "reveal-fetch") == 1
    });
    let seen = target.seen("/hang");
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[1].target, format!("/hang?key={VALUE_1}"));
    assert_eq!(
        seen[1].headers.get("x-api-key").map(String::as_str),
        Some(VALUE_1)
    );
    assert!(
        seen.iter()
            .all(|r| !contains(&r.body, VALUE_2.as_bytes()) && !r.target.contains(VALUE_2)),
        "version 2's value went out"
    );
    assert!(
        bao.count("/v1/secret/data/payments?version=1") >= 1,
        "the value was fetched by its KV version"
    );

    // I8: neither value is in a file or in an answer.
    let rerun = d.history("leaky/a").remove(0);
    assert_eq!(rerun["outcome"]["kind"], "committed", "{rerun}");
    let turns = vec![rerun["turn_id"].as_str().unwrap().to_owned()];
    let answers = d.answers(&["leaky/a", "counter/a"], &turns);
    assert_no_needle(dir.path(), &answers, &[VALUE_1, VALUE_2]);
    // The crash left the turn open; the re-run has closed it.
    assert_closed_when_quiet(&d, "after the crash re-run of a reveal");
}

/// Criterion 3, step 6: when the backend destroyed the version a recorded
/// `secret.reveal` names, the crash re-run of that turn fails with
/// `SECRET_VERSION_GONE`: it never starts the guest, sends nothing, and does
/// not fall back to the value of the current version.
///
/// This reads the log, not the API: while a recorded version is one that the
/// backend no longer serves, the node cannot certify the inventory that
/// scrubs its answers after a restart, and every scrubbed read answers 503
/// `SECRET_UNAVAILABLE`.
#[test]
fn a_crash_re_run_of_a_reveal_fails_with_secret_version_gone_when_the_backend_destroyed_it() {
    let (Linked { mut d, bao, dir }, target) = linked_with_leaky();

    reveal_in_flight(&d, &target, "leaky/a");
    target.wait_for("/hang", 1);
    assert_eq!(
        target.seen("/hang")[0].target,
        format!("/hang?key={VALUE_1}")
    );
    // The secret rotates, the backend destroys version 1 for good, and the
    // daemon dies with the request in flight.
    assert_eq!(bao.put("payments", "stripe", VALUE_2), 2);
    assert_eq!(d.refresh("stripe"), 2);
    bao.destroy("payments", 1);
    d.kill9();

    d = Daemon::start(dir.path(), Some(&bao), "2s");
    target.release();
    d.wait_until("the recovery's outcome", |d| {
        !message_turns(&d.dir, "leaky/a", "reveal-fetch").is_empty()
    });
    let turns = message_turns(dir.path(), "leaky/a", "reveal-fetch");
    assert_eq!(turns.len(), 1, "{turns:?}");
    let outcome = turns[0].outcome.clone().unwrap();
    assert_eq!(
        (outcome.kind, outcome.error_code.as_str()),
        (pb::OutcomeKind::Failed as i32, "SECRET_VERSION_GONE"),
        "{outcome:?}"
    );
    assert!(outcome.output.is_none(), "{outcome:?}");
    // What the turn kept of its first attempt: the recorded reveal of version
    // 1, and no effect after it.
    let kinds: Vec<_> = turns[0].effects.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["secret.reveal"], "{:?}", turns[0].effects);
    let reveal = &turns[0].effects[0];
    assert_eq!(reveal.status, pb::EffectStatus::Ok as i32);
    let Some(pb::sealable::Value::Plain(bytes)) =
        reveal.request.as_ref().and_then(|r| r.value.as_ref())
    else {
        panic!("the reveal request is not plain: {reveal:?}");
    };
    let recorded = pb::RevealEffectRequest::decode(bytes.as_slice())
        .unwrap()
        .secret
        .unwrap();
    assert_eq!(
        (recorded.name.as_str(), recorded.resolved_version().unwrap()),
        ("stripe", 1)
    );

    // Nothing was sent after the crash, and version 2's value went nowhere.
    std::thread::sleep(Duration::from_secs(3));
    let seen = target.seen("/hang");
    assert_eq!(seen.len(), 1, "the failed turn sent something: {seen:?}");
    assert!(
        seen.iter()
            .all(|r| !contains(&r.body, VALUE_2.as_bytes()) && !r.target.contains(VALUE_2)),
        "version 2's value went out"
    );
    assert_eq!(
        committed_messages(dir.path(), "leaky/a", "reveal-fetch"),
        0,
        "the guest ran again"
    );
    // I8: neither value is in any file.
    assert_no_needle(dir.path(), &[], &[VALUE_1, VALUE_2]);
    // The crash left the turn open; recovery has closed it as failed.
    assert_closed_when_quiet(&d, "after the failed re-run of a reveal");
}

/// Criterion 3, step 7: the scrubbing of a revealed value survives a restart.
/// A guest reveals version 1 and moves it into its state, a log event, a
/// message and its reply; the secret rotates; the daemon restarts with the
/// backend down. A node that holds no value of version 1 cannot scrub what it
/// shows, so it shows nothing: every read answers 503 `SECRET_UNAVAILABLE`.
/// Once the backend is back, the reads show the placeholder and never a value.
#[test]
fn the_scrubbing_of_a_revealed_value_survives_a_restart() {
    let Linked { mut d, bao, dir } = linked();
    d.grant("counter", "secret-reveal:stripe", None);
    let turn = d.send("counter/a", "reveal-persist", "stripe");
    assert_eq!(turn["outcome"]["kind"], "committed", "{turn}");
    assert!(!turn.to_string().contains(VALUE_1), "{turn}");
    let turn_id = turn["turn_id"].as_str().unwrap().to_owned();
    // The sink got the message, with the placeholder in it.
    d.wait_until("the message to the sink", |d| {
        committed_messages(&d.dir, "counter/sink", "store") == 1
    });

    assert_eq!(bao.put("payments", "stripe", VALUE_2), 2);
    assert_eq!(d.refresh("stripe"), 2);
    d.kill9();

    // The backend is down, so the value of version 1 is not to be had.
    bao.set_mode(Mode::Unavailable);
    d = Daemon::start(dir.path(), Some(&bao), "1s");
    for path in [
        "/v1/actors/counter/a".to_owned(),
        "/v1/actors/counter/a/history".to_owned(),
        "/v1/actors/counter/sink".to_owned(),
        format!("/v1/turns/{turn_id}"),
    ] {
        let (status, v) = d.api("GET", &path, Value::Null);
        assert_eq!(status, 503, "{path}: {v}");
        assert_eq!(v["error"]["code"], "SECRET_UNAVAILABLE", "{path}: {v}");
        assert!(!v.to_string().contains(VALUE_1), "{path}: {v}");
    }

    // The backend is back, and the node scrubs again.
    bao.set_mode(Mode::Up);
    let inspect = d.get("/v1/actors/counter/a");
    let revealed = inspect["state"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == "revealed")
        .unwrap_or_else(|| panic!("no state `revealed`: {inspect}"));
    assert_eq!(revealed["text"], "[secret:stripe]", "{revealed}");
    let sink = d.get("/v1/actors/counter/sink");
    assert!(sink.to_string().contains("[secret:stripe]"), "{sink}");
    let answers = d.answers(&["counter/a", "counter/sink"], &[turn_id]);
    assert_no_needle(dir.path(), &answers, &[VALUE_1, VALUE_2]);
    assert_closed_when_quiet(&d, "the scrubbing after a restart");
}

/// I10: a backend that hangs delays only the turns that need an uncached
/// secret, and only by the fetch timeout; they answer `SECRET_UNAVAILABLE`.
#[test]
fn a_backend_that_hangs_stops_only_the_turns_that_need_its_secrets() {
    let Linked { mut d, bao, dir } = linked();
    d.send("counter/h", "hmac", "stripe\npayload");
    // A restarted node knows the link and holds no value.
    d.kill9();
    bao.set_mode(Mode::Hang);
    d = Daemon::start(dir.path(), Some(&bao), "1s");

    // Turns without a secret commit, each within a moment.
    let before = committed_messages(dir.path(), "counter/a", "increment");
    for _ in 0..5 {
        let started = Instant::now();
        let (status, answer) = d.api(
            "POST",
            "/v1/actors/counter/a/messages",
            json!({"name": "increment", "reason": "a turn without a secret"}),
        );
        println!("increment: {status} in {:?}: {answer}", started.elapsed());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    assert_eq!(
        committed_messages(dir.path(), "counter/a", "increment"),
        before + 5
    );

    // A turn that needs the uncached secret ends within the fetch timeout: the
    // effect gets SECRET_UNAVAILABLE as its recorded result and the guest fails
    // with it (this guest does not handle it), so the turn is a failed turn, not
    // an open one (design m23 sections 6 and 9).
    let started = Instant::now();
    let (status, answer) = d.api(
        "POST",
        "/v1/actors/counter/h/messages",
        json!({"name": "hmac", "text": "stripe\npayload", "reason": "an uncached secret"}),
    );
    println!("hmac: {status} in {:?}: {answer}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(10));
    let text = answer.to_string();
    assert!(text.contains("SECRET_UNAVAILABLE"), "{answer}");
    assert_eq!(answer["outcome"]["kind"], "failed", "{answer}");
    assert_eq!(open_turns(dir.path()), 0, "the aborted turn was left open");
    // The rebuild that cannot hold version 1 says which version it is.
    d.wait_until("the rebuild warning to name the version", |d| {
        d.serve_log()
            .contains("failed_version=stripe@v1 on bao: the secret backend is unavailable")
    });

    // Turns without a secret still commit.
    let (status, _) = d.api(
        "POST",
        "/v1/actors/counter/a/messages",
        json!({"name": "increment", "reason": "after the failed secret"}),
    );
    assert_eq!(status, 200);

    // The backend is back; so is the secret, once the five seconds that a
    // failure is remembered have passed.
    bao.set_mode(Mode::Up);
    std::thread::sleep(Duration::from_secs(6));
    d.settle();
    let again = d.send("counter/h", "hmac", "stripe\npayload");
    assert_eq!(
        again["reply"]["text"],
        hmac_hex(VALUE_1.as_bytes(), b"payload"),
        "{again}"
    );
    assert_closed_when_quiet(&d, "a backend that hangs");
}

// ------------------------------------------------ a turn without its secret

/// One request to the gateway: the status and the body.
fn gateway(addr: &str, path: &str, body: &str, key: Option<&str>) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let key = key.map_or(String::new(), |k| format!("idempotency-key: {k}\r\n"));
    write!(
        s,
        "POST {path} HTTP/1.1\r\nhost: x\r\n{key}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status = out
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let body = out.split_once("\r\n\r\n").map_or("", |(_, b)| b).to_owned();
    (status, body)
}

/// `TurnBegin` records of the log that no `TurnRecord` follows. While the
/// daemon runs there are none: an open turn is what a crash leaves.
fn open_turns(dir: &Path) -> usize {
    let records = log_records(dir);
    let done: Vec<&str> = records
        .iter()
        .filter_map(|r| match r {
            Record::TurnRecord(t) => Some(t.execution_id.as_str()),
            _ => None,
        })
        .collect();
    records
        .iter()
        .filter(|r| matches!(r, Record::TurnBegin(b) if !done.contains(&b.execution_id.as_str())))
        .count()
}

/// The invariant that a recorded error keeps and that nothing else enforces:
/// when the daemon is quiet, no `TurnBegin` is open. An open turn is what a
/// crash leaves, and the next start runs it; a turn that stays open while the
/// daemon runs is one that was abandoned after its `TurnBegin`, to be run by a
/// start that nobody expects (S-7). Quiet means that the applied LSN has not
/// moved for a second. After an injected crash, call it once the recovery is
/// over: the re-runs have then closed what the crash left open.
fn assert_closed_when_quiet(d: &Daemon, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = d.applied_lsn();
    let mut since = Instant::now();
    while since.elapsed() < Duration::from_secs(1) {
        assert!(
            Instant::now() < deadline,
            "{what}: the daemon never became quiet: {}",
            d.serve_log()
        );
        std::thread::sleep(Duration::from_millis(100));
        let now = d.applied_lsn();
        if now != last {
            last = now;
            since = Instant::now();
        }
    }
    let open = open_turns(&d.dir);
    assert_eq!(
        open, 0,
        "{what}: {open} TurnBegin records have no TurnRecord although the daemon is quiet"
    );
}

/// A node that has restarted with the backend down, so that the secret is not
/// cached and the cold fetch is what fails. The counter may call
/// `http:127.0.0.1` with `delivery`.
fn after_a_restart_with_the_backend_down(delivery: &str) -> (Linked, Target, String) {
    let Linked { mut d, bao, dir } = linked();
    let target = Target::start();
    d.grant("counter", "http:127.0.0.1", Some(delivery));
    d.kill9();
    bao.set_mode(Mode::Unavailable);
    d = Daemon::start(dir.path(), Some(&bao), "1s");
    let gateway = d.get("/v1/health")["http_listen"]
        .as_str()
        .unwrap()
        .to_owned();
    (Linked { d, bao, dir }, target, gateway)
}

fn fetch_spec(target: &Target) -> String {
    format!(
        "POST {}\nS x-api-key stripe {{}}\n\nbody",
        target.url("/hook")
    )
}

fn restart(linked: &mut Linked) -> String {
    linked.d.kill9();
    linked.d = Daemon::start(linked.dir.path(), Some(&linked.bao), "2s");
    linked.d.get("/v1/health")["http_listen"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A turn that needs a secret it cannot get does not abandon its `TurnBegin`:
/// the effect gets `SECRET_UNAVAILABLE` as its recorded result and the guest
/// decides, as for any other effect error. Nothing is left for the next start
/// to run (design m23 section 6, ADR 0091).
#[test]
fn a_turn_that_cannot_get_its_secret_leaves_no_open_turn() {
    let (l, target, gw) = after_a_restart_with_the_backend_down("idempotency-keyed");
    // Through the gateway, and an operator's `send`.
    let (status, body) = gateway(&gw, "/counter/h/fetch", &fetch_spec(&target), Some("K-1"));
    println!(
        "gateway: {status} {}",
        body.chars().take(160).collect::<String>()
    );
    assert!(body.contains("SECRET_UNAVAILABLE"), "{status} {body}");
    let (status, v) = l.d.api(
        "POST",
        "/v1/actors/counter/h/messages",
        json!({"name": "hmac", "text": "stripe\npayload", "reason": "uncached"}),
    );
    println!("send: {status} {v}");
    assert!(v.to_string().contains("SECRET_UNAVAILABLE"), "{v}");
    assert_eq!(
        open_turns(l.dir.path()),
        0,
        "TurnBegin records without a TurnRecord while the daemon runs"
    );
    // Nothing went to the target: the request never had its credential.
    assert!(target.seen("/hook").is_empty());
    assert_closed_when_quiet(&l.d, "a turn without its secret");
}

/// One client key is one request: the failed turn is the answer to the key,
/// whatever happens to the backend, and a restart finds nothing to run.
#[test]
fn retrying_with_the_same_key_after_the_outage_sends_the_request_at_most_once() {
    let (mut l, target, gw) = after_a_restart_with_the_backend_down("idempotency-keyed");
    let mut answers = Vec::new();
    for i in 0..3 {
        let (status, body) = gateway(&gw, "/counter/h/fetch", &fetch_spec(&target), Some("K-3"));
        println!("attempt {i}: {status}");
        answers.push((status, body));
    }
    l.bao.set_mode(Mode::Up);
    std::thread::sleep(Duration::from_secs(7));
    let (status, body) = gateway(&gw, "/counter/h/fetch", &fetch_spec(&target), Some("K-3"));
    println!("attempt 3, backend up: {status}");
    answers.push((status, body));
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "one key, different answers: {answers:?}"
    );
    restart(&mut l);
    l.d.wait_until("no open turn", |d| open_turns(&d.dir) == 0);
    std::thread::sleep(Duration::from_secs(3));
    let seen = target.seen("/hook");
    let keys: std::collections::BTreeSet<_> = seen
        .iter()
        .map(|r| {
            r.headers
                .get("idempotency-key")
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    // The request never had its credential, so it is never sent: not by the
    // retries, and not by a start that finds a turn to run.
    assert!(
        seen.is_empty(),
        "one client key, {} POSTs to the target with {} different Idempotency-Key headers",
        seen.len(),
        keys.len()
    );
    assert_closed_when_quiet(&l.d, "a repeated key after the outage");
}

#[test]
fn a_timer_that_meets_the_outage_does_not_wait_for_a_restart() {
    let Linked { d, bao, dir } = after_a_restart_with_the_backend_down("idempotency-keyed").0;
    let (status, v) = d.api(
        "POST",
        "/v1/actors/counter/h/messages",
        json!({"name": "schedule", "text": "300 hmac\nstripe\npayload", "reason": "timer"}),
    );
    println!("schedule: {status} {}", v["reply"]["text"]);
    std::thread::sleep(Duration::from_secs(3));
    bao.set_mode(Mode::Up);
    std::thread::sleep(Duration::from_secs(8));
    assert_eq!(
        open_turns(dir.path()),
        0,
        "the timer's turn is still open 8 s after the backend returned"
    );
    // The timer did fire, met the outage, and ended as a failed turn (a dead
    // letter) that names it, instead of waiting for the next start.
    let timer_turns: Vec<pb::TurnRecord> = log_records(dir.path())
        .into_iter()
        .filter_map(|r| match r {
            Record::TurnRecord(t)
                if matches!(
                    t.input.as_ref().and_then(|i| i.kind.as_ref()),
                    Some(pb::input::Kind::Timer(_))
                ) =>
            {
                Some(t)
            }
            _ => None,
        })
        .collect();
    assert_eq!(timer_turns.len(), 1, "{timer_turns:?}");
    let outcome = timer_turns[0].outcome.as_ref().unwrap();
    assert_eq!(outcome.kind, pb::OutcomeKind::Failed as i32, "{outcome:?}");
    assert!(
        outcome.message.contains("SECRET_UNAVAILABLE"),
        "{outcome:?}"
    );
    assert_eq!(
        timer_turns[0].effects.len(),
        1,
        "{:?}",
        timer_turns[0].effects
    );
    assert_eq!(
        timer_turns[0].effects[0].error,
        "SECRET_UNAVAILABLE: stripe"
    );
    assert_closed_when_quiet(&d, "a timer that met the outage");
}

#[test]
fn an_unsafe_target_is_not_made_unknown_by_a_turn_that_sent_nothing() {
    let (mut l, target, gw) = after_a_restart_with_the_backend_down("unsafe");
    let (status, _) = gateway(&gw, "/counter/h/fetch", &fetch_spec(&target), Some("K-2"));
    println!("1st request, backend down: {status}");
    l.bao.set_mode(Mode::Up);
    std::thread::sleep(Duration::from_secs(7));
    let (status, _) = gateway(&gw, "/counter/h/fetch", &fetch_spec(&target), Some("K-2"));
    println!("2nd request, same key, backend up: {status}");
    let gw = restart(&mut l);
    l.d.wait_until("no open turn", |d| open_turns(&d.dir) == 0);
    std::thread::sleep(Duration::from_secs(3));
    let (status, body) = gateway(&gw, "/counter/h/fetch", &fetch_spec(&target), Some("K-2"));
    println!(
        "3rd request, same key, after the restart: {status} {}",
        body.chars().take(100).collect::<String>()
    );
    assert!(
        !body.contains("EFFECT_OUTCOME_UNKNOWN"),
        "the key now answers EFFECT_OUTCOME_UNKNOWN for a request that was never sent"
    );
    assert!(target.seen("/hook").is_empty());
    assert_closed_when_quiet(&l.d, "an unsafe grant that met the outage");
}

/// Each kind of effect that can ask for a secret records the outage as its
/// result, and a fork replays the recorded errors exactly: every effect is
/// matched, nothing changes, and the fork never asks the backend (a fork never
/// fetches).
#[test]
fn a_fork_replays_the_secret_errors_that_production_recorded() {
    let Linked { mut d, bao, dir } = linked();
    let target = Target::start();
    d.grant("counter", "http:127.0.0.1", Some("idempotency-keyed"));
    d.grant("counter", "secret-reveal:stripe", None);
    d.kill9();
    bao.set_mode(Mode::Unavailable);
    d = Daemon::start(dir.path(), Some(&bao), "1s");
    let fork_point = d.applied_lsn();

    // (message, text, kind of effect, recorded status, recorded error)
    let cases = [
        (
            "hmac",
            "stripe\npayload".to_owned(),
            "crypto.hmac-sha256",
            pb::EffectStatus::Denied,
            "SECRET_UNAVAILABLE: stripe",
        ),
        (
            "reveal",
            "stripe".to_owned(),
            "secret.reveal",
            pb::EffectStatus::Denied,
            "SECRET_UNAVAILABLE: stripe",
        ),
        (
            "fetch-ok",
            fetch_spec(&target),
            "http.fetch",
            pb::EffectStatus::Network,
            "SECRET_UNAVAILABLE",
        ),
    ];
    for (name, text, ..) in &cases {
        let (status, answer) = d.api(
            "POST",
            "/v1/actors/counter/h/messages",
            json!({"name": name, "text": text, "reason": "an outage"}),
        );
        println!("{name}: {status} {answer}");
    }
    assert_eq!(open_turns(dir.path()), 0, "a turn was left open");
    for (name, _, kind, status, error) in &cases {
        let turns = message_turns(dir.path(), "counter/h", name);
        assert_eq!(turns.len(), 1, "{name}");
        assert_eq!(turns[0].effects.len(), 1, "{name}: {:?}", turns[0].effects);
        let effect = &turns[0].effects[0];
        assert_eq!(
            (effect.kind.as_str(), effect.status, effect.error.as_str()),
            (*kind, *status as i32, *error),
            "{name}"
        );
    }
    assert!(
        target.seen("/hook").is_empty(),
        "the request had no credential"
    );

    // The backend returns; so does the coverage that the reads need.
    bao.set_mode(Mode::Up);
    std::thread::sleep(Duration::from_secs(7));
    d.settle();
    let requests = bao.requests();
    let fork = d.mutate(
        "POST",
        "/v1/forks",
        json!({"at": fork_point, "reason": "the outage, replayed"}),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    d.mutate(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"reason": "the outage, replayed"}),
    );
    let diff = d.get(&format!("/v1/forks/{fork}/diff"));
    let summary = &diff["summary"];
    assert_eq!(summary["changed"], false, "{diff}");
    assert_eq!(summary["divergent_turns"], 0, "{diff}");
    assert_eq!(
        (
            &diff["effects"]["added"],
            &diff["effects"]["removed"],
            &diff["effects"]["changed"]
        ),
        (&json!(0), &json!(0), &json!(0)),
        "{diff}"
    );
    assert!(summary["exact"].as_u64() >= Some(3), "{diff}");
    for kind in ["approximate", "synthetic", "live"] {
        assert_eq!(summary[kind], 0, "{kind}: {diff}");
    }
    assert_eq!(bao.requests(), requests, "the fork asked the backend");
    assert!(target.seen("/hook").is_empty(), "the fork sent the request");
    assert_closed_when_quiet(&d, "a fork replay of the outage");
}

/// The turn records of `actor` that came from an HTTP request.
fn http_turns(dir: &Path, actor: &str) -> Vec<pb::TurnRecord> {
    log_records(dir)
        .into_iter()
        .filter_map(|r| match r {
            Record::TurnRecord(t) => Some(t),
            _ => None,
        })
        .filter(|t| {
            t.actor
                .as_ref()
                .is_some_and(|a| format!("{}/{}", a.kind, a.key) == actor)
                && matches!(
                    t.input.as_ref().and_then(|i| i.kind.as_ref()),
                    Some(pb::input::Kind::Http(_))
                )
        })
        .collect()
}

/// The lines of the daemon's log about secrets that could not be fetched.
fn fetch_failures(d: &Daemon) -> Vec<String> {
    d.serve_log()
        .lines()
        .filter(|line| line.contains("secret fetch failed"))
        .map(str::to_owned)
        .collect()
}

/// A secret that cannot be had ends its effect with `SECRET_UNAVAILABLE`
/// whatever the reason: an outage, a refusal, a configuration that no longer
/// has the backend. The guest is told no more; the log says which. A refusal
/// used to close the turn before the guest could decide, as failed with
/// `SECRET_VERSION_GONE` and a text about a recorded reveal.
fn assert_the_effects_failed_as_unavailable(dir: &Path, target: &Target) {
    let sent = message_turns(dir, "counter/h", "hmac");
    assert_eq!(sent.len(), 1, "{sent:?}");
    let effect = &sent[0].effects;
    assert_eq!(effect.len(), 1, "{effect:?}");
    assert_eq!(
        (
            effect[0].kind.as_str(),
            effect[0].status,
            effect[0].error.as_str()
        ),
        (
            "crypto.hmac-sha256",
            pb::EffectStatus::Denied as i32,
            "SECRET_UNAVAILABLE: stripe"
        ),
        "{effect:?}"
    );
    let outcome = sent[0].outcome.as_ref().unwrap();
    assert_eq!(outcome.kind, pb::OutcomeKind::Failed as i32, "{outcome:?}");
    assert!(
        outcome.message.contains("SECRET_UNAVAILABLE"),
        "{outcome:?}"
    );
    assert!(!outcome.message.contains("recoverable"), "{outcome:?}");
    assert_ne!(outcome.error_code, "SECRET_VERSION_GONE", "{outcome:?}");

    let requests = http_turns(dir, "counter/h");
    assert_eq!(requests.len(), 1, "{requests:?}");
    let effect = &requests[0].effects;
    assert_eq!(effect.len(), 1, "{effect:?}");
    assert_eq!(
        (
            effect[0].kind.as_str(),
            effect[0].status,
            effect[0].error.as_str()
        ),
        (
            "http.fetch",
            pb::EffectStatus::Network as i32,
            "SECRET_UNAVAILABLE"
        ),
        "{effect:?}"
    );
    assert!(
        target.seen("/hook").is_empty(),
        "the request had no credential"
    );
    assert_eq!(open_turns(dir), 0, "a turn was left open");
}

/// Both requests of the two tests below: one through the gateway whose handler
/// fails on the error, one `send` of an HMAC.
fn ask_for_the_secret_twice(d: &Daemon, target: &Target) {
    let gw = d.get("/v1/health")["http_listen"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, body) = gateway(&gw, "/counter/h/fetch", &fetch_spec(target), Some("K-R"));
    assert_eq!(status, 500, "{body}");
    assert!(body.contains("TURN_FAILED"), "{body}");
    let (status, answer) = d.api(
        "POST",
        "/v1/actors/counter/h/messages",
        json!({"name": "hmac", "text": "stripe\npayload", "reason": "a refusal"}),
    );
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["outcome"]["kind"], "failed", "{answer}");
}

#[test]
fn a_backend_that_refuses_ends_the_effect_like_an_outage_and_the_log_says_why() {
    let Linked { mut d, bao, dir } = linked();
    let target = Target::start();
    d.grant("counter", "http:127.0.0.1", Some("idempotency-keyed"));
    d.kill9();
    bao.set_mode(Mode::Forbidden);
    d = Daemon::start(dir.path(), Some(&bao), "1s");
    ask_for_the_secret_twice(&d, &target);
    assert_the_effects_failed_as_unavailable(dir.path(), &target);

    // The operator finds the reason in the log: a line when the refusal is
    // first remembered (the background cycle asks too, so it may come before
    // the first turn, and again for each window in which it lasts). It names
    // the secret, the backend and the version asked for, and has neither the
    // credential nor the words of the provider.
    let lines = fetch_failures(&d);
    assert!(!lines.is_empty(), "no line in the log");
    for line in &lines {
        for part in ["name=stripe", "backend=bao", "reason=denied"] {
            assert!(line.contains(part), "{part}: {line}");
        }
    }
    // The start-up inventory asked for the recorded version by its id, the
    // turns and the cycle for the current one.
    assert!(
        lines.iter().any(|line| line.contains("version=current")),
        "{lines:?}"
    );
    let log = d.serve_log();
    assert!(!log.contains(BAO_TOKEN), "the credential is in the log");
    assert!(
        !log.contains("permission denied"),
        "the provider's words are in the log"
    );
    assert_closed_when_quiet(&d, "a backend that refuses");
}

/// The configuration no longer has the backend that the link names: the node
/// cannot trust the binding, asks nobody, and says so.
#[test]
fn a_name_whose_backend_is_no_longer_configured_ends_the_effect_and_the_log_says_so() {
    let Linked { mut d, dir, .. } = linked();
    let target = Target::start();
    d.grant("counter", "http:127.0.0.1", Some("idempotency-keyed"));
    d.kill9();
    d = Daemon::start(dir.path(), None, "1s");
    ask_for_the_secret_twice(&d, &target);
    assert_the_effects_failed_as_unavailable(dir.path(), &target);
    let lines = fetch_failures(&d);
    assert!(!lines.is_empty(), "no line in the log");
    for line in &lines {
        for part in ["name=stripe", "backend=bao", "reason=binding"] {
            assert!(line.contains(part), "{part}: {line}");
        }
    }
    assert_closed_when_quiet(&d, "a backend that is no longer configured");
}

// ------------------------------------------- a fork and a name that is linked

/// A message into a fork that makes `counter/h` HMAC `payload` with `secret`:
/// the status, the body, and the effect the fork recorded for it.
fn fork_hmac(d: &Daemon, fork: &str, secret: &str) -> (u16, Value) {
    d.api(
        "POST",
        &format!("/v1/forks/{fork}/actors/counter/h/messages"),
        json!({"name": "hmac", "text": format!("{secret}\npayload"), "reason": "a linked name"}),
    )
}

/// An unmatched `crypto.*` of a fork (a turn that has no recording to answer
/// from) under a `compute` grant computes on the host. For a name linked at
/// the fork point it uses the value this process holds for that link (here
/// VALUE_2, the backend's), never the built-in store's older value (VALUE_1)
/// and never a fetch; when the process holds none (after a restart) the
/// effect is denied with SECRET_UNAVAILABLE and graded synthetic. A fork from
/// before the link or from after the unlink computes with the built-in value
/// as it always did, and a name that was never linked is unaffected.
#[test]
fn a_fork_computes_a_linked_name_with_the_value_held_for_its_link_and_never_fetches() {
    let bao = Bao::start();
    assert_eq!(bao.put("payments", "stripe", VALUE_2), 1);
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(dir.path(), Some(&bao), "2s");
    d.deploy("counter.wasm");
    for name in ["stripe", "plain"] {
        // compute: this test is the link decision, not the recorded default.
        d.mutate(
            "POST",
            "/v1/grants",
            json!({"kind": "counter", "capability": format!("secret:{name}"),
                   "in_forks": "compute", "reason": "secret backends"}),
        );
        d.mutate(
            "PUT",
            &format!("/v1/secrets/{name}"),
            json!({"text": VALUE_1, "reason": "a built-in value"}),
        );
    }
    let before_link = d.applied_lsn();
    d.link("stripe", "secret/payments#stripe");
    // A turn of main uses the linked value: the process holds it now.
    let used = d.send("counter/h", "hmac", "stripe\npayload");
    assert_eq!(
        used["reply"]["text"],
        hmac_hex(VALUE_2.as_bytes(), b"payload")
    );
    let linked_at = d.applied_lsn();
    d.mutate(
        "DELETE",
        "/v1/secrets/stripe/link",
        json!({"reason": "back to the built-in store"}),
    );
    d.settle();
    let unlinked_at = d.applied_lsn();
    // The unlink rebuilt the inventory in the background; let its fetch land
    // before the count that the forks are measured against is taken.
    d.quiet(&bao);
    let requests = bao.requests();
    let fork_at = |d: &Daemon, lsn: u64| {
        d.mutate(
            "POST",
            "/v1/forks",
            json!({"at": lsn, "reason": "a linked name"}),
        )["fork"]["name"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (before, linked, unlinked) = (
        fork_at(&d, before_link),
        fork_at(&d, linked_at),
        fork_at(&d, unlinked_at),
    );
    let built_in = hmac_hex(VALUE_1.as_bytes(), b"payload");
    let backend = hmac_hex(VALUE_2.as_bytes(), b"payload");

    // After the link: the held value of the link; the other name is the
    // built-in store's.
    let (status, answer) = fork_hmac(&d, &linked, "stripe");
    println!("linked fork, stripe: {status} {answer}");
    assert_eq!(status, 200, "{answer}");
    assert!(answer.to_string().contains(&backend), "{answer}");
    assert!(!answer.to_string().contains(&built_in), "{answer}");
    let (status, answer) = fork_hmac(&d, &linked, "plain");
    assert_eq!(status, 200, "{answer}");
    assert!(answer.to_string().contains(&built_in), "{answer}");

    // Before the link and after the unlink: the built-in store's, as before.
    for (fork, when) in [
        (&before, "before the link"),
        (&unlinked, "after the unlink"),
    ] {
        for name in ["stripe", "plain"] {
            let (status, answer) = fork_hmac(&d, fork, name);
            println!("{when}, {name}: {status} {answer}");
            assert_eq!(status, 200, "{when}, {name}: {answer}");
            assert!(
                answer.to_string().contains(&built_in),
                "{when}, {name}: {answer}"
            );
            assert!(!answer.to_string().contains("SECRET_"), "{answer}");
        }
    }
    assert_eq!(bao.requests(), requests, "a fork asked the backend");

    // A restarted process holds no value of the old link (main no longer
    // links the name, so nothing fetches it): denied, and graded synthetic.
    d.kill9();
    d = Daemon::start(dir.path(), Some(&bao), "2s");
    d.settle();
    d.quiet(&bao);
    let requests = bao.requests();
    let linked = fork_at(&d, linked_at);
    let (status, answer) = fork_hmac(&d, &linked, "stripe");
    println!("linked fork after a restart, stripe: {status} {answer}");
    assert_eq!(status, 200, "{answer}");
    let text = answer.to_string();
    assert!(
        text.contains("SECRET_UNAVAILABLE: stripe is linked"),
        "{text}"
    );
    assert!(text.contains("synthetic"), "{text}");
    for value in [&built_in, &backend] {
        assert!(!text.contains(value.as_str()), "{text}");
    }
    let (status, answer) = fork_hmac(&d, &linked, "plain");
    assert_eq!(status, 200, "{answer}");
    assert!(answer.to_string().contains(&built_in), "{answer}");
    assert_eq!(bao.requests(), requests, "a fork asked the backend");
    assert_closed_when_quiet(&d, "a fork and a linked name");
}

/// A foreign actor gets its secrets through the node's resolver, as the
/// effects of turns do (m23 section 6): `foreign add --secret` checks a
/// linked name through the cache (or its backend) and goes on to the image
/// (which does not exist here), and so does a name in the built-in store.
/// With the backend down and nothing cached, a linked name cannot be had:
/// SECRET_UNAVAILABLE, and no value of the built-in store instead. An unlink
/// makes the name the built-in store's again. (Starting an actor needs a
/// sandbox; the tests of `kronik-foreign` and of the node's resolver cover the
/// start, and the foreign tests of this crate need root and runsc.)
#[test]
fn a_foreign_actor_gets_a_linked_name_through_the_resolver() {
    let bao = Bao::start();
    assert_eq!(bao.put("payments", "stripe", VALUE_2), 1);
    let dir = tempfile::tempdir().unwrap();
    // Adds check that the runtime is an executable file, nothing more.
    let runsc = dir.path().join("runsc");
    std::fs::write(&runsc, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&runsc, std::fs::Permissions::from_mode(0o755)).unwrap();
    let extra = format!(
        "[foreign]\nrun_dir = {:?}\nrunsc_path = {:?}\n",
        dir.path().join("foreign-run"),
        runsc
    );
    let mut d = Daemon::start_with(dir.path(), Some(&bao), "2s", &extra);
    for name in ["stripe", "plain"] {
        d.mutate(
            "PUT",
            &format!("/v1/secrets/{name}"),
            json!({"text": VALUE_1, "reason": "a built-in value"}),
        );
    }
    d.link("stripe", "secret/payments#stripe");
    let add = |d: &Daemon, secret: &str| {
        d.api(
            "POST",
            "/v1/foreign",
            json!({"name": "echo", "image": "oci-layout:/nonexistent/image.oci", "port": 8080,
                   "secrets": [format!("API_KEY={secret}")], "dry_run": true,
                   "reason": "a linked name"}),
        )
    };
    let past_the_secrets = |what: &str, (status, answer): (u16, Value)| {
        println!("{what}: {status} {answer}");
        let code = answer["error"]["code"].as_str().unwrap_or("");
        assert!(
            !status.to_string().starts_with('2') && !code.starts_with("SECRET_"),
            "{what}: {status} {answer}"
        );
        for value in [VALUE_1, VALUE_2] {
            assert!(!answer.to_string().contains(value), "{what}: {answer}");
        }
    };
    past_the_secrets("linked", add(&d, "stripe"));
    past_the_secrets("built-in", add(&d, "plain"));

    // A restart with the backend down: nothing is cached.
    d.kill9();
    bao.set_mode(Mode::Unavailable);
    d = Daemon::start_with(dir.path(), Some(&bao), "1s", &extra);
    let (status, answer) = add(&d, "stripe");
    println!("linked, backend down: {status} {answer}");
    assert_eq!(status, 503, "{answer}");
    assert_eq!(answer["error"]["code"], "SECRET_UNAVAILABLE", "{answer}");
    for value in [VALUE_1, VALUE_2] {
        assert!(!answer.to_string().contains(value), "{answer}");
    }
    past_the_secrets("built-in, backend down", add(&d, "plain"));

    // Unlinked again: the built-in store's name, as before.
    bao.set_mode(Mode::Up);
    std::thread::sleep(Duration::from_secs(6));
    d.mutate(
        "DELETE",
        "/v1/secrets/stripe/link",
        json!({"reason": "back to the built-in store"}),
    );
    d.settle();
    d.quiet(&bao);
    let requests = bao.requests();
    past_the_secrets("unlinked", add(&d, "stripe"));
    assert_eq!(
        bao.requests(),
        requests,
        "an unlinked name asked the backend"
    );
}
