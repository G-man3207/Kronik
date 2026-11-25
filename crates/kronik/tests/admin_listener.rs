//! The TLS admin listener is a public API client: it serves every documented
//! `/v1` GET operation, including the streamed blob content that the buffered
//! router refuses (issue #123). A subject's blob content needs `pii:read` on
//! that listener, the Unix socket and the TCP API (issue #171).

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

#[path = "support/blob_fixtures.rs"]
mod blob_fixtures;

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use blob_fixtures::pattern;
use common::{command, free_port};
use serde_json::{Value, json};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

/// One HTTP answer, parsed from an API socket or the admin listener.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn error_code(&self) -> Option<String> {
        let value: Value = serde_json::from_slice(&self.body).ok()?;
        value["error"]["code"].as_str().map(str::to_owned)
    }
}

fn read_answer(reader: impl Read) -> Answer {
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

struct Daemon {
    dir: PathBuf,
    child: Option<Child>,
    admin: String,
    /// `server.api_listen`. With `[tls] mode = "files"` this is HTTPS, the
    /// same certificate as the admin listener.
    api: String,
    tls: rustls::ClientConfig,
}

impl Daemon {
    fn start(dir: &Path) -> Daemon {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
        let admin_port = free_port();
        let api_port = free_port();
        let config = dir.join("kronik.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\napi_socket = {:?}\n\
                 http_listen = \"127.0.0.1:0\"\napi_listen = \"127.0.0.1:{api_port}\"\n\
                 admin_listen = \"127.0.0.1:{admin_port}\"\n\n\
                 [tls]\nmode = \"files\"\ncert_file = {:?}\nkey_file = {:?}\n",
                dir.join("data"),
                dir.join("api.sock"),
                dir.join("cert.pem"),
                dir.join("key.pem"),
            ),
        )
        .unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = command()
            .arg("serve")
            .arg("--config")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let daemon = Daemon {
            dir: dir.to_path_buf(),
            child: Some(child),
            admin: format!("127.0.0.1:{admin_port}"),
            api: format!("127.0.0.1:{api_port}"),
            tls,
        };
        for _ in 0..800 {
            if daemon.try_api("GET", "/v1/health", Value::Null).is_some() {
                return daemon;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("kronik serve did not start: {}", daemon.log());
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    fn try_api(&self, method: &str, path: &str, body: Value) -> Option<(u16, Value)> {
        let mut stream = UnixStream::connect(self.dir.join("api.sock")).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nhost: kronik\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        )
        .ok()?;
        let answer = read_answer(stream);
        Some((answer.status, serde_json::from_slice(&answer.body).ok()?))
    }

    fn api(&self, method: &str, path: &str, body: Value) -> Value {
        let (status, value) = self
            .try_api(method, path, body)
            .unwrap_or_else(|| panic!("{method} {path} failed: {}", self.log()));
        assert_eq!(status, 200, "{method} {path}: {value}\n{}", self.log());
        value
    }

    fn unix_get(&self, path: &str, bearer: Option<&str>) -> Answer {
        let mut stream = UnixStream::connect(self.dir.join("api.sock")).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let auth = bearer.map_or(String::new(), |t| format!("authorization: Bearer {t}\r\n"));
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nhost: kronik\r\n{auth}connection: close\r\n\r\n"
        )
        .unwrap();
        read_answer(stream)
    }

    /// A GET over TLS on `addr` (the admin listener or the TCP API).
    /// `streaming` stops after the response head, which is all an SSE
    /// answer gives without waiting.
    fn tls_get(&self, addr: &str, path: &str, bearer: &str, streaming: bool) -> Answer {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut connection =
            rustls::ClientConnection::new(Arc::new(self.tls.clone()), name).unwrap();
        let mut socket = TcpStream::connect(addr).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut stream = rustls::Stream::new(&mut connection, &mut socket);
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {bearer}\r\n\
             connection: close\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();
        if streaming {
            let mut reader = BufReader::new(stream);
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
            return Answer {
                status,
                headers: Vec::new(),
                body: Vec::new(),
            };
        }
        read_answer(stream)
    }

    /// A GET over the TLS admin listener.
    fn admin_get(&self, path: &str, bearer: &str, streaming: bool) -> Answer {
        self.tls_get(&self.admin, path, bearer, streaming)
    }

    /// `GET path` with `bearer` on the Unix socket, the TCP API and the TLS
    /// admin listener. The socket sends the token: without one the peer has
    /// every scope, including `pii:read`.
    fn content(&self, path: &str, bearer: &str) -> Vec<(&'static str, Answer)> {
        vec![
            ("unix", self.unix_get(path, Some(bearer))),
            ("tcp", self.tls_get(&self.api, path, bearer, false)),
            ("admin", self.tls_get(&self.admin, path, bearer, false)),
        ]
    }

    /// [`Daemon::content`], waiting out the fail-closed secret-coverage
    /// window after a secret change (ADR 0108). A scope refusal is not
    /// retried: it is decided before the matcher is built.
    fn content_when_ready(&self, path: &str, bearer: &str) -> Vec<(&'static str, Answer)> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let answers = self.content(path, bearer);
            let waiting = answers
                .iter()
                .any(|(_, answer)| answer.error_code().as_deref() == Some("SECRET_UNAVAILABLE"));
            if !waiting || Instant::now() >= deadline {
                return answers;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn token(&self, name: &str, scopes: &[&str]) -> String {
        self.api(
            "POST",
            "/v1/tokens",
            json!({"name": name, "scopes": scopes, "reason": "admin listener test"}),
        )["secret"]
            .as_str()
            .unwrap()
            .to_owned()
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

/// Every GET operation the OpenAPI document declares is served on the admin
/// listener (ADR 0104), not just on the socket and TCP listeners. The streamed
/// blob answer is the one the buffered router cannot give, and issue #123 was
/// its omission here.
#[test]
fn the_admin_listener_serves_every_declared_get_operation() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path());
    let bearer = d.token("admin-parity", &["admin"]);

    for op in kronik_api::openapi::OPERATIONS
        .iter()
        .filter(|op| op.method == "GET")
    {
        let path = op
            .path
            .replace("{hash}", &format!("b3:{}", "0".repeat(64)))
            .replace("{kind}", "missing")
            .replace("{key}", "missing")
            .replace("{id}", "missing")
            .replace("{name}", "missing")
            .replace("{target}", "missing")
            .replace("{stream}", "missing")
            .replace("{epoch}", "1");
        let streaming = matches!(op.answer, kronik_api::openapi::Answer::EventsSse);
        let answer = d.admin_get(&path, &bearer, streaming);
        assert!(
            answer.status != 405,
            "{} {path} is not served by the admin listener",
            op.method
        );
        if matches!(op.answer, kronik_api::openapi::Answer::Bytes) {
            assert_eq!(
                (answer.status, answer.error_code()),
                (404, Some("BLOB_NOT_FOUND".to_owned())),
                "{} {path}: {}",
                op.method,
                String::from_utf8_lossy(&answer.body)
            );
            continue;
        }
        if streaming {
            assert_eq!(answer.status, 200, "{} {path}", op.method);
            continue;
        }
        assert_ne!(
            answer.error_code(),
            Some("ROUTE_NOT_FOUND".to_owned()),
            "{} {path} is documented but the admin listener does not route it: {}",
            op.method,
            String::from_utf8_lossy(&answer.body)
        );
    }
}

/// `GET /v1/blobs/{hash}/content` on the TLS admin listener answers with the
/// same bytes, length and headers as the Unix socket.
#[test]
fn the_admin_listener_streams_a_blobs_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path());

    let wasm = std::fs::read(MEDIA).unwrap();
    d.api(
        "POST",
        "/v1/deployments",
        json!({
            "wasm_base64": base64::engine::general_purpose::STANDARD.encode(wasm),
            "reason": "admin blob content",
        }),
    );
    // The callee's `write` makes a blob and the caller retains it.
    let turn = d.api(
        "POST",
        "/v1/actors/media/m/messages",
        json!({
            "name": "call?to=m2&op=write?size=1000&keep=1",
            "reason": "admin blob content",
        }),
    );
    let reply = turn["reply"]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{turn}"));
    let hash = reply
        .strip_prefix("reply blob ")
        .and_then(|rest| rest.strip_suffix(" retained"))
        .and_then(|rest| rest.split_once(' '))
        .map(|(hash, _)| hash)
        .unwrap_or_else(|| panic!("{reply}"))
        .to_owned();

    let bearer = d.token("admin-blob-reader", &["read"]);
    let path = format!("/v1/blobs/{hash}/content");
    let local = d.unix_get(&path, None);
    let admin = d.admin_get(&path, &bearer, false);
    assert_eq!(
        local.status,
        200,
        "{}",
        String::from_utf8_lossy(&local.body)
    );
    assert_eq!(
        (admin.status, admin.error_code()),
        (200, None),
        "{}\n{}",
        String::from_utf8_lossy(&admin.body),
        d.log()
    );
    assert_eq!(admin.body, local.body);
    assert_eq!(admin.body.len(), 1000);
    assert_eq!(
        blob_fixtures::hash(&admin.body),
        hash,
        "the admin listener answered with the addressed blob's bytes"
    );
    for name in ["content-length", "x-kronik-blob-size", "content-type"] {
        assert_eq!(admin.header(name), local.header(name), "{name}");
    }
}

/// A 401 from the TLS admin listener carries the bearer challenge RFC 9110
/// §15.5.2 requires, as the other API listeners' do (issue #392).
#[test]
fn an_unauthorized_admin_response_carries_the_bearer_challenge() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path());
    let answer = d.admin_get("/v1/actors", "kronik_wrong", false);
    assert_eq!(
        (answer.status, answer.error_code().as_deref()),
        (401, Some("UNAUTHENTICATED")),
        "{}\n{}",
        String::from_utf8_lossy(&answer.body),
        d.log()
    );
    assert_eq!(answer.header("www-authenticate"), Some("Bearer"));
}

/// `bytes` with every `secret` replaced by `[secret:name]`, as the output
/// matcher does.
fn scrubbed(bytes: &[u8], secret: &[u8], name: &str) -> Vec<u8> {
    let marker = format!("[secret:{name}]");
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(secret) {
            out.extend_from_slice(marker.as_bytes());
            i += secret.len();
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// A message whose turn writes `size` bytes. `subject` is the turn's
/// default subject, so the blob is that subject's.
fn written(d: &Daemon, key: &str, size: u64, subject: Option<&str>) -> String {
    let mut body = json!({
        "name": format!("write?size={size}"),
        "reason": "blob content scope",
    });
    if let Some(subject) = subject {
        body["subject"] = json!(subject);
    }
    let turn = d.api("POST", &format!("/v1/actors/media/{key}/messages"), body);
    let hash = turn["reply"]["blob"]["hash"]
        .as_str()
        .unwrap_or_else(|| panic!("{turn}"))
        .to_owned();
    assert_eq!(turn["reply"]["blob"]["size"], size, "{turn}");
    hash
}

/// `GET /v1/blobs/{hash}/content` of a subject's blob is `SCOPE_MISSING`
/// for a token that has `read` and not `pii:read`, on the Unix socket, the
/// TCP API and the TLS admin listener, and returns no blob bytes. The same
/// hash with `pii:read` returns the bytes through the secret output matcher.
/// A blob with no subject stays readable with `read` alone (issue #171).
#[test]
fn a_subjects_blob_content_needs_pii_read_on_every_listener() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path());
    let wasm = std::fs::read(MEDIA).unwrap();
    d.api(
        "POST",
        "/v1/deployments",
        json!({
            "wasm_base64": base64::engine::general_purpose::STANDARD.encode(wasm),
            "reason": "blob content scope",
        }),
    );

    const SUBJECT_SIZE: u64 = 2048;
    const PLAIN_SIZE: u64 = 40;
    let subject_bytes = pattern(SUBJECT_SIZE);
    let plain_bytes = pattern(PLAIN_SIZE);
    // Inside the subject blob, absent from the plain one.
    let secret = subject_bytes[100..124].to_vec();
    assert!(!plain_bytes.windows(secret.len()).any(|w| w == secret));

    let subject_hash = written(&d, "s", SUBJECT_SIZE, Some("user:1"));
    let plain_hash = written(&d, "p", PLAIN_SIZE, None);
    assert!(
        subject_hash.starts_with("b3s:"),
        "a subject's blob is keyed: {subject_hash}"
    );
    assert!(plain_hash.starts_with("b3:"), "{plain_hash}");
    let subject_row = d.api("GET", &format!("/v1/blobs/{subject_hash}"), Value::Null);
    assert_eq!(subject_row["subject"], "user:1", "{subject_row}");
    let plain_row = d.api("GET", &format!("/v1/blobs/{plain_hash}"), Value::Null);
    assert_eq!(plain_row["subject"], Value::Null, "{plain_row}");

    // After the writes, so the stored bytes still hold the value. The
    // download matcher is what must replace it.
    d.api(
        "PUT",
        "/v1/secrets/token",
        json!({
            "base64": base64::engine::general_purpose::STANDARD.encode(&secret),
            "reason": "a value in a subject blob",
        }),
    );
    let expected = scrubbed(&subject_bytes, &secret, "token");
    assert!(expected.len() < subject_bytes.len());
    assert!(!expected.windows(secret.len()).any(|w| w == secret));

    let reader = d.token("blob-reader", &["read"]);
    let pii = d.token("blob-pii", &["read", "pii:read"]);
    let subject_path = format!("/v1/blobs/{subject_hash}/content");
    let plain_path = format!("/v1/blobs/{plain_hash}/content");

    for (via, answer) in d.content(&subject_path, &reader) {
        assert_eq!(
            (answer.status, answer.error_code().as_deref()),
            (403, Some("SCOPE_MISSING")),
            "{via}: {}\n{}",
            String::from_utf8_lossy(&answer.body),
            d.log()
        );
        assert_eq!(
            answer.header("content-type"),
            Some("application/json"),
            "{via}"
        );
        assert!(
            answer.body.len() < SUBJECT_SIZE as usize,
            "{via} returned {} bytes of a refused blob",
            answer.body.len()
        );
        assert!(
            !answer.body.windows(16).any(|w| w == &subject_bytes[..16]),
            "{via} included the blob's bytes"
        );
        assert!(
            !answer.body.windows(secret.len()).any(|w| w == secret),
            "{via} included the secret value"
        );
    }

    for (via, answer) in d.content_when_ready(&subject_path, &pii) {
        assert_eq!(
            (answer.status, answer.error_code()),
            (200, None),
            "{via}: {}\n{}",
            String::from_utf8_lossy(&answer.body),
            d.log()
        );
        assert_eq!(answer.body, expected, "{via} did not scrub the download");
        assert_eq!(
            answer.header("content-type"),
            Some("application/octet-stream"),
            "{via}"
        );
        assert_eq!(
            answer.header("content-length"),
            Some(expected.len().to_string()).as_deref(),
            "{via}"
        );
        assert_eq!(
            answer.header("x-kronik-blob-size"),
            Some(SUBJECT_SIZE.to_string()).as_deref(),
            "{via}"
        );
    }

    for (via, answer) in d.content_when_ready(&plain_path, &reader) {
        assert_eq!(
            (answer.status, answer.error_code()),
            (200, None),
            "{via}: {}\n{}",
            String::from_utf8_lossy(&answer.body),
            d.log()
        );
        assert_eq!(answer.body, plain_bytes, "{via}");
    }
}
