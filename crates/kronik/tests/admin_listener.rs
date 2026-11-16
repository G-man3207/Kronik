//! The TLS admin listener is a public API client: it serves every documented
//! `/v1` GET operation, including the streamed blob content that the buffered
//! router refuses (issue #123).

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use common::free_port;
use serde_json::{Value, json};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

const SETTINGS_ENV: [&str; 7] = [
    "KRONIK_CONFIG",
    "KRONIK_DATA_DIR",
    "KRONIK_HTTP_LISTEN",
    "KRONIK_ADMIN_LISTEN",
    "KRONIK_API_SOCKET",
    "KRONIK_MASTER_KEY_FILE",
    "KRONIK_TOKEN",
];

fn command() -> Command {
    let mut command = Command::new(KRONIK);
    for var in SETTINGS_ENV {
        command.env_remove(var);
    }
    command.env("KRONIK_DISK_RESERVE", "0B");
    command.stdin(Stdio::null());
    command
}

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
        let config = dir.join("kronik.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\napi_socket = {:?}\n\
                 http_listen = \"127.0.0.1:0\"\nadmin_listen = \"127.0.0.1:{admin_port}\"\n\n\
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

    /// A GET over the TLS admin listener. `streaming` stops after the
    /// response head, which is all an SSE answer gives without waiting.
    fn admin_get(&self, path: &str, bearer: &str, streaming: bool) -> Answer {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut connection =
            rustls::ClientConnection::new(Arc::new(self.tls.clone()), name).unwrap();
        let mut socket = TcpStream::connect(&self.admin).unwrap();
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
        format!("b3:{}", blake3::hash(&admin.body).to_hex()),
        hash,
        "the admin listener answered with the addressed blob's bytes"
    );
    for name in ["content-length", "x-kronik-blob-size", "content-type"] {
        assert_eq!(admin.header(name), local.header(name), "{name}");
    }
}
