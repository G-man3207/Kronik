//! Tokens and scopes (M5) against a real `kronik serve`: `kronik token`,
//! `$KRONIK_TOKEN` on the socket, the API over TCP (plain on loopback, TLS
//! elsewhere) with bearer tokens, forced no-PII forks, and the token id
//! recorded with every mutation.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::free_port;
use serde_json::{Value, json};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

/// A `kronik` command with no setting from the developer's shell.
fn command() -> Command {
    let mut c = Command::new(KRONIK);
    for var in [
        "KRONIK_CONFIG",
        "KRONIK_DATA_DIR",
        "KRONIK_HTTP_LISTEN",
        "KRONIK_ADMIN_LISTEN",
        "KRONIK_API_SOCKET",
        "KRONIK_API_LISTEN",
        "KRONIK_TOKEN",
        "KRONIK_MASTER_KEY_FILE",
    ] {
        c.env_remove(var);
    }
    // The tests' temporary file system may have less than the reserve.
    c.env("KRONIK_DISK_RESERVE", "0B");
    c.stdin(Stdio::null());
    c
}

/// `kronik serve` with its socket in a temporary directory and the API on
/// TCP at `api`; killed when dropped.
struct Daemon {
    child: Child,
    socket: PathBuf,
    api: String,
    dir: tempfile::TempDir,
}

impl Daemon {
    fn start(extra: &[&str]) -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let api = format!("127.0.0.1:{}", free_port());
        let log = std::fs::File::create(dir.path().join("serve.log")).unwrap();
        let child = command()
            .arg("serve")
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            .args(["--http-listen", &format!("127.0.0.1:{}", free_port())])
            .args(["--admin-listen", &format!("127.0.0.1:{}", free_port())])
            .args(["--api-listen", &api])
            .arg("--api-socket")
            .arg(&socket)
            .args(extra)
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon {
            child,
            socket,
            api,
            dir,
        };
        let up = (0..600).any(|_| {
            let ok = d.cli(None, &["--json", "actors", "list"]).status.success();
            if !ok {
                std::thread::sleep(Duration::from_millis(100));
            }
            ok
        });
        assert!(up, "kronik serve did not start:\n{}", d.log());
        d
    }

    /// `kronik --socket <socket> <args>`, as `token` when given.
    fn cli(&self, token: Option<&str>, args: &[&str]) -> Output {
        let mut c = command();
        c.arg("--socket").arg(&self.socket).args(args);
        if let Some(token) = token {
            c.env("KRONIK_TOKEN", token);
        }
        c.output().unwrap()
    }

    fn json(&self, token: Option<&str>, args: &[&str]) -> Value {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        let out = self.cli(token, &all);
        assert!(out.status.success(), "{args:?}: {out:?}");
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("serve.log")).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

/// One HTTP/1.1 request over `stream`: the status, the head and the body.
fn exchange(
    stream: &mut dyn ReadWrite,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> (u16, String, String) {
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
         Content-Length: {}\r\n",
        body.len()
    );
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    let mut out = Vec::new();
    // A TLS server may close without close_notify after the response.
    let _ = stream.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, head.to_owned(), body.to_owned())
}

trait ReadWrite: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> ReadWrite for T {}

/// A request to the API over plain TCP.
fn tcp(
    addr: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> (u16, String, Value) {
    let mut stream = TcpStream::connect(addr).unwrap();
    let (status, head, body) = exchange(&mut stream, method, path, token, body);
    let value = serde_json::from_str(&body).unwrap_or(Value::String(body));
    (status, head, value)
}

/// `GET path` on the socket without a token: the API's JSON.
fn socket_get(socket: &Path, path: &str) -> Value {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    let (status, _, body) = exchange(&mut stream, "GET", path, None, "");
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

#[test]
fn tokens_carry_scopes_on_every_listener_and_are_recorded() {
    let d = Daemon::start(&[]);
    let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();

    // No tokens yet; creating one prints it once.
    let none = d.cli(None, &["token", "list"]);
    assert!(text(&none).contains("No tokens."), "{}", text(&none));
    let created = d.json(
        None,
        &[
            "token", "create", "--name", "agent-1", "--reason", "ci agent",
        ],
    );
    let agent = created["secret"].as_str().unwrap().to_owned();
    assert!(agent.starts_with("kronik_"), "{created}");
    assert_eq!(
        created["token"]["scopes"],
        json!(["read", "fork", "propose"])
    );
    assert_eq!(created["token"]["token_id"], "token:agent-1");
    assert_eq!(created["token"]["created_by"], format!("unix:uid={uid}"));
    let ops_out = d.cli(
        None,
        &[
            "token",
            "create",
            "--name",
            "ops",
            "--scopes",
            "read,operate,promote",
            "--reason",
            "ops",
        ],
    );
    let shown = text(&ops_out);
    assert!(ops_out.status.success(), "{shown}");
    assert!(
        shown.contains("Created token ops, recorded as token:ops"),
        "{shown}"
    );
    assert!(
        shown.contains("This is the only time the token is shown"),
        "{shown}"
    );
    let ops = shown
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("Token "))
        .map(|rest| rest.trim().to_owned())
        .unwrap();
    assert!(ops.starts_with("kronik_"), "{shown}");

    // A dry run writes nothing; names are never reused; scopes are checked.
    let dry = d.cli(
        None,
        &[
            "token",
            "create",
            "--name",
            "dry",
            "--reason",
            "x",
            "--dry-run",
        ],
    );
    assert!(
        text(&dry).contains(
            "Dry run: token dry can be created with the scopes read, fork, propose; nothing was written"
        ),
        "{}",
        text(&dry)
    );
    let again = d.cli(
        None,
        &["token", "create", "--name", "agent-1", "--reason", "x"],
    );
    assert_eq!(again.status.code(), Some(1));
    assert!(
        text(&again).contains("names are never reused"),
        "{}",
        text(&again)
    );
    let bad = d.cli(
        None,
        &[
            "token",
            "create",
            "--name",
            "x",
            "--scopes",
            "read,root",
            "--reason",
            "x",
        ],
    );
    assert!(
        text(&bad).contains("unknown scope \"root\""),
        "{}",
        text(&bad)
    );
    let listed = d.json(None, &["token", "list"]);
    let names: Vec<&str> = listed["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["agent-1", "ops"]);
    // The data directory has the hashes, never the tokens.
    let db = std::fs::read(d.dir.path().join("data/keys/tokens.db")).unwrap();
    let secret = &agent.as_bytes()["kronik_".len()..];
    assert!(!db.windows(secret.len()).any(|w| w == secret));

    // The agent's token reads and forks, but neither operates nor manages
    // tokens; its errors name the scope.
    assert!(d.cli(Some(&agent), &["actors", "list"]).status.success());
    let grant = d.cli(
        Some(&agent),
        &["grant", "counter", "http:example.com", "--reason", "x"],
    );
    assert_eq!(grant.status.code(), Some(1));
    let shown = text(&grant);
    assert!(shown.contains("SCOPE_MISSING"), "{shown}");
    assert!(
        shown.contains("token token:agent-1 lacks scope operate"),
        "{shown}"
    );
    let manage = d.cli(Some(&agent), &["token", "list"]);
    assert!(
        text(&manage).contains("lacks scope admin"),
        "{}",
        text(&manage)
    );

    // Mutations record the token: a deployment and an operator message.
    let deployed = d.cli(Some(&ops), &["deploy", COUNTER, "--reason", "ops deploy"]);
    assert!(deployed.status.success(), "{}", text(&deployed));
    let deployments = d.json(None, &["deployments", "list"]);
    assert_eq!(
        deployments["deployments"][0]["token_id"], "token:ops",
        "{deployments}"
    );
    assert_eq!(deployments["deployments"][0]["reason"], "ops deploy");
    let listed = d.cli(None, &["deployments", "list"]);
    assert!(text(&listed).contains("token:ops"), "{}", text(&listed));
    let sent = d.json(
        Some(&ops),
        &["send", "counter/a", "increment", "--reason", "ops message"],
    );
    let turn_id = sent["turn_id"].as_str().unwrap();
    let turn = socket_get(&d.socket, &format!("/v1/turns/{turn_id}"));
    assert_eq!(turn["input"]["token_id"], "token:ops", "{turn}");
    assert_eq!(turn["input"]["reason"], "ops message", "{turn}");
    // Without a token the socket's caller is its user.
    let local = d.json(
        None,
        &["send", "counter/a", "increment", "--reason", "local"],
    );
    let turn = socket_get(
        &d.socket,
        &format!("/v1/turns/{}", local["turn_id"].as_str().unwrap()),
    );
    assert_eq!(
        turn["input"]["token_id"],
        format!("unix:uid={uid}"),
        "{turn}"
    );

    // A token without pii:read always gets a fork without personal data.
    let forked = d.json(
        Some(&agent),
        &["fork", "create", "--at", "now", "--reason", "agent fork"],
    );
    assert_eq!(forked["fork"]["no_pii"], true, "{forked}");
    let forked = d.json(
        None,
        &["fork", "create", "--at", "now", "--reason", "local fork"],
    );
    assert_eq!(forked["fork"]["no_pii"], false, "{forked}");

    // Over TCP every request needs a token.
    let (status, head, body) = tcp(&d.api, "GET", "/v1/actors", None, "");
    assert_eq!(status, 401, "{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("www-authenticate: bearer"),
        "{head}"
    );
    assert_eq!(body["error"]["code"], "UNAUTHENTICATED", "{body}");
    let (status, _, body) = tcp(&d.api, "GET", "/v1/actors", Some(&agent), "");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["actors"][0]["key"], "a", "{body}");
    let (status, _, body) = tcp(&d.api, "GET", "/v1/tokens", Some(&agent), "");
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (403, Some("SCOPE_MISSING"))
    );
    let (status, _, body) = tcp(&d.api, "GET", "/v1/actors", Some("kronik_wrong"), "");
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (401, Some("UNAUTHENTICATED"))
    );
    // MCP on TCP too: refused without a token, served with one.
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "kronik-test", "version": "0"}}
    })
    .to_string();
    let (status, _, _) = tcp(&d.api, "POST", "/mcp", None, &init);
    assert_eq!(status, 401);
    let (status, _, body) = tcp(&d.api, "POST", "/mcp", Some(&agent), &init);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["serverInfo"]["name"], "kronik", "{body}");

    // A revoked token authenticates nobody, on either listener.
    let dry = d.cli(
        None,
        &["token", "revoke", "agent-1", "--reason", "x", "--dry-run"],
    );
    assert!(
        text(&dry).contains("Dry run: token agent-1 can be revoked"),
        "{}",
        text(&dry)
    );
    assert!(d.cli(Some(&agent), &["actors", "list"]).status.success());
    let revoked = d.cli(None, &["token", "revoke", "agent-1", "--reason", "rotated"]);
    assert!(
        text(&revoked).contains("Revoked token agent-1: it authenticates nobody from now on"),
        "{}",
        text(&revoked)
    );
    let refused = d.cli(Some(&agent), &["actors", "list"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        text(&refused).contains("UNAUTHENTICATED"),
        "{}",
        text(&refused)
    );
    let (status, _, _) = tcp(&d.api, "GET", "/v1/actors", Some(&agent), "");
    assert_eq!(status, 401);
    let listed = d.cli(None, &["token", "list"]);
    assert!(text(&listed).contains("revoked 20"), "{}", text(&listed));
    let unknown = d.cli(None, &["token", "revoke", "nobody", "--reason", "x"]);
    assert!(
        text(&unknown).contains("TOKEN_NOT_FOUND"),
        "{}",
        text(&unknown)
    );

    // A value that cannot be a token is refused before anything is sent.
    let spaced = d.cli(Some("kronik_a b"), &["actors", "list"]);
    assert_eq!(spaced.status.code(), Some(1));
    assert!(
        text(&spaced).contains("$KRONIK_TOKEN is not a token"),
        "{}",
        text(&spaced)
    );
}

#[test]
fn the_tcp_api_is_loopback_only_without_tls() {
    let dir = tempfile::tempdir().unwrap();
    let out = command()
        .arg("serve")
        .arg("--data-dir")
        .arg(dir.path().join("data"))
        .args(["--api-listen", &format!("0.0.0.0:{}", free_port())])
        .arg("--api-socket")
        .arg(dir.path().join("api.sock"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("is not a loopback address and [tls] is off"),
        "{stderr}"
    );
}

#[test]
fn with_tls_the_tcp_api_serves_https() {
    let dir = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(dir.path().join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.path().join("key.pem"), key.serialize_pem()).unwrap();
    let config = dir.path().join("kronik.toml");
    let port = free_port();
    std::fs::write(
        &config,
        format!(
            "[server]\nhttp_listen = \"127.0.0.1:{}\"\nadmin_listen = \"127.0.0.1:{}\"\n\
             api_listen = \"0.0.0.0:{port}\"\n\n\
             [tls]\nmode = \"files\"\ncert_file = {:?}\nkey_file = {:?}\n",
            free_port(),
            free_port(),
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
        ),
    )
    .unwrap();
    let d = Daemon {
        child: command()
            .args(["serve", "--config"])
            .arg(&config)
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            .arg("--api-socket")
            .arg(dir.path().join("api.sock"))
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        socket: dir.path().join("api.sock"),
        api: format!("127.0.0.1:{port}"),
        dir,
    };
    let up = (0..600).any(|_| {
        let ok = d.cli(None, &["--json", "actors", "list"]).status.success();
        if !ok {
            std::thread::sleep(Duration::from_millis(100));
        }
        ok
    });
    assert!(up);
    let created = d.json(
        None,
        &[
            "token", "create", "--name", "remote", "--scopes", "read", "--reason", "tls test",
        ],
    );
    let token = created["secret"].as_str().unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let https = |token: Option<&str>| {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(tls_config.clone()), name).unwrap();
        let mut sock = TcpStream::connect(&d.api).unwrap();
        let mut stream = rustls::Stream::new(&mut conn, &mut sock);
        let (status, _, body) = exchange(&mut stream, "GET", "/v1/health", token, "");
        (status, body)
    };
    let (status, body) = https(Some(token));
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"status\":\"ok\""), "{body}");
    let (status, body) = https(None);
    assert_eq!(status, 401, "{body}");
    // Plain HTTP gets no answer from a TLS listener.
    let mut plain = TcpStream::connect(&d.api).unwrap();
    plain
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (status, _, _) = exchange(&mut plain, "GET", "/v1/health", Some(token), "");
    assert_eq!(status, 0);
}
