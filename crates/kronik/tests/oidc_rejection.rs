//! Rejected OIDC ID tokens mint no browser session, and an accepted one's
//! session ends at its `exp`, at most an hour after login.
//!
//! `verify` turns off the JWT library's expiry and `nbf` checks and enforces
//! issuer, audience, `azp`, `nbf`, skew, expiry, nonce, algorithm and a header
//! without `jku` itself. The browser script covers that path, and no CI step
//! runs it. This test completes the code exchange against `kronik serve`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

#[path = "../../kronik-api/tests/common/oidc_provider.rs"]
mod oidc_provider;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");

/// Modes the fixture can mint, and that the callback must reject. `signature`
/// is a key that is not the published one. `algorithm` is RS384. `azp` lists
/// this client and another audience and authorizes the other client. `nbf` is
/// still in the future. `jku` is a header on an otherwise valid token.
const REJECTED: [&str; 9] = [
    "expired",
    "issuer",
    "audience",
    "nonce",
    "signature",
    "algorithm",
    "azp",
    "nbf",
    "jku",
];

fn command() -> Command {
    let mut command = Command::new(KRONIK);
    for var in [
        "KRONIK_CONFIG",
        "KRONIK_DATA_DIR",
        "KRONIK_HTTP_LISTEN",
        "KRONIK_ADMIN_LISTEN",
        "KRONIK_API_SOCKET",
        "KRONIK_API_LISTEN",
        "KRONIK_TOKEN",
        "KRONIK_MASTER_KEY_FILE",
        "KRONIK_MASTER_KEY",
    ] {
        command.env_remove(var);
    }
    command.env("KRONIK_DISK_RESERVE", "0B");
    command.stdin(Stdio::null());
    command
}

struct Answer {
    status: u16,
    body: Vec<u8>,
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
    Answer { status, body }
}

struct Daemon {
    child: Option<Child>,
    dir: PathBuf,
    socket: PathBuf,
}

impl Daemon {
    fn start(dir: &Path, provider: &oidc_provider::OwnedOidc, admin: &str) -> Daemon {
        let data = dir.join("data");
        let socket = dir.join("api.sock");
        let config = dir.join("kronik.toml");
        let redirect = format!("{}/v1/auth/callback", provider.origin);
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {data:?}\napi_socket = {socket:?}\n\
                 http_listen = \"127.0.0.1:0\"\nadmin_listen = \"127.0.0.1:0\"\n\n\
                 [tls]\nmode = \"files\"\ncert_file = {:?}\nkey_file = {:?}\n\
                 [oidc]\nissuer = {:?}\nclient_id = \"kronik-ui\"\n\
                 redirect_uri = {redirect:?}\nca_file = {:?}\n\
                 [[oidc.bindings]]\nsubject = \"fixture-reviewer\"\ntoken = \"ui-reviewer\"\n",
                provider.certificate(),
                provider.key(),
                provider.issuer,
                provider.ca(),
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
            .env("KRONIK_ADMIN_LISTEN", admin)
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let daemon = Daemon {
            child: Some(child),
            dir: dir.to_path_buf(),
            socket,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        while daemon.try_api("GET", "/v1/health", &Value::Null).is_none() {
            assert!(
                Instant::now() < deadline,
                "kronik serve did not start:\n{}",
                daemon.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        daemon
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    fn try_api(&self, method: &str, path: &str, body: &Value) -> Option<(u16, Value)> {
        let mut stream = UnixStream::connect(&self.socket).ok()?;
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
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .ok()?;
        let answer = read_answer(stream);
        Some((answer.status, serde_json::from_slice(&answer.body).ok()?))
    }

    fn api(&self, method: &str, path: &str, body: &Value) -> Value {
        let (status, value) = self
            .try_api(method, path, body)
            .unwrap_or_else(|| panic!("{method} {path} failed:\n{}", self.log()));
        assert_eq!(status, 200, "{method} {path}: {value}\n{}", self.log());
        value
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

fn json_body(response: &Value) -> Value {
    serde_json::from_str(response["body"].as_str().unwrap_or(""))
        .unwrap_or_else(|error| panic!("{error}: {response}"))
}

fn minted_session(response: &Value) -> bool {
    response["headers"].as_array().unwrap().iter().any(|row| {
        row[0].as_str().unwrap().eq_ignore_ascii_case("set-cookie")
            && row[1]
                .as_str()
                .unwrap()
                .split(';')
                .next()
                .is_some_and(|cookie| {
                    cookie
                        .strip_prefix("__Host-kronik-session=")
                        .is_some_and(|value| !value.is_empty())
                })
    })
}

fn count(stats: &Value, name: &str) -> u64 {
    stats[name]
        .as_u64()
        .unwrap_or_else(|| panic!("{name} missing from {stats}"))
}

/// A daemon whose admitted OIDC configuration maps the fixture's reviewer.
fn admitted() -> (oidc_provider::OwnedOidc, tempfile::TempDir, Daemon) {
    let port = common::free_port();
    let provider = oidc_provider::OwnedOidc::start(format!("https://localhost:{port}"));
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path(), &provider, &format!("127.0.0.1:{port}"));
    daemon.api(
        "POST",
        "/v1/tokens",
        &json!({"name": "ui-reviewer", "scopes": ["read"], "reason": "map the fixture subject"}),
    );
    let admitted = daemon.api(
        "PUT",
        "/v1/auth/config",
        &json!({
            "config": provider.profile("ui-reviewer"),
            "reason": "admit the fixture issuer",
            "dry_run": false
        }),
    );
    assert_eq!(admitted["active"], true, "{admitted}\n{}", daemon.log());
    assert_eq!(admitted["restart_required"], false, "{admitted}");
    (provider, dir, daemon)
}

#[test]
fn rejected_id_tokens_complete_the_exchange_and_mint_no_session() {
    let (mut provider, _dir, _daemon) = admitted();
    let origin = provider.origin.clone();

    for mode in REJECTED {
        let before = provider.set_mode(mode);
        let callback = provider.exchange();
        assert_eq!(callback["status"], 401, "{mode}: {callback}");
        assert!(
            !minted_session(&callback),
            "{mode} set a session cookie: {callback}"
        );
        assert_eq!(json_body(&callback)["error"]["code"], "UNAUTHENTICATED");
        let after = provider.set_mode(mode);
        assert_eq!(
            count(&after, "authorizations"),
            count(&before, "authorizations") + 1,
            "{mode}"
        );
        assert_eq!(
            count(&after, "exchanges"),
            count(&before, "exchanges") + 1,
            "{mode}"
        );
        assert_eq!(
            count(&after, "pkce_verified"),
            count(&before, "pkce_verified") + 1,
            "{mode} did not complete the code exchange"
        );
        let actors = provider.request("GET", &format!("{origin}/v1/actors"), json!({}), None);
        assert_eq!(actors["status"], 401, "{mode}: {actors}");
        assert_eq!(json_body(&actors)["error"]["code"], "UNAUTHENTICATED");
    }

    provider.set_mode("valid");
    let login = provider.login();
    assert!(login.principal.starts_with("oidc:"), "{}", login.principal);
    let actors = provider.request(
        "GET",
        &format!("{origin}/v1/actors"),
        json!({"Cookie": login.cookie}),
        None,
    );
    assert_eq!(actors["status"], 200, "{actors}");
    assert!(json_body(&actors)["actors"].is_array());
}

#[test]
fn browser_session_ends_at_the_id_token_expiry_and_within_an_hour() {
    let (mut provider, _dir, _daemon) = admitted();
    let origin = provider.origin.clone();
    let wall_ms = || {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    };

    provider.set_mode("long");
    let login = provider.login();
    let info = provider.request(
        "GET",
        &format!("{origin}/v1/auth/session"),
        json!({"Cookie": login.cookie}),
        None,
    );
    let expires = json_body(&info)["expires_at_ms"].as_u64().unwrap();
    assert!(
        expires <= wall_ms() + 3_600_000,
        "a two-hour ID token outlived the one-hour session cap: {info}"
    );

    // The ID token expires 2 to 3 s after it was minted.
    provider.set_mode("short");
    let login = provider.login();
    let mut actors = || {
        provider.request(
            "GET",
            &format!("{origin}/v1/actors"),
            json!({"Cookie": login.cookie}),
            None,
        )
    };
    let live = actors();
    assert_eq!(live["status"], 200, "{live}");
    std::thread::sleep(Duration::from_secs(3));
    let expired = actors();
    assert_eq!(expired["status"], 401, "{expired}");
    assert_eq!(json_body(&expired)["error"]["code"], "UNAUTHENTICATED");
    assert!(!minted_session(&expired), "re-minted a session: {expired}");
}
