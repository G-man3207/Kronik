//! M24 criterion 3 with a real `kronik serve` (docs/design/m24-connections.md
//! §19): a daemon killed with SIGKILL after a `send-now` frame was written
//! to its WebSocket and before its result was recorded
//! (`--test-hold-after-send-now`). After the restart the re-run does not
//! send the frame again: its effect is `OUTCOME_UNKNOWN` with the frame in
//! its request, a turn that does not handle it is a dead letter with
//! `EFFECT_OUTCOME_UNKNOWN`, one that handles it commits and counts it, the
//! frame reached the client exactly once, and the connection got its
//! restart close.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::{Message, WebSocket};

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

struct Daemon {
    dir: PathBuf,
    child: Option<Child>,
    http: String,
}

impl Daemon {
    fn start(dir: &Path, extra: &[&str]) -> Daemon {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_kronik"))
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .arg("--data-dir")
            .arg(dir.join("data"))
            .args([
                "--http-listen",
                "127.0.0.1:0",
                "--admin-listen",
                "127.0.0.1:0",
                "--api-socket",
            ])
            .arg(dir.join("api.sock"))
            .args(extra)
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

    /// SIGKILL.
    fn kill9(&mut self) {
        if let Some(mut c) = self.child.take() {
            c.kill().unwrap();
            c.wait().unwrap();
        }
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

    /// A message to room/lobby; its reply text.
    fn ask(&self, name: &str) -> String {
        let v = self.api(
            "POST",
            "/v1/actors/room/lobby/messages",
            json!({"name": name, "text": "", "reason": "kill test"}),
        );
        v["reply"]["text"].as_str().unwrap_or_default().to_owned()
    }

    fn connect(&self, path: &str) -> WebSocket<TcpStream> {
        let req = format!("ws://{}{path}", self.http)
            .into_client_request()
            .unwrap();
        let stream = TcpStream::connect(&self.http).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        tokio_tungstenite::tungstenite::client(req, stream)
            .unwrap()
            .0
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill9();
    }
}

fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..800 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

/// Every text the client got until the connection ended.
fn transcript(ws: &mut WebSocket<TcpStream>, until_text: &str) -> Vec<String> {
    let mut got = Vec::new();
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => {
                let t = t.as_str().to_owned();
                let done = t == until_text;
                got.push(t);
                if done {
                    return got;
                }
            }
            Ok(_) => {}
            Err(_) => return got,
        }
    }
}

/// The next text message.
fn first_text(ws: &mut WebSocket<TcpStream>) -> String {
    loop {
        if let Message::Text(t) = ws.read().unwrap() {
            return t.as_str().to_owned();
        }
    }
}

fn run(stream: &str, safe: bool) {
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(dir.path(), &["--test-hold-after-send-now"]);
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(ROOM).unwrap());
    d.api(
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "deploy the room"}),
    );
    d.api(
        "POST",
        "/v1/grants",
        json!({"kind": "room", "capability": "connection:send-now", "reason": "stream tokens"}),
    );
    let mut ws = d.connect("/room/lobby/ws?user=ada");
    ws.send(Message::text(stream)).unwrap();
    // `tok 0` marks the hold point: written, its result not recorded.
    let got = transcript(&mut ws, "tok 0");
    assert_eq!(got.last().map(String::as_str), Some("tok 0"), "{got:?}");
    d.kill9();
    // The old connection's transcript ends there.
    let rest = transcript(&mut ws, "");
    assert!(!rest.iter().any(|t| t.starts_with("tok")), "{rest:?}");
    drop(ws);

    let d = Daemon::start(dir.path(), &[]);
    until("the restart close", || {
        d.ask("closes").contains("host 1012 restart")
    });
    // The re-run's send-now: OUTCOME_UNKNOWN, never sent again.
    let history = d.api("GET", "/v1/actors/room/lobby/history", Value::Null);
    let rerun = history["turns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["effects"][0]["kind"] == "connection.send-now")
        .unwrap_or_else(|| panic!("no send-now turn: {history}"))
        .clone();
    assert_eq!(rerun["effects"][0]["status"], "outcome_unknown", "{rerun}");
    assert_eq!(rerun["effects"][0]["delivery"], "unsafe", "{rerun}");
    assert_eq!(rerun["effects"].as_array().unwrap().len(), 1, "{rerun}");
    let dead = d.api("GET", "/v1/dead-letters", Value::Null);
    let letters = dead["dead_letters"].as_array().cloned().unwrap_or_default();
    if safe {
        assert!(letters.is_empty(), "{dead}");
        assert_eq!(d.ask("unknown"), "1");
    } else {
        assert_eq!(letters.len(), 1, "{dead}");
        assert_eq!(letters[0]["error_code"], "EFFECT_OUTCOME_UNKNOWN", "{dead}");
    }
    // A new connection gets a welcome, never the token.
    let mut again = d.connect("/room/lobby/ws?user=bob");
    let welcome = first_text(&mut again);
    assert!(welcome.contains("\"welcome\""), "{welcome}");
}

#[test]
fn kill9_after_send_now_gives_outcome_unknown_and_a_dead_letter() {
    run("stream 3", false);
}

#[test]
fn kill9_after_send_now_handled_by_the_actor_commits() {
    run("stream-safe 3", true);
}
