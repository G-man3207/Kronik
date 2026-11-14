//! M24 with a real `kronik serve` and a real WebSocket client
//! (docs/design/m24-connections.md §5): `[connections]` from kronik.toml,
//! an accepted connection's 101 with the selected subprotocol, frames as
//! turns of the owner, the per-client cap (503 `CONNECTION_LIMIT`), the
//! actor's and the client's closes, a graceful stop's 1012 `kronik:
//! restart`, and after the restart the host close of every connection the
//! last process held.

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
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message, WebSocket};

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

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
            format!(
                "[server]\ndata_dir = {:?}\n\n[connections]\nmax_per_client = 2\n",
                dir.join("data")
            ),
        )
        .unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_kronik"))
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

    /// A message to room/lobby; its reply text.
    fn ask(&self, name: &str) -> String {
        let v = self.api(
            "POST",
            "/v1/actors/room/lobby/messages",
            json!({"name": name, "text": "", "reason": "connections test"}),
        );
        v["reply"]["text"].as_str().unwrap_or_default().to_owned()
    }

    /// Opens a WebSocket to `path`; the handshake's error when it fails.
    fn connect(
        &self,
        path: &str,
        protocols: Option<&str>,
    ) -> Result<(WebSocket<TcpStream>, Option<String>), WsError> {
        let mut req = format!("ws://{}{path}", self.http)
            .into_client_request()
            .unwrap();
        if let Some(p) = protocols {
            req.headers_mut()
                .insert("sec-websocket-protocol", p.parse().unwrap());
        }
        let stream = TcpStream::connect(&self.http).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        match tokio_tungstenite::tungstenite::client(req, stream) {
            Ok((ws, response)) => {
                let selected = response
                    .headers()
                    .get("sec-websocket-protocol")
                    .map(|v| v.to_str().unwrap().to_owned());
                Ok((ws, selected))
            }
            Err(tokio_tungstenite::tungstenite::HandshakeError::Failure(e)) => Err(e),
            Err(e) => panic!("handshake: {e}"),
        }
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

/// The next text or close message, skipping pings and pongs.
fn next(ws: &mut WebSocket<TcpStream>) -> Message {
    loop {
        match ws.read().unwrap() {
            Message::Ping(_) | Message::Pong(_) => continue,
            m => return m,
        }
    }
}

fn text(ws: &mut WebSocket<TcpStream>) -> String {
    match next(ws) {
        Message::Text(t) => t.as_str().to_owned(),
        other => panic!("expected text, got {other:?}"),
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

#[test]
fn websocket_connections_with_a_real_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(dir.path());
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(ROOM).unwrap());
    d.api(
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "deploy the room"}),
    );

    // Accepted after the open turn: 101 with the selected subprotocol, then
    // the welcome.
    let (mut ada, selected) = d
        .connect("/room/lobby/ws?user=ada", Some("x.v0, room.v1"))
        .unwrap();
    assert_eq!(selected.as_deref(), Some("room.v1"));
    assert!(text(&mut ada).contains("\"welcome\""));
    let (mut bob, _) = d.connect("/room/lobby/ws?user=bob", None).unwrap();
    assert!(text(&mut bob).contains("\"welcome\""));
    assert!(text(&mut ada).contains("\"joined\""));

    // [connections] max_per_client = 2: the third from this address is
    // refused before any turn.
    match d.connect("/room/lobby/ws?user=cid", None) {
        Err(WsError::Http(response)) => {
            assert_eq!(response.status(), 503);
            assert_eq!(response.headers().get("retry-after").unwrap(), "5");
            let body: Value = serde_json::from_slice(response.body().as_deref().unwrap()).unwrap();
            assert_eq!(body["error"]["code"], "CONNECTION_LIMIT");
        }
        other => panic!("expected 503, got {other:?}"),
    }

    // A frame is a turn of the owner; its broadcast reaches both.
    ada.send(Message::text("say hello")).unwrap();
    for ws in [&mut ada, &mut bob] {
        let m = text(ws);
        assert!(m.contains("\"seq\":1") && m.contains("\"hello\""), "{m}");
    }
    assert_eq!(d.ask("seq"), "1");

    // The actor closes bob after a last frame.
    bob.send(Message::text("echo goodbye")).unwrap();
    bob.send(Message::text("bye")).unwrap();
    assert_eq!(text(&mut bob), "goodbye");
    match next(&mut bob) {
        Message::Close(Some(f)) => {
            assert_eq!((u16::from(f.code), f.reason.as_str()), (1000, "bye"))
        }
        other => panic!("expected a close, got {other:?}"),
    }
    let _ = bob.close(None);
    assert!(text(&mut ada).contains("\"left\""));
    until("bob's close", || d.ask("closes").contains("actor 1000 bye"));

    // The client closes a third connection.
    let (mut cid, _) = d.connect("/room/lobby/ws?user=cid", None).unwrap();
    assert!(text(&mut cid).contains("\"welcome\""));
    assert!(text(&mut ada).contains("\"joined\""));
    cid.close(Some(CloseFrame {
        code: CloseCode::Away,
        reason: "tab closed".into(),
    }))
    .unwrap();
    while cid.read().is_ok() {}
    until("cid's close", || {
        d.ask("closes").contains("client 1001 tab closed")
    });
    assert!(text(&mut ada).contains("\"left\""));

    // A graceful stop: 1012 `kronik: restart`.
    d.stop();
    match next(&mut ada) {
        Message::Close(Some(f)) => {
            assert_eq!(u16::from(f.code), 1012);
            assert_eq!(f.reason.as_str(), "kronik: restart");
        }
        other => panic!("expected a close, got {other:?}"),
    }
    drop(ada);

    // After the restart ada's connection gets its host close: `restart`,
    // 1012; the room keeps its messages, and new connections open.
    let d = Daemon::start(dir.path());
    until("the restart close", || {
        d.ask("closes").contains("host 1012 restart")
    });
    assert_eq!(d.ask("members"), "");
    assert_eq!(d.ask("seq"), "1");
    let (mut again, _) = d.connect("/room/lobby/ws?user=ada", None).unwrap();
    let welcome = text(&mut again);
    assert!(welcome.contains("\"last\":1"), "{welcome}");
    let health = d.api("GET", "/v1/health", Value::Null);
    assert!(health.is_object());
}
