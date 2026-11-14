//! Tests for actors. [`TestHost`] runs the project's component in an
//! in-memory Kronik node (`kronik test-host`): the real scheduler, runtime
//! and effect gate, with a clock that moves only when the test advances it
//! and outgoing HTTP answered by [`Stub`]s and recorded.
//!
//! ```no_run
//! use kronik_sdk::testkit::TestHost;
//!
//! let mut host = TestHost::start(env!("CARGO_MANIFEST_DIR")).unwrap();
//! let res = host.http("POST", "/counter/alice/increment", "").unwrap();
//! assert_eq!(res.status, 200);
//! assert_eq!(res.json::<serde_json::Value>().unwrap()["n"], 1);
//! ```
//!
//! [`TestHost::start`] builds the project as `kronik build` does, so tests
//! run the code they see. The `kronik` binary comes from the `KRONIK_BIN`
//! environment variable or `PATH`. Every request waits until what it started
//! has finished (messages delivered, timers that came due fired), so a test
//! can check the outcome right after it. The testkit exists only on the
//! host, not in the Wasm build.
//!
//! A test plays the client of WebSocket and SSE connections too:
//!
//! ```no_run
//! # use kronik_sdk::testkit::TestHost;
//! # let mut host = TestHost::start(env!("CARGO_MANIFEST_DIR")).unwrap();
//! let conn = host.open_connection("/chat/lobby/ws?user=ada").unwrap();
//! host.send_frame(&conn, r#"{"type":"say","text":"hi"}"#).unwrap();
//! let frames = host.frames_sent(&conn, true).unwrap().frames;
//! ```

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// What went wrong in a test host or with a request to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestError(pub String);

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TestError {}

/// The result of a test host call.
pub type Result<T, E = TestError> = std::result::Result<T, E>;

fn fail(what: &str, e: impl std::fmt::Display) -> TestError {
    TestError(format!("{what}: {e}"))
}

/// An in-memory node running the components under test.
pub struct TestHost {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// A response through the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The headers, in order.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
    /// The id of the turn that answered, such as `main:5`.
    pub turn: Option<String>,
}

impl Response {
    /// The first header called `name`, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    /// The body as UTF-8 text.
    pub fn text(&self) -> Result<&str> {
        std::str::from_utf8(&self.body).map_err(|e| fail("the response body", e))
    }

    /// The body parsed as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| fail("the response body", e))
    }
}

/// A WebSocket or SSE connection a test opened with
/// [`TestHost::open_connection`]: the client's side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestConnection {
    /// The connection's id (`c-` and 32 hex digits) when its actor
    /// accepted it.
    pub id: Option<String>,
    /// The handshake's answer: 101 for an accepted WebSocket, 200 for an
    /// accepted event stream, else the refusal or the error.
    pub response: Response,
}

impl TestConnection {
    /// Whether the actor accepted the connection.
    pub fn accepted(&self) -> bool {
        self.id.is_some()
    }

    fn accepted_id(&self) -> Result<&str> {
        self.id.as_deref().ok_or_else(|| {
            TestError(format!(
                "the connection was not accepted: HTTP {} {}",
                self.response.status,
                String::from_utf8_lossy(&self.response.body)
            ))
        })
    }
}

/// A frame an actor sent on a connection, as [`TestHost::frames_sent`]
/// returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentFrame {
    /// Its outgoing seq on the connection, from 0.
    pub seq: u64,
    /// `text`, `binary` or `event`.
    pub kind: String,
    /// The text or binary data, or the event's data.
    pub body: Vec<u8>,
    /// An event's `event` field.
    pub event: Option<String>,
    /// An event's `id` field.
    pub id: Option<String>,
}

impl SentFrame {
    /// The data as UTF-8 text.
    pub fn text(&self) -> Result<&str> {
        std::str::from_utf8(&self.body).map_err(|e| fail("the frame", e))
    }

    /// The data parsed as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| fail("the frame", e))
    }
}

/// What an actor sent on a connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FramesSent {
    /// The frames since the last clear, oldest first.
    pub frames: Vec<SentFrame>,
    /// The close the connection got, from its actor or from the host: its
    /// code and reason.
    pub closed: Option<(u16, String)>,
}

/// A frame from the client: text from a `&str`, binary from bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientFrame<'a> {
    /// A text frame.
    Text(&'a str),
    /// A binary frame.
    Binary(&'a [u8]),
}

impl<'a> From<&'a str> for ClientFrame<'a> {
    fn from(text: &'a str) -> Self {
        ClientFrame::Text(text)
    }
}

impl<'a> From<&'a String> for ClientFrame<'a> {
    fn from(text: &'a String) -> Self {
        ClientFrame::Text(text)
    }
}

impl<'a> From<&'a [u8]> for ClientFrame<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        ClientFrame::Binary(bytes)
    }
}

impl<'a> From<&'a Vec<u8>> for ClientFrame<'a> {
    fn from(bytes: &'a Vec<u8>) -> Self {
        ClientFrame::Binary(bytes)
    }
}

/// How [`TestHost::close_connection`] ends a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Close {
    /// The client's close frame, with its code and reason.
    Client(u16, String),
    /// The client goes away without a close frame: the actor sees 1006.
    Gone,
    /// The host closes it for a cause: `restart`, `ping-timeout`,
    /// `too-large`, `slow-consumer`, `protocol`, `operator` or
    /// `unavailable`.
    Host(String),
}

impl Close {
    /// The client's normal close: 1000 without a reason.
    pub fn normal() -> Close {
        Close::Client(1000, String::new())
    }

    fn request(&self, connection: &str) -> Value {
        match self {
            Close::Client(code, reason) => {
                json!({ "op": "close-connection", "connection": connection, "initiator": "client", "code": code, "reason": reason })
            }
            Close::Gone => {
                json!({ "op": "close-connection", "connection": connection, "initiator": "client", "code": 1006 })
            }
            Close::Host(cause) => {
                json!({ "op": "close-connection", "connection": connection, "initiator": "host", "cause": cause })
            }
        }
    }
}

/// The frames and the close of a `frames-sent` answer.
fn frames_of(answer: &Value) -> Result<FramesSent> {
    let none = Vec::new();
    let frames = answer["frames"]
        .as_array()
        .unwrap_or(&none)
        .iter()
        .map(|f| {
            Ok(SentFrame {
                seq: f["seq"].as_u64().unwrap_or(0),
                kind: f["kind"].as_str().unwrap_or("").to_string(),
                body: get_body(f)?,
                event: f["event"].as_str().map(str::to_string),
                id: f["id"].as_str().map(str::to_string),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let closed = answer["closed"].as_object().map(|c| {
        (
            c.get("code").and_then(Value::as_u64).unwrap_or(0) as u16,
            c.get("reason")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        )
    });
    Ok(FramesSent { frames, closed })
}

/// An outgoing request an actor made, as the target would have received it
/// (with the secrets the host inserted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// The method.
    pub method: String,
    /// The URL.
    pub url: String,
    /// The headers, in order.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Recorded {
    /// The first header called `name`, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    /// The body parsed as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| fail("the request body", e))
    }
}

/// An answer for the outgoing requests whose URL starts with a prefix. The
/// newest stub that matches answers; a request no stub matches fails as if
/// the connection were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stub {
    url: String,
    method: Option<String>,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    error: Option<&'static str>,
    times: Option<u32>,
}

impl Stub {
    /// Answers `200` with an empty body to requests whose URL starts with
    /// `prefix`.
    pub fn url(prefix: impl Into<String>) -> Stub {
        Stub {
            url: prefix.into(),
            method: None,
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            error: None,
            times: None,
        }
    }

    /// Only for requests with this method.
    pub fn method(mut self, method: &str) -> Stub {
        self.method = Some(method.to_string());
        self
    }

    /// The status to answer with.
    pub fn status(mut self, status: u16) -> Stub {
        self.status = status;
        self
    }

    /// Adds a response header.
    pub fn header(mut self, name: &str, value: &str) -> Stub {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// The response body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Stub {
        self.body = body.into();
        self
    }

    /// A JSON response body, with its content type.
    pub fn json(self, value: &impl Serialize) -> Stub {
        let body = serde_json::to_vec(value).unwrap_or_default();
        self.header("content-type", "application/json").body(body)
    }

    /// Refuses the connection instead: the request was not sent.
    pub fn refuse(mut self) -> Stub {
        self.error = Some("connect");
        self
    }

    /// Breaks the connection off instead: the request may have reached the
    /// target, and the outcome is unknown.
    pub fn break_off(mut self) -> Stub {
        self.error = Some("io");
        self
    }

    /// Answers only this many requests.
    pub fn times(mut self, n: u32) -> Stub {
        self.times = Some(n);
        self
    }
}

impl TestHost {
    /// Builds the project in `dir` (as `kronik build` does) and starts a
    /// test host with its component deployed.
    pub fn start(dir: impl AsRef<Path>) -> Result<TestHost> {
        let mut args = vec!["--dir".into(), dir.as_ref().as_os_str().to_owned()];
        args.extend(seed_args());
        TestHost::spawn(args)
    }

    /// Starts a test host with components that are already built.
    pub fn with_components(paths: &[impl AsRef<Path>]) -> Result<TestHost> {
        let mut args = Vec::new();
        for path in paths {
            args.push("--wasm".into());
            args.push(path.as_ref().as_os_str().to_owned());
        }
        args.extend(seed_args());
        TestHost::spawn(args)
    }

    fn spawn(args: Vec<std::ffi::OsString>) -> Result<TestHost> {
        let bin = std::env::var_os("KRONIK_BIN").unwrap_or_else(|| "kronik".into());
        let mut child = Command::new(&bin)
            .arg("test-host")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                fail(
                    &format!(
                        "starting {} test-host (install kronik or set KRONIK_BIN)",
                        bin.to_string_lossy()
                    ),
                    e,
                )
            })?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return Err(TestError("the test host has no pipes".into()));
        };
        let mut host = TestHost {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        };
        host.answer()?;
        Ok(host)
    }

    fn answer(&mut self) -> Result<Value> {
        let mut line = String::new();
        let n = self
            .stdout
            .read_line(&mut line)
            .map_err(|e| fail("reading from the test host", e))?;
        if n == 0 {
            return Err(TestError(
                "the test host exited (its errors are above, on stderr)".into(),
            ));
        }
        let answer: Value =
            serde_json::from_str(&line).map_err(|e| fail("the test host's answer", e))?;
        if answer["ok"] == true {
            Ok(answer)
        } else {
            Err(TestError(
                answer["error"]
                    .as_str()
                    .unwrap_or("the test host failed")
                    .to_string(),
            ))
        }
    }

    fn call(&mut self, request: Value) -> Result<Value> {
        writeln!(self.stdin, "{request}")
            .and_then(|()| self.stdin.flush())
            .map_err(|e| fail("writing to the test host", e))?;
        self.answer()
    }

    /// Sends an HTTP request through the gateway, as a client would.
    pub fn http(&mut self, method: &str, path: &str, body: impl AsRef<[u8]>) -> Result<Response> {
        self.http_with_headers(method, path, &[], body)
    }

    /// Sends an HTTP request with headers through the gateway.
    pub fn http_with_headers(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: impl AsRef<[u8]>,
    ) -> Result<Response> {
        let mut request =
            json!({ "op": "http", "method": method, "path": path, "headers": headers });
        put_body(&mut request, body.as_ref());
        let answer = self.call(request)?;
        Ok(Response {
            status: answer["status"].as_u64().unwrap_or(0) as u16,
            headers: pairs(&answer["headers"]),
            body: get_body(&answer)?,
            turn: answer["turn"].as_str().map(str::to_string),
        })
    }

    /// Opens a WebSocket at `path` through the gateway, as a client would.
    /// The open turn has run when it returns: [`TestConnection::accepted`]
    /// tells whether the actor accepted, and [`TestHost::frames_sent`] has
    /// what its open turn sent.
    pub fn open_connection(&mut self, path: &str) -> Result<TestConnection> {
        self.open_connection_with(path, "websocket", &[])
    }

    /// Opens a connection with a protocol (`websocket` or `sse`) and
    /// headers.
    pub fn open_connection_with(
        &mut self,
        path: &str,
        protocol: &str,
        headers: &[(&str, &str)],
    ) -> Result<TestConnection> {
        let answer = self.call(json!({ "op": "open-connection", "path": path, "protocol": protocol, "headers": headers }))?;
        Ok(TestConnection {
            id: answer["connection"].as_str().map(str::to_string),
            response: Response {
                status: answer["status"].as_u64().unwrap_or(0) as u16,
                headers: pairs(&answer["headers"]),
                body: get_body(&answer)?,
                turn: answer["turn"].as_str().map(str::to_string),
            },
        })
    }

    /// A frame from the client: a text frame from a `&str`, a binary frame
    /// from bytes. Returns once its turn, and what that started, have
    /// finished.
    pub fn send_frame<'a>(
        &mut self,
        conn: &TestConnection,
        frame: impl Into<ClientFrame<'a>>,
    ) -> Result<()> {
        let mut request = json!({ "op": "send-frame", "connection": conn.accepted_id()? });
        match frame.into() {
            ClientFrame::Text(text) => request["body"] = json!(text),
            ClientFrame::Binary(bytes) => request["body_base64"] = json!(base64_encode(bytes)),
        }
        self.call(request).map(drop)
    }

    /// Ends a connection as `close` says. Returns once the close turn, and
    /// what that started, have finished.
    pub fn close_connection(&mut self, conn: &TestConnection, close: Close) -> Result<()> {
        self.call(close.request(conn.accepted_id()?)).map(drop)
    }

    /// What the actor sent on a connection since the last `clear`, and the
    /// close it got; `clear` forgets the frames returned.
    pub fn frames_sent(&mut self, conn: &TestConnection, clear: bool) -> Result<FramesSent> {
        let answer = self.call(
            json!({ "op": "frames-sent", "connection": conn.accepted_id()?, "clear": clear }),
        )?;
        frames_of(&answer)
    }

    /// Sends the message `name` to `actor` (`"kind/key"`) as the operator
    /// and returns the API's answer: `outcome`, `reply` and `turn_id`.
    pub fn send(&mut self, actor: &str, name: &str, body: &str) -> Result<Value> {
        let path = format!("/v1/actors/{actor}/messages");
        let (status, answer) = self.api(
            "POST",
            &path,
            Some(json!({ "name": name, "text": body, "reason": "test" })),
        )?;
        api_ok(status, answer)
    }

    /// Moves the clock forward and runs the timers that came due; returns
    /// the new time in ms since the Unix epoch.
    pub fn advance(&mut self, by: Duration) -> Result<u64> {
        let answer = self.call(json!({ "op": "advance", "ms": by.as_millis() as u64 }))?;
        Ok(answer["now_ms"].as_u64().unwrap_or(0))
    }

    /// Adds a stub for outgoing HTTP.
    pub fn stub(&mut self, stub: Stub) -> Result<()> {
        let mut request = json!({
            "op": "stub",
            "url": stub.url,
            "method": stub.method,
            "status": stub.status,
            "headers": stub.headers,
            "error": stub.error,
            "times": stub.times,
        });
        put_body(&mut request, &stub.body);
        self.call(request).map(drop)
    }

    /// The outgoing requests the actors made so far, oldest first.
    pub fn requests(&mut self) -> Result<Vec<Recorded>> {
        self.recorded(false)
    }

    /// The outgoing requests so far, which are then forgotten.
    pub fn take_requests(&mut self) -> Result<Vec<Recorded>> {
        self.recorded(true)
    }

    fn recorded(&mut self, clear: bool) -> Result<Vec<Recorded>> {
        let answer = self.call(json!({ "op": "requests", "clear": clear }))?;
        let empty = Vec::new();
        answer["requests"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|r| {
                Ok(Recorded {
                    method: r["method"].as_str().unwrap_or_default().to_string(),
                    url: r["url"].as_str().unwrap_or_default().to_string(),
                    headers: pairs(&r["headers"]),
                    body: get_body(r)?,
                })
            })
            .collect()
    }

    /// Grants the actor type `kind` a capability, such as
    /// `http:api.example.com` or `secret:stripe`. `delivery` is required for
    /// `http:` grants: `idempotency-keyed`, `at-most-once` or `unsafe`.
    pub fn grant(&mut self, kind: &str, capability: &str, delivery: Option<&str>) -> Result<()> {
        let body = json!({ "kind": kind, "capability": capability, "delivery": delivery, "reason": "test" });
        let (status, answer) = self.api("POST", "/v1/grants", Some(body))?;
        api_ok(status, answer).map(drop)
    }

    /// Sets the secret `name`.
    pub fn secret(&mut self, name: &str, value: &str) -> Result<()> {
        let path = format!("/v1/secrets/{name}");
        let (status, answer) = self.api(
            "PUT",
            &path,
            Some(json!({ "text": value, "reason": "test" })),
        )?;
        api_ok(status, answer).map(drop)
    }

    /// The key-value state of `actor` (`"kind/key"`), sorted by key.
    pub fn state(&mut self, actor: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let (status, answer) = self.api("GET", &format!("/v1/actors/{actor}"), None)?;
        let answer = api_ok(status, answer)?;
        let empty = Vec::new();
        answer["state"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|e| {
                let value = match e["base64"].as_str() {
                    Some(b) => base64_decode(b)?,
                    None => e["text"].as_str().unwrap_or_default().as_bytes().to_vec(),
                };
                Ok((e["key"].as_str().unwrap_or_default().to_string(), value))
            })
            .collect()
    }

    /// The state value `key` of `actor` parsed as JSON, if there is one.
    pub fn state_json<T: DeserializeOwned>(&mut self, actor: &str, key: &str) -> Result<Option<T>> {
        let state = self.state(actor)?;
        match state.into_iter().find(|(k, _)| k == key) {
            Some((_, value)) => serde_json::from_slice(&value)
                .map(Some)
                .map_err(|e| fail(key, e)),
            None => Ok(None),
        }
    }

    /// Any request to the daemon's API, as `kronik` sends it over its socket
    /// (`/v1/...`); returns the status and the JSON body.
    pub fn api(&mut self, method: &str, path: &str, body: Option<Value>) -> Result<(u16, Value)> {
        let answer =
            self.call(json!({ "op": "api", "method": method, "path": path, "body": body }))?;
        Ok((
            answer["status"].as_u64().unwrap_or(0) as u16,
            answer["body"].clone(),
        ))
    }
}

impl Drop for TestHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `KRONIK_TEST_SEED`, if set, seeds the host's ids and guest randomness.
fn seed_args() -> Vec<std::ffi::OsString> {
    match std::env::var_os("KRONIK_TEST_SEED") {
        Some(seed) => vec!["--seed".into(), seed],
        None => Vec::new(),
    }
}

fn api_ok(status: u16, answer: Value) -> Result<Value> {
    if status == 200 {
        return Ok(answer);
    }
    Err(TestError(format!(
        "{}: {}",
        answer["error"]["code"].as_str().unwrap_or("ERROR"),
        answer["error"]["message"]
            .as_str()
            .unwrap_or("the request failed")
    )))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn pairs(value: &Value) -> Vec<(String, String)> {
    serde_json::from_value(value.clone()).unwrap_or_default()
}

fn put_body(request: &mut Value, body: &[u8]) {
    match std::str::from_utf8(body) {
        Ok(text) => request["body"] = json!(text),
        Err(_) => request["body_base64"] = json!(base64_encode(body)),
    }
}

fn get_body(answer: &Value) -> Result<Vec<u8>> {
    match (answer["body_base64"].as_str(), answer["body"].as_str()) {
        (Some(b), _) => base64_decode(b),
        (None, Some(text)) => Ok(text.as_bytes().to_vec()),
        (None, None) => Ok(Vec::new()),
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(BASE64[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut n, mut bits) = (0u32, 0);
    for c in text.bytes().filter(|&c| c != b'=') {
        let v = BASE64
            .iter()
            .position(|&b| b == c)
            .ok_or_else(|| TestError(format!("invalid base64 character {:?}", char::from(c))))?;
        n = n << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((n >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod connection_tests {
    use super::*;

    #[test]
    fn frames_sent_answers_parse() {
        let answer = json!({
            "ok": true,
            "frames": [
                { "seq": 0, "kind": "text", "body": "{\"type\":\"welcome\"}" },
                { "seq": 1, "kind": "binary", "body_base64": "/wA=" },
                { "seq": 2, "kind": "event", "body": "x", "event": "message", "id": "7" }
            ],
            "closed": { "code": 1000, "reason": "bye" }
        });
        let sent = frames_of(&answer).unwrap();
        assert_eq!(sent.frames.len(), 3);
        assert_eq!(sent.frames[0].json::<Value>().unwrap()["type"], "welcome");
        assert_eq!(sent.frames[1].body, [0xff, 0]);
        assert_eq!(sent.frames[2].event.as_deref(), Some("message"));
        assert_eq!(sent.frames[2].id.as_deref(), Some("7"));
        assert_eq!(sent.closed, Some((1000, "bye".to_string())));
        let empty = frames_of(&json!({ "ok": true, "frames": [], "closed": null })).unwrap();
        assert_eq!(empty, FramesSent::default());
    }

    #[test]
    fn closes_become_requests() {
        let c = "c-0123456789abcdef0123456789abcdef";
        assert_eq!(Close::normal().request(c)["code"], 1000);
        assert_eq!(Close::Gone.request(c)["code"], 1006);
        let host = Close::Host("restart".into()).request(c);
        assert_eq!(host["initiator"], "host");
        assert_eq!(host["cause"], "restart");
        assert!(host.get("code").is_none());
        let refused = TestConnection {
            id: None,
            response: Response {
                status: 403,
                headers: Vec::new(),
                body: b"no".to_vec(),
                turn: None,
            },
        };
        assert!(!refused.accepted());
        assert!(refused.accepted_id().unwrap_err().0.contains("HTTP 403 no"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for input in [&b""[..], b"f", b"fo", b"foo", b"foob", &[0xff, 0, 0x80]] {
            let encoded = base64_encode(input);
            assert_eq!(base64_decode(&encoded).unwrap(), input, "{encoded}");
        }
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert!(base64_decode("@@").is_err());
    }
}
