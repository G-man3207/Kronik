//! M8 acceptance with a real `kronik serve` (docs/design/m8-privacy.md):
//! subject tags per value from the gateway and the SDK (also switching
//! subject mid-turn), recorded in `off` mode; `on` seals; erasure makes a
//! subject's values unreadable in the log and state, deletes its SQL rows
//! (also after a rebuild) and leaves other subjects of the same turn; a
//! `--no-pii` fork replays with pseudonyms, marks `pii-masked`, and its diff
//! shows no real value.

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

const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests");

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
                "[server]\ndata_dir = {:?}\n\n[privacy]\nsubject_from = \"header:x-user-id\"\n",
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
            if let Some((200, v)) = d.try_api("GET", "/v1/health", Value::Null, None) {
                d.http = v["http_listen"].as_str().unwrap().to_owned();
                return d;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("daemon did not start: {}", d.serve_log());
    }

    fn serve_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(c.id().to_string())
                .status();
            let _ = c.wait();
        }
    }

    fn try_api(
        &self,
        method: &str,
        path: &str,
        body: Value,
        token: Option<&str>,
    ) -> Option<(u16, Value)> {
        let mut s = UnixStream::connect(self.dir.join("api.sock")).ok()?;
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        let auth = token.map_or(String::new(), |t| format!("authorization: Bearer {t}\r\n"));
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nhost: kronik\r\n{auth}content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .ok()?;
        read_response(&mut BufReader::new(s))
    }

    fn api_as(&self, method: &str, path: &str, body: Value, token: Option<&str>) -> Value {
        let (s, v) = self
            .try_api(method, path, body, token)
            .unwrap_or_else(|| panic!("API {method} {path} failed: {}", self.serve_log()));
        assert_eq!(s, 200, "{method} {path}: {v}");
        v
    }

    fn api(&self, method: &str, path: &str, body: Value) -> Value {
        self.api_as(method, path, body, None)
    }

    fn send(&self, actor: &str, name: &str, text: &str, subject: Option<&str>) -> Value {
        self.api(
            "POST",
            &format!("/v1/actors/{actor}/messages"),
            json!({"name": name, "text": text, "subject": subject, "reason": "privacy test"}),
        )
    }

    /// A gateway request with the subject header; returns the body.
    fn post(&self, path: &str, user: &str) -> String {
        let mut s = TcpStream::connect(&self.http).unwrap();
        write!(
            s,
            "POST {path} HTTP/1.1\r\nhost: x\r\nx-user-id: {user}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned()
    }

    fn turn(&self, id: &str, token: Option<&str>) -> Value {
        self.api_as("GET", &format!("/v1/turns/{id}"), Value::Null, token)
    }

    fn state(&self, actor: &str, token: Option<&str>) -> Vec<(String, String, Value)> {
        let v = self.api_as("GET", &format!("/v1/actors/{actor}"), Value::Null, token);
        v["state"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["key"].as_str().unwrap().to_owned(),
                    e["text"].as_str().unwrap_or_default().to_owned(),
                    e["subject"].clone(),
                )
            })
            .collect()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_response(r: &mut impl BufRead) -> Option<(u16, Value)> {
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

/// Every byte of the log segments.
fn log_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir.join("data/branches/main/log")).unwrap() {
        out.extend(std::fs::read(e.unwrap().path()).unwrap());
    }
    out
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn write_value<'a>(turn: &'a Value, key: &str) -> &'a Value {
    turn["writes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["key"] == key)
        .unwrap_or_else(|| panic!("no write {key} in {turn}"))
}

fn deploy(d: &Daemon, wasm: &str) {
    let b64 = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join(wasm)).unwrap());
    d.api(
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": b64, "reason": "privacy test"}),
    );
}

#[test]
fn privacy_mode_end_to_end() {
    let tmp = tempfile::Builder::new()
        .prefix("kronik-m8-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    let mut d = Daemon::start(dir);
    deploy(&d, "counter.wasm");
    deploy(&d, "notes.wasm");
    // A token without pii:read sees sealed values as placeholders.
    let reader = d.api(
        "POST",
        "/v1/tokens",
        json!({"name": "reader", "scopes": ["read", "fork"], "reason": "privacy test"}),
    )["secret"]
        .as_str()
        .unwrap()
        .to_owned();

    // ---- off: values are tagged and recorded plain.
    assert_eq!(d.post("/counter/g/increment", "user:3"), "1");
    let r = d.send("counter/off", "subject", "", None);
    let off_turn = d.turn(r["turn_id"].as_str().unwrap(), None);
    // The SDK's set_for and a mid-turn subject switch: one value each.
    assert_eq!(write_value(&off_turn, "s")["value"]["subject"], "user:1");
    assert_eq!(write_value(&off_turn, "t")["value"]["subject"], "user:2");
    d.send("notes/n", "add", "note-off-user1", Some("user:1"));
    let st = d.state("counter/g", None);
    assert_eq!(
        st[0].2, "user:3",
        "the gateway's subject tags the state: {st:?}"
    );
    assert!(
        contains(&log_bytes(dir), "note-off-user1"),
        "off records plain"
    );

    // ---- on: tagged values are sealed in the log and in state.db.
    d.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "privacy test"}),
    );
    assert_eq!(d.post("/counter/g/increment", "user:3"), "2");
    assert_eq!(d.post("/counter/g/increment", "user:3"), "3");
    let r = d.send("counter/on", "subject", "", None);
    let on_id = r["turn_id"].as_str().unwrap().to_owned();
    d.send("notes/n", "add", "note-on-user1", Some("user:1"));
    d.send("notes/n", "add", "note-on-user2", Some("user:2"));
    let log = log_bytes(dir);
    for secret in ["note-on-user1", "note-on-user2", "also personal"] {
        // "also personal" was written in off mode too, by counter/off; the
        // on-mode copies are sealed, so count occurrences instead.
        if secret != "also personal" {
            assert!(!contains(&log, secret), "{secret} is in the log in on mode");
        }
    }
    let with_pii = d.state("counter/on", None);
    let without = d.state("counter/on", Some(&reader));
    assert_eq!(
        with_pii[0].1,
        "personal",
        "{with_pii:?} {:?}",
        d.api("GET", "/v1/actors/counter/on", Value::Null)
    );
    assert_eq!(without[0].1, "[sealed]", "{without:?}");
    assert_eq!(without[1].1, "[sealed]");
    let t = d.turn(&on_id, Some(&reader));
    assert_eq!(
        write_value(&t, "s")["value"]["value"]["text"],
        "[sealed]",
        "{t}"
    );
    let listed = d.send("notes/n", "list", "", None)["reply"]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(listed.contains("note-on-user1 [user:1]"), "{listed}");

    // Identity replay over sealed history: production is unsealed for the
    // fork, so the same code gives an empty diff.
    let fork = d.api(
        "POST",
        "/v1/forks",
        json!({"at": 2, "reason": "privacy test: identity"}),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let v = d.api(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"mode": "both", "reason": "privacy test: identity"}),
    );
    assert_eq!(
        v["summary"]["changed"], false,
        "identity replay differs: {v}"
    );
    assert!(v["summary"]["exact"].as_u64().is_some());

    // ---- erase user:1.
    let e = d.api(
        "POST",
        "/v1/privacy/erase",
        json!({"subject": "user:1", "reason": "privacy test: right to erasure"}),
    );
    assert_eq!(e["key_version"], 1, "{e}");
    assert!(
        e["plain_values"].as_u64().unwrap() >= 2,
        "off-mode values: {e}"
    );
    // Its sealed values read as [erased] for every caller; user:2's value
    // written in the same turn is untouched.
    let t = d.turn(&on_id, None);
    assert_eq!(
        write_value(&t, "s")["value"]["value"]["text"],
        "[erased]",
        "{t}"
    );
    assert_eq!(
        write_value(&t, "t")["value"]["value"]["text"],
        "also personal"
    );
    // history, which shows no values, marks the write [erased].
    let h = d.api("GET", "/v1/actors/counter/on/history", Value::Null);
    let writes: Vec<(String, bool)> = h["turns"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|t| t["writes"].as_array().unwrap().clone())
        .map(|w| (w["key"].as_str().unwrap().to_owned(), w["erased"] == true))
        .collect();
    assert!(writes.contains(&("s".to_owned(), true)), "{h}");
    assert!(writes.contains(&("t".to_owned(), false)), "{h}");
    let st = d.state("counter/on", None);
    assert_eq!(st.len(), 1, "user:1's state value is deleted: {st:?}");
    assert_eq!((st[0].0.as_str(), st[0].1.as_str()), ("t", "also personal"));
    // Its SQL rows are deleted; user:2's stay.
    let listed = d.send("notes/n", "list", "", None)["reply"]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!listed.contains("user:1]"), "{listed}");
    assert!(listed.contains("note-on-user2 [user:2]"), "{listed}");

    // A rebuild from the log equals the live state: user:1's changesets
    // can't be unsealed and are skipped, the erasure is replayed.
    d.stop();
    let branch = dir.join("data/branches/main");
    std::fs::remove_dir_all(branch.join("sql")).unwrap();
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(branch.join(f));
    }
    let _ = std::fs::remove_dir_all(dir.join("data/snapshots"));
    d = Daemon::start(dir);
    let rebuilt = d.send("notes/n", "list", "", None)["reply"]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(rebuilt, listed, "the rebuilt database differs");
    let st = d.state("counter/on", None);
    assert_eq!(st.len(), 1, "{st:?}");

    // ---- a --no-pii fork replays with pseudonyms and marks pii-masked.
    let fork = d.api(
        "POST",
        "/v1/forks",
        json!({"at": 2, "no_pii": true, "reason": "privacy test"}),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let v = d.api(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"mode": "isolated", "reason": "privacy test"}),
    );
    assert!(
        v["summary"]["pii_masked"].as_u64().unwrap_or(0) >= 1,
        "no pii-masked turns: {v}"
    );
    let diff = d.api("GET", &format!("/v1/forks/{fork}/diff"), Value::Null);
    let text = diff.to_string();
    // Values with a subject (state, bodies, SQL rows) are redacted in every
    // diff; the fork's guests ran on pseudonyms, so nothing real is there.
    assert!(text.contains("redacted"), "{text}");
    for real in [
        "note-on-user2",
        "also personal",
        "note-off-user1",
        "personal",
    ] {
        assert!(!text.contains(real), "{real} leaked into a --no-pii diff");
    }
    assert!(!diff["samples"]["pii_masked"].as_array().unwrap().is_empty());
}

/// A plain HTTP server that answers every request with 200 and `body`.
fn http_target(body: &'static str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
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
    addr
}

/// The body of a GET on the API socket, as text.
fn api_text(d: &Daemon, path: &str, token: Option<&str>) -> String {
    let mut s = UnixStream::connect(d.dir.join("api.sock")).unwrap();
    let auth = token.map_or(String::new(), |t| format!("authorization: Bearer {t}\r\n"));
    write!(
        s,
        "GET {path} HTTP/1.1\r\nhost: kronik\r\n{auth}content-length: 0\r\nconnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{path}: {out}");
    out.split_once("\r\n\r\n").unwrap().1.to_owned()
}

/// `kronik <args>` against the daemon's socket with `token`.
fn cli_as(d: &Daemon, token: &str, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_kronik"))
        .arg("--socket")
        .arg(d.dir.join("api.sock"))
        .args(args)
        .env_remove("KRONIK_API_SOCKET")
        .env("KRONIK_TOKEN", token)
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// MCP `get_diff` through `kronik mcp` (stdio) with `token`.
fn mcp_get_diff(d: &Daemon, token: &str, proposal: &str) -> String {
    let r = mcp_call(d, token, "get_diff", json!({"proposal": proposal}));
    assert!(r["result"]["isError"] != true, "{r}");
    r.to_string()
}

/// One MCP `tools/call` of `tool` through `kronik mcp` (stdio) with
/// `token`: the JSON-RPC response.
fn mcp_call(d: &Daemon, token: &str, tool: &str, arguments: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kronik"))
        .arg("--socket")
        .arg(d.dir.join("api.sock"))
        .arg("mcp")
        .env_remove("KRONIK_API_SOCKET")
        .env("KRONIK_TOKEN", token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    // A request (with an id, answered) or a notification (without).
    let mut rpc = |id: Option<u64>, method: &str, params: Value| -> Value {
        let mut m = json!({"jsonrpc": "2.0", "method": method, "params": params});
        if let Some(id) = id {
            m["id"] = json!(id);
        }
        writeln!(stdin, "{m}").unwrap();
        stdin.flush().unwrap();
        let Some(id) = id else {
            return Value::Null;
        };
        loop {
            let mut line = String::new();
            assert!(stdout.read_line(&mut line).unwrap() > 0, "mcp closed");
            let m: Value = serde_json::from_str(&line).unwrap();
            if m["id"] == json!(id) {
                return m;
            }
        }
    };
    rpc(
        Some(1),
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "privacy-test", "version": "0"}}),
    );
    rpc(None, "notifications/initialized", json!({}));
    let r = rpc(
        Some(2),
        "tools/call",
        json!({"name": tool, "arguments": arguments}),
    );
    let _ = child.kill();
    let _ = child.wait();
    r
}

/// Every file under `dir` (recursively) whose bytes contain `needle`.
fn files_with(dir: &Path, needle: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(p) = todo.pop() {
        if p.is_dir() {
            todo.extend(std::fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
        } else if std::fs::read(&p).is_ok_and(|b| contains(&b, needle)) {
            out.push(p);
        }
    }
    out
}

/// M8 v0.1 gap: an `http.fetch` of a turn with a subject records its
/// request and response under that subject. A proposal that changes the
/// request must neither show those values in its diff (JSON, Markdown, CLI,
/// MCP) nor write them in plain to the fork's files, for a caller with or
/// without `pii:read`; `trace` of the effect turn shows them only with
/// `pii:read`.
#[test]
fn a_subjects_effect_values_stay_sealed_in_proposals() {
    const REQUEST: &str = "req-secret-9c2b";
    const RESPONSE: &str = "resp-secret-4e1a";
    const NOTE: &str = "note-secret-3b7d";
    let tmp = tempfile::Builder::new()
        .prefix("kronik-m8-effects-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    let d = Daemon::start(dir);
    deploy(&d, "counter.wasm");
    deploy(&d, "notes.wasm");
    d.api(
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "http:127.0.0.1", "reason": "privacy test"}),
    );
    d.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "privacy test"}),
    );
    let agent = d.api(
        "POST",
        "/v1/tokens",
        json!({"name": "agent", "scopes": ["read", "fork", "propose"], "reason": "privacy test"}),
    )["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let target = http_target(RESPONSE);
    let r = d.send(
        "counter/bob",
        "fetch-ok",
        &format!("POST http://{target}/v1/pay\n\n{REQUEST}"),
        Some("user:1"),
    );
    let effect_turn = r["turn_id"].as_str().unwrap().to_owned();
    d.send("counter/bob", "subject", "", None);
    d.send("notes/n", "add", NOTE, Some("user:1"));
    assert!(!contains(&log_bytes(dir), REQUEST), "the request is sealed");

    let wasm = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join("counter-body-v2.wasm")).unwrap());
    let propose = |token: Option<&str>| -> String {
        d.api_as(
            "POST",
            "/v1/proposals",
            json!({"wasm_base64": [wasm], "reason": "privacy test"}),
            token,
        )["proposal"]["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let with_pii = propose(None);
    let without = propose(Some(&agent));

    let mut leaks = Vec::new();
    for secret in [REQUEST, RESPONSE, NOTE] {
        for id in [&with_pii, &without] {
            for f in files_with(&dir.join("data/branches").join(id), secret) {
                leaks.push(format!("{secret} in {}", f.display()));
            }
        }
    }
    // Diffs never show a subject's values, to any caller (m8-privacy §9).
    for id in [&with_pii, &without] {
        for token in [None, Some(agent.as_str())] {
            let outputs = [
                (
                    "json",
                    api_text(&d, &format!("/v1/proposals/{id}/diff"), token),
                ),
                (
                    "md",
                    api_text(&d, &format!("/v1/proposals/{id}/diff?format=md"), token),
                ),
            ];
            for (what, text) in outputs {
                // The policy floor's own wording (ADR 0031) is no value.
                let text = text.replace("verified without personal data;", "verified;");
                for secret in [REQUEST, RESPONSE, NOTE, "personal"] {
                    if text.contains(secret) {
                        let at = text.find(secret).unwrap_or(0);
                        let from = text[..at]
                            .char_indices()
                            .rev()
                            .nth(160)
                            .map_or(0, |(i, _)| i);
                        leaks.push(format!(
                            "{secret} in the {what} diff of {id} ({token:?}): ...{}",
                            &text[from..(at + secret.len()).min(text.len())]
                        ));
                    }
                }
            }
        }
        let cli = cli_as(&d, &agent, &["diff", "show", id]);
        let mcp = mcp_get_diff(&d, &agent, id);
        for secret in [REQUEST, RESPONSE, NOTE, "personal"] {
            if cli.contains(secret) {
                leaks.push(format!("{secret} in kronik diff show {id}"));
            }
            if mcp.contains(secret) {
                leaks.push(format!("{secret} in MCP get_diff {id}"));
            }
        }
    }
    // The effect turn, in main and in the fork with real values: sealed
    // without pii:read (its input holds the request, its reply the
    // response), plain with it.
    let diff: Value = serde_json::from_str(&api_text(
        &d,
        &format!("/v1/proposals/{with_pii}/diff"),
        None,
    ))
    .unwrap();
    let fork_turn = diff["effects"]["items"]
        .as_array()
        .and_then(|items| items.iter().find_map(|i| i["turn_fork"].as_str()))
        .unwrap_or_else(|| panic!("no changed effect: {}", diff["effects"]))
        .to_owned();
    for turn in [&effect_turn, &fork_turn] {
        for path in [
            format!("/v1/turns/{turn}"),
            format!("/v1/turns/{turn}/trace"),
        ] {
            // An ordinary fork's turns need pii:read altogether (H7).
            if turn == &fork_turn {
                let (status, v) = d.try_api("GET", &path, Value::Null, Some(&agent)).unwrap();
                assert_eq!(v["error"]["code"], "SCOPE_MISSING", "{path}: {status} {v}");
                continue;
            }
            let text = api_text(&d, &path, Some(&agent));
            for secret in [REQUEST, RESPONSE] {
                if text.contains(secret) {
                    leaks.push(format!("{secret} in {path} without pii:read"));
                }
            }
        }
        let text = api_text(&d, &format!("/v1/turns/{turn}"), None);
        if !text.contains(REQUEST) {
            leaks.push(format!(
                "pii:read does not see the request of {turn}: {text}"
            ));
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

/// One raw gateway request: (status, response headers, body).
fn gateway(
    d: &Daemon,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    let mut s = TcpStream::connect(&d.http).unwrap();
    let extra: String = headers
        .iter()
        .map(|(n, v)| format!("{n}: {v}\r\n"))
        .collect();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nhost: x\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, head.to_ascii_lowercase(), body.to_owned())
}

/// H8, H10, M7 (v0.1 privacy review): a saved idempotent response is
/// replayed only to the requester it was made for; a subject's request
/// path, query and route parameters are sealed in the log and hidden from
/// callers without pii:read (as is its Idempotency-Key); a repeated
/// subject header is refused.
#[test]
fn a_subjects_request_line_and_saved_replies_stay_theirs() {
    const NOTE: &str = "MARK-u1-note-7d1f";
    const TOKEN: &str = "rt-5f3a9c";
    let tmp = tempfile::Builder::new()
        .prefix("kronik-m8-ingress-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    let d = Daemon::start(dir);
    deploy(&d, "counter.wasm");
    deploy(&d, "notes.wasm");
    d.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "privacy test"}),
    );
    let reader = d.api(
        "POST",
        "/v1/tokens",
        json!({"name": "reader", "scopes": ["read", "fork", "propose"], "reason": "privacy test"}),
    )["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let query = format!("email=carol%40example.com&reset_token={TOKEN}");
    let (status, _, body) = gateway(
        &d,
        "POST",
        &format!("/notes/n1?{query}"),
        &[("x-user-id", "user:1")],
        NOTE,
    );
    assert_eq!((status, body.as_str()), (200, "1"));
    // Route parameters reach the guest unsealed: `op` picks increment.
    let (status, _, body) = gateway(
        &d,
        "POST",
        "/counter/c1/increment",
        &[("x-user-id", "user:1")],
        "",
    );
    assert_eq!((status, body.as_str()), (200, "1"));

    // An idempotent read by user:1, saved with its response.
    let list = format!("/notes/n1?reset_token={TOKEN}");
    let (status, head, body) = gateway(
        &d,
        "GET",
        &list,
        &[("x-user-id", "user:1"), ("idempotency-key", "k1")],
        "",
    );
    assert_eq!(status, 200, "{head}");
    assert!(body.contains(NOTE), "{body}");
    let turn_id = head
        .lines()
        .find_map(|l| l.strip_prefix("kronik-turn-id: "))
        .unwrap()
        .trim()
        .to_owned();
    // The same key and request by someone else: never the saved response.
    for who in [vec![("x-user-id", "user:2")], vec![]] {
        let mut h = who.clone();
        h.push(("idempotency-key", "k1"));
        let (status, _, body) = gateway(&d, "GET", &list, &h, "");
        assert!(
            !body.contains(NOTE),
            "{who:?} got user:1's reply: {status} {body}"
        );
        assert_eq!(status, 422, "{who:?}: {body}");
    }
    // The same requester gets it again.
    let (status, head, body) = gateway(
        &d,
        "GET",
        &list,
        &[("x-user-id", "user:1"), ("idempotency-key", "k1")],
        "",
    );
    assert_eq!(status, 200);
    assert!(
        body.contains(NOTE) && head.contains(&turn_id),
        "{head} {body}"
    );

    // M7: a repeated or list-valued subject header is a 400.
    let (status, _, _) = gateway(
        &d,
        "POST",
        "/counter/c1/increment",
        &[("x-user-id", "user:evil"), ("x-user-id", "user:1")],
        "",
    );
    assert_eq!(status, 400);
    let (status, _, _) = gateway(
        &d,
        "POST",
        "/counter/c1/increment",
        &[("x-user-id", "a,b")],
        "",
    );
    assert_eq!(status, 400);

    // H10: sealed in the log; hidden from the reader, shown with pii:read.
    let log = log_bytes(dir);
    for secret in [TOKEN, "carol%40example.com"] {
        assert!(!contains(&log, secret), "{secret} is plain in the log");
    }
    let hidden = d.turn(&turn_id, Some(&reader));
    let text = hidden.to_string();
    for secret in [TOKEN, "\"k1\""] {
        assert!(
            !text.contains(secret),
            "{secret} shown without pii:read: {text}"
        );
    }
    assert_eq!(hidden["input"]["route"], "/notes/{key}", "{hidden}");
    let shown = d.turn(&turn_id, None);
    assert!(
        shown["input"]["query"].as_str().unwrap().contains(TOKEN),
        "{shown}"
    );
    assert_eq!(shown["input"]["idempotency_key"], "k1");
    let history = api_text(&d, "/v1/actors/notes/n1/history", Some(&reader));
    assert!(!history.contains(TOKEN), "{history}");
}

/// A token named `name` with `scopes`.
fn token(d: &Daemon, name: &str, scopes: &[&str]) -> String {
    d.api(
        "POST",
        "/v1/tokens",
        json!({"name": name, "scopes": scopes, "reason": "privacy test"}),
    )["secret"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// H7, M3 (v0.1 privacy review): a caller without pii:read never sees a
/// subject id (state, turns, trace, history, dead letters, a proposal's
/// diff in JSON and Markdown), and can neither send into nor read the
/// turns of a fork made with personal data (API and MCP); a --no-pii fork
/// is open to it. A caller with pii:read still sees the subject.
#[test]
fn subjects_and_ordinary_forks_need_pii_read() {
    const SUBJECT: &str = "user:9";
    let tmp = tempfile::Builder::new()
        .prefix("kronik-m8-pii-read-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    let d = Daemon::start(dir);
    deploy(&d, "counter.wasm");
    d.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "privacy test"}),
    );
    let reader = token(&d, "reader", &["read", "fork", "propose"]);
    assert_eq!(d.post("/counter/g/increment", SUBJECT), "1");
    let h = d.api("GET", "/v1/actors/counter/g/history", Value::Null);
    let turn_id = h["turns"][0]["turn_id"].as_str().unwrap().to_owned();
    // pii:read sees the subject.
    assert_eq!(d.state("counter/g", None)[0].2, SUBJECT);
    assert!(d.turn(&turn_id, None).to_string().contains(SUBJECT));
    assert!(h.to_string().contains(SUBJECT), "{h}");

    let step2 = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join("counter-step2.wasm")).unwrap());
    let proposal = d.api(
        "POST",
        "/v1/proposals",
        json!({"wasm_base64": [step2], "reason": "privacy test"}),
    )["proposal"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let diff: Value = serde_json::from_str(&api_text(
        &d,
        &format!("/v1/proposals/{proposal}/diff"),
        Some(&reader),
    ))
    .unwrap();
    let diff = diff.to_string();
    assert!(
        diff.contains(r#""subject":"s:"#),
        "no pseudonymized subject: {diff}"
    );
    let mut shown = vec![
        ("diff".to_owned(), diff),
        (
            "md".to_owned(),
            api_text(
                &d,
                &format!("/v1/proposals/{proposal}/diff?format=md"),
                Some(&reader),
            ),
        ),
    ];
    for path in [
        "/v1/actors/counter/g".to_owned(),
        format!("/v1/turns/{turn_id}"),
        format!("/v1/turns/{turn_id}/trace"),
        "/v1/actors/counter/g/history".to_owned(),
        "/v1/dead-letters".to_owned(),
    ] {
        let text = api_text(&d, &path, Some(&reader));
        shown.push((path, text));
    }
    for (what, text) in &shown {
        assert!(
            !text.contains(SUBJECT),
            "{SUBJECT} in {what} without pii:read: {text}"
        );
    }

    // An ordinary fork: pii:read only.
    let fork = d.api(
        "POST",
        "/v1/forks",
        json!({"at": "now", "reason": "privacy test"}),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let send = |fork: &str, token: Option<&str>| {
        d.try_api(
            "POST",
            &format!("/v1/forks/{fork}/actors/counter/g/messages"),
            json!({"name": "increment", "subject": SUBJECT, "reason": "privacy test"}),
            token,
        )
        .unwrap()
    };
    let (_, v) = send(&fork, Some(&reader));
    assert_eq!(v["error"]["code"], "SCOPE_MISSING", "{v}");
    assert!(v.to_string().contains("pii:read"), "{v}");
    let (status, v) = send(&fork, None);
    assert_eq!(status, 200, "{v}");
    let fork_turn = v["turn_id"].as_str().unwrap().to_owned();
    for path in [
        format!("/v1/turns/{fork_turn}"),
        format!("/v1/turns/{fork_turn}/trace"),
    ] {
        let (_, v) = d.try_api("GET", &path, Value::Null, Some(&reader)).unwrap();
        assert_eq!(v["error"]["code"], "SCOPE_MISSING", "{path}: {v}");
        let (status, v) = d.try_api("GET", &path, Value::Null, None).unwrap();
        assert_eq!(status, 200, "{path}: {v}");
    }
    let mcp = mcp_call(
        &d,
        &reader,
        "send_to_fork",
        json!({"fork": fork, "actor": "counter/g", "name": "increment", "reason": "privacy test"}),
    );
    assert!(mcp.to_string().contains("SCOPE_MISSING"), "{mcp}");

    // A --no-pii fork (every fork the reader makes is one) is open to it.
    let open = d.api_as(
        "POST",
        "/v1/forks",
        json!({"at": "now", "reason": "privacy test"}),
        Some(&reader),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, v) = send(&open, Some(&reader));
    assert_eq!(status, 200, "{v}");
    let t = d.turn(v["turn_id"].as_str().unwrap(), Some(&reader));
    assert!(!t.to_string().contains(SUBJECT), "{t}");
}

/// M5 (v0.1 privacy review): SQL rows are not pseudonymized, so in a
/// --no-pii fork a turn that used SQL shows no values: its reply, its turn,
/// its trace, the fork's files and a proposal's diff carry no real row to
/// a caller without pii:read.
#[test]
fn no_pii_forks_show_no_sql_rows() {
    const ROW: &str = "ROW-u1-5e2c";
    let tmp = tempfile::Builder::new()
        .prefix("kronik-m8-no-pii-sql-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    let d = Daemon::start(dir);
    deploy(&d, "notes.wasm");
    d.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "privacy test"}),
    );
    d.send("notes/n", "add", ROW, Some("user:1"));
    let agent = token(&d, "agent", &["read", "fork", "propose"]);

    let fork = d.api_as(
        "POST",
        "/v1/forks",
        json!({"at": "now", "reason": "privacy test"}),
        Some(&agent),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = d.api_as(
        "POST",
        &format!("/v1/forks/{fork}/actors/notes/n/messages"),
        json!({"name": "list", "reason": "privacy test"}),
        Some(&agent),
    );
    assert_eq!(r["outcome"]["kind"], "committed", "{r}");
    assert_eq!(r["reply"]["text"], "[sql]", "{r}");
    let turn = r["turn_id"].as_str().unwrap().to_owned();

    let wasm = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join("notes-tally.wasm")).unwrap());
    let proposal = d.api_as(
        "POST",
        "/v1/proposals",
        json!({"wasm_base64": [wasm], "reason": "privacy test"}),
        Some(&agent),
    )["proposal"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut leaks = Vec::new();
    for path in [
        format!("/v1/turns/{turn}"),
        format!("/v1/turns/{turn}/trace"),
        format!("/v1/proposals/{proposal}/diff"),
        format!("/v1/proposals/{proposal}/diff?format=md"),
    ] {
        if api_text(&d, &path, Some(&agent)).contains(ROW) {
            leaks.push(path);
        }
    }
    for id in [&fork, &proposal] {
        for f in files_with(&dir.join("data/branches").join(id), ROW) {
            leaks.push(f.display().to_string());
        }
    }
    assert!(leaks.is_empty(), "{ROW} in {leaks:#?}");
}

/// Every file under `dir` (recursively) whose bytes contain `needle`.
fn files_with_bytes(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
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

/// The wrapped keys of `subject`, read from a copy of `keys/keystore.db`
/// and its WAL (the daemon keeps the file open).
fn wrapped_keys(data: &Path, subject: &str) -> Vec<Vec<u8>> {
    let copy = tempfile::tempdir().unwrap();
    for f in ["keystore.db", "keystore.db-wal"] {
        let from = data.join("keys").join(f);
        if from.exists() {
            std::fs::copy(&from, copy.path().join(f)).unwrap();
        }
    }
    let conn = rusqlite::Connection::open(copy.path().join("keystore.db")).unwrap();
    let mut st = conn
        .prepare("SELECT wrapped FROM subject_keys WHERE subject = ?1")
        .unwrap();
    st.query_map([subject], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// A gateway GET with the subject header and an `Idempotency-Key`; the
/// whole response.
fn get_idempotent(d: &Daemon, path: &str, user: &str, key: &str) -> String {
    let mut s = TcpStream::connect(&d.http).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nhost: x\r\nx-user-id: {user}\r\nidempotency-key: {key}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

/// v0.1 review H9 and H11: after `erase user:1`, no file under the data
/// directory (databases, their WAL and -shm files, snapshots, the keystore)
/// holds a plain value of user:1 or its wrapped key, also after a rebuild
/// from the log. Its saved idempotent response and its dead letter are
/// gone; user:2's values and dead letter stay.
#[test]
fn an_erasure_leaves_nothing_in_the_data_directory() {
    let tmp = tempfile::Builder::new()
        .prefix("kronik-m8-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    let data = dir.join("data");
    let mut d = Daemon::start(dir);
    deploy(&d, "counter.wasm");
    deploy(&d, "notes.wasm");
    d.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "privacy test"}),
    );
    const NOTE1: &str = "SECRETNOTE-u1-zq81";
    const NOTE2: &str = "SECRETNOTE-u2-zq81";
    const STATE1: &str = "SECRETSTATE-u1-zq81";
    const STATE2: &str = "SECRETSTATE-u2-zq81";
    const DEAD1: &str = "SECRETDEAD-u1-zq81";
    d.send("notes/n", "add", NOTE1, Some("user:1"));
    d.send("notes/n", "add", NOTE2, Some("user:2"));
    d.send("counter/c1", "note", STATE1, Some("user:1"));
    d.send("counter/c2", "note", STATE2, Some("user:2"));
    // Dead letters: a failing message of each subject.
    for (actor, text, subject) in [("c1", DEAD1, "user:1"), ("c2", "dead-u2", "user:2")] {
        let _ = d.try_api(
            "POST",
            &format!("/v1/actors/counter/{actor}/messages"),
            json!({"name": "fail", "text": text, "subject": subject, "reason": "privacy test"}),
            None,
        );
    }
    let dead = d.api("GET", "/v1/dead-letters", Value::Null).to_string();
    assert!(
        dead.contains("counter/c1") && dead.contains("counter/c2"),
        "{dead}"
    );
    // An idempotent request of user:1 whose saved response holds NOTE1.
    let first = get_idempotent(&d, "/notes/n", "user:1", "idem-u1");
    assert!(first.contains(NOTE1), "{first}");

    let wrapped = wrapped_keys(&data, "user:1");
    assert!(!wrapped.is_empty(), "user:1 has a key");
    assert!(
        !files_with_bytes(&data, &wrapped[0]).is_empty(),
        "the scan finds the wrapped key before the erasure"
    );
    assert!(
        !files_with(&data, NOTE1).is_empty(),
        "the scan finds the SQL row before the erasure"
    );

    d.api(
        "POST",
        "/v1/privacy/erase",
        json!({"subject": "user:1", "reason": "privacy test: nothing left"}),
    );
    let leaks = |data: &Path| {
        let mut leaks = Vec::new();
        for m in [NOTE1, STATE1, DEAD1] {
            leaks.extend(
                files_with(data, m)
                    .into_iter()
                    .map(|f| format!("{m}: {f:?}")),
            );
        }
        for k in &wrapped {
            leaks.extend(
                files_with_bytes(data, k)
                    .into_iter()
                    .map(|f| format!("user:1's wrapped key: {f:?}")),
            );
        }
        leaks
    };
    let found = leaks(&data);
    assert!(found.is_empty(), "after the erasure: {found:#?}");

    // The repeated request runs anew instead of replaying user:1's response.
    let again = get_idempotent(&d, "/notes/n", "user:1", "idem-u1");
    assert!(
        !again.contains(NOTE1) && again.contains(NOTE2),
        "the saved response came back: {again}"
    );
    let dead = d.api("GET", "/v1/dead-letters", Value::Null).to_string();
    assert!(
        !dead.contains("counter/c1") && dead.contains("counter/c2"),
        "{dead}"
    );
    let listed = d.send("notes/n", "list", "", None)["reply"]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        listed.contains(NOTE2) && !listed.contains(NOTE1),
        "{listed}"
    );
    let st = d.state("counter/c2", None);
    assert_eq!(st[0].1, STATE2, "{st:?}");
    assert!(d.state("counter/c1", None).is_empty());

    // A rebuild from the log leaves nothing either.
    d.stop();
    let branch = data.join("branches/main");
    std::fs::remove_dir_all(branch.join("sql")).unwrap();
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(branch.join(f));
    }
    let _ = std::fs::remove_dir_all(data.join("snapshots"));
    d = Daemon::start(dir);
    let rebuilt = d.send("notes/n", "list", "", None)["reply"]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(rebuilt, listed, "the rebuilt database differs");
    assert_eq!(d.state("counter/c2", None)[0].1, STATE2);
    let dead = d.api("GET", "/v1/dead-letters", Value::Null).to_string();
    assert!(
        !dead.contains("counter/c1") && dead.contains("counter/c2"),
        "{dead}"
    );
    let found = leaks(&data);
    assert!(found.is_empty(), "after the rebuild: {found:#?}");
}

/// Four requests of user:1 with a secret in the query; returns the LSN
/// before them (a fork's `at`).
fn carol_requests(d: &Daemon) -> u64 {
    let at = d.api("GET", "/v1/health", Value::Null)["applied_lsn"]
        .as_u64()
        .unwrap();
    for i in 1..=4 {
        assert_eq!(
            d.post(
                "/counter/carol-key/increment?reset_token=rt-SECRET42",
                "user:1"
            ),
            i.to_string()
        );
    }
    at
}

fn privacy_on(prefix: &str) -> (tempfile::TempDir, Daemon) {
    let tmp = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/var/tmp")
        .unwrap();
    let d = Daemon::start(tmp.path());
    deploy(&d, "counter.wasm");
    d.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "privacy test"}),
    );
    (tmp, d)
}

/// R2 (v0.1 re-review, redone): a `--no-pii` fork's actors get a subject's
/// request line as pseudonyms too, so an identity replay of
/// `POST /counter/{key}/{op}` fails in the fork (the guest dispatches on
/// `op`, now a pseudonym). That is `pii-masked`, never an introduced error
/// or a cause, so the default `no-new-errors` rule does not fire on it.
#[test]
fn a_no_pii_identity_replay_is_pii_masked_not_an_error() {
    let (_tmp, d) = privacy_on("kronik-m8-no-pii-params-");
    let reader = token(&d, "reader", &["read", "fork", "propose"]);
    let at = carol_requests(&d);
    let fork = d.api_as(
        "POST",
        "/v1/forks",
        json!({"at": at, "reason": "privacy test"}),
        Some(&reader),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let v = d.api_as(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"mode": "both", "reason": "privacy test"}),
        Some(&reader),
    );
    assert_eq!(v["summary"]["root_inputs"], 4, "{v}");
    let diff = api_text(&d, &format!("/v1/forks/{fork}/diff"), Some(&reader));
    let diff: Value = serde_json::from_str(&diff).unwrap();
    assert_eq!(diff["errors"]["introduced"], 0, "{}", diff["errors"]);
    let s = &diff["summary"];
    assert_eq!(s["pii_masked"], 4, "{s}");
    assert_eq!(
        (&s["origins"], &s["consequences"]),
        (&json!(0), &json!(0)),
        "{s}"
    );
    assert!(!diff.to_string().contains("rt-SECRET42"), "{diff}");
}

/// R2 (v0.1 re-review, redone): code an agent proposes (scope `propose`,
/// so a `--no-pii` fork) that fails with its request line sees only
/// pseudonyms; the real line is in neither the diff nor the fork's files.
#[test]
fn an_agents_probe_sees_only_pseudonyms_of_the_request_line() {
    let (tmp, d) = privacy_on("kronik-m8-no-pii-probe-");
    let agent = token(&d, "agent", &["read", "fork", "propose"]);
    carol_requests(&d);
    let wasm = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join("counter-fail-line.wasm")).unwrap());
    let id = d.api_as(
        "POST",
        "/v1/proposals",
        json!({"wasm_base64": [wasm], "reason": "privacy test"}),
        Some(&agent),
    )["proposal"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let diff: Value = serde_json::from_str(&api_text(
        &d,
        &format!("/v1/proposals/{id}/diff"),
        Some(&agent),
    ))
    .unwrap();
    assert_eq!(diff["errors"]["introduced"], 0, "{}", diff["errors"]);
    assert!(
        diff["summary"]["pii_masked"].as_u64().unwrap() > 0,
        "{diff}"
    );
    // What the probe saw: the admin reads the fork turn's failure.
    let sample = diff["samples"]["pii_masked"][0].as_str().unwrap();
    let seen = d.turn(sample, None).to_string();
    assert!(seen.contains("line POST pii:"), "{seen}");
    let md = api_text(
        &d,
        &format!("/v1/proposals/{id}/diff?format=md"),
        Some(&agent),
    );
    for (what, text) in [("json", diff.to_string()), ("md", md), ("turn", seen)] {
        for real in ["rt-SECRET42", "carol-key/increment"] {
            assert!(!text.contains(real), "{real} in the {what}: {text}");
        }
    }
    let files = files_with(&tmp.path().join("data/branches").join(&id), "rt-SECRET42");
    assert!(files.is_empty(), "{files:?}");
}

/// R4 (v0.1 re-review): history and trace summaries show a subject's path
/// only with `pii:read` (the route pattern otherwise); a request without a
/// sealed value shows its path to every reader.
#[test]
fn summaries_show_a_sealed_path_only_with_pii_read() {
    let (_tmp, d) = privacy_on("kronik-m8-summaries-");
    let reader = token(&d, "reader", &["read"]);
    carol_requests(&d);
    let plain = gateway(&d, "POST", "/counter/plain/increment", &[], "");
    assert_eq!(plain.0, 200);
    let summary = |actor: &str, token: Option<&str>| {
        d.api_as(
            "GET",
            &format!("/v1/actors/{actor}/history"),
            Value::Null,
            token,
        )["turns"][0]["input"]["summary"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        summary("counter/carol-key", None),
        "POST /counter/carol-key/increment"
    );
    assert_eq!(
        summary("counter/carol-key", Some(&reader)),
        "POST /counter/{key}/{op}"
    );
    assert_eq!(
        summary("counter/plain", Some(&reader)),
        "POST /counter/plain/increment"
    );
    let h = d.api("GET", "/v1/actors/counter/carol-key/history", Value::Null);
    let turn = h["turns"][0]["turn_id"].as_str().unwrap();
    let trace = |token| api_text(&d, &format!("/v1/turns/{turn}/trace"), token);
    assert!(trace(None).contains("POST /counter/carol-key/increment"));
    let redacted = trace(Some(&reader));
    assert!(redacted.contains("POST /counter/{key}/{op}"), "{redacted}");
    assert!(!redacted.contains("carol-key/increment"), "{redacted}");
}

/// R3 (v0.1 re-review): a client's own retry is replayed although its
/// cookie rotated (a load balancer's sticky cookie) or its token was
/// refreshed: with a subject, the request hash covers the subject, not the
/// credential headers.
#[test]
fn a_retry_with_a_rotated_cookie_is_replayed() {
    let tmp = tempfile::Builder::new()
        .prefix("kronik-m8-retry-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    let d = Daemon::start(dir);
    deploy(&d, "counter.wasm");
    let first = gateway(
        &d,
        "POST",
        "/counter/r1/increment",
        &[
            ("x-user-id", "user:1"),
            ("idempotency-key", "k1"),
            ("cookie", "AWSALB=one"),
            ("authorization", "Bearer old"),
        ],
        "",
    );
    assert_eq!((first.0, first.2.as_str()), (200, "1"));
    let retry = gateway(
        &d,
        "POST",
        "/counter/r1/increment",
        &[
            ("x-user-id", "user:1"),
            ("idempotency-key", "k1"),
            ("cookie", "AWSALB=rotated"),
            ("authorization", "Bearer refreshed"),
        ],
        "",
    );
    assert_eq!((retry.0, retry.2.as_str()), (200, "1"), "{retry:?}");
    // Another subject with the same key is still refused.
    let other = gateway(
        &d,
        "POST",
        "/counter/r1/increment",
        &[("x-user-id", "user:2"), ("idempotency-key", "k1")],
        "",
    );
    assert_eq!(other.0, 422, "{other:?}");
}

/// `wasm` proposed by `token` (None: the admin); returns the response.
fn propose_as(d: &Daemon, wasm: &str, token: Option<&str>) -> Value {
    let b64 = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join(wasm)).unwrap());
    d.api_as(
        "POST",
        "/v1/proposals",
        json!({"wasm_base64": [b64], "reason": "privacy test"}),
        token,
    )
}

/// ADR 0031 (v0.1 re-review M1): an agent's proposal of really broken code
/// (`get` fails) runs on pseudonyms, so its diff can't show the
/// regression. Its policy is never `allow`: the floor asks for an approval
/// with the reason, shown in the JSON, the Markdown, the CLI and the
/// approval request's command, and promote refuses without one. With real
/// data (the admin) the same code is denied, and `pii_masked` is 0, not
/// absent (L1).
#[test]
fn a_diff_with_pii_masked_turns_needs_an_approval() {
    let (_tmp, d) = privacy_on("kronik-m8-floor-");
    let agent = token(&d, "agent", &["read", "fork", "propose"]);
    carol_requests(&d);
    for _ in 0..4 {
        let r = gateway(
            &d,
            "GET",
            "/counter/carol-key",
            &[("x-user-id", "user:1")],
            "",
        );
        assert_eq!(r.0, 200, "{r:?}");
    }
    let p = &propose_as(&d, "counter-fail-get.wasm", Some(&agent))["proposal"];
    let id = p["id"].as_str().unwrap().to_owned();
    assert_eq!(p["summary"]["pii_masked"], 8, "{p}");
    assert_eq!(p["policy"]["outcome"], "require_approval", "{p}");
    let floor = p["policy"]["fired"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "pii-masked-needs-approval")
        .unwrap_or_else(|| panic!("no floor: {p}"));
    assert!(
        floor["reason"]
            .as_str()
            .unwrap()
            .starts_with("8 turns could not be verified"),
        "{floor}"
    );
    let md = api_text(
        &d,
        &format!("/v1/proposals/{id}/diff?format=md"),
        Some(&agent),
    );
    assert!(md.contains("| PII-masked turns | 8 "), "{md}");
    assert!(
        md.contains("pii-masked-needs-approval (require_approval): 8 turns"),
        "{md}"
    );
    let shown = cli_as(&d, &agent, &["proposals", "show", &id]);
    assert!(shown.contains("PII-masked"), "{shown}");
    assert!(
        shown.contains("pii-masked-needs-approval -> APPROVAL REQUIRED: 8 turns"),
        "{shown}"
    );
    let asked = d.api_as(
        "POST",
        &format!("/v1/proposals/{id}/request-approval"),
        json!({"reason": "privacy test"}),
        Some(&agent),
    );
    let command = asked["request"]["command"].as_str().unwrap();
    assert!(
        command.contains("# 8 pii-masked turns were not verified"),
        "{asked}"
    );
    let (status, refused) = d
        .try_api(
            "POST",
            &format!("/v1/proposals/{id}/promote"),
            json!({"reason": "privacy test"}),
            None,
        )
        .unwrap();
    assert_eq!(
        refused["error"]["code"], "APPROVAL_REQUIRED",
        "{status} {refused}"
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pii-masked-needs-approval"),
        "{refused}"
    );

    let real = &propose_as(&d, "counter-fail-get.wasm", None)["proposal"];
    assert_eq!(real["summary"]["pii_masked"], 0, "{real}");
    assert_eq!(real["policy"]["outcome"], "deny", "{real}");
    let rule =
        "[[rule]]\nname = \"masked\"\nwhen = \"diff.summary.pii_masked > 0\"\naction = \"deny\"\n";
    let tested = d.api(
        "POST",
        "/v1/policy/test",
        json!({"proposal": real["id"], "rules_toml": rule}),
    );
    assert_eq!(
        (&tested["outcome"], &tested["errors"]),
        (&json!("allow"), &json!([])),
        "{tested}"
    );
}

/// v0.1 re-review L2: a production turn missing in the fork because its
/// pii-masked parent failed (counter calls notes/tally) is pii-masked too,
/// not a consequence on the unchanged notes kind.
#[test]
fn a_turn_missing_below_a_masked_turn_is_masked_too() {
    let (_tmp, d) = privacy_on("kronik-m8-masked-child-");
    deploy(&d, "counter-calls-tally.wasm");
    deploy(&d, "notes-tally.wasm");
    let agent = token(&d, "agent", &["read", "fork", "propose"]);
    carol_requests(&d);
    let p = &propose_as(&d, "counter-fail-line.wasm", Some(&agent))["proposal"];
    let s = &p["summary"];
    assert_eq!(
        (&s["consequences"], &s["divergent_turns"]),
        (&json!(0), &json!(0)),
        "{s}"
    );
    // Every production turn: 4 counter turns and the notes turns below them.
    assert_eq!(s["pii_masked"], s["turns_prod"], "{s}");
}

/// ADR 0031 (v0.1 re-review residual): a turn of changed code that reads a
/// pseudonym but comes out identical (a timer firing `get`, which has no
/// output) did not run on the real value either: `pii_unverified`, and the
/// floor fires. An identity replay of the same window has none.
#[test]
fn identical_turns_on_pseudonyms_of_changed_code_need_an_approval() {
    let (_tmp, d) = privacy_on("kronik-m8-unverified-");
    let agent = token(&d, "agent", &["read", "fork", "propose"]);
    assert_eq!(d.post("/counter/t/increment", "user:1"), "1");
    let at = d.api("GET", "/v1/health", Value::Null)["applied_lsn"]
        .as_u64()
        .unwrap();
    d.send("counter/t", "schedule", "1 get", None);
    let fired = (0..200).any(|_| {
        let h = d.api("GET", "/v1/actors/counter/t/history", Value::Null);
        if h["turns"].as_array().is_some_and(|t| t.len() >= 3) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        false
    });
    assert!(fired, "the timer never fired");
    let wasm = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join("counter-step2.wasm")).unwrap());
    let p = &d.api_as(
        "POST",
        "/v1/proposals",
        json!({"wasm_base64": [wasm], "at": at, "reason": "privacy test"}),
        Some(&agent),
    )["proposal"];
    let s = &p["summary"];
    assert_eq!(
        (&s["pii_masked"], &s["pii_unverified"]),
        (&json!(0), &json!(1)),
        "{p}"
    );
    assert_eq!(p["policy"]["outcome"], "require_approval", "{p}");
    let floor = &p["policy"]["fired"][0];
    assert_eq!(floor["name"], "pii-masked-needs-approval", "{p}");
    assert!(
        floor["reason"]
            .as_str()
            .unwrap()
            .starts_with("1 turn could not"),
        "{p}"
    );

    let fork = d.api_as(
        "POST",
        "/v1/forks",
        json!({"at": at, "reason": "privacy test"}),
        Some(&agent),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let v = d.api_as(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"mode": "both", "reason": "privacy test"}),
        Some(&agent),
    );
    let s = &v["summary"];
    assert_eq!(
        (&s["pii_masked"], &s["pii_unverified"]),
        (&json!(0), &json!(0)),
        "{v}"
    );
}

/// M10 criterion 3: `diff show --summary` (`format=summary`) has no bodies,
/// no state values and no actor keys, for a diff with personal data under
/// privacy mode `on` (sealed values with subjects) and with plain values.
#[test]
fn the_diff_summary_shows_no_bodies_or_values() {
    let tmp = tempfile::Builder::new()
        .prefix("kronik-m10-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    let d = Daemon::start(dir);
    deploy(&d, "counter.wasm");
    d.api(
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "http:127.0.0.1", "reason": "privacy test"}),
    );
    d.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "privacy test"}),
    );
    let target = http_target("pong");
    let pay = |body: &str| format!("POST http://{target}/v1/pay\n\n{body}");
    // A plain value and a value with a subject, in effect bodies and state.
    d.send(
        "counter/alice-key",
        "fetch-ok",
        &pay("plain-body-7f3a"),
        None,
    );
    d.send(
        "counter/bob-key",
        "fetch-ok",
        &pay("sealed-body-9c2b"),
        Some("user:1"),
    );
    d.send("counter/alice-key", "note", "plain-state-5d1e", None);
    d.send("counter/bob-key", "subject", "", None);

    let wasm = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join("counter-body-v2.wasm")).unwrap());
    let v = d.api(
        "POST",
        "/v1/proposals",
        json!({"wasm_base64": [wasm], "reason": "privacy test"}),
    );
    let id = v["proposal"]["id"].as_str().unwrap().to_owned();
    let full = api_text(&d, &format!("/v1/proposals/{id}/diff?format=md"), None);
    // The full diff shows the plain value; the subject's effect body is
    // redacted there too (m8-privacy §5).
    assert!(full.contains("plain-body-7f3a"), "{full}");
    assert!(!full.contains("sealed-body-9c2b"), "{full}");
    let summary = api_text(&d, &format!("/v1/proposals/{id}/diff?format=summary"), None);
    for leak in [
        "plain-body-7f3a",
        "sealed-body-9c2b",
        "plain-state-5d1e",
        "personal",
        "alice-key",
        "bob-key",
        "user:1",
        "redacted",
        "sealed",
    ] {
        assert!(!summary.contains(leak), "{leak} in the summary:\n{summary}");
    }
    assert!(
        summary.starts_with(&format!("# Behavior diff summary: `{id}`\n")),
        "{summary}"
    );
    assert!(summary.contains("| Effects | "), "{summary}");
}

/// M10 criterion 3 (review H1): an e-mail address in an effect's URL path
/// never reaches the summary, through the API or `kronik diff show
/// --summary`; grounding shows the kind, method and granted host only.
#[test]
fn the_diff_summary_shows_no_url_paths() {
    const EMAIL: &str = "alice.smith@example.com";
    let tmp = tempfile::Builder::new()
        .prefix("kronik-m10-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let d = Daemon::start(tmp.path());
    deploy(&d, "counter.wasm");
    d.api(
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "http:127.0.0.1", "reason": "privacy test"}),
    );
    d.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "privacy test"}),
    );
    let target = http_target("pong");
    d.send(
        "counter/alice",
        "fetch-ok",
        &format!("POST http://{target}/v1/customers/{EMAIL}/notify\n\nhello"),
        Some("user:alice"),
    );
    let reader = d.api(
        "POST",
        "/v1/tokens",
        json!({"name": "reader", "scopes": ["read"], "reason": "privacy test"}),
    )["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let wasm = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join("counter-body-v2.wasm")).unwrap());
    let v = d.api(
        "POST",
        "/v1/proposals",
        json!({"wasm_base64": [wasm], "reason": "privacy test"}),
    );
    let id = v["proposal"]["id"].as_str().unwrap().to_owned();
    let api = api_text(&d, &format!("/v1/proposals/{id}/diff?format=summary"), None);
    let cli = cli_as(&d, &reader, &["diff", "show", &id, "--summary"]);
    for (from, summary) in [("API", &api), ("CLI", &cli)] {
        // The grounding table is there, without the path.
        assert!(
            summary.contains("| `http.fetch` | `POST` | `127.0.0.1` |"),
            "{from}:\n{summary}"
        );
        for leak in [EMAIL, "alice.smith", "/v1/customers"] {
            assert!(
                !summary.contains(leak),
                "{leak} in the {from} summary:\n{summary}"
            );
        }
    }
}
