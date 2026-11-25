//! Answers that are blobs, on a real `kronik serve` with the test guest
//! `media` (M25, M26), as the v0.5.0 release rehearsal met them, where each
//! failed: a call whose callee answers with a blob it wrote (`write` always
//! makes one), from an HTTP turn and from a message turn (503 UNAVAILABLE,
//! and the caller's turn stayed open); an operator's message answered with
//! such a blob (503 UNAVAILABLE, "retry shortly", for good); and the turn
//! JSON of an answer that is a blob (`"body": null`), whose subject only a
//! caller with `pii:read` sees.

// A test harness of a real daemon: unwraps, and deadlines on the wall clock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

#[path = "support/blob_fixtures.rs"]
mod blob_fixtures;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use blob_fixtures::{pattern, pattern_sum};
use kronik_api::openapi::TURN_SCHEMA;
use serde_json::{Value, json};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");
const TURN_URL: &str = "file:///kronik/docs/reference/turn.schema.json";

const SETTINGS_ENV: [&str; 7] = [
    "KRONIK_CONFIG",
    "KRONIK_DATA_DIR",
    "KRONIK_HTTP_LISTEN",
    "KRONIK_ADMIN_LISTEN",
    "KRONIK_API_SOCKET",
    "KRONIK_MASTER_KEY_FILE",
    "KRONIK_TOKEN",
];

/// `kronik` with none of the developer's settings, and no disk reserve (the
/// tests' file system may have less free space).
fn kronik() -> Command {
    let mut command = Command::new(KRONIK);
    for var in SETTINGS_ENV {
        command.env_remove(var);
    }
    command.env("KRONIK_DISK_RESERVE", "0B");
    command.stdin(Stdio::null());
    command
}

struct Daemon {
    dir: PathBuf,
    child: Child,
    http: String,
}

/// An HTTP response: status, head and body.
struct Response {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Response {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

impl Daemon {
    /// A daemon on ports of its own, whose HTTP requests take their subject
    /// from `x-user-id`.
    fn start(dir: &Path) -> Daemon {
        let config = dir.join("kronik.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\n\n[gateway]\ntrusted_proxies = [\"127.0.0.1\"]\n\n[privacy]\nsubject_from = \"header:x-user-id\"\n",
                dir.join("data")
            ),
        )
        .unwrap();
        let log = std::fs::File::create(dir.join("serve.log")).unwrap();
        let child = kronik()
            .arg("serve")
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
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut d = Daemon {
            dir: dir.to_path_buf(),
            child,
            http: String::new(),
        };
        for _ in 0..1200 {
            if let Some((200, v)) = d.try_api("GET", "/v1/health", Value::Null, None) {
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

    fn socket(&self) -> PathBuf {
        self.dir.join("api.sock")
    }

    fn try_api(
        &self,
        method: &str,
        path: &str,
        body: Value,
        token: Option<&str>,
    ) -> Option<(u16, Value)> {
        let mut s = UnixStream::connect(self.socket()).ok()?;
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
        let r = read_response(s).ok()?;
        Some((r.status, serde_json::from_slice(&r.body).ok()?))
    }

    /// An API request that must answer 200. A request can meet the
    /// fail-closed secret-coverage window after a change (ADR 0108), which
    /// closes in milliseconds: 503 SECRET_UNAVAILABLE is waited out.
    fn api(&self, method: &str, path: &str, body: Value, token: Option<&str>) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (status, v) = self
                .try_api(method, path, body.clone(), token)
                .unwrap_or_else(|| panic!("{method} {path} failed: {}", self.log()));
            if status == 200 {
                return v;
            }
            assert!(
                v["error"]["code"] == "SECRET_UNAVAILABLE" && Instant::now() < deadline,
                "{method} {path}: {status} {v}\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// An operator's message to `actor`: its turn (`kronik send`'s answer).
    fn send(&self, actor: &str, name: &str) -> Value {
        self.api(
            "POST",
            &format!("/v1/actors/{actor}/messages"),
            json!({"name": name, "reason": "blob replies"}),
            None,
        )
    }

    /// `POST <path>` to the gateway, with `user` as the request's subject.
    fn post(&self, path: &str, user: Option<&str>) -> Response {
        let mut s = TcpStream::connect(&self.http).unwrap();
        let user = user.map_or(String::new(), |u| format!("x-user-id: {u}\r\n"));
        write!(
            s,
            "POST {path} HTTP/1.1\r\nhost: x\r\n{user}content-length: 0\r\n\
             connection: close\r\n\r\n"
        )
        .unwrap();
        read_response(s).unwrap()
    }

    /// [`Daemon::post`] that must answer 200; its body as text.
    fn ok(&self, path: &str) -> String {
        let r = self.post(path, None);
        assert_eq!(r.status, 200, "{path}: {}\n{}", r.text(), self.log());
        r.text()
    }

    fn cli(&self, args: &[&str]) -> std::process::Output {
        let socket = self.socket();
        let mut all = vec!["--socket", socket.to_str().unwrap()];
        all.extend_from_slice(args);
        kronik()
            .args(&all)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One HTTP/1.1 response, with a `content-length` or a chunked body.
fn read_response(stream: impl Read) -> std::io::Result<Response> {
    let mut r = BufReader::new(stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::other(format!("no status in {head:?}")))?;
    let mut response = Response {
        status,
        head,
        body: Vec::new(),
    };
    if response
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let mut size = String::new();
            r.read_line(&mut size)?;
            let size = usize::from_str_radix(size.trim(), 16).map_err(std::io::Error::other)?;
            let mut chunk = vec![0; size + 2];
            r.read_exact(&mut chunk)?;
            if size == 0 {
                break;
            }
            response.body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(len) = response.header("content-length") {
        let mut body = vec![0; len.parse().map_err(std::io::Error::other)?];
        r.read_exact(&mut body)?;
        response.body = body;
    } else {
        r.read_to_end(&mut response.body)?;
    }
    Ok(response)
}

/// The blob of the `call` operation's answer `reply blob <hash> <size>`,
/// with ` retained` after it when `keep=1` retained it.
fn reply_blob(answer: &str, retained: bool) -> (String, u64) {
    let rest = answer
        .strip_prefix("reply blob ")
        .unwrap_or_else(|| panic!("{answer}"));
    let rest = if retained {
        rest.strip_suffix(" retained")
            .unwrap_or_else(|| panic!("{answer}"))
    } else {
        rest
    };
    let (hash, size) = rest.split_once(' ').unwrap_or_else(|| panic!("{answer}"));
    assert!(hash.starts_with("b3"), "{answer}");
    (hash.to_owned(), size.parse().unwrap())
}

fn deploy(d: &Daemon) {
    let wasm = std::fs::read(MEDIA).unwrap();
    use base64::Engine as _;
    d.api(
        "POST",
        "/v1/deployments",
        json!({
            "wasm_base64": base64::engine::general_purpose::STANDARD.encode(wasm),
            "reason": "blob replies",
        }),
        None,
    );
}

/// The turn JSON schema (docs/reference/turn.schema.json), compiled.
fn turn_schema() -> (boon::Schemas, boon::SchemaIndex) {
    let mut schemas = boon::Schemas::new();
    let mut c = boon::Compiler::new();
    c.set_default_draft(boon::Draft::V2020_12);
    c.add_resource(TURN_URL, serde_json::from_str(TURN_SCHEMA).unwrap())
        .unwrap();
    let index = c.compile(TURN_URL, &mut schemas).unwrap();
    (schemas, index)
}

/// A call whose callee answers with a blob it wrote gives the caller that
/// blob, an HTTP turn (the gateway's answer) and a message turn alike: the
/// caller reads it, retains it and holds it; the pins that keep the blob
/// match the rows they mirror; nothing is left unprocessed; and an identity
/// replay gives the callers the same replies.
#[test]
fn a_call_answered_with_a_blob_the_callee_wrote() {
    let tmp = tempfile::tempdir().unwrap();
    let d = Daemon::start(tmp.path());
    deploy(&d);
    let setup = d.api("GET", "/v1/health", Value::Null, None)["applied_lsn"]
        .as_u64()
        .unwrap();
    // From an HTTP turn, at 100 000 bytes and at 1 000, which is below
    // every blob threshold: `write` always makes a blob.
    let (hash, size) = reply_blob(&d.ok("/media/c/call?to=c2&op=write?size=100000"), false);
    assert_eq!(size, 100_000);
    let (kept, size) = reply_blob(&d.ok("/media/c/call?to=c3&op=write?size=1000&keep=1"), true);
    assert_eq!(size, 1000);
    assert_ne!(hash, kept);
    assert_eq!(d.ok("/media/c/held-sum"), pattern_sum(1000));

    // From a message turn: an operator's message whose turn calls.
    let turn = d.send("media/m", "call?to=m2&op=write?size=1000&keep=1");
    assert_eq!(turn["outcome"]["kind"], "committed", "{turn}");
    let (held, _) = reply_blob(turn["reply"]["text"].as_str().unwrap(), true);
    assert_eq!(held, kept, "the same bytes: the same blob");
    let actor = d.api("GET", "/v1/actors/media/m", Value::Null, None);
    assert_eq!(actor["blobs"]["held"], 1, "{actor}");
    let turn = d.send("media/m", "held-sum");
    assert_eq!(turn["reply"]["text"], pattern_sum(1000), "{turn}");

    let plan = d.api("GET", "/v1/blobs/gc?verify=true", Value::Null, None);
    assert_eq!(plan["drift"], json!([]), "{plan}");
    let log = d.log();
    assert!(!log.contains("input not processed"), "{log}");

    let fork = d.api(
        "POST",
        "/v1/forks",
        json!({"at": setup, "reason": "blob replies"}),
        None,
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    d.api(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"reason": "blob replies"}),
        None,
    );
    let diff = d.api("GET", &format!("/v1/forks/{fork}/diff"), Value::Null, None);
    assert_eq!(diff["summary"]["changed"], false, "{diff}");
    assert!(diff["summary"]["replayed"].as_u64() >= Some(5), "{diff}");
}

/// An operator's message whose turn answers with a blob it wrote gets the
/// blob's reference as its reply (`blob`, no inline bytes), which `kronik
/// send` shows and `kronik blobs get` reads.
#[test]
fn an_operator_message_answered_with_a_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let d = Daemon::start(tmp.path());
    deploy(&d);
    let turn = d.send("media/b", "write?size=100000");
    assert_eq!(turn["outcome"]["kind"], "committed", "{turn}");
    let reply = &turn["reply"];
    assert_eq!(reply["name"], "http 200", "{turn}");
    assert_eq!(reply["blob"]["size"], 100_000, "{turn}");
    assert!(reply.get("text").is_none() && reply.get("base64").is_none());
    let hash = reply["blob"]["hash"].as_str().unwrap().to_owned();
    assert!(hash.starts_with("b3:"), "{turn}");
    let file = tmp.path().join("reply.bin");
    let o = d.cli(&["blobs", "get", &hash, "-o", file.to_str().unwrap()]);
    assert!(o.status.success(), "{o:?}");
    assert!(std::fs::read(&file).unwrap() == pattern(100_000));

    let o = d.cli(&[
        "send",
        "media/b",
        "write?size=2000",
        "--reason",
        "blob replies",
    ]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{o:?}");
    assert!(out.contains("committed on media/b"), "{out}");
    assert!(
        out.contains("Blob b3:") && out.contains("(2000 bytes)"),
        "{out}"
    );
}

/// `GET /v1/turns/{id}` of a turn whose HTTP answer is a blob shows the
/// blob's reference: its hash and size to every reader, its subject only
/// to one with `pii:read`. The JSON matches the turn schema.
#[test]
fn the_turn_json_shows_an_answers_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let d = Daemon::start(tmp.path());
    deploy(&d);
    let r = d.post("/media/w/write?size=100000", Some("user:1"));
    assert_eq!(r.status, 200, "{}\n{}", r.text(), d.log());
    assert!(r.body == pattern(100_000), "the answer is the blob's bytes");
    let id = r.header("kronik-turn-id").unwrap().to_owned();
    let reader = d.api(
        "POST",
        "/v1/tokens",
        json!({"name": "reader", "scopes": ["read"], "reason": "blob replies"}),
        None,
    )["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let (schemas, schema) = turn_schema();
    let path = format!("/v1/turns/{id}");
    let shown = |token: Option<&str>| {
        let t = d.api("GET", &path, Value::Null, token);
        if let Err(e) = schemas.validate(&t, schema) {
            panic!("the turn does not match its schema: {e:#}\n{t:#}");
        }
        t["output"]["http"]["body"]["blob"].clone()
    };
    let with = shown(None);
    let hash = with["hash"].as_str().unwrap_or_else(|| panic!("{with}"));
    assert!(hash.starts_with("b3s:"), "a subject's blob: {with}");
    assert_eq!(with["size"], 100_000, "{with}");
    assert_eq!(with["subject"], "user:1", "{with}");
    let without = shown(Some(&reader));
    assert_eq!(without["hash"], hash, "{without}");
    assert_eq!(without["size"], 100_000, "{without}");
    assert_eq!(without["subject"], Value::Null, "{without}");
}
