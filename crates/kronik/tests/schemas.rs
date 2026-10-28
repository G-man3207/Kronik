//! The hand-written JSON Schemas of the two bodies the API does not generate
//! from types (ADR 0010): `kronik.diff/v1` (docs/reference/diff-v1.schema.json)
//! and the turn JSON of `GET /v1/turns/{id}` (docs/reference/turn.schema.json),
//! checked against what a real `kronik serve` answers: every turn of main's
//! log, fork turns of both replay modes, and the diffs of an identity replay,
//! counter +2, approximate payments, a sample, stub rules, a new error and a
//! fork without personal data.

// Test harness code: unwraps are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use kronik_api::openapi::{DIFF_SCHEMA, TURN_SCHEMA};
use serde_json::{Value, json};

const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests");
const DIFF_URL: &str = "file:///kronik/docs/reference/diff-v1.schema.json";
const TURN_URL: &str = "file:///kronik/docs/reference/turn.schema.json";

/// The two schema files, compiled.
struct Schemas {
    compiled: boon::Schemas,
    diff: boon::SchemaIndex,
    summary: boon::SchemaIndex,
    turn: boon::SchemaIndex,
}

impl Schemas {
    fn compile() -> Schemas {
        let mut compiled = boon::Schemas::new();
        let mut c = boon::Compiler::new();
        c.set_default_draft(boon::Draft::V2020_12);
        for (url, text) in [(DIFF_URL, DIFF_SCHEMA), (TURN_URL, TURN_SCHEMA)] {
            c.add_resource(url, serde_json::from_str(text).unwrap())
                .unwrap();
        }
        let mut compile = |loc: &str| {
            c.compile(loc, &mut compiled)
                .unwrap_or_else(|e| panic!("{loc}: {e:#}"))
        };
        let diff = compile(DIFF_URL);
        let summary = compile(&format!("{DIFF_URL}#/$defs/DiffSummary"));
        let turn = compile(TURN_URL);
        Schemas {
            compiled,
            diff,
            summary,
            turn,
        }
    }

    fn check(&self, schema: boon::SchemaIndex, what: &str, v: &Value) {
        if let Err(e) = self.compiled.validate(v, schema) {
            panic!(
                "{what} does not match its schema:\n{e:#}\n{}",
                serde_json::to_string_pretty(v).unwrap()
            );
        }
    }
}

struct Daemon {
    dir: PathBuf,
    child: Child,
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
        let log = std::fs::File::create(dir.join("serve.log")).unwrap();
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
            .env("KRONIK_LOG", "warn")
            .env_remove("KRONIK_TOKEN")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut d = Daemon {
            dir: dir.to_path_buf(),
            child,
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

    /// A message to `actor`; failing handlers are part of the test.
    fn send(&self, actor: &str, name: &str, text: &str, subject: Option<&str>) {
        let body = json!({"name": name, "text": text, "subject": subject, "reason": "schemas"});
        self.try_api("POST", &format!("/v1/actors/{actor}/messages"), body)
            .unwrap_or_else(|| panic!("send {actor} {name}: {}", self.log()));
    }

    /// A gateway request; returns the response's status line and body.
    fn post(&self, path: &str, body: &str, user: Option<&str>) -> String {
        let mut s = TcpStream::connect(&self.http).unwrap();
        let user = user.map_or(String::new(), |u| format!("x-user-id: {u}\r\n"));
        write!(
            s,
            "POST {path} HTTP/1.1\r\nhost: x\r\n{user}content-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    fn deploy(&self, guest: &str) {
        self.api(
            "POST",
            "/v1/deployments",
            json!({"wasm_base64": wasm(guest), "reason": "schemas"}),
        );
    }

    fn applied_lsn(&self) -> u64 {
        self.api("GET", "/v1/health", Value::Null)["applied_lsn"]
            .as_u64()
            .unwrap()
    }

    /// Every turn of main's log, by LSN.
    fn main_turns(&self) -> Vec<Value> {
        (1..=self.applied_lsn())
            .filter_map(|lsn| {
                match self.try_api("GET", &format!("/v1/turns/main:{lsn}"), Value::Null) {
                    Some((200, v)) => Some(v),
                    Some((_, v)) => {
                        assert_eq!(v["error"]["code"], "TURN_NOT_FOUND", "main:{lsn}: {v}");
                        None
                    }
                    None => panic!("main:{lsn}: {}", self.log()),
                }
            })
            .collect()
    }

    /// Proposes `guest` with `options`; returns the proposal's id.
    fn propose(&self, s: &Schemas, guest: &str, options: Value) -> String {
        let mut body = json!({"wasm_base64": [wasm(guest)], "reason": "schemas"});
        if let (Value::Object(b), Value::Object(o)) = (&mut body, options) {
            b.extend(o);
        }
        let v = self.api("POST", "/v1/proposals", body);
        s.check(s.summary, "a proposal's summary", &v["proposal"]["summary"]);
        v["proposal"]["id"].as_str().unwrap().to_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wasm(guest: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join(format!("{guest}.wasm"))).unwrap())
}

/// A plain HTTP server on a free port that answers every request with 200
/// and the body `pong`, until the test process exits. Returns its address.
// A test harness thread, not daemon code (ADR 0004).
#[allow(clippy::disallowed_methods)]
fn http_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
            );
        }
    });
    addr
}

/// Every fork turn a diff names.
fn sampled_turns(diff: &Value) -> BTreeSet<String> {
    diff["samples"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|ids| ids.as_array().unwrap())
        .map(|id| id.as_str().unwrap().to_owned())
        .collect()
}

/// The policy fixtures (docs/design/fixtures/diff-*.json, without their
/// `expected_policy`) are diffs as the schema describes them.
#[test]
fn the_diff_fixtures_match_the_diff_schema() {
    let s = Schemas::compile();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/fixtures");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !(name.starts_with("diff-") && name.ends_with(".json")) {
            continue;
        }
        let mut diff: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        diff.as_object_mut().unwrap().remove("expected_policy");
        s.check(s.diff, &name, &diff);
        checked += 1;
    }
    assert!(checked >= 6, "only {checked} fixtures");
}

#[test]
fn real_diffs_and_turns_match_their_schemas() {
    let s = Schemas::compile();
    let tmp = tempfile::tempdir().unwrap();
    let d = Daemon::start(tmp.path());
    let target = http_target();
    d.deploy("counter");
    d.deploy("notes");
    d.api(
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "http:127.0.0.1", "reason": "schemas"}),
    );
    let setup = d.applied_lsn();

    // Production: HTTP inputs (one with a subject), payments and a GET
    // through the counter's fetch-ok, messages between actors, a value with
    // a subject, failing handlers, a denied effect, and SQL state with a
    // subject.
    for i in 0..2 {
        let user = (i == 0).then_some("user:1");
        let answer = d.post("/counter/a/increment", "", user);
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        let pay = format!("POST http://{target}/v1/charges/{i}\n\namount=10");
        assert!(d.post("/counter/pay/fetch-ok", &pay, None).contains("pong"));
    }
    let get = format!("GET http://{target}/items/1");
    assert!(
        d.post("/counter/shop/fetch-ok", &get, None)
            .contains("pong")
    );
    d.send("counter/a", "forward", "b", None);
    d.send("counter/a", "get", "", None);
    d.send("counter/s", "subject", "", None);
    d.send("counter/f", "fail", "", None);
    d.send("counter/x", "trap", "", None);
    d.send("counter/d", "fetch-ok", "GET http://denied.example/x", None);
    d.send("notes/n", "add", "a note", Some("user:1"));
    d.send("notes/n", "list", "", None);

    // Diffs, and every fork turn they name. The identity diff comes from a
    // plain fork: a proposal of the code main runs is refused (M9).
    let mut diffs = Vec::new();
    let identity = d.api(
        "POST",
        "/v1/forks",
        json!({"at": setup, "reason": "schemas"}),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    d.api(
        "POST",
        &format!("/v1/forks/{identity}/replay"),
        json!({"reason": "schemas"}),
    );
    let diff = d.api("GET", &format!("/v1/forks/{identity}/diff"), Value::Null);
    s.check(s.diff, "the identity fork's diff", &diff);
    diffs.push(diff);
    let step2 = d.propose(&s, "counter-step2", json!({}));
    let payments = d.propose(&s, "counter-body-v2", json!({}));
    let sampled = d.propose(&s, "counter-step2", json!({"sample": 0.5}));
    let stubbed = d.propose(
        &s,
        "counter-fetch-extra",
        json!({"stubs": [{"method": "GET", "url_prefix": format!("http://{target}/items/"), "body": "stubbed"}]}),
    );
    let fail_get = d.propose(&s, "counter-fail-get", json!({"mode": "isolated"}));
    // A system proposal (M9): two kinds in one fork, reported per kind.
    let system = d.propose(
        &s,
        "counter-calls-tally",
        json!({"wasm_base64": [wasm("counter-calls-tally"), wasm("notes-tally")]}),
    );
    for id in [&step2, &payments, &sampled, &stubbed, &fail_get, &system] {
        let diff = d.api("GET", &format!("/v1/proposals/{id}/diff"), Value::Null);
        s.check(s.diff, &format!("the diff of {id}"), &diff);
        diffs.push(diff);
    }
    let system_diff = diffs.pop().unwrap();
    let kinds: Vec<(&str, &str)> = system_diff["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| (k["kind"].as_str().unwrap(), k["code"].as_str().unwrap()))
        .collect();
    assert_eq!(
        kinds,
        [("counter", "changed"), ("notes", "changed")],
        "{system_diff}"
    );
    // A fork without personal data, replayed through the same code.
    let fork = d.api(
        "POST",
        "/v1/forks",
        json!({"at": setup, "no_pii": true, "reason": "schemas"}),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let replayed = d.api(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"mode": "isolated", "reason": "schemas"}),
    );
    s.check(s.summary, "a replay's summary", &replayed["summary"]);
    let diff = d.api("GET", &format!("/v1/forks/{fork}/diff"), Value::Null);
    s.check(s.diff, "the --no-pii fork's diff", &diff);
    diffs.push(diff);

    let summary = |i: usize| &diffs[i]["summary"];
    assert_eq!(summary(0)["changed"], false, "identity: {}", diffs[0]);
    assert!(summary(1)["divergent_turns"].as_u64() > Some(0));
    assert!(
        !diffs[1]["state"]["continuous"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        summary(2)["approximate"].as_u64() >= Some(2),
        "{}",
        diffs[2]
    );
    assert!(summary(3)["sample"].as_f64() < Some(1.0), "{}", diffs[3]);
    assert!(summary(4)["synthetic"].as_u64() >= Some(1), "{}", diffs[4]);
    assert_eq!(diffs[4]["options"]["stubs"][0]["body"], "stubbed");
    assert!(
        diffs[5]["errors"]["introduced"].as_u64() >= Some(1),
        "{}",
        diffs[5]
    );
    assert!(summary(6)["pii_masked"].as_u64() >= Some(1), "{}", diffs[6]);
    assert!(
        !diffs[6]["samples"]["pii_masked"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let mut isolated = 0;
    for diff in &diffs {
        for id in sampled_turns(diff) {
            let t = d.api("GET", &format!("/v1/turns/{id}"), Value::Null);
            s.check(s.turn, &format!("fork turn {id}"), &t);
            isolated += usize::from(id.contains(":r"));
        }
    }
    assert!(isolated > 0, "no isolated turn in the samples");
    // Continuous replay's turns, from the fork's log.
    let fork_lsn = diffs[1]["base"]["fork_lsn"].as_u64().unwrap();
    let mut continuous = 0;
    for lsn in fork_lsn + 1..=diffs[1]["base"]["to_lsn"].as_u64().unwrap() + 4 {
        let id = format!("{step2}:{lsn}");
        if let Some((200, t)) = d.try_api("GET", &format!("/v1/turns/{id}"), Value::Null) {
            s.check(s.turn, &format!("fork turn {id}"), &t);
            continuous += 1;
        }
    }
    assert!(continuous > 0, "no continuous fork turn");
    // A preview of step2 (M11): its request is a preview input of its diff.
    let preview = d.api(
        "POST",
        "/v1/previews",
        json!({"proposal": step2, "reason": "schemas"}),
    )["preview"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = d.post(
        &format!("/__preview/{preview}/counter/a/increment"),
        "",
        None,
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let diff = d.api("GET", &format!("/v1/forks/{preview}/diff"), Value::Null);
    s.check(s.diff, "a preview's diff", &diff);
    assert_eq!(diff["summary"]["preview_inputs"], 1, "{diff}");
    let turn = diff["samples"]["preview"][0]["turn"].as_str().unwrap();
    s.check(
        s.turn,
        "a preview's turn",
        &d.api("GET", &format!("/v1/turns/{turn}"), Value::Null),
    );

    // A timer that fires and one that is cancelled, after the proposals, so
    // that the replays above do not depend on how replay treats timers.
    d.send("counter/t", "schedule", "1 increment", None);
    d.send("counter/t", "schedule", "3600000 increment", None);
    let timers = d.api("GET", "/v1/actors/counter/t/timers", Value::Null);
    let later = timers["timers"]
        .as_array()
        .unwrap()
        .iter()
        .max_by_key(|t| t["due_ms"].as_u64())
        .map(|t| t["id"].as_str().unwrap().to_owned())
        .unwrap_or_else(|| panic!("no timer: {timers}"));
    d.send("counter/t", "cancel", &later, None);

    // Every turn of main's log, once the timer has fired.
    let mut turns = Vec::new();
    for _ in 0..200 {
        turns = d.main_turns();
        if turns.iter().any(|t| t["input"]["type"] == "timer") {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    for t in &turns {
        s.check(s.turn, &format!("turn {}", t["turn_id"]), t);
    }
    let seen = |f: &dyn Fn(&Value) -> bool| turns.iter().any(f);
    for kind in ["http", "message", "timer", "migrate"] {
        assert!(seen(&|t| t["input"]["type"] == kind), "no {kind} turn");
    }
    assert!(seen(&|t| t["input"]["source"] == "MESSAGE_SOURCE_ACTOR"));
    assert!(seen(&|t| t["output"]["http"]["status"] == 200));
    assert!(seen(&|t| t["output"]["reply"]["name"].is_string()));
    assert!(seen(&|t| t["outcome"]["kind"] == "failed"));
    assert!(seen(&|t| t["outcome"]["kind"] == "trap"));
    assert!(seen(&|t| t["effects"][0]["status"] == "denied"));
    assert!(seen(&|t| t["effects"][0]["status"] == "ok"));
    assert!(seen(&|t| t["timers"][0]["op"] == "cancel"));
    assert!(seen(&|t| t["messages"][0]["to"] == "counter/b"));
    assert!(seen(&|t| t["writes"][0]["value"]["subject"] == "user:1"));
    assert!(seen(&|t| t["sql_changes"][0]["bytes"].as_u64() > Some(0)));
    assert!(seen(&|t| t["input"]["headers"].as_array().is_some_and(
        |h| h.iter().any(|h| h["value"]["subject"] == "user:1")
    )));

    // The schemas have teeth: an unknown field or a missing one fails.
    let mut extra = diffs[1].clone();
    extra["summary"]["surprise"] = json!(1);
    assert!(s.compiled.validate(&extra, s.diff).is_err());
    let mut missing = turns[0].clone();
    missing.as_object_mut().unwrap().remove("effects");
    assert!(s.compiled.validate(&missing, s.turn).is_err());
}
