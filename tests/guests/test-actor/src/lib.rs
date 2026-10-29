//! Test guests for the daemon tests and the simulator, written directly
//! against the WIT (the SDK examples live in `examples/`).
//!
//! Default build: kind `counter`, schema version 0, key-value state only.
//! Feature `notes`: kind `notes`, schema version 1, SQL state created by
//! `migrate(0)`.
//!
//! HTTP routes take the last path segment as the operation; messages use
//! their name. Operations (counter):
//! - `increment`: n += 1, replies n (decimal text)
//! - `get`: replies n
//! - `probe`: replies "causal=<id> now=<ms> random=<hex> subject=<s>"
//! - `forward`: n += 1 and sends `increment` to counter/<body>
//! - `fail` / `reject`: handler errors; `trap`: a panic
//! - `spin`: loops <body> times (an unparsable body loops until fuel ends)
//! - `subject`: sets key "s" for subject "user:1" via `state.set-for`
//! - `big`: replies with <body> bytes (size-limit tests)
//!
//! - `fetch` / `fetch-ok`: one HTTP effect described by the body (see
//!   `request`); `fetch` fails the turn on a fetch error, `fetch-ok` replies
//!   with the error; `fetch2`: two requests separated by a `---` line
//! - `hmac`: body `secret\ndata`, replies the hex HMAC-SHA256
//! - `reveal`: body `secret`, replies the value
//! - `exfiltrate`: body `secret url`: tries every way to get the secret out
//!   (reveal, a fetch with the secret header to an echo URL), then stores,
//!   logs, sends and replies whatever it got
//! - `call` / `call-fail`: body `kind/key name [compensation]`; `call-fail`
//!   fails the turn after the call
//! - `schedule`: body `delay-ms name`, then optionally a newline and the
//!   timer message's body; replies the timer id; `cancel`: body id
//! - `flaky`: fails until `allow` was run on the actor, then increments
//! - `reveal-persist`: body `secret`: reveals it and puts the value in
//!   state, a log event, stdout, a message to counter/sink and the reply
//!
//! - `fanout`: body N: n += 1, then sends `note` with body n to
//!   counter/f0 .. counter/f<N-1>; `note` stores its body under key "last"
//!
//! Variants for replay tests (M3), each a separate build of `counter`:
//! feature `step2` (increment adds 2), `body-v2` (fetch request bodies get
//! " v2" appended), `fail-get` (`get` fails), `fetch-extra` (`fetch-ok` then
//! also GETs `<url>/extra` and appends that answer), `schema1` (schema
//! version 1; `migrate(0)` sets key "schema" to "1"). In `fetch-extra`,
//! request head lines `T read <key>`, `T hmac <secret>`, `T reveal
//! <secret>` and `T call <kind/key> <name>` (which other builds ignore) read
//! state, use or reveal a secret, or call before the extra GET, and the op `read` reads key "s": the
//! model simulator's taint paths (review M5, N12-3).
//! For system proposals (M9): feature `calls-tally` (every `increment`
//! also calls `tally` on notes/tally and fails when that call does).
//!
//! Operations (notes): `add` inserts the body, `count` replies the row
//! count, `list` replies the bodies joined by newlines, `add-secret`
//! (body `secret`) inserts a note holding the revealed value; with feature
//! `tally` (M9), `tally` inserts "tally <body>".
//! Privacy tests (v0.1): `fail-line` (every HTTP request fails with its
//! request line); with `notes`, `sql-call` (`add-call` inserts its body,
//! then calls `increment` on counter/c).
//! Standard fetch (M22): feature `wasi-http` adds operations that use
//! `wasi:http` directly, the way StarlingMonkey's `fetch` does (`handle`
//! first, the body after). A request is `METHOD URL`, `name: value` header
//! lines, an empty line and the body:
//! - `wfetch`: one request; replies "<status> <body>" or "error <code>"
//!   (with `fetch-extra`, then also GETs `<url>/extra` and appends that)
//! - `wfetch2`: two requests separated by a `---` line, both started
//!   before either body is written; the second body is finished first, then
//!   both responses are polled together, then the first body is written:
//!   replies the ready lists and both answers
//! - `wfetch3`: two requests separated by a `---` line, both started, then
//!   both bodies finished with non-blocking writes (as StarlingMonkey's
//!   `Promise.all` of fetches does), then both responses polled together:
//!   replies the first ready list and both answers
//! - `wstream`: one request whose body (the spec's body) is written one byte
//!   at a time through `check-write`, `subscribe` and `poll`
//! - `wstall`: starts a request, never finishes its body, waits for it
//! - `wleave`: starts a request, finishes its body and returns without
//!   waiting (a `fetch` nobody awaits)
//! - `wdrop`: starts a request and drops its future, then sends the next
//!   one (after `---`)

// The notes build does not use the counter helpers.
#![cfg_attr(feature = "notes", allow(unused_imports, dead_code))]

use std::fmt::Write as _;

wit_bindgen::generate!({
    world: "actor",
    path: "../../../wit/kronik-actor.wit",
});

use exports::kronik::actor::handler::Guest;
use kronik::actor::types::{
    ActorRef, HandlerError, HttpBody, HttpResponse, Input, Manifest, Message, Output, Route,
};
use kronik::actor::{context, crypto, http_client, log, messaging, privacy, secrets, state, timers};

struct TestActor;

fn route(method: &str, pattern: &str) -> Route {
    Route {
        method: method.to_string(),
        pattern: pattern.to_string(),
    }
}

fn text(s: String) -> Message {
    Message {
        name: "reply".to_string(),
        content_type: "text/plain".to_string(),
        body: s.into_bytes(),
        blobs: Vec::new(),
    }
}

fn counter() -> u64 {
    state::get("n")
        .and_then(|v| String::from_utf8(v).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

const STEP: u64 = if cfg!(feature = "step2") { 2 } else { 1 };

fn increment() -> u64 {
    let n = counter() + STEP;
    state::set("n", n.to_string().as_bytes());
    n
}

/// Parses `METHOD URL` then `H name value` / `S name secret template`
/// header lines, then an empty line and the body.
fn request(spec: &str) -> http_client::Request {
    let (head, body) = spec.split_once("\n\n").unwrap_or((spec, ""));
    let mut lines = head.lines();
    let first = lines.next().unwrap_or("GET http://invalid/");
    let (method, url) = first.split_once(' ').unwrap_or(("GET", first));
    let mut headers = Vec::new();
    for l in lines {
        let parts: Vec<&str> = l.splitn(4, ' ').collect();
        match parts.as_slice() {
            ["H", name, value] => headers.push(http_client::RequestHeader {
                name: name.to_string(),
                value: http_client::HeaderValue::Text(value.to_string()),
            }),
            ["S", name, secret, template] => headers.push(http_client::RequestHeader {
                name: name.to_string(),
                value: http_client::HeaderValue::Secret(http_client::SecretTemplate {
                    name: secret.to_string(),
                    template: template.to_string(),
                }),
            }),
            _ => {}
        }
    }
    let body = if cfg!(feature = "body-v2") {
        format!("{body} v2")
    } else {
        body.to_string()
    };
    http_client::Request {
        method: method.to_string(),
        url: url.to_string(),
        headers,
        body: HttpBody::Inline(body.into_bytes()),
    }
}

fn fetch_text(spec: &str) -> Result<String, String> {
    match http_client::fetch(&request(spec)) {
        Ok(r) => {
            let body = match r.body {
                HttpBody::Inline(b) => String::from_utf8_lossy(&b).into_owned(),
                HttpBody::Blob(_) => String::new(),
            };
            Ok(format!("{} {}", r.status, body))
        }
        Err(e) => Err(format!("{e:?}")),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(not(feature = "notes"))]
fn run(op: &str, body: &[u8]) -> Result<String, HandlerError> {
    let text = String::from_utf8_lossy(body).into_owned();
    match op {
        "fetch" => fetch_text(&text).map_err(|e| HandlerError::Failed(format!("fetch: {e}"))),
        "fetch-ok" => {
            let first = fetch_text(&text).unwrap_or_else(|e| format!("error {e}"));
            if !cfg!(feature = "fetch-extra") {
                return Ok(first);
            }
            let url = text.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("");
            let head = text.split_once("\n\n").map_or(text.as_str(), |(h, _)| h);
            for line in head.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                match parts.as_slice() {
                    ["T", "read", key] => {
                        let _ = state::get(key);
                    }
                    ["T", "hmac", secret] => {
                        let _ = crypto::hmac_sha256(secret, b"x");
                    }
                    ["T", "reveal", secret] => {
                        let _ = secrets::reveal(secret);
                    }
                    ["T", "call", target, name] => {
                        let (kind, key) = target.split_once('/').unwrap_or(("counter", target));
                        let to = ActorRef {
                            kind: kind.to_string(),
                            key: key.to_string(),
                        };
                        let msg = Message {
                            name: name.to_string(),
                            content_type: "text/plain".to_string(),
                            body: Vec::new(),
                            blobs: Vec::new(),
                        };
                        let _ = messaging::call(&to, &msg, None);
                    }
                    _ => {}
                }
            }
            let extra = fetch_text(&format!("GET {url}/extra"))
                .unwrap_or_else(|e| format!("error {e}"));
            Ok(format!("{first} | {extra}"))
        }
        "fetch2" => {
            let (a, b) = text.split_once("\n---\n").unwrap_or((&text, ""));
            let first = fetch_text(a).map_err(|e| HandlerError::Failed(format!("fetch 1: {e}")))?;
            let second = fetch_text(b).map_err(|e| HandlerError::Failed(format!("fetch 2: {e}")))?;
            Ok(format!("{first} | {second}"))
        }
        "hmac" => {
            let (secret, data) = text.split_once('\n').unwrap_or((&text, ""));
            crypto::hmac_sha256(secret, data.as_bytes())
                .map(|m| hex(&m))
                .map_err(|e| HandlerError::Failed(format!("hmac: {e:?}")))
        }
        "reveal" => secrets::reveal(&text).map_err(|e| HandlerError::Failed(format!("reveal: {e}"))),
        "exfiltrate" => {
            let (secret, url) = text.split_once(' ').unwrap_or((&text, "http://invalid/"));
            let mut loot = String::new();
            loot.push_str(&format!("reveal={:?};", secrets::reveal(secret)));
            let spec = format!("POST {url}\nS x-secret {secret} {{}}\n\necho");
            loot.push_str(&format!("echo={:?};", fetch_text(&spec)));
            loot.push_str(&format!(
                "hmac={:?};",
                crypto::hmac_sha256(secret, b"x").map(|m| hex(&m))
            ));
            state::set("loot", loot.as_bytes());
            log::emit(log::Level::Info, &loot, &[("loot".to_string(), loot.clone())]);
            println!("{loot}");
            messaging::send(
                &ActorRef {
                    kind: "counter".to_string(),
                    key: "sink".to_string(),
                },
                &Message {
                    name: "store".to_string(),
                    content_type: "text/plain".to_string(),
                    body: loot.clone().into_bytes(),
                    blobs: Vec::new(),
                },
            );
            Ok(loot)
        }
        "store" => {
            state::set("stored", body);
            Ok("stored".to_string())
        }
        "call" | "call-fail" => {
            let mut parts = text.split_whitespace();
            let target = parts.next().unwrap_or("counter/x");
            let name = parts.next().unwrap_or("increment");
            let comp = parts.next();
            let (kind, key) = target.split_once('/').unwrap_or(("counter", target));
            let msg = |n: &str| Message {
                name: n.to_string(),
                content_type: "text/plain".to_string(),
                body: Vec::new(),
                blobs: Vec::new(),
            };
            let to = ActorRef {
                kind: kind.to_string(),
                key: key.to_string(),
            };
            let res = messaging::call(&to, &msg(name), comp.map(msg).as_ref());
            let out = match res {
                Ok(Some(m)) => format!("reply {}", String::from_utf8_lossy(&m.body)),
                Ok(None) => "reply none".to_string(),
                Err(e) => format!("error {e:?}"),
            };
            if op == "call-fail" {
                return Err(HandlerError::Failed(format!("failing after call: {out}")));
            }
            Ok(out)
        }
        "schedule" => {
            let (head, body) = text.split_once('\n').unwrap_or((&text, ""));
            let (delay, name) = head.split_once(' ').unwrap_or(("0", "increment"));
            let id = timers::schedule(
                delay.trim().parse().unwrap_or(0),
                &Message {
                    name: name.trim().to_string(),
                    content_type: "text/plain".to_string(),
                    body: body.as_bytes().to_vec(),
                    blobs: Vec::new(),
                },
            );
            Ok(id.to_string())
        }
        "cancel" => Ok(timers::cancel(text.trim().parse().unwrap_or(0)).to_string()),
        "allow" => {
            state::set("allowed", b"1");
            Ok("allowed".to_string())
        }
        "flaky" => {
            if state::get("allowed").is_none() {
                return Err(HandlerError::Failed("not allowed yet".to_string()));
            }
            Ok(increment().to_string())
        }
        "reveal-persist" => {
            let v = secrets::reveal(text.trim())
                .map_err(|e| HandlerError::Failed(format!("reveal: {e}")))?;
            state::set("revealed", v.as_bytes());
            log::emit(log::Level::Info, &format!("revealed {v}"), &[("value".to_string(), v.clone())]);
            println!("stdout {v}");
            messaging::send(
                &ActorRef {
                    kind: "counter".to_string(),
                    key: "sink".to_string(),
                },
                &Message {
                    name: "store".to_string(),
                    content_type: "text/plain".to_string(),
                    body: v.clone().into_bytes(),
                    blobs: Vec::new(),
                },
            );
            Ok(format!("value {v}"))
        }
        // calls-tally: every increment also calls `tally` on notes/tally, a
        // message only the notes `tally` build serves; the turn fails when
        // the call does.
        "increment" if cfg!(feature = "calls-tally") => {
            let n = increment();
            let to = ActorRef {
                kind: "notes".to_string(),
                key: "tally".to_string(),
            };
            let msg = Message {
                name: "tally".to_string(),
                content_type: "text/plain".to_string(),
                body: n.to_string().into_bytes(),
                blobs: Vec::new(),
            };
            messaging::call(&to, &msg, None)
                .map_err(|e| HandlerError::Failed(format!("tally: {e:?}")))?;
            Ok(n.to_string())
        }
        "increment" => Ok(increment().to_string()),
        "get" if cfg!(feature = "fail-get") => {
            Err(HandlerError::Failed("get is broken in this build".to_string()))
        }
        "get" => Ok(counter().to_string()),
        #[cfg(feature = "fetch-extra")]
        "read" => Ok(state::get("s").map(|v| v.len()).unwrap_or(0).to_string()),
        "fanout" => {
            let n = increment();
            let count: u32 = text.trim().parse().unwrap_or(0);
            for i in 0..count {
                messaging::send(
                    &ActorRef {
                        kind: "counter".to_string(),
                        key: format!("f{i}"),
                    },
                    &Message {
                        name: "note".to_string(),
                        content_type: "text/plain".to_string(),
                        body: n.to_string().into_bytes(),
                        blobs: Vec::new(),
                    },
                );
            }
            Ok(n.to_string())
        }
        "note" => {
            state::set("last", body);
            Ok("noted".to_string())
        }
        "probe" => {
            let mut hex = String::new();
            for b in context::random_bytes(8) {
                let _ = write!(hex, "{b:02x}");
            }
            Ok(format!(
                "causal={} now={} random={} subject={:?}",
                context::causal_id(),
                context::now_ms(),
                hex,
                privacy::current_subject()
            ))
        }
        "forward" => {
            let n = increment();
            let key = String::from_utf8_lossy(body).into_owned();
            messaging::send(
                &ActorRef {
                    kind: "counter".to_string(),
                    key,
                },
                &Message {
                    name: "increment".to_string(),
                    content_type: "text/plain".to_string(),
                    body: Vec::new(),
                    blobs: Vec::new(),
                },
            );
            Ok(n.to_string())
        }
        "fail" => Err(HandlerError::Failed("deliberate failure".to_string())),
        "reject" => Err(HandlerError::Rejected("deliberate rejection".to_string())),
        "trap" => panic!("deliberate trap"),
        "spin" => {
            let limit: u64 = std::str::from_utf8(body)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(u64::MAX);
            let mut x: u64 = 0;
            let mut i = 0;
            while i < limit {
                x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(i));
                i += 1;
            }
            Ok(x.to_string())
        }
        "subject" => {
            state::set_for(Some("user:1"), "s", b"personal");
            privacy::set_subject(Some("user:2"));
            state::set("t", b"also personal");
            Ok("ok".to_string())
        }
        // Pulls in wasi:filesystem, which the deploy check must reject.
        #[cfg(feature = "fs-probe")]
        "fs" => std::fs::read_to_string("/etc/hostname")
            .map_err(|e| HandlerError::Failed(e.to_string())),
        "big" => {
            let n: usize = std::str::from_utf8(body)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            Ok("x".repeat(n))
        }
        #[cfg(feature = "wasi-http")]
        "wfetch" | "wfetch2" | "wfetch3" | "wleave" | "wstream" | "wstall" | "wdrop" => Ok(wasi_http_ops::run(op, &text)),
        other => Err(HandlerError::Rejected(format!("unknown operation {other}"))),
    }
}

#[cfg(feature = "notes")]
fn run(op: &str, body: &[u8]) -> Result<String, HandlerError> {
    use kronik::actor::sql::{self, SqlValue};
    let failed = |e: sql::SqlError| HandlerError::Failed(format!("sql: {e:?}"));
    match op {
        "add" => {
            let text = String::from_utf8_lossy(body).into_owned();
            sql::execute(
                "INSERT INTO notes(body) VALUES (?1)",
                &[SqlValue::Text(text)],
            )
            .map_err(failed)?;
            let rows = sql::query("SELECT count(*) FROM notes", &[]).map_err(failed)?;
            Ok(match rows.values.first().and_then(|r| r.first()) {
                Some(SqlValue::Integer(n)) => n.to_string(),
                _ => "?".to_string(),
            })
        }
        "count" => {
            let rows = sql::query("SELECT count(*) FROM notes", &[]).map_err(failed)?;
            Ok(match rows.values.first().and_then(|r| r.first()) {
                Some(SqlValue::Integer(n)) => n.to_string(),
                _ => "?".to_string(),
            })
        }
        "list" => {
            let rows = sql::query("SELECT body, _subject FROM notes ORDER BY id", &[])
                .map_err(failed)?;
            let mut out = String::new();
            for row in rows.values {
                if let [SqlValue::Text(b), subject] = row.as_slice() {
                    let s = match subject {
                        SqlValue::Text(s) => s.as_str(),
                        _ => "-",
                    };
                    let _ = writeln!(out, "{b} [{s}]");
                }
            }
            Ok(out)
        }
        "ddl" => {
            sql::execute("CREATE TABLE late(x)", &[]).map_err(failed)?;
            Ok("created".to_string())
        }
        "add-secret" => {
            let v = kronik::actor::secrets::reveal(String::from_utf8_lossy(body).trim())
                .map_err(|e| HandlerError::Failed(format!("reveal: {e}")))?;
            sql::execute(
                "INSERT INTO notes(body) VALUES (?1)",
                &[SqlValue::Text(format!("secret is {v}"))],
            )
            .map_err(failed)?;
            Ok("added".to_string())
        }
        // tally (with notes): a new message `tally` that records its body.
        "tally" if cfg!(feature = "tally") => {
            let text = String::from_utf8_lossy(body).into_owned();
            sql::execute(
                "INSERT INTO notes(body) VALUES (?1)",
                &[SqlValue::Text(format!("tally {text}"))],
            )
            .map_err(failed)?;
            Ok("tallied".to_string())
        }
        // sql-call: the turn's savepoint stays open across the call.
        "add-call" if cfg!(feature = "sql-call") => {
            let text = String::from_utf8_lossy(body).into_owned();
            sql::execute("INSERT INTO notes(body) VALUES (?1)", &[SqlValue::Text(text)])
                .map_err(failed)?;
            let to = ActorRef {
                kind: "counter".to_string(),
                key: "c".to_string(),
            };
            let msg = Message {
                name: "increment".to_string(),
                content_type: "text/plain".to_string(),
                body: Vec::new(),
                blobs: Vec::new(),
            };
            messaging::call(&to, &msg, None)
                .map_err(|e| HandlerError::Failed(format!("call: {e:?}")))?;
            Ok("added".to_string())
        }
        other => Err(HandlerError::Rejected(format!("unknown operation {other}"))),
    }
}

#[cfg(feature = "notes")]
fn migrate(from: u32) -> Result<(), HandlerError> {
    use kronik::actor::sql;
    if from == 0 {
        sql::execute(
            "CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT NOT NULL, \
             _subject TEXT DEFAULT (kronik_subject()))",
            &[],
        )
        .map_err(|e| HandlerError::Failed(format!("migrate: {e:?}")))?;
    }
    Ok(())
}

#[cfg(not(feature = "notes"))]
fn migrate(from: u32) -> Result<(), HandlerError> {
    if cfg!(feature = "schema1") && from == 0 {
        state::set("schema", b"1");
    }
    Ok(())
}

impl Guest for TestActor {
    fn describe() -> Manifest {
        // route-tally (M9): either kind also claims GET /tally/{key}, for the
        // route checks of a set.
        let tally = cfg!(feature = "route-tally").then(|| route("GET", "/tally/{key}"));
        #[cfg(not(feature = "notes"))]
        return Manifest {
            kind: "counter".to_string(),
            schema_version: if cfg!(feature = "schema1") { 1 } else { 0 },
            routes: [
                route("POST", "/counter/{key}/{op}"),
                route("GET", "/counter/{key}"),
            ]
            .into_iter()
            .chain(tally)
            .collect(),
            capabilities: Vec::new(),
        };
        #[cfg(feature = "notes")]
        return Manifest {
            kind: "notes".to_string(),
            schema_version: 1,
            routes: [route("POST", "/notes/{key}"), route("GET", "/notes/{key}")]
                .into_iter()
                .chain(tally)
                .collect(),
            capabilities: Vec::new(),
        };
    }

    fn handle(input: Input) -> Result<Output, HandlerError> {
        match input {
            Input::Http(req) => {
                let body = match req.body {
                    HttpBody::Inline(b) => b,
                    HttpBody::Blob(_) => Vec::new(),
                };
                if cfg!(feature = "fail-line") {
                    return Err(HandlerError::Failed(format!(
                        "line {} {}?{} {:?}",
                        req.method, req.path, req.query, req.params
                    )));
                }
                let op = match (req.method.as_str(), cfg!(feature = "notes")) {
                    ("GET", false) => "get".to_string(),
                    ("GET", true) => "list".to_string(),
                    ("POST", true) => "add".to_string(),
                    _ => req
                        .params
                        .iter()
                        .find(|(k, _)| k == "op")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default(),
                };
                #[cfg(feature = "respond")] if op == "respond" { return Ok(Output::Http(respond(&body))); } let reply = run(&op, &body)?;
                Ok(Output::Http(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: HttpBody::Inline(reply.into_bytes()),
                }))
            }
            Input::Message(incoming) => {
                let reply = run(&incoming.msg.name, &incoming.msg.body)?;
                Ok(Output::Reply(text(reply)))
            }
            Input::Timer(t) => {
                run(&t.msg.name, &t.msg.body)?;
                Ok(Output::None)
            }
            Input::Migrate(from) => {
                migrate(from)?;
                Ok(Output::None)
            }
        }
    }
}

export!(TestActor);

// `respond` (feature `respond`) answers with the HTTP response its request
// body spells out, `<status>\n<name>: <value>\n...\n\n<body>`, for the
// gateway's tests of what an actor may not set. Its hook in `handle` shares
// a line, and this code is below `export!` and compiled only with the
// feature, so the other guests keep their bytes.
#[cfg(feature = "respond")]
fn respond(body: &[u8]) -> HttpResponse {
    let text = String::from_utf8_lossy(body);
    let (head, rest) = text.split_once("\n\n").unwrap_or((text.as_ref(), ""));
    let mut lines = head.lines();
    let status = lines.next().and_then(|s| s.trim().parse().ok()).unwrap_or(200);
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(name, value)| kronik::actor::types::Header {
            name: name.to_string(),
            value: value.to_string(),
        })
        .collect();
    HttpResponse {
        status,
        headers,
        body: HttpBody::Inline(rest.as_bytes().to_vec()),
    }
}

#[cfg(feature = "wasi-http")]
mod wasi_http_ops {
    use wasip2::http::outgoing_handler;
    use wasip2::http::types::{
        ErrorCode, Fields, FutureIncomingResponse, Method, OutgoingBody, OutgoingRequest, Scheme,
    };
    use wasip2::io::poll;

    struct Started {
        future: FutureIncomingResponse,
        body: OutgoingBody,
        payload: Vec<u8>,
    }

    /// Starts a request: `handle` before any body byte is written.
    fn start(spec: &str) -> Result<Started, String> {
        let (head, body) = spec.split_once("\n\n").unwrap_or((spec, ""));
        let mut lines = head.lines();
        let first = lines.next().unwrap_or("GET http://invalid/");
        let (method, url) = first.split_once(' ').unwrap_or(("GET", first));
        let mut entries = Vec::new();
        for l in lines {
            if let Some((name, value)) = l.split_once(": ") {
                entries.push((name.to_string(), value.as_bytes().to_vec()));
            }
        }
        let headers = Fields::from_list(&entries).map_err(|e| format!("headers: {e:?}"))?;
        let req = OutgoingRequest::new(headers);
        let method = match method {
            "GET" => Method::Get,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            other => Method::Other(other.to_string()),
        };
        req.set_method(&method).map_err(|()| "method")?;
        let (scheme, rest) = url.split_once("://").ok_or("url")?;
        let scheme = if scheme == "https" { Scheme::Https } else { Scheme::Http };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        req.set_scheme(Some(&scheme)).map_err(|()| "scheme")?;
        req.set_authority(Some(authority)).map_err(|()| "authority")?;
        req.set_path_with_query(Some(path)).map_err(|()| "path")?;
        let out = req.body().map_err(|()| "body")?;
        let future = outgoing_handler::handle(req, None).map_err(|e| format!("handle: {e:?}"))?;
        Ok(Started {
            future,
            body: out,
            payload: body.as_bytes().to_vec(),
        })
    }

    /// Writes the whole body with blocking writes and finishes it.
    fn finish(s: Started) -> FutureIncomingResponse {
        {
            let stream = s.body.write().expect("body stream");
            for chunk in s.payload.chunks(4096) {
                stream.blocking_write_and_flush(chunk).expect("body write");
            }
        }
        OutgoingBody::finish(s.body, None).expect("finish");
        s.future
    }

    /// Writes the whole body with non-blocking writes (none of which drives
    /// a request) and finishes it.
    fn finish_quietly(s: Started) -> Result<FutureIncomingResponse, String> {
        {
            let stream = s.body.write().map_err(|()| "body stream")?;
            let mut rest = &s.payload[..];
            while !rest.is_empty() {
                let n = stream.check_write().map_err(|e| format!("check-write: {e:?}"))? as usize;
                let n = n.min(rest.len()).max(1);
                stream.write(&rest[..n]).map_err(|e| format!("write: {e:?}"))?;
                rest = &rest[n..];
            }
        }
        OutgoingBody::finish(s.body, None).map_err(|e| format!("finish: {e:?}"))?;
        Ok(s.future)
    }

    fn answer(future: &FutureIncomingResponse) -> String {
        match future.get() {
            None => "not ready".to_string(),
            Some(Err(())) => "taken".to_string(),
            Some(Ok(Err(e))) => format!("error {}", code(&e)),
            Some(Ok(Ok(resp))) => {
                let status = resp.status();
                let body = resp.consume().expect("consume");
                let mut bytes = Vec::new();
                {
                    let stream = body.stream().expect("stream");
                    while let Ok(chunk) = stream.blocking_read(65536) {
                        bytes.extend_from_slice(&chunk);
                    }
                }
                format!("{status} {}", String::from_utf8_lossy(&bytes))
            }
        }
    }

    fn code(e: &ErrorCode) -> String {
        match e {
            ErrorCode::InternalError(Some(m)) => format!("internal-error({m})"),
            other => format!("{other:?}"),
        }
    }

    fn wait(future: FutureIncomingResponse) -> String {
        future.subscribe().block();
        answer(&future)
    }

    pub fn run(op: &str, text: &str) -> String {
        let r = (|| -> Result<String, String> {
            match op {
                "wfetch" => {
                    let first = wait(finish(start(text)?));
                    if !cfg!(feature = "fetch-extra") {
                        return Ok(first);
                    }
                    // As fetch-ok in fetch-extra: also GET <url>/extra.
                    let url = text.lines().next().and_then(|l| l.split_whitespace().nth(1));
                    let extra = wait(finish(start(&format!("GET {}/extra", url.unwrap_or("")))?));
                    Ok(format!("{first} | {extra}"))
                }
                "wfetch2" => {
                    let (a, b) = text.split_once("\n---\n").unwrap_or((text, ""));
                    let a = start(a)?;
                    let b = finish(start(b)?);
                    let (pa, pb) = (a.future.subscribe(), b.subscribe());
                    let first = poll::poll(&[&pa, &pb]);
                    drop(pa);
                    let a = finish(a);
                    let pa = a.subscribe();
                    let second = poll::poll(&[&pa, &pb]);
                    drop((pa, pb));
                    Ok(format!(
                        "ready {first:?} then {second:?}: {} | {}",
                        answer(&a),
                        answer(&b)
                    ))
                }
                "wfetch3" => {
                    let (a, b) = text.split_once("\n---\n").unwrap_or((text, ""));
                    let (a, b) = (start(a)?, start(b)?);
                    let (a, b) = (finish_quietly(a)?, finish_quietly(b)?);
                    let (pa, pb) = (a.subscribe(), b.subscribe());
                    let first = poll::poll(&[&pa, &pb]);
                    drop((pa, pb));
                    Ok(format!("ready {first:?}: {} | {}", answer(&a), answer(&b)))
                }
                "wleave" => {
                    let future = finish_quietly(start(text)?)?;
                    // Kept until the turn ends, never waited for.
                    std::mem::forget(future);
                    Ok("left".into())
                }
                "wstream" => {
                    let s = start(text)?;
                    {
                        let stream = s.body.write().map_err(|()| "body stream")?;
                        for byte in &s.payload {
                            loop {
                                match stream.check_write() {
                                    Ok(0) => {
                                        let p = stream.subscribe();
                                        poll::poll(&[&p]);
                                    }
                                    Ok(_) => break,
                                    Err(e) => return Err(format!("check-write: {e:?}")),
                                }
                            }
                            stream.write(&[*byte]).map_err(|e| format!("write: {e:?}"))?;
                        }
                    }
                    OutgoingBody::finish(s.body, None).map_err(|e| format!("finish: {e:?}"))?;
                    Ok(wait(s.future))
                }
                "wstall" => {
                    let s = start(text)?;
                    let _body = s.body;
                    Ok(wait(s.future))
                }
                "wdrop" => {
                    let (a, b) = text.split_once("\n---\n").unwrap_or((text, ""));
                    drop(finish(start(a)?));
                    Ok(wait(finish(start(b)?)))
                }
                _ => Err("unknown".into()),
            }
        })();
        r.unwrap_or_else(|e| format!("guest error {e}"))
    }
}
