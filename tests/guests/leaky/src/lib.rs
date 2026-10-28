//! Test guest (kind `leaky`, from the v0.1 security review): reveals a secret, then moves the value
//! through paths the production scrubber may not cover.
wit_bindgen::generate!({
    world: "actor",
    path: "../../../wit/kronik-actor.wit",
});

use exports::kronik::actor::handler::Guest;
use kronik::actor::types::{ActorRef, HandlerError, HttpBody, Input, Manifest, Message, Output};
use kronik::actor::{http_client, log, messaging, secrets, sql, state};

struct Leaky;

fn msg(name: &str, body: &[u8]) -> Message {
    Message { name: name.to_string(), content_type: "text/plain".to_string(), body: body.to_vec(), blobs: Vec::new() }
}

fn actor(target: &str) -> ActorRef {
    let (kind, key) = target.split_once('/').unwrap_or(("leaky", target));
    ActorRef { kind: kind.to_string(), key: key.to_string() }
}

fn reveal(name: &str) -> Result<String, HandlerError> {
    secrets::reveal(name).map_err(|e| HandlerError::Failed(format!("reveal: {e}")))
}

fn run(op: &str, body: &[u8]) -> Result<String, HandlerError> {
    let text = String::from_utf8_lossy(body).into_owned();
    let mut args = text.split_whitespace();
    let a = args.next().unwrap_or("").to_string();
    let b = args.next().unwrap_or("").to_string();
    match op {
        // a = secret, b = url: the value in the query, a text header and the body.
        "reveal-fetch" => {
            let v = reveal(&a)?;
            let req = http_client::Request {
                method: "POST".to_string(),
                url: format!("{b}?key={v}"),
                headers: vec![http_client::RequestHeader {
                    name: "x-api-key".to_string(),
                    value: http_client::HeaderValue::Text(v.clone()),
                }],
                body: HttpBody::Inline(format!("{{\"client_secret\":\"{v}\"}}").into_bytes()),
            };
            Ok(match http_client::fetch(&req) {
                Ok(r) => format!("status {}", r.status),
                Err(e) => format!("fetch error {e:?}"),
            })
        }
        // a = secret, then three URLs: the value goes to an echo server (b);
        // the next request (c) depends on the length of its answer; the last
        // (d) may hang, so a test can kill the daemon mid-turn.
        "reveal-echo-len" => {
            let v = reveal(&a)?;
            let rest: Vec<String> = text.split_whitespace().skip(2).map(str::to_string).collect();
            let get = |url: String| http_client::Request {
                method: "GET".to_string(),
                url,
                headers: Vec::new(),
                body: HttpBody::Inline(Vec::new()),
            };
            let first = http_client::fetch(&http_client::Request {
                method: "POST".to_string(),
                url: format!("{b}?key={v}"),
                headers: vec![http_client::RequestHeader {
                    name: "x-api-key".to_string(),
                    value: http_client::HeaderValue::Text(v.clone()),
                }],
                body: HttpBody::Inline(v.clone().into_bytes()),
            })
            .map_err(|e| HandlerError::Failed(format!("echo: {e:?}")))?;
            let len = match &first.body {
                HttpBody::Inline(b) => b.len(),
                HttpBody::Blob(_) => 0,
            } + first.headers.iter().map(|(n, v)| n.len() + v.len()).sum::<usize>();
            let next = rest.first().cloned().unwrap_or_default();
            let last = rest.get(1).cloned().unwrap_or_default();
            http_client::fetch(&get(format!("{next}?len={len}")))
                .map_err(|e| HandlerError::Failed(format!("next: {e:?}")))?;
            let r = http_client::fetch(&get(last))
                .map_err(|e| HandlerError::Failed(format!("last: {e:?}")))?;
            Ok(format!("done {} len {len}", r.status))
        }
        // a = secret, b = kind/key: hands the value to another actor with call.
        "reveal-call" => {
            let v = reveal(&a)?;
            match messaging::call(&actor(&b), &msg("keep", v.as_bytes()), None) {
                Ok(_) => Ok("called".to_string()),
                Err(e) => Ok(format!("call error {e:?}")),
            }
        }
        // a = secret, b = kind/key: a compensation carrying the value, then fail.
        "reveal-comp" => {
            let v = reveal(&a)?;
            let _ = messaging::call(&actor(&b), &msg("keep", b"plain"), Some(&msg("undo", v.as_bytes())));
            Err(HandlerError::Failed("failing after the call".to_string()))
        }
        // a = secret: the value as an SQL BLOB and as a text cell.
        "reveal-blob" => {
            let v = reveal(&a)?;
            sql::execute("INSERT INTO t(txt, b) VALUES (?1, ?2)", &[sql::SqlValue::Text(format!("t:{v}")), sql::SqlValue::Blob(v.clone().into_bytes())])
                .map_err(|e| HandlerError::Failed(format!("sql: {e:?}")))?;
            Ok("inserted".to_string())
        }
        // a = secret: the value inside a state key.
        "reveal-key" => {
            let v = reveal(&a)?;
            state::set(&format!("cache/{v}"), b"1");
            Ok("keyed".to_string())
        }
        // Callee side: keeps, logs and echoes whatever it got.
        "keep" => {
            state::set("kept", body);
            log::emit(log::Level::Info, &format!("kept {text}"), &[]);
            Ok(format!("kept {text}"))
        }
        "undo" => {
            state::set("undone", body);
            Ok("undone".to_string())
        }
        other => Err(HandlerError::Rejected(format!("unknown operation {other}"))),
    }
}

impl Guest for Leaky {
    fn describe() -> Manifest {
        Manifest { kind: "leaky".to_string(), schema_version: 1, routes: Vec::new(), capabilities: Vec::new() }
    }

    fn handle(input: Input) -> Result<Output, HandlerError> {
        match input {
            Input::Message(m) => {
                let reply = run(&m.msg.name, &m.msg.body)?;
                Ok(Output::Reply(msg("reply", reply.as_bytes())))
            }
            Input::Migrate(from) => {
                if from == 0 {
                    sql::execute("CREATE TABLE t(id INTEGER PRIMARY KEY, txt TEXT, b BLOB)", &[])
                        .map_err(|e| HandlerError::Failed(format!("migrate: {e:?}")))?;
                }
                Ok(Output::None)
            }
            _ => Ok(Output::None),
        }
    }
}

export!(Leaky);
