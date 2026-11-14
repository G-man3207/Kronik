// The room (see lib.rs).

use std::fmt::Write as _;

wit_bindgen::generate!({
    world: "actor-connections",
    path: "../../../wit/kronik-actor.wit",
});

use exports::kronik::actor::connection_handler::Guest as ConnectionGuest;
use exports::kronik::actor::handler::Guest;
use kronik::actor::connections::{
    self, Accept, CloseInitiator, Closed, Frame, IncomingFrame, OpenReply, OpenRequest, Protocol,
    SendError, SseEvent,
};
use kronik::actor::types::{
    ActorRef, HandlerError, Header, HttpBody, HttpResponse, Input, Manifest, Message, Output, Route,
};
use kronik::actor::{context, messaging, state};

struct Room;

fn route(method: &str, pattern: &str) -> Route {
    Route {
        method: method.to_string(),
        pattern: pattern.to_string(),
    }
}

fn message(name: &str, body: &str) -> Message {
    Message {
        name: name.to_string(),
        content_type: "text/plain".to_string(),
        body: body.as_bytes().to_vec(),
        blobs: Vec::new(),
    }
}

fn get_text(key: &str) -> Option<String> {
    state::get(key).map(|v| String::from_utf8_lossy(&v).into_owned())
}

fn get_u64(key: &str) -> u64 {
    get_text(key).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The value of `name` in a query string `a=1&b=2` (no decoding).
fn query_value<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
}

/// The members' connection ids, in id order.
fn members() -> Vec<String> {
    state::keys("member/")
        .into_iter()
        .filter_map(|k| k.strip_prefix("member/").map(str::to_string))
        .collect()
}

fn member_user(conn: &str) -> Option<String> {
    get_text(&format!("member/{conn}")).map(|m| m.split(' ').next().unwrap_or("").to_string())
}

fn message_frame(seq: u64, user: &str, text: &str) -> Frame {
    let field = if cfg!(feature = "fmt2") { "body" } else { "text" };
    Frame::Event(SseEvent {
        event: "message".to_string(),
        id: seq.to_string(),
        data: format!(
            "{{\"type\":\"message\",\"seq\":{seq},\"user\":{},\"{field}\":{}}}",
            json_str(user),
            json_str(text)
        ),
    })
}

/// Stores a message under the next room seq and broadcasts it.
fn say(user: &str, text: &str) -> u64 {
    let seq = get_u64("seq") + 1;
    state::set("seq", seq.to_string().as_bytes());
    state::set(&format!("msg/{seq:020}"), format!("{user} {text}").as_bytes());
    connections::broadcast(&members(), &message_frame(seq, user, text));
    seq
}

/// The stored messages after `after`, at most 100, oldest first.
fn messages_after(after: u64) -> Vec<(u64, String, String)> {
    state::keys("msg/")
        .into_iter()
        .filter_map(|k| {
            let seq: u64 = k.strip_prefix("msg/")?.parse().ok()?;
            (seq > after).then_some((seq, k))
        })
        .take(100)
        .filter_map(|(seq, k)| {
            let m = get_text(&k)?;
            let (user, text) = m.split_once(' ').unwrap_or((m.as_str(), ""));
            Some((seq, user.to_string(), text.to_string()))
        })
        .collect()
}

fn stream(conn: &str, n: u32, safe: bool) -> Result<(), HandlerError> {
    for i in 0..n {
        match connections::send_now(conn, &Frame::Text(format!("tok {i}"))) {
            Ok(()) => {}
            Err(SendError::Closed) => break,
            Err(SendError::Denied(m)) => {
                connections::send(conn, &Frame::Text(format!("denied {m}")));
                return Ok(());
            }
            Err(SendError::OutcomeUnknown) => {
                if !safe {
                    return Err(HandlerError::Failed(
                        "send-now: the outcome is unknown".to_string(),
                    ));
                }
                let unknown = get_u64("unknown") + 1;
                state::set("unknown", unknown.to_string().as_bytes());
                break;
            }
        }
    }
    connections::send(conn, &Frame::Text(format!("done {n}")));
    Ok(())
}

/// The answers of `GET /room/{key}/{op}` and the operator messages.
fn query(op: &str, arg: &str) -> Result<String, HandlerError> {
    let mut out = String::new();
    match op {
        "members" => {
            for conn in members() {
                let m = get_text(&format!("member/{conn}")).unwrap_or_default();
                let _ = writeln!(out, "{conn} {m}");
            }
        }
        "closes" => {
            for k in state::keys("close/") {
                let v = get_text(&k).unwrap_or_default();
                let _ = writeln!(out, "{} {v}", k.trim_start_matches("close/"));
            }
        }
        "unknown" => out = get_u64("unknown").to_string(),
        "seq" => out = get_u64("seq").to_string(),
        "messages" => {
            let after = query_value(arg, "after").and_then(|v| v.parse().ok()).unwrap_or(0);
            for (seq, user, text) in messages_after(after) {
                let _ = writeln!(out, "{seq} {user} {text}");
            }
        }
        other => return Err(HandlerError::Rejected(format!("unknown operation {other}"))),
    }
    Ok(out)
}

impl Guest for Room {
    fn describe() -> Manifest {
        Manifest {
            kind: "room".to_string(),
            schema_version: 0,
            routes: vec![
                route("WEBSOCKET", "/room/{key}/ws"),
                route("SSE", "/room/{key}/events"),
                route("GET", "/room/{key}/{op}"),
                route("POST", "/room/{key}/say"),
            ],
            capabilities: vec!["connection:send-now".to_string()],
        }
    }

    fn handle(input: Input) -> Result<Output, HandlerError> {
        match input {
            Input::Http(req) => {
                let body = match req.body {
                    HttpBody::Inline(b) => b,
                    HttpBody::Blob(_) => Vec::new(),
                };
                let reply = if req.method == "POST" {
                    say("http", &String::from_utf8_lossy(&body)).to_string()
                } else {
                    let op = req
                        .params
                        .iter()
                        .find(|(k, _)| k == "op")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    query(&op, &req.query)?
                };
                Ok(Output::Http(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: HttpBody::Inline(reply.into_bytes()),
                }))
            }
            Input::Message(incoming) => {
                let body = String::from_utf8_lossy(&incoming.msg.body).into_owned();
                let reply = match incoming.msg.name.as_str() {
                    "ping" => "pong".to_string(),
                    "say" => say("op", &body).to_string(),
                    "kick" => {
                        connections::close(body.trim(), 4000, "kicked");
                        "kicked".to_string()
                    }
                    "spray" => {
                        let n: u64 = body.trim().parse().unwrap_or(1);
                        let ids: Vec<String> = (0..n).map(|i| format!("c-{i:032x}")).collect();
                        connections::broadcast(&ids, &Frame::Text("x".to_string()));
                        "sprayed".to_string()
                    }
                    other => query(other, &body)?,
                };
                Ok(Output::Reply(message("reply", &reply)))
            }
            Input::Timer(_) | Input::Migrate(_) => Ok(Output::None),
        }
    }
}

impl ConnectionGuest for Room {
    fn open(req: OpenRequest) -> Result<OpenReply, HandlerError> {
        let q = req.request.query.clone();
        if query_value(&q, "fail") == Some("1") {
            return Err(HandlerError::Failed("the open failed on request".to_string()));
        }
        if query_value(&q, "deny") == Some("1") {
            return Ok(OpenReply::Refuse(HttpResponse {
                status: 403,
                headers: Vec::new(),
                body: HttpBody::Inline(b"denied".to_vec()),
            }));
        }
        if query_value(&q, "call") == Some("1") {
            let callee = ActorRef {
                kind: "room".to_string(),
                key: "callee".to_string(),
            };
            messaging::call(&callee, &message("ping", ""), None)
                .map_err(|e| HandlerError::Failed(format!("call: {e:?}")))?;
        }
        if query_value(&q, "now") == Some("1") {
            // The connection opens when this turn commits: the host traps.
            let _ = connections::send_now(&req.connection, &Frame::Text("early".to_string()));
        }
        let user = query_value(&q, "user").unwrap_or("anon").to_string();
        let others = members();
        let proto = match req.protocol {
            Protocol::Websocket => "ws",
            Protocol::Sse => "sse",
        };
        state::set(
            &format!("member/{}", req.connection),
            format!("{user} {proto}").as_bytes(),
        );
        match req.protocol {
            Protocol::Websocket => {
                let welcome = format!(
                    "{{\"type\":\"welcome\",\"connection\":{},\"members\":{},\"last\":{}}}",
                    json_str(&req.connection),
                    others.len() + 1,
                    get_u64("seq")
                );
                connections::send(&req.connection, &Frame::Text(welcome));
            }
            Protocol::Sse => {
                let after = req
                    .request
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("last-event-id"))
                    .and_then(|h| h.value.trim().parse().ok())
                    .unwrap_or(0);
                for (seq, user, text) in messages_after(after) {
                    connections::send(&req.connection, &message_frame(seq, &user, &text));
                }
            }
        }
        if !others.is_empty() {
            let joined = format!("{{\"type\":\"joined\",\"user\":{}}}", json_str(&user));
            connections::broadcast(&others, &Frame::Text(joined));
        }
        // `pick=last` selects the last offered subprotocol, whatever it is
        // (the token tests: browsers put bearer tokens there).
        let subprotocol = if query_value(&q, "pick") == Some("last") {
            req.subprotocols.last().cloned()
        } else {
            req.subprotocols.iter().find(|p| *p == "room.v1").cloned()
        };
        let mut headers = vec![Header {
            name: "x-room".to_string(),
            value: context::self_ref().key,
        }];
        // `headers=<n>`: as many more (the host bounds them).
        for i in 0..query_value(&q, "headers")
            .and_then(|n| n.parse::<u32>().ok())
            .unwrap_or(0)
        {
            headers.push(Header {
                name: format!("x-h{i}"),
                value: "v".to_string(),
            });
        }
        Ok(OpenReply::Accept(Accept {
            subprotocol,
            headers,
            subject: query_value(&q, "user").map(|u| format!("user:{u}")),
        }))
    }

    fn frame(event: IncomingFrame) -> Result<(), HandlerError> {
        let conn = event.connection;
        let text = match event.frame {
            Frame::Text(t) => t,
            Frame::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
            Frame::Event(e) => e.data,
        };
        let (cmd, arg) = text.split_once(' ').unwrap_or((text.as_str(), ""));
        match cmd {
            "say" => {
                let user = member_user(&conn).unwrap_or_else(|| "?".to_string());
                say(&user, arg);
            }
            "echo" => connections::send(&conn, &Frame::Text(arg.to_string())),
            "binary" => connections::send(&conn, &Frame::Binary(arg.as_bytes().to_vec())),
            "stream" | "stream-safe" => {
                let n = arg.trim().parse().unwrap_or(1);
                stream(&conn, n, cmd == "stream-safe")?;
            }
            "kick" => connections::close(arg.trim(), 4000, "kicked"),
            "bye" => connections::close(&conn, 1000, "bye"),
            "burst" => {
                let (n, size) = arg.split_once(' ').unwrap_or((arg, "1"));
                let size: usize = size.trim().parse().unwrap_or(1);
                for i in 0..n.trim().parse::<u64>().unwrap_or(1) {
                    connections::send(&conn, &Frame::Text(format!("{i:0>size$}")));
                }
            }
            "send-to" => {
                let (to, rest) = arg.split_once(' ').unwrap_or((arg, ""));
                connections::send(to, &Frame::Text(rest.to_string()));
            }
            "now-to" => {
                let (to, rest) = arg.split_once(' ').unwrap_or((arg, ""));
                let answer = match connections::send_now(to, &Frame::Text(rest.to_string())) {
                    Ok(()) => "now ok".to_string(),
                    Err(SendError::Closed) => "now closed".to_string(),
                    Err(SendError::OutcomeUnknown) => "now unknown".to_string(),
                    Err(SendError::Denied(m)) => format!("now denied {m}"),
                };
                connections::send(&conn, &Frame::Text(answer));
            }
            "fail" => return Err(HandlerError::Failed("the frame failed on request".to_string())),
            "trap" => panic!("the frame trapped on request"),
            other => connections::send(&conn, &Frame::Text(format!("unknown {other}"))),
        }
        Ok(())
    }

    fn close(event: Closed) -> Result<(), HandlerError> {
        let initiator = match event.info.initiator {
            CloseInitiator::Client => "client",
            CloseInitiator::Actor => "actor",
            CloseInitiator::Host => "host",
        };
        state::set(
            &format!("close/{}", event.connection),
            format!("{initiator} {} {}", event.info.code, event.info.reason).as_bytes(),
        );
        let user = member_user(&event.connection);
        state::delete(&format!("member/{}", event.connection));
        let rest = members();
        if let Some(user) = user
            && !rest.is_empty()
        {
            let left = format!("{{\"type\":\"left\",\"user\":{}}}", json_str(&user));
            connections::broadcast(&rest, &Frame::Text(left));
        }
        Ok(())
    }
}

export!(Room);
