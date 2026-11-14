//! The JSON lines that `kronik test-host` reads and writes: one request
//! object per line in, one response object per line out.
//!
//! Requests carry an `op`:
//!
//! - `{"op": "http", "method", "path", "headers": [[name, value]], "body" |
//!   "body_base64"}`: through the gateway. Answer: `status`, `headers`,
//!   `body` (if UTF-8) or `body_base64`, and `turn`, the turn's id.
//! - `{"op": "api", "method", "path", "query", "body": <JSON>}`: the daemon's
//!   API (crates/kronik-api), as `kronik` uses it over the socket. Answer:
//!   `status` and `body`.
//! - `{"op": "advance", "ms"}`: moves the clock and runs the timers that
//!   came due. Answer: `now_ms`.
//! - `{"op": "stub", "url", "method", "status", "headers", "body" |
//!   "body_base64", "error": "connect" | "io", "times"}`: an answer for the
//!   outgoing requests whose URL starts with `url`; the newest match wins.
//! - `{"op": "requests", "clear": bool}`: the outgoing requests so far.
//! - `{"op": "settle"}`: waits until the node is idle.
//!
//! The test plays the client of a long-lived connection (M24) with:
//!
//! - `{"op": "open-connection", "path", "headers": [[name, value]],
//!   "protocol": "websocket" | "sse"}`: a WebSocket upgrade (the default;
//!   the host adds the handshake headers the test leaves out) or an event
//!   stream's GET, through the gateway. Answer: `connection`, the id when
//!   the actor accepted (else null), and the handshake's response as for
//!   `http`: `status` (101 or 200 when accepted), `headers`, `body` or
//!   `body_base64`, and `turn`, the open turn's id.
//! - `{"op": "send-frame", "connection", "body" | "body_base64"}`: a text
//!   frame (`body`) or a binary frame (`body_base64`) from the client.
//! - `{"op": "close-connection", "connection", "initiator", "code", "reason",
//!   "cause"}`: the `client` closes with `code` (default 1000; 1006: it goes
//!   away without a close frame) and `reason`, or the `host` closes for a
//!   `cause` (`restart`, `ping-timeout`, `too-large`, `slow-consumer`,
//!   `protocol`, `operator`, `unavailable`).
//! - `{"op": "frames-sent", "connection", "clear": bool}`: what the actor
//!   sent on the connection since the last `clear`. Answer: `frames`, each
//!   with `seq`, `kind` (`text`, `binary` or `event`), `body` or
//!   `body_base64`, and an event's `event` and `id`; and `closed`, the close
//!   the connection got (`code` and `reason`), or null.
//!
//! Every answer has `"ok": true`, or `"ok": false` and an `error`. After a
//! request that can start turns, the host settles before it answers, so the
//! messages and timers those turns caused have been handled.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kronik_gateway::{HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use kronik_proto::connection as conn;
use kronik_proto::log::v1 as pb;

use crate::{CloseBy, Error, Stub, TestHost};

/// A body on the wire: UTF-8 text in `body`, or any bytes in `body_base64`,
/// which wins if both are given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    #[serde(rename = "body", default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(
        rename = "body_base64",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub base64: Option<String>,
}

impl Body {
    /// Text if the bytes are UTF-8, else base64.
    pub fn from_bytes(bytes: &[u8]) -> Body {
        match std::str::from_utf8(bytes) {
            Ok(text) => Body {
                text: Some(text.to_string()),
                base64: None,
            },
            Err(_) => Body {
                text: None,
                base64: Some(STANDARD.encode(bytes)),
            },
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        match (&self.base64, &self.text) {
            (Some(b), _) => STANDARD.decode(b).map_err(|e| format!("body_base64: {e}")),
            (None, Some(t)) => Ok(t.as_bytes().to_vec()),
            (None, None) => Ok(Vec::new()),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Http {
        method: String,
        path: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        body_base64: Option<String>,
    },
    Api {
        method: String,
        path: String,
        #[serde(default)]
        query: String,
        #[serde(default)]
        body: Option<Value>,
    },
    Advance {
        ms: u64,
    },
    Stub(Stub),
    Requests {
        #[serde(default)]
        clear: bool,
    },
    Settle,
    OpenConnection {
        path: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
        #[serde(default = "websocket")]
        protocol: String,
    },
    SendFrame {
        connection: String,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        body_base64: Option<String>,
    },
    CloseConnection {
        connection: String,
        initiator: String,
        #[serde(default)]
        code: Option<u16>,
        #[serde(default)]
        reason: String,
        #[serde(default)]
        cause: Option<String>,
    },
    FramesSent {
        connection: String,
        #[serde(default)]
        clear: bool,
    },
}

fn websocket() -> String {
    "websocket".into()
}

/// A response as `http` and `open-connection` answer it: the status, the
/// headers, the body and the turn's id.
fn response_json(res: &HttpResponse) -> Result<Value, Error> {
    let turn = res
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("kronik-turn-id"))
        .map(|(_, v)| v.clone());
    let mut out =
        serde_json::to_value(Body::from_bytes(&res.body)).map_err(|e| Error::new("body", e))?;
    out["status"] = json!(res.status);
    out["headers"] = json!(res.headers);
    out["turn"] = json!(turn);
    Ok(out)
}

/// A client's frame: text from `body`, binary from `body_base64`.
fn client_frame(body: Option<String>, body_base64: Option<String>) -> Result<pb::Frame, Error> {
    let (kind, bytes) = match (body_base64, body) {
        (Some(b), None) => (
            pb::frame::Kind::Binary,
            STANDARD
                .decode(b)
                .map_err(|e| Error(format!("body_base64: {e}")))?,
        ),
        (None, Some(text)) => (pb::frame::Kind::Text, text.into_bytes()),
        _ => {
            return Err(Error(
                "a frame is text in `body` or binary in `body_base64`, not both".into(),
            ));
        }
    };
    Ok(pb::Frame {
        kind: kind as i32,
        // The hub tags it with the connection's subject.
        data: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(bytes)),
        }),
        ..Default::default()
    })
}

/// A frame the actor sent, as `frames-sent` answers it.
fn frame_json(seq: u64, frame: &pb::Frame) -> Result<Value, Error> {
    let data = match frame.data.as_ref().and_then(|d| d.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.as_slice(),
        Some(pb::sealable::Value::Sealed(_)) => {
            return Err(Error("a frame's data is sealed".into()));
        }
        None => &[],
    };
    let kind = conn::frame_kind_name(frame.kind);
    let mut out = if kind == "binary" {
        json!({ "body_base64": STANDARD.encode(data) })
    } else {
        serde_json::to_value(Body::from_bytes(data)).map_err(|e| Error::new("frame", e))?
    };
    out["seq"] = json!(seq);
    out["kind"] = json!(kind);
    if kind == "event" {
        out["event"] = json!(frame.event);
        out["id"] = json!(frame.id);
    }
    Ok(out)
}

impl TestHost {
    /// Handles one request line and returns the response line.
    pub async fn handle_line(&self, line: &str) -> String {
        let answer = match serde_json::from_str::<Request>(line) {
            Ok(req) => self.handle(req).await,
            Err(e) => Err(Error(format!("invalid request: {e}"))),
        };
        match answer {
            Ok(mut v) => {
                v["ok"] = Value::Bool(true);
                v.to_string()
            }
            Err(e) => json!({ "ok": false, "error": e.to_string() }).to_string(),
        }
    }

    async fn handle(&self, req: Request) -> Result<Value, Error> {
        match req {
            Request::Http {
                method,
                path,
                headers,
                body,
                body_base64,
            } => {
                let body = Body {
                    text: body,
                    base64: body_base64,
                }
                .to_bytes()
                .map_err(Error)?;
                let (path, query) = path.split_once('?').unwrap_or((&path, ""));
                let res = self
                    .http(HttpRequest {
                        method,
                        path: path.to_string(),
                        query: query.to_string(),
                        headers,
                        body,
                        peer: None,
                    })
                    .await;
                self.settle().await?;
                response_json(&res)
            }
            Request::Api {
                method,
                path,
                query,
                body,
            } => {
                let body = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
                let res = self.api(&method, &path, &query, body).await;
                if method != "GET" {
                    self.settle().await?;
                }
                let body = serde_json::from_slice::<Value>(&res.body).unwrap_or_else(|_| {
                    Value::String(String::from_utf8_lossy(&res.body).into_owned())
                });
                Ok(json!({ "status": res.status, "body": body }))
            }
            Request::Advance { ms } => {
                self.advance(Duration::from_millis(ms)).await?;
                Ok(json!({ "now_ms": self.now_ms() }))
            }
            Request::Stub(stub) => {
                stub.body.to_bytes().map_err(Error)?;
                self.stub(stub);
                Ok(json!({}))
            }
            Request::Requests { clear } => Ok(json!({ "requests": self.requests(clear) })),
            Request::Settle => {
                self.settle().await?;
                Ok(json!({}))
            }
            Request::OpenConnection {
                path,
                headers,
                protocol,
            } => {
                let answer = self.open_connection(&path, headers, &protocol).await?;
                let mut out = response_json(&answer.response)?;
                out["connection"] = json!(answer.connection);
                Ok(out)
            }
            Request::SendFrame {
                connection,
                body,
                body_base64,
            } => {
                self.send_frame(&connection, client_frame(body, body_base64)?)
                    .await?;
                Ok(json!({}))
            }
            Request::CloseConnection {
                connection,
                initiator,
                code,
                reason,
                cause,
            } => {
                let by =
                    CloseBy::parse(&initiator, code, reason, cause.as_deref()).map_err(Error)?;
                self.close_connection(&connection, by).await?;
                Ok(json!({}))
            }
            Request::FramesSent { connection, clear } => {
                let sent = self.frames_sent(&connection, clear)?;
                let frames = sent
                    .frames
                    .iter()
                    .map(|(seq, f)| frame_json(*seq, f))
                    .collect::<Result<Vec<_>, _>>()?;
                let closed = sent
                    .closed
                    .map(|(code, reason)| json!({ "code": code, "reason": reason }));
                Ok(json!({ "frames": frames, "closed": closed }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_are_text_when_they_can_be() {
        assert_eq!(Body::from_bytes(b"hi").text.as_deref(), Some("hi"));
        let bin = Body::from_bytes(&[0xff, 0]);
        assert_eq!(bin.base64.as_deref(), Some("/wA="));
        assert_eq!(bin.to_bytes().unwrap(), [0xff, 0]);
        assert_eq!(Body::default().to_bytes().unwrap(), b"");
    }

    #[test]
    fn requests_parse() {
        let req: Request = serde_json::from_str(
            r#"{"op": "stub", "url": "https://x/", "status": 500, "times": 2}"#,
        )
        .unwrap();
        assert!(matches!(
            req,
            Request::Stub(Stub {
                status: 500,
                times: Some(2),
                ..
            })
        ));
        assert!(
            serde_json::from_str::<Request>(r#"{"op": "advance", "ms": 5, "extra": 1}"#).is_err()
        );
        assert!(matches!(
            serde_json::from_str(r#"{"op": "settle"}"#).unwrap(),
            Request::Settle
        ));
        assert!(matches!(
            serde_json::from_str(r#"{"op": "close-connection", "connection": "c-1", "initiator": "host", "cause": "restart"}"#).unwrap(),
            Request::CloseConnection { code: None, .. }
        ));
        assert!(matches!(
            serde_json::from_str(r#"{"op": "frames-sent", "connection": "c-1"}"#).unwrap(),
            Request::FramesSent { clear: false, .. }
        ));
    }

    #[test]
    fn frames_go_both_ways() {
        let text = client_frame(Some("hi".into()), None).unwrap();
        assert_eq!(text.kind, pb::frame::Kind::Text as i32);
        let binary = client_frame(None, Some("/wA=".into())).unwrap();
        assert_eq!(binary.kind, pb::frame::Kind::Binary as i32);
        assert!(client_frame(None, None).is_err());
        assert!(client_frame(Some("a".into()), Some("YQ==".into())).is_err());
        assert!(client_frame(None, Some("not base64!".into())).is_err());

        assert_eq!(
            frame_json(3, &text).unwrap(),
            json!({ "seq": 3, "kind": "text", "body": "hi" })
        );
        assert_eq!(
            frame_json(4, &binary).unwrap(),
            json!({ "seq": 4, "kind": "binary", "body_base64": "/wA=" })
        );
        let event = pb::Frame {
            kind: pb::frame::Kind::Event as i32,
            event: "message".into(),
            id: "7".into(),
            ..text
        };
        assert_eq!(
            frame_json(5, &event).unwrap(),
            json!({ "seq": 5, "kind": "event", "body": "hi", "event": "message", "id": "7" })
        );
    }
}
