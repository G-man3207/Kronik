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
//! Every answer has `"ok": true`, or `"ok": false` and an `error`. After a
//! request that can start turns, the host settles before it answers, so the
//! messages and timers those turns caused have been handled.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kronik_gateway::HttpRequest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Error, Stub, TestHost};

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
                let turn = res
                    .headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("kronik-turn-id"))
                    .map(|(_, v)| v.clone());
                let mut out = serde_json::to_value(Body::from_bytes(&res.body))
                    .map_err(|e| Error::new("body", e))?;
                out["status"] = json!(res.status);
                out["headers"] = json!(res.headers);
                out["turn"] = json!(turn);
                Ok(out)
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
    }
}
