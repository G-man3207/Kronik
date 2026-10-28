//! Outgoing HTTP for tests: answers from stubs, every request recorded.

use std::sync::{Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use kronik_core::env::{BoxFuture, HttpRequest, HttpResponse, Net, NetError};
use serde::{Deserialize, Serialize};

use crate::protocol::Body;

/// How a stub fails instead of answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StubFailure {
    /// The request was not sent (connection refused): safe to retry.
    Connect,
    /// The request may have reached the target; the outcome is unknown.
    Io,
}

/// An answer for the requests whose URL starts with `url`.
#[derive(Debug, Clone, Deserialize)]
pub struct Stub {
    /// Only requests with this method; any method if absent.
    #[serde(default)]
    pub method: Option<String>,
    pub url: String,
    #[serde(default = "Stub::default_status")]
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(flatten)]
    pub body: Body,
    /// Fail instead of answering.
    #[serde(default)]
    pub error: Option<StubFailure>,
    /// How many requests it answers; all of them if absent.
    #[serde(default)]
    pub times: Option<u32>,
}

impl Stub {
    fn default_status() -> u16 {
        200
    }

    fn matches(&self, req: &HttpRequest) -> bool {
        self.times != Some(0)
            && req.url.starts_with(&self.url)
            && self
                .method
                .as_deref()
                .is_none_or(|m| m.eq_ignore_ascii_case(&req.method))
    }
}

/// An outgoing request as the target would have received it: with the
/// secrets the host inserted.
#[derive(Debug, Clone, Serialize)]
pub struct Recorded {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    #[serde(flatten)]
    pub body: Body,
}

/// The test host's network: the newest matching stub answers; a request
/// that no stub matches fails as if the connection were refused.
#[derive(Default)]
pub struct StubNet {
    state: Mutex<NetState>,
}

#[derive(Default)]
struct NetState {
    stubs: Vec<Stub>,
    recorded: Vec<Recorded>,
}

impl StubNet {
    fn state(&self) -> MutexGuard<'_, NetState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn stub(&self, stub: Stub) {
        self.state().stubs.push(stub);
    }

    /// The requests made so far, oldest first; `clear` forgets them.
    pub fn recorded(&self, clear: bool) -> Vec<Recorded> {
        let mut st = self.state();
        if clear {
            std::mem::take(&mut st.recorded)
        } else {
            st.recorded.clone()
        }
    }

    fn answer(&self, req: &HttpRequest) -> Result<HttpResponse, NetError> {
        let mut st = self.state();
        st.recorded.push(Recorded {
            method: req.method.clone(),
            url: req.url.clone(),
            headers: req.headers.clone(),
            body: Body::from_bytes(&req.body),
        });
        let Some(stub) = st.stubs.iter_mut().rev().find(|s| s.matches(req)) else {
            return Err(NetError::Connect(format!(
                "the test host has no stub for {} {}",
                req.method, req.url
            )));
        };
        if let Some(times) = &mut stub.times {
            *times -= 1;
        }
        match stub.error {
            Some(StubFailure::Connect) => {
                Err(NetError::Connect(format!("stub: {} refused", stub.url)))
            }
            Some(StubFailure::Io) => Err(NetError::Io(format!("stub: {} broke off", stub.url))),
            None => {
                let body = stub
                    .body
                    .to_bytes()
                    .map_err(|e| NetError::Connect(format!("stub body: {e}")))?;
                if body.len() as u64 > req.max_response_bytes {
                    return Err(NetError::TooLarge);
                }
                Ok(HttpResponse {
                    status: stub.status,
                    headers: stub.headers.clone(),
                    body: Bytes::from(body),
                })
            }
        }
    }
}

impl Net for StubNet {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        Box::pin(std::future::ready(self.answer(&req)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            url: url.into(),
            headers: vec![("x-a".into(), "1".into())],
            body: Bytes::from_static(b"hi"),
            max_response_bytes: 1 << 20,
        }
    }

    fn stub(json: &str) -> Stub {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn the_newest_matching_stub_answers_and_requests_are_recorded() {
        let net = StubNet::default();
        assert!(matches!(
            net.answer(&request("https://a.example/x")),
            Err(NetError::Connect(_))
        ));
        net.stub(stub(r#"{"url": "https://a.example/", "body": "ok"}"#));
        net.stub(stub(
            r#"{"url": "https://a.example/", "status": 503, "times": 1}"#,
        ));
        net.stub(stub(
            r#"{"url": "https://a.example/", "method": "GET", "error": "io"}"#,
        ));
        assert_eq!(
            net.answer(&request("https://a.example/x")).unwrap().status,
            503
        );
        let ok = net.answer(&request("https://a.example/y")).unwrap();
        assert_eq!((ok.status, &ok.body[..]), (200, &b"ok"[..]));
        let recorded = net.recorded(true);
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[2].url, "https://a.example/y");
        assert_eq!(recorded[2].body.text.as_deref(), Some("hi"));
        assert!(net.recorded(false).is_empty());
    }
}
