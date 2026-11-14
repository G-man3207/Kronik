//! A simulated external service ("payments") for effect DST. It lives on the
//! supervisor side, so it survives daemon crashes, and it is reached through
//! the node's `Net`: a request travels for a while, is processed atomically
//! by the service, and the response travels back. A crash before processing
//! loses the request; a crash after it loses only the response.
//!
//! Streamed exchanges (`Net::http_stream_authorized`, M25 §7.1) move their
//! bodies in chunks of seeded sizes, each after a seeded delay, and a
//! response can be cut in the middle of its body. Besides charges, the
//! service serves `GET /bytes/<n>` ([`content`]) and keeps what `POST /sink`
//! sends it ([`SimService::sinks`]).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use kronik_core::env::{
    BodySource, BoxFuture, Clock, HttpBody, HttpRequest, HttpResponse, HttpStreamRequest,
    HttpStreamResponse, Net, NetError,
};

use crate::SimRng;

/// One request as the service saw it.
#[derive(Debug, Clone)]
pub struct Received {
    pub key: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub at: Duration,
}

/// One call as the daemon sent it (before any network delay or failure).
#[derive(Debug, Clone)]
pub struct Sent {
    pub at: Duration,
    /// The daemon process that sent it.
    pub node: u32,
}

/// A body `POST /sink` received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sink {
    pub key: String,
    pub body: Vec<u8>,
}

#[derive(Default)]
struct State {
    sent: Vec<Sent>,
    received: Vec<Received>,
    /// Idempotency-Key -> saved response (dedup).
    processed: BTreeMap<String, Vec<u8>>,
    charges: u64,
    sinks: Vec<Sink>,
}

/// Fault knobs.
#[derive(Debug, Clone, Copy)]
pub struct ServiceFaults {
    /// The connection fails before anything is sent.
    pub connect_fail: f64,
    /// The request is processed but the response is lost.
    pub lose_response: f64,
    /// A streamed response is cut somewhere in its body.
    pub cut_body: f64,
}

/// The body of `GET /bytes/<n>`: `n` bytes that depend on `n`.
pub fn content(n: u64) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(131).wrapping_add(n).wrapping_add(17) % 253) as u8)
        .collect()
}

pub struct SimService {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
    rng: SimRng,
    faults: ServiceFaults,
}

impl SimService {
    pub fn new(clock: Arc<dyn Clock>, rng: SimRng, faults: ServiceFaults) -> Arc<SimService> {
        Arc::new(SimService {
            state: Mutex::new(State::default()),
            clock,
            rng,
            faults,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Processes one request: a repeated Idempotency-Key gets the saved
    /// response, a new one makes a charge.
    fn handle(&self, req: &HttpRequest) -> HttpResponse {
        let key = req
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("idempotency-key"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let mut st = self.lock();
        st.received.push(Received {
            key: key.clone(),
            headers: req.headers.clone(),
            body: req.body.to_vec(),
            at: self.clock.monotonic(),
        });
        let body = match st.processed.get(&key) {
            Some(saved) => saved.clone(),
            None => {
                st.charges += 1;
                let b = format!("charged #{}", st.charges).into_bytes();
                st.processed.insert(key, b.clone());
                b
            }
        };
        HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Bytes::from(body),
        }
    }

    /// Processes a streamed exchange's request: `GET /bytes/<n>` and
    /// `POST /sink` (each repeated Idempotency-Key getting the saved
    /// response), or a charge.
    fn handle_stream(&self, req: &HttpRequest) -> HttpResponse {
        let path = req.url.strip_prefix("http://payments").unwrap_or("");
        if let Some(n) = path.strip_prefix("/bytes/")
            && let Ok(n) = n.parse::<u64>()
        {
            return HttpResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/octet-stream".into())],
                body: Bytes::from(content(n)),
            };
        }
        if path != "/sink" {
            return self.handle(req);
        }
        let key = req
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("idempotency-key"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let mut st = self.lock();
        let body = match st.processed.get(&key) {
            Some(saved) if !key.is_empty() => saved.clone(),
            _ => {
                st.sinks.push(Sink {
                    key: key.clone(),
                    body: req.body.to_vec(),
                });
                let b = format!("stored {}", req.body.len()).into_bytes();
                if !key.is_empty() {
                    st.processed.insert(key, b.clone());
                }
                b
            }
        };
        HttpResponse {
            status: 201,
            headers: Vec::new(),
            body: Bytes::from(body),
        }
    }

    /// What `POST /sink` received, in order.
    pub fn sinks(&self) -> Vec<Sink> {
        self.lock().sinks.clone()
    }

    pub fn received(&self) -> Vec<Received> {
        self.lock().received.clone()
    }

    pub fn sent(&self) -> Vec<Sent> {
        self.lock().sent.clone()
    }

    pub fn charges(&self) -> u64 {
        self.lock().charges
    }

    /// The `Net` the daemon process `node` uses to reach the service.
    pub fn net(self: &Arc<Self>, node: u32) -> Arc<dyn Net> {
        Arc::new(ServiceNet(self.clone(), node))
    }
}

struct ServiceNet(Arc<SimService>, u32);

impl Net for ServiceNet {
    fn http_authorized(
        &self,
        req: HttpRequest,
        original: kronik_core::authority::AuthLease,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let svc = self.0.clone();
        let node = self.1;
        Box::pin(async move {
            let denied = |error: kronik_core::error::ApiError| NetError::Connect(error.to_string());
            original.check().map_err(denied)?;
            let there = svc
                .rng
                .duration(Duration::from_micros(200), Duration::from_millis(20));
            let back = svc
                .rng
                .duration(Duration::from_micros(200), Duration::from_millis(20));
            let connect_fails = svc.rng.chance(svc.faults.connect_fail);
            let lose = svc.rng.chance(svc.faults.lose_response);
            svc.clock.sleep(there).await;
            if connect_fails {
                return Err(NetError::Connect("connection refused".into()));
            }
            if !req.url.starts_with("http://payments/") {
                return Err(NetError::Connect(format!("unknown host in {}", req.url)));
            }
            let mut response = None;
            original
                .admit(&mut || {
                    let at = svc.clock.monotonic();
                    svc.lock().sent.push(Sent { at, node });
                    response = Some(svc.handle(&req));
                    Ok(())
                })
                .map_err(denied)?;
            let response = response.ok_or_else(|| {
                NetError::Connect("authority did not admit simulated HTTP".into())
            })?;
            svc.clock.sleep(back).await;
            drop(original);
            if lose {
                Err(NetError::Io("connection reset after the request".into()))
            } else {
                Ok(response)
            }
        })
    }

    fn http_stream_authorized(
        &self,
        req: HttpStreamRequest,
        original: kronik_core::authority::AuthLease,
    ) -> BoxFuture<'static, Result<HttpStreamResponse, NetError>> {
        let svc = self.0.clone();
        let node = self.1;
        Box::pin(async move {
            let denied = |error: kronik_core::error::ApiError| NetError::Connect(error.to_string());
            original.check().map_err(denied)?;
            let there = svc
                .rng
                .duration(Duration::from_micros(200), Duration::from_millis(20));
            let back = svc
                .rng
                .duration(Duration::from_micros(200), Duration::from_millis(20));
            let connect_fails = svc.rng.chance(svc.faults.connect_fail);
            let lose = svc.rng.chance(svc.faults.lose_response);
            let cut = svc.rng.chance(svc.faults.cut_body);
            svc.clock.sleep(there).await;
            if connect_fails {
                return Err(NetError::Connect("connection refused".into()));
            }
            if !req.url.starts_with("http://payments/") {
                return Err(NetError::Connect(format!("unknown host in {}", req.url)));
            }
            // The request body arrives as the daemon sends it, chunk by chunk.
            let body = match req.body {
                HttpBody::Bytes(bytes) => bytes,
                HttpBody::Stream { len, mut source } => {
                    let mut body = Vec::new();
                    while let Some(chunk) = source
                        .next()
                        .await
                        .map_err(|e| NetError::Io(format!("reading the request body: {e}")))?
                    {
                        let pause = svc
                            .rng
                            .duration(Duration::from_micros(10), Duration::from_millis(2));
                        svc.clock.sleep(pause).await;
                        body.extend_from_slice(&chunk);
                    }
                    if body.len() as u64 != len {
                        return Err(NetError::Io(format!(
                            "the request body has {} bytes, not its content-length {len}",
                            body.len()
                        )));
                    }
                    Bytes::from(body)
                }
            };
            let request = HttpRequest {
                method: req.method,
                url: req.url,
                headers: req.headers,
                body,
                max_response_bytes: req.max_response_bytes,
            };
            let mut response = None;
            original
                .admit(&mut || {
                    let at = svc.clock.monotonic();
                    svc.lock().sent.push(Sent { at, node });
                    response = Some(svc.handle_stream(&request));
                    Ok(())
                })
                .map_err(denied)?;
            let response = response.ok_or_else(|| {
                NetError::Connect("authority did not admit simulated HTTP".into())
            })?;
            svc.clock.sleep(back).await;
            drop(original);
            if lose {
                return Err(NetError::Io("connection reset after the request".into()));
            }
            let cut_at = cut.then(|| svc.rng.below(response.body.len() as u64 + 1) as usize);
            Ok(HttpStreamResponse {
                status: response.status,
                headers: response.headers,
                body: Box::new(Chunks {
                    svc,
                    body: response.body,
                    at: 0,
                    cut_at,
                    max: req.max_response_bytes,
                }),
            })
        })
    }

    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let svc = self.0.clone();
        let at = svc.clock.monotonic();
        svc.lock().sent.push(Sent { at, node: self.1 });
        Box::pin(async move {
            let there = svc
                .rng
                .duration(Duration::from_micros(200), Duration::from_millis(20));
            let back = svc
                .rng
                .duration(Duration::from_micros(200), Duration::from_millis(20));
            let connect_fails = svc.rng.chance(svc.faults.connect_fail);
            let lose = svc.rng.chance(svc.faults.lose_response);
            svc.clock.sleep(there).await;
            if connect_fails {
                return Err(NetError::Connect("connection refused".into()));
            }
            if !req.url.starts_with("http://payments/") {
                return Err(NetError::Connect(format!("unknown host in {}", req.url)));
            }
            let resp = svc.handle(&req);
            svc.clock.sleep(back).await;
            if lose {
                return Err(NetError::Io("connection reset after the request".into()));
            }
            Ok(resp)
        })
    }
}

/// A streamed response body: chunks of 1 byte to 64 KiB, each after up to
/// 2 ms, cut at `cut_at` if set, failing past `max` as a real connection
/// does ([`kronik_core::env::response_too_large`]).
struct Chunks {
    svc: Arc<SimService>,
    body: Bytes,
    at: usize,
    cut_at: Option<usize>,
    max: u64,
}

impl BodySource for Chunks {
    fn next(&mut self) -> BoxFuture<'_, std::io::Result<Option<Bytes>>> {
        Box::pin(async move {
            let pause = self
                .svc
                .rng
                .duration(Duration::from_micros(10), Duration::from_millis(2));
            self.svc.clock.sleep(pause).await;
            if self.cut_at.is_some_and(|cut| self.at >= cut) {
                return Err(std::io::Error::other("connection reset in the body"));
            }
            if self.at >= self.body.len() {
                return Ok(None);
            }
            let n = 1 + self.svc.rng.below(64 << 10) as usize;
            let end = (self.at + n).min(self.body.len());
            let end = self.cut_at.map_or(end, |cut| end.min(cut.max(self.at + 1)));
            if end as u64 > self.max {
                return Err(kronik_core::env::response_too_large());
            }
            let chunk = self.body.slice(self.at..end);
            self.at = end;
            Ok(Some(chunk))
        })
    }
}
