//! A simulated external service ("payments") for effect DST. It lives on the
//! supervisor side, so it survives daemon crashes, and it is reached through
//! the node's `Net`: a request travels for a while, is processed atomically
//! by the service, and the response travels back. A crash before processing
//! loses the request; a crash after it loses only the response.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use kronik_core::env::{BoxFuture, Clock, HttpRequest, HttpResponse, Net, NetError};

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

#[derive(Default)]
struct State {
    sent: Vec<Sent>,
    received: Vec<Received>,
    /// Idempotency-Key -> saved response (dedup).
    processed: BTreeMap<String, Vec<u8>>,
    charges: u64,
}

/// Fault knobs.
#[derive(Debug, Clone, Copy)]
pub struct ServiceFaults {
    /// The connection fails before anything is sent.
    pub connect_fail: f64,
    /// The request is processed but the response is lost.
    pub lose_response: f64,
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
