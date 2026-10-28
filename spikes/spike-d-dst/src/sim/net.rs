//! Simulated outbound network with one external service (`payments.sim`).
//!
//! The service records every request it actually receives. At the moment of
//! receipt it runs a world-provided check (used for I14: a durable
//! `TurnBegin` must exist for the request's idempotency key) and enforces the
//! delivery class: an `idempotency-keyed` target applies each key once, an
//! `unsafe` target must never see the same key twice.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;

use super::SimRng;
use crate::env::{BoxFuture, Clock, HttpRequest, HttpResponse, Net, NetError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    IdempotencyKeyed,
    Unsafe,
}

#[derive(Debug, Clone, Copy)]
pub struct NetFaults {
    /// Request never leaves the host.
    pub connect_fail: f64,
    /// Request is applied, response lost.
    pub response_lost: f64,
    /// Request is applied, response never comes (caller times out).
    pub hang: f64,
}

pub type ReceiptCheck = Arc<dyn Fn(&HttpRequest) -> Result<(), String> + Send + Sync>;

pub struct Payments {
    pub delivery: Delivery,
    /// Idempotency key -> (times received, response).
    pub seen: BTreeMap<String, (u32, Bytes)>,
    /// Charges actually applied, in order: (idempotency key, body).
    pub applied: Vec<(String, Bytes)>,
    pub violations: Vec<String>,
    check: Option<ReceiptCheck>,
}

impl Payments {
    pub fn new(delivery: Delivery) -> Self {
        Self {
            delivery,
            seen: BTreeMap::new(),
            applied: Vec::new(),
            violations: Vec::new(),
            check: None,
        }
    }

    pub fn set_check(&mut self, check: ReceiptCheck) {
        self.check = Some(check);
    }

    fn receive(&mut self, req: &HttpRequest) -> HttpResponse {
        if let Some(check) = &self.check
            && let Err(v) = check(req)
        {
            self.violations.push(v);
        }
        let key = req
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("idempotency-key"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let body = match self.seen.get_mut(&key) {
            Some((count, body)) => {
                *count += 1;
                if self.delivery == Delivery::Unsafe {
                    self.violations
                        .push(format!("unsafe effect delivered twice: key {key}"));
                }
                body.clone()
            }
            None => {
                let body = Bytes::from(format!("charged #{}", self.applied.len() + 1));
                self.applied.push((key.clone(), req.body.clone()));
                self.seen.insert(key, (1, body.clone()));
                body
            }
        };
        HttpResponse {
            status: 200,
            headers: Vec::new(),
            body,
        }
    }
}

pub type TraceFn = Arc<dyn Fn(String) + Send + Sync>;

pub struct SimNet {
    pub payments: Arc<Mutex<Payments>>,
    pub clock: Arc<dyn Clock>,
    pub rng: SimRng,
    pub faults: NetFaults,
    pub trace: TraceFn,
}

impl Net for SimNet {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let rng = self.rng.clone();
        let clock = self.clock.clone();
        let payments = self.payments.clone();
        let faults = self.faults;
        let trace = self.trace.clone();
        Box::pin(async move {
            clock
                .sleep(rng.duration(Duration::from_micros(200), Duration::from_millis(2)))
                .await;
            if !req.url.starts_with("https://payments.sim/") {
                return Err(NetError::Connect(format!("no route to {}", req.url)));
            }
            if rng.chance(faults.connect_fail) {
                trace("net connect-fail".into());
                return Err(NetError::Connect("connection refused".into()));
            }
            let resp = payments
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .receive(&req);
            trace(format!(
                "net delivered {}",
                String::from_utf8_lossy(&req.body)
            ));
            let lat = if rng.chance(0.01) {
                Duration::from_secs(3)
            } else {
                rng.duration(Duration::from_millis(1), Duration::from_millis(30))
            };
            clock.sleep(lat).await;
            if rng.chance(faults.hang) {
                clock.sleep(Duration::from_secs(120)).await;
                return Err(NetError::Io("hung".into()));
            }
            if rng.chance(faults.response_lost) {
                trace("net response-lost".into());
                return Err(NetError::Io("connection reset after send".into()));
            }
            Ok(resp)
        })
    }
}
