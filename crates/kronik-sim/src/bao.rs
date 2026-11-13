//! A simulated OpenBao for the secret workloads: the KV v2 engine at the
//! mount `secret` with token authentication, as the daemon's real `openbao`
//! secret backend speaks to it (`lookup-self`, `data/<path>?version=N`,
//! `metadata/<path>`). It lives on the supervisor side, so it survives daemon
//! crashes, and it is reached through the node's `Net` ([`SimNet`] routes
//! [`ADDRESS`] to it). A request travels for a while, is answered atomically,
//! and the answer travels back; while the service hangs, a request waits in
//! virtual time until the client's own timeout gives up on it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use kronik_core::env::{BoxFuture, Clock, HttpRequest, HttpResponse, Net, NetError, TlsConfig};
use serde_json::{Value, json};

use crate::SimRng;

/// Where the daemon's `[secrets.backends]` entry points.
pub const ADDRESS: &str = "http://127.0.0.1:8200";
/// The token the service accepts (the daemon reads it from its token file).
pub const TOKEN: &str = "dst-bao-token";

/// Whether the service answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Up,
    /// No answer, for as long as the mode lasts.
    Hang,
}

struct Version {
    value: String,
    destroyed: bool,
}

#[derive(Default)]
struct State {
    /// The versions of each path of the mount, oldest first.
    paths: BTreeMap<String, Vec<Version>>,
    hanging: bool,
    /// Paths that hang, whatever the mode, once they have answered this many
    /// reads of their data.
    hang_after: BTreeMap<String, u64>,
    /// Reads of each path's data that were answered.
    answered: BTreeMap<String, u64>,
    /// Every request that reached the service.
    requests: u64,
}

pub struct SimBao {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
    rng: SimRng,
}

impl SimBao {
    pub fn new(clock: Arc<dyn Clock>, rng: SimRng) -> Arc<SimBao> {
        Arc::new(SimBao {
            state: Mutex::new(State::default()),
            clock,
            rng,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Writes a new version of `path` (a KV write); its version number.
    pub fn put(&self, path: &str, value: &str) -> u64 {
        let mut st = self.lock();
        let versions = st.paths.entry(path.to_owned()).or_default();
        versions.push(Version {
            value: value.to_owned(),
            destroyed: false,
        });
        versions.len() as u64
    }

    /// `kv destroy -versions=N`: the value is gone for good.
    pub fn destroy(&self, path: &str, version: u64) {
        let mut st = self.lock();
        if let Some(v) = st
            .paths
            .get_mut(path)
            .and_then(|versions| versions.get_mut(version.saturating_sub(1) as usize))
        {
            v.destroyed = true;
            v.value.clear();
        }
    }

    /// The value of a version, as the service holds it.
    pub fn value(&self, path: &str, version: u64) -> Option<String> {
        let st = self.lock();
        st.paths
            .get(path)?
            .get(version.checked_sub(1)? as usize)
            .filter(|v| !v.destroyed)
            .map(|v| v.value.clone())
    }

    /// The number of the newest version of `path`.
    pub fn current(&self, path: &str) -> u64 {
        self.lock().paths.get(path).map_or(0, |v| v.len() as u64)
    }

    pub fn set_mode(&self, mode: Mode) {
        self.lock().hanging = mode == Mode::Hang;
    }

    /// `path` hangs once it has answered `reads` reads of its data.
    pub fn hang_after(&self, path: &str, reads: u64) {
        self.lock().hang_after.insert(path.to_owned(), reads);
    }

    /// Every request that reached the service so far.
    pub fn requests(&self) -> u64 {
        self.lock().requests
    }

    /// The path of the mount a request is for, if it reads a path's data.
    fn data_path(url: &str) -> Option<&str> {
        let rest = url
            .strip_prefix(ADDRESS)?
            .strip_prefix("/v1/secret/data/")?;
        Some(rest.split_once('?').map_or(rest, |(path, _)| path))
    }

    /// Whether the request must wait now.
    fn hangs(&self, req: &HttpRequest) -> bool {
        let st = self.lock();
        st.hanging
            || Self::data_path(&req.url).is_some_and(|path| {
                st.hang_after
                    .get(path)
                    .is_some_and(|after| st.answered.get(path).copied().unwrap_or(0) >= *after)
            })
    }

    fn answer(&self, req: &HttpRequest) -> HttpResponse {
        let response = |status: u16, body: Value| HttpResponse {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Bytes::from(body.to_string()),
        };
        let mut st = self.lock();
        st.requests += 1;
        let token = req
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-vault-token"))
            .map(|(_, value)| value.as_str());
        if req.method != "GET" || token != Some(TOKEN) {
            return response(403, json!({"errors": ["permission denied"]}));
        }
        let Some(rest) = req.url.strip_prefix(ADDRESS) else {
            return response(404, json!({"errors": []}));
        };
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        if path == "/v1/auth/token/lookup-self" {
            return response(200, json!({"data": {"ttl": 0, "renewable": false}}));
        }
        if let Some(secret) = path.strip_prefix("/v1/secret/metadata/") {
            let Some(versions) = st.paths.get(secret) else {
                return response(404, json!({"errors": []}));
            };
            let listed: serde_json::Map<String, Value> = versions
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    (
                        (i + 1).to_string(),
                        json!({"destroyed": v.destroyed, "deletion_time": ""}),
                    )
                })
                .collect();
            return response(
                200,
                json!({"data": {
                    "current_version": versions.len(),
                    "oldest_version": 1,
                    "versions": listed
                }}),
            );
        }
        if let Some(secret) = path.strip_prefix("/v1/secret/data/") {
            let Some(versions) = st.paths.get(secret) else {
                return response(404, json!({"errors": []}));
            };
            let wanted = match query.strip_prefix("version=") {
                Some(v) => v.parse::<usize>().unwrap_or(0),
                None => versions.len(),
            };
            let Some(version) = wanted.checked_sub(1).and_then(|i| versions.get(i)) else {
                return response(404, json!({"errors": []}));
            };
            if version.destroyed {
                return response(
                    404,
                    json!({"data": {"data": null, "metadata": {
                        "version": wanted, "destroyed": true, "deletion_time": ""
                    }}}),
                );
            }
            let body = json!({"data": {"data": {"key": version.value}, "metadata": {
                "version": wanted, "destroyed": false, "deletion_time": ""
            }}});
            *st.answered.entry(secret.to_owned()).or_default() += 1;
            return response(200, body);
        }
        response(404, json!({"errors": []}))
    }

    /// One request: travel there, wait while the service hangs, be answered
    /// (inside `admit` when there is an authority), travel back.
    fn serve(
        self: &Arc<Self>,
        req: HttpRequest,
        original: Option<kronik_core::authority::AuthLease>,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let bao = self.clone();
        Box::pin(async move {
            let denied = |error: kronik_core::error::ApiError| NetError::Connect(error.to_string());
            if let Some(original) = &original {
                original.check().map_err(denied)?;
            }
            let there = bao
                .rng
                .duration(Duration::from_micros(200), Duration::from_millis(5));
            let back = bao
                .rng
                .duration(Duration::from_micros(200), Duration::from_millis(5));
            bao.clock.sleep(there).await;
            while bao.hangs(&req) {
                bao.clock.sleep(Duration::from_millis(50)).await;
            }
            let mut response = None;
            match &original {
                Some(original) => original
                    .admit(&mut || {
                        response = Some(bao.answer(&req));
                        Ok(())
                    })
                    .map_err(denied)?,
                None => response = Some(bao.answer(&req)),
            }
            let response =
                response.ok_or_else(|| NetError::Connect("the request was not admitted".into()))?;
            bao.clock.sleep(back).await;
            Ok(response)
        })
    }
}

/// The node's network in the simulator: [`ADDRESS`] reaches the simulated
/// OpenBao, everything else the simulated payments service, or nothing.
pub struct SimNet {
    pub bao: Option<Arc<SimBao>>,
    pub service: Option<Arc<dyn Net>>,
}

impl SimNet {
    fn bao_for(&self, url: &str) -> Option<&Arc<SimBao>> {
        self.bao
            .as_ref()
            .filter(|_| url == ADDRESS || url.starts_with(&format!("{ADDRESS}/")))
    }
}

impl Net for SimNet {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        if let Some(bao) = self.bao_for(&req.url) {
            return bao.serve(req, None);
        }
        match &self.service {
            Some(service) => service.http(req),
            None => {
                Box::pin(async move { Err(NetError::Connect(format!("no network: {}", req.url))) })
            }
        }
    }

    fn http_authorized(
        &self,
        req: HttpRequest,
        original: kronik_core::authority::AuthLease,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        if let Some(bao) = self.bao_for(&req.url) {
            return bao.serve(req, Some(original));
        }
        match &self.service {
            Some(service) => service.http_authorized(req, original),
            None => Box::pin(async move {
                original
                    .check()
                    .map_err(|error| NetError::Connect(error.to_string()))?;
                Err(NetError::Connect(format!("no network: {}", req.url)))
            }),
        }
    }

    fn with_tls(&self, _tls: TlsConfig) -> Result<Arc<dyn Net>, NetError> {
        Err(NetError::Connect("the simulated network has no TLS".into()))
    }
}
