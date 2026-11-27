//! Shared helpers of the API integration tests: a default local node, a
//! request and its JSON answer, a read-only caller, a guest's bytes and a
//! plain HTTP target.

// Each test binary uses only part of this module.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use kronik_api::auth::{Authenticator, Caller, Scope};
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_core::error::ApiError;
use kronik_sched::{Node, NodeConfig, start_local};
use serde_json::Value;

/// The test guests, built by `tests/guests/build.sh`.
pub const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests");

/// Base64 of the guest `{name}.wasm`, as a deployment body.
pub fn wasm(name: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(format!("{GUESTS}/{name}.wasm")).unwrap())
}

/// The status and the JSON answer.
pub async fn call(api: &Api, method: &str, path: &str, body: Value) -> (u16, Value) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let r = api
        .handle(ApiRequest {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            body: if body.is_null() {
                vec![]
            } else {
                body.to_string().into_bytes()
            },
            token_id: "unix:uid=0".into(),
            bearer: None,
        })
        .await;
    (r.status, serde_json::from_slice(&r.body).unwrap())
}

/// A caller with `read` only: no `pii:read`, no `operate`.
pub struct Reader(pub Arc<Node>);

impl Authenticator for Reader {
    fn caller(&self, _req: &ApiRequest) -> Result<Caller, ApiError> {
        Ok(Caller {
            token_id: "token:reader".into(),
            scopes: BTreeSet::from([Scope::Read]),
        })
    }

    fn authority(
        &self,
        _req: &ApiRequest,
        _required: Scope,
    ) -> Result<kronik_core::authority::AuthLease, ApiError> {
        self.0.local_operator_authority()
    }
}

/// A plain HTTP server on a free port that reads each request, body included,
/// and answers every one with 200 and the body `pong`, until the test process
/// exits. Returns its address.
pub fn http_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 {
                    break;
                }
                let h = h.trim_end().to_ascii_lowercase();
                if h.is_empty() {
                    break;
                }
                if let Some(v) = h.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; len];
            let _ = r.read_exact(&mut body);
            let _ = w.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
            );
        }
    });
    addr
}

/// A local node on `dir` with the default configuration, on the current
/// Tokio runtime.
pub async fn start_node(dir: &Path) -> Arc<Node> {
    start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir,
        NodeConfig::default(),
    )
    .await
    .unwrap()
}

/// A node over `dir` on a runtime of its own. Dropping the site drops the
/// runtime with everything the node spawned: a crash.
pub struct Site {
    runtime: tokio::runtime::Runtime,
    api: Arc<Api>,
}

impl Site {
    pub fn start(dir: &Path) -> Site {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let api = runtime.block_on(async { Arc::new(Api::new(start_node(dir).await)) });
        Site { runtime, api }
    }

    /// One call, as it answers: 503s are left to the caller.
    pub fn call(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        self.runtime.block_on(call(&self.api, method, path, body))
    }
}
