//! Shared helpers of the API integration tests: a request and its JSON
//! answer, a read-only caller, a guest's bytes and a plain HTTP target.

// Each test binary uses only part of this module.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use base64::Engine as _;
use kronik_api::auth::{Authenticator, Caller, Scope};
use kronik_api::{Api, ApiRequest};
use kronik_core::error::ApiError;
use kronik_sched::Node;
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

/// A plain HTTP server on a free port that answers every request with 200
/// and the body `pong`, until the test process exits. Returns its address.
pub fn http_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
            );
        }
    });
    addr
}
