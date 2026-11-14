//! M24 (docs/design/m24-connections.md §8, §5.13): browsers cannot set
//! `Authorization` on a WebSocket, so apps put bearer tokens in
//! `Sec-WebSocket-Protocol`. The offered subprotocols are recorded only as
//! that sealable header of the open's request, and the accept records only
//! the selected value's position. With privacy mode on and a request with a
//! subject, a token there, even the one the actor selects, appears in
//! plaintext nowhere in the data directory, and a caller without `pii:read`
//! sees it neither in the turn JSON nor in history nor in a trace (the
//! endpoints behind MCP's `trace_turn` and `query_history`). The operator,
//! who has `pii:read`, sees it, which shows the checks would catch it.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use kronik_api::auth::{Authenticator, Caller, Scope};
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_core::error::ApiError;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::{Node, NodeConfig, start_local};
use serde_json::{Value, json};

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

const TOKEN: &str = "bearer.tok-7c1f0e6a5b2d4c39";

/// A caller with `read` only: no `pii:read`.
struct Reader(Arc<Node>);

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

async fn call(api: &Api, method: &str, path: &str, body: Value, reader: bool) -> Value {
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
            token_id: if reader { "token:reader" } else { "unix:uid=0" }.into(),
            bearer: reader.then(|| "not-checked-by-the-test-authenticator".into()),
        })
        .await;
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(r.status, 200, "{method} {path}: {v}");
    v
}

/// Tagged with the request's subject, as `privacy.subject_from` tags every
/// header and the body of a request (m8-privacy §11).
fn tagged(v: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: Some("user:ada".into()),
        value: Some(pb::sealable::Value::Plain(v.to_vec())),
    })
}

/// Every file under `dir` that holds `needle`.
fn files_containing(dir: &Path, needle: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path)
                && bytes.windows(needle.len()).any(|w| w == needle)
            {
                found.push(path.display().to_string());
            }
        }
    }
    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_in_the_subprotocols_stays_sealed_and_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let api = Api::new(node.clone());
    let reader = Api::new(node.clone()).with_authenticator(Arc::new(Reader(node.clone())));
    call(
        &api,
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "seal the subjects' data"}),
        false,
    )
    .await;
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(ROOM).unwrap());
    call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "deploy"}),
        false,
    )
    .await;

    // The client offers `room.v1` and a token; the actor selects the last
    // one offered, the token.
    let request = pb::HttpInput {
        method: "GET".into(),
        path: "/room/lobby/ws".into(),
        query: "user=ada&pick=last".into(),
        params: vec![pb::Param {
            name: "key".into(),
            value: "lobby".into(),
            sealed_value: None,
        }],
        headers: vec![pb::Header {
            name: "sec-websocket-protocol".into(),
            value: tagged(format!("room.v1, {TOKEN}").as_bytes()),
        }],
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(tagged(b"").unwrap())),
        }),
        route: "/room/{key}/ws".into(),
        ..Default::default()
    };
    let (_conn, waiter) = node
        .connection_open(
            ActorRef::parse("room/lobby").unwrap(),
            request,
            pb::ConnectionProtocol::Websocket,
            Some("user:ada".into()),
            None,
            false,
        )
        .unwrap();
    let r = waiter.wait().await.unwrap();
    let Some(pb::outcome::Output::Accept(accept)) = &r.outcome.output else {
        panic!("{r:?}")
    };
    assert_eq!(
        accept.subprotocol_index,
        Some(1),
        "the token, offered second"
    );
    let turn = r.turn_id.to_string();

    // (i) Nowhere in plaintext: log segments, state.db, its WAL, SQL.
    let found = files_containing(dir.path(), TOKEN.as_bytes());
    assert!(found.is_empty(), "the token is in plaintext in {found:?}");

    // (ii) to (iv): the turn JSON, history and the trace without pii:read.
    let reads = [
        format!("/v1/turns/{turn}"),
        "/v1/actors/room/lobby/history".to_owned(),
        format!("/v1/turns/{turn}/trace"),
    ];
    for path in &reads {
        let v = call(&reader, "GET", path, Value::Null, true).await;
        assert!(!v.to_string().contains(TOKEN), "GET {path}: {v}");
    }
    let t = call(
        &reader,
        "GET",
        &format!("/v1/turns/{turn}"),
        Value::Null,
        true,
    )
    .await;
    assert_eq!(t["output"]["accept"]["subprotocol_index"], 1, "{t}");
    assert_eq!(t["output"]["accept"]["subprotocol"], Value::Null, "{t}");

    // The operator has pii:read: the header and the selected value show.
    let t = call(
        &api,
        "GET",
        &format!("/v1/turns/{turn}"),
        Value::Null,
        false,
    )
    .await;
    assert_eq!(t["output"]["accept"]["subprotocol"], TOKEN, "{t}");
    assert!(t["input"]["request"].to_string().contains(TOKEN), "{t}");
}
