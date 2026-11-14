//! M24's connection endpoints (docs/design/m24-connections.md §12): list and
//! inspect connections, open and closed, with their counts; the subject only
//! with `pii:read` (§8); and the operator's close, a mutation with a reason
//! that the close input records (I12).

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use kronik_api::auth::{Authenticator, Caller, Scope};
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_core::error::ApiError;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::RecordingTransport;
use kronik_sched::{Node, NodeConfig, start_local};
use serde_json::{Value, json};

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

/// A caller with `read` only: no `pii:read`, no `operate`.
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

/// The status and the JSON answer.
async fn call(api: &Api, method: &str, path: &str, body: Value) -> (u16, Value) {
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

async fn get(api: &Api, path: &str) -> Value {
    let (status, v) = call(api, "GET", path, Value::Null).await;
    assert_eq!(status, 200, "GET {path}: {v}");
    v
}

struct Room {
    node: Arc<Node>,
    api: Api,
    reader: Api,
    _dir: tempfile::TempDir,
}

async fn room() -> Room {
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
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(ROOM).unwrap());
    let (status, v) = call(
        &api,
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "deploy"}),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    Room {
        node,
        api,
        reader,
        _dir: dir,
    }
}

impl Room {
    /// Joins room `key` as `user` over a WebSocket, attached to a
    /// recording transport.
    async fn join(&self, key: &str, user: &str) -> (String, Arc<RecordingTransport>) {
        let request = pb::HttpInput {
            method: "GET".into(),
            path: format!("/room/{key}/ws"),
            query: format!("user={user}"),
            params: vec![pb::Param {
                name: "key".into(),
                value: key.into(),
                sealed_value: None,
            }],
            route: "/room/{key}/ws".into(),
            ..Default::default()
        };
        let (id, waiter) = self
            .node
            .connection_open(
                ActorRef::parse(&format!("room/{key}")).unwrap(),
                request,
                pb::ConnectionProtocol::Websocket,
                None,
                None,
                false,
            )
            .unwrap();
        let r = waiter.wait().await.unwrap();
        assert!(
            matches!(r.outcome.output, Some(pb::outcome::Output::Accept(_))),
            "{r:?}"
        );
        let t = RecordingTransport::attach(self.node.hub(), &id).unwrap();
        (id, t)
    }

    /// Waits until the connection's view satisfies `f`.
    async fn until(&self, id: &str, what: &str, f: impl Fn(&Value) -> bool) -> Value {
        for _ in 0..500 {
            let v = get(&self.api, &format!("/v1/connections/{id}")).await;
            if f(&v) {
                return v;
            }
            self.node.env().clock.sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }
}

fn ids(v: &Value) -> Vec<String> {
    v["connections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_are_listed_and_inspected() {
    let r = room().await;
    let (ada, ta) = r.join("lobby", "ada").await;
    let (bob, tb) = r.join("lobby", "bob").await;
    let (cy, _tc) = r.join("den", "cy").await;
    let mut all = vec![ada.clone(), bob.clone(), cy.clone()];
    all.sort();

    // Open ones by default, in id order; filters by actor and kind.
    assert_eq!(ids(&get(&r.api, "/v1/connections").await), all);
    let mut lobby = vec![ada.clone(), bob.clone()];
    lobby.sort();
    assert_eq!(
        ids(&get(&r.api, "/v1/connections?actor=room/lobby").await),
        lobby
    );
    assert_eq!(ids(&get(&r.api, "/v1/connections?kind=room").await), all);
    assert!(ids(&get(&r.api, "/v1/connections?kind=chat").await).is_empty());
    // Pages.
    let first = get(&r.api, "/v1/connections?limit=2").await;
    assert_eq!(ids(&first), all[..2]);
    let next = first["next"].as_str().unwrap();
    let second = get(&r.api, &format!("/v1/connections?limit=2&after={next}")).await;
    assert_eq!(ids(&second), all[2..]);
    assert_eq!(second["next"], Value::Null);

    // One connection: its owner, route, open turn and counts. The room
    // sent ada its welcome and bob's `joined`; the recording transport
    // wrote both.
    let v = r
        .until(&ada, "ada's frames", |v| v["frames"]["out"] == 2)
        .await;
    assert_eq!(v["actor"], "room/lobby");
    assert_eq!(v["protocol"], "websocket");
    assert_eq!(v["route"], "/room/{key}/ws");
    assert_eq!(v["state"], "open");
    assert!(
        v["opened"]["turn_id"]
            .as_str()
            .unwrap()
            .starts_with("main:")
    );
    assert!(v["opened"]["logical_time_ms"].as_u64().is_some(), "{v}");
    assert_eq!(v["closed"], Value::Null);
    assert_eq!(
        v["frames"],
        json!({"in": 0, "out": 2, "written": 2, "queued": 0, "dropped": 0, "unknown": 0})
    );
    assert_eq!(v["live"], json!({"queued_bytes": 0}));
    assert_eq!(ta.recording().frames.len(), 2);
    // The subject only with pii:read.
    assert_eq!(v["subject"], "user:ada");
    let (status, hidden) = call(
        &r.reader,
        "GET",
        &format!("/v1/connections/{ada}"),
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{hidden}");
    assert_eq!(hidden["subject"], Value::Null);
    let (_, listed) = call(&r.reader, "GET", "/v1/connections", Value::Null).await;
    assert!(
        listed["connections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["subject"].is_null()),
        "{listed}"
    );

    // A frame from the client counts in `in`.
    r.node
        .hub()
        .incoming(
            &ada,
            pb::Frame {
                kind: pb::frame::Kind::Text as i32,
                data: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(b"echo hi".to_vec())),
                }),
                ..Default::default()
            },
        )
        .await;
    r.until(&ada, "ada's frame", |v| {
        v["frames"]["in"] == 1 && v["frames"]["written"] == 3
    })
    .await;

    // Ada's turns in the room's history: only those of her connection, her
    // open's and her frame's, and bob's open, which sent her `joined`; with
    // each send's fates.
    let h = get(
        &r.api,
        &format!("/v1/actors/room/lobby/history?connection={ada}"),
    )
    .await;
    let turns = h["turns"].as_array().unwrap();
    assert!(turns.len() >= 3, "{h}");
    assert!(turns.iter().all(|t| t.to_string().contains(&ada)), "{h}");
    let bob_open = turns
        .iter()
        .find(|t| {
            t["input"]["summary"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!("open {bob}")))
        })
        .unwrap_or_else(|| panic!("bob's open turn in {h}"));
    let joined = bob_open["connection_ops"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["connections"] == json!([ada]))
        .unwrap_or_else(|| panic!("a send to ada in {bob_open}"));
    assert_eq!(joined["op"], "send");
    assert_eq!(joined["kind"], "text");
    assert_eq!(
        joined["fates"],
        json!({"written": 1, "queued": 0, "dropped": 0, "unknown": 0})
    );
    // Unfiltered history shows the operations too, and none on turns
    // without them.
    let all_turns = get(&r.api, "/v1/actors/room/lobby/history").await;
    assert!(
        all_turns.to_string().contains("connection_ops"),
        "{all_turns}"
    );
    let (status, v) = call(
        &r.api,
        "GET",
        "/v1/actors/room/lobby/history?connection=nope",
        Value::Null,
    )
    .await;
    assert_eq!(status, 400, "{v}");

    // A closed connection: listed as closed, with its close.
    tb.client_close(Some((1001, "tab closed".into())));
    let v = r
        .until(&bob, "bob's close", |v| v["state"] == "closed")
        .await;
    assert_eq!(
        v["closed"]["initiator"]
            .as_str()
            .zip(v["closed"]["cause"].as_str()),
        Some(("client", "client"))
    );
    assert_eq!(v["closed"]["code"], 1001);
    assert_eq!(v["live"], Value::Null);
    assert_eq!(v["frames"]["dropped"], 0);
    assert_eq!(v["frames"]["written"], v["frames"]["out"]);
    assert_eq!(
        ids(&get(&r.api, "/v1/connections?state=closed").await),
        std::slice::from_ref(&bob)
    );
    assert_eq!(ids(&get(&r.api, "/v1/connections?state=all").await), all);
    assert!(!ids(&get(&r.api, "/v1/connections").await).contains(&bob));

    // Errors.
    for (path, status) in [
        ("/v1/connections?state=gone", 400),
        ("/v1/connections?actor=room/lobby&kind=room", 400),
        ("/v1/connections?after=nope", 400),
        ("/v1/connections/nope", 400),
        ("/v1/connections/c-00000000000000000000000000000000", 404),
    ] {
        let (got, v) = call(&r.api, "GET", path, Value::Null).await;
        assert_eq!(got, status, "{path}: {v}");
    }
    let (_, v) = call(
        &r.api,
        "GET",
        "/v1/connections/c-00000000000000000000000000000000",
        Value::Null,
    )
    .await;
    assert_eq!(v["error"]["code"], "CONNECTION_NOT_FOUND", "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_operator_closes_a_connection() {
    let r = room().await;
    let (ada, ta) = r.join("lobby", "ada").await;
    let path = format!("/v1/connections/{ada}/close");

    // A mutation: a reason, a valid code and message, and the operate
    // scope.
    for (body, status, code) in [
        (json!({}), 400, "REASON_REQUIRED"),
        (json!({"reason": "x", "code": 1005}), 400, "BAD_REQUEST"),
        (json!({"reason": "x", "code": 2000}), 400, "BAD_REQUEST"),
        (
            json!({"reason": "x", "message": "m".repeat(124)}),
            400,
            "BAD_REQUEST",
        ),
    ] {
        let (got, v) = call(&r.api, "POST", &path, body.clone()).await;
        assert_eq!(
            (got, v["error"]["code"].as_str()),
            (status, Some(code)),
            "{body}: {v}"
        );
    }
    let (status, v) = call(&r.reader, "POST", &path, json!({"reason": "x"})).await;
    assert_eq!(
        (status, v["error"]["code"].as_str()),
        (403, Some("SCOPE_MISSING")),
        "{v}"
    );

    // A dry run changes nothing.
    let (status, v) = call(
        &r.api,
        "POST",
        &path,
        json!({"reason": "check", "dry_run": true}),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["connection"]["state"], "open");
    assert_eq!(ta.recording().closed, None);

    // The close: the client gets the code and the message, the close input
    // the cause, the code and the reason.
    let (status, v) = call(
        &r.api,
        "POST",
        &path,
        json!({"code": 4001, "message": "closed by the operator", "reason": "an abusive client"}),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["dry_run"], false);
    assert_eq!(v["connection"]["state"], "closing");
    assert_eq!(
        ta.recording().closed,
        Some((4001, "closed by the operator".into()))
    );
    let v = r
        .until(&ada, "ada's close", |v| v["state"] == "closed")
        .await;
    assert_eq!(
        v["closed"],
        json!({"turn_id": v["closed"]["turn_id"], "initiator": "host", "cause": "operator", "code": 4001})
    );
    let turn = get(
        &r.api,
        &format!("/v1/turns/{}", v["closed"]["turn_id"].as_str().unwrap()),
    )
    .await;
    assert_eq!(turn["input"]["type"], "connection", "{turn}");
    assert_eq!(turn["input"]["reason"], "an abusive client", "{turn}");
    // The mutation's record: an AuditEvent, written before the close.
    let mut events = Vec::new();
    r.node
        .reader()
        .read(1, r.node.applied_lsn(), |c| {
            if let kronik_proto::Record::AuditEvent(e) = &c.record {
                events.push(e.clone());
            }
            Ok(())
        })
        .await
        .unwrap();
    let close = events
        .iter()
        .find(|e| e.action == "connection.close")
        .unwrap_or_else(|| panic!("no connection.close in {events:?}"));
    assert_eq!(close.target, ada);
    assert_eq!(close.details["actor"], "room/lobby");
    assert_eq!(close.details["code"], "4001");
    assert_eq!(close.audit.as_ref().unwrap().reason, "an abusive client");
    assert!(!events.iter().any(|e| e.action == "connection.close.failed"));

    // Closed: not open any more.
    let (status, v) = call(&r.api, "POST", &path, json!({"reason": "again"})).await;
    assert_eq!(
        (status, v["error"]["code"].as_str()),
        (404, Some("CONNECTION_NOT_FOUND")),
        "{v}"
    );
}
