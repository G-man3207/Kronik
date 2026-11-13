//! M24 long-lived connections in the scheduler (docs/design/m24-connections.md):
//! deploy checks and route conflicts of connection routes.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use kronik_core::env::Env;
use kronik_core::error::ErrorCode;
use kronik_proto::log::v1 as pb;
use kronik_sched::{Node, NodeConfig, start_local};
use tokio::runtime::Runtime;

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");
const ROOM_BARE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/room-bare.wasm"
);

struct Proc {
    rt: Runtime,
    node: Arc<Node>,
}

fn start(dir: &Path) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let config = NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        };
        start_local(env, dir, config).await.unwrap()
    });
    Proc { rt, node }
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

impl Proc {
    fn deploy(
        &self,
        path: &str,
        dry_run: bool,
    ) -> Result<kronik_sched::DeployResult, kronik_core::error::ApiError> {
        let bytes = std::fs::read(path).unwrap();
        let owner = self.node.local_operator_authority().unwrap();
        self.rt
            .block_on(self.node.deploy(&bytes, audit(), dry_run, owner))
    }
}

fn version(kind: &str, routes: &[(&str, &str)]) -> pb::KindVersion {
    pb::KindVersion {
        kind: kind.into(),
        manifest: Some(pb::Manifest {
            kind: kind.into(),
            schema_version: 0,
            routes: routes
                .iter()
                .map(|(method, pattern)| pb::Route {
                    method: (*method).into(),
                    pattern: (*pattern).into(),
                })
                .collect(),
            capabilities: vec![],
        }),
        ..Default::default()
    }
}

/// ADR 0113: a kind with WebSocket or SSE routes needs the
/// `connection-handler` export; deploy (and its dry run) refuse one
/// without it and change nothing. The room guest, which has it, deploys.
#[test]
fn connection_routes_need_the_connection_export() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    for dry_run in [true, false] {
        let err = p.deploy(ROOM_BARE, dry_run).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
        assert_eq!(
            err.message,
            "kind room declares WebSocket or SSE routes but its component does not export \
             kronik:actor/connection-handler; build it with an SDK from v0.5"
        );
        assert!(!p.node.kind_exists("room"));
    }
    let deployed = p.deploy(ROOM, false).unwrap();
    assert!(p.node.kind_exists("room"));
    let methods: Vec<&str> = deployed
        .manifest
        .routes
        .iter()
        .map(|r| r.method.as_str())
        .collect();
    assert_eq!(methods, ["WEBSOCKET", "SSE", "GET", "POST"]);
    assert!(
        deployed
            .warnings
            .iter()
            .any(|w| w.contains("connection:send-now")),
        "{:?}",
        deployed.warnings
    );
    let (_, routes) = p.node.routes();
    assert!(
        routes
            .iter()
            .any(|r| r.kind == "room" && r.method == "WEBSOCKET" && r.pattern == "/room/{key}/ws")
    );
}

/// M24 §2.5: a WEBSOCKET route conflicts with a WEBSOCKET route on the same
/// pattern, an SSE route with an SSE or GET route; a WEBSOCKET and a GET
/// route (or SSE and HEAD) may share a pattern.
#[test]
fn connection_routes_conflict_with_the_routes_that_answer_the_same_requests() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy(ROOM, false).unwrap();
    let check = |routes: &[(&str, &str)]| {
        p.node
            .check_set_routes(&[version("other", routes)])
            .err()
            .map(|e| e.code)
    };
    let conflict = Some(ErrorCode::RouteConflict);
    assert_eq!(check(&[("WEBSOCKET", "/room/{id}/ws")]), conflict);
    assert_eq!(check(&[("GET", "/room/{k}/events")]), conflict);
    assert_eq!(check(&[("SSE", "/room/{k}/{what}")]), conflict);
    assert_eq!(check(&[("SSE", "/room/{k}/events")]), conflict);
    assert_eq!(check(&[("GET", "/room/{k}/ws")]), None);
    assert_eq!(check(&[("HEAD", "/room/{k}/events")]), None);
    assert_eq!(check(&[("WEBSOCKET", "/room/{k}/events")]), None);
    assert_eq!(check(&[("POST", "/room/{k}/ws")]), None);
    // The room's own new code replaces its routes: no conflict with itself.
    assert_eq!(
        p.node
            .check_set_routes(&[version("room", &[("SSE", "/room/{key}/events")])])
            .err()
            .map(|e| e.code),
        None
    );
}
