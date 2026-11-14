//! M24 review M8: `kronik_connections_open` is kept as counters, not
//! recomputed over every live connection under the hub's lock; it still
//! counts the connections past their open turn, by kind and protocol. In a
//! test binary of its own: the metrics are global to the process.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::RecordingTransport;
use kronik_sched::{NodeConfig, start_local};

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

fn open_gauge() -> Option<f64> {
    kronik_metrics::render()
        .lines()
        .find(|l| {
            l.starts_with("kronik_connections_open{")
                && l.contains("kind=\"room\"")
                && l.contains("protocol=\"websocket\"")
        })
        .and_then(|l| l.rsplit(' ').next()?.parse().ok())
}

fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn the_open_gauge_counts_connections_past_their_open_turn() {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        start_local(env, dir.path(), NodeConfig::default())
            .await
            .unwrap()
    });
    let owner = node.local_operator_authority().unwrap();
    let audit = pb::Audit {
        token_id: "t".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    };
    rt.block_on(node.deploy(&std::fs::read(ROOM).unwrap(), audit, false, owner))
        .unwrap();
    let open = |user: &str| {
        let request = pb::HttpInput {
            method: "GET".into(),
            path: "/room/lobby/ws".into(),
            query: format!("user={user}"),
            params: vec![pb::Param {
                name: "key".into(),
                value: "lobby".into(),
                sealed_value: None,
            }],
            route: "/room/{key}/ws".into(),
            ..Default::default()
        };
        let (id, waiter) = node
            .connection_open(
                ActorRef::parse("room/lobby").unwrap(),
                request,
                pb::ConnectionProtocol::Websocket,
                None,
                None,
                false,
            )
            .unwrap();
        rt.block_on(waiter.wait()).unwrap();
        let t = RecordingTransport::attach(node.hub(), &id).unwrap();
        (id, t)
    };
    let (_a, ta) = open("ada");
    assert_eq!(open_gauge(), Some(1.0));
    let (_b, _tb) = open("bob");
    assert_eq!(open_gauge(), Some(2.0));
    ta.client_close(Some((1000, String::new())));
    until("the close", || open_gauge() == Some(1.0));
    assert_eq!(node.hub().live(), 1);
}
