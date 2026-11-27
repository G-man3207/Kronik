//! M24 review M8: `kronik_connections_open` is kept as counters, not
//! recomputed over every live connection under the hub's lock; it still
//! counts the connections past their open turn, by kind and protocol. In a
//! test binary of its own: the metrics are global to the process.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{audit, open_request, start_proc};
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::NodeConfig;
use kronik_sched::connections::RecordingTransport;

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
    let p = start_proc(dir.path(), NodeConfig::default());
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(ROOM).unwrap(), audit(), false, owner),
    )
    .unwrap();
    let open = |user: &str| {
        let request = open_request("lobby", &format!("user={user}"));
        let (id, waiter) = p
            .node
            .connection_open(
                ActorRef::parse("room/lobby").unwrap(),
                request,
                pb::ConnectionProtocol::Websocket,
                None,
                None,
                false,
            )
            .unwrap();
        p.rt.block_on(waiter.wait()).unwrap();
        let t = RecordingTransport::attach(p.node.hub(), &id).unwrap();
        (id, t)
    };
    let (_a, ta) = open("ada");
    assert_eq!(open_gauge(), Some(1.0));
    let (_b, _tb) = open("bob");
    assert_eq!(open_gauge(), Some(2.0));
    ta.client_close(Some((1000, String::new())));
    until("the close", || open_gauge() == Some(1.0));
    assert_eq!(p.node.hub().live(), 1);
}
