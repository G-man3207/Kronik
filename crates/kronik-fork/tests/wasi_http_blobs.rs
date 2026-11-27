//! M25 slice B9 in a fork (docs/design/m25-streaming-bodies.md §7.6, §9):
//! a turn that sent a 3 MiB request body through `wasi:http`, spooled into
//! a blob, and read its echo, a blob response, back through the body's
//! stream replays without divergence, in both modes: the fork's guest
//! spools the same body into the fork's space, the replay serves the
//! recorded response, and the guest reads production's blob frame by frame.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::proposal::Proposals;
use kronik_proto::log::v1 as pb;
use kronik_sched::{BlobsConfig, NodeConfig};

/// An HTTP peer that answers every request with its body; counts them.
fn echo() -> (String, Arc<AtomicUsize>) {
    let served = Arc::new(AtomicUsize::new(0));
    let count = served.clone();
    let addr = common::http::serve(move |req, stream| {
        count.fetch_add(1, Ordering::SeqCst);
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            req.body.len()
        );
        let _ = stream.write_all(&req.body);
    });
    (addr, served)
}

#[test]
fn a_fork_replays_a_wasi_http_exchange_of_blob_bodies_without_divergence() {
    let dir = tempdir();
    let p = Proc::start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        },
    );
    p.deploy("counter-wasi-http-blobs");
    let owner = p.owner();
    p.rt.block_on(p.node.set_limits(
        pb::Limits {
            kind: "counter".into(),
            blob_threshold_bytes: Some(65_536),
            fuel: Some(2_000_000_000),
            ..Default::default()
        },
        audit(),
        false,
        owner.clone(),
    ))
    .unwrap();
    p.rt.block_on(p.node.grant(
        "counter",
        "http:127.0.0.1",
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        owner,
    ))
    .unwrap();
    let (addr, served) = echo();
    let fork_at = p.settle();
    let r = p.send(
        "counter/a",
        "wbig",
        &format!("POST http://{addr}/echo\nsize={}", 3u64 << 20),
    );
    assert!(r.committed(), "{:?}", r.outcome);
    let Some(pb::outcome::Output::Reply(m)) = &r.outcome.output else {
        panic!("{:?}", r.outcome)
    };
    let Some(pb::sealable::Value::Plain(reply)) = m.body.as_ref().and_then(|b| b.value.as_ref())
    else {
        panic!("{m:?}")
    };
    let reply = String::from_utf8_lossy(reply).into_owned();
    assert!(reply.starts_with("200 "), "{reply}");
    p.settle();
    assert_eq!(served.load(Ordering::SeqCst), 1);

    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    for (name, mode) in [("both", Mode::Both), ("isolated", Mode::Isolated)] {
        new_fork(&p, &props, name, fork_at, false, None);
        let diff = serde_json::from_slice::<serde_json::Value>(&replay_fork(
            &p,
            &props,
            name,
            DiffOptions {
                mode,
                ..DiffOptions::default()
            },
            None,
        ))
        .unwrap();
        let summary = &diff["summary"];
        assert_eq!(summary["changed"], false, "{name}: {diff:#}");
        assert_eq!(summary["divergent_turns"], 0, "{name}: {diff:#}");
        assert_eq!(summary["unverifiable"], 0, "{name}: {diff:#}");
    }
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the replays served the recording"
    );
}
