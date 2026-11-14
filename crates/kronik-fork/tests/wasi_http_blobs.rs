//! M25 slice B9 in a fork (docs/design/m25-streaming-bodies.md §7.6, §9):
//! a turn that sent a 3 MiB request body through `wasi:http`, spooled into
//! a blob, and read its echo, a blob response, back through the body's
//! stream replays without divergence, in both modes: the fork's guest
//! spools the same body into the fork's space, the replay serves the
//! recorded response, and the guest reads production's blob frame by frame.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::proposal::Proposals;
use kronik_proto::log::v1 as pb;
use kronik_sched::{BlobsConfig, NodeConfig};

/// An HTTP peer that answers every request with its body; counts them.
fn echo() -> (String, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let served = Arc::new(AtomicUsize::new(0));
    let count = served.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let count = count.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let (mut head, mut line) = (String::new(), String::new());
                while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                    head.push_str(&line);
                    line.clear();
                }
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let mut stream = stream;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(&body);
            });
        }
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
        p.rt.block_on(props.create_fork(
            Some(name.into()),
            fork_at,
            false,
            audit(),
            false,
            p.owner(),
        ))
        .unwrap();
        p.rt.block_on(props.fork_replay(
            name,
            None,
            DiffOptions {
                mode,
                ..DiffOptions::default()
            },
            None,
            p.owner(),
        ))
        .unwrap();
        let diff: serde_json::Value =
            serde_json::from_slice(&p.rt.block_on(props.diff(name, false, false)).unwrap())
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
