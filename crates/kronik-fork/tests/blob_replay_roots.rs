//! M26 criterion 7 (slice B16, docs/design/m26-blobs.md §6.1, §6.3): a blob
//! that a replay in progress is reading is not cleaned away during the
//! replay. A proposal's isolated replay is parked
//! (`Proposals::with_test_gate`) before the root input that reads a blob
//! its actor held at the fork point and has released since; retention then
//! moves the log's start past every record that references the blob, and
//! two immediate passes of the collector run. The blob stays: the replay's
//! floor lease and its fork's roots keep it. Let go, the parked turn reads
//! it, and nothing diverges.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use kronik_blob::{BlobId, Space, SweepOptions};
use kronik_core::ids::ActorRef;
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::proposal::{Proposals, ProposeRequest};
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{BlobsConfig, Ingress, NodeConfig, TurnResult};

fn http(op: &str, query: &str) -> pb::HttpInput {
    pb::HttpInput {
        method: "POST".into(),
        path: format!("/media/a/{op}"),
        query: query.into(),
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(Vec::new())),
            })),
        }),
        route: "/media/{key}/{op}".into(),
        ..Default::default()
    }
}

fn ingress(p: &Proc, input: pb::HttpInput) -> TurnResult {
    p.rt.block_on(async {
        match p
            .node
            .ingress(ActorRef::parse("media/a").unwrap(), input, None)
            .unwrap()
        {
            Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
            Ingress::Done(r) => *r,
        }
    })
}

/// The text answer of a turn that committed.
fn ok(p: &Proc, op: &str, query: &str) -> String {
    let r = ingress(p, http(op, query));
    assert!(r.committed(), "{op}: {r:?}");
    match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    other => panic!("{other:?}"),
                },
                other => panic!("not inline: {other:?}"),
            }
        }
        other => panic!("{other:?}: {r:?}"),
    }
}

/// The first LSN the main log still holds: its first segment's name.
fn log_start(dir: &std::path::Path) -> u64 {
    std::fs::read_dir(dir.join("branches/main/log"))
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".seg")?.parse::<u64>().ok()
        })
        .min()
        .unwrap()
}

#[test]
fn a_replay_in_progress_keeps_the_blobs_it_reads() {
    let dir = tempdir();
    // The proposal needs its fork point within retention (7 days);
    // retention then runs with no history at all.
    let storage = StorageConfig::new(dir.path().to_path_buf());
    let p = Proc::start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            storage: Some(storage.clone()),
            segment_max_bytes: Some(4096),
            blobs: Some(BlobsConfig {
                gc_interval: Duration::ZERO,
                ..BlobsConfig::default()
            }),
            ..NodeConfig::default()
        },
    );
    p.deploy("media");
    // media/a holds a blob at the fork point.
    let put = ok(&p, "put", "size=5000");
    let hash = put.split(' ').nth(1).unwrap().to_owned();
    let fork_at = p.settle();
    // After it, a turn reads the blob, and then the actor releases it.
    let sum = ok(&p, "held-sum", "");
    assert!(sum.starts_with("5000 "), "{sum}");
    assert_eq!(ok(&p, "release", ""), "released");
    let released_at = p.settle();

    // A proposal of the same code (a custom section makes it another
    // component), replayed in isolation from the fork point; parked before
    // its first root input, the read.
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_test_gate(gate.clone()),
    );
    let mut v2 = std::fs::read(guest("media")).unwrap();
    v2.extend_from_slice(&[0x00, 0x07, 0x04, b't', b'e', b's', b't', b'v', b'2']);
    let task = {
        let props = props.clone();
        let owner = p.owner();
        p.rt.spawn(async move {
            props
                .propose(
                    ProposeRequest {
                        wasm: vec![v2],
                        names: Vec::new(),
                        window_ms: None,
                        at: Some(fork_at),
                        options: DiffOptions {
                            mode: Mode::Isolated,
                            ..DiffOptions::default()
                        },
                        workers: Some(1),
                        audit: audit(),
                        dry_run: false,
                    },
                    owner,
                )
                .await
        })
    };
    let store = p.node.blob_store().unwrap().clone();
    for _ in 0..3000 {
        if store.leases().lowest_floor().is_some() {
            break;
        }
        assert!(
            !task.is_finished(),
            "{:?}",
            p.rt.block_on(task).unwrap().map(|_| ())
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        store.leases().lowest_floor(),
        Some(fork_at),
        "the replay's floor lease"
    );

    // Retention moves the log's start past every record that references
    // the blob: turns that roll segments, a snapshot, a later turn, a pass.
    for i in 0..60 {
        ok(&p, "info", &format!("n={i}"));
    }
    let owner = p.owner();
    p.rt.block_on(p.node.snapshot("manual", owner)).unwrap();
    let hwm = p.node.store().db().time_hwm().unwrap();
    while p.node.store().db().time_hwm().unwrap() <= hwm {
        std::thread::sleep(Duration::from_millis(2));
        ok(&p, "info", "");
    }
    p.node
        .compact(&StorageConfig {
            history: Duration::ZERO,
            ..storage
        })
        .unwrap();
    assert!(
        log_start(dir.path()) > released_at,
        "the log still holds the records that reference the blob"
    );

    // Two immediate passes: the blob stays.
    for _ in 0..2 {
        p.rt.block_on(p.node.blob_gc(SweepOptions {
            immediate: true,
            ..Default::default()
        }))
        .unwrap();
    }
    let id = BlobId::parse(&hash).unwrap();
    assert!(
        store.object_path(&Space::Main, &id).exists(),
        "the collector deleted a blob a replay in progress reads"
    );

    // Let go: the parked turn reads it, and nothing diverges.
    gate.add_permits(1 << 20);
    let (proposal, _) = p.rt.block_on(task).unwrap().unwrap();
    let diff: serde_json::Value = serde_json::from_slice(
        &p.rt
            .block_on(props.diff(&proposal.id, false, false))
            .unwrap(),
    )
    .unwrap();
    let summary = &diff["summary"];
    assert_eq!(summary["divergent_turns"], 0, "{diff:#}");
    assert!(summary["replayed"].as_u64().unwrap() >= 2, "{diff:#}");
}
