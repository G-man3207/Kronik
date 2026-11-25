//! M26 slice B16: what keeps a blob, and why one has nothing
//! (docs/design/m26-blobs.md §6.1, §6.6; criteria 5 and 11). The collector's
//! dry run lists exactly the blob files without a root, each with its
//! reason: `loose`, `released` (with the actor that released it) or
//! `out-of-retention`; held blobs, a timer's blob and a blob a kept snapshot
//! held are kept, and `kronik blobs inspect` names what keeps each. The
//! pins checked against the rows they mirror (`--verify`) show no drift, and
//! a pin the index lost or one that no row accounts for is drift.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{Proc, start_proc, wait_turn};
use kronik_blob::SweepOptions;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{BlobsConfig, NodeConfig, TurnResult};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

/// A node with blobs, no history window and no collector loop of its own;
/// `media` deployed unless `deploy` is false (a restart).
fn start(dir: &Path, deploy: bool) -> Proc {
    let mut storage = StorageConfig::new(dir.to_path_buf());
    storage.history = Duration::ZERO;
    storage.snapshot_interval = Duration::from_secs(3600);
    let p = start_proc(
        dir,
        NodeConfig {
            concurrency: 8,
            storage: Some(storage),
            segment_max_bytes: Some(4096),
            ingress_ttl: Duration::from_secs(3600),
            blobs: Some(BlobsConfig {
                gc_interval: Duration::ZERO,
                ..BlobsConfig::default()
            }),
            ..NodeConfig::default()
        },
    );
    if deploy {
        p.deploy_file(MEDIA);
    }
    p
}

fn blob_of(answer: &str) -> pb::BlobRef {
    let mut words = answer.split(' ');
    assert_eq!(words.next(), Some("blob"), "{answer}");
    pb::BlobRef {
        hash: words.next().unwrap().into(),
        size: words.next().unwrap().parse().unwrap(),
        subject: None,
        key_version: 0,
    }
}

impl Proc {
    /// Runs `op` on `media/<key>` over HTTP with an inline body.
    fn run(&self, key: &str, op: &str, query: &str, body: &[u8]) -> TurnResult {
        let input = pb::HttpInput {
            method: "POST".into(),
            path: format!("/media/{key}/{op}"),
            query: query.into(),
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(body.to_vec())),
                })),
            }),
            ..Default::default()
        };
        self.rt.block_on(async {
            let actor = ActorRef::parse(&format!("media/{key}")).unwrap();
            wait_turn(self.node.ingress(actor, input, None).unwrap())
                .await
                .unwrap()
        })
    }

    /// [`Proc::run`] of a turn that commits; its text answer.
    fn ok(&self, key: &str, op: &str, query: &str) -> String {
        let r = self.run(key, op, query, b"");
        assert!(r.committed(), "{op}?{query}: {r:?}");
        match &r.outcome.output {
            Some(pb::outcome::Output::Http(h)) => {
                match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                    Some(pb::body::Value::Inline(s)) => match &s.value {
                        Some(pb::sealable::Value::Plain(b)) => {
                            String::from_utf8_lossy(b).into_owned()
                        }
                        other => panic!("{other:?}"),
                    },
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
    }

    fn exists(&self, blob: &pb::BlobRef) -> bool {
        let id = kronik_blob::BlobId::parse(&blob.hash).unwrap();
        self.node
            .blob_store()
            .unwrap()
            .object_path(&kronik_blob::Space::Main, &id)
            .exists()
    }

    /// Turns that roll segments (4 KiB each), then a snapshot, a turn in a
    /// later millisecond than every turn so far and a retention pass: with
    /// `history` 0 the closed segments before the snapshot leave the log.
    fn compact(&self) {
        for i in 0..60 {
            self.ok("z", "info", &format!("n={i}"));
        }
        self.rt
            .block_on(
                self.node
                    .snapshot("manual", self.node.local_operator_authority().unwrap()),
            )
            .unwrap();
        let hwm = self.node.store().db().time_hwm().unwrap();
        while self.node.store().db().time_hwm().unwrap() <= hwm {
            std::thread::sleep(Duration::from_millis(2));
            self.ok("z", "info", "");
        }
        self.node
            .compact(self.node.storage_config().unwrap())
            .unwrap();
    }

    /// Two immediate passes of the collector.
    fn collect(&self) {
        for _ in 0..2 {
            self.rt
                .block_on(self.node.blob_gc(SweepOptions {
                    immediate: true,
                    ..Default::default()
                }))
                .unwrap();
        }
    }
}

impl Proc {
    /// The blob of a turn's HTTP answer whose body is a blob.
    fn answered_blob(&self, key: &str, op: &str, query: &str) -> pb::BlobRef {
        let r = self.run(key, op, query, b"");
        assert!(r.committed(), "{op}?{query}: {r:?}");
        match &r.outcome.output {
            Some(pb::outcome::Output::Http(h)) => {
                match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                    Some(pb::body::Value::Blob(b)) => b.clone(),
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
    }

    fn plan(&self) -> Vec<kronik_sched::blob_gc::Unrooted> {
        self.rt
            .block_on(self.node.blob_gc(SweepOptions {
                dry_run: true,
                ..Default::default()
            }))
            .unwrap()
            .unwrap()
            .unrooted
    }

    fn roots(&self, blob: &pb::BlobRef) -> Vec<kronik_sched::blob_gc::BlobRoot> {
        self.rt
            .block_on(self.node.blob_inspect(&blob.hash, false))
            .unwrap()
            .roots
    }

    fn drift(&self) -> Vec<kronik_store::db::PinDrift> {
        self.rt.block_on(self.node.blob_pin_drift()).unwrap()
    }
}

/// The `write` pattern's hash over `size` bytes: what `write-discard`
/// writes and drops.
fn pattern_hash(size: u64) -> String {
    let bytes: Vec<u8> = (0..size)
        .map(|i| ((i.wrapping_mul(31) + 7) % 251) as u8)
        .collect();
    format!("b3:{}", blake3::hash(&bytes).to_hex())
}

/// Criteria 11 and 5: once the records of the first four leave retention,
/// the dry run lists exactly the files without a root, with why; held
/// blobs, a timer's blob and a blob a kept snapshot held stay, and inspect
/// names what keeps each. Two passes delete exactly the listed files.
#[test]
fn the_dry_run_lists_exactly_the_blobs_without_roots_and_why() {
    use kronik_sched::blob_gc::{BlobRoot, UnrootedReason};
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    // Held, then released.
    let released = blob_of(&p.ok("r", "put", "size=3000"));
    assert_eq!(p.ok("r", "release", ""), "released");
    // An answer: referenced by its record only.
    let answered = p.answered_blob("o", "write", "size=4000");
    // Held.
    let held = blob_of(&p.ok("h", "put", "size=5000"));
    // In a timer a day away, after its holder released it.
    let timed = blob_of(&p.ok("t", "put", "size=6000"));
    assert_eq!(p.ok("t", "schedule", "delay=86400000&op=info"), "scheduled");
    assert_eq!(p.ok("t", "release", ""), "released");
    // Held when a snapshot was taken, released after it.
    let snapped = blob_of(&p.ok("s", "put", "size=7000"));
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.snapshot("while s holds it", owner))
        .unwrap();
    assert_eq!(p.ok("s", "release", ""), "released");

    // Within retention, their records keep the released blob and the
    // answer.
    for blob in [&released, &answered] {
        assert!(
            p.roots(blob)
                .iter()
                .any(|r| matches!(r, BlobRoot::Log { .. })),
            "{:?}",
            p.roots(blob)
        );
    }

    // The retention pass of `compact` wakes a collector pass; a blob
    // written and dropped after it has never been a candidate.
    p.compact();
    assert_eq!(p.ok("l", "write-discard", "size=1000"), "discarded");
    let loose = pattern_hash(1000);
    let mut plan = p.plan();
    plan.sort_by(|a, b| a.hash.cmp(&b.hash));
    let mut expected = vec![
        (loose.clone(), UnrootedReason::Loose, None),
        (
            released.hash.clone(),
            UnrootedReason::Released,
            Some("media/r".to_owned()),
        ),
        (answered.hash.clone(), UnrootedReason::OutOfRetention, None),
    ];
    expected.sort();
    let got: Vec<(String, UnrootedReason, Option<String>)> = plan
        .iter()
        .map(|u| {
            (
                u.hash.clone(),
                u.reason,
                u.released_by.as_ref().map(|(actor, _)| actor.clone()),
            )
        })
        .collect();
    assert_eq!(got, expected, "{plan:#?}");

    // What keeps the others.
    assert!(
        p.roots(&held).iter().any(|r| matches!(
            r,
            BlobRoot::Held { actor, .. } if actor == "media/h"
        )),
        "{:?}",
        p.roots(&held)
    );
    let timer_roots = p.roots(&timed);
    assert!(
        timer_roots.iter().any(|r| matches!(
            r,
            BlobRoot::Pin {
                source: "timer",
                ..
            }
        )),
        "{timer_roots:?}"
    );
    assert!(
        !timer_roots
            .iter()
            .any(|r| matches!(r, BlobRoot::Held { .. })),
        "{timer_roots:?}"
    );
    assert!(
        p.roots(&snapped)
            .iter()
            .any(|r| matches!(r, BlobRoot::Snapshot { .. })),
        "{:?}",
        p.roots(&snapped)
    );
    assert!(p.roots(&released).is_empty());
    assert!(p.drift().is_empty(), "{:?}", p.drift());

    // Two passes delete exactly the listed files.
    p.collect();
    let dropped = pb::BlobRef {
        hash: loose,
        ..Default::default()
    };
    for gone in [&released, &answered, &dropped] {
        assert!(!p.exists(gone), "{}", gone.hash);
    }
    for kept in [&held, &timed, &snapped] {
        assert!(p.exists(kept), "{}", kept.hash);
    }
    assert!(p.plan().is_empty(), "{:?}", p.plan());
}

/// `--verify`: the pins match the rows they mirror. A pin the index lost
/// is drift (`missing`: the collector could delete the blob under its
/// row), and so is an open turn's pin without its turn (`extra`: nothing
/// would ever delete it); a pin of a mailbox row that is gone waits for the
/// next retention pass, so it is not.
#[test]
fn pin_drift_is_found_against_the_rows() {
    use kronik_store::db::blob_source;
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    let timed = blob_of(&p.ok("t", "put", "size=6000"));
    assert_eq!(p.ok("t", "schedule", "delay=86400000&op=info"), "scheduled");
    assert!(p.drift().is_empty(), "{:?}", p.drift());

    let db = p.node.store().db();
    db.conn()
        .execute(
            "DELETE FROM blob_pins WHERE source = ?1",
            [blob_source::TIMER],
        )
        .unwrap();
    for (source, owner) in [
        (blob_source::MAILBOX, "gone"),
        (blob_source::OPEN_TURN, "closed"),
    ] {
        db.conn()
            .execute(
                "INSERT INTO blob_pins (hash, source, owner, lsn) VALUES (?1, ?2, ?3, 1)",
                rusqlite::params![timed.hash, source, owner],
            )
            .unwrap();
    }
    drop(db);
    let drift = p.drift();
    assert_eq!(drift.len(), 2, "{drift:#?}");
    let missing = drift.iter().find(|d| d.missing).unwrap();
    assert_eq!(missing.hash, timed.hash);
    assert_eq!(missing.source, blob_source::TIMER);
    assert!(
        missing.owner.starts_with("media\u{1f}t\u{1f}"),
        "{missing:?}"
    );
    let extra = drift.iter().find(|d| !d.missing).unwrap();
    assert_eq!(
        (extra.source, extra.owner.as_str()),
        (blob_source::OPEN_TURN, "closed")
    );
}
