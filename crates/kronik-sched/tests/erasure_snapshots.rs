//! Snapshots after erasure (docs/design/m8-privacy.md §6.6): the old snapshot
//! goes, a new one exists, and a rebuild from it plus the log does not bring
//! the subject's value back. Another subject's value from the same turn stays.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use common::{Proc, audit, msg, start_proc};
use kronik_proto::log::v1 as pb;
use kronik_sched::NodeConfig;

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

fn start(dir: &Path) -> Proc {
    start_proc(dir, NodeConfig::default())
}

#[test]
fn erasure_replaces_older_snapshots_and_a_rebuild_drops_the_subject() {
    let dir = tempfile::tempdir().unwrap();
    let erasure_lsn = {
        let p = start(dir.path());
        let wasm = std::fs::read(COUNTER).unwrap();
        let owner = || p.node.local_operator_authority().unwrap();
        p.rt.block_on(p.node.deploy(&wasm, audit(), false, owner()))
            .unwrap();
        let actor = kronik_core::ids::ActorRef::parse("counter/a").unwrap();
        let turn =
            p.rt.block_on(
                p.node
                    .send(actor, msg("subject", ""), audit(), false, owner()),
            )
            .unwrap()
            .unwrap();
        assert!(turn.committed());
        let old = p.rt.block_on(p.node.snapshot("manual", owner())).unwrap();
        let old_dir = dir
            .path()
            .join("snapshots/main")
            .join(format!("{:020}", old.lsn));
        assert!(old_dir.join("manifest.json").is_file());

        let done =
            p.rt.block_on(p.node.erase_subject("user:1", audit(), false, owner()))
                .unwrap();
        assert!(done.complete_after_ms > 0);
        assert!(!old_dir.exists(), "the pre-erasure snapshot should be gone");
        let snaps = p.node.snapshots().unwrap();
        assert!(
            snaps
                .iter()
                .any(|m| m.lsn >= done.lsn.unwrap() && m.reason == "erasure"),
            "no snapshot at or after the erasure: {snaps:?}"
        );
        assert!(
            snaps.iter().all(|m| m.lsn >= done.lsn.unwrap()),
            "a snapshot older than the erasure survived: {snaps:?}"
        );
        done.lsn.unwrap()
    };

    // Rebuild from the remaining snapshot plus the log.
    std::fs::remove_file(dir.path().join("branches/main/state.db")).unwrap();
    let _ = std::fs::remove_file(dir.path().join("branches/main/state.db-wal"));
    let _ = std::fs::remove_file(dir.path().join("branches/main/state.db-shm"));
    let _ = std::fs::remove_dir_all(dir.path().join("branches/main/sql"));
    let p = start(dir.path());
    let s = p
        .node
        .store()
        .db()
        .kv_get_written("counter", "a", "s")
        .unwrap()
        .map(|(s, _)| s);
    let t = p
        .node
        .store()
        .db()
        .kv_get_written("counter", "a", "t")
        .unwrap()
        .map(|(t, _)| t);
    assert!(s.is_none(), "user:1's value came back: {s:?}");
    let t = t.expect("user:2's value from the same turn");
    assert_eq!(t.subject.as_deref(), Some("user:2"));
    match &t.value {
        Some(pb::sealable::Value::Plain(b)) => assert_eq!(b, b"also personal"),
        other => panic!("user:2's value is not plain: {other:?}"),
    }
    assert!(p.node.applied_lsn() >= erasure_lsn);
}
