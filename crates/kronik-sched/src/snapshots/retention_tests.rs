//! The order of a compaction pass: raise the idle actor databases,
//! make the raise durable, then delete. The pass ends with an error where a
//! crash would, through the hooks of [`super`].

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;

use super::*;
use kronik_core::env::Env;
use kronik_core::ids::ActorRef;

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const NOTES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/notes.wasm");

fn env() -> Env {
    Env::real(tokio::runtime::Handle::current())
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn message(name: &str, text: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(text.as_bytes().to_vec())),
        }),
        blobs: Vec::new(),
        retained_compensation_source: None,
    }
}

/// A node that compacts as soon as it can: no history, small segments.
async fn start(dir: &Path) -> Arc<Node> {
    let mut storage = StorageConfig::new(dir.to_path_buf());
    storage.history = Duration::ZERO;
    storage.snapshot_interval = Duration::from_secs(3600);
    crate::start_local(
        env(),
        dir,
        crate::NodeConfig {
            concurrency: 8,
            storage: Some(storage),
            segment_max_bytes: Some(4096),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

async fn send(node: &Node, actor: &str, name: &str, text: &str) -> crate::TurnResult {
    let r = node
        .send(
            ActorRef::parse(actor).unwrap(),
            message(name, text),
            audit(),
            false,
            node.local_operator_authority().unwrap(),
        )
        .await
        .unwrap()
        .expect("a turn");
    assert!(r.committed(), "{r:?}");
    r
}

fn reply(r: &crate::TurnResult) -> String {
    match &r.outcome.output {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// `notes/n` gets its only SQL change; other actors then keep the log
/// rolling and time moving. Returns the LSN of the note.
async fn history(node: &Node) -> Lsn {
    let owner = || node.local_operator_authority().unwrap();
    node.deploy(&std::fs::read(COUNTER).unwrap(), audit(), false, owner())
        .await
        .unwrap();
    node.deploy(&std::fs::read(NOTES).unwrap(), audit(), false, owner())
        .await
        .unwrap();
    send(node, "notes/n", "add", "hello").await;
    for i in 0..80 {
        send(node, &format!("counter/k{}", i % 5), "increment", "").await;
        if i % 20 == 19 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    node.store()
        .db()
        .actor("notes", "n")
        .unwrap()
        .unwrap()
        .last_lsn
}

/// One turn of `counter/tick` in a later millisecond than every turn so far.
/// With `history` 0 the window holds the fork points of the newest
/// millisecond, so a snapshot becomes the window's base only once it is
/// older than that: a fork point of its own millisecond may lie before it.
async fn age(node: &Node) {
    let before = node.store().db().time_hwm().unwrap();
    loop {
        tokio::time::sleep(Duration::from_millis(2)).await;
        send(node, "counter/tick", "increment", "").await;
        if node.store().db().time_hwm().unwrap() > before {
            return;
        }
    }
}

/// One life of a node: the runtime is dropped when it ends, which stops the
/// node's tasks and closes its databases, as a kill does. (The hooks are
/// thread-local: the test thread polls everything the hooks reach.)
fn life<T>(future: impl std::future::Future<Output = T>) -> T {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let out = runtime.block_on(future);
    drop(runtime);
    out
}

/// Nothing to repair, and the data is there.
fn assert_hello_survives(dir: &Path) {
    assert_eq!(prepare_state(dir, "main").unwrap(), None);
    life(async {
        let node = start(dir).await;
        let list = reply(&send(&node, "notes/n", "list", "").await);
        assert_eq!(list.matches("hello").count(), 1, "{list}");
    });
}

#[test]
fn a_crash_after_the_raise_deletes_nothing_and_the_next_pass_finishes() {
    let dir = tempfile::tempdir().unwrap();
    life(async {
        let node = start(dir.path()).await;
        let note = history(&node).await;
        let storage = node.storage_config().unwrap().clone();
        assert_eq!(node.log_first(&storage).unwrap(), 1);

        // A snapshot covers the traffic, and a later turn makes it the
        // window's base. A retention pass raises the databases, then
        // "crashes". (The hooks are thread-local, so the pass is driven from
        // this thread.)
        node.snapshot_configured("manual").await.unwrap();
        age(&node).await;
        CRASH_AFTER_RAISE.with(|c| c.set(true));
        let crashed = node.compact(&storage);
        CRASH_AFTER_RAISE.with(|c| c.set(false));
        assert!(crashed.is_err());
        // Nothing was deleted, and the raise is there already.
        assert_eq!(node.log_first(&storage).unwrap(), 1);
        assert!(
            node.store().replay_from().unwrap() > note,
            "the idle database must be raised before the first delete"
        );

        // The next pass deletes.
        let first = node.compact(&storage).unwrap();
        assert!(first > note + 1, "first {first}, note {note}");
    });
    assert_hello_survives(dir.path());
}

#[test]
fn a_crash_after_a_delete_leaves_a_log_every_database_reaches() {
    let dir = tempfile::tempdir().unwrap();
    let (note, first) = life(async {
        let node = start(dir.path()).await;
        let note = history(&node).await;
        let storage = node.storage_config().unwrap().clone();
        let log = dir.path().join("branches/main/log");
        let before = kronik_log::segment_starts(&log).unwrap();
        assert!(before.len() > 3, "{before:?}");

        // A snapshot covers the traffic, and a later turn makes it the
        // window's base. The pass deletes one segment and "crashes". (The
        // hooks are thread-local, so the pass is driven from this thread.)
        node.snapshot_configured("manual").await.unwrap();
        age(&node).await;
        CRASH_AFTER_DELETE.with(|c| c.set(true));
        let crashed = node.compact(&storage);
        CRASH_AFTER_DELETE.with(|c| c.set(false));
        assert!(crashed.is_err());
        let first = node.log_first(&storage).unwrap();
        assert_eq!(first, before[1], "exactly the first segment is gone");
        assert!(
            node.store().replay_from().unwrap() + 1 >= first,
            "replay would start at {} but the log starts at {first}",
            node.store().replay_from().unwrap()
        );
        (note, first)
    });
    assert_hello_survives(dir.path());

    // And the rest of the pass, on the restarted node.
    life(async {
        let node = start(dir.path()).await;
        let storage = node.storage_config().unwrap().clone();
        let later = node.compact(&storage).unwrap();
        assert!(later >= first && later > note + 1, "{later} {first} {note}");
    });
    assert_hello_survives(dir.path());
}

/// The snapshot markers among the records after `after`.
async fn markers_after(node: &Node, after: Lsn) -> usize {
    let mut markers = 0;
    let upto = node.applied_lsn();
    if upto > after {
        node.reader()
            .read(after + 1, upto, |c| {
                markers += usize::from(matches!(c.record, Record::SnapshotMarker(_)));
                Ok(())
            })
            .await
            .unwrap();
    }
    markers
}

/// A snapshot is durable before its marker, and so before a compaction may
/// delete what it replaces: every file and directory of the copy is fsynced
/// before the copy is renamed into place, the snapshots directory after the
/// rename, and only then is the manifest written. When that last fsync
/// fails, the snapshot fails: no marker, nothing listed. (v0.4.1 never
/// fsynced the snapshots directory, nor the copy's directories.)
#[test]
fn a_snapshot_is_durable_before_its_marker() {
    use crate::durable::test_ops::{Op, watch};
    let dir = tempfile::tempdir().unwrap();
    life(async {
        let node = start(dir.path()).await;
        history(&node).await;
        let branch = node.branch().to_owned();
        let root = snapshots_dir(dir.path(), &branch);

        let applied = node.applied_lsn();
        let listed = list(dir.path(), &branch).len();
        let failing = watch(&root, {
            let root = root.clone();
            move |op| *op == Op::Sync(root.clone())
        });
        let refused = node.snapshot_configured("manual").await;
        drop(failing);
        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(list(dir.path(), &branch).len(), listed);
        assert_eq!(markers_after(&node, applied).await, 0);

        let watching = watch(&root, |_| false);
        let manifest = node.snapshot_configured("manual").await.unwrap();
        let ops = watching.ops();
        drop(watching);
        let at = |want: &dyn Fn(&Op) -> bool| ops.iter().position(want);
        let dest = root.join(dir_name(manifest.lsn));
        let renamed = at(&|op| matches!(op, Op::Rename(_, to) if *to == dest))
            .unwrap_or_else(|| panic!("no rename into {}: {ops:#?}", dest.display()));
        let Op::Rename(tmp, _) = ops[renamed].clone() else {
            unreachable!()
        };
        for file in &manifest.files {
            let synced = at(&|op| *op == Op::Sync(tmp.join(&file.path)));
            assert!(
                synced.is_some_and(|s| s < renamed),
                "{} is not synced before the rename: {ops:#?}",
                file.path
            );
        }
        let tmp_synced = at(&|op| *op == Op::Sync(tmp.clone()));
        assert!(tmp_synced.is_some_and(|s| s < renamed), "{ops:#?}");
        let root_synced = ops[renamed..]
            .iter()
            .position(|op| *op == Op::Sync(root.clone()))
            .map(|p| p + renamed);
        let manifest_renamed =
            at(&|op| matches!(op, Op::Rename(_, to) if *to == dest.join("manifest.json")));
        assert!(
            root_synced.is_some() && manifest_renamed.is_some() && root_synced < manifest_renamed,
            "{ops:#?}"
        );
        assert_eq!(ops.last(), Some(&Op::Sync(dest.clone())), "{ops:#?}");
    });
}
