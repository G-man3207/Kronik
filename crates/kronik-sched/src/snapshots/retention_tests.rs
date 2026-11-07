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

        // The snapshot's retention pass raises the databases, then "crashes".
        CRASH_AFTER_RAISE.with(|c| c.set(true));
        // (The operator's `snapshot` runs on a task of its own: the hooks are
        // thread-local, so the pass is driven from this thread.)
        node.snapshot_configured("manual").await.unwrap();
        CRASH_AFTER_RAISE.with(|c| c.set(false));
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

        // The pass deletes one segment and "crashes".
        CRASH_AFTER_DELETE.with(|c| c.set(true));
        // (The operator's `snapshot` runs on a task of its own: the hooks are
        // thread-local, so the pass is driven from this thread.)
        node.snapshot_configured("manual").await.unwrap();
        CRASH_AFTER_DELETE.with(|c| c.set(false));
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
