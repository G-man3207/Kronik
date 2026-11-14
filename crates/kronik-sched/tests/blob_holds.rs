//! M26 slice B14: what actors hold, and blobs on the edges between them
//! (docs/design/m26-blobs.md §2-§5, ADR 0119). A reference is the
//! authorization: a hash learned as bytes gives nothing; a reference sent in
//! `message.blobs`, a timer or a call's reply can be read and retained.
//! `put`, `retain` and `release` change what the actor holds when the turn
//! commits, within `blob_bytes_per_actor`; holds and the rows that carry
//! blobs keep them through the collector; a hash in state keeps nothing; the
//! state rebuilt from the log equals the live one.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_blob::SweepOptions;
use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{BlobsConfig, Ingress, Node, NodeConfig, TurnResult, start_local};
use tokio::runtime::Runtime;

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

struct Proc {
    rt: Runtime,
    node: Arc<Node>,
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

/// A node with blobs, no history window and no collector loop of its own;
/// `media` deployed unless `deploy` is false (a restart).
fn start(dir: &Path, deploy: bool) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let mut storage = StorageConfig::new(dir.to_path_buf());
        storage.history = Duration::ZERO;
        storage.snapshot_interval = Duration::from_secs(3600);
        let config = NodeConfig {
            concurrency: 8,
            storage: Some(storage),
            segment_max_bytes: Some(4096),
            ingress_ttl: Duration::from_secs(3600),
            blobs: Some(BlobsConfig {
                gc_interval: Duration::ZERO,
                ..BlobsConfig::default()
            }),
            ..NodeConfig::default()
        };
        start_local(env, dir, config).await.unwrap()
    });
    let p = Proc { rt, node };
    if deploy {
        let bytes = std::fs::read(MEDIA).unwrap();
        let owner = p.node.local_operator_authority().unwrap();
        p.rt.block_on(p.node.deploy(&bytes, audit(), false, owner))
            .unwrap();
    }
    p
}

/// The `write` and `put` pattern's checksum over `size` bytes, as the
/// guest's `sum` answers it.
fn pattern_sum(size: u64) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0..size {
        h ^= u64::from(((i.wrapping_mul(31) + 7) % 251) as u8);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{size} {h:016x}")
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
            match self.node.ingress(actor, input, None).unwrap() {
                Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
                Ingress::Done(r) => *r,
            }
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

    /// Waits until no message to `media/<key>` waits in the mailbox: its
    /// turns have been applied.
    fn delivered(&self, key: &str) {
        // Up to 20 s.
        for _ in 0..2000 {
            let waiting: i64 = self
                .node
                .store()
                .db()
                .conn()
                .query_row(
                    "SELECT count(*) FROM mailbox WHERE to_kind = 'media' AND to_key = ?1",
                    [key],
                    |r| r.get(0),
                )
                .unwrap();
            if waiting == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("media/{key} never ran");
    }

    fn held(&self, key: &str, blob: &pb::BlobRef) -> bool {
        self.node
            .store()
            .db()
            .held("media", key, &blob.hash)
            .unwrap()
            .is_some()
    }

    fn exists(&self, blob: &pb::BlobRef) -> bool {
        let id = kronik_blob::BlobId::parse(&blob.hash).unwrap();
        self.node
            .blob_store()
            .unwrap()
            .object_path(&kronik_blob::Space::Main, &id)
            .exists()
    }

    fn set_quota(&self, bytes: u64) {
        let owner = self.node.local_operator_authority().unwrap();
        self.rt
            .block_on(self.node.set_limits(
                pb::Limits {
                    kind: "media".into(),
                    blob_bytes_per_actor: Some(bytes),
                    ..Default::default()
                },
                audit(),
                false,
                owner,
            ))
            .unwrap();
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

    fn records(&self) -> Vec<Record> {
        let mut out = Vec::new();
        self.rt
            .block_on(self.node.reader().read(1, self.node.applied_lsn(), |c| {
                out.push(c.record);
                Ok(())
            }))
            .unwrap();
        out
    }
}

/// Criterion 2: actor A puts a blob and sends its hash to B as message text;
/// B can neither read nor retain it nor answer with it, and an actor that
/// sends it fails with `BLOB_NOT_HELD`. Sent in `message.blobs`, B reads
/// it, retains it, and reads it again in a later turn.
#[test]
fn a_learned_hash_is_not_a_reference() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    let blob = blob_of(&p.ok("a", "put", "size=5000"));
    assert!(p.held("a", &blob));

    p.ok("a", "send", "to=b&op=remember-text&with=text");
    p.delivered("b");
    assert_eq!(p.ok("b", "forged-get", ""), "not-held");
    assert_eq!(p.ok("b", "forged-retain", ""), "not-held");
    let echo = p.run("b", "forged-echo", "", b"");
    assert_eq!(echo.outcome.error_code, "BLOB_NOT_HELD", "{echo:?}");
    // Sending a reference it learned as bytes fails the turn, and sends
    // nothing.
    let sent = p.run("b", "send", "to=c&op=retain", b"");
    assert!(!sent.committed());
    assert_eq!(sent.outcome.error_code, "BLOB_NOT_HELD", "{sent:?}");
    assert!(!p.held("b", &blob));

    // In message.blobs, the reference is B's to use: it retains it, and
    // reads it in a later turn.
    p.ok("a", "send", "to=b&op=retain");
    p.delivered("b");
    assert!(p.held("b", &blob));
    assert_eq!(p.ok("b", "held-sum", ""), pattern_sum(5000));
    // Now held, B may send it on: C receives it and retains it too.
    p.ok("b", "send", "to=c&op=retain");
    p.delivered("c");
    assert!(p.held("c", &blob));
}

/// `put` holds what it stores, `retain` of a held blob changes nothing,
/// `release` lets go only of the actor's own hold, and the quota counts the
/// distinct blobs the actor would hold: a blob it holds already adds
/// nothing, and a release makes room. A failed turn changes no hold.
#[test]
fn holds_follow_put_retain_release_and_the_quota() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    p.set_quota(10_000);
    let six = blob_of(&p.ok("a", "put", "size=6000"));
    assert!(p.held("a", &six));
    assert_eq!(p.node.store().db().held_bytes("media", "a").unwrap(), 6000);
    // The same bytes again: the same blob, held already.
    assert_eq!(blob_of(&p.ok("a", "put", "size=6000")), six);
    // Another 5000 bytes would make 11 000.
    assert_eq!(p.ok("a", "put", "size=5000"), "quota-exceeded");
    assert_eq!(p.ok("a", "release", ""), "released");
    assert!(!p.held("a", &six));
    let five = blob_of(&p.ok("a", "put", "size=5000"));
    assert!(p.held("a", &five));
    // Released and not retained since: another release is not-held.
    assert_eq!(p.ok("a", "release", ""), "released");
    assert_eq!(p.ok("a", "release", ""), "not-held");
    // B never held it.
    let body = format!("{} {}", five.hash, five.size);
    let r = p.run("b", "remember-text", "", body.as_bytes());
    assert!(r.committed());
    assert_eq!(p.ok("b", "release", ""), "not-held");

    // The records carry the net operations of committed turns only.
    let ops: Vec<(i32, String)> = p
        .records()
        .iter()
        .filter_map(Record::turn)
        .flat_map(|t| {
            t.blob_refs
                .iter()
                .map(|op| (op.kind, op.blob.as_ref().unwrap().hash.clone()))
        })
        .collect();
    use pb::blob_ref_op::Kind;
    assert_eq!(
        ops,
        [
            (Kind::Retain as i32, six.hash.clone()),
            (Kind::Release as i32, six.hash.clone()),
            (Kind::Retain as i32, five.hash.clone()),
            (Kind::Release as i32, five.hash.clone()),
        ]
    );
}

/// Criterion 10: a hash in state keeps nothing, a hold does. Blob 1's only
/// mention once its record leaves retention is its hash in an actor's state;
/// blob 2 is held. Two passes delete 1 and keep 2.
#[test]
fn bytes_in_state_keep_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    let one = blob_of(&p.ok("b", "put", "size=2000"));
    assert_eq!(p.ok("b", "release", ""), "released");
    let text = format!("{} {}", one.hash, one.size);
    assert!(p.run("c", "remember-text", "", text.as_bytes()).committed());
    let two = blob_of(&p.ok("a", "put", "size=3000"));
    p.compact();
    p.collect();
    assert!(!p.exists(&one));
    assert!(p.exists(&two));
    assert_eq!(p.ok("a", "held-sum", ""), pattern_sum(3000));
    // The state still has blob 1's hash; using it is not-held.
    assert_eq!(p.ok("c", "forged-get", ""), "not-held");
}

/// A timer's message carries a reference: while the timer waits, it keeps
/// the blob through retention and passes; its turn receives the reference,
/// retains it and reads the bytes.
#[test]
fn a_timer_carries_a_blob_through_retention() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    let blob = blob_of(&p.ok("a", "put", "size=4000"));
    p.ok("a", "schedule", "delay=1500&op=retain");
    assert_eq!(p.ok("a", "release", ""), "released");
    assert!(!p.held("a", &blob));
    p.compact();
    p.collect();
    assert!(p.exists(&blob), "the timer keeps it");
    // Up to 20 s.
    let mut waited = 0;
    while !p.held("a", &blob) {
        waited += 1;
        assert!(waited < 1000, "the timer never retained it");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(p.ok("a", "held-sum", ""), pattern_sum(4000));
}

/// A call carries references both ways: the callee receives the message's
/// blob, its reply's blob is the caller's to retain, and the call's effect
/// record lists both; the callee's saved outcome pins its reply's.
#[test]
fn a_call_and_its_reply_carry_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    let theirs = blob_of(&p.ok("b", "put", "size=1500"));
    let mine = blob_of(&p.ok("a", "put", "size=2500"));
    // B replies with the blob it received; A calls with its own.
    assert_eq!(
        p.ok("a", "call", "to=b&op=reply"),
        format!("reply blob {} {}", mine.hash, mine.size)
    );
    // C calls B, which replies with its stored blob; C retains it.
    p.ok("b", "put", "size=1500");
    assert_eq!(
        p.ok("c", "call", "to=b&op=reply&keep=1"),
        format!("reply blob {} {} retained", theirs.hash, theirs.size)
    );
    assert!(p.held("c", &theirs));
    assert_eq!(p.ok("c", "held-sum", ""), pattern_sum(1500));
    let calls: Vec<Vec<String>> = p
        .records()
        .iter()
        .filter_map(Record::turn)
        .flat_map(|t| t.effects.iter())
        .filter(|e| e.kind == "actor.call")
        .map(|e| e.blobs.iter().map(|b| b.hash.clone()).collect())
        .collect();
    assert_eq!(calls, [vec![mine.hash.clone()], vec![theirs.hash.clone()]]);
}

/// The state rebuilt from the log equals the live one, holds and pins
/// included, and its hash does not depend on whether `blob_refs` exists
/// for a state without holds.
#[test]
fn holds_and_pins_rebuild_from_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    let empty_hash = p.node.store().state_hash().unwrap();
    let blob = blob_of(&p.ok("a", "put", "size=3000"));
    p.ok("a", "send", "to=b&op=retain");
    p.delivered("b");
    p.ok("a", "schedule", "delay=3600000&op=retain");
    p.ok("c", "put", "size=1000");
    assert_eq!(p.ok("c", "release", ""), "released");
    assert!(p.held("b", &blob));
    let hash = p.node.store().state_hash().unwrap();
    assert_ne!(hash, empty_hash);
    let pins = |p: &Proc| -> Vec<(String, i64, String)> {
        let conn = p.node.store().db();
        let mut st = conn
            .conn()
            .prepare("SELECT hash, source, owner FROM blob_pins ORDER BY 1, 2, 3")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let live_pins = pins(&p);
    assert!(
        live_pins
            .iter()
            .any(|(h, s, _)| h == &blob.hash && *s == kronik_store::db::blob_source::TIMER),
        "{live_pins:?}"
    );
    drop(p);
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(dir.path().join("branches/main").join(f));
    }
    let q = start(dir.path(), false);
    assert_eq!(q.node.store().state_hash().unwrap(), hash);
    assert!(q.held("a", &blob) && q.held("b", &blob));
    assert_eq!(pins(&q), live_pins);
    assert_eq!(q.ok("b", "held-sum", ""), pattern_sum(3000));
}
