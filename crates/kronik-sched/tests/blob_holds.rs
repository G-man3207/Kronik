//! M26 slice B14: what actors hold, and blobs on the edges between them
//! (docs/design/m26-blobs.md §2-§5, ADR 0119). A reference is the
//! authorization: a hash learned as bytes gives nothing; a reference sent in
//! `message.blobs`, a timer or a call's reply can be read and retained.
//! `put`, `retain` and `release` change what the actor holds when the turn
//! commits, within `blob_bytes_per_actor`; holds and the rows that carry
//! blobs keep them through the collector; a hash in state keeps nothing; the
//! state rebuilt from the log equals the live one.
//!
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

use common::{Proc, audit, msg, start_proc, wait_turn};
use kronik_blob::SweepOptions;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{BlobsConfig, NodeConfig, TurnResult};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

/// A node with blobs, no history window and no collector loop of its own;
/// `media` deployed unless `deploy` is false (a restart).
fn start(dir: &Path, deploy: bool) -> Proc {
    start_holding(dir, deploy, false)
}

/// [`start`]; with `hold_after_call`, a caller's turn stops for good after
/// its call has its answer, before it records it (a crash there).
fn start_holding(dir: &Path, deploy: bool, hold_after_call: bool) -> Proc {
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
            test_hold_after_call: hold_after_call,
            ..NodeConfig::default()
        },
    );
    if deploy {
        p.deploy_file(MEDIA);
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

/// The `write` pattern's hash over `size` bytes: what `write-discard`
/// writes and drops.
fn pattern_hash(size: u64) -> String {
    let bytes: Vec<u8> = (0..size)
        .map(|i| ((i.wrapping_mul(31) + 7) % 251) as u8)
        .collect();
    format!("b3:{}", blake3::hash(&bytes).to_hex())
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

/// The blob of the `call` operation's answer `reply blob <hash> <size>
/// retained`.
fn retained_reply(answer: &str) -> pb::BlobRef {
    blob_of(
        answer
            .strip_prefix("reply ")
            .and_then(|rest| rest.strip_suffix(" retained"))
            .unwrap_or_else(|| panic!("{answer}")),
    )
}

/// The text answer of a committed turn.
fn text_of(r: &TurnResult) -> String {
    match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    other => panic!("{other:?}"),
                },
                other => panic!("{other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

/// The recorded `actor.call` effects of `media/<key>`'s committed turns.
fn calls_of(records: &[Record], key: &str) -> Vec<pb::EffectRecord> {
    records
        .iter()
        .filter_map(Record::turn)
        .filter(|t| t.actor.as_ref().is_some_and(|a| a.key == key))
        .filter(|t| {
            t.outcome
                .as_ref()
                .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32)
        })
        .flat_map(|t| t.effects.iter().cloned())
        .filter(|e| e.kind == "actor.call")
        .collect()
}

/// The reply a recorded call effect gave its caller.
fn recorded_reply(call: &pb::EffectRecord) -> pb::Message {
    let Some(pb::sealable::Value::Plain(bytes)) =
        call.response.as_ref().and_then(|r| r.value.as_ref())
    else {
        panic!("{call:?}")
    };
    use prost::Message as _;
    pb::CallEffectResponse::decode(bytes.as_slice())
        .unwrap()
        .reply
        .unwrap_or_else(|| panic!("{call:?}"))
}

/// What a caller gets for a callee's HTTP answer whose body is `blob`: the
/// reply `http 200` with an empty body, and the blob as its one blob.
fn assert_blob_reply(call: &pb::EffectRecord, blob: &pb::BlobRef) {
    let reply = recorded_reply(call);
    assert_eq!(reply.name, "http 200", "{reply:?}");
    assert_eq!(reply.content_type, "", "{reply:?}");
    assert_eq!(
        reply.body.as_ref().and_then(|b| b.value.clone()),
        Some(pb::sealable::Value::Plain(Vec::new())),
        "{reply:?}"
    );
    assert_eq!(reply.blobs, std::slice::from_ref(blob), "{reply:?}");
    assert!(call.blobs.contains(blob), "the call lists it: {call:?}");
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

    /// Runs `op` on `media/<key>` over HTTP with `body`.
    fn run_with(&self, key: &str, op: &str, query: &str, body: pb::body::Value) -> TurnResult {
        let input = pb::HttpInput {
            method: "POST".into(),
            path: format!("/media/{key}/{op}"),
            query: query.into(),
            body: Some(pb::Body { value: Some(body) }),
            ..Default::default()
        };
        self.rt.block_on(async {
            let actor = ActorRef::parse(&format!("media/{key}")).unwrap();
            wait_turn(self.node.ingress(actor, input, None).unwrap())
                .await
                .unwrap()
        })
    }

    /// A blob of `size` bytes written as the gateway writes an upload.
    fn upload(&self, size: usize) -> pb::BlobRef {
        let store = self.node.blob_store().unwrap().clone();
        self.rt.block_on(async move {
            let mut w = store
                .writer(
                    kronik_blob::Space::Main,
                    None,
                    u64::MAX,
                    store.leases().take("upload"),
                )
                .await
                .unwrap();
            w.write(&vec![9u8; size]).await.unwrap();
            let meta = w.finish().await.unwrap();
            store
                .ensure_durable(&kronik_blob::Space::Main, &[meta.id])
                .await
                .unwrap();
            meta.to_pb()
        })
    }

    /// [`Proc::run`] of a turn that commits; its text answer.
    fn ok(&self, key: &str, op: &str, query: &str) -> String {
        let r = self.run(key, op, query, b"");
        assert!(r.committed(), "{op}?{query}: {r:?}");
        text_of(&r)
    }

    /// An operator's message `name` (`op?query`) to `media/<key>`, as
    /// `kronik send` sends it: a message turn; its result.
    fn send(&self, key: &str, name: &str) -> TurnResult {
        let actor = ActorRef::parse(&format!("media/{key}")).unwrap();
        let owner = self.node.local_operator_authority().unwrap();
        self.rt
            .block_on(self.node.send(actor, msg(name, ""), audit(), false, owner))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .unwrap()
    }

    /// [`Proc::send`] without waiting: the turn may not end in this process.
    fn send_detached(&self, key: &str, name: &str) {
        let node = self.node.clone();
        let actor = ActorRef::parse(&format!("media/{key}")).unwrap();
        let name = name.to_owned();
        self.rt.spawn(async move {
            let owner = node.local_operator_authority().unwrap();
            let _ = node
                .send(actor, msg(&name, ""), audit(), false, owner)
                .await;
        });
    }

    /// Waits up to 20 s for `f`.
    fn wait_until(&self, what: &str, f: impl Fn(&Proc) -> bool) {
        for _ in 0..2000 {
            if f(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}");
    }

    /// How many turns `media/<key>` committed or failed.
    fn turns(&self, key: &str) -> u64 {
        self.node
            .store()
            .db()
            .actor("media", key)
            .unwrap()
            .map_or(0, |a| a.turns)
    }

    /// Whether a turn is open: begun, and not ended by a record.
    fn open_turns(&self) -> usize {
        self.node.store().db().open_turns().unwrap().len()
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

/// A callee that answers a call with an HTTP response whose body is a blob
/// it wrote (`write` always makes one) gives the caller that blob: the
/// reply `http 200` with an empty body and the blob as its one blob, which
/// the caller reads and retains, and which its call effect lists. The callee
/// holds nothing. Found by the v0.5.0 release rehearsal: the caller failed
/// with 503 UNAVAILABLE, a missing prerequisite, and its turn stayed open.
#[test]
fn a_callee_answering_with_a_blob_it_wrote_replies_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    for (callee, size) in [("b", 1000u64), ("c", 100_000)] {
        let answer = p.ok(
            "a",
            "call",
            &format!("to={callee}&op=write?size={size}&keep=1"),
        );
        let blob = retained_reply(&answer);
        assert_eq!(blob.size, size);
        assert!(p.held("a", &blob));
        assert!(!p.held(callee, &blob), "the callee only wrote it");
        // Retained, it reads in a later turn.
        assert_eq!(p.ok("a", "held-sum", ""), pattern_sum(size));
        let calls = calls_of(&p.records(), "a");
        assert_blob_reply(calls.last().unwrap(), &blob);
    }
    assert_eq!(p.open_turns(), 0);
}

/// The same answer to a caller that is a message turn (here an operator's
/// message, as `kronik send` sends it): its turn commits and ends, so no
/// turn is left open to run again, and the actor goes on with its next
/// input.
#[test]
fn a_message_turn_calling_a_blob_writer_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    let r = p.send("m", "call?to=w&op=write?size=1000&keep=1");
    assert!(r.committed(), "{r:?}");
    let blob = retained_reply(&text_of(&r));
    assert_eq!(blob.size, 1000);
    assert!(p.held("m", &blob));
    assert_eq!(p.open_turns(), 0);
    assert_blob_reply(&calls_of(&p.records(), "m")[0], &blob);
    // The next message runs and reads the blob it retained.
    assert_eq!(text_of(&p.send("m", "held-sum")), pattern_sum(1000));
}

/// A message turn that stopped after its call had its answer, a blob the
/// callee wrote, and before it recorded it (a crash), runs again at the
/// next start, takes the callee's saved answer and commits, instead of
/// staying open to fail at every start (as it did when that answer was
/// refused as a missing prerequisite: then every run of the turn stopped
/// there). The callee ran once.
#[test]
fn a_rerun_message_turn_takes_the_saved_blob_answer() {
    let dir = tempfile::tempdir().unwrap();
    let p = start_holding(dir.path(), true, true);
    p.send_detached("m", "call?to=w&op=write?size=1000&keep=1");
    p.wait_until("the callee's turn", |p| p.turns("w") == 1);
    drop(p);
    let p = start(dir.path(), false);
    p.wait_until("the caller's turn", |p| p.turns("m") == 1);
    assert_eq!(p.open_turns(), 0);
    let calls = calls_of(&p.records(), "m");
    assert_eq!(calls.len(), 1, "{calls:?}");
    let blob = recorded_reply(&calls[0]).blobs[0].clone();
    assert_blob_reply(&calls[0], &blob);
    assert!(p.held("m", &blob));
    assert_eq!(p.turns("w"), 1, "the callee ran once");
    assert_eq!(text_of(&p.send("m", "held-sum")), pattern_sum(1000));
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

/// The quota bounds what an actor keeps alive, not only what it holds
/// (ADR 0119 as amended 2026-11-14): a blob it put into a timer still
/// counts after it released its hold, until the timer fires; a message
/// that would take it past the quota traps its turn with
/// BLOB_QUOTA_EXCEEDED, and nothing is sent.
#[allow(clippy::disallowed_methods)]
#[test]
fn the_quota_counts_timers_and_messages() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), true);
    p.set_quota(10_000);
    let six = blob_of(&p.ok("a", "put", "size=6000"));
    // A timer with the held blob adds nothing; released, it still counts.
    p.ok("a", "schedule", "delay=1500&op=info");
    assert_eq!(p.ok("a", "release", ""), "released");
    assert!(!p.held("a", &six));
    assert_eq!(p.ok("a", "put", "size=5000"), "quota-exceeded");
    // Once the timer has fired, the room is back.
    let mut waited = 0;
    loop {
        let charged = p.node.store().db().charged_bytes("media", "a").unwrap();
        if charged == 0 {
            break;
        }
        waited += 1;
        assert!(waited < 1000, "the timer never fired");
        std::thread::sleep(Duration::from_millis(20));
    }
    let five = blob_of(&p.ok("a", "put", "size=5000"));
    // A message that would keep 5000 + 6000 bytes: the turn traps.
    let upload = p.upload(6000);
    let sent = p.run_with("a", "send", "to=c&op=info", pb::body::Value::Blob(upload));
    assert!(!sent.committed());
    assert_eq!(sent.outcome.error_code, "BLOB_QUOTA_EXCEEDED", "{sent:?}");
    assert!(p.held("a", &five));
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
