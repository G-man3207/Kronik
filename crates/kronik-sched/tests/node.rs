//! Node tests on the real environment: each "process" is its own tokio
//! runtime, and dropping the runtime cancels every task like a crash.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::error::ErrorCode;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{Ingress, Node, NodeConfig, TurnResult, start_local};
use tokio::runtime::Runtime;

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const NOTES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/notes.wasm");
const FS_PROBE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/fs-probe.wasm"
);

struct Proc {
    rt: Runtime,
    node: Arc<Node>,
}

fn start(dir: &Path) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let config = NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        };
        start_local(env, dir, config).await.unwrap()
    });
    Proc { rt, node }
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn plain(b: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(b.to_vec())),
    })
}

fn msg(name: &str, body: &[u8]) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: plain(body),
        blobs: vec![],
    }
}

fn http(method: &str, path: &str, op: Option<&str>, key: &str, body: &[u8]) -> pb::HttpInput {
    let mut params = vec![pb::Param {
        name: "key".into(),
        value: key.into(),
        sealed_value: None,
    }];
    if let Some(op) = op {
        params.push(pb::Param {
            name: "op".into(),
            value: op.into(),
            sealed_value: None,
        });
    }
    pb::HttpInput {
        method: method.into(),
        path: path.into(),
        params,
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(plain(body).unwrap())),
        }),
        ..Default::default()
    }
}

fn reply_text(r: &TurnResult) -> String {
    let bytes = match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => b.clone(),
                    _ => vec![],
                },
                _ => vec![],
            }
        }
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => b.clone(),
            _ => vec![],
        },
        None => vec![],
    };
    String::from_utf8(bytes).unwrap()
}

impl Proc {
    fn deploy(&self, path: &str) -> kronik_sched::DeployResult {
        let bytes = std::fs::read(path).unwrap();
        self.rt
            .block_on(self.node.deploy(&bytes, audit(), false))
            .unwrap()
    }

    fn ingress(
        &self,
        actor: &str,
        h: pb::HttpInput,
    ) -> Result<TurnResult, kronik_core::error::ApiError> {
        let actor = ActorRef::parse(actor).unwrap();
        self.rt.block_on(async {
            match self.node.ingress(actor, h, None)? {
                Ingress::Started(w) | Ingress::Joined(w) => w.wait().await,
                Ingress::Done(r) => Ok(*r),
            }
        })
    }

    fn inc(&self, key: &str) -> String {
        let r = self
            .ingress(
                &format!("counter/{key}"),
                http(
                    "POST",
                    &format!("/counter/{key}/increment"),
                    Some("increment"),
                    key,
                    b"",
                ),
            )
            .unwrap();
        assert!(r.committed(), "{r:?}");
        reply_text(&r)
    }

    fn send(&self, actor: &str, m: pb::Message) -> TurnResult {
        self.rt
            .block_on(
                self.node
                    .send(ActorRef::parse(actor).unwrap(), m, audit(), false),
            )
            .unwrap()
            .unwrap()
    }

    fn kv(&self, actor: &str, k: &str) -> Option<String> {
        let a = ActorRef::parse(actor).unwrap();
        self.node
            .store()
            .db()
            .kv_get(&a.kind, &a.key, k)
            .unwrap()
            .map(|v| String::from_utf8(v).unwrap())
    }

    fn wait_kv(&self, actor: &str, k: &str, want: &str) {
        for _ in 0..500 {
            if self.kv(actor, k).as_deref() == Some(want) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "{actor} {k} never became {want:?}, is {:?}",
            self.kv(actor, k)
        );
    }

    fn record(&self, r: &TurnResult) -> pb::TurnRecord {
        match self
            .rt
            .block_on(self.node.read_record(r.turn_id.lsn))
            .unwrap()
            .unwrap()
            .record
        {
            Record::TurnRecord(t) => t,
            other => panic!("not a turn record: {other:?}"),
        }
    }
}

#[test]
fn counter_survives_restart_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    {
        let p = start(dir.path());
        let d = p.deploy(COUNTER);
        assert_eq!(d.manifest.kind, "counter");
        for i in 1..=5 {
            assert_eq!(p.inc("a"), i.to_string());
        }
        // Simulated crash: the runtime and all tasks are dropped.
    }
    {
        let p = start(dir.path());
        assert_eq!(p.inc("a"), "6");
    }
    // Delete the materialized state: it is rebuilt from the log.
    std::fs::remove_file(dir.path().join("branches/main/state.db")).unwrap();
    let _ = std::fs::remove_file(dir.path().join("branches/main/state.db-wal"));
    let p = start(dir.path());
    assert_eq!(p.kv("counter/a", "n").as_deref(), Some("6"));
    assert_eq!(p.inc("a"), "7");
    let actor = p.node.store().db().actor("counter", "a").unwrap().unwrap();
    assert_eq!(actor.turns, 7);
}

#[test]
fn messages_failures_dead_letters_and_resend() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy(COUNTER);
    let r = p.send("counter/a", msg("forward", b"b"));
    assert!(r.committed());
    p.wait_kv("counter/b", "n", "1");
    // The receiver's logical time is never below its message's (I15).
    let sender = p.record(&r);
    let hist = p
        .node
        .store()
        .db()
        .history("counter", "b", None, 10)
        .unwrap();
    let recv = match p
        .rt
        .block_on(p.node.reader().read_at(hist[0].pos))
        .unwrap()
        .record
    {
        Record::TurnRecord(t) => t,
        _ => unreachable!(),
    };
    assert!(recv.logical_time_ms >= sender.logical_time_ms);
    assert_eq!(
        recv.causal_key.as_ref().unwrap().root,
        sender.causal_key.as_ref().unwrap().root
    );
    assert_eq!(recv.causal_key.as_ref().unwrap().path.len(), 1);

    let failed = p.send("counter/a", msg("fail", b""));
    assert!(!failed.committed());
    assert_eq!(failed.outcome.error_code, "TURN_FAILED");
    let dls = p.node.store().db().dead_letters(0, 10).unwrap();
    assert_eq!(dls.len(), 1);
    assert_eq!(dls[0].lsn, failed.turn_id.lsn);

    let resent =
        p.rt.block_on(p.node.resend(failed.turn_id.lsn, audit(), false))
            .unwrap()
            .unwrap();
    assert!(!resent.committed());
    let dls = p.node.store().db().dead_letters(0, 10).unwrap();
    assert_eq!(dls.len(), 2);
    assert_eq!(dls[0].resent_as, Some(resent.turn_id.lsn));
    let again =
        p.rt.block_on(p.node.resend(failed.turn_id.lsn, audit(), false));
    assert_eq!(again.unwrap_err().code, ErrorCode::DeadLetterAlreadyResent);

    // Fuel exhaustion and traps are failed turns too.
    let spin = p.send("counter/a", msg("spin", b"x"));
    assert_eq!(spin.outcome.error_code, "FUEL_EXHAUSTED");
    let trap = p.send("counter/a", msg("trap", b""));
    assert_eq!(trap.outcome.kind, pb::OutcomeKind::Trap as i32);
    // A failed turn writes nothing.
    assert_eq!(p.kv("counter/a", "n").as_deref(), Some("1"));
}

#[test]
fn ingress_idempotency_key() {
    let dir = tempfile::tempdir().unwrap();
    // Request hashes are a version byte and 32 bytes (the gateway's).
    let current = |body: &[u8]| {
        let mut hash = vec![kronik_sched::INGRESS_HASH_VERSION];
        hash.extend_from_slice(blake3::hash(body).as_bytes());
        hash
    };
    let keyed = |body: &[u8]| {
        let mut h = http("POST", "/counter/a/increment", Some("increment"), "a", body);
        h.idempotency_key = "k1".into();
        h.request_hash = current(body);
        h
    };
    let first = {
        let p = start(dir.path());
        p.deploy(COUNTER);
        let first = p.ingress("counter/a", keyed(b"x")).unwrap();
        let second = p.ingress("counter/a", keyed(b"x")).unwrap();
        assert_eq!(first, second);
        let err = p.ingress("counter/a", keyed(b"y")).unwrap_err();
        assert_eq!(err.code, ErrorCode::IdempotencyKeyReused);
        first
    };
    let p = start(dir.path());
    assert_eq!(p.ingress("counter/a", keyed(b"x")).unwrap(), first);
    assert_eq!(p.kv("counter/a", "n").as_deref(), Some("1"));
    // A row saved with a v1 hash (before hashes covered the requester)
    // counts as expired: the request runs anew, nothing is replayed.
    let v1 = |body: &[u8]| {
        let mut h = http("POST", "/counter/a/increment", Some("increment"), "a", body);
        h.idempotency_key = "k-v1".into();
        h.request_hash = blake3::hash(body).as_bytes().to_vec();
        h
    };
    let old = p.ingress("counter/a", v1(b"x")).unwrap();
    let again = p.ingress("counter/a", v1(b"x")).unwrap();
    assert_ne!(old.turn_id, again.turn_id);
    assert_eq!(p.kv("counter/a", "n").as_deref(), Some("3"));
    // Rows of another version count as expired too: a v2 row (also over
    // cookies), and a 32-byte v1 row whose first byte happens to be 3. A
    // retry with the current hash runs anew instead of getting 422.
    for (key, old_hash) in [
        ("k-v2", {
            let mut h = vec![2];
            h.extend_from_slice(blake3::hash(b"x").as_bytes());
            h
        }),
        ("k-v1-3", {
            let mut h = vec![3];
            h.extend_from_slice(&[0; 31]);
            h
        }),
    ] {
        let with = |hash: Vec<u8>| {
            let mut h = http("POST", "/counter/a/increment", Some("increment"), "a", b"x");
            h.idempotency_key = key.into();
            h.request_hash = hash;
            h
        };
        let old = p.ingress("counter/a", with(old_hash)).unwrap();
        let retry = p
            .ingress("counter/a", with(current(b"x")))
            .unwrap_or_else(|e| panic!("{key}: {e}"));
        assert_ne!(old.turn_id, retry.turn_id, "{key}");
    }
    assert_eq!(p.kv("counter/a", "n").as_deref(), Some("7"));
}

#[test]
fn notes_sql_state_migrates_and_rebuilds() {
    let dir = tempfile::tempdir().unwrap();
    let add = |p: &Proc, text: &str| {
        let r = p
            .ingress(
                "notes/n1",
                http("POST", "/notes/n1", None, "n1", text.as_bytes()),
            )
            .unwrap();
        assert!(r.committed(), "{r:?}");
        reply_text(&r)
    };
    {
        let p = start(dir.path());
        let d = p.deploy(NOTES);
        assert_eq!(d.manifest.schema_version, 1);
        assert_eq!(add(&p, "first"), "1");
        assert_eq!(add(&p, "second"), "2");
        let a = p.node.store().db().actor("notes", "n1").unwrap().unwrap();
        assert_eq!(a.schema_version, 1);
        assert!(a.sql);
        // migrate + 2 adds
        assert_eq!(a.turns, 3);
        // DDL outside migrate is denied.
        let r = p.send("notes/n1", msg("ddl", b""));
        assert!(!r.committed());
        assert!(
            r.outcome.message.contains("DDL is only allowed in migrate"),
            "{r:?}"
        );
    }
    {
        let p = start(dir.path());
        assert_eq!(add(&p, "third"), "3");
    }
    // Lose only the actor database (it commits independently of state.db):
    // recovery replays from the lowest applied LSN.
    std::fs::remove_dir_all(dir.path().join("branches/main/sql")).unwrap();
    {
        let p = start(dir.path());
        let r = p.send("notes/n1", msg("count", b""));
        assert_eq!(reply_text(&r), "3");
    }
    // Rebuild both state.db and the actor database from the log.
    std::fs::remove_dir_all(dir.path().join("branches/main/sql")).unwrap();
    std::fs::remove_file(dir.path().join("branches/main/state.db")).unwrap();
    let _ = std::fs::remove_file(dir.path().join("branches/main/state.db-wal"));
    let p = start(dir.path());
    let r = p.send("notes/n1", msg("list", b""));
    assert_eq!(reply_text(&r), "first [-]\nsecond [-]\nthird [-]\n");
}

#[test]
fn deploy_checks() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let bytes = std::fs::read(FS_PROBE).unwrap();
    let err =
        p.rt.block_on(p.node.deploy(&bytes, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ImportNotAllowed);
    assert!(err.message.contains("wasi:filesystem"), "{err}");
    let counter = std::fs::read(COUNTER).unwrap();
    let dry =
        p.rt.block_on(p.node.deploy(&counter, audit(), true))
            .unwrap();
    assert!(dry.dry_run);
    assert!(!p.node.kind_exists("counter"));
    p.deploy(COUNTER);
    assert!(p.node.kind_exists("counter"));
    let again = p.deploy(COUNTER);
    assert!(again.unchanged);
    let err =
        p.rt.block_on(p.node.send(
            ActorRef::parse("nope/a").unwrap(),
            msg("x", b""),
            audit(),
            false,
        ))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ActorNotFound);
}

#[test]
fn turns_are_deterministic_and_hide_the_execution_id() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy(COUNTER);
    let r = p.send("counter/a", msg("probe", b""));
    let text = reply_text(&r);
    let rec = p.record(&r);
    let causal_id = kronik_core::causal::causal_id(rec.causal_key.as_ref().unwrap());
    assert!(text.contains(&format!("causal={causal_id}")), "{text}");
    assert!(!text.contains(&rec.execution_id), "{text}");
    assert!(
        text.contains(&format!("now={}", rec.logical_time_ms)),
        "{text}"
    );

    // Re-running the recorded turn on a fresh instance gives the same outcome.
    let bytes = std::fs::read(COUNTER).unwrap();
    let engine = kronik_runtime::build_engine(kronik_runtime::PoolSize { concurrency: 2 }).unwrap();
    let code = kronik_runtime::CodeStore::new(engine, None).unwrap();
    let (_, program) = code.add(&bytes).unwrap();
    struct Empty;
    impl kronik_runtime::StateView for Empty {
        fn get(&self, _: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        fn keys(&self, _: &str) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
        fn timer_pending(&self, _: u64) -> Result<bool, String> {
            Ok(false)
        }
    }
    let rerun = |rec: &pb::TurnRecord| {
        p.rt.block_on(program.run(
            kronik_runtime::TurnRequest {
                actor: ActorRef::from_pb(rec.actor.as_ref().unwrap()),
                causal_key: rec.causal_key.clone().unwrap(),
                logical_time_ms: rec.logical_time_ms,
                seed: rec.random_seed.clone().try_into().unwrap(),
                input: rec.input.clone().unwrap(),
                limits: kronik_runtime::TurnLimits::default(),
                subject: None,
            },
            Arc::new(Empty),
            None,
            None,
        ))
        .unwrap()
    };
    let a = rerun(&rec);
    let b = rerun(&rec);
    assert_eq!(Some(&a.outcome), rec.outcome.as_ref());
    assert_eq!(a.outcome, b.outcome);
    assert_eq!(a.fuel_used, rec.fuel_used);
    assert_eq!(a.fuel_used, b.fuel_used);
}

/// docs/design/m8-privacy.md §6.1: a stop between the keystore erase and the
/// Erasure record leaves the keys gone; the next start commits the record,
/// so the subject's state values go too, and only once.
#[test]
fn an_erasure_without_its_record_is_recovered_at_start() {
    let dir = tempfile::tempdir().unwrap();
    // Sealed values aren't text: only whether they exist.
    let has = |p: &Proc, k: &str| {
        p.node
            .store()
            .db()
            .kv_get("counter", "x", k)
            .unwrap()
            .is_some()
    };
    {
        let p = start(dir.path());
        p.deploy(COUNTER);
        p.rt.block_on(
            p.node
                .set_privacy_mode(pb::PrivacyState::On, audit(), false),
        )
        .unwrap();
        // `subject` writes s for user:1 and t for user:2.
        assert!(p.send("counter/x", msg("subject", b"")).committed());
        assert!(has(&p, "s"));
        // The keys go; the daemon stops before the record.
        assert_eq!(p.node.sealer().erase("user:1", 1).unwrap(), 1);
    }
    let epoch = {
        let p = start(dir.path());
        assert_eq!(
            p.node.store().db().erasures().unwrap(),
            vec![("user:1".to_owned(), 1)]
        );
        assert!(!has(&p, "s"));
        assert!(has(&p, "t"));
        p.node.epoch()
    };
    let p = start(dir.path());
    assert_eq!(p.node.epoch(), epoch, "recovered once, not again");
}

/// `[log] disk_reserve`: with less free space than the reserve, new inputs
/// and changes are refused with UNAVAILABLE before anything is written, the
/// node keeps running (no fatal log write), and erasure still works.
#[test]
fn below_the_disk_reserve_new_work_waits_and_the_node_stays_up() {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let config = NodeConfig {
            // More than any disk has: the reserve is always short.
            disk_reserve: u64::MAX,
            ..NodeConfig::default()
        };
        start_local(env, dir.path(), config).await.unwrap()
    });
    let p = Proc { rt, node };
    let bytes = std::fs::read(COUNTER).unwrap();
    let e =
        p.rt.block_on(p.node.deploy(&bytes, audit(), false))
            .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable, "{e}");
    assert!(e.message.contains("disk_reserve"), "{e}");
    assert_eq!(p.node.fatal(), None);
    p.rt.block_on(p.node.erase_subject("user:1", audit(), false))
        .unwrap();
}
