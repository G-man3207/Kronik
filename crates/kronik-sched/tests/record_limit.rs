//! One log record holds everything a turn records (docs/design/m1-core.md
//! §2, "Record size"; issue #26): with a small record limit, a turn whose
//! output or effects do not fit fails with `TURN_TOO_LARGE` and writes a
//! record that does fit, no record over the limit is ever written, no
//! `TurnBegin` stays open, and the history reads and the node restarts.
//!
//! The effect bytes one turn may record (ADR 0145, issue #74): a kind's
//! `effect_bytes_per_turn` bounds the requests and responses its turns'
//! effect results hold inline. An effect that would pass it fails with
//! `EFFECT_BYTES_EXCEEDED` recorded as its result: before it is sent when
//! its request alone does not fit, else its response is not recorded. The
//! turn goes on, and the limit is exact.

// Test helpers outside #[test] functions may unwrap, and the test server
// uses plain std threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Proc, audit, http, msg, start_proc};
use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{HoldPoint, NodeConfig, TestHold, TurnResult};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

/// The log's record limit in these tests: 512 KiB instead of 128 MiB.
const LIMIT: u32 = 512 << 10;

/// A test server: `/big/<n>` answers `n` bytes, `/hang` never answers (for
/// a minute), anything else `ok`.
struct Server {
    addr: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start() -> Server {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let addr = http::serve(move |req, w| {
            log.lock().unwrap().push(req.path.clone());
            if req.path == "/hang" {
                std::thread::sleep(Duration::from_secs(60));
                // Then the connection closes, as before.
                let _ = w.shutdown(std::net::Shutdown::Both);
                return;
            }
            let reply = match req.path.strip_prefix("/big/") {
                Some(n) => "b".repeat(n.parse().unwrap_or(0)),
                None => "ok".to_owned(),
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\n\r\n",
                reply.len()
            );
            let _ = w
                .write_all(head.as_bytes())
                .and_then(|()| w.write_all(reply.as_bytes()));
        });
        Server { addr, seen }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

fn start(dir: &Path) -> Proc {
    start_limit(dir, LIMIT)
}

/// [`start`] with the log's record limit `limit`.
fn start_limit(dir: &Path, limit: u32) -> Proc {
    start_with(dir, limit, None, None, None)
}

/// [`start_limit`] with a crash hold, retention settings and a segment size.
fn start_with(
    dir: &Path,
    limit: u32,
    hold: Option<TestHold>,
    storage: Option<StorageConfig>,
    segment_max_bytes: Option<u64>,
) -> Proc {
    start_proc(
        dir,
        NodeConfig {
            concurrency: 4,
            test_max_record_bytes: Some(limit),
            test_hold: hold,
            storage,
            segment_max_bytes,
            ..NodeConfig::default()
        },
    )
}

impl Proc {
    fn deploy(&self) {
        self.deploy_file(COUNTER);
    }

    fn grant(&self, cap: &str) {
        self.rt
            .block_on(self.node.grant(
                "counter",
                cap,
                None,
                None,
                kronik_effects::InForks::Recorded,
                audit(),
                false,
                self.owner(),
            ))
            .unwrap();
    }

    fn send(&self, actor: &str, m: pb::Message) -> TurnResult {
        self.rt
            .block_on(self.node.send(
                ActorRef::parse(actor).unwrap(),
                m,
                audit(),
                false,
                self.owner(),
            ))
            .unwrap()
            .unwrap()
    }

    /// The record at `lsn`, read by position as `history` does.
    fn record(&self, lsn: u64) -> Record {
        self.rt
            .block_on(self.node.read_record(lsn))
            .unwrap()
            .unwrap()
            .record
    }
}

/// Every record body in the log with its LSN, read with a fresh runtime.
fn bodies(dir: &Path) -> Vec<(u64, Record, usize)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let reader = kronik_log::LogReader::new(env, dir.join("branches/main/log"), "main");
        let mut out = Vec::new();
        reader
            .read(1, u64::MAX, |c| {
                let len = c.record.encoded_len();
                out.push((c.lsn, c.record, len));
                Ok(())
            })
            .await
            .unwrap();
        out
    })
}

fn assert_every_record_fits(dir: &Path) {
    for (lsn, record, len) in bodies(dir) {
        assert!(
            len <= LIMIT as usize,
            "the record of kind {} at lsn {lsn} is {len} bytes, over the limit {LIMIT}",
            record.kind()
        );
    }
}

fn assert_too_large(r: &TurnResult) {
    assert!(!r.committed(), "{:?}", r.outcome);
    assert_eq!(r.outcome.error_code, "TURN_TOO_LARGE", "{:?}", r.outcome);
    assert_eq!(r.outcome.kind, pb::OutcomeKind::Trap as i32);
    assert!(r.outcome.output.is_none());
}

fn turn_record(p: &Proc, r: &TurnResult) -> pb::TurnRecord {
    match p.record(r.turn_id.lsn) {
        Record::TurnRecord(t) => t,
        other => panic!("not a turn record: {other:?}"),
    }
}

/// Crashes the node: its tasks die with the runtime, and the log stays.
fn crash(p: Proc) {
    let Proc { rt, node } = p;
    drop(node);
    rt.shutdown_timeout(Duration::from_secs(1));
}

/// A turn's base cost, before its input: what its budget must hold.
fn begin_base_cost(begin: &pb::TurnBegin) -> usize {
    let mut input = begin.input.clone().unwrap();
    let input_cost = kronik_sched::record_budget::input_cost(&mut input);
    kronik_sched::record_budget::base_cost(
        begin.actor.as_ref().unwrap(),
        &begin.code_hash,
        begin.causal_key.as_ref().unwrap(),
        begin.logical_time_ms,
        &begin.random_seed,
        input_cost,
        begin.config_epoch,
    )
}

/// The closing `TurnRecord` of `execution_id`, once it is there and the turn
/// is no longer open.
fn closing_record(p: &Proc, dir: &Path, execution_id: &str) -> pb::TurnRecord {
    for _ in 0..600 {
        let closed = bodies(dir)
            .into_iter()
            .find_map(|(_, record, _)| match record {
                Record::TurnRecord(t) if t.execution_id == execution_id => Some(t),
                _ => None,
            });
        if let Some(t) = closed
            && p.node.store().db().open_turns().unwrap().is_empty()
        {
            return t;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the open turn was never closed");
}

impl Proc {
    /// Sets the counter type's effect bytes per turn.
    fn effect_bytes(&self, bytes: u64) {
        self.rt
            .block_on(self.node.set_limits(
                pb::Limits {
                    kind: "counter".into(),
                    effect_bytes_per_turn: Some(bytes),
                    ..Default::default()
                },
                audit(),
                false,
                self.owner(),
            ))
            .unwrap();
    }

    /// `counter/<key>` fetches `spec` in one turn; its only effect.
    fn fetch(&self, key: &str, spec: &str) -> (TurnResult, pb::EffectRecord) {
        let r = self.send(&format!("counter/{key}"), msg("fetch", spec.as_bytes()));
        let record = turn_record(self, &r);
        assert_eq!(record.effects.len(), 1, "{:?}", record.effects);
        (r, record.effects[0].clone())
    }
}

fn setup(limit: u32) -> (Server, tempfile::TempDir, Proc) {
    let server = Server::start();
    let dir = tempfile::tempdir().unwrap();
    let p = start_limit(dir.path(), limit);
    p.deploy();
    p.grant("http:127.0.0.1");
    (server, dir, p)
}

/// A reply over what one record holds: before the fix the node committed a
/// record its own readers then refused; now the turn fails and its record
/// fits, `history` reads it, the actor goes on and the node restarts.
#[test]
fn a_turn_whose_output_does_not_fit_fails_and_every_record_fits() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    assert_eq!(p.node.record_limit(), LIMIT as usize);
    p.send("counter/a", msg("increment", b""));

    let big = p.send("counter/a", msg("big", (600 << 10).to_string().as_bytes()));
    assert_too_large(&big);
    let record = turn_record(&p, &big);
    assert!(record.writes.is_empty() && record.messages.is_empty());
    // The failed message is a dead letter, as for any failed turn.
    assert!(
        p.node
            .store()
            .db()
            .dead_letter(big.turn_id.lsn)
            .unwrap()
            .is_some()
    );
    // The actor goes on.
    let after = p.send("counter/a", msg("increment", b""));
    assert!(after.committed(), "{:?}", after.outcome);
    assert!(p.node.store().db().open_turns().unwrap().is_empty());
    let applied = p.node.applied_lsn();
    drop(p);

    assert_every_record_fits(dir.path());
    let p = start(dir.path());
    assert_eq!(p.node.applied_lsn(), applied);
    assert_too_large(&TurnResult {
        turn_id: big.turn_id.clone(),
        outcome: turn_record(&p, &big).outcome.unwrap(),
        scrubbed_with: None,
    });
}

/// The second of two fetches no longer fits in the turn's record: it never
/// reaches the server, the turn fails with TURN_TOO_LARGE, its record keeps
/// the first effect, and no `TurnBegin` stays open to run it again.
#[test]
fn an_effect_that_does_not_fit_never_happens_and_the_turn_closes() {
    let (server, dir, p) = setup(LIMIT);
    let body = "a".repeat(150 << 10);
    let spec = format!(
        "POST {}\n\n{body}\n---\nPOST {}\n\n{body}",
        server.url("/one"),
        server.url("/two")
    );
    let r = p.send("counter/b", msg("fetch2", spec.as_bytes()));
    assert_too_large(&r);
    assert!(
        r.outcome.message.contains("effect 1 (http.fetch)"),
        "{:?}",
        r.outcome
    );
    assert_eq!(server.seen(), vec!["/one".to_owned()]);
    let record = turn_record(&p, &r);
    assert_eq!(record.effects.len(), 1);
    assert_eq!(record.effects[0].status, pb::EffectStatus::Ok as i32);
    assert!(p.node.store().db().open_turns().unwrap().is_empty());
    drop(p);

    assert_every_record_fits(dir.path());
    let begins = bodies(dir.path())
        .into_iter()
        .filter(|(_, r, _)| matches!(r, Record::TurnBegin(_)))
        .count();
    assert_eq!(begins, 1);
    // Nothing is run again at the next start.
    let p = start(dir.path());
    assert!(p.node.store().db().open_turns().unwrap().is_empty());
    let again = p.send("counter/b", msg("increment", b""));
    assert!(again.committed(), "{:?}", again.outcome);
    assert_eq!(server.seen(), vec!["/one".to_owned()]);
}

/// A response larger than what is left of the turn's record is read only
/// that far and is `too-large` for the guest, as one over the kind's
/// effect_response_bytes is: the record keeps a result without its body.
#[test]
fn a_response_over_what_is_left_is_too_large_and_the_record_fits() {
    let (server, dir, p) = setup(LIMIT);
    let spec = format!("GET {}", server.url(&format!("/big/{}", 2 << 20)));
    let r = p.send("counter/c", msg("fetch", spec.as_bytes()));
    assert!(!r.committed());
    assert_eq!(r.outcome.error_code, "TURN_FAILED", "{:?}", r.outcome);
    assert!(r.outcome.message.contains("TooLarge"), "{:?}", r.outcome);
    let record = turn_record(&p, &r);
    assert_eq!(record.effects.len(), 1);
    let effect = &record.effects[0];
    assert_eq!(effect.status, pb::EffectStatus::TooLarge as i32);
    assert!(effect.response.is_none());
    assert!(
        effect.error.contains("what is left of the turn's record"),
        "{}",
        effect.error
    );
    drop(p);
    assert_every_record_fits(dir.path());
}

/// A turn begun by an earlier release, before this budget existed, can have
/// an input that does not fit in a turn's record under it (review of the
/// integration branch, item 6). Its re-run refused it with
/// PAYLOAD_TOO_LARGE at every start and never closed it, so it ran again at
/// each start and kept its segment from retention for ever. Now the re-run
/// closes it with a failed record under the TurnBegin's own execution id:
/// the turn is no longer open, the record fits the log, and a second start
/// has nothing to run.
///
/// The earlier release is played by a larger record limit: the turn begins
/// under it and the node stops while its fetch hangs; the next start has a
/// limit whose turn budget the input does not fit, while the log still
/// takes the closing record.
#[test]
fn an_open_turn_whose_input_no_longer_fits_is_closed_not_rerun_for_ever() {
    let (server, dir, p) = setup(LIMIT);
    let spec = format!("POST {}\n\n{}", server.url("/hang"), "a".repeat(200 << 10));
    let node = p.node.clone();
    let owner = p.owner();
    p.rt.spawn(async move {
        let _ = node
            .send(
                ActorRef::parse("counter/h").unwrap(),
                msg("fetch", spec.as_bytes()),
                audit(),
                false,
                owner,
            )
            .await;
    });
    for _ in 0..600 {
        if server.seen().iter().any(|path| path == "/hang") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        server.seen().iter().any(|path| path == "/hang"),
        "{:?}",
        server.seen()
    );
    // A crash: the TurnBegin is durable, the turn's record is never written.
    // The fetch's blocking thread is left to the server's timeout.
    crash(p);
    let begin = bodies(dir.path())
        .into_iter()
        .find_map(|(_, record, _)| match record {
            Record::TurnBegin(begin) => Some(begin),
            _ => None,
        })
        .expect("the turn began");
    let base = begin_base_cost(&begin);
    // A turn's budget is the log's limit less 4 KiB: this limit holds the
    // closing record, and its budget is less than the input needs.
    let limit = u32::try_from(base + 2048).unwrap();
    assert!(base > kronik_sched::record_budget::turn_limit(limit as usize));

    let p = start_limit(dir.path(), limit);
    let closed = closing_record(&p, dir.path(), &begin.execution_id);
    let len = Record::TurnRecord(closed.clone()).encoded_len();
    assert!(len <= limit as usize, "the closing record is {len} bytes");
    assert_eq!(closed.input, begin.input);
    let outcome = closed.outcome.unwrap();
    assert_eq!(outcome.kind, pb::OutcomeKind::Failed as i32, "{outcome:?}");
    assert_eq!(outcome.error_code, "TURN_TOO_LARGE", "{outcome:?}");
    assert!(p.node.store().db().open_turns().unwrap().is_empty());
    // The fetch was not sent again, and a second start has nothing to run.
    drop(p);
    let p = start_limit(dir.path(), limit);
    assert!(p.node.store().db().open_turns().unwrap().is_empty());
    assert_eq!(
        server.seen().iter().filter(|path| *path == "/hang").count(),
        1
    );
}

/// Issue #87: a turn begun before 0.5 could record compensation messages that
/// no budget charged. When this release re-ran it and the recorded compensation
/// put its failed record over the budget, the closing record kept the
/// compensation, the log refused it, and every start ran the turn again and
/// pinned its segment from retention. The closing record now leaves it out
/// before the effects: the call stays without a compensation to deliver, the
/// turn is closed, and the pin goes.
#[test]
fn an_open_turn_whose_compensations_no_longer_fit_is_closed_not_rerun_for_ever() {
    let dir = tempfile::tempdir().unwrap();
    let armed = dir.path().join("hold-armed");
    let reached = dir.path().join("hold-reached");
    std::fs::write(&armed, b"armed").unwrap();
    let mut storage = StorageConfig::new(dir.path().to_path_buf());
    storage.history = Duration::ZERO;
    storage.snapshot_interval = Duration::from_secs(3600);
    let hold = TestHold {
        point: HoldPoint::BeforeCommit,
        armed,
        reached: reached.clone(),
    };

    let p = start_with(
        dir.path(),
        LIMIT,
        Some(hold),
        Some(storage.clone()),
        Some(4096),
    );
    p.deploy();
    // The counter/callee turn parks before its record (the hold); the call
    // times out, and the caller records the compensation of a timed-out call
    // exactly as it records a successful one's. Then the caller parks too.
    p.rt.block_on(p.node.set_limits(
        pb::Limits {
            kind: "counter".into(),
            effect_timeout_ms: Some(100),
            ..Default::default()
        },
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    let compensation = "c".repeat(100 << 10);
    let spec = format!("counter/callee increment {compensation}");
    let node = p.node.clone();
    let owner = p.owner();
    p.rt.spawn(async move {
        let _ = node
            .send(
                ActorRef::parse("counter/h").unwrap(),
                msg("call", spec.as_bytes()),
                audit(),
                false,
                owner,
            )
            .await;
    });

    // The caller is open with its call result recorded: a crash there leaves
    // a TurnBegin whose open_effects hold a compensation past the next
    // start's budget.
    let mut caller = None;
    for _ in 0..600 {
        let open = p.node.store().db().open_turns().unwrap();
        if let Some(turn) = open.iter().find(|t| t.actor.key == "h")
            && !p
                .node
                .store()
                .db()
                .open_effects(&turn.execution_id)
                .unwrap()
                .is_empty()
        {
            caller = Some((turn.execution_id.clone(), turn.pos.segment));
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let (execution_id, begin_segment) =
        caller.expect("the caller did not reach its record's commit");
    assert!(reached.is_file(), "the caller is held before its commit");

    // A crash: the TurnBegin and the call result are durable, the TurnRecord
    // is never written.
    crash(p);
    let begin = bodies(dir.path())
        .into_iter()
        .find_map(|(_, record, _)| match record {
            Record::TurnBegin(begin) if begin.execution_id == execution_id => Some(begin),
            _ => None,
        })
        .expect("the caller's turn began");
    let base = begin_base_cost(&begin);
    // A turn's budget is the log's limit less 4 KiB: this limit lets the
    // guest re-run under the budget (the input and a short outcome fit) and
    // holds the closing record once its recorded compensation is left out.
    let limit = u32::try_from(base + 8192).unwrap();
    assert!(base <= kronik_sched::record_budget::turn_limit(limit as usize));

    let p = start_with(dir.path(), limit, None, Some(storage.clone()), Some(4096));
    let closed = closing_record(&p, dir.path(), &execution_id);
    let len = Record::TurnRecord(closed.clone()).encoded_len();
    assert!(len <= limit as usize, "the closing record is {len} bytes");
    assert_eq!(closed.input, begin.input);
    // The turn re-ran under the budget and replayed its recorded call; the
    // compensation is what put its record over. That goes, the call stays
    // without a compensation to deliver, and its EffectResult keeps the
    // request and response the closing record leaves out.
    assert!(
        closed.compensations.is_empty(),
        "{} compensations stayed",
        closed.compensations.len()
    );
    assert_eq!(closed.effects.len(), 1);
    assert!(closed.effects[0].request.is_none() && closed.effects[0].response.is_none());
    assert!(
        bodies(dir.path())
            .into_iter()
            .any(|(_, record, _)| matches!(
                record,
                Record::EffectResult(effect)
                    if effect.execution_id == execution_id
                        && effect
                        .effect
                        .as_ref()
                        .is_some_and(|e| e.kind == "actor.call")
            )),
        "the call's result is not in the log"
    );
    let outcome = closed.outcome.clone().unwrap();
    assert_eq!(outcome.kind, pb::OutcomeKind::Trap as i32, "{outcome:?}");
    assert_eq!(outcome.error_code, "TURN_TOO_LARGE", "{outcome:?}");
    assert!(
        outcome
            .message
            .contains("its 1 compensations are not recorded: their calls are orphans"),
        "{outcome:?}"
    );
    assert!(p.node.store().db().open_turns().unwrap().is_empty());
    assert_every_record_fits(dir.path());

    // A later start has nothing to run, and the pin is gone: retention may
    // delete the segment that held the begin.
    drop(p);
    let p = start_with(dir.path(), limit, None, Some(storage), Some(4096));
    assert!(p.node.store().db().open_turns().unwrap().is_empty());
    assert_eq!(
        bodies(dir.path())
            .into_iter()
            .filter(|(_, record, _)| matches!(
                record,
                Record::TurnRecord(t) if t.execution_id == execution_id
            ))
            .count(),
        1
    );
    for i in 0..40 {
        p.send(&format!("counter/k{}", i % 5), msg("increment", b""));
    }
    p.rt.block_on(p.node.snapshot("manual", p.owner())).unwrap();
    let before = p.node.store().db().time_hwm().unwrap();
    loop {
        std::thread::sleep(Duration::from_millis(2));
        p.send("counter/tick", msg("increment", b""));
        if p.node.store().db().time_hwm().unwrap() > before {
            break;
        }
    }
    // The compensation left out was not delivered either. The callee has a
    // failed record from the lost-call close at startup, but no turn of a
    // compensation, and it never ran.
    assert!(
        !bodies(dir.path())
            .into_iter()
            .any(|(_, record, _)| matches!(
                record,
                Record::TurnRecord(turn)
                    if turn.actor.as_ref().is_some_and(|actor| actor.key == "callee")
                        && matches!(
                            turn.input.as_ref().and_then(|input| input.kind.as_ref()),
                            Some(pb::input::Kind::Message(m))
                                if m.source == pb::MessageSource::Compensation as i32
                        )
            )),
        "a compensation the closing record left out was delivered"
    );
    assert_eq!(
        p.node
            .store()
            .db()
            .kv_get("counter", "callee", "n")
            .unwrap(),
        None,
        "a compensation the closing record left out changed the callee"
    );
    let log_dir = dir.path().join("branches/main/log");
    let starts = kronik_log::segment_starts(&log_dir).unwrap();
    let next = starts
        .iter()
        .position(|start| *start == begin_segment)
        .and_then(|i| starts.get(i + 1).copied())
        .expect("the begin's segment and a later one");
    let first = p.node.compact(p.node.storage_config().unwrap()).unwrap();
    assert!(
        first >= next,
        "compact returned {first}, the begin's segment ended at {next}"
    );
    assert!(
        !log_dir
            .join(kronik_log::segment_name(begin_segment))
            .is_file(),
        "the begin's segment was not deleted"
    );
    assert_eq!(p.node.retention_pin(), None);
}

/// The default is 32 MiB, recorded with the kind's other limits.
#[test]
fn the_default_is_32_mib_and_a_set_limit_is_in_the_log() {
    assert_eq!(
        kronik_effects::KindLimits::default().effect_bytes_per_turn,
        32 << 20
    );
    let (_server, _dir, p) = setup(kronik_log::MAX_RECORD);
    p.effect_bytes(1 << 20);
    let config = p.node.config_now();
    assert_eq!(config.limits("counter").effect_bytes_per_turn, 1 << 20);
    assert_eq!(config.limits("other").effect_bytes_per_turn, 32 << 20);
}

/// A response that would pass what is left fails its effect: the request
/// was sent, the response is not recorded, and the result says
/// EFFECT_BYTES_EXCEEDED; the guest gets `too-large` and goes on (the
/// counter guest then fails its turn, as for any failed fetch).
#[test]
fn a_response_past_the_effect_bytes_is_sent_and_not_recorded() {
    let (server, _dir, p) = setup(kronik_log::MAX_RECORD);
    p.effect_bytes(64 << 10);
    let (r, effect) = p.fetch("a", &format!("GET {}", server.url("/big/100000")));
    assert!(!r.committed());
    assert!(r.outcome.message.contains("TooLarge"), "{:?}", r.outcome);
    assert_eq!(effect.status, pb::EffectStatus::TooLarge as i32);
    assert!(effect.request.is_some() && effect.response.is_none());
    assert!(
        effect.error.starts_with("EFFECT_BYTES_EXCEEDED:") && effect.error.contains("not recorded"),
        "{}",
        effect.error
    );
    assert_eq!(server.seen(), ["/big/100000"]);
}

/// A request that alone would pass what is left is not sent.
#[test]
fn a_request_past_the_effect_bytes_is_not_sent() {
    let (server, _dir, p) = setup(kronik_log::MAX_RECORD);
    p.effect_bytes(64 << 10);
    let spec = format!("POST {}\n\n{}", server.url("/post"), "a".repeat(100 << 10));
    let (r, effect) = p.fetch("a", &spec);
    assert!(!r.committed());
    assert_eq!(effect.status, pb::EffectStatus::TooLarge as i32);
    assert!(effect.request.is_none() && effect.response.is_none());
    assert!(effect.error.contains("not sent"), "{}", effect.error);
    assert!(server.seen().is_empty(), "{:?}", server.seen());
}

/// What a turn's earlier effects recorded counts: a second request that
/// no longer fits in what the first left is not sent.
#[test]
fn what_earlier_effects_recorded_counts() {
    let (server, _dir, p) = setup(kronik_log::MAX_RECORD);
    p.effect_bytes(200 << 10);
    let body = "a".repeat(150 << 10);
    let spec = format!(
        "POST {}\n\n{body}\n---\nPOST {}\n\n{body}",
        server.url("/one"),
        server.url("/two")
    );
    let r = p.send("counter/a", msg("fetch2", spec.as_bytes()));
    assert!(!r.committed());
    let record = turn_record(&p, &r);
    assert_eq!(record.effects.len(), 2, "{:?}", record.effects);
    assert_eq!(record.effects[0].status, pb::EffectStatus::Ok as i32);
    assert!(
        record.effects[1].error.contains("not sent"),
        "{:?}",
        record.effects[1]
    );
    assert_eq!(server.seen(), ["/one"]);
}

/// The limit is exact: an effect that records exactly what is left fits,
/// one byte less does not.
#[test]
fn the_limit_is_exact() {
    let (server, _dir, p) = setup(kronik_log::MAX_RECORD);
    let spec = format!("GET {}", server.url("/big/1000"));
    let (r, effect) = p.fetch("a", &spec);
    assert!(r.committed(), "{:?}", r.outcome);
    let exact = kronik_sched::record_budget::effect_bytes(&effect);
    p.effect_bytes(exact);
    let (r, effect) = p.fetch("b", &spec);
    assert!(r.committed(), "{:?}", r.outcome);
    assert_eq!(kronik_sched::record_budget::effect_bytes(&effect), exact);
    p.effect_bytes(exact - 1);
    let (r, effect) = p.fetch("c", &spec);
    assert!(!r.committed());
    assert!(
        effect.error.starts_with("EFFECT_BYTES_EXCEEDED:"),
        "{}",
        effect.error
    );
    assert_eq!(server.seen().len(), 3);
}

/// A crash and a re-run: the re-run is charged what the first execution
/// recorded and refuses the same effects (the failure is the recorded
/// result, so the turn ends the same way after a restart).
#[test]
fn the_failure_survives_a_restart() {
    let (server, dir, p) = setup(kronik_log::MAX_RECORD);
    p.effect_bytes(64 << 10);
    let (r, effect) = p.fetch("a", &format!("GET {}", server.url("/big/100000")));
    assert!(!r.committed());
    drop(p);
    let p = start_limit(dir.path(), kronik_log::MAX_RECORD);
    let record = turn_record(&p, &r);
    assert_eq!(record.effects[0], effect);
    assert_eq!(
        p.node.config_now().limits("counter").effect_bytes_per_turn,
        64 << 10
    );
}
