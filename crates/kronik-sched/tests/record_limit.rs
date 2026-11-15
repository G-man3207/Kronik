//! One log record holds everything a turn records (docs/design/m1-core.md
//! §2, "Record size"; issue #26): with a small record limit, a turn whose
//! output or effects do not fit fails with `TURN_TOO_LARGE` and writes a
//! record that does fit, no record over the limit is ever written, no
//! `TurnBegin` stays open, and the history reads and the node restarts.

// Test helpers outside #[test] functions may unwrap, and the test server
// uses plain std threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{HoldPoint, Node, NodeConfig, TestHold, TurnResult, start_local};
use tokio::runtime::Runtime;

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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let log = log.clone();
                std::thread::spawn(move || serve(stream, log));
            }
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

fn serve(stream: TcpStream, seen: Arc<Mutex<Vec<String>>>) {
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
        let mut len = 0usize;
        loop {
            let mut h = String::new();
            if r.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':')
                && k.trim().eq_ignore_ascii_case("content-length")
            {
                len = v.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; len];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        seen.lock().unwrap().push(path.clone());
        if path == "/hang" {
            std::thread::sleep(std::time::Duration::from_secs(60));
            return;
        }
        let reply = match path.strip_prefix("/big/") {
            Some(n) => "b".repeat(n.parse().unwrap_or(0)),
            None => "ok".to_owned(),
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\n\r\n",
            reply.len()
        );
        if w.write_all(head.as_bytes()).is_err() || w.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

struct Proc {
    rt: Runtime,
    node: Arc<Node>,
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
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        start_local(
            env,
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
        .await
        .unwrap()
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

fn msg(name: &str, body: &[u8]) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(body.to_vec())),
        }),
        blobs: vec![],
        retained_compensation_source: None,
    }
}

impl Proc {
    fn owner(&self) -> kronik_core::authority::AuthLease {
        self.node.local_operator_authority().unwrap()
    }

    fn deploy(&self) {
        let bytes = std::fs::read(COUNTER).unwrap();
        self.rt
            .block_on(self.node.deploy(&bytes, audit(), false, self.owner()))
            .unwrap();
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
    let server = Server::start();
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1");
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
    let server = Server::start();
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1");
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
    let server = Server::start();
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1");
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
    let Proc { rt, node } = p;
    drop(node);
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    let begin = bodies(dir.path())
        .into_iter()
        .find_map(|(_, record, _)| match record {
            Record::TurnBegin(begin) => Some(begin),
            _ => None,
        })
        .expect("the turn began");
    let base = {
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
    };
    // A turn's budget is the log's limit less 4 KiB: this limit holds the
    // closing record, and its budget is less than the input needs.
    let limit = u32::try_from(base + 2048).unwrap();
    assert!(base > kronik_sched::record_budget::turn_limit(limit as usize));

    let p = start_limit(dir.path(), limit);
    let mut closed = None;
    for _ in 0..600 {
        closed = bodies(dir.path())
            .into_iter()
            .find_map(|(_, record, _)| match record {
                Record::TurnRecord(t) if t.execution_id == begin.execution_id => Some(t),
                _ => None,
            });
        if closed.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let closed = closed.expect("the open turn was never closed");
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
    let Proc { rt, node } = p;
    drop(node);
    rt.shutdown_timeout(Duration::from_secs(1));
    let begin = bodies(dir.path())
        .into_iter()
        .find_map(|(_, record, _)| match record {
            Record::TurnBegin(begin) if begin.execution_id == execution_id => Some(begin),
            _ => None,
        })
        .expect("the caller's turn began");
    let base = {
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
    };
    // A turn's budget is the log's limit less 4 KiB: this limit lets the
    // guest re-run under the budget (the input and a short outcome fit) and
    // holds the closing record once its recorded compensation is left out.
    let limit = u32::try_from(base + 8192).unwrap();
    assert!(base <= kronik_sched::record_budget::turn_limit(limit as usize));

    let p = start_with(dir.path(), limit, None, Some(storage.clone()), Some(4096));
    let mut closed = None;
    for _ in 0..600 {
        closed = bodies(dir.path())
            .into_iter()
            .find_map(|(_, record, _)| match record {
                Record::TurnRecord(t) if t.execution_id == execution_id => Some(t),
                _ => None,
            });
        if closed.is_some() && p.node.store().db().open_turns().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let closed = closed.expect("the open turn was never closed");
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
