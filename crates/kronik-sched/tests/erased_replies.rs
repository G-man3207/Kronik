//! A call whose callee's answer belongs to an erased subject (ADR 0123,
//! docs/design/m8-privacy.md §6.8). An erasure must never wedge an actor:
//! the caller's call gets a recorded call error with the code
//! `SUBJECT_ERASED`, live, at a re-run after a restart, and the same way
//! whichever path the answer took, and the caller's turn ends as its guest
//! decides. Nothing is left open to run again at every start.
//!
//! The callee committed, so a caller that fails after the call still owes
//! that change: the call is an orphan and its compensation is delivered
//! exactly once (ADR 0124).
//!
//! A callee whose turn runs across an erasure answers its caller with the
//! erasure's tombstone in place of the subject's values, and its record,
//! which the store keeps as the call's saved outcome, holds the tombstone
//! too. A turn takes its provenance before it waits for a worker permit:
//! with every permit taken, a turn waits there after taking it, so an
//! erasure that begins meanwhile is one the turn runs across.

// Test helpers outside #[test] functions may unwrap, and the test server
// uses plain std threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use common::{Proc, audit, http, msg, start_proc};
use kronik_core::error::ApiError;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{NodeConfig, TurnResult};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
/// `fetch-ok` also runs the request head's `T call <actor> <name>` line,
/// then GETs `<url>/extra`.
const COUNTER_FETCH_EXTRA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter-fetch-extra.wasm"
);

/// The subject whose values counter's `subject` operation writes and
/// answers with (its default subject once it set it).
const ERASED: &str = "user:2";

// ---------------------------------------------------------------- test server

#[derive(Default)]
struct Gates {
    seen: Vec<String>,
    /// Requests to /hang wait until released; to a path ending in /extra
    /// for ever.
    released: bool,
}

struct Server {
    addr: String,
    state: Arc<(Mutex<Gates>, Condvar)>,
}

impl Server {
    fn start() -> Server {
        let state = Arc::new((Mutex::new(Gates::default()), Condvar::new()));
        let st = state.clone();
        let addr = http::serve(move |req, w| serve(req, w, &st));
        Server { addr, state }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn seen(&self, path: &str) -> usize {
        let g = self.state.0.lock().unwrap();
        g.seen.iter().filter(|p| *p == path).count()
    }

    /// Waits until `n` requests to `path` arrived.
    fn wait_for(&self, path: &str, n: usize) {
        let (m, cv) = &*self.state;
        let mut g = m.lock().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while g.seen.iter().filter(|p| *p == path).count() < n {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "no request {n} to {path}");
            g = cv.wait_timeout(g, left).unwrap().0;
        }
    }

    fn release(&self) {
        let (m, cv) = &*self.state;
        m.lock().unwrap().released = true;
        cv.notify_all();
    }
}

fn serve(req: http::Request, w: &mut TcpStream, st: &(Mutex<Gates>, Condvar)) {
    let http::Request { path, .. } = req;
    let (m, cv) = st;
    {
        let mut g = m.lock().unwrap();
        g.seen.push(path.clone());
        cv.notify_all();
        if path.ends_with("/extra") {
            // Never answered: the daemon stops while its turn waits.
            loop {
                g = cv.wait(g).unwrap();
            }
        }
        if path == "/hang" {
            while !g.released {
                g = cv.wait(g).unwrap();
            }
        }
    }
    let reply = "ok";
    let resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\n\r\n{reply}",
        reply.len()
    );
    let _ = w.write_all(resp.as_bytes());
}

// ---------------------------------------------------------------- daemon

/// Two worker permits: two turns that wait take them all, and the next turn
/// waits for one after it took its provenance. With `hold_after_call`, a
/// caller's turn stops for good after its call had its answer, before it
/// records it (a crash there).
fn start(dir: &Path, hold_after_call: bool) -> Proc {
    start_proc(
        dir,
        NodeConfig {
            concurrency: 2,
            test_hold_after_call: hold_after_call,
            ..NodeConfig::default()
        },
    )
}

fn reply_text(outcome: Option<&pb::Outcome>) -> String {
    match outcome.and_then(|o| o.output.as_ref()) {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            other => format!("{other:?}"),
        },
        other => format!("{other:?}"),
    }
}

/// The call error of a call whose callee's answer belongs to an erased
/// subject: `call-error::failed` with this text.
const ERASED_ERROR: &str = "SUBJECT_ERASED: the call's response belonged to an erased subject";

/// What counter's `call` operation answers for that call error.
fn assert_erased_reply(text: &str) {
    assert!(
        text.starts_with("error ") && text.contains("Failed") && text.contains(ERASED_ERROR),
        "{text}"
    );
}

type Pending = tokio::task::JoinHandle<Result<Option<TurnResult>, ApiError>>;

impl Proc {
    /// Deploys `wasm` (a counter build), grants it the test server and sets
    /// the privacy mode.
    fn setup(&self, wasm: &str, mode: pb::PrivacyState) {
        let bytes = std::fs::read(wasm).unwrap();
        self.rt.block_on(async {
            self.node
                .deploy(&bytes, audit(), false, self.owner())
                .await
                .unwrap();
            self.node
                .grant(
                    "counter",
                    "http:127.0.0.1",
                    None,
                    None,
                    kronik_effects::InForks::Recorded,
                    audit(),
                    false,
                    self.owner(),
                )
                .await
                .unwrap();
            self.node
                .set_privacy_mode(mode, audit(), false, self.owner())
                .await
                .unwrap();
        });
    }

    /// Sends `m` to `actor` without waiting for the turn.
    fn send_detached(&self, actor: &str, m: pb::Message) -> Pending {
        let node = self.node.clone();
        let actor = ActorRef::parse(actor).unwrap();
        self.rt.spawn(async move {
            let original = node.local_operator_authority().unwrap();
            node.send(actor, m, audit(), false, original).await
        })
    }

    fn send(&self, actor: &str, m: pb::Message) -> TurnResult {
        let pending = self.send_detached(actor, m);
        self.rt.block_on(pending).unwrap().unwrap().unwrap()
    }

    fn erase(&self, subject: &str) -> u64 {
        self.rt
            .block_on(
                self.node
                    .erase_subject(subject, audit(), false, self.owner()),
            )
            .unwrap()
            .lsn
            .unwrap()
    }

    /// Waits up to 30 s for `f`.
    fn wait_until(&self, what: &str, f: impl Fn(&Proc) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !f(self) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// How many turns `counter/<key>` committed or failed.
    fn turns(&self, key: &str) -> u64 {
        self.node
            .store()
            .db()
            .actor("counter", key)
            .unwrap()
            .map_or(0, |a| a.turns)
    }

    fn open_turns(&self) -> usize {
        self.node.store().db().open_turns().unwrap().len()
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

    /// The turn records of `counter/<key>`.
    fn turn_records(&self, key: &str) -> Vec<pb::TurnRecord> {
        self.records()
            .into_iter()
            .filter_map(|r| match r {
                Record::TurnRecord(t) if t.actor.as_ref().is_some_and(|a| a.key == key) => Some(t),
                _ => None,
            })
            .collect()
    }

    /// A blocker on `counter/<key>`: a turn that waits for the test server's
    /// /hang, holding a worker permit until it is released.
    fn block(&self, server: &Server, key: &str) -> Pending {
        self.send_detached(
            &format!("counter/{key}"),
            msg("fetch-ok", format!("GET {}", server.url("/hang"))),
        )
    }

    /// Waits until `waiting` turns have taken their provenance: those that
    /// hold both permits and the one that waits for a permit. Then erases
    /// user:2, which the waiting turn runs across, releases the blockers and
    /// returns the erasure's LSN.
    fn erase_while_waiting(&self, server: &Server, waiting: usize) -> u64 {
        self.wait_until("the turn that waits for a permit", |p| {
            p.node.running_turns() == waiting
        });
        let lsn = self.erase(ERASED);
        server.release();
        lsn
    }
}

/// The caller's recorded `actor.call`: a call error with the code, no
/// response, and the callee's committed source (ADR 0124).
fn erased_call(caller: &pb::TurnRecord) -> &pb::EffectRecord {
    let calls: Vec<&pb::EffectRecord> = caller
        .effects
        .iter()
        .filter(|e| e.kind == "actor.call")
        .collect();
    assert_eq!(calls.len(), 1, "{caller:?}");
    let call = calls[0];
    assert_eq!(call.status, pb::EffectStatus::Failed as i32, "{call:?}");
    assert_eq!(call.error, ERASED_ERROR);
    assert!(call.response.is_none(), "{call:?}");
    assert!(call.callee_source.is_some(), "{call:?}");
    assert!(call.successful_call(), "{call:?}");
    call
}

/// The caller's turn committed after it chose to handle the call error.
fn assert_erased_call(caller: &pb::TurnRecord) {
    erased_call(caller);
    assert_eq!(
        caller.outcome.as_ref().map(|o| o.kind),
        Some(pb::OutcomeKind::Committed as i32),
        "{caller:?}"
    );
    assert_erased_reply(&reply_text(caller.outcome.as_ref()));
}

/// The callee's committed record: its answer is the erasure's tombstone.
fn assert_tombstoned_answer(callee: &pb::TurnRecord) {
    let Some(pb::outcome::Output::Reply(reply)) =
        callee.outcome.as_ref().and_then(|o| o.output.as_ref())
    else {
        panic!("no reply: {callee:?}")
    };
    let body = reply.body.as_ref().unwrap();
    assert_eq!(body.subject.as_deref(), Some(ERASED));
    assert!(
        kronik_privacy::sealer::is_erased(body),
        "the callee's answer is not the tombstone: {body:?}"
    );
}

const MODES: [pb::PrivacyState; 2] = [pb::PrivacyState::On, pb::PrivacyState::Off];

/// The callee (counter/w, whose `subject` operation answers with a value of
/// user:2) waits for a worker permit while user:2 is erased, then runs, and
/// answers its caller with the tombstone. The caller (counter/a, an
/// operator's message without a subject) gets a recorded call error with
/// the code `SUBJECT_ERASED`, which its guest answers with, and its turn
/// commits. Before, the call met a missing prerequisite (`UNAVAILABLE`):
/// the caller's turn stayed open, to meet it again at every start.
#[test]
fn an_answer_an_erasure_tombstoned_is_a_subject_erased_call_error() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::start();
        let p = start(dir.path(), false);
        p.setup(COUNTER, mode);
        let blocker = p.block(&server, "blk");
        server.wait_for("/hang", 1);
        let caller = p.send_detached("counter/a", msg("call", "counter/w subject"));
        p.erase_while_waiting(&server, 3);
        let r = p.rt.block_on(caller).unwrap();
        let r = r.unwrap_or_else(|e| panic!("{mode:?}: the caller's turn: {e}"));
        let r = r.unwrap();
        assert!(r.committed(), "{mode:?}: {r:?}");
        assert_erased_reply(&reply_text(Some(&r.outcome)));
        assert!(
            p.rt.block_on(blocker)
                .unwrap()
                .unwrap()
                .unwrap()
                .committed()
        );
        assert_tombstoned_answer(&p.turn_records("w")[0]);
        let a = p.turn_records("a");
        assert_eq!(a.len(), 1, "{mode:?}: {a:?}");
        assert_erased_call(&a[0]);
        assert_eq!(p.open_turns(), 0, "{mode:?}");
        assert_eq!(p.turns("w"), 1, "{mode:?}: the callee ran once");
        // A restart runs nothing again, and counter/a takes its next input.
        drop(p);
        let p = start(dir.path(), false);
        assert_eq!(p.open_turns(), 0, "{mode:?}");
        let next = p.send("counter/a", msg("get", ""));
        assert!(next.committed(), "{mode:?}: {next:?}");
        assert_eq!(p.turns("a"), 2, "{mode:?}");
    }
}

/// The same erased answer, but the caller's turn fails after the call and
/// carries a compensation. The callee's write stands; the caller's failed
/// turn must name it an orphan and deliver the compensation exactly once
/// (ADR 0124), as it does for a readable answer. Before, the erased answer
/// was recorded as a plain failed call and both were silently lost.
#[test]
fn a_failed_caller_orphans_an_erased_answer_and_delivers_its_compensation() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::start();
        let p = start(dir.path(), false);
        p.setup(COUNTER, mode);
        let blocker = p.block(&server, "blk");
        server.wait_for("/hang", 1);
        let caller = p.send_detached("counter/a", msg("call-fail", "counter/w subject increment"));
        p.erase_while_waiting(&server, 3);
        let r = p.rt.block_on(caller).unwrap().unwrap().unwrap();
        assert!(!r.committed(), "{mode:?}: {r:?}");
        assert!(
            r.outcome.message.contains(ERASED_ERROR),
            "{mode:?}: the guest did not see the erased call error: {r:?}"
        );
        assert!(
            p.rt.block_on(blocker)
                .unwrap()
                .unwrap()
                .unwrap()
                .committed()
        );

        // The compensation ran once, as an ordinary compensation message.
        p.wait_until("the compensation's turn", |p| {
            p.turns("a") == 1 && p.turns("w") == 2
        });
        let w = p.turn_records("w");
        assert_eq!(w.len(), 2, "{mode:?}: {w:?}");
        let compensation = message_input(&w[1]).expect("the second turn is a message");
        assert_eq!(
            compensation.source,
            pb::MessageSource::Compensation as i32,
            "{mode:?}: {compensation:?}"
        );
        assert_eq!(
            compensation.sender.as_ref().map(|a| a.key.as_str()),
            Some("a"),
            "{mode:?}: {compensation:?}"
        );
        assert_eq!(
            compensation.msg.as_ref().map(|m| m.name.as_str()),
            Some("increment"),
            "{mode:?}: {compensation:?}"
        );

        let a = p.turn_records("a");
        assert_eq!(a.len(), 1, "{mode:?}: {a:?}");
        let call = erased_call(&a[0]);
        assert_eq!(
            call.observed_callee_status,
            Some(pb::EffectStatus::Ok as i32),
            "{mode:?}: {call:?}"
        );
        assert_eq!(
            a[0].outcome.as_ref().map(|o| o.kind),
            Some(pb::OutcomeKind::Failed as i32),
            "{mode:?}: {a:?}"
        );
        let source = call.callee_source.as_ref().unwrap();
        assert_eq!(source.branch, "main", "{mode:?}");
        assert!(source.lsn > 0, "{mode:?}");

        // Exactly one orphan, naming the callee's committed turn, the call
        // and the compensation, and resolved by the compensation's turn.
        let orphans = p.node.store().db().orphans(true).unwrap();
        assert_eq!(orphans.len(), 1, "{mode:?}: {orphans:?}");
        let orphan = &orphans[0];
        assert_eq!(orphan.callee.to_string(), "counter/w", "{mode:?}");
        assert_eq!(orphan.caller.to_string(), "counter/a", "{mode:?}");
        assert_eq!(
            orphan.compensation_id.as_deref(),
            Some(compensation.message_id.as_str()),
            "{mode:?}"
        );
        assert_eq!(
            orphan.callee_turn,
            format!("{}:{}", source.branch, source.lsn),
            "{mode:?}"
        );
        assert!(orphan.resolved_lsn.is_some(), "{mode:?}: {orphan:?}");
        assert_eq!(p.open_turns(), 0, "{mode:?}");

        // Nothing is left to run again at the next start.
        drop(p);
        let p = start(dir.path(), false);
        assert_eq!(p.open_turns(), 0, "{mode:?}");
        assert_eq!(p.turns("a"), 1, "{mode:?}");
        assert_eq!(p.turns("w"), 2, "{mode:?}");
    }
}

fn message_input(turn: &pb::TurnRecord) -> Option<&pb::MessageInput> {
    match turn.input.as_ref()?.kind.as_ref()? {
        pb::input::Kind::Message(m) => Some(m),
        _ => None,
    }
}

/// The same call, with the daemon stopped after the caller's call had its
/// answer and before it recorded it. At the next start the caller's turn
/// runs again and its call gets the callee's saved outcome, which holds the
/// tombstone: a recorded `SUBJECT_ERASED` call error, the turn commits, the
/// callee ran once, and the start after runs nothing again. Before, every
/// run of the turn met `UNAVAILABLE`: the worker tried twelve times (about
/// 36 s, the actor's other inputs waiting behind it) and left the turn open
/// for the next start.
#[test]
fn a_rerun_caller_gets_the_saved_tombstoned_answer_as_subject_erased() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::start();
        let p = start(dir.path(), true);
        p.setup(COUNTER, mode);
        let _blocker = p.block(&server, "blk");
        server.wait_for("/hang", 1);
        let _caller = p.send_detached("counter/a", msg("call", "counter/w subject"));
        p.erase_while_waiting(&server, 3);
        p.wait_until("the callee's and the blocker's commits", |p| {
            p.turns("w") == 1 && p.turns("blk") == 1
        });
        assert_eq!(p.open_turns(), 1, "{mode:?}: the caller's turn is open");
        drop(p); // the daemon stops: the caller's turn stays open
        let p = start(dir.path(), false);
        p.wait_until("the caller's turn to end", |p| {
            p.open_turns() == 0 && p.turns("a") == 1
        });
        let a = p.turn_records("a");
        assert_eq!(a.len(), 1, "{mode:?}: {a:?}");
        assert_erased_call(&a[0]);
        assert_eq!(p.turns("w"), 1, "{mode:?}: the callee ran once");
        drop(p);
        let p = start(dir.path(), false);
        assert_eq!(p.open_turns(), 0, "{mode:?}");
        assert_eq!(p.turns("a"), 1, "{mode:?}: nothing ran again");
    }
}

/// The callee committed its answer, a value of user:2, before user:2 was
/// erased, and the daemon stopped before the caller recorded its call.
/// Applying the erasure replaced the callee's saved outcome with the store's
/// `SUBJECT_ERASED` failure, so the caller's turn, run again at the next
/// start, already got a recorded call error and committed; it now carries
/// the code, as the call error of a tombstoned answer does.
#[test]
fn a_saved_answer_erased_after_the_callee_committed_is_the_same_call_error() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let p = start(dir.path(), true);
        p.setup(COUNTER, mode);
        let _caller = p.send_detached("counter/a", msg("call", "counter/w subject"));
        p.wait_until("the callee's commit", |p| p.turns("w") == 1);
        p.erase(ERASED);
        drop(p);
        let p = start(dir.path(), false);
        p.wait_until("the caller's turn to end", |p| {
            p.open_turns() == 0 && p.turns("a") == 1
        });
        let a = p.turn_records("a");
        assert_eq!(a.len(), 1, "{mode:?}: {a:?}");
        assert_erased_call(&a[0]);
        assert_eq!(p.turns("w"), 1, "{mode:?}: the callee ran once");
    }
}

/// The caller took its provenance before user:2 was erased (it waited for a
/// permit), and made its call after the erasure's record: the callee's
/// answer is new data of user:2, which the caller's guest read, but the
/// caller's record of the call holds the tombstone (its provenance
/// predates the erasure). The daemon stops while the caller's turn waits
/// for its next request. At the next start its recorded call result cannot
/// be served again: the turn is closed with `SUBJECT_ERASED` (a dead
/// letter) without running its guest, as a re-run whose recorded effects
/// hold a value of a subject erased since it began is. Before, the re-run
/// met the tombstone as a missing secret (`SECRET_UNAVAILABLE`), which the
/// worker waits for without bound: the actor took no other input again.
#[test]
fn a_rerun_whose_recorded_answer_is_a_tombstone_closes_as_subject_erased() {
    for mode in MODES {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::start();
        let p = start(dir.path(), false);
        p.setup(COUNTER_FETCH_EXTRA, mode);
        let _b1 = p.block(&server, "b1");
        let _b2 = p.block(&server, "b2");
        server.wait_for("/hang", 2);
        let spec = format!("GET {}\nT call counter/w subject", server.url("/first"));
        let _caller = p.send_detached("counter/a", msg("fetch-ok", &spec));
        let erased = p.erase_while_waiting(&server, 3);
        // The caller recorded its call, then asked for /first/extra.
        server.wait_for("/first/extra", 1);
        p.wait_until("the blockers' commits", |p| {
            p.turns("b1") == 1 && p.turns("b2") == 1
        });
        let begun = p.node.store().db().open_turns().unwrap();
        assert_eq!(begun.len(), 1, "{mode:?}: {begun:?}");
        let call = p
            .node
            .store()
            .db()
            .open_effects(&begun[0].execution_id)
            .unwrap()
            .into_iter()
            .find(|e| e.kind == "actor.call")
            .unwrap();
        assert_eq!(call.status, pb::EffectStatus::Ok as i32, "{mode:?}");
        assert!(
            kronik_privacy::sealer::is_erased(call.response.as_ref().unwrap()),
            "{mode:?}: the recorded answer is not the tombstone: {call:?}"
        );
        assert!(
            begun[0].lsn > erased,
            "{mode:?}: the turn began after the erasure"
        );
        drop(p);
        let p = start(dir.path(), false);
        p.wait_until("the caller's turn to end", |p| p.open_turns() == 0);
        let letters = p.node.store().db().dead_letters(0, 10).unwrap();
        assert_eq!(
            letters
                .iter()
                .map(|d| (d.actor.key.as_str(), d.error_code.as_str()))
                .collect::<Vec<_>>(),
            [("a", "SUBJECT_ERASED")],
            "{mode:?}"
        );
        // The guest did not run again: nothing was requested again.
        assert_eq!(server.seen("/first"), 1, "{mode:?}");
        assert_eq!(server.seen("/first/extra"), 1, "{mode:?}");
        assert_eq!(p.turns("w"), 1, "{mode:?}: the callee ran once");
        let next = p.send("counter/a", msg("get", ""));
        assert!(next.committed(), "{mode:?}: {next:?}");
    }
}
