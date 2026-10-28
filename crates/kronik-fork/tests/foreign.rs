//! Copies of `fork_mode = "sandbox"` foreign actors in forks (M14,
//! docs/design/m14-foreign-forks.md) against a real node, with an
//! in-memory host whose actor and copies keep the requests they got as
//! their state. `crates/kronik/tests/foreign.rs` runs it with gVisor and
//! Postgres.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use common::*;
use kronik_core::env::{BoxFuture, HttpRequest, HttpResponse, NetError};
use kronik_effects::foreign::{Checkpoint, CopySpec, ForeignCopy, ForeignHost, ForeignSlot};
use kronik_fork::diff::{DiffOptions, ForeignFork};
use kronik_fork::proposal::Proposals;
use kronik_proto::log::v1 as pb;
use kronik_sched::NodeConfig;

/// A service whose state is the bodies it was sent; it answers
/// `<count>:<body>`.
#[derive(Default)]
struct Service(Mutex<Vec<String>>);

impl Service {
    fn answer(&self, req: &HttpRequest) -> HttpResponse {
        let mut s = self.0.lock().unwrap();
        s.push(String::from_utf8_lossy(&req.body).into_owned());
        HttpResponse {
            status: 200,
            headers: vec![],
            body: format!("{}:{}", s.len(), s.last().unwrap())
                .into_bytes()
                .into(),
        }
    }
}

#[derive(Default)]
struct Host {
    prod: Service,
    checkpoints: Mutex<BTreeMap<u64, Vec<String>>>,
    copies: Mutex<Vec<Arc<Copy>>>,
    /// Per start: whether every earlier copy of the same fork was stopped.
    clean_starts: Mutex<Vec<bool>>,
    /// A checkpoint waits until this is set (or 10 s pass) and fails
    /// without it.
    slow: Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>,
    /// The data size its checkpoints report (default 1).
    ck_bytes: Mutex<Option<u64>>,
    /// While set, calls to copies wait.
    hold_copies: Arc<std::sync::atomic::AtomicBool>,
}

struct Copy {
    fork: String,
    service: Service,
    stopped: Mutex<bool>,
    hold: Arc<std::sync::atomic::AtomicBool>,
}

impl ForeignCopy for Copy {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let r = self.service.answer(&req);
        let hold = self.hold.clone();
        Box::pin(async move {
            while hold.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok(r)
        })
    }
    fn stop(&self) -> BoxFuture<'static, ()> {
        *self.stopped.lock().unwrap() = true;
        Box::pin(async {})
    }
}

impl ForeignHost for Host {
    fn reconcile(
        &self,
        _: Vec<pb::ForeignActor>,
        _: Option<Arc<kronik_privacy::SecretStore>>,
    ) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
    fn http(
        &self,
        _: &str,
        req: HttpRequest,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let r = self.prod.answer(&req);
        Box::pin(async move { Ok(r) })
    }
    fn checkpoint(
        &self,
        name: &str,
        lsn: u64,
        hold: Box<dyn std::any::Any + Send>,
        _budget: Option<u64>,
    ) -> BoxFuture<'static, Result<Checkpoint, String>> {
        let state = self.prod.0.lock().unwrap().clone();
        self.checkpoints.lock().unwrap().insert(lsn, state);
        drop(hold);
        let c = ck(name, lsn);
        let slow = self.slow.lock().unwrap().clone();
        Box::pin(async move {
            if let Some(flag) = slow {
                for _ in 0..200 {
                    if flag.load(std::sync::atomic::Ordering::SeqCst) {
                        return Ok(c);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                return Err("main did not run during the checkpoint".into());
            }
            Ok(c)
        })
    }
    fn checkpoints(&self, name: &str) -> Vec<Checkpoint> {
        self.checkpoints
            .lock()
            .unwrap()
            .keys()
            .map(|lsn| Checkpoint {
                bytes: self.ck_bytes.lock().unwrap().unwrap_or(1),
                ..ck(name, *lsn)
            })
            .collect()
    }
    fn start_copy(
        &self,
        spec: CopySpec,
    ) -> BoxFuture<'static, Result<Arc<dyn ForeignCopy>, String>> {
        let state = self.checkpoints.lock().unwrap()[&spec.checkpoint.lsn].clone();
        let copy = Arc::new(Copy {
            fork: spec.fork.clone(),
            service: Service(Mutex::new(state)),
            stopped: Mutex::new(false),
            hold: self.hold_copies.clone(),
        });
        let mut copies = self.copies.lock().unwrap();
        let clean = copies
            .iter()
            .filter(|c| c.fork == spec.fork)
            .all(|c| *c.stopped.lock().unwrap());
        self.clean_starts.lock().unwrap().push(clean);
        copies.push(copy.clone());
        Box::pin(async move { Ok(copy as Arc<dyn ForeignCopy>) })
    }
}

fn ck(name: &str, lsn: u64) -> Checkpoint {
    Checkpoint {
        name: name.into(),
        lsn,
        dir: std::path::PathBuf::new(),
        at_ms: 0,
        bytes: 1,
    }
}

fn message(body: &str) -> pb::Message {
    pb::Message {
        name: "fetch-ok".into(),
        content_type: "text/plain".into(),
        body: plain(body),
        blobs: vec![],
    }
}

fn reply(t: &kronik_fork::ForkTurn) -> String {
    match t.record.outcome.as_ref().and_then(|o| o.output.as_ref()) {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

#[test]
fn a_continuous_fork_talks_to_a_copy_from_the_nearest_checkpoint() {
    let dir = tempdir();
    let host = Arc::new(Host::default());
    let p = Proc::start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            foreign: ForeignSlot(Some(host.clone())),
            ..NodeConfig::default()
        },
    );
    p.grant("foreign:pg");
    p.rt.block_on(p.node.foreign_add(
        pb::ForeignActor {
            name: "pg".into(),
            image: "oci-layout:/x@sha256:00".into(),
            port: 8080,
            isolation: pb::Isolation::Gvisor as i32,
            fork_mode: "sandbox".into(),
            ..Default::default()
        },
        audit(),
        false,
    ))
    .unwrap();
    let call = |body: &str| {
        p.send(
            "counter/c1",
            "fetch-ok",
            &format!("POST foreign://pg/sql\n\n{body}"),
        )
    };
    let before = call("a").turn_id.lsn;
    let checkpointed = p.rt.block_on(p.node.checkpoint_foreign());
    let ck_lsn = checkpointed[0].1.as_ref().unwrap().lsn;
    assert!(ck_lsn >= before);
    let fork_lsn = call("b").turn_id.lsn;
    call("c");
    assert_eq!(*host.prod.0.lock().unwrap(), ["a", "b", "c"]);

    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    let continuous = DiffOptions {
        mode: kronik_fork::diff::Mode::Continuous,
        ..DiffOptions::default()
    };
    let replay = |name: &str, at: u64, code: &str| {
        p.rt.block_on(props.create_fork(Some(name.into()), at, false, audit(), false))
            .unwrap();
        let wasm = std::fs::read(guest(code)).unwrap();
        p.rt.block_on(props.fork_deploy(name, &wasm, false))
            .unwrap();
        p.rt.block_on(props.fork_replay(name, None, continuous.clone(), None))
            .unwrap();
        let d: serde_json::Value =
            serde_json::from_slice(&p.rt.block_on(props.diff(name, false, false)).unwrap())
                .unwrap();
        d
    };

    // New code changes the request: the copy (checkpoint "a", then main's
    // "b" replayed) answers it, graded forked.
    let d = replay("changed", fork_lsn, "counter-body-v2");
    assert_eq!(
        serde_json::from_value::<Vec<ForeignFork>>(d["options"]["foreign"].clone()).unwrap(),
        [ForeignFork {
            name: "pg".into(),
            mode: "sandbox".into(),
            checkpoint_lsn: Some(ck_lsn),
            replayed_calls: 1,
            why: String::new(),
        }]
    );
    assert_eq!(
        (&d["summary"]["forked"], &d["summary"]["exact"]),
        (&1.into(), &0.into())
    );
    let copy = host.copies.lock().unwrap()[0].clone();
    assert_eq!(*copy.service.0.lock().unwrap(), ["a", "b", "c v2"]);
    // Messages into the fork go to the same copy.
    let actor = kronik_core::ids::ActorRef::parse("counter/c1").unwrap();
    let t =
        p.rt.block_on(props.fork_send("changed", actor, message("POST foreign://pg/sql\n\nd")))
            .unwrap();
    assert_eq!(reply(&t), "200 4:d v2");
    assert_eq!(t.record.effects[0].grounding, pb::Grounding::Forked as i32);
    assert_eq!(*host.prod.0.lock().unwrap(), ["a", "b", "c"]);
    // The copy goes with the fork.
    p.rt.block_on(props.delete_fork("changed", false)).unwrap();
    assert!(*copy.stopped.lock().unwrap());

    // The same code: production's answer stays (exact), and the copy still
    // gets the call so its state follows the fork.
    let d = replay("same", fork_lsn, "counter");
    assert_eq!(
        (&d["summary"]["forked"], &d["summary"]["exact"]),
        (&0.into(), &1.into())
    );
    let copy = host.copies.lock().unwrap()[1].clone();
    assert_eq!(*copy.service.0.lock().unwrap(), ["a", "b", "c"]);

    // No checkpoint at or before the fork point: recorded answers, and why.
    let d = replay("early", before - 1, "counter-body-v2");
    assert_eq!(d["options"]["foreign"][0]["mode"], "recorded");
    assert!(
        d["options"]["foreign"][0]["why"]
            .as_str()
            .unwrap()
            .starts_with("no checkpoint at or before the fork point"),
        "{d}"
    );
    assert_eq!(d["summary"]["forked"], 0);
    assert_eq!(host.copies.lock().unwrap().len(), 2);
}

/// A node with the in-memory host and a `sandbox` actor `pg`; `a` is
/// called before the checkpoint, `b` and `c` after. Returns the fork point
/// (the turn of `b`).
fn pg_node(dir: &std::path::Path, host: &Arc<Host>) -> (Proc, Arc<Proposals>, u64) {
    let p = Proc::start_with(
        dir,
        NodeConfig {
            concurrency: 8,
            foreign: ForeignSlot(Some(host.clone())),
            // A reserve, so the disk budget is known (review N14-2).
            disk_reserve: 1,
            ..NodeConfig::default()
        },
    );
    p.grant("foreign:pg");
    p.rt.block_on(p.node.foreign_add(
        pb::ForeignActor {
            name: "pg".into(),
            image: "oci-layout:/x@sha256:00".into(),
            port: 8080,
            isolation: pb::Isolation::Gvisor as i32,
            fork_mode: "sandbox".into(),
            ..Default::default()
        },
        audit(),
        false,
    ))
    .unwrap();
    call(&p, "a");
    p.rt.block_on(p.node.checkpoint_foreign())[0]
        .1
        .as_ref()
        .unwrap();
    let fork_lsn = call(&p, "b");
    call(&p, "c");
    let props = Arc::new(Proposals::open(p.node.clone(), dir.to_path_buf()).unwrap());
    (p, props, fork_lsn)
}

fn call(p: &Proc, body: &str) -> u64 {
    p.send(
        "counter/c1",
        "fetch-ok",
        &format!("POST foreign://pg/sql\n\n{body}"),
    )
    .turn_id
    .lsn
}

fn fork_diff(p: &Proc, props: &Proposals, name: &str) -> serde_json::Value {
    serde_json::from_slice(&p.rt.block_on(props.diff(name, false, false)).unwrap()).unwrap()
}

fn new_fork(p: &Proc, props: &Proposals, name: &str, at: u64, no_pii: bool, code: &str) {
    p.rt.block_on(props.create_fork(Some(name.into()), at, no_pii, audit(), false))
        .unwrap();
    let wasm = std::fs::read(guest(code)).unwrap();
    p.rt.block_on(props.fork_deploy(name, &wasm, false))
        .unwrap();
}

fn propose_at(
    p: &Proc,
    props: &Arc<Proposals>,
    at: u64,
    code: &str,
    dry_run: bool,
) -> kronik_fork::proposal::Proposal {
    p.rt.block_on(props.propose(kronik_fork::proposal::ProposeRequest {
        wasm: vec![std::fs::read(guest(code)).unwrap()],
        names: Vec::new(),
        window_ms: None,
        at: Some(at),
        options: DiffOptions::default(),
        workers: Some(2),
        audit: audit(),
        dry_run,
    }))
    .unwrap()
    .0
}

/// Review H11: a second replay stops the fork's old copy before it starts
/// the new one.
#[test]
fn a_second_replay_stops_the_old_copy_first() {
    let dir = tempdir();
    let host = Arc::new(Host::default());
    let (p, props, fork_lsn) = pg_node(dir.path(), &host);
    new_fork(&p, &props, "f", fork_lsn, false, "counter-body-v2");
    let continuous = DiffOptions {
        mode: kronik_fork::diff::Mode::Continuous,
        ..DiffOptions::default()
    };
    for _ in 0..2 {
        p.rt.block_on(props.fork_replay("f", None, continuous.clone(), None))
            .unwrap();
    }
    assert_eq!(*host.clean_starts.lock().unwrap(), [true, true]);
    // A deployment into the fork stops its copy too.
    new_fork(&p, &props, "g", fork_lsn, false, "counter-body-v2");
    p.rt.block_on(props.fork_replay("g", None, continuous, None))
        .unwrap();
    let wasm = std::fs::read(guest("counter")).unwrap();
    p.rt.block_on(props.fork_deploy("g", &wasm, false)).unwrap();
    assert!(*host.copies.lock().unwrap()[2].stopped.lock().unwrap());
}

/// Review H12: in the default `both` mode the copied actor's answers are
/// the continuous view's (forked), not the isolated view's (approximate).
#[test]
fn both_mode_takes_copied_answers_from_the_continuous_view() {
    let dir = tempdir();
    let host = Arc::new(Host::default());
    let (p, props, fork_lsn) = pg_node(dir.path(), &host);
    new_fork(&p, &props, "f", fork_lsn, false, "counter-body-v2");
    p.rt.block_on(props.fork_replay("f", None, DiffOptions::default(), None))
        .unwrap();
    let d = fork_diff(&p, &props, "f");
    assert_eq!(d["options"]["mode"], "both", "{d}");
    assert_eq!(
        (&d["summary"]["forked"], &d["summary"]["approximate"]),
        (&1.into(), &0.into()),
        "{d}"
    );
    let items = d["effects"]["items"].as_array().unwrap();
    assert!(!items.is_empty(), "{d}");
    assert!(items.iter().all(|i| i["grounding"] == "forked"), "{d}");
}

/// Review H13: a fork without personal data gets no copies.
#[test]
fn a_fork_without_personal_data_gets_no_copies() {
    let dir = tempdir();
    let host = Arc::new(Host::default());
    let (p, props, fork_lsn) = pg_node(dir.path(), &host);
    new_fork(&p, &props, "f", fork_lsn, true, "counter-body-v2");
    let continuous = DiffOptions {
        mode: kronik_fork::diff::Mode::Continuous,
        ..DiffOptions::default()
    };
    p.rt.block_on(props.fork_replay("f", None, continuous, None))
        .unwrap();
    let d = fork_diff(&p, &props, "f");
    assert_eq!(d["options"]["foreign"][0]["mode"], "recorded", "{d}");
    assert_eq!(
        d["options"]["foreign"][0]["why"],
        "a fork without personal data gets no copies"
    );
    assert_eq!(d["summary"]["forked"], 0);
    assert!(host.copies.lock().unwrap().is_empty());
}

/// Review M11: calls of a turn that spans the fork point reach the copy
/// once (the fork re-runs the turn), not twice.
#[test]
fn calls_of_a_turn_across_the_fork_point_reach_the_copy_once() {
    let dir = tempdir();
    let host = Arc::new(Host::default());
    let (p, props, b) = pg_node(dir.path(), &host);
    // Inside b's turn: its call is logged, its turn record is not.
    new_fork(&p, &props, "f", b - 1, false, "counter");
    let continuous = DiffOptions {
        mode: kronik_fork::diff::Mode::Continuous,
        ..DiffOptions::default()
    };
    p.rt.block_on(props.fork_replay("f", None, continuous, None))
        .unwrap();
    let d = fork_diff(&p, &props, "f");
    assert_eq!(d["options"]["foreign"][0]["replayed_calls"], 0, "{d}");
    let copy = host.copies.lock().unwrap()[0].clone();
    assert_eq!(*copy.service.0.lock().unwrap(), ["a", "b", "c"]);
}

/// Review H8 (M14 part) and L1: a dry run and a rollback via replay start
/// no copies; M13: a rejected proposal stops its copies.
#[test]
fn dry_runs_rebases_and_rejected_proposals_keep_no_copies() {
    let dir = tempdir();
    let host = Arc::new(Host::default());
    let (p, props, fork_lsn) = pg_node(dir.path(), &host);
    let quiet = "[[rule]]\nname = \"quiet\"\nwhen = \"false\"\naction = \"allow\"\n";
    p.rt.block_on(p.node.set_policy(quiet, audit(), false))
        .unwrap();
    let prop = propose_at(&p, &props, fork_lsn, "counter-body-v2", true);
    assert!(prop.summary["forked"] == 0, "{}", prop.summary);
    assert!(host.copies.lock().unwrap().is_empty());

    let prop = propose_at(&p, &props, fork_lsn, "counter-body-v2", false);
    assert_eq!(prop.summary["forked"], 1, "{}", prop.summary);
    let epoch =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap()
            .epoch;
    let copies = host.copies.lock().unwrap().len();
    assert!(*host.copies.lock().unwrap()[0].stopped.lock().unwrap());
    call(&p, "d");
    let (r, _) =
        p.rt.block_on(props.rebase(kronik_fork::proposal::RebaseRequest {
            epoch,
            options: DiffOptions::default(),
            workers: Some(2),
            audit: audit(),
            dry_run: false,
        }))
        .unwrap();
    let d = fork_diff(&p, &props, &r.id);
    assert_eq!(d["options"]["foreign"][0]["mode"], "recorded", "{d}");
    assert_eq!(
        d["options"]["foreign"][0]["why"],
        "a rollback via replay answers from production's recordings only"
    );
    assert_eq!(host.copies.lock().unwrap().len(), copies);

    let deny = "[[rule]]\nname = \"no\"\nwhen = \"true\"\naction = \"deny\"\n";
    p.rt.block_on(p.node.set_policy(deny, audit(), false))
        .unwrap();
    let prop = propose_at(&p, &props, fork_lsn, "counter", false);
    assert_eq!(prop.status, "rejected");
    let last = host.copies.lock().unwrap().last().unwrap().clone();
    assert!(*last.stopped.lock().unwrap());
}

/// Review M14: main runs while a foreign actor is being checkpointed.
#[test]
fn main_runs_during_a_foreign_checkpoint() {
    let dir = tempdir();
    let host = Arc::new(Host::default());
    let (p, _props, _) = pg_node(dir.path(), &host);
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    *host.slow.lock().unwrap() = Some(flag.clone());
    let node = p.node.clone();
    let checkpoint = p.rt.spawn(async move { node.checkpoint_foreign().await });
    std::thread::sleep(std::time::Duration::from_millis(200));
    call(&p, "d");
    flag.store(true, std::sync::atomic::Ordering::SeqCst);
    let r = p.rt.block_on(checkpoint).unwrap();
    assert!(r[0].1.is_ok(), "{r:?}");
}

/// Review N14-2: below `[log] disk_reserve` no checkpoint is taken (a
/// warning, not a failed snapshot), and a fork gets no copy whose disk would
/// not fit above the reserve: the actor is `recorded`, with the reason.
#[test]
fn checkpoints_and_copies_keep_to_the_disk_reserve() {
    let dir = tempdir();
    let host = Arc::new(Host::default());
    let (p, props, fork_lsn) = pg_node(dir.path(), &host);
    // A checkpoint that would not fit above the reserve.
    *host.ck_bytes.lock().unwrap() = Some(u64::MAX / 4);
    new_fork(&p, &props, "f", fork_lsn, false, "counter-body-v2");
    let continuous = DiffOptions {
        mode: kronik_fork::diff::Mode::Continuous,
        ..DiffOptions::default()
    };
    p.rt.block_on(props.fork_replay("f", None, continuous, None))
        .unwrap();
    let d = fork_diff(&p, &props, "f");
    assert_eq!(d["options"]["foreign"][0]["mode"], "recorded", "{d}");
    assert!(
        d["options"]["foreign"][0]["why"]
            .as_str()
            .unwrap_or_default()
            .contains("disk_reserve"),
        "{d}"
    );
    assert!(host.copies.lock().unwrap().is_empty());
    drop(props);
    drop(p);

    // Restarted with a reserve no disk has room for: snapshots still work,
    // and no checkpoint is taken.
    let host = Arc::new(Host::default());
    let p = Proc::open(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            foreign: ForeignSlot(Some(host.clone())),
            disk_reserve: u64::MAX / 2,
            ..NodeConfig::default()
        },
    );
    let results = p.rt.block_on(p.node.checkpoint_foreign());
    assert_eq!(results.len(), 1, "{results:?}");
    assert!(results[0].1.is_err(), "{results:?}");
    assert!(host.checkpoints.lock().unwrap().is_empty());
}

/// Review M14 M3: a fork replay cancelled while its copies start (here,
/// while a copy is being brought to the fork point) stops the copies it
/// started; they hold production data and secret values.
#[test]
fn a_cancelled_replay_stops_the_copies_it_started() {
    let dir = tempdir();
    let host = Arc::new(Host::default());
    let (p, props, fork_lsn) = pg_node(dir.path(), &host);
    new_fork(&p, &props, "f", fork_lsn, false, "counter-body-v2");
    host.hold_copies
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let continuous = DiffOptions {
        mode: kronik_fork::diff::Mode::Continuous,
        ..DiffOptions::default()
    };
    p.rt.block_on(async {
        tokio::select! {
            biased;
            r = props.fork_replay("f", None, continuous, None) => panic!("the replay ended: {r:?}"),
            () = async {
                while host.copies.lock().unwrap().is_empty() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            } => {}
        }
    });
    host.hold_copies
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !host
        .copies
        .lock()
        .unwrap()
        .iter()
        .all(|c| *c.stopped.lock().unwrap())
    {
        assert!(
            std::time::Instant::now() < deadline,
            "a copy of the cancelled replay was never stopped"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
