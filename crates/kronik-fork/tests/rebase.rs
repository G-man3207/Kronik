//! Rollback via replay end to end against a real node
//! (docs/design/m13-rebase.md §9).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::collections::BTreeMap;
use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::*;
use kronik_core::error::ErrorCode;
use kronik_core::ids::{ActorRef, CodeHash, Lsn};
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::proposal::{Proposals, ProposeRequest, RebaseRequest};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{Ingress, NodeConfig, SwitchHold, TurnResult};
use serde_json::Value;

const QUIET: &str = "[[rule]]\nname = \"quiet\"\nwhen = \"false\"\naction = \"allow\"\n";

fn kv(p: &Proc, key: &str, k: &str) -> Option<String> {
    p.node
        .store()
        .db()
        .kv_get("counter", key, k)
        .unwrap()
        .map(|v| String::from_utf8(v).unwrap())
}

fn hash(name: &str) -> Vec<u8> {
    CodeHash::of(&std::fs::read(guest(name)).unwrap())
        .0
        .to_vec()
}

/// An increment of counter/`key` with an idempotency key.
fn keyed(p: &Proc, key: &str, idem: &str) -> TurnResult {
    keyed_op(p, key, "increment", "", idem)
}

/// Operation `op` on counter/`key` with `body` and an idempotency key.
fn keyed_op(p: &Proc, key: &str, op: &str, body: &str, idem: &str) -> TurnResult {
    let input = pb::HttpInput {
        method: "POST".into(),
        path: format!("/counter/{key}/{op}"),
        params: vec![
            pb::Param {
                name: "key".into(),
                value: key.into(),
                sealed_value: None,
            },
            pb::Param {
                name: "op".into(),
                value: op.into(),
                sealed_value: None,
            },
        ],
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(plain(body).unwrap())),
        }),
        route: "/counter/{key}/{op}".into(),
        idempotency_key: idem.into(),
        request_hash: blake3::hash(idem.as_bytes()).as_bytes().to_vec(),
        ..Default::default()
    };
    let actor = ActorRef::parse(&format!("counter/{key}")).unwrap();
    match p.node.ingress(actor, input, None).unwrap() {
        Ingress::Started(w) | Ingress::Joined(w) => p.rt.block_on(w.wait()).unwrap(),
        Ingress::Done(r) => *r,
    }
}

struct Setup {
    p: Proc,
    props: Arc<Proposals>,
    /// The rolled-back deployment's epoch.
    epoch: u64,
    hits_after_promote: usize,
    hits: Arc<std::sync::atomic::AtomicUsize>,
}

/// Main runs the counter (schema 0), takes a snapshot, then promotes a
/// schema-1 build that migrates (`schema` = 1) and makes an extra GET for
/// every fetch, and serves traffic under it.
fn setup(dir: &std::path::Path, max_pause: Duration) -> Setup {
    setup_with(
        dir,
        max_pause,
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
    )
}

fn setup_with(dir: &std::path::Path, max_pause: Duration, cfg: NodeConfig) -> Setup {
    setup_full(dir, max_pause, cfg, |_| {})
}

/// `setup_with`, with `before` run on main before any traffic (so the
/// rebase's fork point sees what it configures).
fn setup_full(
    dir: &std::path::Path,
    max_pause: Duration,
    cfg: NodeConfig,
    before: impl FnOnce(&Proc),
) -> Setup {
    setup_env(dir, max_pause, cfg, |_| {}, before)
}

/// `setup_full` on an environment `wrap` changed.
fn setup_env(
    dir: &std::path::Path,
    max_pause: Duration,
    cfg: NodeConfig,
    wrap: impl FnOnce(&mut kronik_core::env::Env),
    before: impl FnOnce(&Proc),
) -> Setup {
    let (addr, hits) = server();
    let p = Proc::start_env(dir, cfg, wrap);
    p.grant("http:127.0.0.1");
    before(&p);
    p.rt.block_on(p.node.set_policy(QUIET, audit(), false))
        .unwrap();
    for _ in 0..3 {
        p.http("a", "increment", "");
    }
    p.http(
        "pay",
        "fetch-ok",
        &format!("POST http://{addr}/v1/charges/0\n\namount=1"),
    );
    p.settle();
    p.rt.block_on(p.node.snapshot("before the deployment"))
        .unwrap();
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.to_path_buf())
            .unwrap()
            .with_rebase(max_pause),
    );
    let bytes = std::fs::read(guest("counter-schema1-extra")).unwrap();
    let (prop, _) =
        p.rt.block_on(props.propose(ProposeRequest {
            wasm: vec![bytes],
            names: Vec::new(),
            window_ms: None,
            at: None,
            options: DiffOptions::default(),
            workers: Some(2),
            audit: audit(),
            dry_run: false,
        }))
        .unwrap();
    let promoted =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap();
    // The new code: the migration runs first, then the increment; the
    // fetch makes the POST and an extra GET, both real.
    assert_eq!(http_body(&p.http("a", "increment", "")), "4");
    p.http(
        "pay",
        "fetch-ok",
        &format!("POST http://{addr}/v1/charges/1\n\namount=1"),
    );
    p.settle();
    assert_eq!(kv(&p, "a", "schema").as_deref(), Some("1"));
    let hits_after_promote = hits.load(Ordering::SeqCst);
    assert_eq!(hits_after_promote, 3, "POST 0, POST 1 and GET 1/extra");
    Setup {
        p,
        props,
        epoch: promoted.epoch,
        hits_after_promote,
        hits,
    }
}

fn rebase(s: &Setup) -> kronik_fork::proposal::Proposal {
    s.p.settle();
    s.p.rt
        .block_on(s.props.rebase(RebaseRequest {
            epoch: s.epoch,
            options: DiffOptions {
                mode: Mode::Continuous,
                ..DiffOptions::default()
            },
            workers: Some(2),
            audit: audit(),
            dry_run: false,
        }))
        .unwrap()
        .0
}

fn switch(s: &Setup, id: &str) -> kronik_fork::proposal::PromoteResult {
    s.p.rt
        .block_on(s.props.approve(id, audit(), false))
        .unwrap();
    s.p.rt
        .block_on(s.props.promote(id, audit(), false))
        .unwrap()
}

/// M13 (1): after a migration, a rollback via replay gives the old code's
/// state and lists the effects the new code made that the old would not.
#[test]
fn rollback_by_replay_after_a_migration_restores_the_old_state() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(2));
    let p = &s.p;
    let r = rebase(&s);
    assert!(r.id.starts_with("r-"), "{}", r.id);
    let info = r.rebase.clone().unwrap();
    assert_eq!(info.rolled_back_epoch, s.epoch);
    let d: Value =
        serde_json::from_slice(&p.rt.block_on(s.props.diff(&r.id, false, false)).unwrap()).unwrap();
    // The extra GET happened under the new code; the POSTs the old code
    // makes too (exact) are not listed.
    let irr = &d["irreversible"];
    assert_eq!(irr["count"], 1, "{irr}");
    assert_eq!(irr["items"][0]["method"], "GET");
    assert_eq!(irr["items"][0]["route"], "/v1/charges/{}/extra");
    assert_eq!(info.irreversible_effects, 1);
    // The diff's state is the old code's: no migrated key.
    let a = d["state"]["continuous"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["actor"] == "counter/a")
        .unwrap_or_else(|| panic!("{}", d["state"]));
    assert!(a.to_string().contains("schema"), "{a}");
    let md = String::from_utf8(p.rt.block_on(s.props.diff(&r.id, true, false)).unwrap()).unwrap();
    assert!(md.contains("Irreversible effects"), "{md}");

    // A rebase must be newest, and the switch needs an approval.
    let err =
        p.rt.block_on(s.props.promote(&r.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ApprovalRequired, "{err}");
    let new_code_turn = p.node.applied_lsn();
    let done = switch(&s, &r.id);
    let rb = done.rebase.unwrap();
    assert!(rb.lsn > new_code_turn);
    assert_eq!(p.node.last_rebase().unwrap(), Some((rb.lsn, info.base_lsn)));

    // The old code's state: no migrated key, schema version 0, n as the old
    // code counts; the old code runs.
    assert_eq!(kv(p, "a", "schema"), None);
    assert_eq!(kv(p, "a", "n").as_deref(), Some("4"));
    let actor = p.node.store().db().actor("counter", "a").unwrap().unwrap();
    assert_eq!(actor.schema_version, 0);
    let kinds = p.node.store().db().kinds().unwrap();
    assert!(
        kinds.iter().any(|k| k.version.code_hash == hash("counter")),
        "{kinds:?}"
    );
    assert_eq!(http_body(&p.http("a", "increment", "")), "5");
    p.settle();
    assert_eq!(
        kv(p, "a", "schema"),
        None,
        "no migration under the old code"
    );
    // Main's history is kept: the new code's turns are still in the log.
    let rec = p.rt.block_on(p.node.read_record(new_code_turn)).unwrap();
    assert!(rec.is_some());
    // Nothing reached the world during the rebase (I7).
    assert_eq!(s.hits.load(Ordering::SeqCst), s.hits_after_promote);
    // A second rollback via replay of the same deployment is refused.
    let err =
        p.rt.block_on(s.props.rebase(RebaseRequest {
            epoch: s.epoch,
            options: DiffOptions::default(),
            workers: Some(2),
            audit: audit(),
            dry_run: true,
        }))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
}

/// M13 (2): the state after a switch survives a restart, and a rebuild
/// from a snapshot before the switch (crossing it, from the log alone)
/// gives the same state.
#[test]
fn the_rebased_state_is_rebuilt_from_the_log() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(2));
    let r = rebase(&s);
    let base = r.rebase.as_ref().unwrap().base_lsn;
    let rb = switch(&s, &r.id).rebase.unwrap();
    s.p.settle();
    let before = s.p.node.store().state_hash().unwrap();
    drop(s);

    // Restart.
    let p = Proc::start(dir.path());
    assert_eq!(p.node.store().state_hash().unwrap(), before);
    assert_eq!(kv(&p, "a", "n").as_deref(), Some("4"));
    p.settle();
    drop(p);

    // Rebuild: no state.db, only the snapshot from before the deployment.
    let branch = dir.path().join("branches/main");
    std::fs::remove_dir_all(branch.join("sql")).ok();
    for e in std::fs::read_dir(&branch).unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with("state.db") {
            std::fs::remove_file(e.path()).unwrap();
        }
    }
    let snaps = dir.path().join("snapshots/main");
    let mut kept = 0;
    for e in std::fs::read_dir(&snaps).unwrap().flatten() {
        let lsn: Lsn = e.file_name().to_string_lossy().parse().unwrap();
        if lsn > base {
            std::fs::remove_dir_all(e.path()).unwrap();
        } else {
            kept += 1;
        }
    }
    assert!(kept >= 1, "a snapshot before the deployment");
    let p = Proc::start(dir.path());
    assert!(p.node.applied_lsn() > rb.lsn);
    assert_eq!(p.node.store().state_hash().unwrap(), before);
    assert_eq!(kv(&p, "a", "schema"), None);
}

/// Every root turn of main's effective history with an idempotency key:
/// main's turns after the switch and the rebase's turns.
fn effective_keys(p: &Proc, switch: Lsn, rebase_id: &str) -> BTreeMap<String, usize> {
    let head = p.settle();
    let mut keys = BTreeMap::new();
    p.rt.block_on(p.node.reader().read(1, head, |c| {
        let turn = match &c.record {
            Record::TurnRecord(t) if c.lsn > switch => Some(t),
            Record::StateRebase(r) if r.rebase_id == rebase_id => c.record.turn(),
            _ => None,
        };
        if let Some(t) = turn
            && t.causal_key.as_ref().is_some_and(|k| k.path.is_empty())
            && let Some(pb::input::Kind::Http(h)) = t.input.as_ref().and_then(|i| i.kind.as_ref())
            && !h.idempotency_key.is_empty()
        {
            *keys.entry(h.idempotency_key.clone()).or_insert(0) += 1;
        }
        Ok(())
    }))
    .unwrap();
    keys
}

/// M13 (3): requests sent while the rebase switches are neither lost nor
/// duplicated: each is in main's effective history exactly once, and the
/// counter counts every one.
#[test]
fn no_root_input_is_lost_or_duplicated_during_the_switch() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(5));
    let r = rebase(&s);
    s.p.rt
        .block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    let go = AtomicBool::new(true);
    let (sent, done) = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|t| {
                let (p, go) = (&s.p, &go);
                scope.spawn(move || {
                    let mut sent = Vec::new();
                    let mut i = 0;
                    while go.load(Ordering::SeqCst) || i < 5 {
                        let idem = format!("k-{t}-{i}");
                        let res = keyed(p, "a", &idem);
                        assert!(res.committed(), "{idem}: {:?}", res.outcome);
                        sent.push(idem);
                        i += 1;
                    }
                    sent
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        let done =
            s.p.rt
                .block_on(s.props.promote(&r.id, audit(), false))
                .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        go.store(false, Ordering::SeqCst);
        let sent: Vec<String> = workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect();
        (sent, done)
    });
    let rb = done.rebase.unwrap();
    let keys = effective_keys(&s.p, rb.lsn, &r.id);
    for k in &sent {
        assert_eq!(keys.get(k), Some(&1), "{k}: {keys:?}");
    }
    assert_eq!(keys.len(), sent.len());
    // Before the requests: 3 old-code and 1 new-code increments.
    assert_eq!(kv(&s.p, "a", "n"), Some((4 + sent.len()).to_string()));
    // Some were replayed by the rebase, some ran after the switch.
    let replayed = effective_keys(&s.p, Lsn::MAX, &r.id).len();
    assert!(
        replayed > 0 && replayed < sent.len(),
        "{replayed} of {}",
        sent.len()
    );
}

/// A server that accepts connections and answers none until released.
fn hanging() -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let release = Arc::new(AtomicBool::new(false));
    let r = release.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let r = r.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                while !r.load(Ordering::SeqCst) {
                    let _ = stream.read(&mut buf);
                }
            });
        }
    });
    (addr, release)
}

/// A turn that keeps running (an effect that does not answer) makes the
/// switch give up after `rebase.max_pause`: nothing is switched, held
/// requests are answered, and a retry succeeds.
#[test]
fn a_switch_that_cannot_pause_in_time_writes_nothing() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_millis(300));
    let r = rebase(&s);
    s.p.rt
        .block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    let (slow, release) = hanging();
    std::thread::scope(|scope| {
        let p = &s.p;
        let stuck = scope
            .spawn(move || p.http("slow", "fetch-ok", &format!("GET http://{slow}/never\n\n")));
        std::thread::sleep(Duration::from_millis(300));
        let err =
            s.p.rt
                .block_on(s.props.promote(&r.id, audit(), false))
                .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
        assert!(err.message.contains("max_pause"), "{err}");
        assert_eq!(s.p.node.last_rebase().unwrap(), None);
        // Main runs as before.
        assert_eq!(http_body(&s.p.http("b", "increment", "")), "1");
        release.store(true, Ordering::SeqCst);
        stuck.join().unwrap();
    });
    // Released: the retry switches. The slow turn may have added an
    // effect the approval did not cover; then the new diff is approved.
    s.p.settle();
    let done = match s.p.rt.block_on(s.props.promote(&r.id, audit(), false)) {
        Ok(d) => d,
        Err(e) if e.code == ErrorCode::ApprovalRequired => {
            s.p.rt
                .block_on(s.props.approve(&r.id, audit(), false))
                .unwrap();
            s.p.rt
                .block_on(s.props.promote(&r.id, audit(), false))
                .unwrap()
        }
        Err(e) => panic!("{e}"),
    };
    assert!(done.rebase.is_some());
    assert_eq!(kv(&s.p, "a", "schema"), None);
}

/// Polls `done` until it holds; the limit only turns a hang into a failure.
fn wait_until(what: &str, done: impl Fn() -> bool) {
    for _ in 0..6000 {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("never: {what}");
}

/// Every turn record in main's log after `after`.
fn turns_after(p: &Proc, after: Lsn) -> Vec<(Lsn, pb::TurnRecord)> {
    let head = p.settle();
    (after + 1..=head)
        .filter_map(
            |lsn| match p.rt.block_on(p.node.read_record(lsn)).unwrap()?.record {
                Record::TurnRecord(t) => Some((lsn, t)),
                _ => None,
            },
        )
        .collect()
}

/// Releases every parked switch when dropped, so a failed assertion does
/// not leave a scoped thread parked forever.
struct Release(Arc<SwitchHold>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.release.add_permits(64);
    }
}

/// A setup whose code switches park after their record is applied and
/// before their code is installed (`test_hold_switch`); the promote of the
/// schema-1 build goes through at once.
fn held(dir: &std::path::Path) -> (Setup, Arc<SwitchHold>) {
    let hold = Arc::new(SwitchHold::default());
    hold.release.add_permits(1);
    let s = setup_with(
        dir,
        Duration::from_secs(5),
        NodeConfig {
            concurrency: 8,
            test_hold_switch: Some(hold.clone()),
            ..NodeConfig::default()
        },
    );
    assert_eq!(hold.parked.load(Ordering::SeqCst), 1);
    (s, hold)
}

/// The rebase switch goes through the turn gate like a set switch (ADR
/// 0013, 0018): parked with its `StateRebase` switch applied and before its
/// code is installed, a turn sent then waits, and runs the old code at the
/// switch's epoch.
#[test]
fn no_turn_starts_with_old_code_after_a_rebase_switch() {
    let dir = tempdir();
    let (s, hold) = held(dir.path());
    let _release = Release(hold.clone());
    let p = &s.p;
    let r = rebase(&s);
    p.rt.block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    std::thread::scope(|scope| {
        let promote = scope.spawn(|| p.rt.block_on(s.props.promote(&r.id, audit(), false)));
        wait_until("the rebase switch parks", || {
            hold.parked.load(Ordering::SeqCst) == 2
        });
        // The switch is applied: main knows the rebase.
        let (switch_lsn, _) = p.node.last_rebase().unwrap().unwrap();
        let turn = scope.spawn(|| p.http("a", "increment", ""));
        hold.release.add_permits(1);
        let done = promote.join().unwrap().unwrap();
        assert_eq!(done.rebase.as_ref().unwrap().lsn, switch_lsn);
        // The old code counts from the old state: 3 + 1 + 1 under it.
        assert_eq!(http_body(&turn.join().unwrap()), "5");
        for (at, t) in turns_after(p, switch_lsn) {
            assert_eq!(t.code_hash, hash("counter"), "turn {at}");
            assert!(
                t.config_epoch >= done.epoch,
                "turn {at}: {}",
                t.config_epoch
            );
        }
    });
}

/// Lock order deploy lock, drain, switch gate: a deploy while a rebase
/// switch holds main lands after it, at the next epoch, and the rebase is
/// not stale.
#[test]
fn a_set_switch_waits_for_a_rebase_switch() {
    let dir = tempdir();
    let (s, hold) = held(dir.path());
    let _release = Release(hold.clone());
    let p = &s.p;
    let r = rebase(&s);
    p.rt.block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    std::thread::scope(|scope| {
        let promote = scope.spawn(|| p.rt.block_on(s.props.promote(&r.id, audit(), false)));
        wait_until("the rebase switch parks", || {
            hold.parked.load(Ordering::SeqCst) == 2
        });
        let notes = std::fs::read(guest("notes")).unwrap();
        let deploy = scope.spawn(move || p.rt.block_on(p.node.deploy(&notes, audit(), false)));
        hold.release.add_permits(1);
        let done = promote.join().unwrap().unwrap();
        let deployed = deploy.join().unwrap().unwrap();
        assert!(deployed.lsn > done.rebase.as_ref().unwrap().lsn);
        assert_eq!(deployed.epoch, done.epoch + 1);
    });
    assert_eq!(
        s.p.rt.block_on(s.props.get(&r.id)).unwrap().status,
        "promoted"
    );
}

/// A turn that began under the rebased code and is re-run after a crash
/// keeps that code and the rebased schema version: no migration, the old
/// code's state. The switch's deployment is in the table re-runs read.
#[test]
fn a_rerun_after_a_rebase_keeps_the_rebased_code_and_schema() {
    let dir = tempdir();
    let s = setup_with(
        dir.path(),
        Duration::from_secs(2),
        NodeConfig {
            concurrency: 8,
            test_hold_after_call: true,
            ..NodeConfig::default()
        },
    );
    let r = rebase(&s);
    let done = switch(&s, &r.id);
    let p = &s.p;
    let (_, d) = p.node.store().db().deployments().unwrap().pop().unwrap();
    assert_eq!(
        (d.epoch, d.cause, d.rollback_of_epoch),
        (done.epoch, pb::DeploymentCause::Rollback as i32, s.epoch)
    );
    assert_eq!(d.kinds[0].code_hash, hash("counter"));
    // counter/c begins under the rebased code and holds after its call.
    p.http_detached("c", "call", "counter/b increment");
    p.wait_kv("counter/b", "n");
    let Setup { p, props, .. } = s;
    drop(props);
    drop(p);

    let p = Proc::open(dir.path(), NodeConfig::default());
    wait_until("the re-run of counter/c", || {
        p.node.store().db().actor("counter", "c").unwrap().is_some()
    });
    let c = p.node.store().db().actor("counter", "c").unwrap().unwrap();
    assert_eq!(c.schema_version, 0);
    assert_eq!(kv(&p, "c", "schema"), None, "the re-run migrated");
    let rerun = turns_after(&p, 0)
        .into_iter()
        .rev()
        .find(|(_, t)| t.actor.as_ref().is_some_and(|a| a.key == "c"))
        .unwrap()
        .1;
    assert_eq!(rerun.code_hash, hash("counter"));
    assert!(rerun.config_epoch >= done.epoch);
    // The old code keeps running: an increment, no migration.
    p.http("c", "increment", "");
    assert_eq!(kv(&p, "c", "schema"), None);
}

/// Every turn record rebase `id` wrote into main's log.
fn rebased_turns(p: &Proc, id: &str) -> Vec<pb::TurnRecord> {
    let head = p.node.applied_lsn();
    let mut out = Vec::new();
    p.rt.block_on(p.node.reader().read(1, head, |c| {
        if let Record::StateRebase(r) = &c.record
            && r.rebase_id == id
            && let Some(t) = c.record.turn()
        {
            out.push(t.clone());
        }
        Ok(())
    }))
    .unwrap();
    out
}

/// A proposal of the build `name` (not promoted).
fn propose(p: &Proc, props: &Arc<Proposals>, name: &str) -> kronik_fork::proposal::Proposal {
    p.settle();
    p.rt.block_on(props.propose(ProposeRequest {
        wasm: vec![std::fs::read(guest(name)).unwrap()],
        names: Vec::new(),
        window_ms: None,
        at: None,
        options: DiffOptions::default(),
        workers: Some(2),
        audit: audit(),
        dry_run: false,
    }))
    .unwrap()
    .0
}

/// Main runs counter (after `before`), then promotes the build `name`;
/// returns its epoch.
fn deployed(
    dir: &std::path::Path,
    before: impl FnOnce(&Proc),
    name: &str,
) -> (Proc, Arc<Proposals>, u64) {
    let p = Proc::start(dir);
    before(&p);
    p.rt.block_on(p.node.set_policy(QUIET, audit(), false))
        .unwrap();
    p.http("a", "increment", "");
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.to_path_buf())
            .unwrap()
            .with_rebase(Duration::from_secs(2)),
    );
    let prop = propose(&p, &props, name);
    let epoch =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap()
            .epoch;
    (p, props, epoch)
}

fn rebase_of(
    p: &Proc,
    props: &Proposals,
    epoch: u64,
    dry_run: bool,
) -> (kronik_fork::proposal::Proposal, bool) {
    p.settle();
    p.rt.block_on(props.rebase(RebaseRequest {
        epoch,
        options: DiffOptions {
            mode: Mode::Continuous,
            ..DiffOptions::default()
        },
        workers: Some(2),
        audit: audit(),
        dry_run,
    }))
    .unwrap()
}

fn is_timer(t: &pb::TurnRecord, key: &str) -> bool {
    t.actor.as_ref().is_some_and(|a| a.key == key)
        && matches!(
            t.input.as_ref().and_then(|i| i.kind.as_ref()),
            Some(pb::input::Kind::Timer(_))
        )
}

/// H2: a deployment after the rebase was created makes its promote stale;
/// the switch would silently revert that code.
#[test]
fn a_deployment_after_the_rebase_makes_its_promote_stale() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(2));
    let r = rebase(&s);
    let newer = propose(&s.p, &s.props, "counter-fetch-extra");
    s.p.rt
        .block_on(s.props.promote(&newer.id, audit(), false))
        .unwrap();
    s.p.rt
        .block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    let err =
        s.p.rt
            .block_on(s.props.promote(&r.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
    assert!(err.message.contains("came after"), "{err}");
    assert_eq!(s.p.node.last_rebase().unwrap(), None);
    assert!(rebased_turns(&s.p, &r.id).is_empty(), "nothing staged");
    let kinds = s.p.node.store().db().kinds().unwrap();
    assert!(
        kinds
            .iter()
            .any(|k| k.version.code_hash == hash("counter-fetch-extra")),
        "{kinds:?}"
    );
}

/// H2 and m13-rebase §6: a proposal made before a rebase switch cannot be
/// promoted after it (its fork point is before the fork floor).
#[test]
fn a_proposal_from_before_a_rebase_switch_is_stale() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(2));
    let older = propose(&s.p, &s.props, "counter-fetch-extra");
    let r = rebase(&s);
    switch(&s, &r.id);
    let err =
        s.p.rt
            .block_on(s.props.promote(&older.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
    assert!(err.message.contains("state rebase"), "{err}");
    assert_eq!(
        s.p.rt.block_on(s.props.get(&older.id)).unwrap().status,
        "stale"
    );
}

/// H3, H4: a timer production fires after the rebase was created is
/// replayed at its place by a later round, and main does not fire it
/// again after the switch. Review M13-1: that later round's timer turn
/// keeps the fork turn that scheduled it (`scheduled_by`), as a turn queued
/// in the scheduling round does, so a resumed promote matches it.
#[test]
fn a_timer_fired_during_catch_up_is_replayed_in_its_place() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(2));
    let p = &s.p;
    p.http("t", "schedule", "4000 increment");
    let r = rebase(&s);
    assert!(
        kv(p, "t", "n").is_none(),
        "the timer fired before the rebase was created"
    );
    p.wait_kv("counter/t", "n");
    p.http("a", "increment", "");
    let switch_lsn = switch(&s, &r.id).rebase.unwrap().lsn;
    let rebased = rebased_turns(p, &r.id);
    let timer = rebased
        .iter()
        .find(|t| is_timer(t, "t"))
        .expect("the rebase did not replay the timer");
    let Some(pb::input::Kind::Timer(input)) = timer.input.as_ref().and_then(|i| i.kind.as_ref())
    else {
        unreachable!()
    };
    assert!(
        input.scheduled_by.starts_with(&format!("{}:", r.id)),
        "scheduled_by {:?}",
        input.scheduled_by
    );
    std::thread::sleep(Duration::from_millis(500));
    for (at, t) in turns_after(p, switch_lsn) {
        assert!(!is_timer(&t, "t"), "main fired the timer again at {at}");
    }
    assert_eq!(kv(p, "t", "n").as_deref(), Some("1"));
}

/// H4: consequences of root inputs that main had not run when the switch
/// paused it are not run by the rebase (it has no recordings for them);
/// they stay pending and main runs them after the switch, once.
#[test]
fn consequences_in_flight_at_the_pause_run_on_main_after_the_switch() {
    let dir = tempdir();
    // The drain waits for the running root input; its forwarded message is
    // queued then and held: in flight at the pause.
    let s = setup(dir.path(), Duration::from_secs(5));
    let r = rebase(&s);
    s.p.rt
        .block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    let go = AtomicBool::new(true);
    let (sent, done) = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|t| {
                let (p, go) = (&s.p, &go);
                scope.spawn(move || {
                    let mut sent = 0;
                    while go.load(Ordering::SeqCst) || sent < 5 {
                        let res = keyed_op(p, "a", "forward", "f", &format!("f-{t}-{sent}"));
                        assert!(res.committed(), "{:?}", res.outcome);
                        sent += 1;
                    }
                    sent
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(300));
        let done =
            s.p.rt
                .block_on(s.props.promote(&r.id, audit(), false))
                .unwrap();
        go.store(false, Ordering::SeqCst);
        let sent: usize = workers.into_iter().map(|w| w.join().unwrap()).sum();
        (sent, done)
    });
    let p = &s.p;
    let switch_lsn = done.rebase.unwrap().lsn;
    p.settle();
    let main_keys: std::collections::BTreeSet<Vec<u8>> = turns_after(p, 0)
        .into_iter()
        .filter(|(at, _)| *at < switch_lsn)
        .filter_map(|(_, t)| t.causal_key.map(|k| kronik_core::causal::encode(&k)))
        .collect();
    let rebased = rebased_turns(p, &r.id);
    let mut roots = std::collections::BTreeSet::new();
    for t in &rebased {
        let k = t.causal_key.as_ref().unwrap();
        if k.path.is_empty() {
            roots.insert(k.root.clone());
        } else {
            assert!(
                main_keys.contains(&kronik_core::causal::encode(k)),
                "the rebase ran a consequence main had not run: {k:?}"
            );
        }
    }
    let after = turns_after(p, switch_lsn)
        .into_iter()
        .filter(|(_, t)| {
            t.causal_key
                .as_ref()
                .is_some_and(|k| !k.path.is_empty() && roots.contains(&k.root))
        })
        .count();
    assert!(after > 0, "no consequence was in flight at the pause");
    // Every forward reached counter/f once (3 + 1 increments of a before).
    assert_eq!(kv(p, "f", "n"), Some(sent.to_string()));
    assert_eq!(kv(p, "a", "n"), Some((4 + sent).to_string()));
}

/// H5: the whole pause is bounded by `rebase.max_pause`: with a last round
/// far longer than it, held requests wait at most about that long.
#[test]
fn the_pause_holds_requests_at_most_max_pause() {
    let dir = tempdir();
    let max_pause = Duration::from_millis(150);
    let Setup {
        p, props, epoch, ..
    } = setup(dir.path(), max_pause);
    // One catch-up round before the pause; the rest is the last round.
    // propose holds the proposals in an Arc: open them again with the option.
    drop(props);
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_rebase(max_pause)
            .with_promote(Duration::from_secs(3600), Duration::from_secs(60)),
    );
    let s = Setup {
        p,
        props,
        epoch,
        hits_after_promote: 0,
        hits: Arc::default(),
    };
    let r = rebase(&s);
    s.p.rt
        .block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    let go = AtomicBool::new(true);
    // Busy turns on 6 actors run in parallel on main (8 workers) but one
    // after another in the fork: the last round is far longer than the
    // pause.
    let (mut held, result) = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..6)
            .map(|t| {
                let (p, go) = (&s.p, &go);
                scope.spawn(move || {
                    let mut held = Vec::new();
                    let mut i = 0;
                    while go.load(Ordering::SeqCst) {
                        let at = std::time::Instant::now();
                        keyed_op(
                            p,
                            &format!("h{t}"),
                            "spin",
                            "3000000",
                            &format!("h-{t}-{i}"),
                        );
                        held.push(at.elapsed());
                        i += 1;
                    }
                    held
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(300));
        let result = s.p.rt.block_on(s.props.promote(&r.id, audit(), false));
        std::thread::sleep(Duration::from_millis(200));
        go.store(false, Ordering::SeqCst);
        let held: Vec<Duration> = workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect();
        (held, result)
    });
    if let Err(e) = &result {
        assert_eq!(e.code, ErrorCode::ProposalStale, "{e}");
    }
    // Measured on the dev host: about 190 ms with the bound, 770 ms with an
    // unbounded last round. A held request also waits for its own busy
    // turn, which takes longer when the machine (or the tests beside this
    // one) is busy: the slack scales with the median request of this run.
    held.sort();
    let (worst, typical) = (held[held.len() - 1], held[held.len() / 2]);
    let slack = Duration::from_millis(250).max(typical * 3);
    assert!(
        worst < max_pause + slack,
        "a request was held {worst:?}, the median one {typical:?} ({result:?})"
    );
}

/// H6 (I8): a revealed secret the old code writes to its state is
/// scrubbed in the rebase as in production: no value in main's log,
/// state or the fork's directory.
#[test]
fn a_rebase_scrubs_revealed_secrets_like_production() {
    const SECRET: &str = "rebase-reveal-value-5d1f0a";
    let dir = tempdir();
    let s = setup_full(
        dir.path(),
        Duration::from_secs(2),
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
        |p| {
            p.node
                .secret_set("db-password", SECRET.as_bytes(), &audit(), false)
                .unwrap();
            p.grant("secret-reveal:db-password");
        },
    );
    let r = s.p.send("counter/a", "reveal-persist", "db-password");
    assert!(r.committed(), "{r:?}");
    let rb = rebase(&s);
    switch(&s, &rb.id);
    s.p.settle();
    assert_eq!(
        kv(&s.p, "a", "revealed").as_deref(),
        Some("[secret:db-password]")
    );
    let Setup { p, props, .. } = s;
    drop(props);
    drop(p);
    let mut leaks = Vec::new();
    scan(dir.path(), SECRET.as_bytes(), &mut leaks);
    assert!(leaks.is_empty(), "the revealed value is in {leaks:?}");
}

fn scan(dir: &std::path::Path, needle: &[u8], hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            scan(&p, needle, hits);
        } else if let Ok(bytes) = std::fs::read(&p)
            && bytes.windows(needle.len()).any(|w| w == needle)
        {
            hits.push(p.display().to_string());
        }
    }
}

/// H8, L1 (I12): a rebase answers from recordings only, never from the
/// simulators or the model; its dry run writes nothing.
#[test]
fn a_rebase_uses_recordings_only_and_its_dry_run_writes_nothing() {
    let dir = tempdir();
    let (addr, _) = server();
    let charge = |p: &Proc, i: u32| {
        p.http(
            "pay",
            "fetch-ok",
            &format!("POST http://{addr}/v1/charges/{i}\n\namount=1"),
        )
    };
    // The old code also GETs `<url>/extra`; the new code does not, so the
    // window has no recording for it.
    let (p, props, epoch) = deployed(
        dir.path(),
        |p| {
            p.deploy("counter-fetch-extra");
            p.grant("http:127.0.0.1");
            charge(p, 0);
        },
        "counter-fail-get",
    );
    charge(&p, 1);
    let (model_addr, seen) = model_server();
    p.rt.block_on(p.node.set_simulators(
        pb::SimulatorConfig {
            target: "http:127.0.0.1".into(),
            model: true,
            ..Default::default()
        },
        audit(),
        false,
    ))
    .unwrap();
    // propose holds the proposals in an Arc: open them again with the model.
    drop(props);
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_rebase(Duration::from_secs(2))
            .with_model(Some(model(&model_addr))),
    );
    let branches = || {
        let mut b: Vec<_> = std::fs::read_dir(dir.path().join("branches"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        b.sort();
        b
    };
    let before = branches();
    // Overrides would be ignored: they are refused, like stubs (H8).
    let err =
        p.rt.block_on(props.rebase(RebaseRequest {
            epoch,
            options: DiffOptions {
                mode: Mode::Continuous,
                simulator_overrides: vec![kronik_fork::simulators::SimulatorOverride {
                    target: "http:127.0.0.1".into(),
                    stubs: vec![],
                    contract: None,
                    neighbor: true,
                    model: false,
                }],
                ..DiffOptions::default()
            },
            workers: Some(2),
            audit: audit(),
            dry_run: true,
        }))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
    assert!(err.message.contains("simulator overrides"), "{err}");
    let (_, dry) = rebase_of(&p, &props, epoch, true);
    assert!(dry);
    assert_eq!(branches(), before, "the dry run wrote a branch directory");
    assert!(
        seen.lock().unwrap().is_empty(),
        "the dry run asked the model"
    );
    let (r, _) = rebase_of(&p, &props, epoch, false);
    assert!(
        seen.lock().unwrap().is_empty(),
        "the rebase asked the model"
    );
    let d: Value =
        serde_json::from_slice(&p.rt.block_on(props.diff(&r.id, false, false)).unwrap()).unwrap();
    let by = d["summary"]["synthetic_by"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    assert!(
        by.keys().all(|k| k == "fail-closed") && !by.is_empty(),
        "{}",
        d["summary"]
    );
    assert!(d["options"].get("simulators").is_none(), "{}", d["options"]);
    assert!(
        !dir.path()
            .join("branches")
            .join(&r.id)
            .join("simulator-cache.json")
            .exists()
    );
}

/// M7: a message pending at the fork point runs in the fork at the place
/// production delivered it.
#[test]
fn a_message_pending_at_the_fork_point_is_replayed() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.rt.block_on(p.node.set_policy(QUIET, audit(), false))
        .unwrap();
    p.http("a", "forward", "f");
    p.wait_kv("counter/f", "n");
    p.http("a", "increment", "");
    p.settle();
    // The fork point: right after the forwarding turn, before the delivery.
    let at = turns_after(&p, 0)
        .into_iter()
        .find(|(_, t)| t.actor.as_ref().is_some_and(|a| a.key == "a"))
        .unwrap()
        .0;
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let (prop, _) =
        p.rt.block_on(props.propose(ProposeRequest {
            wasm: vec![std::fs::read(guest("counter-fail-get")).unwrap()],
            names: Vec::new(),
            window_ms: None,
            at: Some(at),
            options: DiffOptions {
                mode: Mode::Continuous,
                ..DiffOptions::default()
            },
            workers: Some(2),
            audit: audit(),
            dry_run: false,
        }))
        .unwrap();
    let d: Value =
        serde_json::from_slice(&p.rt.block_on(props.diff(&prop.id, false, false)).unwrap())
            .unwrap();
    let f = d["state"]["continuous"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["actor"] == "counter/f");
    assert!(f.is_none(), "the fork never delivered the message: {f:?}");
}

/// M8: a dead-letter resend in the window whose original the old code ran
/// successfully is not applied a second time.
#[test]
fn a_resend_of_a_message_the_old_code_ran_is_skipped() {
    let dir = tempdir();
    let (p, props, epoch) = deployed(dir.path(), |_| {}, "counter-fail-get");
    let r = p.send("counter/a", "get", "");
    assert!(!r.committed());
    let dl = p.node.store().db().dead_letters(0, 10).unwrap();
    let lsn = dl.last().unwrap().lsn;
    p.rt.block_on(p.node.resend(lsn, audit(), false)).unwrap();
    let (rb, _) = rebase_of(&p, &props, epoch, false);
    p.rt.block_on(props.approve(&rb.id, audit(), false))
        .unwrap();
    p.rt.block_on(props.promote(&rb.id, audit(), false))
        .unwrap();
    let resends = rebased_turns(&p, &rb.id)
        .into_iter()
        .filter(|t| {
            matches!(
                t.input.as_ref().and_then(|i| i.kind.as_ref()),
                Some(pb::input::Kind::Message(m))
                    if m.source == pb::MessageSource::DeadLetterResend as i32
            )
        })
        .count();
    let gets = rebased_turns(&p, &rb.id)
        .into_iter()
        .filter(|t| t.actor.as_ref().is_some_and(|a| a.key == "a"))
        .count();
    assert_eq!(resends, 0, "the resend ran again");
    assert!(gets > 0);
}

/// H3: a resume (here after a restart) that cannot prove the turns it
/// would stage equal the ones already in main's log is refused; nothing
/// more is staged.
#[test]
fn a_resume_that_cannot_prove_its_staged_turns_is_refused() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_millis(300));
    let r = rebase(&s);
    s.p.rt
        .block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    let (slow, release) = hanging();
    std::thread::scope(|scope| {
        let p = &s.p;
        let stuck = scope
            .spawn(move || p.http("slow", "fetch-ok", &format!("GET http://{slow}/never\n\n")));
        std::thread::sleep(Duration::from_millis(300));
        let err =
            s.p.rt
                .block_on(s.props.promote(&r.id, audit(), false))
                .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
        release.store(true, Ordering::SeqCst);
        stuck.join().unwrap();
    });
    // Staged before the pause gave up.
    let staged = rebased_turns(&s.p, &r.id).len();
    assert!(staged > 0);
    let Setup { p, props, .. } = s;
    drop(props);
    drop(p);
    // The record of what was staged is gone.
    std::fs::remove_dir_all(dir.path().join("branches").join(&r.id).join("log")).unwrap();
    let p = Proc::open(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
    );
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf())
        .unwrap()
        .with_rebase(Duration::from_secs(2));
    p.settle();
    let err =
        p.rt.block_on(props.promote(&r.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
    assert!(err.message.contains("differs"), "{err}");
    assert_eq!(rebased_turns(&p, &r.id).len(), staged);
    assert_eq!(p.node.last_rebase().unwrap(), None);
}

/// M10: a rebase of SQL actors: an actor both codes use gets the shadow's
/// database (`copy_from`, stamped at the switch), one only the new code
/// created is cleared, and a restart keeps the state.
#[test]
fn a_rebase_replaces_and_clears_sql_actor_databases() {
    let dir = tempdir();
    let (p, props, epoch) = deployed(
        dir.path(),
        |p| {
            p.deploy("notes-tally");
            p.send("notes/n", "add", "one");
        },
        "counter-calls-tally",
    );
    // The new code calls notes/tally on every increment.
    p.http("a", "increment", "");
    p.send("notes/n", "add", "two");
    assert!(
        p.node
            .store()
            .db()
            .actor("notes", "tally")
            .unwrap()
            .is_some()
    );
    let (r, _) = rebase_of(&p, &props, epoch, false);
    p.rt.block_on(props.approve(&r.id, audit(), false)).unwrap();
    p.rt.block_on(props.promote(&r.id, audit(), false)).unwrap();
    p.settle();
    let list = |p: &Proc| {
        let r = p.send("notes/n", "list", "");
        match r.outcome.output {
            Some(pb::outcome::Output::Reply(m)) => match m.body.and_then(|b| b.value) {
                Some(pb::sealable::Value::Plain(b)) => String::from_utf8(b).unwrap(),
                _ => String::new(),
            },
            _ => String::new(),
        }
    };
    assert_eq!(list(&p), "one [-]\ntwo [-]\n");
    assert!(
        p.node
            .store()
            .db()
            .actor("notes", "tally")
            .unwrap()
            .is_none(),
        "the old code never called notes/tally"
    );
    assert_eq!(kv(&p, "a", "n").as_deref(), Some("2"));
    let before = p.node.store().state_hash().unwrap();
    drop(props);
    drop(p);
    let p = Proc::open(dir.path(), NodeConfig::default());
    assert_eq!(p.node.store().state_hash().unwrap(), before);
    assert_eq!(list(&p), "one [-]\ntwo [-]\n");
}

/// Promote review A1 on M13: a proposal made after a rebase switch pins
/// changed kinds to their code at its creation head (`created_lsn`), which
/// comes from the switch record's deployment. With the base snapshot from before the
/// switch (here the snapshot after it is gone), reading only `Deployment`
/// records would see the rolled-back code and refuse the promote as stale.
#[test]
fn a_proposal_after_a_rebase_switch_pins_the_rebased_code() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(2));
    let r = rebase(&s);
    let switched = switch(&s, &r.id);
    // Only the snapshot from before the rolled-back deployment stays.
    let snapshots = dir.path().join("snapshots").join("main");
    let mut dirs: Vec<_> = std::fs::read_dir(&snapshots)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    dirs.sort();
    for d in dirs.iter().skip(1) {
        std::fs::remove_dir_all(d).unwrap();
    }
    s.p.http("a", "increment", "");
    let newer = propose(&s.p, &s.props, "counter-fetch-extra");
    assert!(
        newer.fork_lsn >= switched.lsn,
        "{} {}",
        newer.fork_lsn,
        switched.lsn
    );
    s.p.rt
        .block_on(s.props.promote(&newer.id, audit(), false))
        .unwrap();
    let kinds = s.p.node.store().db().kinds().unwrap();
    assert!(
        kinds
            .iter()
            .any(|k| k.version.code_hash == hash("counter-fetch-extra")),
        "{kinds:?}"
    );
}

/// Review N13-3: a rebase promote cut short after its switch committed is
/// recorded on the proposal (promoted, with its switch LSN), and a second
/// promote says so instead of saving the proposal as stale.
#[test]
fn a_rebase_promote_cut_short_after_its_switch_is_recorded() {
    let dir = tempdir();
    let (s, hold) = held(dir.path());
    let _release = Release(hold.clone());
    let p = &s.p;
    let r = rebase(&s);
    p.rt.block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    // The caller goes away once the switch is applied and parks.
    p.rt.block_on(async {
        let parked = async {
            while hold.parked.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::select! {
            biased;
            _ = parked => {}
            r = s.props.promote(&r.id, audit(), false) => panic!("finished: {r:?}"),
        }
    });
    let (switch_lsn, _) = p.node.last_rebase().unwrap().unwrap();
    hold.release.add_permits(1);
    p.settle();
    let got = p.rt.block_on(s.props.get(&r.id)).unwrap();
    assert_eq!(got.status, "promoted", "{got:?}");
    assert_eq!(got.promoted.as_ref().unwrap().lsn, switch_lsn);
    assert_eq!(got.rebase.as_ref().unwrap().switch_lsn, Some(switch_lsn));
    let err =
        p.rt.block_on(s.props.promote(&r.id, audit(), false))
            .unwrap_err();
    assert!(err.message.contains("already promoted"), "{err}");
    assert_eq!(
        p.rt.block_on(s.props.get(&r.id)).unwrap().status,
        "promoted"
    );
}

/// Review N13-1, H3: with privacy mode on, a rebase whose promote gave up
/// after staging (the pause bound) resumes after a restart: the fork log's
/// sealed turns are compared with the fresh replay as plaintext.
#[test]
fn a_rebase_resumes_after_a_restart_with_privacy_on() {
    let dir = tempdir();
    let s = setup_full(
        dir.path(),
        Duration::from_millis(300),
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
        |p| {
            p.rt.block_on(
                p.node
                    .set_privacy_mode(pb::PrivacyState::On, audit(), false),
            )
            .unwrap();
        },
    );
    // Values the fork's own turns tag (state.set-for user:1): plaintext in
    // the replay, sealed in the fork log.
    for key in ["alice", "bob"] {
        s.p.http(key, "subject", "");
    }
    let r = rebase(&s);
    s.p.rt
        .block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    let (slow, release) = hanging();
    std::thread::scope(|scope| {
        let p = &s.p;
        let stuck = scope
            .spawn(move || p.http("slow", "fetch-ok", &format!("GET http://{slow}/never\n\n")));
        std::thread::sleep(Duration::from_millis(300));
        let err =
            s.p.rt
                .block_on(s.props.promote(&r.id, audit(), false))
                .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
        release.store(true, Ordering::SeqCst);
        stuck.join().unwrap();
    });
    assert!(
        !rebased_turns(&s.p, &r.id).is_empty(),
        "staged before the bound"
    );
    let Setup { p, props, .. } = s;
    drop(props);
    drop(p);
    let p = Proc::open(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
    );
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf())
        .unwrap()
        .with_rebase(Duration::from_secs(5));
    p.settle();
    // The diff after the restart's replay gets its own approval.
    let err =
        p.rt.block_on(props.promote(&r.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ApprovalRequired, "{err}");
    p.rt.block_on(props.approve(&r.id, audit(), false)).unwrap();
    let done = p.rt.block_on(props.promote(&r.id, audit(), false)).unwrap();
    assert!(done.rebase.is_some());
    assert_eq!(
        p.node.last_rebase().unwrap().map(|(l, _)| l),
        Some(done.lsn)
    );
}

/// Review N13-4 (I12): a promote --dry-run of a rebase, after a restart
/// and with traffic since the rebase was made, writes nothing (no fork
/// log, no saved state) and leaves the proposal as it was, so a later
/// approval binds to the diff the approver saw.
#[test]
fn a_rebase_promote_dry_run_writes_and_changes_nothing() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(2));
    let r = rebase(&s);
    for _ in 0..2 {
        s.p.http("a", "increment", "");
    }
    let Setup { p, props, .. } = s;
    drop(props);
    drop(p);
    let p = Proc::open(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
    );
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf())
        .unwrap()
        .with_rebase(Duration::from_secs(2));
    p.settle();
    let branch = dir.path().join("branches").join(&r.id);
    let files = |d: &std::path::Path| {
        let mut out = Vec::new();
        let mut stack = vec![d.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                if e.path().is_dir() {
                    stack.push(e.path());
                } else {
                    out.push((e.path(), std::fs::read(e.path()).unwrap()));
                }
            }
        }
        out.sort();
        out
    };
    let before = files(&branch);
    let meta = p.rt.block_on(props.get(&r.id)).unwrap();
    // Unapproved: the dry run answers APPROVAL_REQUIRED, without writing.
    let err =
        p.rt.block_on(props.promote(&r.id, audit(), true))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ApprovalRequired, "{err}");
    assert!(
        files(&branch) == before,
        "the dry run wrote into {}",
        branch.display()
    );
    let after = p.rt.block_on(props.get(&r.id)).unwrap();
    assert_eq!(
        (&after.diff_hash, &after.status, &after.policy),
        (&meta.diff_hash, &meta.status, &meta.policy)
    );
}

/// Review N13-2: below `[log] disk_reserve` a rollback via replay is not
/// created (it replays a window and writes its own log), and an approved
/// one is not promoted (staging appends a window of turns to main's log);
/// nothing is staged.
#[test]
fn a_rebase_is_refused_below_the_disk_reserve() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(2));
    let r = rebase(&s);
    s.p.rt
        .block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    let epoch = s.epoch;
    let Setup { p, props, .. } = s;
    drop(props);
    drop(p);
    // A reserve no disk has room for.
    let p = Proc::open(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            disk_reserve: u64::MAX / 2,
            ..NodeConfig::default()
        },
    );
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf())
        .unwrap()
        .with_rebase(Duration::from_secs(2));
    assert!(p.node.disk_below_reserve().is_some());
    let err =
        p.rt.block_on(props.rebase(RebaseRequest {
            epoch,
            options: DiffOptions {
                mode: Mode::Continuous,
                ..DiffOptions::default()
            },
            workers: Some(2),
            audit: audit(),
            dry_run: false,
        }))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unavailable, "{err}");
    let err =
        p.rt.block_on(props.promote(&r.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unavailable, "{err}");
    assert!(err.message.contains("disk_reserve"), "{err}");
    assert!(rebased_turns(&p, &r.id).is_empty(), "nothing staged");
    assert_eq!(p.node.last_rebase().unwrap(), None);
}

/// Review M13-2: a fork at a rebase switch R (or after it) does not start
/// from a snapshot taken between the rebase's base and R, which cannot
/// rebuild the switch; it uses one at or before the base. Here the snapshot
/// after the switch is missing (refused below the reserve, or a promote cut
/// short), so the fork point R has no snapshot at or after the switch.
#[test]
fn a_fork_at_the_switch_skips_snapshots_inside_the_rebased_window() {
    let dir = tempdir();
    let s = setup(dir.path(), Duration::from_secs(2));
    let r = rebase(&s);
    s.p.http("a", "increment", "");
    s.p.settle();
    s.p.rt
        .block_on(s.p.node.snapshot("inside the window"))
        .unwrap();
    let switch_lsn = switch(&s, &r.id).rebase.unwrap().lsn;
    s.p.settle();
    for (snap, m) in kronik_sched::snapshots::list(dir.path(), "main") {
        if m.lsn >= switch_lsn {
            std::fs::remove_dir_all(snap).unwrap();
        }
    }
    s.p.rt
        .block_on(
            s.props
                .create_fork(Some("after".into()), switch_lsn, false, audit(), false),
        )
        .unwrap();
    s.p.rt
        .block_on(s.props.fork_replay(
            "after",
            None,
            DiffOptions {
                mode: Mode::Continuous,
                ..DiffOptions::default()
            },
            Some(2),
        ))
        .unwrap();
}

/// The real file system, with the free space the test sets.
struct TestDisk {
    inner: Arc<dyn kronik_core::env::Fs>,
    free: Arc<std::sync::atomic::AtomicU64>,
}

impl kronik_core::env::Fs for TestDisk {
    fn create_dir_all(
        &self,
        p: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        self.inner.create_dir_all(p)
    }
    fn open(
        &self,
        p: std::path::PathBuf,
        mode: kronik_core::env::OpenMode,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<Arc<dyn kronik_core::env::File>>>
    {
        self.inner.open(p, mode)
    }
    fn exists(
        &self,
        p: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<bool>> {
        self.inner.exists(p)
    }
    fn read_dir(
        &self,
        p: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<Vec<String>>> {
        self.inner.read_dir(p)
    }
    fn rename(
        &self,
        from: std::path::PathBuf,
        to: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        self.inner.rename(from, to)
    }
    fn remove_file(
        &self,
        p: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        self.inner.remove_file(p)
    }
    fn sync_dir(
        &self,
        p: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        self.inner.sync_dir(p)
    }
    fn available(
        &self,
        _: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<u64>> {
        let free = self.free.load(Ordering::SeqCst);
        Box::pin(async move { Ok(free) })
    }
}

/// Sets the test disk's free space and waits until the node has read it.
fn set_free(p: &Proc, free: &std::sync::atomic::AtomicU64, bytes: u64) {
    free.store(bytes, Ordering::SeqCst);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while p.node.disk_free() != Some(bytes) {
        assert!(
            std::time::Instant::now() < deadline,
            "the node never read {bytes}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Review N13-2 (round 3): rebase staging keeps to `[log] disk_reserve`.
/// (1) The budget counts what staging writes (the StateRebase wrapper, the
/// frame, sealing), not the bare turns. (2) Every staged batch is checked,
/// not only the estimate before the first. (3) The snapshot after the
/// switch is taken below the reserve too: until it exists compaction holds
/// the log, so the node could not climb back.
#[test]
fn rebase_staging_keeps_to_the_disk_reserve() {
    const RESERVE: u64 = 1 << 20;
    let dir = tempdir();
    let free = Arc::new(std::sync::atomic::AtomicU64::new(1 << 40));
    let disk = free.clone();
    let s = setup_env(
        dir.path(),
        Duration::from_secs(2),
        NodeConfig {
            concurrency: 8,
            disk_reserve: RESERVE,
            ..NodeConfig::default()
        },
        move |env| {
            env.fs = Arc::new(TestDisk {
                inner: env.fs.clone(),
                free: disk,
            })
        },
        |_| {},
    );
    let r = rebase(&s);
    s.p.rt
        .block_on(s.props.approve(&r.id, audit(), false))
        .unwrap();
    // The fork's turns as staging takes them.
    let fork_turns: Vec<(Lsn, pb::TurnRecord)> = (r.fork_lsn + 1..=s.p.node.applied_lsn() + 64)
        .filter_map(|lsn| {
            s.p.rt
                .block_on(s.props.fork_turn(&r.id, lsn))
                .unwrap()
                .map(|t| (lsn, t))
        })
        .collect();
    assert!(!fork_turns.is_empty());
    let bare: u64 = fork_turns
        .iter()
        .map(|(_, t)| prost::Message::encoded_len(t) as u64)
        .sum();
    // (1) Room for the bare turns, not for what staging writes.
    set_free(&s.p, &free, RESERVE + bare + 1);
    let err =
        s.p.rt
            .block_on(s.props.promote(&r.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unavailable, "{err}");
    // Refused by the estimate before staging, not by the first batch.
    assert!(
        err.message.contains("a rollback via replay stages"),
        "{err}"
    );
    assert!(rebased_turns(&s.p, &r.id).is_empty(), "nothing staged");
    // (2) A batch on a disk below the reserve writes nothing.
    set_free(&s.p, &free, RESERVE - 1);
    s.p.rt
        .block_on(s.p.node.rebase_prepare(&r.id, r.fork_lsn))
        .unwrap();
    let err =
        s.p.rt
            .block_on(
                s.p.node
                    .rebase_stage(&r.id, fork_turns, s.p.node.applied_lsn(), None),
            )
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unavailable, "{err}");
    assert!(rebased_turns(&s.p, &r.id).is_empty(), "nothing staged");
    // (3) With room, the promote switches; the snapshot after the switch is
    // then taken below the reserve as well.
    set_free(&s.p, &free, 1 << 40);
    let switch_lsn =
        s.p.rt
            .block_on(s.props.promote(&r.id, audit(), false))
            .unwrap()
            .rebase
            .unwrap()
            .lsn;
    s.p.settle();
    for (snap, m) in kronik_sched::snapshots::list(dir.path(), "main") {
        if m.lsn >= switch_lsn {
            std::fs::remove_dir_all(snap).unwrap();
        }
    }
    set_free(&s.p, &free, RESERVE - 1);
    s.p.rt.block_on(s.p.node.snapshot_after_rebase());
    assert!(
        kronik_sched::snapshots::list(dir.path(), "main")
            .iter()
            .any(|(_, m)| m.lsn >= switch_lsn),
        "no snapshot at or after the switch"
    );
}
