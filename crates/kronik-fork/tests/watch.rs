//! `kronik watch` against a real node (docs/design/m11-watch.md): the
//! default guards after a promote roll back on errors, and alert instead
//! when the deployment raised a schema version; a watch never undoes a later
//! deployment, records a rollback it made before a crash, waits for turns,
//! and can be stopped.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use kronik_core::error::ErrorCode;
use kronik_fork::diff::DiffOptions;
use kronik_fork::proposal::{Proposals, ProposeRequest};
use kronik_fork::watch::{EVAL_ERROR, MAX_FOR_MS, Triggered, Watch, Watches};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

/// Promotes `wasm` after `before` increments; returns the new epoch.
fn promote(p: &Proc, props: &Arc<Proposals>, wasm: &str, before: usize) -> u64 {
    promote_all(p, props, &[wasm], before)
}

/// Promotes these modules together after `before` increments.
fn promote_all(p: &Proc, props: &Arc<Proposals>, wasm: &[&str], before: usize) -> u64 {
    for _ in 0..before {
        p.http("a", "increment", "");
    }
    let wasm = wasm
        .iter()
        .map(|w| std::fs::read(guest(w)).unwrap())
        .collect();
    p.settle();
    let (prop, _) =
        p.rt.block_on(props.propose(ProposeRequest {
            wasm,
            names: Vec::new(),
            window_ms: None,
            at: None,
            options: DiffOptions::default(),
            workers: Some(2),
            audit: audit(),
            dry_run: false,
        }))
        .unwrap();
    assert_eq!(prop.policy["outcome"], "allow", "{}", prop.policy);
    p.rt.block_on(props.promote(&prop.id, audit(), false))
        .unwrap()
        .epoch
}

fn watches(p: &Proc, props: &Arc<Proposals>, dir: &std::path::Path) -> Arc<Watches> {
    let _guard = p.rt.enter();
    Watches::open(p.node.clone(), props.clone(), dir.to_path_buf())
        .unwrap()
        .with_interval(Duration::from_millis(50))
        .start()
}

fn guards_in_log(p: &Proc) -> Vec<pb::GuardTriggered> {
    let mut out = Vec::new();
    p.rt.block_on(p.node.reader().read(1, p.node.applied_lsn(), |c| {
        if let Record::GuardTriggered(g) = c.record {
            out.push(g);
        }
        Ok(())
    }))
    .unwrap();
    out
}

fn wait_for(watches: &Watches, id: &str, f: impl Fn(&Watch) -> bool) -> Watch {
    for _ in 0..400 {
        let w = watches.get(id).unwrap();
        if f(&w) {
            return w;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("watch {id} never got there: {:?}", watches.get(id).unwrap());
}

/// Sets a policy with these guards and no rules, so every proposal is
/// allowed.
/// The `error-rate-up` entries of a watch's triggered guards.
fn error_rate_up(t: &[Triggered]) -> Vec<&Triggered> {
    t.iter().filter(|t| t.guard == "error-rate-up").collect()
}

fn set_guards(p: &Proc, toml: &str) {
    p.rt.block_on(p.node.set_policy(toml, audit(), false))
        .unwrap();
}

fn rollbacks(p: &Proc) -> Vec<pb::Deployment> {
    p.node
        .store()
        .db()
        .deployments()
        .unwrap()
        .into_iter()
        .map(|(_, d)| d)
        .filter(|d| d.cause == pb::DeploymentCause::Rollback as i32)
        .collect()
}

fn get_n(p: &Proc, n: usize) {
    for _ in 0..n {
        p.http("a", "get", "");
    }
}

#[test]
fn watch_rolls_back_when_the_error_rate_after_promote_breaks_a_guard() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    // Traffic after the promote: every `get` fails in the new build.
    get_n(&p, 25);
    p.settle();
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    let w = wait_for(&watches, &w.id, |w| w.status != "watching");
    assert_eq!(w.status, "rolled_back", "{w:?}");

    // The rollback went through the normal path.
    let (_, d) = p.node.store().db().deployments().unwrap().pop().unwrap();
    assert_eq!(d.cause, pb::DeploymentCause::Rollback as i32);
    assert_eq!(d.rollback_of_epoch, epoch);
    assert_eq!(d.audit.as_ref().unwrap().token_id, "kronik");
    assert!(d.audit.unwrap().reason.contains("error-rate-up"));
    assert_eq!(http_body(&p.http("a", "get", "")), "20");

    // GuardTriggered holds the metrics the decision was made on.
    let [g] = guards_in_log(&p).try_into().unwrap();
    assert_eq!(g.watch_id, w.id);
    assert_eq!(g.guard, "error-rate-up");
    assert_eq!(g.deployment_epoch, epoch);
    assert_eq!(g.rollback_epoch, d.epoch);
    assert_eq!(g.action, pb::GuardAction::Rollback as i32);
    assert_eq!(g.outcome, pb::GuardOutcome::RolledBack as i32);
    let after = g.after.unwrap();
    assert_eq!((after.turns, after.failed), (25, 25));
    assert_eq!(after.error_rate, 1.0);
    assert!(after.latency_p99_us > 0, "{after:?}");
    let before = g.before.unwrap();
    assert_eq!(before.failed, 0);
    assert_eq!(before.error_rate, 0.0);
    assert!(before.turns > 0 && before.turns <= 20, "{before:?}");
    assert!(g.observed_lsn >= after.to_lsn);
    assert_eq!(w.triggered.len(), 1);
    assert_eq!(w.metrics.as_ref().unwrap()["after"]["error_rate"], 1.0);

    // A resumed watch reads the record and does not act again.
    p.rt.block_on(async {
        p.node.env().clock.sleep(Duration::from_millis(200)).await;
    });
    assert_eq!(guards_in_log(&p).len(), 1);
    let again = Watches::open(p.node.clone(), props.clone(), dir.path().to_path_buf()).unwrap();
    assert_eq!(again.get(&w.id).unwrap().status, "rolled_back");
}

#[test]
fn watch_alerts_instead_of_rolling_back_a_schema_change() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let epoch = promote(&p, &props, "counter-schema1", 5);
    for _ in 0..25 {
        p.http("a", "fail", "");
    }
    p.settle();
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    let w = wait_for(&watches, &w.id, |w| !w.triggered.is_empty());
    assert_eq!(w.status, "watching", "{w:?}");
    assert_eq!(w.triggered[0].outcome, "rollback_refused_schema");
    assert_eq!(w.metrics.as_ref().unwrap()["schema_changed"], true);

    let [g] = guards_in_log(&p).try_into().unwrap();
    assert_eq!(g.guard, "error-rate-up");
    assert_eq!(g.outcome, pb::GuardOutcome::RollbackRefusedSchema as i32);
    assert_eq!(g.rollback_epoch, 0);
    assert!(g.reason.contains("schema version"), "{}", g.reason);
    let after = g.after.unwrap();
    assert_eq!((after.turns, after.failed), (26, 25));
    // No rollback: the promote is still the newest deployment.
    let (_, d) = p.node.store().db().deployments().unwrap().pop().unwrap();
    assert_eq!(
        (d.epoch, d.cause),
        (epoch, pb::DeploymentCause::Promote as i32)
    );
    // The guard fired once; the watch keeps watching.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(guards_in_log(&p).len(), 1);
}

/// Fires only once 60 turns ran after the watched deployment.
const LATE_ROLLBACK: &str = "[[guard]]\nname = \"late\"\n\
    when = \"guard.after.turns >= 60 && guard.after.failed >= 3\"\naction = \"rollback\"\n";

/// Review W-H1: a hotfix promoted while a failing build is watched ends
/// the watch's window; the guard never rolls the hotfix back to the code
/// from before the watched deployment.
#[test]
fn a_later_promote_ends_the_watch_and_is_never_rolled_back() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    set_guards(&p, LATE_ROLLBACK);
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    get_n(&p, 25);
    // 20 more turns under the failing build, then the hotfix, then 20
    // under the hotfix: 65 turns since the watched deployment.
    let hotfix = promote(&p, &props, "counter-body-v2", 20);
    get_n(&p, 20);
    p.settle();
    let w = wait_for(&watches, &w.id, |w| w.status != "watching");
    assert_eq!(w.status, "superseded", "{w:?}");
    // The window ended at the hotfix.
    assert_eq!(w.metrics.as_ref().unwrap()["after"]["turns"], 45, "{w:?}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(guards_in_log(&p).is_empty());
    assert!(rollbacks(&p).is_empty());
    let (_, d) = p.node.store().db().deployments().unwrap().pop().unwrap();
    assert_eq!(
        (d.epoch, d.cause),
        (hotfix, pb::DeploymentCause::Promote as i32)
    );
}

/// Review W-H1: the watch's rollback is pinned to the watched deployment's
/// code, so it refuses once a later deployment replaced it (the race
/// between the watch's read and its switch).
#[test]
fn a_watched_rollback_after_a_later_promote_is_stale() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let epoch = promote(&p, &props, "counter-fail-get", 5);
    promote(&p, &props, "counter-body-v2", 5);
    let e =
        p.rt.block_on(props.rollback_watched(epoch, audit()))
            .unwrap_err();
    assert_eq!(e.code, ErrorCode::ProposalStale, "{e}");
    assert!(rollbacks(&p).is_empty());
}

/// Review W-H1: after a manual rollback of the watched deployment, the
/// watch ends without rolling back a second time.
#[test]
fn a_manual_rollback_ends_the_watch_without_a_second_rollback() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    set_guards(&p, LATE_ROLLBACK);
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    get_n(&p, 50);
    p.settle();
    let (manual, _, _) =
        p.rt.block_on(props.rollback(epoch, audit(), false))
            .unwrap();
    // 15 healthy turns after it: 65 since the watched deployment.
    get_n(&p, 15);
    p.settle();
    let w = wait_for(&watches, &w.id, |w| w.status != "watching");
    assert_eq!(w.status, "superseded", "{w:?}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(guards_in_log(&p).is_empty());
    let rollbacks = rollbacks(&p);
    assert_eq!(rollbacks.len(), 1, "{rollbacks:?}");
    assert_eq!(rollbacks[0].epoch, manual);
}

/// Review W-H1: only the latest deployment of its kinds can be watched,
/// and W-M5: `--for` is at most 24 hours.
#[test]
fn watching_a_replaced_deployment_or_for_too_long_is_refused() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    set_guards(&p, "guard = []\n");
    let old = promote(&p, &props, "counter-fail-get", 5);
    let new = promote(&p, &props, "counter-body-v2", 5);
    let watches = watches(&p, &props, dir.path());
    let err =
        p.rt.block_on(watches.watch(old, 60_000, audit(), true, false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
    assert!(err.message.contains("no longer the latest"), "{err}");
    let err =
        p.rt.block_on(watches.watch(new, MAX_FOR_MS + 1, audit(), true, false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
    p.rt.block_on(watches.watch(new, MAX_FOR_MS, audit(), true, false))
        .unwrap();
}

/// Review W-M1: the daemon stopped between a watch's rollback and its
/// `GuardTriggered`. The resumed watch writes the record although healthy
/// traffic since would not fire the guard, and rolls back nothing more.
#[test]
fn a_rollback_without_its_record_is_recorded_at_resume() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    // The watch as it was saved, and its rollback with the watch's audit.
    let mut w = {
        let watches = watches(&p, &props, dir.path());
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), true, false))
            .unwrap()
    };
    w.metrics = None;
    std::fs::create_dir_all(dir.path().join("watches")).unwrap();
    std::fs::write(
        dir.path().join(format!("watches/{}.json", w.id)),
        serde_json::to_vec_pretty(&w).unwrap(),
    )
    .unwrap();
    let crashed = pb::Audit {
        token_id: "kronik".into(),
        reason: format!("watch {}: guard `error-rate-up` fired", w.id),
        wall_time_ms: 0,
    };
    let (rollback, _, _) =
        p.rt.block_on(props.rollback(epoch, crashed, false))
            .unwrap();
    get_n(&p, 25);
    p.settle();

    let resumed = watches(&p, &props, dir.path());
    let w = wait_for(&resumed, &w.id, |w| w.status != "watching");
    assert_eq!(w.status, "rolled_back", "{w:?}");
    let [g] = guards_in_log(&p).try_into().unwrap();
    assert_eq!(g.guard, "error-rate-up");
    assert_eq!(g.action, pb::GuardAction::Rollback as i32);
    assert_eq!(g.outcome, pb::GuardOutcome::RolledBack as i32);
    assert_eq!(g.rollback_epoch, rollback);
    assert_eq!(rollbacks(&p).len(), 1);
}

/// Review W-M2: before the first turn after the deployment nothing is
/// evaluated, so a guard that divides by `after.turns` is not used up by
/// a division by zero, and rolls back once the failures come.
#[test]
fn guards_wait_for_a_turn_after_the_deployment() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    set_guards(
        &p,
        "[[guard]]\nname = \"ratio\"\n\
         when = \"guard.after.failed * 100 / guard.after.turns > 5\"\naction = \"rollback\"\n",
    );
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(guards_in_log(&p).is_empty());
    get_n(&p, 5);
    p.settle();
    let w = wait_for(&watches, &w.id, |w| w.status != "watching");
    assert_eq!(w.status, "rolled_back", "{w:?}");
    let [g] = guards_in_log(&p).try_into().unwrap();
    assert_eq!(g.outcome, pb::GuardOutcome::RolledBack as i32);
}

/// Review W-M2: a guard that cannot be evaluated alerts once and is not
/// used up: it rolls back once it can be evaluated and holds.
#[test]
fn a_guard_that_cannot_be_evaluated_alerts_once_and_can_still_roll_back() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    // Divides by zero while fewer than 5 turns ran after the deployment.
    set_guards(
        &p,
        "[[guard]]\nname = \"ratio\"\n\
         when = \"guard.after.failed * 100 / (guard.after.turns - guard.after.turns % 5) > 50\"\n\
         action = \"rollback\"\n",
    );
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    get_n(&p, 2);
    p.settle();
    wait_for(&watches, &w.id, |w| !w.triggered.is_empty());
    get_n(&p, 10);
    p.settle();
    let w = wait_for(&watches, &w.id, |w| w.status != "watching");
    assert_eq!(w.status, "rolled_back", "{w:?}");
    let [alert, rollback] = guards_in_log(&p).try_into().unwrap();
    assert_eq!(alert.outcome, pb::GuardOutcome::Alerted as i32);
    assert!(alert.reason.starts_with(EVAL_ERROR), "{}", alert.reason);
    assert_eq!(rollback.guard, "ratio");
    assert_eq!(rollback.outcome, pb::GuardOutcome::RolledBack as i32);
}

/// Review W-M4: client input errors (`REJECTED`) are not failures, so the
/// default guards do not roll back a build that rejects bad input.
#[test]
fn rejected_turns_do_not_roll_back() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    for _ in 0..25 {
        p.http("a", "reject", "");
    }
    p.settle();
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    // Evaluated on all 25 turns, a few times over.
    wait_for(&watches, &w.id, |w| {
        w.metrics
            .as_ref()
            .is_some_and(|m| m["after"]["turns"] == 25)
    });
    std::thread::sleep(Duration::from_millis(300));
    let w = watches.get(&w.id).unwrap();
    assert_eq!(w.status, "watching", "{w:?}");
    assert_eq!(w.metrics.as_ref().unwrap()["after"]["failed"], 0);
    // latency-p99-up depends on the host's load (turn durations are wall
    // time) and may alert; rejected turns must not fire error-rate-up.
    let guards = guards_in_log(&p);
    assert!(
        guards.iter().all(|g| g.guard != "error-rate-up"),
        "{guards:?}"
    );
    assert!(rollbacks(&p).is_empty());
}

/// Review W-M5: `guard = []` means no guards, not the default rollback.
#[test]
fn an_empty_guard_list_never_rolls_back() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    set_guards(&p, "guard = []\n");
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    get_n(&p, 25);
    p.settle();
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    wait_for(&watches, &w.id, |w| {
        w.metrics
            .as_ref()
            .is_some_and(|m| m["after"]["failed"] == 25)
    });
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(watches.get(&w.id).unwrap().status, "watching");
    assert!(guards_in_log(&p).is_empty());
    assert!(rollbacks(&p).is_empty());
}

/// Review W-M5: a stopped watch writes nothing and rolls nothing back; a
/// dry run changes nothing, and a watch that is over cannot be stopped.
#[test]
fn a_stopped_watch_acts_no_more() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    let dry = p.rt.block_on(watches.stop(&w.id, audit(), true)).unwrap();
    assert_eq!(dry.status, "watching");
    let stopped = p.rt.block_on(watches.stop(&w.id, audit(), false)).unwrap();
    assert_eq!(stopped.status, "stopped");
    assert_eq!(stopped.stopped.unwrap().reason, "test");
    get_n(&p, 25);
    p.settle();
    std::thread::sleep(Duration::from_millis(300));
    assert!(guards_in_log(&p).is_empty());
    assert!(rollbacks(&p).is_empty());
    assert_eq!(watches.get(&w.id).unwrap().status, "stopped");
    let err =
        p.rt.block_on(watches.stop(&w.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
}

/// Review W-L2: a dry run evaluates the guards on the current windows.
#[test]
fn a_dry_run_reports_the_guards_that_would_fire() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let epoch = promote(&p, &props, "counter-fail-get", 20);
    get_n(&p, 25);
    p.settle();
    let watches = watches(&p, &props, dir.path());
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), true, false))
            .unwrap();
    assert_eq!(w.metrics.as_ref().unwrap()["after"]["failed"], 25);
    // Only error-rate-up is certain: latency-p99-up depends on the host's
    // load (turn durations are wall time) and may fire too.
    let fired = error_rate_up(&w.triggered);
    assert_eq!(fired.len(), 1, "{w:?}");
    assert_eq!(fired[0].lsn, 0);
    assert!(guards_in_log(&p).is_empty());
    assert!(rollbacks(&p).is_empty());
    assert!(watches.list().is_empty());
}

/// Review W-L2: the dry run plans the rollback as the real tick does: a
/// deployment that added a kind cannot be rolled back.
#[test]
fn a_dry_run_predicts_a_failing_rollback() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let epoch = promote_all(&p, &props, &["counter-fail-get", "notes"], 20);
    get_n(&p, 25);
    p.settle();
    let watches = watches(&p, &props, dir.path());
    let dry =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), true, false))
            .unwrap();
    let fired = error_rate_up(&dry.triggered);
    assert_eq!(fired.len(), 1, "{dry:?}");
    assert_eq!(fired[0].outcome, "rollback_failed");
    let w =
        p.rt.block_on(watches.watch(epoch, 60_000, audit(), false, false))
            .unwrap();
    let w = wait_for(&watches, &w.id, |w| !error_rate_up(&w.triggered).is_empty());
    assert_eq!(
        error_rate_up(&w.triggered)[0].outcome,
        fired[0].outcome,
        "{w:?}"
    );
    assert!(rollbacks(&p).is_empty());
}
