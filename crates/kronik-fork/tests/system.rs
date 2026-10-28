//! System proposals (docs/design/m9-system-proposals.md): several actor
//! kinds verified and switched as one unit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{CodeHash, Lsn};
use kronik_fork::diff::DiffOptions;
use kronik_fork::proposal::{Proposal, Proposals, ProposeRequest};
use kronik_policy::RuleSet;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{NodeConfig, SwitchHold, TurnResult};
use serde_json::Value;

fn try_propose(p: &Proc, props: &Proposals, guests: &[&str]) -> Result<Proposal, ApiError> {
    let wasm = guests
        .iter()
        .map(|g| std::fs::read(guest(g)).unwrap())
        .collect();
    p.settle();
    p.rt.block_on(props.propose(ProposeRequest {
        wasm,
        names: guests.iter().map(|g| (*g).to_owned()).collect(),
        window_ms: None,
        at: None,
        options: DiffOptions::default(),
        workers: Some(2),
        audit: audit(),
        dry_run: false,
    }))
    .map(|(prop, _)| prop)
}

fn diff(p: &Proc, props: &Proposals, id: &str) -> Value {
    serde_json::from_slice(&p.rt.block_on(props.diff(id, false, false)).unwrap()).unwrap()
}

/// The diff's entry for `kind`.
fn kind<'a>(d: &'a Value, kind: &str) -> &'a Value {
    d["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kind"] == kind)
        .unwrap_or_else(|| panic!("no kind {kind} in {}", d["kinds"]))
}

fn reply(r: &TurnResult) -> String {
    match &r.outcome.output {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn hash(name: &str) -> Vec<u8> {
    CodeHash::of(&std::fs::read(guest(name)).unwrap())
        .0
        .to_vec()
}

/// main with counter and notes deployed and traffic on both.
fn system(dir: &std::path::Path, cfg: Option<NodeConfig>) -> Proc {
    let p = match cfg {
        Some(cfg) => Proc::start_with(dir, cfg),
        None => Proc::start(dir),
    };
    p.deploy("notes");
    for _ in 0..4 {
        p.http("a", "increment", "");
    }
    p.send("notes/n", "add", "first");
    p
}

/// The one rule the together/apart test is about. The default rules also
/// judge fuel, which the new calls raise; the test checks them separately.
const NO_NEW_ERRORS: &str = "[[rule]]\nname = \"no-new-errors\"\nwhen = \"diff.errors.introduced > 0\"\naction = \"deny\"\n";

/// The default rules that fire on a diff.
fn default_rules_fired(d: &Value) -> Vec<String> {
    RuleSet::defaults()
        .evaluate(d)
        .fired
        .into_iter()
        .map(|f| f.name)
        .collect()
}

/// Criteria 1 and 2: the caller and its new callee in one proposal give
/// one fork, one replay and one diff with each kind on its own, and no
/// errors; the caller alone introduces errors.
#[test]
fn a_caller_and_its_new_callee_verify_together_and_fail_apart() {
    let dir = tempdir();
    let p = system(dir.path(), None);
    p.rt.block_on(p.node.set_policy(NO_NEW_ERRORS, audit(), false))
        .unwrap();
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();

    let together = try_propose(&p, &props, &["counter-calls-tally", "notes-tally"]).unwrap();
    let d = diff(&p, &props, &together.id);
    assert_eq!(together.status, "evaluated", "{}", together.policy);
    assert_eq!(together.policy["outcome"], "allow", "{}", together.policy);
    assert_eq!(d["errors"]["introduced"], 0, "{d}");
    assert_eq!(d["errors"]["new_orphans"], 0, "{d}");
    let fired = default_rules_fired(&d);
    for rule in ["no-new-errors", "no-new-orphans"] {
        assert!(!fired.iter().any(|f| f == rule), "{rule}: {fired:?}");
    }
    // One fork with both kinds' code, one diff that reports them apart.
    assert_eq!(d["fork"], together.id);
    let after: Vec<&str> = d["code"]["after"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert_eq!(after, ["counter", "notes"]);
    let names: Vec<&str> = d["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kind"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["counter", "notes"]);
    let (counter, notes) = (kind(&d, "counter"), kind(&d, "notes"));
    assert_eq!(counter["code"], "changed");
    assert_eq!(notes["code"], "changed");
    assert_eq!(counter["root_inputs"], 4, "{counter}");
    assert_eq!(notes["root_inputs"], 1, "{notes}");
    // The counter's turns now call; the notes kind gets new tally turns.
    assert!(counter["divergent_turns"].as_u64() > Some(0), "{counter}");
    assert!(notes["divergent_turns"].as_u64() > Some(0), "{notes}");
    assert!(
        notes["turns_fork"].as_u64() > notes["turns_prod"].as_u64(),
        "{notes}"
    );
    assert_eq!(counter["errors"]["introduced"], 0);
    assert_eq!(notes["errors"]["introduced"], 0);
    let per_kind: u64 = d["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["divergent_turns"].as_u64().unwrap())
        .sum();
    assert_eq!(per_kind, d["summary"]["divergent_turns"].as_u64().unwrap());
    let md = String::from_utf8(
        p.rt.block_on(props.diff(&together.id, true, false))
            .unwrap(),
    )
    .unwrap();
    assert!(md.contains("## Actor kinds"), "{md}");
    assert!(md.contains("| notes | changed |"), "{md}");

    // The same changes proposed apart: the caller alone calls a message
    // the running notes code does not serve.
    let caller = try_propose(&p, &props, &["counter-calls-tally"]).unwrap();
    let dc = diff(&p, &props, &caller.id);
    assert_eq!(caller.status, "rejected", "{}", caller.policy);
    assert_eq!(caller.policy["outcome"], "deny");
    assert_eq!(caller.policy["fired"][0]["name"], "no-new-errors");
    assert!(
        default_rules_fired(&dc)
            .iter()
            .any(|f| f == "no-new-errors"),
        "the default rules deny it too"
    );
    assert!(dc["errors"]["introduced"].as_u64() > Some(0), "{dc}");
    assert!(kind(&dc, "counter")["errors"]["introduced"].as_u64() > Some(0));
    assert!(kind(&dc, "notes")["errors"]["introduced"].as_u64() > Some(0));
    assert_eq!(kind(&dc, "notes")["code"], "unchanged");
    let callee = try_propose(&p, &props, &["notes-tally"]).unwrap();
    let dn = diff(&p, &props, &callee.id);
    assert_eq!(dn["errors"]["introduced"], 0, "{dn}");
    assert_eq!(
        kind(&dn, "notes")["divergent_turns"],
        0,
        "nothing calls tally yet"
    );

    // Three proposals, three forks; the system one holds both kinds.
    assert_eq!(p.rt.block_on(props.list()).len(), 3);
    assert_eq!(together.kinds.len(), 2);
    assert_eq!(caller.kinds.len(), 1);
}

/// "Components with an unchanged hash are skipped."
#[test]
fn unchanged_components_are_skipped_and_nothing_changed_is_refused() {
    let dir = tempdir();
    let p = system(dir.path(), None);
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();

    let prop = try_propose(&p, &props, &["counter-step2", "notes"]).unwrap();
    assert_eq!(prop.kinds.len(), 1, "notes is already deployed");
    let skipped = prop.unchanged_versions().unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].kind, "notes");
    assert_eq!(skipped[0].code_hash, hash("notes"), "the full hash is kept");

    // Two builds of one kind: the error names both components.
    let err = try_propose(&p, &props, &["notes-tally", "notes-route-tally"]).unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
    assert!(
        err.message.contains("notes-tally and notes-route-tally"),
        "{err}"
    );
    let d = diff(&p, &props, &prop.id);
    assert_eq!(kind(&d, "counter")["code"], "changed");
    assert_eq!(kind(&d, "notes")["code"], "unchanged");

    let err = try_propose(&p, &props, &["counter", "notes"]).unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
    assert!(err.message.contains("nothing to propose"), "{err}");
    assert!(
        err.hint
            .as_deref()
            .is_some_and(|h| h.contains("kronik replay"))
    );
    assert_eq!(
        p.rt.block_on(props.list()).len(),
        1,
        "a refusal writes nothing"
    );
}

/// Review H1: a component that main runs now but did not run at the fork
/// point is not skipped: the fork would run the fork point's code for it.
#[test]
fn a_component_promoted_inside_the_window_is_not_skipped() {
    let dir = tempdir();
    let p = system(dir.path(), None);
    p.rt.block_on(p.node.set_policy(NO_NEW_ERRORS, audit(), false))
        .unwrap();
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    // notes-tally goes live inside the window, after the fork point.
    let callee = try_propose(&p, &props, &["notes-tally"]).unwrap();
    p.rt.block_on(props.promote(&callee.id, audit(), false))
        .unwrap();
    p.http("a", "increment", "");

    let set = try_propose(&p, &props, &["counter-calls-tally", "notes-tally"]).unwrap();
    assert!(set.unchanged.is_empty(), "notes-tally was skipped");
    assert_eq!(set.kinds.len(), 2);
    let d = diff(&p, &props, &set.id);
    assert_eq!(kind(&d, "notes")["code"], "changed", "{}", d["code"]);
    assert_eq!(d["errors"]["introduced"], 0, "{d}");
    assert_eq!(set.policy["outcome"], "allow", "{}", set.policy);
    // Promote then swaps notes to the code it already runs.
    let r =
        p.rt.block_on(props.promote(&set.id, audit(), false))
            .unwrap();
    assert_eq!(r.kinds.len(), 2);
}

/// Review M1: a skipped component is pinned. When its kind changes code
/// between propose and promote, promote refuses with PROPOSAL_STALE.
#[test]
fn promote_refuses_when_a_skipped_kind_changed_code() {
    let dir = tempdir();
    let p = system(dir.path(), None);
    p.rt.block_on(p.node.set_policy(NO_NEW_ERRORS, audit(), false))
        .unwrap();
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    let prop = try_propose(&p, &props, &["counter-step2", "notes"]).unwrap();
    assert_eq!(prop.unchanged.len(), 1, "notes is skipped");
    // Another proposal changes notes in between.
    let other = try_propose(&p, &props, &["notes-tally"]).unwrap();
    p.rt.block_on(props.promote(&other.id, audit(), false))
        .unwrap();
    let deployments = p.node.store().db().deployments().unwrap().len();

    for dry_run in [true, false] {
        let err =
            p.rt.block_on(props.promote(&prop.id, audit(), dry_run))
                .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
        assert!(err.message.contains("\"notes\" no longer runs"), "{err}");
    }
    assert_eq!(
        p.node.store().db().deployments().unwrap().len(),
        deployments
    );
    assert_eq!(p.rt.block_on(props.get(&prop.id)).unwrap().status, "stale");
    // The counter kept its code: 4 + 1.
    assert_eq!(http_body(&p.http("a", "increment", "")), "5");
}

/// Review A1: a changed kind is pinned to main's code for it when the
/// proposal was made. Two proposals change counter from the same code;
/// once one is promoted, the other would overwrite it with code built on
/// the old one, so it is stale. A proposal made after that promote, whose
/// window still reaches back before it, promotes as usual.
#[test]
fn promote_refuses_when_a_changed_kind_changed_code_since_the_fork() {
    let dir = tempdir();
    let p = system(dir.path(), None);
    p.rt.block_on(p.node.set_policy(NO_NEW_ERRORS, audit(), false))
        .unwrap();
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    let p1 = try_propose(&p, &props, &["counter-step2"]).unwrap();
    let p2 = try_propose(&p, &props, &["counter-body-v2"]).unwrap();
    p.rt.block_on(props.promote(&p2.id, audit(), false))
        .unwrap();
    let deployments = p.node.store().db().deployments().unwrap().len();

    for dry_run in [true, false] {
        let err =
            p.rt.block_on(props.promote(&p1.id, audit(), dry_run))
                .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
        assert!(err.message.contains("\"counter\" no longer runs"), "{err}");
        assert!(
            err.message
                .contains("the code it ran when the proposal was made (deployment "),
            "{err}"
        );
        assert!(err.message.ends_with("changed it)"), "{err}");
        assert!(
            err.hint
                .as_deref()
                .is_some_and(|h| h.contains("kronik deployments list")),
            "{err:?}"
        );
    }
    assert_eq!(
        p.node.store().db().deployments().unwrap().len(),
        deployments
    );
    assert_eq!(p.rt.block_on(props.get(&p1.id)).unwrap().status, "stale");
    assert_eq!(
        p.node.deployed("counter").unwrap().code_hash,
        hash("counter-body-v2"),
        "main still runs p2's code"
    );

    // Proposed after p2's promote: its fork point (the window's start) is
    // before that promote, the head it was made at after it.
    let p3 = try_propose(&p, &props, &["counter-step2"]).unwrap();
    assert!(p3.fork_lsn < p.node.store().db().deployments().unwrap().last().unwrap().0);
    for dry_run in [true, false] {
        p.rt.block_on(props.promote(&p3.id, audit(), dry_run))
            .unwrap();
    }
    assert_eq!(
        p.node.deployed("counter").unwrap().code_hash,
        hash("counter-step2")
    );
}

/// Review L3: a turn re-run after a crash keeps the schema version of the
/// code it began with, even when a switch raised the kind's version.
#[test]
fn a_rerun_across_a_schema_raising_switch_keeps_its_code_version() {
    let dir = tempdir();
    let p = Proc::start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            test_hold_after_call: true,
            ..NodeConfig::default()
        },
    );
    p.http("a", "increment", "");
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    let prop = try_propose(&p, &props, &["counter-schema1"]).unwrap();
    // counter/c begins under schema 0 and holds after its call answered.
    p.http_detached("c", "call", "counter/b increment");
    p.wait_kv("counter/b", "n");
    p.rt.block_on(props.promote(&prop.id, audit(), false))
        .unwrap();
    drop(props);
    drop(p);

    // After the crash, the re-run runs the schema-0 code again; counter/c
    // must still migrate on its first turn under the schema-1 code.
    let p = Proc::open(dir.path(), NodeConfig::default());
    wait_until("the re-run of counter/c", || {
        p.node.store().db().actor("counter", "c").unwrap().is_some()
    });
    p.http("c", "increment", "");
    let schema = p
        .node
        .store()
        .db()
        .kv_get("counter", "c", "schema")
        .unwrap();
    assert_eq!(
        schema.as_deref(),
        Some(&b"1"[..]),
        "counter/c skipped its migration"
    );
}

/// Every turn record in main's log after `after`.
fn turns_after(p: &Proc, after: Lsn) -> Vec<(Lsn, pb::TurnRecord)> {
    let head = p.settle();
    (after + 1..=head)
        .filter_map(|lsn| {
            let c = p.rt.block_on(p.node.read_record(lsn)).unwrap()?;
            match c.record {
                Record::TurnRecord(t) => Some((lsn, t)),
                _ => None,
            }
        })
        .collect()
}

/// Polls `done` until it holds; it depends on no timing, the limit only
/// turns a hang into a failure.
fn wait_until(what: &str, done: impl Fn() -> bool) {
    for _ in 0..6000 {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("never: {what}");
}

/// Criterion 3: once a set's `Deployment` is in the log, no turn of any
/// kind in the set starts with the old code. The switch is parked right
/// after its `Deployment` is applied and before the code is swapped; turns
/// that arrive then wait for it and run the new code.
#[test]
fn no_turn_starts_with_old_code_after_a_set_switch() {
    let dir = tempdir();
    let hold = Arc::new(SwitchHold::default());
    let p = system(
        dir.path(),
        Some(NodeConfig {
            concurrency: 8,
            test_hold_switch: Some(hold.clone()),
            ..NodeConfig::default()
        }),
    );
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let prop = try_propose(&p, &props, &["counter-calls-tally", "notes-tally"]).unwrap();
    // The promote goes through its hold at once.
    hold.release.add_permits(1);
    let promoted =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap();
    assert_eq!(hold.parked.load(Ordering::SeqCst), 1);
    p.settle();

    // Roll the set back and keep it parked with its Deployment applied.
    let rollback = {
        let props = props.clone();
        p.rt.spawn(async move { props.rollback(promoted.epoch, audit(), false).await })
    };
    wait_until("the rollback parks", || {
        hold.parked.load(Ordering::SeqCst) == 2
    });
    let (lsn, d) = p.node.store().db().deployments().unwrap().pop().unwrap();
    assert_eq!(
        d.rollback_of_epoch, promoted.epoch,
        "the rollback is in the log"
    );
    assert_eq!(p.node.applied_lsn(), lsn, "and applied");
    // Turns of both kinds come while it is parked.
    let arrived = hold.arrived.load(Ordering::SeqCst);
    std::thread::scope(|s| {
        s.spawn(|| p.http("a", "increment", ""));
        s.spawn(|| p.send("notes/n", "add", "during the switch"));
        wait_until("both turns arrive", || {
            hold.arrived.load(Ordering::SeqCst) >= arrived + 2
        });
        hold.release.add_permits(1);
    });
    let (epoch, at, kinds) = p.rt.block_on(rollback).unwrap().unwrap();
    assert_eq!((at, kinds.len()), (lsn, 2));

    let old = [("counter", hash("counter")), ("notes", hash("notes"))];
    let turns = turns_after(&p, lsn);
    assert!(
        turns.len() >= 2,
        "the turns sent while parked were not recorded"
    );
    for (at, t) in &turns {
        let k = t.actor.as_ref().unwrap().kind.as_str();
        let (_, code) = old.iter().find(|(n, _)| *n == k).unwrap();
        assert_eq!(
            &t.code_hash, code,
            "turn {at} of {k} started after the rollback at lsn {lsn} with the code it replaced"
        );
        assert!(
            t.config_epoch >= epoch,
            "turn {at}: epoch {}",
            t.config_epoch
        );
    }
    // The counter turn ran the restored code: no call to notes.
    assert!(
        turns
            .iter()
            .all(|(_, t)| t.effects.iter().all(|e| e.kind != "actor.call")),
        "a turn after the switch still called tally"
    );
}

/// Criterion 4: rolling back a set restores every kind of it in one
/// `Deployment`, at one LSN and one epoch.
#[test]
fn rolling_back_a_set_restores_every_kind_at_one_lsn() {
    let dir = tempdir();
    let p = system(dir.path(), None);
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    let prop = try_propose(&p, &props, &["counter-calls-tally", "notes-tally"]).unwrap();
    let promoted =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap();

    // The promote switched both kinds with one record.
    let deployments = p.node.store().db().deployments().unwrap();
    let (at, d) = deployments.last().unwrap();
    assert_eq!((*at, d.epoch), (promoted.lsn, promoted.epoch));
    let set: Vec<(&str, Vec<u8>)> = d
        .kinds
        .iter()
        .map(|k| (k.kind.as_str(), k.code_hash.clone()))
        .collect();
    assert_eq!(
        set,
        [
            ("counter", hash("counter-calls-tally")),
            ("notes", hash("notes-tally"))
        ]
    );
    // Both new codes serve: the increment calls notes/tally.
    assert_eq!(http_body(&p.http("a", "increment", "")), "5");
    assert_eq!(reply(&p.send("notes/tally", "count", "")), "1");

    let (epoch, lsn, kinds) =
        p.rt.block_on(props.rollback(promoted.epoch, audit(), false))
            .unwrap();
    assert_eq!(kinds.len(), 2);
    let deployments = p.node.store().db().deployments().unwrap();
    let (at, d) = deployments.last().unwrap();
    assert_eq!(
        (*at, d.epoch, d.cause, d.rollback_of_epoch),
        (
            lsn,
            epoch,
            pb::DeploymentCause::Rollback as i32,
            promoted.epoch
        )
    );
    let set: Vec<(&str, Vec<u8>)> = d
        .kinds
        .iter()
        .map(|k| (k.kind.as_str(), k.code_hash.clone()))
        .collect();
    assert_eq!(
        set,
        [("counter", hash("counter")), ("notes", hash("notes"))]
    );
    assert_eq!(
        deployments
            .iter()
            .filter(|(l, _)| *l > promoted.lsn)
            .count(),
        1
    );

    // Both kinds behave as before the promote again.
    assert_eq!(http_body(&p.http("a", "increment", "")), "6");
    assert_eq!(
        reply(&p.send("notes/tally", "count", "")),
        "1",
        "no new tally"
    );
    assert!(!p.send("notes/tally", "tally", "x").committed());
}

/// Rolling back a set that added a kind is refused as a whole: there is no
/// code to roll the new kind back to, and a deployment cannot remove it.
#[test]
fn rolling_back_a_set_that_added_a_kind_is_refused() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    for _ in 0..3 {
        p.http("a", "increment", "");
    }
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    let prop = try_propose(&p, &props, &["counter-step2", "notes"]).unwrap();
    assert_eq!(kind(&diff(&p, &props, &prop.id), "notes")["code"], "new");
    let promoted =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap();
    let deployments = p.node.store().db().deployments().unwrap().len();
    for dry_run in [true, false] {
        let err =
            p.rt.block_on(props.rollback(promoted.epoch, audit(), dry_run))
                .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
        assert!(err.message.contains("\"notes\" did not exist"), "{err}");
        assert!(
            err.hint
                .as_deref()
                .is_some_and(|h| h.contains("kronik propose")),
            "{err:?}"
        );
    }
    assert_eq!(
        p.node.store().db().deployments().unwrap().len(),
        deployments
    );
    // The counter keeps the promoted code: 3 + 2.
    assert_eq!(http_body(&p.http("a", "increment", "")), "5");
}

/// A component's code as a set member, as propose records it.
fn kind_version(p: &Proc, name: &str) -> pb::KindVersion {
    let bytes = std::fs::read(guest(name)).unwrap();
    let (hash, _, manifest) = p.rt.block_on(p.node.prepare_code(&bytes)).unwrap();
    pb::KindVersion {
        kind: manifest.kind.clone(),
        code_hash: hash.0.to_vec(),
        schema_version: manifest.schema_version,
        manifest: Some(manifest),
        code_size: bytes.len() as u64,
    }
}

/// Who serves GET /tally/{key} on main, if anyone.
fn tally_route(p: &Proc) -> Option<String> {
    let (_, routes) = p.node.routes();
    routes
        .into_iter()
        .find(|r| r.method == "GET" && r.pattern == "/tally/{key}")
        .map(|r| r.kind)
}

/// Proposal directories under `branches/`.
fn proposal_dirs(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir.join("branches"))
        .map(|d| {
            d.filter(|e| {
                e.as_ref()
                    .is_ok_and(|e| e.file_name().to_string_lossy().starts_with("p-"))
            })
            .count()
        })
        .unwrap_or(0)
}

/// Two kinds of one set cannot both take a new route: propose and the
/// switch refuse it with ROUTE_CONFLICT, dry run or not, and write nothing.
#[test]
fn two_kinds_of_a_set_cannot_claim_one_route() {
    let dir = tempdir();
    let p = system(dir.path(), None);
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    let deployments = p.node.store().db().deployments().unwrap().len();
    let set = ["counter-route-tally", "notes-route-tally"];
    for dry_run in [true, false] {
        let wasm = set
            .iter()
            .map(|g| std::fs::read(guest(g)).unwrap())
            .collect();
        let err =
            p.rt.block_on(props.propose(ProposeRequest {
                wasm,
                names: Vec::new(),
                window_ms: None,
                at: None,
                options: DiffOptions::default(),
                workers: Some(2),
                audit: audit(),
                dry_run,
            }))
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::RouteConflict,
            "dry run {dry_run}: {err}"
        );
        assert!(err.message.contains("GET /tally/{key}"), "{err}");
    }
    assert!(p.rt.block_on(props.list()).is_empty());
    assert_eq!(proposal_dirs(dir.path()), 0, "propose wrote a proposal");

    // The switch (promote, rollback) checks the set the same way.
    let kinds: Vec<pb::KindVersion> = set.iter().map(|g| kind_version(&p, g)).collect();
    for dry_run in [true, false] {
        let err =
            p.rt.block_on(p.node.switch_code(
                kronik_sched::CodeSwitch {
                    kinds: kinds.clone(),
                    pinned: Vec::new(),
                    cause: pb::DeploymentCause::Promote,
                    verified_through_lsn: 0,
                    unverified_inputs: 0,
                    proposal_id: String::new(),
                    rollback_of_epoch: 0,
                },
                audit(),
                dry_run,
            ))
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::RouteConflict,
            "dry run {dry_run}: {err}"
        );
    }
    assert_eq!(
        p.node.store().db().deployments().unwrap().len(),
        deployments
    );
    assert_eq!(tally_route(&p), None);
}

/// A set may move a route from one of its kinds to another: the check sees
/// the routes after the switch, not the ones the set replaces.
#[test]
fn a_set_can_move_a_route_from_one_kind_to_another() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    // The counter serves GET /tally/{key} on main (no history yet, so a
    // plain deploy replaces the first one).
    p.deploy("counter-route-tally");
    p.deploy("notes");
    p.http("a", "increment", "");
    p.send("notes/n", "add", "first");
    p.rt.block_on(p.node.set_policy(NO_NEW_ERRORS, audit(), false))
        .unwrap();
    assert_eq!(tally_route(&p).as_deref(), Some("counter"));
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();

    // The notes kind alone cannot take a route the counter serves...
    let err = try_propose(&p, &props, &["notes-route-tally"]).unwrap_err();
    assert_eq!(err.code, ErrorCode::RouteConflict, "{err}");
    // ...but it can in a set where the counter gives it up.
    let prop = try_propose(&p, &props, &["counter", "notes-route-tally"]).unwrap();
    assert_eq!(prop.policy["outcome"], "allow", "{}", prop.policy);
    p.rt.block_on(props.promote(&prop.id, audit(), false))
        .unwrap();
    assert_eq!(tally_route(&p).as_deref(), Some("notes"));
}
