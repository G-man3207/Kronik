//! Proposals end to end against a real node (docs/design/m3-fork.md §8,
//! §10): propose, catch-up, policy, approval, promote, rollback.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use kronik_core::error::ErrorCode;
use kronik_fork::diff::DiffOptions;
use kronik_fork::proposal::{Proposals, ProposeRequest};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

fn propose(
    p: &Proc,
    props: &Arc<Proposals>,
    wasm: &str,
    options: DiffOptions,
) -> kronik_fork::proposal::Proposal {
    let bytes = std::fs::read(guest(wasm)).unwrap();
    p.settle();
    let (prop, dry) =
        p.rt.block_on(props.propose(ProposeRequest {
            wasm: vec![bytes],
            names: Vec::new(),
            window_ms: None,
            at: None,
            options,
            workers: Some(2),
            audit: audit(),
            dry_run: false,
        }))
        .unwrap();
    assert!(!dry);
    prop
}

fn last_deployment(p: &Proc) -> (u64, pb::Deployment) {
    p.node.store().db().deployments().unwrap().pop().unwrap()
}

#[test]
fn promote_runs_catch_up_switches_code_and_rollback_restores_it() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    for _ in 0..10 {
        p.http("a", "increment", "");
    }
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let prop = propose(&p, &props, "counter-step2", DiffOptions::default());
    assert_eq!(prop.status, "evaluated");
    assert_eq!(prop.policy["outcome"], "allow", "{}", prop.policy);
    assert_eq!(prop.summary["root_inputs"], 10);

    // Traffic after the proposal runs through the new code before the
    // switch (catch-up).
    for _ in 0..5 {
        p.http("a", "increment", "");
    }
    let before_switch = p.settle();
    let r =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap();
    assert!(
        r.verified_through_lsn >= before_switch,
        "{} < {before_switch}",
        r.verified_through_lsn
    );
    let (lsn, d) = last_deployment(&p);
    assert_eq!(lsn, r.lsn);
    assert_eq!(d.cause, pb::DeploymentCause::Promote as i32);
    assert_eq!(d.epoch, r.epoch);
    assert_eq!(d.proposal_id, prop.id);
    assert_eq!(d.verified_through_lsn, r.verified_through_lsn);
    assert_eq!(d.unverified_inputs, 0);
    let after = props_get(&p, &props, &prop.id);
    assert_eq!(after.status, "promoted");
    assert_eq!(after.summary["root_inputs"], 15);

    // The fork's log holds BranchCreated, the Deployment and all 15 turns
    // (catch-up included), at LSNs after the fork point.
    let first = prop.fork_lsn + 3;
    let t =
        p.rt.block_on(props.fork_turn(&prop.id, first))
            .unwrap()
            .unwrap();
    assert_eq!(t.actor.unwrap().key, "a");
    assert!(
        p.rt.block_on(props.fork_turn(&prop.id, first + 14))
            .unwrap()
            .is_some()
    );
    assert!(
        p.rt.block_on(props.fork_turn(&prop.id, first + 15))
            .unwrap()
            .is_none()
    );
    // Every fork turn ran the proposed code — the five catch-up turns at
    // first+10..=first+14 included: each carries the new component's code
    // hash, not the deployment the traffic first ran under.
    let old = p
        .node
        .store()
        .db()
        .deployments()
        .unwrap()
        .into_iter()
        .find(|(_, d)| d.cause == pb::DeploymentCause::Deploy as i32)
        .map(|(_, d)| d.kinds[0].code_hash.clone())
        .unwrap();
    let new = r.kinds[0].code_hash.clone();
    assert_ne!(new, old);
    for lsn in first..=first + 14 {
        let t =
            p.rt.block_on(props.fork_turn(&prop.id, lsn))
                .unwrap()
                .unwrap_or_else(|| panic!("no fork turn at {lsn}"));
        assert_eq!(t.code_hash, new, "fork turn at lsn {lsn}");
    }

    // The new code serves from the switch on: 15 + 2.
    assert_eq!(http_body(&p.http("a", "increment", "")), "17");

    // Rollback restores the old behaviour: 17 + 1.
    let (epoch, _, kinds) =
        p.rt.block_on(props.rollback(r.epoch, audit(), false))
            .unwrap();
    assert_eq!(kinds.len(), 1);
    let (_, d) = last_deployment(&p);
    assert_eq!(
        (d.epoch, d.cause, d.rollback_of_epoch),
        (epoch, pb::DeploymentCause::Rollback as i32, r.epoch)
    );
    assert_eq!(http_body(&p.http("a", "increment", "")), "18");

    // Proposals survive a reload from their directories.
    let again = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    assert_eq!(props_get(&p, &again, &prop.id).status, "promoted");
    let md = String::from_utf8(p.rt.block_on(again.diff(&prop.id, true, false)).unwrap()).unwrap();
    assert!(md.contains("# Behavior diff"), "{md}");
    assert!(
        p.rt.block_on(again.promote(&prop.id, audit(), false))
            .is_err()
    );
}

#[test]
fn rollback_refuses_when_the_schema_version_was_raised() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    for _ in 0..3 {
        p.http("a", "increment", "");
    }
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let prop = propose(&p, &props, "counter-schema1", DiffOptions::default());
    assert_eq!(prop.policy["outcome"], "allow", "{}", prop.policy);
    let r =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap();
    // The promote raised the schema version 0 -> 1: rolling it back would
    // move the schema version over already-migrated state.
    let err =
        p.rt.block_on(props.rollback(r.epoch, audit(), false))
            .unwrap_err();
    assert_eq!(
        err.code,
        ErrorCode::RollbackSchemaChanged,
        "{}",
        err.message
    );
    assert!(
        err.message.contains("from schema version 1 back to 0"),
        "{}",
        err.message
    );
    // Nothing was switched: the promote is still the newest deployment and
    // the new code keeps serving.
    let (_, d) = last_deployment(&p);
    assert_eq!(
        (d.epoch, d.cause),
        (r.epoch, pb::DeploymentCause::Promote as i32)
    );
    assert_eq!(http_body(&p.http("a", "increment", "")), "4");
}

fn props_get(p: &Proc, props: &Proposals, id: &str) -> kronik_fork::proposal::Proposal {
    p.rt.block_on(props.get(id)).unwrap()
}

#[test]
fn a_catch_up_that_finds_a_new_error_stops_promote() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    for _ in 0..5 {
        p.http("a", "increment", "");
    }
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    // The new build breaks `get`, which the window does not contain.
    let prop = propose(&p, &props, "counter-fail-get", DiffOptions::default());
    assert_eq!(prop.policy["outcome"], "allow", "{}", prop.policy);
    p.send("counter/a", "get", "");
    let err =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::PolicyDenied, "{}", err.message);
    assert!(err.message.contains("no-new-errors"), "{}", err.message);
    let after = props_get(&p, &props, &prop.id);
    assert_eq!(after.status, "rejected");
    assert_eq!(after.policy["outcome"], "deny");
    // Main kept the old code.
    assert_eq!(http_body(&p.http("a", "increment", "")), "6");
    assert_eq!(
        last_deployment(&p).1.cause,
        pb::DeploymentCause::Deploy as i32
    );
}

#[test]
fn approximate_effects_need_an_approval_for_promote() {
    let (addr, hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:127.0.0.1");
    for i in 0..3 {
        let spec = format!("POST http://{addr}/v1/charges/{i}\n\namount=10");
        p.http("pay", "fetch-ok", &spec);
    }
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let prop = propose(&p, &props, "counter-body-v2", DiffOptions::default());
    assert_eq!(
        prop.policy["outcome"], "require_approval",
        "{}",
        prop.policy
    );
    assert_eq!(
        prop.policy["fired"][0]["name"],
        "low-grounding-needs-approval"
    );
    let err =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ApprovalRequired, "{}", err.message);
    let (approved, _) =
        p.rt.block_on(props.approve(&prop.id, audit(), false))
            .unwrap();
    assert!(approved.lsn > 0);
    let approvals = p.node.store().db().approvals(&prop.id).unwrap();
    assert_eq!(approvals.len(), 1);
    let r =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap();
    assert!(r.epoch > 0);
    // No replay or catch-up reached the service.
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[test]
fn payments_full_coverage_stops_promote_under_a_sample() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:payments.internal");
    for i in 0..20 {
        // The name does not resolve: the recorded effect fails (network),
        // which is still a recorded effect against payments.internal.
        p.http(
            &format!("k{i}"),
            "fetch-ok",
            "POST http://payments.internal/v1/charges\n\namount=10",
        );
    }
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let sampled = DiffOptions {
        sample: 0.1,
        ..DiffOptions::default()
    };
    let prop = propose(&p, &props, "counter-step2", sampled.clone());
    assert_eq!(prop.policy["outcome"], "deny", "{}", prop.policy);
    assert!(
        prop.policy["fired"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"] == "payments-full-coverage"),
        "{}",
        prop.policy
    );
    assert_eq!(prop.status, "rejected");
    assert!(prop.summary["sample"].as_f64().unwrap() < 1.0);
    let err =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::PolicyDenied);
    // The same proposal samples the same inputs: its diff is stable.
    let d1 = p.rt.block_on(props.diff(&prop.id, false, false)).unwrap();
    let again = propose(&p, &props, "counter-step2", sampled);
    assert_ne!(again.id, prop.id);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&d1).unwrap()["summary"]["replayed"],
        2
    );
    // Full coverage passes that rule.
    let full = propose(&p, &props, "counter-step2", DiffOptions::default());
    assert_eq!(full.policy["outcome"], "allow", "{}", full.policy);
}

fn reply_text(t: &kronik_fork::ForkTurn) -> String {
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
fn messages_into_a_fork_reach_the_network_only_as_allowlisted_gets() {
    let (addr, hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:127.0.0.1");
    let fork_lsn = p.settle();
    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf())
        .unwrap()
        .with_live_allowlist(vec!["127.0.0.1".into()]);
    let (f, _) =
        p.rt.block_on(props.create_fork(Some("probe".into()), fork_lsn, true, audit(), false))
            .unwrap();
    assert!(f.options.no_pii);
    let send = |body: String| {
        let m = pb::Message {
            name: "fetch-ok".into(),
            content_type: "text/plain".into(),
            body: plain(&body),
            blobs: vec![],
        };
        let actor = kronik_core::ids::ActorRef::parse("counter/x").unwrap();
        p.rt.block_on(props.fork_send("probe", actor, m)).unwrap()
    };
    // A POST to an allowlisted host stays FailClosed.
    let t = send(format!("POST http://{addr}/charge\n\nx"));
    assert!(
        reply_text(&t).contains("replay: no recording"),
        "{}",
        reply_text(&t)
    );
    assert_eq!(
        t.record.effects[0].grounding,
        pb::Grounding::Synthetic as i32
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    // A GET to it goes out live.
    let t = send(format!("GET http://{addr}/status"));
    assert_eq!(reply_text(&t), "200 charged 1");
    assert_eq!(t.record.effects[0].grounding, pb::Grounding::Live as i32);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    // Main never saw any of it.
    let a = kronik_core::ids::ActorRef::parse("counter/x").unwrap();
    assert!(
        p.node
            .store()
            .db()
            .actor(&a.kind, &a.key)
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_schema_change_migrates_in_catch_up_and_in_production_after_promote() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.http("a", "increment", "");
    p.http("a", "increment", "");
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let prop = propose(&p, &props, "counter-schema1", DiffOptions::default());
    assert_eq!(prop.policy["outcome"], "allow", "{}", prop.policy);
    // A new actor after the proposal: catch-up migrates it in the fork.
    p.http("c", "increment", "");
    p.settle();
    p.rt.block_on(props.promote(&prop.id, audit(), false))
        .unwrap();
    let mut migrations = Vec::new();
    let mut lsn = prop.fork_lsn + 3;
    while let Some(t) = p.rt.block_on(props.fork_turn(&prop.id, lsn)).unwrap() {
        if matches!(
            t.input.as_ref().and_then(|i| i.kind.as_ref()),
            Some(pb::input::Kind::Migrate(_))
        ) {
            migrations.push(t.actor.unwrap().key);
        }
        lsn += 1;
    }
    assert_eq!(migrations, vec!["a".to_string(), "c".to_string()]);
    // Production migrates each actor on its first turn under the new code.
    p.http("c", "increment", "");
    p.settle();
    let kv = |key: &str| {
        p.node
            .store()
            .db()
            .kv_get("counter", key, "schema")
            .unwrap()
    };
    assert_eq!(kv("c").as_deref(), Some(&b"1"[..]));
    assert_eq!(kv("a"), None);
    p.http("a", "increment", "");
    p.settle();
    assert_eq!(kv("a").as_deref(), Some(&b"1"[..]));
}

/// Traffic inside `[promote] max_gap` is switched over unverified: while
/// promote replays a 300-input backlog, sends keep arriving from eight
/// actors, land inside the hour-wide gap and are counted by
/// `Deployment.unverified_inputs`.
#[test]
fn inputs_inside_the_promote_gap_stay_unverified() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    for _ in 0..5 {
        p.http("a", "increment", "");
    }
    // An hour-wide gap: catch-up converges with the newest root input at
    // most an hour ahead of the verified head, so traffic that arrives
    // while promote runs is switched over without a re-run.
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_promote(Duration::from_secs(3600), Duration::from_secs(120)),
    );
    let prop = propose(&p, &props, "counter-step2", DiffOptions::default());
    assert_eq!(prop.policy["outcome"], "allow", "{}", prop.policy);
    // A backlog the catch-up has to replay, keeping promote busy, while
    // eight actors keep sending: every send that is applied after
    // promote's head is a root input inside the gap.
    for _ in 0..300 {
        p.http("a", "increment", "");
    }
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut senders = Vec::new();
    for i in 0..8 {
        let (node, actor, stop) = (
            p.node.clone(),
            kronik_core::ids::ActorRef::parse(&format!("counter/s{i}")).unwrap(),
            stop.clone(),
        );
        senders.push(p.rt.spawn(async move {
            let m = pb::Message {
                name: "increment".into(),
                content_type: "text/plain".into(),
                body: plain(""),
                blobs: vec![],
            };
            while !stop.load(Ordering::Relaxed) {
                let _ = node.send(actor.clone(), m.clone(), audit(), false).await;
            }
        }));
    }
    let r =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap();
    stop.store(true, Ordering::Relaxed);
    for s in senders {
        let _ = p.rt.block_on(s);
    }
    assert!(
        r.unverified_inputs > 0,
        "the sends inside the gap were all verified: {r:?}"
    );
    let (_, d) = last_deployment(&p);
    assert_eq!(d.unverified_inputs, r.unverified_inputs);
    assert_eq!(d.verified_through_lsn, r.verified_through_lsn);
    // What stayed unverified are the turns applied between the verified
    // head and the switch.
    let mut turns = 0;
    p.rt.block_on(
        p.node
            .reader()
            .read(r.verified_through_lsn + 1, r.lsn, |c| {
                if matches!(&c.record, Record::TurnRecord(_)) {
                    turns += 1;
                }
                Ok(())
            }),
    )
    .unwrap();
    assert!(
        r.unverified_inputs <= turns,
        "unverified {} but only {turns} turns in the gap",
        r.unverified_inputs
    );
    // Main switched to the new code (the deployment is the promote).
    assert_eq!(d.cause, pb::DeploymentCause::Promote as i32);
}

/// Re-review #7 (v0.1): a promote or an approval whose caller went away
/// after its record was committed (the switch and the approval finish on
/// their own) leaves no proposal to promote twice: its metadata follows
/// main's deployments and approvals.
#[test]
fn a_promote_or_approval_cut_short_is_recorded_on_the_proposal() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.http("a", "increment", "");
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());

    // The approval record is committed, the proposal's metadata is not.
    let prop = propose(&p, &props, "counter-step2", DiffOptions::default());
    let diff = std::fs::read(dir.path().join("branches").join(&prop.id).join("diff.json")).unwrap();
    p.rt.block_on(p.node.record_approval(pb::Approval {
        proposal_id: prop.id.clone(),
        diff_hash: blake3::hash(&diff).as_bytes().to_vec(),
        verified_through_lsn: prop.verified_through_lsn,
        audit: Some(audit()),
        request: false,
        command: String::new(),
    }))
    .unwrap();
    let got = p.rt.block_on(props.get(&prop.id)).unwrap();
    assert!(got.approved.is_some(), "{got:?}");

    // The switch is committed, the proposal's metadata is not.
    let kinds = prop.kind_versions().unwrap();
    let (epoch, lsn) =
        p.rt.block_on(p.node.switch_code(
            kronik_sched::CodeSwitch {
                kinds,
                pinned: vec![],
                cause: pb::DeploymentCause::Promote,
                verified_through_lsn: prop.verified_through_lsn,
                unverified_inputs: 0,
                proposal_id: prop.id.clone(),
                rollback_of_epoch: 0,
            },
            audit(),
            false,
        ))
        .unwrap();
    let err =
        p.rt.block_on(props.promote(&prop.id, audit(), false))
            .unwrap_err();
    assert!(err.message.contains("already promoted"), "{err}");
    let got = p.rt.block_on(props.get(&prop.id)).unwrap();
    assert_eq!(got.status, "promoted");
    let promoted = got.promoted.unwrap();
    assert_eq!((promoted.epoch, promoted.lsn), (epoch, lsn));
    assert_eq!(last_deployment(&p).0, lsn, "promoted once");
}

/// A proposal job held at its first isolated root input by the test gate.
fn held_job(
    p: &Proc,
    dir: &std::path::Path,
) -> (Arc<Proposals>, Arc<tokio::sync::Semaphore>, String) {
    for _ in 0..3 {
        p.http("a", "increment", "");
    }
    p.settle();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.to_path_buf())
            .unwrap()
            .with_test_gate(gate.clone()),
    );
    let (running, dry) =
        p.rt.block_on(props.propose_job(
            ProposeRequest {
                wasm: vec![std::fs::read(guest("counter-step2")).unwrap()],
                names: Vec::new(),
                window_ms: None,
                at: None,
                options: DiffOptions::default(),
                workers: Some(2),
                audit: audit(),
                dry_run: false,
            },
            false,
        ))
        .unwrap();
    assert!(!dry);
    assert_eq!(running.status, "running");
    (props, gate, running.id)
}

/// Lets the held job run and waits until it is done.
fn finish(props: &Proposals, gate: &tokio::sync::Semaphore, id: &str) {
    gate.add_permits(1000);
    for _ in 0..6000 {
        if props.progress(id).is_none() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the job of {id} did not finish");
}

/// Review M4 and L7: what needs a finished proposal answers
/// PROPOSAL_RUNNING while its job runs, `send` into its fork included.
#[test]
fn a_running_proposal_refuses_send_approve_request_approval_and_diff() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let (props, gate, id) = held_job(&p, dir.path());
    let msg = || pb::Message {
        name: "increment".into(),
        content_type: "text/plain".into(),
        body: plain(""),
        blobs: vec![],
    };
    let actor = || kronik_core::ids::ActorRef::parse("counter/a").unwrap();
    let running = ErrorCode::ProposalRunning;
    let r = p.rt.block_on(props.fork_send(&id, actor(), msg()));
    assert_eq!(r.unwrap_err().code, running);
    let r = p.rt.block_on(props.approve(&id, audit(), false));
    assert_eq!(r.unwrap_err().code, running);
    let r = p.rt.block_on(props.request_approval(&id, audit(), false));
    assert_eq!(r.unwrap_err().code, running);
    let r = p.rt.block_on(props.diff(&id, false, false));
    assert_eq!(r.unwrap_err().code, running);
    let r = p.rt.block_on(props.promote(&id, audit(), false));
    assert_eq!(r.unwrap_err().code, running);
    assert!(props.progress(&id).is_some());

    finish(&props, &gate, &id);
    assert_eq!(p.rt.block_on(props.get(&id)).unwrap().status, "evaluated");
    p.rt.block_on(props.diff(&id, false, false)).unwrap();
    p.rt.block_on(props.fork_send(&id, actor(), msg())).unwrap();
}

/// Review L7: a job does not survive the daemon. A proposal still
/// `running` on disk is `failed` when the proposals load again, and what
/// needs a finished proposal refuses it.
#[test]
fn a_proposal_running_at_a_restart_is_failed_and_refused() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let (props, gate, id) = held_job(&p, dir.path());
    let again = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    let failed = p.rt.block_on(again.get(&id)).unwrap();
    assert_eq!(failed.status, "failed");
    let e = failed.error.expect("the failure is recorded");
    assert_eq!(e.code, ErrorCode::Unavailable);
    assert!(e.message.contains("the daemon restarted"), "{e}");
    for err in [
        p.rt.block_on(again.approve(&id, audit(), false))
            .unwrap_err(),
        p.rt.block_on(again.promote(&id, audit(), false))
            .unwrap_err(),
    ] {
        assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
        assert!(err.message.contains("the daemon restarted"), "{err}");
    }
    // The file says so too.
    let file = dir.path().join("branches").join(&id).join("proposal.json");
    let on_disk = std::fs::read_to_string(file).unwrap();
    assert!(on_disk.contains("\"failed\""), "{on_disk}");
    finish(&props, &gate, &id);
}

/// Review L7: a job whose replay fails (here the proposal's directory is a
/// file by the time the replay writes its log) leaves the proposal
/// `failed` with the error, ends the job, and what needs a finished
/// proposal refuses it.
#[test]
fn a_job_that_fails_leaves_the_proposal_failed() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let (props, gate, id) = held_job(&p, dir.path());
    let branch = dir.path().join("branches").join(&id);
    std::fs::remove_dir_all(&branch).unwrap();
    std::fs::write(&branch, "not a directory").unwrap();
    finish(&props, &gate, &id);
    let failed = p.rt.block_on(props.get(&id)).unwrap();
    assert_eq!(failed.status, "failed");
    assert!(failed.error.is_some(), "{failed:?}");
    let e =
        p.rt.block_on(props.promote(&id, audit(), false))
            .unwrap_err();
    assert_eq!(e.code, ErrorCode::BadRequest, "{e}");
}
