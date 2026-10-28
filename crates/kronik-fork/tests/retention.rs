//! The retention window (docs/design/m6-storage.md §5): forks, replay and
//! proposals may only start within `retention.history` of the newest
//! record's logical time.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{Proc, audit, guest, tempdir};
use kronik_core::env::Env;
use kronik_core::error::ErrorCode;
use kronik_core::ids::Lsn;
use kronik_fork::diff::DiffOptions;
use kronik_fork::proposal::{Proposals, ProposeRequest};
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{NodeConfig, start_local};

fn start(dir: &Path, history: Option<Duration>, segment: Option<u64>) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let mut storage = StorageConfig::new(dir.to_path_buf());
        if let Some(h) = history {
            storage.history = h;
        }
        start_local(
            env,
            dir,
            NodeConfig {
                concurrency: 8,
                storage: Some(storage),
                segment_max_bytes: segment,
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    Proc { rt, node }
}

fn deploy(p: &Proc) {
    let bytes = std::fs::read(guest("counter")).unwrap();
    p.rt.block_on(p.node.deploy(&bytes, audit(), false))
        .unwrap();
}

fn first_turn(p: &Proc) -> Lsn {
    let mut found = None;
    let head = p.node.applied_lsn();
    p.rt.block_on(p.node.reader().read(1, head, |c| {
        if found.is_none() && matches!(c.record, kronik_proto::Record::TurnRecord(_)) {
            found = Some(c.lsn);
        }
        Ok(())
    }))
    .unwrap();
    found.expect("a turn")
}

fn branch_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.join("branches"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Two turns whose logical times differ, without sleeping: a restart sets
/// the logical clock to the recovered high-water mark plus 1 ms, so the
/// second turn is strictly later even in the same wall millisecond.
fn two_turns(dir: &Path, history: Option<Duration>) -> (Proc, Lsn) {
    let p = start(dir, history, None);
    deploy(&p);
    p.send("counter/a", "increment", "");
    let early = first_turn(&p);
    drop(p);
    let p = start(dir, history, None);
    p.send("counter/b", "increment", "");
    let hwm = p.node.store().db().time_hwm().unwrap();
    let early_time =
        p.rt.block_on(p.node.logical_time_at(early))
            .unwrap()
            .expect("the early turn");
    assert!(
        early_time < hwm,
        "early logical time {early_time} is not before the high-water mark {hwm}"
    );
    (p, early)
}

fn open_props(p: &Proc, dir: &Path) -> Proposals {
    Proposals::open(p.node.clone(), dir.to_path_buf()).unwrap()
}

#[test]
fn zero_history_refuses_an_early_fork_and_accepts_head() {
    let dir = tempdir();
    let (p, early) = two_turns(dir.path(), Some(Duration::ZERO));
    let props = open_props(&p, dir.path());
    let before = branch_names(dir.path());

    let dry =
        p.rt.block_on(props.create_fork(Some("early".into()), early, false, audit(), true));
    let err = dry.unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("outside retention"), "{err}");
    assert!(err.message.contains(&early.to_string()), "{err}");
    assert!(err.message.contains("cutoff"), "{err}");
    assert!(err.message.contains("0ms"), "{err}");
    assert!(
        err.hint
            .as_deref()
            .is_some_and(|h| h.contains("kronik integrity")),
        "{err:?}"
    );
    assert_eq!(branch_names(dir.path()), before, "dry-run wrote a fork");

    let again =
        p.rt.block_on(props.create_fork(Some("early".into()), early, false, audit(), false))
            .unwrap_err();
    assert!(again.message.contains("outside retention"), "{again}");
    assert_eq!(branch_names(dir.path()), before);

    let head = p.node.applied_lsn();
    let (made, dry_run) =
        p.rt.block_on(props.create_fork(Some("head".into()), head, false, audit(), false))
            .unwrap();
    assert!(!dry_run);
    assert_eq!(made.fork_lsn, head);
    assert!(dir.path().join("branches/head/proposal.json").is_file());
}

#[test]
fn zero_history_refuses_a_point_before_the_first_turn() {
    let dir = tempdir();
    let (p, early) = two_turns(dir.path(), Some(Duration::ZERO));
    assert!(early > 0, "the first turn has no preceding LSN");
    let before_first = early - 1;
    let props = open_props(&p, dir.path());
    let names = branch_names(dir.path());
    let err = p
        .rt
        .block_on(props.create_fork(Some("before".into()), before_first, false, audit(), false))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
    assert!(err.message.contains("outside retention"), "{err}");
    assert!(err.message.contains(&before_first.to_string()), "{err}");
    assert!(err.message.contains("cutoff"), "{err}");
    assert_eq!(branch_names(dir.path()), names, "create wrote a fork");
}

#[test]
fn propose_refuses_an_early_point_without_writing() {
    let dir = tempdir();
    let (p, early) = two_turns(dir.path(), Some(Duration::ZERO));
    let props = open_props(&p, dir.path());
    let wasm = std::fs::read(guest("counter-step2")).unwrap();
    let err =
        p.rt.block_on(props.propose(ProposeRequest {
            wasm: vec![wasm],
            names: Vec::new(),
            window_ms: None,
            at: Some(early),
            options: DiffOptions::default(),
            workers: Some(2),
            audit: audit(),
            dry_run: true,
        }))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("outside retention"), "{err}");
    assert!(err.message.contains(&early.to_string()), "{err}");
    assert!(
        !branch_names(dir.path()).iter().any(|n| n.starts_with("p-")),
        "propose wrote a proposal directory"
    );
}

#[test]
fn promote_is_stale_when_the_window_shrinks() {
    let dir = tempdir();
    // Default history (7 days): the early point is still inside.
    let (p, early) = two_turns(dir.path(), None);
    let props = open_props(&p, dir.path());
    let wasm = std::fs::read(guest("counter-step2")).unwrap();
    let (prop, _) =
        p.rt.block_on(props.propose(ProposeRequest {
            wasm: vec![wasm],
            names: Vec::new(),
            window_ms: None,
            at: Some(early),
            options: DiffOptions::default(),
            workers: Some(2),
            audit: audit(),
            dry_run: false,
        }))
        .unwrap();
    let id = prop.id.clone();
    let deployments = p.node.store().db().deployments().unwrap().len();
    drop(props);
    drop(p);

    let p = start(dir.path(), Some(Duration::ZERO), None);
    let props = open_props(&p, dir.path());
    let err =
        p.rt.block_on(props.promote(&id, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
    assert!(err.message.contains("outside retention"), "{err}");
    assert!(err.message.contains(&early.to_string()), "{err}");
    assert!(err.message.contains("cutoff"), "{err}");
    assert!(
        err.hint
            .as_deref()
            .is_some_and(|h| h.contains("kronik propose") && h.contains("--window 1h")),
        "{err:?}"
    );
    let saved = p.rt.block_on(props.get(&id)).unwrap();
    assert_eq!(saved.status, "stale");
    let file = std::fs::read_to_string(dir.path().join("branches").join(&id).join("proposal.json"))
        .unwrap();
    assert!(file.contains("\"status\": \"stale\""), "{file}");
    assert_eq!(
        p.node.store().db().deployments().unwrap().len(),
        deployments,
        "promote wrote a deployment"
    );
}

#[test]
fn promote_dry_run_of_an_aged_proposal_does_not_mark_it_stale() {
    let dir = tempdir();
    let (p, early) = two_turns(dir.path(), None);
    let props = open_props(&p, dir.path());
    let wasm = std::fs::read(guest("counter-step2")).unwrap();
    let (prop, _) =
        p.rt.block_on(props.propose(ProposeRequest {
            wasm: vec![wasm],
            names: Vec::new(),
            window_ms: None,
            at: Some(early),
            options: DiffOptions::default(),
            workers: Some(2),
            audit: audit(),
            dry_run: false,
        }))
        .unwrap();
    let id = prop.id.clone();
    let status = prop.status.clone();
    assert_ne!(status, "stale");
    drop(props);
    drop(p);

    let p = start(dir.path(), Some(Duration::ZERO), None);
    let props = open_props(&p, dir.path());
    let path = dir.path().join("branches").join(&id).join("proposal.json");
    let before = std::fs::read(&path).unwrap();
    let err =
        p.rt.block_on(props.promote(&id, audit(), true))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
    assert!(err.message.contains("outside retention"), "{err}");
    let saved = p.rt.block_on(props.get(&id)).unwrap();
    assert_eq!(saved.status, status);
    assert_ne!(saved.status, "stale");
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn replay_refuses_after_the_window_shrinks() {
    let dir = tempdir();
    let (p, early) = two_turns(dir.path(), None);
    let props = open_props(&p, dir.path());
    p.rt.block_on(props.create_fork(Some("try".into()), early, false, audit(), false))
        .unwrap();
    drop(props);
    drop(p);

    let p = start(dir.path(), Some(Duration::ZERO), None);
    let props = open_props(&p, dir.path());
    let err =
        p.rt.block_on(props.fork_replay("try", None, DiffOptions::default(), Some(2)))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
    assert!(err.message.contains("outside retention"), "{err}");
    assert!(err.message.contains(&early.to_string()), "{err}");
}

#[test]
fn fork_create_refuses_a_point_the_log_no_longer_covers() {
    let dir = tempdir();
    let log_dir = dir.path().join("branches/main/log");
    let p = start(dir.path(), Some(Duration::ZERO), Some(4096));
    deploy(&p);
    for i in 0..80 {
        p.send(&format!("counter/k{}", i % 5), "increment", "");
    }
    let before = kronik_log::segment_starts(&log_dir).unwrap();
    assert!(before.len() > 3, "{before:?}");
    let _ = p.rt.block_on(p.node.snapshot("manual")).unwrap();
    let after = kronik_log::segment_starts(&log_dir).unwrap();
    assert!(
        after[0] > 1,
        "compaction did not delete a segment: {after:?}"
    );
    drop(p);

    // A huge history makes the time window pass (cutoff 0). The refusal
    // is then the physical gap: the log no longer reaches LSN 1.
    let p = start(
        dir.path(),
        Some(Duration::from_millis(u64::MAX)),
        Some(4096),
    );
    let props = open_props(&p, dir.path());
    let err =
        p.rt.block_on(props.create_fork(Some("gone".into()), 1, false, audit(), false))
            .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
    assert!(err.message.contains("outside retention"), "{err}");
    assert!(
        !dir.path().join("branches/gone").exists(),
        "create wrote a fork the log does not cover"
    );
}

fn propose_window(p: &Proc, props: &Proposals) -> kronik_fork::proposal::Proposal {
    let wasm = std::fs::read(guest("counter-step2")).unwrap();
    p.rt.block_on(props.propose(ProposeRequest {
        wasm: vec![wasm],
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

/// The quickstart walk on a young node (v0.1 gap): the first deployment
/// sits alone in segment 1, with no turn time. A graceful stop (the
/// shutdown snapshot compacts) must not delete it as older than 7 days: the
/// next proposal replays the whole hour and a fork at LSN 3 is allowed.
#[test]
fn a_young_nodes_first_deployment_survives_its_first_restart() {
    let dir = tempdir();
    let log_dir = dir.path().join("branches/main/log");
    // Every batch in a segment of its own, like the walk's segment 1.
    let p = start(dir.path(), None, Some(1));
    deploy(&p);
    for i in 0..12 {
        p.send(&format!("counter/k{}", i % 3), "increment", "");
    }
    assert_eq!(kronik_log::segment_starts(&log_dir).unwrap()[0], 1);
    p.rt.block_on(p.node.shutdown_snapshot())
        .unwrap()
        .expect("a shutdown snapshot");
    drop(p);
    let p = start(dir.path(), None, Some(1));
    assert_eq!(
        kronik_log::segment_starts(&log_dir).unwrap()[0],
        1,
        "retention deleted the first deployment's segment"
    );
    let props = open_props(&p, dir.path());
    let prop = propose_window(&p, &props);
    assert_eq!(prop.summary["root_inputs"], 12, "{}", prop.summary);
    assert!(prop.warnings().is_empty(), "{:?}", prop.warnings());
    let (fork, _) =
        p.rt.block_on(props.create_fork(Some("at3".into()), 3, false, audit(), false))
            .unwrap();
    assert_eq!(fork.fork_lsn, 3);
}

/// When retention really cut a proposal's window, the proposal says so
/// (`warnings`, and `base.window_cut` in the diff) instead of silently
/// replaying less.
#[test]
fn a_window_cut_by_retention_is_reported() {
    let dir = tempdir();
    let log_dir = dir.path().join("branches/main/log");
    // A 2 s history: the turns before the 3 s pause fall out of it, the
    // proposal's 1 h window still asks for them.
    let p = start(dir.path(), Some(Duration::from_secs(2)), Some(1));
    deploy(&p);
    for i in 0..5 {
        p.send(&format!("counter/k{i}"), "increment", "");
    }
    std::thread::sleep(Duration::from_secs(3));
    p.send("counter/k5", "increment", "");
    let snap = p.rt.block_on(p.node.snapshot("manual")).unwrap();
    assert!(
        kronik_log::segment_starts(&log_dir).unwrap()[0] > 1,
        "nothing was compacted"
    );
    p.send("counter/late", "increment", "");
    let props = open_props(&p, dir.path());
    let prop = propose_window(&p, &props);
    assert_eq!(prop.summary["root_inputs"], 1, "{}", prop.summary);
    let cut = prop.window_cut.clone().expect("the cut is recorded");
    assert_eq!((cut.window_ms, cut.kept_from_lsn), (3_600_000, snap.lsn));
    let warnings = prop.warnings();
    assert!(
        warnings.len() == 1 && warnings[0].contains("retention cut the window"),
        "{warnings:?}"
    );
    let diff: serde_json::Value =
        serde_json::from_slice(&p.rt.block_on(props.diff(&prop.id, false, false)).unwrap())
            .unwrap();
    assert_eq!(
        diff["base"]["window_cut"]["kept_from_lsn"], snap.lsn,
        "{}",
        diff["base"]
    );
    let md = String::from_utf8(p.rt.block_on(props.diff(&prop.id, true, false)).unwrap()).unwrap();
    assert!(md.contains("Window cut by retention"), "{md}");
}
