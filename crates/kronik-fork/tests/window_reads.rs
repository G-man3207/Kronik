//! A short window must not decode the retained log, and a timestamp fork
//! must not read segments older than the one that contains the time (#197).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use common::{Proc, ShiftedClock, audit, guest, tempdir};
use kronik_core::env::test_fs::{FsCall, Then, hooked};
use kronik_core::ids::Lsn;
use kronik_fork::ProductionIndex;
use kronik_fork::diff::DiffOptions;
use kronik_fork::proposal::{Proposals, ProposeRequest};
use kronik_sched::NodeConfig;
use kronik_sched::snapshots::StorageConfig;

fn seg_start(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    name.strip_suffix(".seg")?.parse().ok()
}

fn start(
    dir: &Path,
    offset: Arc<AtomicU64>,
    hits: Arc<Mutex<Vec<u64>>>,
    armed: Arc<AtomicBool>,
) -> Proc {
    Proc::start_env(
        dir,
        NodeConfig {
            concurrency: 8,
            storage: Some(StorageConfig::new(dir.to_path_buf())),
            segment_max_bytes: Some(1),
            ..NodeConfig::default()
        },
        move |env| {
            let clock = Arc::new(ShiftedClock {
                inner: env.clock.clone(),
                offset_ms: offset,
            });
            env.clock = clock;
            // Real files, with the starts of the main log segments opened
            // while `armed` recorded in `hits`.
            env.fs = hooked(env.fs.clone(), move |call| {
                if let FsCall::Open(path, _) = call
                    && armed.load(Ordering::SeqCst)
                    && path
                        .parent()
                        .is_some_and(|dir| dir.ends_with("branches/main/log"))
                    && let Some(start) = seg_start(path)
                {
                    hits.lock().unwrap().push(start);
                }
                Then::Forward
            });
        },
    )
}

#[test]
fn the_index_is_not_reserved_for_the_lsn_span() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.http("a", "increment", "");
    p.settle();
    let index =
        p.rt.block_on(ProductionIndex::load_from(
            p.node.reader(),
            None,
            0,
            1_000_000,
        ))
        .unwrap();
    assert!(index.records.len() < 100, "len {}", index.records.len());
    assert!(
        index.records.capacity() < 10_000,
        "reserved the LSN span: capacity {}",
        index.records.capacity()
    );
}

#[test]
fn a_default_propose_does_not_read_the_retained_span() {
    let dir = tempdir();
    let offset = Arc::new(AtomicU64::new(0));
    let hits = Arc::new(Mutex::new(Vec::new()));
    let armed = Arc::new(AtomicBool::new(false));
    let p = start(dir.path(), offset.clone(), hits.clone(), armed.clone());
    let log = dir.path().join("branches/main/log");
    p.http("old", "increment", "");
    for i in 0..6 {
        p.http(&format!("old{i}"), "increment", "");
    }
    p.settle();
    p.rt.block_on(p.node.snapshot("manual", p.owner())).unwrap();
    let old = kronik_log::segment_starts(&log).unwrap();
    assert!(
        old.len() > 4,
        "expected one segment per record, got {old:?}"
    );

    offset.store(3 * 3_600_000, Ordering::SeqCst);
    p.http("new", "increment", "");
    p.settle();

    hits.lock().unwrap().clear();
    armed.store(true, Ordering::SeqCst);
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let wasm = std::fs::read(guest("counter-step2")).unwrap();
    let prop =
        p.rt.block_on(props.propose(
            ProposeRequest {
                wasm: vec![wasm],
                names: Vec::new(),
                window_ms: None,
                at: None,
                options: DiffOptions::default(),
                workers: Some(1),
                audit: audit(),
                dry_run: false,
            },
            p.owner(),
        ))
        .unwrap()
        .0;
    armed.store(false, Ordering::SeqCst);
    assert!(
        prop.summary["root_inputs"].as_u64().unwrap_or(0) >= 1,
        "{}",
        prop.summary
    );
    let read = hits.lock().unwrap().clone();
    let distinct: std::collections::BTreeSet<u64> = read.iter().copied().collect();
    let old_read = old.iter().filter(|start| distinct.contains(start)).count();
    assert!(
        !distinct.contains(&old[0]),
        "propose read the retained log from its first segment: {distinct:?}"
    );
    assert!(
        old_read * 2 < old.len(),
        "propose read {old_read} of {} retained segments ({distinct:?}), not the window",
        old.len()
    );
}

#[test]
fn a_timestamp_fork_does_not_read_older_segments() {
    let dir = tempdir();
    let offset = Arc::new(AtomicU64::new(0));
    let hits = Arc::new(Mutex::new(Vec::new()));
    let armed = Arc::new(AtomicBool::new(false));
    let p = start(dir.path(), offset.clone(), hits.clone(), armed.clone());
    let mut marks = Vec::new();
    for i in 0..5 {
        offset.store(i * 5_000, Ordering::SeqCst);
        p.http(&format!("k{i}"), "increment", "");
        p.settle();
        let segs = p.node.store().db().segments().unwrap();
        let (start, _, time) = *segs.last().unwrap();
        marks.push((start, time));
    }
    let target = marks[2].1;
    let older: Vec<Lsn> = marks.iter().take(2).map(|(start, _)| *start).collect();
    hits.lock().unwrap().clear();
    armed.store(true, Ordering::SeqCst);
    let head = p.node.applied_lsn();
    let segments = p.node.store().db().segments().unwrap();
    let found =
        p.rt.block_on(kronik_fork::window::last_lsn_at_or_before(
            p.node.reader(),
            &segments,
            head,
            target,
        ))
        .unwrap();
    armed.store(false, Ordering::SeqCst);
    assert!(found > 0, "no turn at or before {target}");
    let read = hits.lock().unwrap().clone();
    for start in &older {
        assert!(
            !read.contains(start),
            "timestamp fork read segment {start} older than the one at {target}; read {read:?}"
        );
    }
}

/// A closed configuration segment keeps the previous turn's mark. A time
/// between that turn and the next must still select the earlier turn (#217).
#[test]
fn a_timestamp_between_turns_uses_the_earlier_turn_across_a_config_segment() {
    let dir = tempdir();
    let offset = Arc::new(AtomicU64::new(0));
    let hits = Arc::new(Mutex::new(Vec::new()));
    let armed = Arc::new(AtomicBool::new(false));
    let p = start(dir.path(), offset.clone(), hits, armed);
    p.http("early", "increment", "");
    p.settle();
    p.grant("http:example.com");
    offset.store(60_000, Ordering::SeqCst);
    p.http("late", "increment", "");
    p.settle();

    let head = p.node.applied_lsn();
    let mut turns = Vec::new();
    let mut turn_segments = std::collections::BTreeSet::new();
    p.rt.block_on(p.node.reader().read(1, head, |c| {
        let is_turn = matches!(
            c.record,
            kronik_proto::Record::TurnBegin(_) | kronik_proto::Record::TurnRecord(_)
        );
        if is_turn {
            turn_segments.insert(c.pos.segment);
        }
        if let kronik_proto::Record::TurnRecord(t) = &c.record {
            turns.push((c.pos.segment, c.lsn, t.logical_time_ms));
        }
        Ok(())
    }))
    .unwrap();
    assert!(turns.len() >= 2, "need two turns, got {turns:?}");
    let early_time = turns[0].2;
    let late_time = turns.last().unwrap().2;
    assert!(
        early_time > 0 && late_time > early_time + 1,
        "times {early_time} then {late_time} leave no point between or before them"
    );
    let between = early_time + 1;
    let (early_seg, early_lsn, _) = turns
        .iter()
        .copied()
        .filter(|(_, _, time)| *time <= between)
        .max_by_key(|(_, lsn, _)| *lsn)
        .unwrap();
    let late_lsn = turns.last().unwrap().1;
    let late_seg = turns
        .iter()
        .filter(|(_, _, time)| *time > between)
        .map(|(seg, _, _)| *seg)
        .min()
        .unwrap();

    let segments = p.node.store().db().segments().unwrap();
    let Some(guess_at) = segments.iter().position(|(_, _, time)| *time > between) else {
        panic!("no segment mark past {between}: {segments:?}");
    };
    assert!(
        guess_at > 0,
        "the later mark is the first segment; no config gap: {segments:?}"
    );
    let (guess_start, _, guess_time) = segments[guess_at - 1];
    assert!(
        !turn_segments.contains(&guess_start)
            && guess_start > early_seg
            && guess_start < late_seg
            && guess_time <= early_time,
        "segment {guess_start} at {guess_time} is not a config-only gap between {early_seg} and {late_seg}; segments {segments:?}"
    );

    let at = |ms| {
        let segments = p.node.store().db().segments().unwrap();
        p.rt.block_on(kronik_fork::window::last_lsn_at_or_before(
            p.node.reader(),
            &segments,
            head,
            ms,
        ))
        .unwrap()
    };
    assert_eq!(
        at(between),
        early_lsn,
        "a time between the turns must use the earlier turn, not LSN 0"
    );
    assert_eq!(at(early_time - 1), 0, "a time before every turn is LSN 0");
    assert_eq!(
        at(late_time + 1),
        late_lsn,
        "a time after the latest turn uses that turn"
    );
}
