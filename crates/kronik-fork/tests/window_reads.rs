//! A short window must not decode the retained log, and a timestamp fork
//! must not read segments older than the one that contains the time (#197).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Proc, audit, guest, tempdir};
use kronik_core::env::{BoxFuture, Clock, File, Fs, OpenMode};
use kronik_core::ids::Lsn;
use kronik_fork::ProductionIndex;
use kronik_fork::diff::DiffOptions;
use kronik_fork::proposal::{Proposals, ProposeRequest};
use kronik_sched::NodeConfig;
use kronik_sched::snapshots::StorageConfig;

struct ShiftedClock {
    inner: Arc<dyn Clock>,
    offset_ms: Arc<AtomicU64>,
}

impl Clock for ShiftedClock {
    fn wall_ms(&self) -> u64 {
        self.inner
            .wall_ms()
            .saturating_add(self.offset_ms.load(Ordering::SeqCst))
    }
    fn monotonic(&self) -> Duration {
        self.inner.monotonic()
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        self.inner.sleep(d)
    }
}

struct CountFs {
    inner: Arc<dyn Fs>,
    hits: Arc<Mutex<Vec<u64>>>,
    armed: Arc<AtomicBool>,
}

impl Fs for CountFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        let inner = self.inner.clone();
        Box::pin(async move { inner.create_dir_all(path).await })
    }
    fn open(
        &self,
        path: PathBuf,
        mode: OpenMode,
    ) -> BoxFuture<'static, std::io::Result<Arc<dyn File>>> {
        if self.armed.load(Ordering::SeqCst)
            && path
                .parent()
                .is_some_and(|dir| dir.ends_with("branches/main/log"))
            && let Some(start) = seg_start(&path)
        {
            self.hits.lock().unwrap().push(start);
        }
        let inner = self.inner.clone();
        Box::pin(async move { inner.open(path, mode).await })
    }
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<bool>> {
        let inner = self.inner.clone();
        Box::pin(async move { inner.exists(path).await })
    }
    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, std::io::Result<Vec<String>>> {
        let inner = self.inner.clone();
        Box::pin(async move { inner.read_dir(dir).await })
    }
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        let inner = self.inner.clone();
        Box::pin(async move { inner.rename(from, to).await })
    }
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        let inner = self.inner.clone();
        Box::pin(async move { inner.remove_file(path).await })
    }
    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        let inner = self.inner.clone();
        Box::pin(async move { inner.sync_dir(dir).await })
    }
}

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
            env.fs = Arc::new(CountFs {
                inner: env.fs.clone(),
                hits,
                armed,
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
