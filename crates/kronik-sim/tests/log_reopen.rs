//! A log opened after its previous process died without a power loss.
//!
//! A process that is killed (SIGKILL, out of memory) between a write and
//! its fsync leaves the written bytes in the page cache: the next process
//! reads them as the log. If it builds on them before they are durable (it
//! replays a record, or rolls past a footer), a later power loss takes back
//! a record it trusted, or tears the footer of a segment that is no longer
//! the last, which no open truncates and every read refuses. The log's open
//! fsyncs what the last process left before it builds on it.
//!
//! Each case kills the first process right after a write and before its
//! fsync, opens the log again in a second process, then loses power, and
//! checks the log in a third process, for the crash outcomes of 32 seeds.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::{Clock, Env};
use kronik_core::ids::Lsn;
use kronik_log::{Log, LogConfig, LogReader};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sim::exec::{Executor, Handle, NodeId, RunEnd};
use kronik_sim::fs::{CrashModel, Disk, DiskFaults, SimFs};
use kronik_sim::{SimClock, SimEntropy, SimNoNet, SimProcs, SimRng, SimSpawner};
use tokio::sync::{mpsc, oneshot};

const SEEDS: u64 = 32;

struct Sim {
    seed: u64,
    exec: Executor,
    handle: Handle,
    disk: Arc<Mutex<Disk>>,
    cfg: LogConfig,
}

impl Sim {
    fn new(seed: u64, segment_max_bytes: u64) -> Sim {
        let exec = Executor::new(seed);
        let handle = exec.handle();
        let mut cfg = LogConfig::new(PathBuf::from("/log"), "main");
        cfg.group_commit_window = Duration::ZERO;
        cfg.segment_max_bytes = segment_max_bytes;
        Sim {
            seed,
            exec,
            handle,
            disk: Arc::new(Mutex::new(Disk::default())),
            cfg,
        }
    }

    /// The environment of process `node` on the shared disk.
    fn env(&self, node: NodeId) -> Env {
        let clock: Arc<dyn Clock> = Arc::new(SimClock {
            exec: self.handle.clone(),
            wall_base_ms: 1_700_000_000_000,
            wall_offset_ms: Arc::new(AtomicI64::new(0)),
        });
        Env {
            clock: clock.clone(),
            spawner: Arc::new(SimSpawner {
                exec: self.handle.clone(),
                node,
            }),
            entropy: Arc::new(SimEntropy(SimRng::new(self.seed, b"entropy"))),
            fs: Arc::new(SimFs::new(
                self.disk.clone(),
                clock.clone(),
                SimRng::new(self.seed, b"fs"),
                DiskFaults {
                    crash_model: CrashModel::PrefixTorn,
                    fsync_error: 0.0,
                },
            )),
            net: Arc::new(SimNoNet),
            procs: Arc::new(SimProcs { clock }),
        }
    }

    /// Runs `f` as a task of process `node` until it is done.
    fn run<T: Send + 'static>(
        &self,
        node: NodeId,
        f: impl Future<Output = T> + Send + 'static,
    ) -> T {
        let out = Arc::new(Mutex::new(None));
        let o = out.clone();
        self.handle.spawn(
            node,
            "step",
            Box::pin(async move {
                let v = f.await;
                *o.lock().unwrap() = Some(v);
            }),
        );
        let end = self.exec.run(50_000_000, || out.lock().unwrap().is_some());
        assert_eq!(end, RunEnd::Stopped, "seed {}", self.seed);
        out.lock().unwrap().take().unwrap()
    }

    /// Opens the log in process `node`.
    fn open(&self, node: NodeId) -> (Log, Lsn) {
        let env = self.env(node);
        let cfg = self.cfg.clone();
        self.run(node, async move {
            let (tx, rx) = mpsc::unbounded_channel();
            // The applier: what it is sent is dropped.
            std::mem::forget(rx);
            let (ftx, frx) = oneshot::channel();
            std::mem::forget(frx);
            let (log, opened) = Log::open(&env, cfg, tx, ftx).await.unwrap();
            (log, opened.next_lsn)
        })
    }

    fn append(&self, node: NodeId, log: &Log) {
        let log = log.clone();
        self.run(node, async move { log.append(record()).await.unwrap() });
    }

    /// Process `node` appends, and dies after the write of the append that
    /// `pending` waits for and before its fsync: the bytes stay in the page
    /// cache, the power stays on.
    fn die_with_unsynced(&self, node: NodeId, log: &Log, segment: &Path) {
        let log = log.clone();
        self.handle.spawn(
            node,
            "append",
            Box::pin(async move {
                let _ = log.append(record()).await;
            }),
        );
        let disk = self.disk.clone();
        let segment = segment.to_path_buf();
        let end = self
            .exec
            .run(50_000_000, || disk.lock().unwrap().has_unsynced(&segment));
        assert_eq!(
            end,
            RunEnd::Stopped,
            "seed {}: no unsynced write",
            self.seed
        );
        self.handle.kill_node(node);
    }

    /// Process `node` opens a fresh log and dies after the first segment's
    /// header is fsynced and before its directory is: the segment is a name
    /// in the page cache only.
    fn die_before_the_directory_sync(&self, node: NodeId) {
        let env = self.env(node);
        let cfg = self.cfg.clone();
        self.handle.spawn(
            node,
            "open",
            Box::pin(async move {
                let (tx, rx) = mpsc::unbounded_channel();
                std::mem::forget(rx);
                let (ftx, frx) = oneshot::channel();
                std::mem::forget(frx);
                let _ = Log::open(&env, cfg, tx, ftx).await;
            }),
        );
        let disk = self.disk.clone();
        let first = segment(1);
        let end = self.exec.run(50_000_000, || {
            let d = disk.lock().unwrap();
            d.is_named(&first)
                && d.synced_len(&first) > 0
                && !d.has_unsynced(&first)
                && !d.is_durably_named(&first)
        });
        assert_eq!(
            end,
            RunEnd::Stopped,
            "seed {}: no undurable name",
            self.seed
        );
        self.handle.kill_node(node);
    }

    /// Power fails: what was not fsynced is lost, kept or torn.
    fn power_loss(&self, node: NodeId) {
        self.handle.kill_node(node);
        self.disk
            .lock()
            .unwrap()
            .crash(CrashModel::PrefixTorn, &SimRng::new(self.seed, b"power"));
    }

    /// Every record of the log, read in process `node`.
    fn read(&self, node: NodeId) -> Result<Vec<Lsn>, String> {
        let env = self.env(node);
        let dir = self.cfg.dir.clone();
        self.run(node, async move {
            let mut lsns = Vec::new();
            LogReader::new(env, dir, "main")
                .read(1, Lsn::MAX, |c| {
                    lsns.push(c.lsn);
                    Ok(())
                })
                .await
                .map_err(|e| e.to_string())?;
            Ok(lsns)
        })
    }
}

fn record() -> Record {
    Record::Policy(pb::Policy::default())
}

fn segment(n: Lsn) -> PathBuf {
    PathBuf::from("/log").join(kronik_log::segment_name(n))
}

/// The first process dies after it wrote a record and before its fsync. The
/// next one trusts that record (its next LSN is past it): a power loss must
/// not take it back.
#[test]
fn a_record_the_next_process_trusts_survives_a_power_loss() {
    for seed in 0..SEEDS {
        let sim = Sim::new(seed, 64 << 20);
        let (log, _) = sim.open(1);
        sim.append(1, &log);
        sim.die_with_unsynced(1, &log, &segment(1));
        let (_log, trusted) = sim.open(2);
        assert_eq!(
            trusted, 3,
            "seed {seed}: the second process reads both records"
        );
        sim.power_loss(2);
        let (_log, next) = sim.open(3);
        assert_eq!(
            next, trusted,
            "seed {seed}: the power loss took back a record the second process trusted"
        );
        assert_eq!(sim.read(3), Ok(vec![1, 2]), "seed {seed}");
    }
}

/// The first process dies after it wrote the footer that closes a segment
/// and before its fsync. The next one rolls past the footer to a new
/// segment: a power loss must not tear the footer of a segment that is no
/// longer the last.
#[test]
fn a_footer_the_next_process_rolled_past_survives_a_power_loss() {
    for seed in 0..SEEDS {
        // Every append after the first rolls to a new segment.
        let sim = Sim::new(seed, 1);
        let (log, _) = sim.open(1);
        sim.append(1, &log);
        sim.die_with_unsynced(1, &log, &segment(1));
        let (log, next) = sim.open(2);
        assert_eq!(
            next, 2,
            "seed {seed}: the second process starts a new segment"
        );
        sim.append(2, &log);
        sim.power_loss(2);
        let _ = sim.open(3);
        assert_eq!(sim.read(3), Ok(vec![1, 2]), "seed {seed}");
    }
}

/// The first process dies after it created the first segment (its header
/// fsynced) and before it synced the directory. The next one opens that
/// segment and appends to it: a power loss must not take the segment, and
/// with it every record, away.
#[test]
fn a_segment_the_next_process_appends_to_survives_a_power_loss() {
    for seed in 0..SEEDS {
        let sim = Sim::new(seed, 64 << 20);
        sim.die_before_the_directory_sync(1);
        let (log, next) = sim.open(2);
        assert_eq!(next, 1, "seed {seed}");
        sim.append(2, &log);
        sim.append(2, &log);
        sim.power_loss(2);
        let _ = sim.open(3);
        assert_eq!(
            sim.read(3),
            Ok(vec![1, 2]),
            "seed {seed}: the power loss took the segment the second process appended to"
        );
    }
}
