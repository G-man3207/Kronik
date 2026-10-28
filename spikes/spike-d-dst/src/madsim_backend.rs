//! The same scenario on madsim's deterministic runtime. Only compiled with
//! `RUSTFLAGS="--cfg madsim"`.
//!
//! madsim provides the executor, virtual time and node kill/restart. Its
//! file system has no power-failure model (`FsSim::power_fail` is a TODO in
//! 0.2.34) and its network is socket-level, so the scenario's own `SimFs`
//! and `SimNet` are used unchanged on top of madsim's clock.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use madsim::runtime::{Handle, Runtime};

use crate::env::{BoxFuture, Clock, Spawner};
use crate::scenario::{Backend, DAEMON, Report, ScenarioConfig, World};
use crate::sim::exec::{NodeId, RunEnd, SUPERVISOR};
use crate::wasm;

static POLLS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

/// Counts polls so that madsim and the own executor report the same metric.
struct Counted(BoxFuture<'static, ()>);

impl Future for Counted {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        POLLS.fetch_add(1, Ordering::Relaxed);
        self.0.as_mut().poll(cx)
    }
}

struct MadsimClock {
    start: madsim::time::Instant,
    wall_base_ms: u64,
    wall_offset_ms: Arc<AtomicI64>,
}

impl Clock for MadsimClock {
    fn wall_ms(&self) -> u64 {
        let v = self.wall_base_ms as i64
            + self.monotonic().as_millis() as i64
            + self.wall_offset_ms.load(Ordering::Relaxed);
        v.max(0) as u64
    }
    fn monotonic(&self) -> Duration {
        madsim::time::Instant::now() - self.start
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        Box::pin(madsim::time::sleep(d))
    }
}

struct MadsimSpawner {
    handle: Handle,
    node: madsim::task::NodeId,
}

impl Spawner for MadsimSpawner {
    fn spawn(&self, _name: &'static str, fut: BoxFuture<'static, ()>) {
        if let Some(n) = self.handle.get_node(self.node) {
            drop(n.spawn(Counted(fut)));
        }
    }
    fn spawn_blocking(&self, name: &'static str, f: Box<dyn FnOnce() + Send + 'static>) {
        self.spawn(name, Box::pin(async move { f() }));
    }
}

struct MadsimBackend {
    handle: Handle,
    nodes: BTreeMap<NodeId, madsim::task::NodeId>,
    clock: Arc<MadsimClock>,
}

impl Backend for MadsimBackend {
    fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }
    fn spawner(&self, node: NodeId) -> Arc<dyn Spawner> {
        Arc::new(MadsimSpawner {
            handle: self.handle.clone(),
            node: self.nodes[&node],
        })
    }
    fn kill(&self, node: NodeId) {
        // `restart` kills every task of the old incarnation (lazily: a killed
        // task's future is dropped when it is next scheduled) and leaves a
        // fresh, empty node to spawn on.
        self.handle.restart(self.nodes[&node]);
    }
    fn name(&self) -> &'static str {
        "madsim"
    }
    fn wall_offset(&self) -> Arc<AtomicI64> {
        self.clock.wall_offset_ms.clone()
    }
}

pub fn run_madsim(seed: u64, cfg: ScenarioConfig) -> Report {
    // Compile outside the simulation: madsim refuses to create OS threads
    // (Cranelift's parallel compilation) inside its context.
    let code = wasm::code();
    drop(code);
    POLLS.store(0, Ordering::Relaxed);
    let started = Instant::now();
    let rt = Runtime::with_seed_and_config(seed, madsim::Config::default());
    let mut report = rt.block_on(async move {
        let handle = Handle::current();
        let sup = handle.create_node().name("supervisor").build();
        let dmn = handle.create_node().name("daemon").build();
        let clock = Arc::new(MadsimClock {
            start: madsim::time::Instant::now(),
            wall_base_ms: 1_761_300_000_000,
            wall_offset_ms: Arc::new(AtomicI64::new(0)),
        });
        let mut nodes = BTreeMap::new();
        nodes.insert(SUPERVISOR, sup.id());
        nodes.insert(DAEMON, dmn.id());
        let backend = Arc::new(MadsimBackend {
            handle: handle.clone(),
            nodes,
            clock,
        });
        let world = World::new(seed, cfg, backend.clone());
        let w = world.clone();
        let main = sup.spawn(Counted(Box::pin(async move { w.main().await })));
        let _ = main.await;
        backend.kill(DAEMON);
        world.finish(
            RunEnd::Stopped,
            POLLS.load(Ordering::Relaxed),
            Duration::ZERO,
        )
    });
    // Inside madsim, `std::time::Instant::now()` is intercepted (libc
    // `clock_gettime`) and returns simulated time: measure outside.
    report.wall_time = started.elapsed();
    report
}

/// Same workload as `scenario::exec_bench_own`, on madsim.
pub fn exec_bench_madsim(seed: u64, tasks: usize, iters: usize) -> (u64, Duration) {
    POLLS.store(0, Ordering::Relaxed);
    let started = Instant::now();
    let rt = Runtime::with_seed_and_config(seed, madsim::Config::default());
    rt.block_on(async move {
        let rng = crate::sim::SimRng::new(seed, b"bench");
        let counter = Arc::new(tokio::sync::Mutex::new(0u64));
        let mut joins = Vec::new();
        for _ in 0..tasks {
            let rng = rng.clone();
            let counter = counter.clone();
            joins.push(madsim::task::spawn(Counted(Box::pin(async move {
                for _ in 0..iters {
                    madsim::time::sleep(Duration::from_micros(rng.below(100))).await;
                    *counter.lock().await += 1;
                }
            }))));
        }
        for j in joins {
            let _ = j.await;
        }
    });
    (POLLS.load(Ordering::Relaxed), started.elapsed())
}
