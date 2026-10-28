//! Simulated implementations of the `Env` traits plus the deterministic
//! executor. Lift target: `kronik-sim`.

pub mod exec;
pub mod fs;
pub mod net;

use std::io;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chacha20::ChaCha8Rng;
use chacha20::rand_core::{Rng, SeedableRng};

use crate::env::{BoxFuture, Clock, EntropySource, Process, ProcessRunner, ProcessSpec, Spawner};
use exec::{Handle, NodeId};

/// The run's single source of simulated randomness (faults, latencies,
/// workload, entropy). Draw order is deterministic because the executor is.
#[derive(Clone)]
pub struct SimRng(Arc<Mutex<ChaCha8Rng>>);

impl SimRng {
    pub fn new(seed: u64, domain: &[u8]) -> Self {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        let n = domain.len().min(24);
        s[8..8 + n].copy_from_slice(&domain[..n]);
        Self(Arc::new(Mutex::new(ChaCha8Rng::from_seed(s))))
    }
    fn with<T>(&self, f: impl FnOnce(&mut ChaCha8Rng) -> T) -> T {
        f(&mut self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
    pub fn u64(&self) -> u64 {
        self.with(|r| r.next_u64())
    }
    /// Uniform in `0..n` (0 when `n == 0`).
    pub fn below(&self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.u64() % n }
    }
    pub fn chance(&self, p: f64) -> bool {
        p > 0.0 && (self.u64() >> 11) as f64 / (1u64 << 53) as f64 <= p
    }
    pub fn fill(&self, buf: &mut [u8]) {
        self.with(|r| r.fill_bytes(buf));
    }
    /// Uniform duration in `[lo, hi]`.
    pub fn duration(&self, lo: Duration, hi: Duration) -> Duration {
        let span = (hi - lo).as_micros() as u64;
        lo + Duration::from_micros(self.below(span + 1))
    }
}

/// Virtual time from the executor; the wall clock is virtual time plus a
/// fault-injected offset that can jump backwards.
#[derive(Clone)]
pub struct SimClock {
    pub exec: Handle,
    pub wall_base_ms: u64,
    pub wall_offset_ms: Arc<AtomicI64>,
}

impl Clock for SimClock {
    fn wall_ms(&self) -> u64 {
        let v = self.wall_base_ms as i64
            + self.exec.now().as_millis() as i64
            + self.wall_offset_ms.load(Ordering::Relaxed);
        v.max(0) as u64
    }
    fn monotonic(&self) -> Duration {
        self.exec.now()
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        self.exec.sleep(d)
    }
}

/// Spawns onto one node of the executor.
pub struct SimSpawner {
    pub exec: Handle,
    pub node: NodeId,
}

impl Spawner for SimSpawner {
    fn spawn(&self, name: &'static str, fut: BoxFuture<'static, ()>) {
        self.exec.spawn(self.node, name, fut);
    }
    fn spawn_blocking(&self, name: &'static str, f: Box<dyn FnOnce() + Send + 'static>) {
        self.exec
            .spawn(self.node, name, Box::pin(async move { f() }));
    }
}

pub struct SimEntropy(pub SimRng);

impl EntropySource for SimEntropy {
    fn fill(&self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

/// Simulated processes: `spawn` succeeds and the process "runs" until killed.
/// Enough for the trait shape; M7 adds scripted behaviour for `runsc`.
pub struct SimProcs {
    pub clock: Arc<dyn Clock>,
}

struct SimProcess {
    killed: Arc<tokio::sync::Notify>,
}

impl Process for SimProcess {
    fn id(&self) -> Option<u32> {
        None
    }
    fn wait(&self) -> BoxFuture<'static, io::Result<Option<i32>>> {
        let killed = self.killed.clone();
        Box::pin(async move {
            killed.notified().await;
            Ok(None)
        })
    }
    fn kill(&self) -> BoxFuture<'static, io::Result<()>> {
        self.killed.notify_waiters();
        Box::pin(async { Ok(()) })
    }
}

impl ProcessRunner for SimProcs {
    fn spawn(&self, _spec: ProcessSpec) -> BoxFuture<'static, io::Result<Arc<dyn Process>>> {
        let sleep = self.clock.sleep(Duration::from_millis(5));
        Box::pin(async move {
            sleep.await;
            Ok(Arc::new(SimProcess {
                killed: Arc::new(tokio::sync::Notify::new()),
            }) as Arc<dyn Process>)
        })
    }
}

/// Ordered, hashed event trace: the determinism fingerprint of a run.
pub struct Trace {
    hasher: blake3::Hasher,
    pub events: u64,
    recent: std::collections::VecDeque<String>,
}

impl Default for Trace {
    fn default() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            events: 0,
            recent: std::collections::VecDeque::new(),
        }
    }
}

impl Trace {
    pub fn push(&mut self, at: Duration, line: String) {
        let entry = format!("{:>12} {line}", at.as_micros());
        self.hasher.update(entry.as_bytes());
        self.hasher.update(b"\n");
        self.events += 1;
        if self.recent.len() == 64 {
            self.recent.pop_front();
        }
        self.recent.push_back(entry);
    }
    pub fn hash(&self) -> String {
        self.hasher.finalize().to_hex()[..16].to_string()
    }
    pub fn recent(&self) -> Vec<String> {
        self.recent.iter().cloned().collect()
    }
}
