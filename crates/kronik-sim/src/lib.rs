//! Deterministic simulation testing (ADR 0004): a seeded single-threaded
//! executor with virtual time, simulated implementations of the `Env`
//! traits (disk with power-failure semantics, clock with backward jumps,
//! seeded entropy), and scenarios that run the real daemon crates under
//! crashes and faults.
//!
//! Re-run a failing seed with `cargo test -p kronik-sim --release --test dst
//! -- --seed N`.

pub mod bao;
pub mod exec;
pub mod fs;
pub mod scenario;
pub mod service;

#[cfg(test)]
mod process_tests;

use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chacha20::ChaCha8Rng;
use chacha20::rand_core::{Rng, SeedableRng};
use kronik_core::env::{
    BoxFuture, Clock, EntropySource, Process, ProcessRunner, ProcessSpec, SensitiveProcessRequest,
    Spawner,
};

use exec::{Handle, NodeId};

/// A seeded random stream. Draw order is deterministic because the executor
/// is.
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
        let span = hi.saturating_sub(lo).as_micros() as u64;
        lo + Duration::from_micros(self.below(span + 1))
    }
}

/// Virtual time from the executor; the wall clock is virtual time plus an
/// offset that fault injection moves, backwards too.
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

/// Simulated processes: `spawn` succeeds and the process runs until killed.
pub struct SimProcs {
    pub clock: Arc<dyn Clock>,
}

struct SimProcess {
    // The DST harness's kill signal: the watch is the harness's own
    // mechanism, not daemon code (ADR-0004 governs the daemon).
    #[allow(clippy::disallowed_types)]
    killed: tokio::sync::watch::Sender<bool>,
    reaped: Arc<AtomicBool>,
}

impl SimProcess {
    fn new() -> Self {
        Self {
            killed: tokio::sync::watch::channel(false).0,
            reaped: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Process for SimProcess {
    fn id(&self) -> Option<u32> {
        None
    }

    fn wait(&self) -> BoxFuture<'static, io::Result<Option<i32>>> {
        let mut killed = self.killed.subscribe();
        let reaped = self.reaped.clone();
        Box::pin(async move {
            drop(
                killed
                    .wait_for(|value| *value)
                    .await
                    .map_err(io::Error::other)?,
            );
            reaped.store(true, Ordering::SeqCst);
            Ok(None)
        })
    }

    fn kill(&self) -> BoxFuture<'static, io::Result<()>> {
        self.killed.send_replace(true);
        Box::pin(async { Ok(()) })
    }
}

impl ProcessRunner for SimProcs {
    fn spawn(&self, _spec: ProcessSpec) -> BoxFuture<'static, io::Result<Arc<dyn Process>>> {
        let sleep = self.clock.sleep(Duration::from_millis(5));
        Box::pin(async move {
            sleep.await;
            Ok(Arc::new(SimProcess::new()) as Arc<dyn Process>)
        })
    }

    fn exchange(
        &self,
        request: SensitiveProcessRequest,
    ) -> BoxFuture<'static, io::Result<zeroize::Zeroizing<Vec<u8>>>> {
        sensitive_exchange(self.clock.clone(), request, Arc::new(SimProcess::new()))
    }
}

// Like ordinary simulated children, this helper runs until killed. No fake
// cryptography: its only completion is the caller's virtual-time deadline.
fn sensitive_exchange(
    clock: Arc<dyn Clock>,
    request: SensitiveProcessRequest,
    process: Arc<SimProcess>,
) -> BoxFuture<'static, io::Result<zeroize::Zeroizing<Vec<u8>>>> {
    struct Reap(Arc<SimProcess>);
    impl Drop for Reap {
        fn drop(&mut self) {
            self.0.killed.send_replace(true);
            self.0.reaped.store(true, Ordering::SeqCst);
        }
    }
    Box::pin(async move {
        if request.stdin.is_empty()
            || request.stdin.len() > 4096
            || request.timeout.is_zero()
            || clock.monotonic().checked_add(request.timeout).is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid sensitive helper bounds",
            ));
        }
        let _reap = Reap(process);
        let timeout = request.timeout;
        // The model never consumes plaintext; erase it before advancing time.
        drop(request);
        clock.sleep(timeout).await;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "sensitive helper timed out",
        ))
    })
}

/// Ordered, hashed event trace: the determinism fingerprint of a run.
#[derive(Default)]
pub struct Trace {
    hasher: blake3::Hasher,
    pub events: u64,
    recent: std::collections::VecDeque<String>,
}

impl Trace {
    /// `KRONIK_DST_TRACE=1` also prints every line as it is traced, for a
    /// seed whose last lines do not tell enough.
    // The harness reports on its standard streams.
    #[allow(clippy::print_stderr)]
    pub fn push(&mut self, at: Duration, line: String) {
        static PRINT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let entry = format!("{:>12} {line}", at.as_micros());
        if *PRINT.get_or_init(|| std::env::var_os("KRONIK_DST_TRACE").is_some_and(|v| v == "1")) {
            eprintln!("trace {entry}");
        }
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

#[cfg(test)]
mod trace_tests {
    use std::time::Duration;

    use super::Trace;

    /// A derived `Default` must hash the same lines as the hand-written one:
    /// `blake3::Hasher::default` is `Hasher::new`, and the counters start empty.
    #[test]
    fn a_new_trace_hashes_the_same_lines_as_a_fresh_hasher() {
        let mut trace = Trace::default();
        assert_eq!(trace.events, 0);
        assert!(trace.recent().is_empty());
        assert_eq!(
            trace.hash(),
            blake3::Hasher::new().finalize().to_hex()[..16].to_string()
        );

        trace.push(Duration::from_micros(12), "node started".to_string());
        trace.push(Duration::from_millis(3), "drain quiet".to_string());
        let mut hasher = blake3::Hasher::new();
        for line in trace.recent() {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        assert_eq!(trace.events, 2);
        assert_eq!(trace.hash(), hasher.finalize().to_hex()[..16].to_string());
    }
}
