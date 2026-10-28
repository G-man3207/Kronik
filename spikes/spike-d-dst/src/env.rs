//! The I/O boundary of the daemon: every source of time, disk, network,
//! concurrency, entropy and child processes goes through these traits, each
//! with a real (tokio/std) and a simulated implementation.
//!
//! Rules (see ADR 0004):
//! - Daemon code receives an [`Env`] explicitly; there are no globals or
//!   thread-locals, so several simulated nodes can share one process.
//! - Everything that waits is `async`; everything that only reads a value
//!   (`Clock::wall_ms`, `EntropySource::fill`) is synchronous.
//! - Traits are object-safe and used as `Arc<dyn _>`: one boxed future per I/O
//!   operation is negligible next to the I/O itself, and it keeps the daemon
//!   free of a generic parameter that would infect every type and double
//!   compile times.
//! - All futures are `Send + 'static` so the same code runs on tokio's
//!   multi-threaded runtime and on the single-threaded simulator.
//! - Lift target: `kronik-core::env` (traits and helpers, no tokio runtime
//!   dependency).

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Time. The wall clock may jump in either direction (NTP, VM migration,
/// operator error); the monotonic clock never decreases.
pub trait Clock: Send + Sync + 'static {
    /// Host wall-clock time in milliseconds since the Unix epoch. Only used as
    /// one input to logical time (I15); never trusted to be monotonic.
    fn wall_ms(&self) -> u64;
    /// Time since an arbitrary origin; never decreases. For timeouts, windows
    /// and latency measurement.
    fn monotonic(&self) -> Duration;
    /// Completes once `monotonic()` has advanced by at least `d`.
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()>;
}

/// Spawning concurrent work. Tasks are detached; results travel through
/// channels (see [`Env::spawn`]). In the simulator a node's tasks are dropped
/// together when the node crashes.
pub trait Spawner: Send + Sync + 'static {
    fn spawn(&self, name: &'static str, fut: BoxFuture<'static, ()>);
    /// Runs blocking, CPU- or syscall-bound work (SQLite, compilation) off the
    /// async workers. The simulator runs it inline as one step.
    fn spawn_blocking(&self, name: &'static str, f: Box<dyn FnOnce() + Send + 'static>);
}

/// Randomness that is *not* guest-visible by construction but feeds seeds,
/// execution ids and tokens. Real: the OS CSPRNG. Simulated: the run seed.
pub trait EntropySource: Send + Sync + 'static {
    fn fill(&self, buf: &mut [u8]);
}

/// How a file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Read only; the file must exist.
    Read,
    /// Read and write; created if missing (creation is durable only after
    /// `Fs::sync_dir` of the parent).
    ReadWriteCreate,
}

/// File system. Writes are durable only after `File::sync_data` (contents)
/// and `Fs::sync_dir` (creation, rename, removal). The simulator drops or
/// tears anything not synced when a node crashes.
pub trait Fs: Send + Sync + 'static {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>>;
    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>>;
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>>;
    /// File names (not paths) in `dir`, sorted.
    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>>;
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>>;
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>>;
    /// Makes creations, renames and removals inside `dir` durable.
    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<()>>;
}

/// An open file. Buffers are owned (`Bytes`/`Vec<u8>`) so real
/// implementations can hand them to a blocking thread.
#[allow(clippy::len_without_is_empty)] // async length of an open file
pub trait File: Send + Sync + 'static {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>>;
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>>;
    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, io::Result<()>>;
    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>>;
    /// `fdatasync`. An error is fatal for the caller: after a failed fsync the
    /// page-cache state is unknown and must never be retried (fsyncgate).
    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>>;
}

/// An outbound HTTP request at the effect boundary (`http.fetch`,
/// `foreign://`). Secrets are already inserted by the effect layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Why a request failed. The distinction matters for I17: only `Connect`
/// proves the request never left the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// The request was definitely not sent (DNS, connection refused).
    Connect(String),
    /// The request may have been delivered; the outcome is unknown.
    Io(String),
}

/// Outbound network at the HTTP level. Inbound HTTP is not part of `Net`: the
/// gateway's service function is called directly in simulation and bound to a
/// hyper listener in production.
pub trait Net: Send + Sync + 'static {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>>;
}

/// A child process (`runsc`, later Firecracker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
}

pub trait Process: Send + Sync + 'static {
    fn id(&self) -> Option<u32>;
    /// Exit code, or `None` when killed by a signal.
    fn wait(&self) -> BoxFuture<'static, io::Result<Option<i32>>>;
    fn kill(&self) -> BoxFuture<'static, io::Result<()>>;
}

pub trait ProcessRunner: Send + Sync + 'static {
    fn spawn(&self, spec: ProcessSpec) -> BoxFuture<'static, io::Result<Arc<dyn Process>>>;
}

/// The bundle handed to every daemon component. Cheap to clone.
#[derive(Clone)]
pub struct Env {
    pub clock: Arc<dyn Clock>,
    pub spawner: Arc<dyn Spawner>,
    pub entropy: Arc<dyn EntropySource>,
    pub fs: Arc<dyn Fs>,
    pub net: Arc<dyn Net>,
    pub procs: Arc<dyn ProcessRunner>,
}

/// Completes with the task's output; dropping it does not cancel the task.
pub struct JoinHandle<T>(tokio::sync::oneshot::Receiver<T>);

impl<T> Future for JoinHandle<T> {
    /// `None` if the task was dropped before finishing (e.g. node crash).
    type Output = Option<T>;
    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(Result::ok)
    }
}

/// The timeout fired before the future completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl Env {
    pub fn spawn<T, F>(&self, name: &'static str, fut: F) -> JoinHandle<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.spawner.spawn(
            name,
            Box::pin(async move {
                let _ = tx.send(fut.await);
            }),
        );
        JoinHandle(rx)
    }

    pub fn blocking<T, F>(&self, name: &'static str, f: F) -> JoinHandle<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.spawner.spawn_blocking(
            name,
            Box::new(move || {
                let _ = tx.send(f());
            }),
        );
        JoinHandle(rx)
    }

    /// Races `fut` against `Clock::sleep(d)`; the future wins ties, so the
    /// result never depends on poll order.
    pub async fn timeout<T, F>(&self, d: Duration, fut: F) -> Result<T, Elapsed>
    where
        F: Future<Output = T> + Send,
    {
        let sleep = self.clock.sleep(d);
        tokio::select! {
            biased;
            v = fut => Ok(v),
            () = sleep => Err(Elapsed),
        }
    }

    pub fn random_bytes<const N: usize>(&self) -> [u8; N] {
        let mut b = [0u8; N];
        self.entropy.fill(&mut b);
        b
    }
}
