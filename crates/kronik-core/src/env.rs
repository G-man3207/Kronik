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
//! - This module depends on tokio's `sync` and `macros` features only; the
//!   production implementations live in [`real`] (feature `real`).

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

#[cfg(feature = "real")]
pub mod real;

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
    /// Deterministic PKCS#1 SHA-256 signature; RSA's internal blinding uses
    /// OS entropy only in the production environment, never in providers.
    fn sign_rs256(&self, _pkcs8: &[u8], _message: &[u8]) -> Result<Vec<u8>, String> {
        Err("RSA signing is not supported by this environment".into())
    }
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
    /// Bytes an unprivileged writer may still use on the file system that
    /// holds `path`. The simulator and test file systems have no limit.
    fn available(&self, _path: PathBuf) -> BoxFuture<'static, io::Result<u64>> {
        Box::pin(async { Ok(u64::MAX) })
    }
    /// Read a singly linked regular file owned by the effective user, with no
    /// group/world permissions. Recheck identity and contents after reading.
    fn read_secure(
        &self,
        _path: PathBuf,
        _max_bytes: usize,
    ) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure file reads are not supported",
            ))
        })
    }
    /// Atomically replace a 0600 file beneath a private owned parent and sync
    /// file and directory. Only a missing immediate 0700 parent may be created.
    fn write_secure(&self, _path: PathBuf, bytes: Vec<u8>) -> BoxFuture<'static, io::Result<()>> {
        drop(zeroize::Zeroizing::new(bytes));
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure file writes are not supported",
            ))
        })
    }
    /// As write_secure, but an existing destination must never be replaced.
    fn write_secure_new(
        &self,
        _path: PathBuf,
        _bytes: Bytes,
    ) -> BoxFuture<'static, io::Result<()>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "exclusive secure file writes are not supported",
            ))
        })
    }
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
    /// A response body above this size fails with `NetError::TooLarge`.
    pub max_response_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// A body read in chunks (M25, docs/design/m25-streaming-bodies.md §7.1):
/// a request body streamed to the peer, or a response body read as it
/// arrives, without holding it whole.
pub trait BodySource: Send + 'static {
    /// The next chunk; `None` at the end.
    fn next(&mut self) -> BoxFuture<'_, std::io::Result<Option<Bytes>>>;
}

/// A body held whole, as one chunk.
pub struct BytesSource(Option<Bytes>);

impl BytesSource {
    pub fn new(bytes: Bytes) -> BytesSource {
        BytesSource(Some(bytes).filter(|b| !b.is_empty()))
    }
}

impl BodySource for BytesSource {
    fn next(&mut self) -> BoxFuture<'_, std::io::Result<Option<Bytes>>> {
        let chunk = self.0.take();
        Box::pin(async move { Ok(chunk) })
    }
}

/// The body of a streaming request.
pub enum HttpBody {
    Bytes(Bytes),
    /// `len` bytes from `source`, sent with that `content-length`.
    Stream {
        len: u64,
        source: Box<dyn BodySource>,
    },
}

/// An outbound HTTP request whose body may be streamed and whose response
/// is read in chunks ([`Net::http_stream_authorized`]).
pub struct HttpStreamRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: HttpBody,
    /// Reading more response bytes than this fails with
    /// [`response_too_large`].
    pub max_response_bytes: u64,
}

/// A response whose body is read as it arrives.
pub struct HttpStreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn BodySource>,
}

/// The error a streamed response body gives past its request's
/// `max_response_bytes` ([`is_response_too_large`]).
#[derive(Debug)]
pub struct ResponseTooLarge;

impl std::fmt::Display for ResponseTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the response body exceeds its limit")
    }
}

impl std::error::Error for ResponseTooLarge {}

/// The I/O error of a response body read past its limit.
pub fn response_too_large() -> std::io::Error {
    std::io::Error::other(ResponseTooLarge)
}

/// Whether `error` is [`response_too_large`].
pub fn is_response_too_large(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<ResponseTooLarge>())
}

/// An outbound bounded WebSocket handshake; redirects are never followed.
#[derive(Clone, PartialEq, Eq)]
pub struct WebSocketRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub max_message_bytes: usize,
}

/// A bounded full-duplex socket. Peer close is sticky across subsequent recv.
pub trait WebSocket: Send + Sync {
    fn recv(&self) -> BoxFuture<'static, Result<Option<Bytes>, NetError>>;
    fn send(&self, message: Bytes) -> BoxFuture<'static, Result<(), NetError>>;
    fn close(&self) -> BoxFuture<'static, Result<(), NetError>>;
}

/// Why a request failed. The distinction matters for I17: only `Connect`
/// proves the request never left the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// The request was definitely not sent (DNS, connection refused).
    Connect(String),
    /// The request may have been delivered; the outcome is unknown.
    Io(String),
    /// The response body exceeded `max_response_bytes`.
    TooLarge,
}

/// Node-local TLS for a provider client. Never installed on the guest's
/// effect client; certificate chains and the PKCS#8 key are DER.
pub struct TlsConfig {
    pub ca: Vec<Vec<u8>>,
    pub identity: Option<(Vec<Vec<u8>>, Vec<u8>)>,
}

impl std::fmt::Debug for TlsConfig {
    /// Structural metadata only: certificate and key bytes never reach a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ca = format!("[redacted] {} certificate(s)", self.ca.len());
        let identity = self.identity.as_ref().map(|(chain, _key)| {
            format!(
                "[redacted] {} certificate(s) and a private key",
                chain.len()
            )
        });
        f.debug_struct("TlsConfig")
            .field("ca", &ca)
            .field("identity", &identity)
            .finish()
    }
}

/// Outbound network at the HTTP level. Inbound HTTP is not part of `Net`: the
/// gateway's service function is called directly in simulation and bound to a
/// hyper listener in production.
pub trait Net: Send + Sync + 'static {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>>;
    /// Recheck the SAME original authority at the actual synchronous request
    /// enqueue, after connection/capacity waits; retain it through response EOF.
    /// Implementations must not admit construction of a lazy HTTP future.
    fn http_authorized(
        &self,
        req: HttpRequest,
        original: crate::authority::AuthLease,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>>;
    /// [`Net::http_authorized`] with a body that may be streamed and a
    /// response read as it arrives (M25). The default buffers: it sends a
    /// whole body through `http_authorized` and gives the response as one
    /// chunk; a streamed request body is refused before anything is sent.
    fn http_stream_authorized(
        &self,
        req: HttpStreamRequest,
        original: crate::authority::AuthLease,
    ) -> BoxFuture<'static, Result<HttpStreamResponse, NetError>> {
        let body = match req.body {
            HttpBody::Bytes(bytes) => bytes,
            HttpBody::Stream { .. } => {
                return Box::pin(std::future::ready(Err(NetError::Connect(
                    "this network does not stream request bodies".into(),
                ))));
            }
        };
        let sent = self.http_authorized(
            HttpRequest {
                method: req.method,
                url: req.url,
                headers: req.headers,
                body,
                max_response_bytes: req.max_response_bytes,
            },
            original,
        );
        Box::pin(async move {
            let response = sent.await?;
            Ok(HttpStreamResponse {
                status: response.status,
                headers: response.headers,
                body: Box::new(BytesSource::new(response.body)),
            })
        })
    }
    /// Builds a separate provider client; simulated networks may implement
    /// this without changing their deterministic request boundary.
    /// Supplied roots augment the system roots; this never changes guest trust.
    fn with_tls(&self, _tls: TlsConfig) -> Result<Arc<dyn Net>, NetError> {
        Err(NetError::Connect(
            "TLS configuration is not supported".into(),
        ))
    }
    /// A separate provider client trusting only the supplied CA certificates.
    fn with_pinned_tls(&self, _tls: TlsConfig) -> Result<Arc<dyn Net>, NetError> {
        Err(NetError::Connect(
            "pinned TLS configuration is not supported".into(),
        ))
    }
    fn websocket(
        &self,
        _request: WebSocketRequest,
    ) -> BoxFuture<'static, Result<Arc<dyn WebSocket>, NetError>> {
        Box::pin(async {
            Err(NetError::Connect(
                "WebSocket connections are not supported".into(),
            ))
        })
    }
}

/// An ordinary child process (`runsc`, later Firecracker). Its stdin is
/// `/dev/null`, and it never gets the daemon's own stdout or stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    pub stdout: Stdio,
    pub stderr: Stdio,
}

/// Where a child's output goes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Stdio {
    #[default]
    Null,
    /// Appended to this file, created with mode 0600 if missing.
    Append(PathBuf),
    /// Through a pipe the daemon reads: appended to `path` (mode 0600),
    /// which is moved to `<path>.1` whenever it would grow past
    /// `max_bytes`, so the output takes at most twice that on disk. When
    /// stdout and stderr name the same file they share one pipe.
    Log { path: PathBuf, max_bytes: u64 },
}

pub trait Process: Send + Sync + 'static {
    fn id(&self) -> Option<u32>;
    /// Exit code, or `None` when killed by a signal.
    fn wait(&self) -> BoxFuture<'static, io::Result<Option<i32>>>;
    fn kill(&self) -> BoxFuture<'static, io::Result<()>>;
}

/// One private helper operation. Never put sensitive bytes in `spec`:
/// argv/environment are explicit configuration, not secret transports.
/// Both streams are bounded to 4096 bytes; `spec.stdout/stderr` are ignored.
/// The trusted, private regular PIN file is opened read-only and mapped to fd3.
/// Ownership is the effective caller or current-namespace root, not an
/// initial-host-root identity assertion. Group/other access and execute bits
/// are rejected. Standard streams remain private regardless of `spec`.
pub struct SensitiveProcessRequest {
    pub spec: ProcessSpec,
    pub stdin: zeroize::Zeroizing<Vec<u8>>,
    pub pin_file: PathBuf,
    pub timeout: Duration,
}

pub trait ProcessRunner: Send + Sync + 'static {
    fn spawn(&self, spec: ProcessSpec) -> BoxFuture<'static, io::Result<Arc<dyn Process>>>;
    /// Send one bounded request followed by EOF, discard stderr, and return
    /// bounded stdout only after successful exit and reap. Dropping the future
    /// cancels the operation; the supervisor still kills and reaps the child.
    /// Response parsing stays with the caller; keep its zeroizing ownership
    /// when rejecting malformed protocol bytes.
    /// Linux uses an owned process group, killed before the leader's final
    /// reap. Descendants deliberately escaping that group are not sandboxed.
    /// Other platforms return `Unsupported`; ordinary spawning is unchanged.
    fn exchange(
        &self,
        request: SensitiveProcessRequest,
    ) -> BoxFuture<'static, io::Result<zeroize::Zeroizing<Vec<u8>>>>;
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

#[cfg(test)]
mod stream_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// A network that only buffers, as test and simulated networks do.
    struct Buffered;

    impl Net for Buffered {
        fn http(&self, _req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
            Box::pin(async { Err(NetError::Connect("unused".into())) })
        }
        fn http_authorized(
            &self,
            req: HttpRequest,
            _original: crate::authority::AuthLease,
        ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
            Box::pin(async move {
                Ok(HttpResponse {
                    status: 201,
                    headers: vec![("x".into(), "y".into())],
                    body: Bytes::from(format!("{} {} bytes", req.method, req.body.len())),
                })
            })
        }
    }

    struct Open;

    impl crate::authority::Authority for Open {
        fn check(&self) -> Result<(), crate::error::ApiError> {
            Ok(())
        }
        fn cancelled(&self) -> BoxFuture<'static, ()> {
            Box::pin(std::future::pending())
        }
        fn admit(
            &self,
            effect: &mut dyn FnMut() -> Result<(), crate::error::ApiError>,
        ) -> Result<(), crate::error::ApiError> {
            effect()
        }
    }

    fn request(body: HttpBody) -> HttpStreamRequest {
        HttpStreamRequest {
            method: "PUT".into(),
            url: "http://example.test/".into(),
            headers: Vec::new(),
            body,
            max_response_bytes: 1 << 20,
        }
    }

    /// The default `http_stream_authorized` buffers: a whole body goes
    /// through `http_authorized` and the response comes as one chunk; a
    /// streamed body is refused as not sent.
    #[tokio::test(flavor = "current_thread")]
    async fn the_default_buffers_and_refuses_streamed_bodies() {
        let mut response = Buffered
            .http_stream_authorized(
                request(HttpBody::Bytes(Bytes::from_static(b"abc"))),
                Arc::new(Open),
            )
            .await
            .unwrap();
        assert_eq!((response.status, response.headers.len()), (201, 1));
        assert_eq!(
            response.body.next().await.unwrap(),
            Some(Bytes::from_static(b"PUT 3 bytes"))
        );
        assert_eq!(response.body.next().await.unwrap(), None);
        let streamed = Buffered
            .http_stream_authorized(
                request(HttpBody::Stream {
                    len: 1,
                    source: Box::new(BytesSource::new(Bytes::from_static(b"a"))),
                }),
                Arc::new(Open),
            )
            .await;
        assert!(matches!(streamed, Err(NetError::Connect(_))));
        assert!(is_response_too_large(&response_too_large()));
        assert!(!is_response_too_large(&std::io::Error::other("other")));
    }
}
