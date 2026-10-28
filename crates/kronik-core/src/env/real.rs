//! Production implementations of the `Env` traits on tokio and std.
//!
//! Threading model: daemon tasks run on tokio's multi-threaded runtime.
//! Every blocking syscall (file I/O, `fdatasync`, directory sync) runs on
//! tokio's blocking pool via `spawn_blocking`, so an fsync never stalls an
//! async worker. The log writer is one task, so its writes and fsyncs are
//! naturally serialized. Enabled by feature `real` (the `kronik` binary and
//! integration tests).
//
// The production Env is where ambient time, entropy and tokio live.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::runtime::Handle;

use crate::env::{
    BoxFuture, Clock, EntropySource, File, Fs, HttpRequest, HttpResponse, Net, NetError, OpenMode,
    Process, ProcessRunner, ProcessSpec, Spawner,
};

pub struct RealClock {
    origin: tokio::time::Instant,
}

impl Default for RealClock {
    fn default() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
        }
    }
}

impl Clock for RealClock {
    fn wall_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
    fn monotonic(&self) -> Duration {
        self.origin.elapsed()
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(d))
    }
}

pub struct RealSpawner(pub Handle);

impl Spawner for RealSpawner {
    fn spawn(&self, _name: &'static str, fut: BoxFuture<'static, ()>) {
        self.0.spawn(fut);
    }
    fn spawn_blocking(&self, _name: &'static str, f: Box<dyn FnOnce() + Send + 'static>) {
        self.0.spawn_blocking(f);
    }
}

pub struct RealEntropy;

impl EntropySource for RealEntropy {
    fn fill(&self, buf: &mut [u8]) {
        // The OS CSPRNG failing is unrecoverable for seeds and ids.
        if let Err(e) = getrandom::fill(buf) {
            panic!("OS entropy unavailable: {e}");
        }
    }
}

pub struct RealFs(pub Handle);

fn blocking<T: Send + 'static>(
    h: &Handle,
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> BoxFuture<'static, io::Result<T>> {
    let task = h.spawn_blocking(f);
    Box::pin(async move { task.await.map_err(io::Error::other)? })
}

impl Fs for RealFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        blocking(&self.0, move || std::fs::create_dir_all(path))
    }
    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        let h = self.0.clone();
        blocking(&self.0, move || {
            let f = match mode {
                OpenMode::Read => std::fs::File::open(path)?,
                OpenMode::ReadWriteCreate => std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path)?,
            };
            Ok(Arc::new(RealFile { f: Arc::new(f), h }) as Arc<dyn File>)
        })
    }
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        blocking(&self.0, move || path.try_exists())
    }
    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        blocking(&self.0, move || {
            let mut v = Vec::new();
            for e in std::fs::read_dir(dir)? {
                v.push(e?.file_name().to_string_lossy().into_owned());
            }
            v.sort();
            Ok(v)
        })
    }
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        blocking(&self.0, move || std::fs::rename(from, to))
    }
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        blocking(&self.0, move || std::fs::remove_file(path))
    }
    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        blocking(&self.0, move || std::fs::File::open(dir)?.sync_all())
    }
    fn available(&self, path: PathBuf) -> BoxFuture<'static, io::Result<u64>> {
        blocking(&self.0, move || {
            let s = rustix::fs::statvfs(&path).map_err(io::Error::from)?;
            Ok(s.f_bavail.saturating_mul(s.f_frsize))
        })
    }
}

struct RealFile {
    f: Arc<std::fs::File>,
    h: Handle,
}

impl File for RealFile {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
        let f = self.f.clone();
        blocking(&self.h, move || Ok(f.metadata()?.len()))
    }
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        let f = self.f.clone();
        blocking(&self.h, move || {
            let mut buf = vec![0u8; len];
            let mut done = 0;
            while done < len {
                let n = f.read_at(&mut buf[done..], offset + done as u64)?;
                if n == 0 {
                    break;
                }
                done += n;
            }
            buf.truncate(done);
            Ok(buf)
        })
    }
    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, io::Result<()>> {
        let f = self.f.clone();
        blocking(&self.h, move || f.write_all_at(&data, offset))
    }
    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>> {
        let f = self.f.clone();
        blocking(&self.h, move || f.set_len(len))
    }
    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
        let f = self.f.clone();
        blocking(&self.h, move || f.sync_data())
    }
}

pub struct RealProcs;

struct RealProcess {
    id: Option<u32>,
    child: Arc<tokio::sync::Mutex<tokio::process::Child>>,
}

impl Process for RealProcess {
    fn id(&self) -> Option<u32> {
        self.id
    }
    fn wait(&self) -> BoxFuture<'static, io::Result<Option<i32>>> {
        let c = self.child.clone();
        Box::pin(async move { Ok(c.lock().await.wait().await?.code()) })
    }
    fn kill(&self) -> BoxFuture<'static, io::Result<()>> {
        let c = self.child.clone();
        Box::pin(async move { c.lock().await.kill().await })
    }
}

fn child_stdio(s: &crate::env::Stdio) -> io::Result<std::process::Stdio> {
    use std::os::unix::fs::OpenOptionsExt as _;
    Ok(match s {
        crate::env::Stdio::Null => std::process::Stdio::null(),
        crate::env::Stdio::Append(path) => std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?
            .into(),
        crate::env::Stdio::Log { path, max_bytes } => log_pipe(path, *max_bytes)?.into(),
    })
}

/// The write end of a pipe whose bytes a thread appends to `path`, moving
/// the file to `<path>.1` when it would grow past `max_bytes`.
fn log_pipe(path: &std::path::Path, max_bytes: u64) -> io::Result<std::io::PipeWriter> {
    let (reader, writer) = std::io::pipe()?;
    let path = path.to_owned();
    // A plain thread, not a tokio task: it blocks on the pipe for as long
    // as the child (and whatever inherits its output) keeps it open, and
    // only copies bytes.
    std::thread::Builder::new()
        .name("kronik-child-log".into())
        .spawn(move || copy_capped(reader, &path, max_bytes))?;
    Ok(writer)
}

/// Copies `from` to `path` until EOF. Write errors (a full disk) drop the
/// bytes but keep reading, so the child never blocks on its output.
fn copy_capped(mut from: impl std::io::Read, path: &std::path::Path, max: u64) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let open = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .ok()
    };
    let mut file = open();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        // The length on disk, not a count: other writers append too.
        let len = file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map_or(0, |m| m.len());
        if file.is_none() || (len > 0 && len + n as u64 > max) {
            let mut rotated = path.as_os_str().to_owned();
            rotated.push(".1");
            if file.is_some() {
                let _ = std::fs::rename(path, &rotated);
            }
            file = open();
        }
        let keep = n.min(usize::try_from(max).unwrap_or(usize::MAX));
        if let Some(f) = file.as_mut() {
            let _ = f.write_all(&buf[..keep]);
        }
    }
}

impl ProcessRunner for RealProcs {
    fn spawn(&self, spec: ProcessSpec) -> BoxFuture<'static, io::Result<Arc<dyn Process>>> {
        Box::pin(async move {
            let mut cmd = tokio::process::Command::new(&spec.program);
            // One pipe when both streams go to the same capped log, so the
            // cap holds for their sum.
            let (stdout, stderr) = match (&spec.stdout, &spec.stderr) {
                (
                    crate::env::Stdio::Log { path, max_bytes },
                    crate::env::Stdio::Log { path: other, .. },
                ) if path == other => {
                    let w = log_pipe(path, *max_bytes)?;
                    let w2 = w.try_clone()?;
                    (w.into(), w2.into())
                }
                (out, err) => (child_stdio(out)?, child_stdio(err)?),
            };
            cmd.args(&spec.args)
                .env_clear()
                .envs(spec.env.iter().map(|(k, v)| (k, v)))
                .stdin(std::process::Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .kill_on_drop(true);
            if let Some(cwd) = &spec.cwd {
                cmd.current_dir(cwd);
            }
            let child = cmd.spawn()?;
            Ok(Arc::new(RealProcess {
                id: child.id(),
                child: Arc::new(tokio::sync::Mutex::new(child)),
            }) as Arc<dyn Process>)
        })
    }
}

/// Outbound HTTP(S): hyper over rustls with the system's root
/// certificates, HTTP/1.1. Connection failures before the request is sent
/// are `NetError::Connect`; anything later is `NetError::Io` (the request may
/// have been delivered, I17).
pub struct RealNet {
    client: Result<HttpClient, String>,
}

type HttpClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Full<Bytes>,
>;

impl RealNet {
    pub fn new() -> RealNet {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map(|b| b.https_or_http().enable_http1().build());
        RealNet {
            client: connector
                .map(|c| {
                    hyper_util::client::legacy::Client::builder(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .build(c)
                })
                .map_err(|e| format!("loading the system root certificates: {e}")),
        }
    }
}

impl Default for RealNet {
    fn default() -> Self {
        RealNet::new()
    }
}

impl Net for RealNet {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let client = self.client.clone();
        Box::pin(async move {
            use http_body_util::BodyExt as _;
            let client = client.map_err(NetError::Connect)?;
            let mut b = hyper::Request::builder()
                .method(req.method.as_str())
                .uri(req.url.as_str());
            for (n, v) in &req.headers {
                b = b.header(n.as_str(), v.as_str());
            }
            let request = b
                .body(http_body_util::Full::new(req.body))
                .map_err(|e| NetError::Connect(format!("invalid request: {e}")))?;
            let resp = client.request(request).await.map_err(|e| {
                if e.is_connect() {
                    NetError::Connect(e.to_string())
                } else {
                    NetError::Io(e.to_string())
                }
            })?;
            let status = resp.status().as_u16();
            let headers = resp
                .headers()
                .iter()
                .map(|(n, v)| {
                    (
                        n.as_str().to_owned(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect();
            let limit = usize::try_from(req.max_response_bytes).unwrap_or(usize::MAX);
            let body = http_body_util::Limited::new(resp.into_body(), limit)
                .collect()
                .await
                .map_err(|e| {
                    if e.downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some()
                    {
                        NetError::TooLarge
                    } else {
                        NetError::Io(e.to_string())
                    }
                })?
                .to_bytes();
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

impl crate::env::Env {
    /// The production environment on the current tokio runtime.
    pub fn real(handle: Handle) -> crate::env::Env {
        crate::env::Env {
            clock: Arc::new(RealClock::default()),
            spawner: Arc::new(RealSpawner(handle.clone())),
            entropy: Arc::new(RealEntropy),
            fs: Arc::new(RealFs(handle)),
            net: Arc::new(RealNet::new()),
            procs: Arc::new(RealProcs),
        }
    }
}
