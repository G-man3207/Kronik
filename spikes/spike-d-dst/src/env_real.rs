//! Production implementations of the `Env` traits on tokio and std.
//!
//! Threading model: daemon tasks run on tokio's multi-threaded runtime.
//! Every blocking syscall (file I/O, `fdatasync`, directory sync) runs on
//! tokio's blocking pool via `spawn_blocking`, so an fsync never stalls an
//! async worker. The log writer is one task, so its writes and fsyncs are
//! naturally serialized. Lift target: `kronik-core::env::real` (feature
//! `real`, enabled only by the `kronik` binary and integration tests).

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

impl ProcessRunner for RealProcs {
    fn spawn(&self, spec: ProcessSpec) -> BoxFuture<'static, io::Result<Arc<dyn Process>>> {
        Box::pin(async move {
            let mut cmd = tokio::process::Command::new(&spec.program);
            cmd.args(&spec.args)
                .env_clear()
                .envs(spec.env.iter().map(|(k, v)| (k, v)))
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

/// In-process stand-in for an external HTTP service, for the production-mode
/// demo only (M2 brings a real hyper client).
pub struct LoopbackNet {
    pub received: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Net for LoopbackNet {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let received = self.received.clone();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            let mut r = received.lock().unwrap_or_else(|e| e.into_inner());
            r.push(String::from_utf8_lossy(&req.body).into_owned());
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: Bytes::from(format!("charged #{}", r.len())),
            })
        })
    }
}
