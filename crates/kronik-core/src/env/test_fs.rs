//! A forwarding [`Fs`] for tests: every call, and every call to the files it
//! opens, is shown to a hook, which lets it through, fails it or holds it.
//! Built only with the `test-util` feature, which crates enable in their
//! `[dev-dependencies]`, so no production build contains it.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;

use super::{BoxFuture, File, Fs, OpenMode};

/// One call to a [`hooked`] file system or to a file it opened. A file call
/// carries the path the file was opened at; a secure write carries only its
/// path, never the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsCall {
    CreateDirAll(PathBuf),
    Open(PathBuf, OpenMode),
    Exists(PathBuf),
    ReadDir(PathBuf),
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    RemoveFile(PathBuf),
    SyncDir(PathBuf),
    Available(PathBuf),
    ReadSecure(PathBuf),
    WriteSecure(PathBuf),
    WriteSecureNew(PathBuf),
    Len(PathBuf),
    ReadAt {
        path: PathBuf,
        offset: u64,
        len: usize,
    },
    WriteAt {
        path: PathBuf,
        offset: u64,
        len: usize,
    },
    SetLen {
        path: PathBuf,
        len: u64,
    },
    SyncData(PathBuf),
}

/// What a [`hooked`] file system does with a call once its hook has seen it.
pub enum Then {
    /// Call the inner file system (or file) now.
    Forward,
    /// Return this error without calling the inner file system.
    Fail(io::Error),
    /// Await this future, then call the inner file system; if the future
    /// fails, return its error without calling it.
    Wait(BoxFuture<'static, io::Result<()>>),
}

type Hook = Arc<dyn Fn(&FsCall) -> Then + Send + Sync>;

/// `inner`, with `hook` called synchronously, once per call and before
/// anything is forwarded, for every `Fs` method and for every `File` method
/// of the files it opens. Every method, `available`, `read_secure`,
/// `write_secure` and `write_secure_new` included, forwards to `inner`
/// unless the hook says otherwise.
pub fn hooked(
    inner: Arc<dyn Fs>,
    hook: impl Fn(&FsCall) -> Then + Send + Sync + 'static,
) -> Arc<dyn Fs> {
    Arc::new(HookFs {
        inner,
        hook: Arc::new(hook),
    })
}

struct HookFs {
    inner: Arc<dyn Fs>,
    hook: Hook,
}

struct HookFile {
    inner: Arc<dyn File>,
    path: PathBuf,
    hook: Hook,
}

fn run<T: Send + 'static>(
    hook: &Hook,
    call: FsCall,
    forward: impl FnOnce() -> BoxFuture<'static, io::Result<T>> + Send + 'static,
) -> BoxFuture<'static, io::Result<T>> {
    match hook(&call) {
        Then::Forward => forward(),
        Then::Fail(error) => Box::pin(async move { Err(error) }),
        Then::Wait(wait) => Box::pin(async move {
            wait.await?;
            forward().await
        }),
    }
}

impl Fs for HookFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        run(&self.hook, FsCall::CreateDirAll(path.clone()), move || {
            inner.create_dir_all(path)
        })
    }

    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        let (inner, hook) = (self.inner.clone(), self.hook.clone());
        run(&self.hook, FsCall::Open(path.clone(), mode), move || {
            let opened = inner.open(path.clone(), mode);
            Box::pin(async move {
                let inner = opened.await?;
                Ok(Arc::new(HookFile { inner, path, hook }) as Arc<dyn File>)
            })
        })
    }

    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        let inner = self.inner.clone();
        run(&self.hook, FsCall::Exists(path.clone()), move || {
            inner.exists(path)
        })
    }

    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        let inner = self.inner.clone();
        run(&self.hook, FsCall::ReadDir(dir.clone()), move || {
            inner.read_dir(dir)
        })
    }

    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        let call = FsCall::Rename {
            from: from.clone(),
            to: to.clone(),
        };
        run(&self.hook, call, move || inner.rename(from, to))
    }

    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        run(&self.hook, FsCall::RemoveFile(path.clone()), move || {
            inner.remove_file(path)
        })
    }

    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        run(&self.hook, FsCall::SyncDir(dir.clone()), move || {
            inner.sync_dir(dir)
        })
    }

    fn available(&self, path: PathBuf) -> BoxFuture<'static, io::Result<u64>> {
        let inner = self.inner.clone();
        run(&self.hook, FsCall::Available(path.clone()), move || {
            inner.available(path)
        })
    }

    fn read_secure(
        &self,
        path: PathBuf,
        max_bytes: usize,
    ) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        let inner = self.inner.clone();
        run(&self.hook, FsCall::ReadSecure(path.clone()), move || {
            inner.read_secure(path, max_bytes)
        })
    }

    fn write_secure(&self, path: PathBuf, bytes: Vec<u8>) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        // Zeroed when dropped, as in the trait default, if the hook fails the call.
        let mut bytes = zeroize::Zeroizing::new(bytes);
        run(&self.hook, FsCall::WriteSecure(path.clone()), move || {
            inner.write_secure(path, std::mem::take(&mut *bytes))
        })
    }

    fn write_secure_new(&self, path: PathBuf, bytes: Bytes) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        run(
            &self.hook,
            FsCall::WriteSecureNew(path.clone()),
            move || inner.write_secure_new(path, bytes),
        )
    }
}

impl File for HookFile {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
        let inner = self.inner.clone();
        run(&self.hook, FsCall::Len(self.path.clone()), move || {
            inner.len()
        })
    }

    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        let inner = self.inner.clone();
        let call = FsCall::ReadAt {
            path: self.path.clone(),
            offset,
            len,
        };
        run(&self.hook, call, move || inner.read_at(offset, len))
    }

    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        let call = FsCall::WriteAt {
            path: self.path.clone(),
            offset,
            len: data.len(),
        };
        run(&self.hook, call, move || inner.write_at(offset, data))
    }

    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        let call = FsCall::SetLen {
            path: self.path.clone(),
            len,
        };
        run(&self.hook, call, move || inner.set_len(len))
    }

    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        run(&self.hook, FsCall::SyncData(self.path.clone()), move || {
            inner.sync_data()
        })
    }
}
