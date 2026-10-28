//! A file system in memory, for the log: tests leave nothing on disk.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use kronik_core::env::{BoxFuture, File, Fs, OpenMode};

/// Files by path. Directories exist implicitly; everything is durable at
/// once, since a test host does not crash.
#[derive(Default)]
pub struct MemFs {
    files: Mutex<BTreeMap<PathBuf, Arc<MemFile>>>,
}

#[derive(Default)]
struct MemFile {
    data: Mutex<Vec<u8>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn ready<T: Send + 'static>(v: T) -> BoxFuture<'static, T> {
    Box::pin(std::future::ready(v))
}

fn not_found(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("{}: no such file", path.display()),
    )
}

impl Fs for MemFs {
    fn create_dir_all(&self, _path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        ready(Ok(()))
    }

    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        let mut files = lock(&self.files);
        let file = match (files.get(&path), mode) {
            (Some(f), _) => Ok(f.clone() as Arc<dyn File>),
            (None, OpenMode::Read) => Err(not_found(&path)),
            (None, OpenMode::ReadWriteCreate) => {
                let f = Arc::new(MemFile::default());
                files.insert(path, f.clone());
                Ok(f as Arc<dyn File>)
            }
        };
        ready(file)
    }

    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        let files = lock(&self.files);
        let found = files.contains_key(&path) || files.keys().any(|f| f.starts_with(&path));
        ready(Ok(found))
    }

    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        // BTreeMap order is path order, so the names come out sorted.
        let names = lock(&self.files)
            .keys()
            .filter(|f| f.parent() == Some(dir.as_path()))
            .filter_map(|f| f.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        ready(Ok(names))
    }

    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        let mut files = lock(&self.files);
        let result = match files.remove(&from) {
            Some(f) => {
                files.insert(to, f);
                Ok(())
            }
            None => Err(not_found(&from)),
        };
        ready(result)
    }

    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        let result = lock(&self.files)
            .remove(&path)
            .map(drop)
            .ok_or_else(|| not_found(&path));
        ready(result)
    }

    fn sync_dir(&self, _dir: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        ready(Ok(()))
    }
}

impl File for MemFile {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
        ready(Ok(lock(&self.data).len() as u64))
    }

    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        let data = lock(&self.data);
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let end = start.saturating_add(len).min(data.len());
        ready(Ok(data[start..end].to_vec()))
    }

    fn write_at(&self, offset: u64, bytes: Bytes) -> BoxFuture<'static, io::Result<()>> {
        let mut data = lock(&self.data);
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(bytes.len());
        if data.len() < end {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(&bytes);
        ready(Ok(()))
    }

    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>> {
        lock(&self.data).resize(usize::try_from(len).unwrap_or(usize::MAX), 0);
        ready(Ok(()))
    }

    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
        ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn files_hold_what_was_written() {
        let fs = MemFs::default();
        let dir = PathBuf::from("/log");
        assert!(fs.open(dir.join("a"), OpenMode::Read).await.is_err());
        let f = fs
            .open(dir.join("b"), OpenMode::ReadWriteCreate)
            .await
            .unwrap();
        f.write_at(3, Bytes::from_static(b"xyz")).await.unwrap();
        assert_eq!(f.read_at(0, 10).await.unwrap(), b"\0\0\0xyz");
        fs.open(dir.join("a"), OpenMode::ReadWriteCreate)
            .await
            .unwrap();
        assert_eq!(fs.read_dir(dir.clone()).await.unwrap(), ["a", "b"]);
        fs.rename(dir.join("b"), dir.join("c")).await.unwrap();
        assert_eq!(
            fs.open(dir.join("c"), OpenMode::Read)
                .await
                .unwrap()
                .len()
                .await
                .unwrap(),
            6
        );
        fs.remove_file(dir.join("a")).await.unwrap();
        assert_eq!(fs.read_dir(dir.clone()).await.unwrap(), ["c"]);
        assert!(fs.exists(dir).await.unwrap());
    }
}
