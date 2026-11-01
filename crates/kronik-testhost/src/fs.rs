//! A file system in memory, for the log: tests leave nothing on disk.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use zeroize::Zeroizing;
use kronik_core::env::{BoxFuture, File, Fs, OpenMode};

/// Files by path. Ordinary directories exist implicitly; their privacy is
/// recorded separately. Everything is durable at once: a test host never crashes.
#[derive(Default)]
pub struct MemFs {
    files: Mutex<BTreeMap<PathBuf, Arc<MemFile>>>,
    dirs: Mutex<BTreeMap<PathBuf, bool>>,
}

#[derive(Default)]
struct MemFile {
    data: Mutex<Vec<u8>>,
    // Files are owned, singly linked and regular; ordinary creation is not private.
    private: bool,
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

fn insecure_file() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "insecure private file")
}

fn secure_path(path: &Path) -> io::Result<PathBuf> {
    use std::path::Component;
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => clean.push(component.as_os_str()),
            Component::CurDir => {}
            _ => return Err(insecure_file()),
        }
    }
    if clean.file_name().is_none() {
        return Err(insecure_file());
    }
    Ok(clean)
}

fn note_dirs(dirs: &mut BTreeMap<PathBuf, bool>, path: &Path) {
    for dir in path.ancestors() {
        dirs.entry(dir.to_path_buf()).or_insert(false);
    }
}

impl MemFs {
    fn secure_write(&self, path: PathBuf, mut bytes: Zeroizing<Vec<u8>>, replace: bool) -> io::Result<()> {
        let path = secure_path(&path)?;
        let dir = path.parent().ok_or_else(insecure_file)?;
        let mut dirs = lock(&self.dirs);
        let mut files = lock(&self.files);
        for ancestor in dir.ancestors() {
            if files.contains_key(ancestor) {
                return Err(insecure_file());
            }
            if ancestor == dir || ancestor.as_os_str().is_empty() || ancestor == Path::new("/") {
                continue;
            }
            if !dirs.contains_key(ancestor) {
                return Err(not_found(ancestor));
            }
        }
        if !dirs.contains_key(dir) {
            // Existing implicit directories are ordinary, not newly private ones.
            if dir.as_os_str().is_empty() || dir == Path::new("/")
                || files.keys().any(|file| file.starts_with(dir))
                || dirs.keys().any(|child| child.starts_with(dir)) {
                return Err(insecure_file());
            }
            dirs.insert(dir.to_path_buf(), true);
        }
        if dirs.get(dir) != Some(&true) {
            return Err(insecure_file());
        }
        if files.contains_key(&path) || dirs.contains_key(&path) {
            if !replace {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            if !files.get(&path).is_some_and(|file| file.private) {
                return Err(insecure_file());
            }
        }
        // One locked replacement models create-exclusive, sync-file, rename, sync-dir.
        files.insert(path, Arc::new(MemFile {
            data: Mutex::new(std::mem::take(&mut *bytes)),
            private: true,
        }));
        Ok(())
    }
}

impl Fs for MemFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        note_dirs(&mut lock(&self.dirs), &path);
        ready(Ok(()))
    }

    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        let mut dirs = lock(&self.dirs);
        let mut files = lock(&self.files);
        let file = match (files.get(&path), mode) {
            (Some(f), _) => Ok(f.clone() as Arc<dyn File>),
            (None, OpenMode::Read) => Err(not_found(&path)),
            (None, OpenMode::ReadWriteCreate) => {
                let f = Arc::new(MemFile::default());
                if let Some(dir) = path.parent() {
                    note_dirs(&mut dirs, dir);
                }
                files.insert(path, f.clone());
                Ok(f as Arc<dyn File>)
            }
        };
        ready(file)
    }

    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        let dirs = lock(&self.dirs);
        let files = lock(&self.files);
        let found = files.contains_key(&path) || dirs.contains_key(&path)
            || files.keys().any(|f| f.starts_with(&path));
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
        let mut dirs = lock(&self.dirs);
        let mut files = lock(&self.files);
        let result = match files.remove(&from) {
            Some(f) => {
                if let Some(dir) = to.parent() {
                    note_dirs(&mut dirs, dir);
                }
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

    fn read_secure(&self, path: PathBuf, max_bytes: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        ready((|| {
            let path = secure_path(&path)?;
            let dirs = lock(&self.dirs);
            let files = lock(&self.files);
            for ancestor in path.parent().ok_or_else(insecure_file)?.ancestors() {
                if files.contains_key(ancestor) {
                    return Err(insecure_file());
                }
                if !ancestor.as_os_str().is_empty() && ancestor != Path::new("/")
                    && !dirs.contains_key(ancestor) {
                    return Err(not_found(ancestor));
                }
            }
            let file = files.get(&path).ok_or_else(|| not_found(&path))?;
            if !file.private {
                return Err(insecure_file());
            }
            let data = lock(&file.data);
            if data.len() > max_bytes {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "private file exceeds limit"));
            }
            // Both locks keep the file and its contents unchanged throughout the read.
            Ok(data.clone())
        })())
    }

    fn write_secure(&self, path: PathBuf, bytes: Vec<u8>) -> BoxFuture<'static, io::Result<()>> {
        ready(self.secure_write(path, Zeroizing::new(bytes), true))
    }

    fn write_secure_new(&self, path: PathBuf, bytes: Bytes) -> BoxFuture<'static, io::Result<()>> {
        ready(self.secure_write(path, Zeroizing::new(bytes.to_vec()), false))
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
