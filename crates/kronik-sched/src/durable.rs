//! Durable writes through `std::fs`, for what the node keeps beside its log
//! in the data directory: snapshots and the shipper's re-upload marks. A
//! file's bytes are durable once the file is fsynced, a name (a file or a
//! directory created or renamed) once its directory is. Until then a power
//! loss can take either back; and a process that died left them in the page
//! cache, where the next process would build on them.
//!
//! Linux, as the log: a file or a directory is fsynced through a read-only
//! handle (a directory can only be opened so).

use std::io;
use std::path::Path;

/// fsyncs `path`: a file's bytes, or the names in a directory.
pub(crate) fn sync(path: &Path) -> io::Result<()> {
    #[cfg(test)]
    test_ops::record(test_ops::Op::Sync(path.to_owned()))?;
    std::fs::File::open(path)?.sync_all()
}

/// Renames `from` to `to`, durable once the directory of `to` is synced.
pub(crate) fn rename(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(test)]
    test_ops::record(test_ops::Op::Rename(from.to_owned(), to.to_owned()))?;
    std::fs::rename(from, to)
}

/// Removes the file `path`, durable once its directory is synced.
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    #[cfg(test)]
    test_ops::record(test_ops::Op::Remove(path.to_owned()))?;
    std::fs::remove_file(path)
}

/// The directory of `path`, `.` for a bare name.
fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// Creates `dir` and the directories missing between it and `root`, and
/// makes each name durable: every directory from `dir`'s parent up to
/// `root` is synced, also when they all exist already, since a process
/// that died may have created one without syncing its parent.
pub(crate) fn create_dir_all(root: &Path, dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    if !dir.starts_with(root) {
        return sync(parent(dir));
    }
    let mut name = dir;
    while name != root {
        let above = parent(name);
        sync(above)?;
        name = above;
    }
    Ok(())
}

/// Writes `path` durably: a temporary file beside it, fsynced, renamed into
/// place, and the directory fsynced. A reader sees the old file or the new
/// one, and once this returns a power loss keeps the new one. When the
/// directory's fsync fails, the file is removed again: nothing may take it
/// for durable, since an fsync is never retried.
pub fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let written = (|| {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        #[cfg(test)]
        test_ops::record(test_ops::Op::Sync(tmp.clone()))?;
        file.sync_all()?;
        rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    sync(parent(path)).inspect_err(|_| {
        let _ = std::fs::remove_file(path);
    })
}

/// What a test watches: the operations of this module under a directory, in
/// order, and the failures it injects there. A registry of the whole
/// process, since the node runs on worker threads, and keyed by directory,
/// since tests run in parallel.
#[cfg(test)]
pub(crate) mod test_ops {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Op {
        Sync(PathBuf),
        Rename(PathBuf, PathBuf),
        Remove(PathBuf),
        /// A named point of a step, where a test may stop it as a crash
        /// would ([`point`]).
        Point(PathBuf, &'static str),
    }

    impl Op {
        fn path(&self) -> &Path {
            match self {
                Op::Sync(path) | Op::Rename(path, _) | Op::Remove(path) | Op::Point(path, _) => {
                    path
                }
            }
        }
    }

    /// The point `name` of a step on `path`: an error there when a test
    /// stops the step at it.
    pub(crate) fn point(path: &Path, name: &'static str) -> io::Result<()> {
        record(Op::Point(path.to_owned(), name))
    }

    type Fail = Box<dyn Fn(&Op) -> bool + Send>;

    struct Watch {
        root: PathBuf,
        ops: Vec<Op>,
        fail: Fail,
    }

    static WATCHES: Mutex<Vec<Watch>> = Mutex::new(Vec::new());

    fn watches() -> MutexGuard<'static, Vec<Watch>> {
        WATCHES.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records the operations under `root` until the result drops; one that
    /// `fail` matches fails with an injected error instead of running.
    pub(crate) fn watch(root: &Path, fail: impl Fn(&Op) -> bool + Send + 'static) -> Watching {
        watches().push(Watch {
            root: root.to_owned(),
            ops: Vec::new(),
            fail: Box::new(fail),
        });
        Watching(root.to_owned())
    }

    pub(crate) struct Watching(PathBuf);

    impl Watching {
        /// The operations so far, in order; an injected failure is not one.
        pub(crate) fn ops(&self) -> Vec<Op> {
            watches()
                .iter()
                .find(|w| w.root == self.0)
                .map(|w| w.ops.clone())
                .unwrap_or_default()
        }
    }

    impl Drop for Watching {
        fn drop(&mut self) {
            watches().retain(|w| w.root != self.0);
        }
    }

    pub(super) fn record(op: Op) -> io::Result<()> {
        for watch in watches().iter_mut() {
            if !op.path().starts_with(&watch.root) {
                continue;
            }
            if (watch.fail)(&op) {
                return Err(io::Error::other(format!("injected failure of {op:?}")));
            }
            watch.ops.push(op.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::test_ops::{Op, watch};
    use super::*;

    /// A file whose directory's fsync fails is not left in place: nothing
    /// may take it for durable.
    #[test]
    fn a_file_whose_name_is_not_made_durable_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let path = root.join("marker");
        let failing = watch(&root, {
            let root = root.clone();
            move |op| *op == Op::Sync(root.clone())
        });
        assert!(write_synced(&path, b"bytes").is_err());
        drop(failing);
        assert!(!path.exists());
        assert!(!path.with_extension("tmp").exists());
    }

    /// Directories that exist already are synced in their parents too, up to
    /// the root: a process that died may have created them unsynced.
    #[test]
    fn existing_directories_are_synced_in_their_parents() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let leaf = root.join("a").join("b");
        std::fs::create_dir_all(&leaf).unwrap();
        let watching = watch(&root, |_| false);
        create_dir_all(&root, &leaf).unwrap();
        assert_eq!(
            watching.ops(),
            [Op::Sync(root.join("a")), Op::Sync(root.clone())]
        );
    }
}
