//! In-memory disk with power-failure semantics.
//!
//! Each file keeps its durable contents plus the ordered list of writes since
//! the last `sync_data`. Each directory keeps its durable name table, updated
//! only by `sync_dir`. On a crash the disk keeps the durable state and applies
//! the unsynced operations according to a [`CrashModel`]: a random prefix with
//! a torn last write, or (stricter) an independent keep/drop/tear decision per
//! write, which models page-cache writeback reordering.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use zeroize::Zeroizing;

use super::SimRng;
use kronik_core::env::Clock;
use kronik_core::env::{BoxFuture, File, Fs, OpenMode};

const SECTOR: u64 = 512;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashModel {
    /// Unsynced writes to a file survive as a random prefix; the first lost
    /// write may survive partially (torn).
    PrefixTorn,
    /// Every unsynced write is independently kept, lost, or torn.
    Reorder,
}

#[derive(Debug, Clone)]
enum Op {
    Write { offset: u64, data: Bytes },
    SetLen(u64),
}

#[derive(Default)]
struct Inode {
    current: Vec<u8>,
    durable: Vec<u8>,
    pending: Vec<Op>,
    // Inodes are owned, singly linked regular files; ordinary creation is not private.
    private: bool,
}

fn apply(buf: &mut Vec<u8>, op: &Op, keep: Option<usize>) {
    match op {
        Op::Write { offset, data } => {
            let n = keep.unwrap_or(data.len()).min(data.len());
            let start = *offset as usize;
            if buf.len() < start + n {
                buf.resize(start + n, 0);
            }
            buf[start..start + n].copy_from_slice(&data[..n]);
        }
        Op::SetLen(len) => buf.resize(*len as usize, 0),
    }
}

/// The text of the error `sync_data` returns when the fault injector fails
/// an fsync. A start whose error carries it was failed by the simulated disk,
/// and the scenarios restart that node.
pub const INJECTED_FSYNC_EIO: &str = "injected fsync EIO";

/// Fault and latency knobs for one disk.
#[derive(Debug, Clone, Copy)]
pub struct DiskFaults {
    pub crash_model: CrashModel,
    /// Probability that `sync_data` fails with EIO.
    pub fsync_error: f64,
}

#[derive(Default)]
pub struct Disk {
    inodes: BTreeMap<u64, Inode>,
    names: BTreeMap<PathBuf, u64>,
    durable_names: BTreeMap<PathBuf, u64>,
    dirs: BTreeSet<PathBuf>,
    private_dirs: BTreeSet<PathBuf>,
    next_inode: u64,
    pub fsyncs: u64,
    pub torn_writes: u64,
    pub lost_writes: u64,
    /// `sync_data` calls so far, failed ones too, in the order they run.
    sync_calls: u64,
    /// The `sync_data` calls (counted from 1) that fail whatever the random
    /// draws say; see [`Disk::fail_syncs`].
    fail_sync_calls: BTreeSet<u64>,
}

fn parent(p: &Path) -> PathBuf {
    p.parent().map(Path::to_path_buf).unwrap_or_default()
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

fn insecure_file() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "insecure private file")
}

impl Disk {
    /// Fails the given `sync_data` calls, counted from 1 over the whole disk
    /// in the order they run, in addition to the random failures of
    /// [`DiskFaults::fsync_error`]. A call is a position in the run's I/O, not
    /// in its random draws, so a test can fail one particular write (the
    /// second fsync of a fresh disk is the first record a start appends)
    /// whatever the seed.
    pub fn fail_syncs(&mut self, calls: impl IntoIterator<Item = u64>) {
        self.fail_sync_calls.extend(calls);
    }

    /// A durable regular file that was on the disk before the run, with its
    /// directories, such as a credential file an operator provisioned. A
    /// crash keeps it, as it keeps every synced file.
    pub fn install(&mut self, path: &Path, bytes: &[u8]) {
        let mut dir = parent(path);
        loop {
            self.dirs.insert(dir.clone());
            match dir.parent() {
                Some(up) if !up.as_os_str().is_empty() => dir = up.to_path_buf(),
                _ => break,
            }
        }
        self.next_inode += 1;
        let ino = self.next_inode;
        self.inodes.insert(
            ino,
            Inode {
                current: bytes.to_vec(),
                durable: bytes.to_vec(),
                pending: Vec::new(),
                private: true,
            },
        );
        self.names.insert(path.to_path_buf(), ino);
        self.durable_names.insert(path.to_path_buf(), ino);
    }

    /// The bytes of `path` that are guaranteed to survive a crash right now:
    /// durable contents of a durably named file.
    pub fn durable_contents(&self, path: &Path) -> Option<Vec<u8>> {
        let ino = self.durable_names.get(path)?;
        Some(self.inodes.get(ino)?.durable.clone())
    }

    /// The durably named files directly in `dir`, in name order: the files
    /// a crash right now would leave there.
    pub fn durable_files_in(&self, dir: &Path) -> Vec<PathBuf> {
        self.durable_names
            .keys()
            .filter(|p| p.parent() == Some(dir))
            .cloned()
            .collect()
    }

    /// Like `durable_contents`, but only the bytes from `from` on, plus the
    /// total durable length (for incremental checks on long runs).
    pub fn durable_suffix(&self, path: &Path, from: usize) -> Option<(usize, Vec<u8>)> {
        let ino = self.durable_names.get(path)?;
        let d = &self.inodes.get(ino)?.durable;
        Some((
            d.len(),
            d.get(from..).map(<[u8]>::to_vec).unwrap_or_default(),
        ))
    }

    /// Power failure: everything not synced is resolved by `model`.
    pub fn crash(&mut self, model: CrashModel, rng: &SimRng) {
        // Name tables: per directory, unsynced changes are all kept or all lost.
        let dirs: BTreeSet<PathBuf> = self
            .names
            .keys()
            .chain(self.durable_names.keys())
            .map(|p| parent(p))
            .collect();
        for dir in dirs {
            let current: BTreeMap<PathBuf, u64> = self
                .names
                .iter()
                .filter(|(p, _)| parent(p) == dir)
                .map(|(p, i)| (p.clone(), *i))
                .collect();
            let durable: BTreeMap<PathBuf, u64> = self
                .durable_names
                .iter()
                .filter(|(p, _)| parent(p) == dir)
                .map(|(p, i)| (p.clone(), *i))
                .collect();
            if current != durable && rng.chance(0.5) {
                // Writeback happened to persist the directory.
                for p in durable.keys() {
                    self.durable_names.remove(p);
                }
                self.durable_names.extend(current);
            }
        }
        self.names = self.durable_names.clone();

        let live: BTreeSet<u64> = self.names.values().copied().collect();
        self.inodes.retain(|ino, _| live.contains(ino));
        for inode in self.inodes.values_mut() {
            let mut buf = inode.durable.clone();
            let pending = std::mem::take(&mut inode.pending);
            match model {
                CrashModel::PrefixTorn => {
                    let k = rng.below(pending.len() as u64 + 1) as usize;
                    for op in &pending[..k] {
                        apply(&mut buf, op, None);
                    }
                    self.lost_writes += (pending.len() - k) as u64;
                    if let Some(op @ Op::Write { data, .. }) = pending.get(k)
                        && rng.chance(0.5)
                        && !data.is_empty()
                    {
                        let keep = rng.below(data.len() as u64) as usize;
                        apply(&mut buf, op, Some(keep));
                        self.torn_writes += 1;
                    }
                }
                CrashModel::Reorder => {
                    for op in &pending {
                        let r = rng.below(100);
                        match op {
                            Op::Write { data, .. } if r >= 85 && !data.is_empty() => {
                                let keep = rng.below(data.len() as u64) as usize;
                                apply(&mut buf, op, Some(keep));
                                self.torn_writes += 1;
                            }
                            _ if r < 60 => apply(&mut buf, op, None),
                            _ => self.lost_writes += 1,
                        }
                    }
                }
            }
            inode.current = buf.clone();
            inode.durable = buf;
        }
    }

    fn inode_of(&self, path: &Path) -> io::Result<u64> {
        self.names
            .get(path)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.display().to_string()))
    }

    fn secure_parent(&mut self, path: &Path, create: bool) -> io::Result<()> {
        let dir = parent(path);
        for ancestor in dir.ancestors() {
            if self.names.contains_key(ancestor) {
                return Err(insecure_file());
            }
            if ancestor.as_os_str().is_empty() || ancestor == Path::new("/") {
                continue;
            }
            if !self.dirs.contains(ancestor) {
                if create && ancestor == dir {
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "parent directory missing",
                ));
            }
        }
        if create {
            if self.dirs.contains(&dir) || dir.as_os_str().is_empty() || dir == Path::new("/") {
                if !self.private_dirs.contains(&dir) {
                    return Err(insecure_file());
                }
            } else {
                // Directories, including their privacy metadata, are always durable.
                self.dirs.insert(dir.clone());
                self.private_dirs.insert(dir);
            }
        }
        Ok(())
    }

    fn secure_destination(&self, path: &Path, replace: bool) -> io::Result<()> {
        if self.dirs.contains(path) {
            return Err(if replace {
                insecure_file()
            } else {
                io::ErrorKind::AlreadyExists.into()
            });
        }
        if let Some(ino) = self.names.get(path) {
            if !replace {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            if !self.inodes.get(ino).is_some_and(|inode| inode.private) {
                return Err(insecure_file());
            }
        }
        Ok(())
    }
}

/// `Fs` over a shared [`Disk`]; every operation takes simulated time and is
/// applied atomically when that time has passed.
#[derive(Clone)]
pub struct SimFs {
    pub disk: Arc<Mutex<Disk>>,
    clock: Arc<dyn Clock>,
    rng: SimRng,
    faults: DiskFaults,
}

impl SimFs {
    pub fn new(
        disk: Arc<Mutex<Disk>>,
        clock: Arc<dyn Clock>,
        rng: SimRng,
        faults: DiskFaults,
    ) -> Self {
        Self {
            disk,
            clock,
            rng,
            faults,
        }
    }

    fn latency(&self, min_us: u64, max_us: u64, slow_p: f64, slow_us: u64) -> Duration {
        let us = if self.rng.chance(slow_p) {
            slow_us
        } else {
            min_us + self.rng.below(max_us - min_us + 1)
        };
        Duration::from_micros(us)
    }

    fn op<T: Send + 'static>(
        &self,
        lat: Duration,
        f: impl FnOnce(&mut Disk) -> io::Result<T> + Send + 'static,
    ) -> BoxFuture<'static, io::Result<T>> {
        let sleep = self.clock.sleep(lat);
        let disk = self.disk.clone();
        Box::pin(async move {
            sleep.await;
            let mut d = disk.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut d)
        })
    }

    fn secure_write(
        &self,
        path: PathBuf,
        bytes: Bytes,
        replace: bool,
    ) -> BoxFuture<'static, io::Result<()>> {
        let fs = self.clone();
        Box::pin(async move {
            let path = secure_path(&path)?;
            let dir = parent(&path);
            let destination = path.clone();
            let (ino, temporary) = fs
                .op(fs.latency(5, 30, 0.0, 0), move |d| {
                    d.secure_parent(&destination, true)?;
                    d.secure_destination(&destination, replace)?;
                    d.next_inode += 1;
                    let ino = d.next_inode;
                    let mut name = std::ffi::OsString::from(".");
                    name.push(destination.file_name().ok_or_else(insecure_file)?);
                    name.push(format!(".{ino}.tmp"));
                    let temp = parent(&destination).join(name);
                    if d.names.contains_key(&temp) || d.dirs.contains(&temp) {
                        return Err(io::ErrorKind::AlreadyExists.into());
                    }
                    d.inodes.insert(
                        ino,
                        Inode {
                            private: true,
                            ..Inode::default()
                        },
                    );
                    d.names.insert(temp.clone(), ino);
                    Ok((ino, temp))
                })
                .await?;
            let file = SimFile {
                fs: fs.clone(),
                ino,
            };
            let result = async {
                file.write_at(0, bytes).await?;
                file.sync_data().await?;
                let temp = temporary.clone();
                fs.op(fs.latency(10, 50, 0.0, 0), move |d| {
                    d.secure_parent(&path, true)?;
                    d.secure_destination(&path, replace)?;
                    if d.inode_of(&temp)? != ino {
                        return Err(insecure_file());
                    }
                    d.names.remove(&temp);
                    d.names.insert(path, ino);
                    Ok(())
                })
                .await?;
                fs.sync_dir(dir).await
            }
            .await;
            if result.is_err() {
                fs.op(fs.latency(10, 50, 0.0, 0), move |d| {
                    if d.names.get(&temporary) == Some(&ino) {
                        d.names.remove(&temporary);
                    }
                    Ok(())
                })
                .await?;
            }
            result
        })
    }
}

fn lock(d: &Mutex<Disk>) -> std::sync::MutexGuard<'_, Disk> {
    d.lock().unwrap_or_else(|e| e.into_inner())
}

impl Fs for SimFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.op(self.latency(5, 20, 0.0, 0), move |d| {
            // Directories are modelled as always durable; files inside them are not.
            let mut p = path.as_path();
            loop {
                d.dirs.insert(p.to_path_buf());
                match p.parent() {
                    Some(q) if !q.as_os_str().is_empty() => p = q,
                    _ => break,
                }
            }
            Ok(())
        })
    }

    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        let me = self.clone();
        self.op(self.latency(5, 30, 0.0, 0), move |d| {
            let ino = match (d.names.get(&path), mode) {
                (Some(i), _) => *i,
                (None, OpenMode::Read) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        path.display().to_string(),
                    ));
                }
                (None, OpenMode::ReadWriteCreate) => {
                    if !d.dirs.contains(&parent(&path)) {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "parent directory missing",
                        ));
                    }
                    d.next_inode += 1;
                    let ino = d.next_inode;
                    d.inodes.insert(ino, Inode::default());
                    d.names.insert(path.clone(), ino);
                    ino
                }
            };
            Ok(Arc::new(SimFile { fs: me, ino }) as Arc<dyn File>)
        })
    }

    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        self.op(self.latency(2, 10, 0.0, 0), move |d| {
            Ok(d.names.contains_key(&path))
        })
    }

    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        self.op(self.latency(5, 20, 0.0, 0), move |d| {
            Ok(d.names
                .keys()
                .filter(|p| parent(p) == dir)
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .collect())
        })
    }

    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.op(self.latency(10, 50, 0.0, 0), move |d| {
            let ino = d.inode_of(&from)?;
            d.names.remove(&from);
            d.names.insert(to, ino);
            Ok(())
        })
    }

    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.op(self.latency(10, 50, 0.0, 0), move |d| {
            d.inode_of(&path)?;
            d.names.remove(&path);
            Ok(())
        })
    }

    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.op(self.latency(100, 1000, 0.01, 10_000), move |d| {
            let stale: Vec<PathBuf> = d
                .durable_names
                .keys()
                .filter(|p| parent(p) == dir)
                .cloned()
                .collect();
            for p in stale {
                d.durable_names.remove(&p);
            }
            let cur: Vec<(PathBuf, u64)> = d
                .names
                .iter()
                .filter(|(p, _)| parent(p) == dir)
                .map(|(p, i)| (p.clone(), *i))
                .collect();
            d.durable_names.extend(cur);
            Ok(())
        })
    }

    fn read_secure(
        &self,
        path: PathBuf,
        max_bytes: usize,
    ) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        self.op(self.latency(5, 40, 0.0, 0), move |d| {
            let path = secure_path(&path)?;
            d.secure_parent(&path, false)?;
            let ino = d.inode_of(&path)?;
            let inode = &d.inodes[&ino];
            if !inode.private {
                return Err(insecure_file());
            }
            if inode.current.len() > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "private file exceeds limit",
                ));
            }
            // The disk lock keeps metadata and contents unchanged throughout the read.
            Ok(inode.current.clone())
        })
    }

    fn write_secure(&self, path: PathBuf, bytes: Vec<u8>) -> BoxFuture<'static, io::Result<()>> {
        self.secure_write(path, Bytes::from_owner(Zeroizing::new(bytes)), true)
    }

    fn write_secure_new(&self, path: PathBuf, bytes: Bytes) -> BoxFuture<'static, io::Result<()>> {
        self.secure_write(path, bytes, false)
    }
}

struct SimFile {
    fs: SimFs,
    ino: u64,
}

impl SimFile {
    fn with<T: Send + 'static>(
        &self,
        lat: Duration,
        f: impl FnOnce(&mut Inode, &mut Disk) -> io::Result<T> + Send + 'static,
    ) -> BoxFuture<'static, io::Result<T>> {
        let ino = self.ino;
        self.fs.op(lat, move |d| {
            let mut inode = d
                .inodes
                .remove(&ino)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "file was removed"))?;
            let r = f(&mut inode, d);
            d.inodes.insert(ino, inode);
            r
        })
    }
}

impl File for SimFile {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
        self.with(Duration::from_micros(2), |i, _| Ok(i.current.len() as u64))
    }

    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        let lat = self.fs.latency(5, 40, 0.0, 0);
        self.with(lat, move |i, _| {
            let start = (offset as usize).min(i.current.len());
            let end = (start + len).min(i.current.len());
            Ok(i.current[start..end].to_vec())
        })
    }

    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, io::Result<()>> {
        let lat = self.fs.latency(5, 40, 0.0, 0);
        self.with(lat, move |i, _| {
            // Writeback works in sectors: each 512-byte-aligned piece of an
            // unsynced write can independently survive a crash.
            let mut pos = 0usize;
            while pos < data.len() {
                let at = offset + pos as u64;
                let n = ((SECTOR - at % SECTOR) as usize).min(data.len() - pos);
                let op = Op::Write {
                    offset: at,
                    data: data.slice(pos..pos + n),
                };
                apply(&mut i.current, &op, None);
                i.pending.push(op);
                pos += n;
            }
            Ok(())
        })
    }

    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>> {
        let lat = self.fs.latency(10, 50, 0.0, 0);
        self.with(lat, move |i, _| {
            let op = Op::SetLen(len);
            apply(&mut i.current, &op, None);
            i.pending.push(op);
            Ok(())
        })
    }

    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
        let lat = self.fs.latency(200, 3000, 0.01, 20_000);
        let fail = self.fs.rng.chance(self.fs.faults.fsync_error);
        self.with(lat, move |i, d| {
            d.sync_calls += 1;
            if fail || d.fail_sync_calls.contains(&d.sync_calls) {
                // The kernel may have dropped the dirty pages: model the worst
                // case by forgetting them, like ext4 after a writeback error.
                i.current = i.durable.clone();
                i.pending.clear();
                return Err(io::Error::other(INJECTED_FSYNC_EIO));
            }
            i.durable = i.current.clone();
            i.pending.clear();
            d.fsyncs += 1;
            Ok(())
        })
    }
}

impl Disk {
    /// Lock helper for code outside the simulator's tasks (invariant checks).
    pub fn snapshot_durable(disk: &Mutex<Disk>, path: &Path) -> Option<Vec<u8>> {
        lock(disk).durable_contents(path)
    }

    pub fn durable_suffix_of(
        disk: &Mutex<Disk>,
        path: &Path,
        from: usize,
    ) -> Option<(usize, Vec<u8>)> {
        lock(disk).durable_suffix(path, from)
    }
}
