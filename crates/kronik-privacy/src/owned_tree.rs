//! File operations for code that runs with more authority than the owner of
//! the tree it works in: `serve --init` and the offline key commands run as
//! root over a data directory that belongs to the nonroot service user
//! (ADR 0062, ADR 0063).
//!
//! The rule is that such code never resolves a path through a directory the
//! service user could have swapped. A process with the service uid (the
//! threat of M21: a sandbox escape lands there) can rename a directory away
//! and plant a symbolic link, a FIFO, a socket or a hard link in its place;
//! a path-based `chown`, `read_dir` or `copy` by root would follow it.
//! A [`Dir`] is an open directory, and everything below it is reached one
//! name at a time with `openat(O_NOFOLLOW)`, so that:
//!
//! * a symbolic link is an error and is never followed, whatever it points at;
//! * a name is a plain file name, never a path with `/`, `.` or `..`;
//! * a directory on another file system is refused (a mount planted in the
//!   tree is not entered);
//! * a file is accepted only if it is a regular file with one link, which
//!   rules out FIFOs, sockets, devices and hard links to files elsewhere;
//! * a file is opened `O_NONBLOCK`, so that a FIFO cannot hang a command, and
//!   read up to a size limit.
//!
//! The walk is made of single-component `openat` calls rather than `openat2`
//! with `RESOLVE_*` flags: the guarantees are the same, and it works on every
//! kernel and under every seccomp profile. There is no `unsafe` code here.
//!
//! The order of writes matters as much as the calls. The way to use this
//! module is to create everything root writes **before** the directory is
//! handed over, while it is still private to root, and to touch nothing in it
//! as root afterwards ([`Dir::hand_over_tree`] does the hand-over, last entry
//! last).

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Gid, Mode, OFlags, Stat, Uid};

/// How deep and how large a tree this module will list and hand over. A
/// restore stage holds one file per log segment, so the bound is generous: it
/// is there so that a tree made to be endless cannot exhaust memory.
const MAX_DEPTH: usize = 16;
const MAX_ENTRIES: usize = 1 << 20;

/// What an entry is, by `lstat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Fifo,
    Socket,
    Other,
}

impl Kind {
    fn of(file_type: FileType) -> Kind {
        match file_type {
            FileType::RegularFile => Kind::File,
            FileType::Directory => Kind::Dir,
            FileType::Symlink => Kind::Symlink,
            FileType::Fifo => Kind::Fifo,
            FileType::Socket => Kind::Socket,
            _ => Kind::Other,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Kind::File => "a regular file",
            Kind::Dir => "a directory",
            Kind::Symlink => "a symbolic link",
            Kind::Fifo => "a FIFO",
            Kind::Socket => "a socket",
            Kind::Other => "a device or another special file",
        }
    }
}

/// The attributes of an entry that the callers decide on.
#[derive(Clone, Copy, Debug)]
pub struct Meta {
    pub kind: Kind,
    pub uid: u32,
    pub gid: u32,
    /// The permission bits, without the file type.
    pub mode: u32,
    pub nlink: u64,
    pub size: u64,
    pub dev: u64,
    pub ino: u64,
}

impl Meta {
    // The integer types of `stat` differ between platforms.
    #[allow(clippy::unnecessary_cast)]
    fn from_stat(st: &Stat) -> Meta {
        Meta {
            kind: Kind::of(FileType::from_raw_mode(st.st_mode as _)),
            uid: st.st_uid,
            gid: st.st_gid,
            mode: (st.st_mode as u32) & 0o7777,
            nlink: st.st_nlink as u64,
            size: u64::try_from(st.st_size).unwrap_or(0),
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
        }
    }
}

/// Which directories a walk may pass through on its way to its target.
#[derive(Clone, Copy, Debug)]
pub enum Ancestors {
    /// Any directory (the caller trusts the starting point).
    Any,
    /// Directories that only root and this uid can change: owned by one of
    /// them, and the group and others have no write permission, or the
    /// directory is sticky. In a sticky directory such as `/tmp` only the
    /// owner of an entry can rename or remove it, so the entry of a path that
    /// root or this uid owns cannot be swapped there; every directory on the
    /// path is checked in turn. Root is always trusted: for a process that is
    /// not root, `/` and `/usr` are as good as its own directories.
    ControlledBy(u32),
}

impl Ancestors {
    fn check(self, meta: &Meta, what: &Path) -> io::Result<()> {
        let Ancestors::ControlledBy(owner) = self else {
            return Ok(());
        };
        let sticky = meta.mode & 0o1000 != 0;
        if (meta.uid != owner && meta.uid != 0) || (meta.mode & 0o022 != 0 && !sticky) {
            return Err(refused(format!(
                "{} is not controlled by root or uid {owner} alone (owner {}, mode {:04o}), so a path through it could be redirected",
                what.display(),
                meta.uid,
                meta.mode
            )));
        }
        Ok(())
    }
}

fn refused(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// The error for a failed `openat` of a directory by `O_NOFOLLOW`: a symbolic
/// link answers `ELOOP` or `ENOTDIR`, depending on the kernel's check order.
fn open_error(what: &Path, e: rustix::io::Errno) -> io::Error {
    match e {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => refused(format!(
            "{} is a symbolic link or not a directory; it is not followed",
            what.display()
        )),
        other => io::Error::new(
            io::Error::from(other).kind(),
            format!("{}: {other}", what.display()),
        ),
    }
}

fn plain_name(name: &OsStr) -> io::Result<&OsStr> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(invalid(format!("{name:?} is not a plain file name")));
    }
    Ok(name)
}

/// Gives the open file to `uid:gid`, by descriptor. A file that root creates in
/// another user's directory is made theirs before it is linked into place, so
/// that the service can read it and root never has to touch the tree again.
pub fn chown_file(file: &File, uid: u32, gid: u32) -> io::Result<()> {
    if uid == u32::MAX || gid == u32::MAX {
        return Err(invalid("not a valid uid or gid".into()));
    }
    rustix::fs::fchown(file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
    Ok(())
}

/// An open directory, and the root of every operation of this module.
#[derive(Debug)]
pub struct Dir {
    fd: OwnedFd,
    dev: u64,
    /// For messages only; never used to open anything.
    label: PathBuf,
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

impl Dir {
    fn from_fd(fd: OwnedFd, label: PathBuf) -> io::Result<Dir> {
        let meta = Meta::from_stat(&rustix::fs::fstat(&fd)?);
        if meta.kind != Kind::Dir {
            return Err(invalid(format!("{} is not a directory", label.display())));
        }
        Ok(Dir {
            fd,
            dev: meta.dev,
            label,
        })
    }

    /// The directory `path`, opened the way an administrator named it:
    /// symbolic links on the way are followed. This is the trust anchor for
    /// callers that already hold the directory (a locked data directory) or
    /// that take the path from root-owned configuration.
    pub fn open(path: &Path) -> io::Result<Dir> {
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Dir::from_fd(fd, path.to_owned())
    }

    /// A second handle on the directory `file` holds, for example the one
    /// [`DataOwnership`](crate::key_source::DataOwnership) locks.
    pub fn from_file(file: &File, label: &Path) -> io::Result<Dir> {
        Dir::from_fd(file.try_clone()?.into(), label.to_owned())
    }

    /// The directory at the absolute `path`, reached from `/` without
    /// following any symbolic link, through directories that only `owner`
    /// (root in production) can write. With `create`, missing directories
    /// are made (`mode` for the last, 0755 for the ones above it), by
    /// descriptor. The last component may belong to anyone: that is for the
    /// caller to look at with [`Dir::stat`].
    pub fn open_controlled(path: &Path, owner: u32, create: Option<u32>) -> io::Result<Dir> {
        Dir::open_absolute(path, Ancestors::ControlledBy(owner), create)
    }

    /// [`Dir::open_controlled`] with the rule for the directories on the way
    /// as a parameter.
    pub fn open_absolute(
        path: &Path,
        ancestors: Ancestors,
        create: Option<u32>,
    ) -> io::Result<Dir> {
        if !path.is_absolute() {
            return Err(invalid(format!(
                "{} is not an absolute path",
                path.display()
            )));
        }
        Dir::open(Path::new("/"))?.open_below(path, ancestors, create)
    }

    /// Walks `relative` (from `/`'s successors: `Normal` components only)
    /// below this directory. See [`Dir::open_controlled`]. The directories on
    /// the way, this one included when there is a component to follow, must
    /// satisfy `ancestors`; the last one is returned unchecked. Mounts may be
    /// crossed on the way (a data directory can be a mount point); a
    /// symbolic link may not.
    pub fn open_below(
        &self,
        relative: &Path,
        ancestors: Ancestors,
        create: Option<u32>,
    ) -> io::Result<Dir> {
        let names: Vec<&OsStr> = relative
            .components()
            .filter_map(|c| match c {
                Component::RootDir => None,
                Component::Normal(n) => Some(Ok(n)),
                other => Some(Err(invalid(format!(
                    "{} has a {other:?} component",
                    relative.display()
                )))),
            })
            .collect::<io::Result<_>>()?;
        let mut current = self.try_clone()?;
        let mut label = self.label.clone();
        for (index, name) in names.iter().enumerate() {
            let name = plain_name(name)?;
            ancestors.check(&current.stat()?, &label)?;
            let last = index + 1 == names.len();
            let opened = match rustix::fs::openat(&current.fd, name, DIR_FLAGS, Mode::empty()) {
                Err(rustix::io::Errno::NOENT) if create.is_some() => {
                    let mode = if last { create.unwrap_or(0o700) } else { 0o755 };
                    match rustix::fs::mkdirat(&current.fd, name, Mode::from_raw_mode(mode as _)) {
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(e) => return Err(e.into()),
                    }
                    rustix::fs::fsync(&current.fd)?;
                    rustix::fs::openat(&current.fd, name, DIR_FLAGS, Mode::empty())
                }
                other => other,
            };
            let fd = opened.map_err(|e| open_error(&label.join(name), e))?;
            label.push(name);
            current = Dir::from_fd(fd, label.clone())?;
        }
        Ok(current)
    }

    pub fn try_clone(&self) -> io::Result<Dir> {
        Ok(Dir {
            fd: self.fd.try_clone()?,
            dev: self.dev,
            label: self.label.clone(),
        })
    }

    /// Where this directory was reached, for messages.
    pub fn label(&self) -> &Path {
        &self.label
    }

    /// The directory's own attributes, by descriptor.
    pub fn stat(&self) -> io::Result<Meta> {
        Ok(Meta::from_stat(&rustix::fs::fstat(&self.fd)?))
    }

    /// The attributes of the entry `name` without following it, or `None`.
    pub fn entry(&self, name: &OsStr) -> io::Result<Option<Meta>> {
        match rustix::fs::statat(&self.fd, plain_name(name)?, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => Ok(Some(Meta::from_stat(&st))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The names in this directory and what they are, without reading any of
    /// them.
    pub fn entries(&self) -> io::Result<Vec<(OsString, Kind)>> {
        let mut out = Vec::new();
        for entry in rustix::fs::Dir::read_from(&self.fd)? {
            let entry = entry?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == "." || name == ".." {
                continue;
            }
            if out.len() >= MAX_ENTRIES {
                return Err(refused(format!(
                    "{} holds too many entries",
                    self.label.display()
                )));
            }
            let kind = match entry.file_type() {
                FileType::Unknown => self.entry(name)?.map_or(Kind::Other, |m| m.kind),
                known => Kind::of(known),
            };
            out.push((name.to_owned(), kind));
        }
        Ok(out)
    }

    /// The subdirectory `name`: never a symbolic link, never on another file
    /// system.
    pub fn open_dir(&self, name: &OsStr) -> io::Result<Dir> {
        let name = plain_name(name)?;
        let what = self.label.join(name);
        let fd = rustix::fs::openat(&self.fd, name, DIR_FLAGS, Mode::empty())
            .map_err(|e| open_error(&what, e))?;
        let dir = Dir::from_fd(fd, what.clone())?;
        if dir.dev != self.dev {
            return Err(refused(format!(
                "{} is on another file system",
                what.display()
            )));
        }
        Ok(dir)
    }

    /// Creates the subdirectory `name` (mode `mode`, subject to the umask)
    /// and opens it. An existing entry is an error.
    pub fn create_dir(&self, name: &OsStr, mode: u32) -> io::Result<Dir> {
        let name = plain_name(name)?;
        rustix::fs::mkdirat(&self.fd, name, Mode::from_raw_mode(mode as _))?;
        rustix::fs::fsync(&self.fd)?;
        self.open_dir(name)
    }

    /// Creates the file `name` (mode `mode`) for writing; it must not exist.
    pub fn create_file(&self, name: &OsStr, mode: u32) -> io::Result<File> {
        let fd = rustix::fs::openat(
            &self.fd,
            plain_name(name)?,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode as _),
        )?;
        Ok(File::from(fd))
    }

    /// Opens the regular file `name` for reading: never a symbolic link, a
    /// FIFO, a socket or a device, never a file with more than one link, and
    /// not larger than `max_len`. A FIFO or socket in its place fails at
    /// once; it does not block.
    pub fn open_regular(&self, name: &OsStr, max_len: u64) -> io::Result<File> {
        let name = plain_name(name)?;
        let what = self.label.join(name);
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            rustix::io::Errno::LOOP => refused(format!(
                "{} is a symbolic link; it is not followed",
                what.display()
            )),
            rustix::io::Errno::NXIO => refused(format!(
                "{} is a socket or a FIFO, not a regular file",
                what.display()
            )),
            other => io::Error::new(
                io::Error::from(other).kind(),
                format!("{}: {other}", what.display()),
            ),
        })?;
        let meta = Meta::from_stat(&rustix::fs::fstat(&fd)?);
        if meta.kind != Kind::File {
            return Err(refused(format!(
                "{} is {}, not a regular file",
                what.display(),
                meta.kind.describe()
            )));
        }
        if meta.nlink != 1 {
            return Err(refused(format!(
                "{} has {} hard links; a regular file here has one",
                what.display(),
                meta.nlink
            )));
        }
        if meta.size > max_len {
            return Err(refused(format!(
                "{} is larger than {max_len} bytes",
                what.display()
            )));
        }
        Ok(File::from(fd))
    }

    /// The contents of the regular file `name`, at most `max_len` bytes.
    pub fn read_regular(&self, name: &OsStr, max_len: u64) -> io::Result<Vec<u8>> {
        let file = self.open_regular(name, max_len)?;
        let mut bytes = Vec::new();
        file.take(max_len.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max_len {
            return Err(refused(format!(
                "{} grew beyond {max_len} bytes while it was read",
                self.label.join(name).display()
            )));
        }
        Ok(bytes)
    }

    /// Copies the regular file `name` to `to`, at most `max_len` bytes.
    pub fn copy_regular(&self, name: &OsStr, to: &mut File, max_len: u64) -> io::Result<u64> {
        let file = self.open_regular(name, max_len)?;
        let copied = io::copy(&mut file.take(max_len.saturating_add(1)), to)?;
        if copied > max_len {
            return Err(refused(format!(
                "{} grew beyond {max_len} bytes while it was copied",
                self.label.join(name).display()
            )));
        }
        to.flush()?;
        Ok(copied)
    }

    /// Whether this directory belongs to a user other than `euid`, the user
    /// the process runs as: a privileged process that works in someone else's
    /// tree must reach everything in it by name, through descriptors, and
    /// follow nothing; in its own tree it has nothing to fear from itself.
    pub fn belongs_to_another_than(&self, euid: u32) -> io::Result<bool> {
        Ok(self.stat()?.uid != euid)
    }

    /// Hard-links the file `from` of this directory as `to`, which must not
    /// exist (a link there is not followed, it is an error).
    pub fn link(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        rustix::fs::linkat(
            &self.fd,
            plain_name(from)?,
            &self.fd,
            plain_name(to)?,
            AtFlags::empty(),
        )?;
        Ok(())
    }

    /// Renames the entry `from` to `to` within this directory, replacing what
    /// is at `to` (a link there is replaced, not followed).
    pub fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        rustix::fs::renameat(&self.fd, plain_name(from)?, &self.fd, plain_name(to)?)?;
        Ok(())
    }

    /// Removes the non-directory entry `name`; a link is removed, not followed.
    pub fn unlink(&self, name: &OsStr) -> io::Result<()> {
        rustix::fs::unlinkat(&self.fd, plain_name(name)?, AtFlags::empty())?;
        Ok(())
    }

    /// Flushes this directory's entries to disk.
    pub fn sync(&self) -> io::Result<()> {
        rustix::fs::fsync(&self.fd)?;
        Ok(())
    }

    /// Makes this directory read-write only for its owner (`mode`), by
    /// descriptor.
    pub fn set_mode(&self, mode: u32) -> io::Result<()> {
        rustix::fs::fchmod(&self.fd, Mode::from_raw_mode(mode as _))?;
        Ok(())
    }

    /// Hands over this directory and everything below it to `uid:gid`, last
    /// entry last, as one operation.
    ///
    /// This is only for a tree no one else can reach: the directory must be
    /// owned by the calling user and closed to group and others (mode `0700`),
    /// and the caller must have created the contents. Every entry is checked
    /// first, and the tree is changed only if all of them are directories or
    /// regular files with one link: a symbolic link, FIFO, socket, device or
    /// hard link anywhere is an error and nothing is changed. Directories
    /// and files are changed by descriptor and without following links, files
    /// before the directory that holds them, this directory at the very end.
    /// Once it returns, the caller must not touch the tree as root again.
    pub fn hand_over_tree(&self, uid: u32, gid: u32) -> io::Result<()> {
        if uid == u32::MAX || gid == u32::MAX {
            return Err(invalid("not a valid uid or gid".into()));
        }
        self.hand_over_tree_with(&mut |dir, name| {
            let (owner, group) = (Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)));
            match name {
                None => rustix::fs::fchown(&dir.fd, owner, group),
                Some(name) => {
                    rustix::fs::chownat(&dir.fd, name, owner, group, AtFlags::SYMLINK_NOFOLLOW)
                }
            }
            .map_err(io::Error::from)
        })
    }

    /// [`Dir::hand_over_tree`] with the ownership change as a parameter: it
    /// is called with a directory and `None` for the directory itself, or
    /// with a directory and the name of a file in it. Tests use it to see the
    /// order and the set of entries without needing the privilege to chown.
    pub fn hand_over_tree_with(
        &self,
        change: &mut dyn FnMut(&Dir, Option<&OsStr>) -> io::Result<()>,
    ) -> io::Result<()> {
        let me = self.stat()?;
        let caller = rustix::process::geteuid().as_raw();
        if me.uid != caller || me.mode & 0o077 != 0 {
            return Err(refused(format!(
                "{} is owned by uid {} with mode {:04o}; only a directory that the caller owns and nobody else can enter is handed over",
                self.label.display(),
                me.uid,
                me.mode
            )));
        }
        let mut seen = 0;
        self.check_tree(0, &mut seen)?;
        self.change_tree(change)
    }

    fn check_tree(&self, depth: usize, seen: &mut usize) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(refused(format!(
                "{} is nested too deeply",
                self.label.display()
            )));
        }
        for (name, kind) in self.entries()? {
            *seen += 1;
            if *seen > MAX_ENTRIES {
                return Err(refused(format!(
                    "{} holds too many entries",
                    self.label.display()
                )));
            }
            match kind {
                Kind::Dir => self.open_dir(&name)?.check_tree(depth + 1, seen)?,
                Kind::File => {
                    let meta = self.entry(&name)?.ok_or_else(|| {
                        refused(format!("{} vanished", self.label.join(&name).display()))
                    })?;
                    if meta.kind != Kind::File || meta.nlink != 1 {
                        return Err(refused(format!(
                            "{} is not a regular file with one link",
                            self.label.join(&name).display()
                        )));
                    }
                }
                other => {
                    return Err(refused(format!(
                        "{} is {}; only directories and regular files are handed over, and nothing was changed",
                        self.label.join(&name).display(),
                        other.describe()
                    )));
                }
            }
        }
        Ok(())
    }

    fn change_tree(
        &self,
        change: &mut dyn FnMut(&Dir, Option<&OsStr>) -> io::Result<()>,
    ) -> io::Result<()> {
        for (name, kind) in self.entries()? {
            match kind {
                Kind::Dir => self.open_dir(&name)?.change_tree(change)?,
                Kind::File => change(self, Some(&name))?,
                other => {
                    return Err(refused(format!(
                        "{} became {}",
                        self.label.join(&name).display(),
                        other.describe()
                    )));
                }
            }
        }
        change(self, None)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    use super::*;

    /// Filesystem clocks tick coarsely: a change time that is the same before
    /// and after proves nothing unless the clock has moved in between.
    fn tick() {
        std::thread::sleep(Duration::from_millis(40));
    }

    fn ctime(path: &Path) -> (i64, i64) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        (meta.ctime(), meta.ctime_nsec())
    }

    struct Scene {
        _dir: tempfile::TempDir,
        /// The tree under test: what root would hand over.
        tree: PathBuf,
        /// A directory elsewhere that an attacker wants root to chown.
        victim: PathBuf,
    }

    /// A private tree `tree/keys/{secrets.db,master.wrapped}` and a victim
    /// directory with a file in it, both under a temporary directory.
    fn scene() -> Scene {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("data");
        let victim = dir.path().join("victim");
        std::fs::create_dir(&tree).unwrap();
        std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(tree.join("keys")).unwrap();
        std::fs::write(tree.join("keys/master.wrapped"), b"envelope").unwrap();
        std::fs::write(tree.join("keys/secrets.db"), b"db").unwrap();
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("a.conf"), b"config").unwrap();
        Scene {
            _dir: dir,
            tree,
            victim,
        }
    }

    fn untouched(path: &Path, before: (i64, i64)) {
        assert_eq!(ctime(path), before, "{} was changed", path.display());
    }

    fn recorded(dir: &Dir) -> io::Result<Vec<String>> {
        let mut seen = Vec::new();
        let base = dir.label().to_owned();
        dir.hand_over_tree_with(&mut |at, name| {
            let at = at.label().strip_prefix(&base).unwrap().to_owned();
            seen.push(match name {
                Some(name) => format!("{}", at.join(name).display()),
                None => format!("{}/", at.display()),
            });
            Ok(())
        })?;
        Ok(seen)
    }

    #[test]
    fn a_tree_is_handed_over_files_first_and_the_top_last() {
        let scene = scene();
        let seen = recorded(&Dir::open(&scene.tree).unwrap()).unwrap();
        assert_eq!(seen.len(), 4, "{seen:?}");
        assert_eq!(seen.last().unwrap(), "/", "the top comes last: {seen:?}");
        let dir_at = seen.iter().position(|s| s == "keys/").unwrap();
        for file in ["keys/master.wrapped", "keys/secrets.db"] {
            assert!(
                seen.iter().position(|s| s == file).unwrap() < dir_at,
                "{seen:?}"
            );
        }
    }

    #[test]
    fn the_real_hand_over_changes_every_entry_and_only_those() {
        let scene = scene();
        let before: Vec<_> = ["", "keys", "keys/master.wrapped", "keys/secrets.db"]
            .iter()
            .map(|p| scene.tree.join(p))
            .map(|p| (ctime(&p), p))
            .collect();
        let victim_before = (ctime(&scene.victim), ctime(&scene.victim.join("a.conf")));
        tick();
        // Handing over to the caller itself changes nothing visible but the
        // change time, which is exactly what shows that the call was made.
        let st = std::fs::metadata(&scene.tree).unwrap();
        Dir::open(&scene.tree)
            .unwrap()
            .hand_over_tree(st.uid(), st.gid())
            .unwrap();
        for (old, path) in &before {
            assert_ne!(ctime(path), *old, "{} was not changed", path.display());
        }
        untouched(&scene.victim, victim_before.0);
        untouched(&scene.victim.join("a.conf"), victim_before.1);
    }

    #[test]
    fn a_planted_symlink_is_never_followed_and_nothing_is_changed() {
        let scene = scene();
        // The service user renames `keys` away and plants a link to a
        // directory that holds only regular files, which a hand-over would
        // accept if it followed the link.
        std::fs::rename(scene.tree.join("keys"), scene.tree.join("keys.old")).unwrap();
        symlink(&scene.victim, scene.tree.join("keys")).unwrap();
        let victim = (ctime(&scene.victim), ctime(&scene.victim.join("a.conf")));
        let tree = ctime(&scene.tree);
        tick();
        let dir = Dir::open(&scene.tree).unwrap();
        assert_eq!(
            dir.entry(OsStr::new("keys")).unwrap().unwrap().kind,
            Kind::Symlink
        );
        let error = dir.open_dir(OsStr::new("keys")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        let error = dir.hand_over_tree(0, 0).unwrap_err();
        assert!(error.to_string().contains("a symbolic link"), "{error}");
        let mut called = 0;
        assert!(
            dir.hand_over_tree_with(&mut |_, _| {
                called += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(
            called, 0,
            "nothing may be changed before every entry is checked"
        );
        untouched(&scene.victim, victim.0);
        untouched(&scene.victim.join("a.conf"), victim.1);
        untouched(&scene.tree, tree);
    }

    #[test]
    fn a_symlink_instead_of_a_file_is_refused_and_not_followed() {
        let scene = scene();
        std::fs::remove_file(scene.tree.join("keys/secrets.db")).unwrap();
        symlink(
            scene.victim.join("a.conf"),
            scene.tree.join("keys/secrets.db"),
        )
        .unwrap();
        let victim = ctime(&scene.victim.join("a.conf"));
        tick();
        let keys = Dir::open(&scene.tree)
            .unwrap()
            .open_dir(OsStr::new("keys"))
            .unwrap();
        let error = keys
            .open_regular(OsStr::new("secrets.db"), 1 << 20)
            .unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert!(
            Dir::open(&scene.tree)
                .unwrap()
                .hand_over_tree(0, 0)
                .is_err()
        );
        untouched(&scene.victim.join("a.conf"), victim);
    }

    #[test]
    #[allow(clippy::disallowed_methods)] // a test without an Env: a thread gives a blocking call a deadline
    fn a_fifo_in_place_of_a_file_fails_at_once_and_does_not_hang() {
        let scene = scene();
        std::fs::remove_file(scene.tree.join("keys/secrets.db")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            scene.tree.join("keys/secrets.db"),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let tree = scene.tree.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let keys = Dir::open(&tree)
                .unwrap()
                .open_dir(OsStr::new("keys"))
                .unwrap();
            let read = keys.read_regular(OsStr::new("secrets.db"), 1 << 20);
            let hand = Dir::open(&tree).unwrap().hand_over_tree(0, 0);
            let _ = sender.send((read.is_err(), hand.is_err()));
        });
        let (read_failed, hand_failed) = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO blocked");
        assert!(read_failed && hand_failed);
    }

    #[test]
    fn a_socket_is_refused_for_reading_and_for_the_hand_over() {
        let scene = scene();
        std::fs::remove_file(scene.tree.join("keys/secrets.db")).unwrap();
        let _listener = UnixListener::bind(scene.tree.join("keys/secrets.db")).unwrap();
        let keys = Dir::open(&scene.tree)
            .unwrap()
            .open_dir(OsStr::new("keys"))
            .unwrap();
        assert!(
            keys.open_regular(OsStr::new("secrets.db"), 1 << 20)
                .is_err()
        );
        let error = Dir::open(&scene.tree)
            .unwrap()
            .hand_over_tree(0, 0)
            .unwrap_err();
        assert!(error.to_string().contains("a socket"), "{error}");
    }

    #[test]
    fn a_file_with_a_second_hard_link_is_refused() {
        let scene = scene();
        std::fs::hard_link(scene.victim.join("a.conf"), scene.tree.join("keys/linked")).unwrap();
        let victim = ctime(&scene.victim.join("a.conf"));
        tick();
        let keys = Dir::open(&scene.tree)
            .unwrap()
            .open_dir(OsStr::new("keys"))
            .unwrap();
        let error = keys
            .open_regular(OsStr::new("linked"), 1 << 20)
            .unwrap_err();
        assert!(error.to_string().contains("hard links"), "{error}");
        assert!(
            Dir::open(&scene.tree)
                .unwrap()
                .hand_over_tree(0, 0)
                .is_err()
        );
        untouched(&scene.victim.join("a.conf"), victim);
    }

    #[test]
    fn only_a_private_tree_owned_by_the_caller_is_handed_over() {
        let scene = scene();
        std::fs::set_permissions(&scene.tree, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = Dir::open(&scene.tree)
            .unwrap()
            .hand_over_tree(0, 0)
            .unwrap_err();
        assert!(
            error.to_string().contains("nobody else can enter"),
            "{error}"
        );
    }

    #[test]
    fn reads_are_bounded_and_names_must_be_plain() {
        let scene = scene();
        let keys = Dir::open(&scene.tree)
            .unwrap()
            .open_dir(OsStr::new("keys"))
            .unwrap();
        assert_eq!(
            keys.read_regular(OsStr::new("master.wrapped"), 8).unwrap(),
            b"envelope"
        );
        let error = keys
            .read_regular(OsStr::new("master.wrapped"), 7)
            .unwrap_err();
        assert!(error.to_string().contains("larger than 7"), "{error}");
        for bad in ["", ".", "..", "a/b", "../victim"] {
            assert!(keys.open_regular(OsStr::new(bad), 8).is_err(), "{bad:?}");
            assert!(keys.entry(OsStr::new(bad)).is_err(), "{bad:?}");
        }
        assert!(keys.entry(OsStr::new("absent")).unwrap().is_none());
    }

    #[test]
    fn files_are_created_linked_renamed_and_removed_by_name_without_following_links() {
        let scene = scene();
        let keys = Dir::open(&scene.tree)
            .unwrap()
            .open_dir(OsStr::new("keys"))
            .unwrap();
        let (a, b) = (OsStr::new("a"), OsStr::new("b"));
        // A new file, linked to a name that is free, then the first name goes.
        let mut file = keys.create_file(a, 0o600).unwrap();
        file.write_all(b"one").unwrap();
        keys.link(a, b).unwrap();
        keys.unlink(a).unwrap();
        assert_eq!(keys.read_regular(b, 16).unwrap(), b"one");
        // A name that is taken is an error for link and create, and a planted
        // link is not followed by either.
        assert!(keys.create_file(b, 0o600).is_err());
        symlink(scene.victim.join("a.conf"), scene.tree.join("keys/c")).unwrap();
        let victim = ctime(&scene.victim.join("a.conf"));
        tick();
        assert!(keys.link(b, OsStr::new("c")).is_err());
        assert!(keys.create_file(OsStr::new("c"), 0o600).is_err());
        // Rename replaces the link itself, and the file it pointed to stays.
        keys.rename(b, OsStr::new("c")).unwrap();
        assert_eq!(keys.read_regular(OsStr::new("c"), 16).unwrap(), b"one");
        assert_eq!(
            std::fs::read(scene.victim.join("a.conf")).unwrap(),
            b"config"
        );
        untouched(&scene.victim.join("a.conf"), victim);
        // Removing a link removes the link.
        symlink(scene.victim.join("a.conf"), scene.tree.join("keys/d")).unwrap();
        keys.unlink(OsStr::new("d")).unwrap();
        assert!(scene.victim.join("a.conf").exists());
        keys.sync().unwrap();
        // Names with a separator are not names.
        for bad in ["", "..", "x/y"] {
            assert!(
                keys.link(OsStr::new("c"), OsStr::new(bad)).is_err(),
                "{bad:?}"
            );
            assert!(keys.unlink(OsStr::new(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_file_is_given_to_the_owner_of_its_directory_by_descriptor() {
        let scene = scene();
        let me = std::fs::metadata(&scene.tree).unwrap();
        let keys = Dir::open(&scene.tree)
            .unwrap()
            .open_dir(OsStr::new("keys"))
            .unwrap();
        let file = keys.create_file(OsStr::new("owned"), 0o600).unwrap();
        // Giving a file to oneself is always allowed; the same call with
        // another uid is what root does.
        chown_file(&file, me.uid(), me.gid()).unwrap();
        assert!(chown_file(&file, u32::MAX, 0).is_err());
        assert!(!keys.belongs_to_another_than(me.uid()).unwrap());
        assert!(
            keys.belongs_to_another_than(me.uid().wrapping_add(1))
                .unwrap()
        );
    }

    #[test]
    fn a_mount_below_the_anchor_is_not_entered() {
        // `/proc` is a different file system from `/`: reaching it as a
        // child of `/` is the mount-crossing case.
        if !Path::new("/proc/self").exists() {
            return;
        }
        let root = Dir::open(Path::new("/")).unwrap();
        if root.stat().unwrap().dev == Dir::open(Path::new("/proc")).unwrap().stat().unwrap().dev {
            return;
        }
        let error = root.open_dir(OsStr::new("proc")).unwrap_err();
        assert!(error.to_string().contains("another file system"), "{error}");
    }

    #[test]
    fn a_walk_refuses_symlinks_and_directories_that_others_can_write() {
        let scene = scene();
        let anchor = Dir::open(&scene.tree).unwrap();
        let me = std::fs::metadata(&scene.tree).unwrap().uid();
        // Plain directories below the anchor, all closed to others: fine, and
        // missing ones are created by descriptor.
        let made = anchor
            .open_below(Path::new("a/b/c"), Ancestors::ControlledBy(me), Some(0o700))
            .unwrap();
        assert_eq!(made.stat().unwrap().mode & 0o777, 0o700);
        assert!(scene.tree.join("a/b/c").is_dir());
        assert_eq!(
            std::fs::metadata(scene.tree.join("a")).unwrap().mode() & 0o700,
            0o700
        );
        // A symlink in the middle is refused, not followed.
        symlink(&scene.victim, scene.tree.join("link")).unwrap();
        let error = anchor
            .open_below(Path::new("link/x"), Ancestors::Any, None)
            .unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        let error = anchor
            .open_below(Path::new("link"), Ancestors::Any, Some(0o700))
            .unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert!(!scene.victim.join("x").exists());
        // An ancestor that others can write is refused when the caller asks
        // for directories that only it controls.
        std::fs::set_permissions(scene.tree.join("a"), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let error = anchor
            .open_below(Path::new("a/b"), Ancestors::ControlledBy(me), None)
            .unwrap_err();
        assert!(error.to_string().contains("not controlled"), "{error}");
        // A directory owned by someone else is refused too (root's own always
        // counts, so as root the tree is first given away).
        let someone_else = if me == 0 {
            std::os::unix::fs::chown(&scene.tree, Some(65_534), None).unwrap();
            1
        } else {
            me.wrapping_add(1)
        };
        let error = anchor
            .open_below(
                Path::new("keys/x"),
                Ancestors::ControlledBy(someone_else),
                None,
            )
            .unwrap_err();
        assert!(error.to_string().contains("not controlled"), "{error}");
        // `..` and relative anchors are not paths this module walks.
        assert!(
            anchor
                .open_below(Path::new("../x"), Ancestors::Any, None)
                .is_err()
        );
        assert!(Dir::open_controlled(Path::new("relative"), 0, None).is_err());
    }

    #[test]
    fn the_real_root_is_controlled_by_root() {
        // Every Linux host: `/`, `/usr` and `/usr/bin` belong to root and
        // nobody else can write them.
        let root_owned =
            |p: &str| std::fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0);
        if !["/", "/usr", "/usr/bin"].iter().all(|p| root_owned(p)) {
            return;
        }
        let dir = Dir::open_controlled(Path::new("/usr/bin"), 0, None).unwrap();
        assert_eq!(dir.stat().unwrap().kind, Kind::Dir);
    }

    #[test]
    fn the_rule_for_the_directories_on_the_way() {
        let meta = |uid, mode| Meta {
            kind: Kind::Dir,
            uid,
            gid: 0,
            mode,
            nlink: 2,
            size: 0,
            dev: 1,
            ino: 1,
        };
        let rule = Ancestors::ControlledBy(0);
        let path = Path::new("/x");
        // root's own, closed to others: fine
        assert!(rule.check(&meta(0, 0o755), path).is_ok());
        assert!(rule.check(&meta(0, 0o700), path).is_ok());
        // writable by the group or others: refused
        assert!(rule.check(&meta(0, 0o775), path).is_err());
        assert!(rule.check(&meta(0, 0o757), path).is_err());
        // someone else's: refused, sticky or not
        assert!(rule.check(&meta(1000, 0o755), path).is_err());
        assert!(rule.check(&meta(1000, 0o1777), path).is_err());
        // root's and sticky, as /tmp and /var/tmp are: its entries cannot be
        // swapped by others
        assert!(rule.check(&meta(0, 0o1777), path).is_ok());
        assert!(Ancestors::Any.check(&meta(1000, 0o777), path).is_ok());
        // For a caller that is not root, root's directories count as its own.
        let user = Ancestors::ControlledBy(1000);
        assert!(user.check(&meta(0, 0o755), path).is_ok());
        assert!(user.check(&meta(1000, 0o700), path).is_ok());
        assert!(user.check(&meta(1001, 0o755), path).is_err());
        assert!(user.check(&meta(0, 0o775), path).is_err());
        assert!(user.check(&meta(1000, 0o1777), path).is_ok());
    }
}
