//! Descriptor-relative private custody; no path reopen or permission repair.

use std::io;
use std::os::unix::fs::MetadataExt as _;

fn insecure_file() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "insecure private file")
}

fn secure_parent(
    path: &std::path::Path,
    create_private_parent: bool,
) -> io::Result<(rustix::fd::OwnedFd, std::ffi::OsString)> {
    use rustix::fs::{Mode, OFlags};
    use std::path::Component;
    let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut parent = rustix::fs::open(
        if path.is_absolute() { "/" } else { "." },
        directory,
        Mode::empty(),
    )?;
    let mut components = path.components().peekable();
    loop {
        let name = match components.next() {
            Some(Component::RootDir | Component::CurDir) => continue,
            Some(Component::Normal(name)) => name,
            _ => return Err(insecure_file()),
        };
        if components.peek().is_none() {
            return Ok((parent, name.to_owned()));
        }
        parent = match rustix::fs::openat(&parent, name, directory, Mode::empty()) {
            Err(rustix::io::Errno::NOENT)
                if create_private_parent && components.clone().nth(1).is_none() =>
            {
                match rustix::fs::mkdirat(&parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                    Ok(()) => rustix::fs::fsync(&parent)?,
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(error.into()),
                }
                rustix::fs::openat(&parent, name, directory, Mode::empty())?
            }
            result => result?,
        };
    }
}

fn private_file_metadata(m: &std::fs::Metadata) -> bool {
    m.is_file()
        && m.nlink() == 1
        && m.uid() == rustix::process::geteuid().as_raw()
        && m.mode() & 0o077 == 0
}

fn unchanged_private_file(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    private_file_metadata(after)
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

pub(super) fn read_secure_file(path: &std::path::Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Read as _;
    let (parent, name) = secure_parent(path, false)?;
    let mut file = std::fs::File::from(rustix::fs::openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let before = file.metadata()?;
    if !private_file_metadata(&before) {
        return Err(insecure_file());
    }
    if before.len() > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private file exceeds limit",
        ));
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(before.len() as usize));
    (&mut file)
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if !unchanged_private_file(&before, &after) {
        return Err(insecure_file());
    }
    if bytes.len() > max_bytes || bytes.len() as u64 != after.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private file exceeds limit or changed",
        ));
    }
    Ok(std::mem::take(&mut *bytes))
}

pub(super) fn write_secure_file(
    path: &std::path::Path,
    bytes: &[u8],
    replace: bool,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
    use std::io::Write as _;
    let (parent, name) = secure_parent(path, true)?;
    let dir = rustix::fs::fstat(&parent)?;
    if dir.st_uid != rustix::process::geteuid().as_raw() || dir.st_mode & 0o077 != 0 {
        return Err(insecure_file());
    }
    match rustix::fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) if !replace => return Err(io::ErrorKind::AlreadyExists.into()),
        Ok(m)
            if FileType::from_raw_mode(m.st_mode) == FileType::RegularFile
                && m.st_nlink == 1
                && m.st_uid == dir.st_uid
                && m.st_mode & 0o077 == 0 => {}
        Err(rustix::io::Errno::NOENT) => {}
        Ok(_) => return Err(insecure_file()),
        Err(error) => return Err(error.into()),
    }
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| io::Error::other("OS entropy unavailable"))?;
    let mut temporary = std::ffi::OsString::from(".");
    temporary.push(&name);
    temporary.push(format!(".{:032x}.tmp", u128::from_le_bytes(nonce)));
    let mut file = std::fs::File::from(rustix::fs::openat(
        &parent,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace {
            rustix::fs::renameat(&parent, &temporary, &parent, &name)?;
        } else {
            rustix::fs::renameat_with(&parent, &temporary, &parent, &name, RenameFlags::NOREPLACE)?;
        }
        rustix::fs::fsync(&parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&parent, &temporary, AtFlags::empty());
    }
    result
}
