//! The small Linux-only syscall boundary of the Firecracker backend.
// Allowlisted: KVM admission, reserved disk allocation and reflink copies have
// no safe binding in this crate's existing dependencies.
#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;

/// Check the real KVM interface, not merely the presence of a path. A temporary
/// empty VM is closed immediately; no image, runtime state or log is written.
pub(crate) fn kvm() -> io::Result<()> {
    let device = OpenOptions::new().read(true).write(true).open("/dev/kvm")?;
    if !device.metadata()?.file_type().is_char_device() {
        return Err(io::Error::other("/dev/kvm is not a character device"));
    }
    // SAFETY: these KVM ioctls have integer arguments and device is owned here.
    let version = unsafe { libc::ioctl(device.as_raw_fd(), 0xae00 as _, 0) };
    if version != 12 {
        return Err(if version < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::other("unsupported KVM API version")
        });
    }
    // SAFETY: KVM_CREATE_VM returns a new descriptor on success.
    let vm = unsafe { libc::ioctl(device.as_raw_fd(), 0xae01 as _, 0) };
    if vm < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful ioctl returned a fresh, exclusively owned fd.
    drop(unsafe { OwnedFd::from_raw_fd(vm) });
    Ok(())
}

/// Reserve the entire finite guest data drive, so future guest writes cannot
/// consume an unaccounted sparse-file allocation below the host's reserve.
pub(crate) fn allocate(file: &File, bytes: u64) -> io::Result<()> {
    let length = libc::off_t::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "disk is too large"))?;
    // SAFETY: the descriptor is valid and the checked range is nonnegative.
    let error = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, length) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    file.set_len(bytes)
}

/// Copy an immutable checkpoint backing file without copying its pages when
/// the filesystem supports reflinks. The destination must not already exist.
pub(crate) fn copy(source: &Path, destination: &Path) -> io::Result<u64> {
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)?;
    if !input.metadata()?.is_file() {
        return Err(io::Error::other("checkpoint backing is not a regular file"));
    }
    copy_from(input, destination)
}

/// [`copy`] from a regular file the caller opened and checked.
pub(crate) fn copy_from(mut input: File, destination: &Path) -> io::Result<u64> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)?;
    // SAFETY: both descriptors are open regular files; FICLONE writes only the
    // new destination and shares source extents copy-on-write.
    let cloned = unsafe { libc::ioctl(output.as_raw_fd(), 0x4004_9409 as _, input.as_raw_fd()) };
    let bytes = if cloned == 0 {
        input.metadata()?.len()
    } else {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL | libc::ENOTTY)
        ) {
            return Err(error);
        }
        io::copy(&mut input, &mut output)?
    };
    output.sync_all()?;
    Ok(bytes)
}

/// Mutable data drives must retain their full allocation after a checkpoint:
/// a reflink would turn later production writes into unreserved COW writes.
pub(crate) fn copy_reserved(source: &Path, destination: &Path) -> io::Result<u64> {
    use std::io::{Read as _, Write as _};
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() != crate::microvm::DATA_BYTES {
        return Err(io::Error::other("invalid fixed microVM data drive"));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)?;
    allocate(&output, metadata.len())?;
    // Deliberately not io::copy: copy_file_range may silently reflink on btrfs.
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
    }
    if output.metadata()?.len() != metadata.len() {
        return Err(io::Error::other("microVM data copy changed length"));
    }
    output.sync_all()?;
    Ok(metadata.len())
}

/// Publish an owned staging file without replacing a drive created meanwhile.
pub(crate) fn publish(source: &Path, destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    // The system call itself, not libc's `renameat2` wrapper: the static
    // release binary links against zig's musl, which has none (an undefined
    // symbol at link time), while the system call exists on every kernel the
    // daemon supports (Linux 3.15 and later).
    // SAFETY: both terminated paths live through the call; NOREPLACE protects
    // an existing actor drive even when another creator wins the race.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Preserve an OCI entry's timestamp without following a final symlink.
pub(crate) fn set_mtime(path: &Path, seconds: u64) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    let seconds = libc::time_t::try_from(seconds)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "OCI mtime is out of range"))?;
    let path = CString::new(path.as_os_str().as_bytes())?;
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
    ];
    // SAFETY: the path and two initialized timespecs remain valid; the caller
    // already confined the entry beneath its private unpack root.
    let result = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_checkpoint_copy_has_independent_writes_and_never_replaces_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        std::fs::write(&source, b"production").unwrap();
        assert_eq!(copy(&source, &destination).unwrap(), 10);
        std::fs::write(&destination, b"fork").unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), b"production");
        assert!(copy(&source, &destination).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"fork");
    }

    #[test]
    fn a_checkpoint_copy_does_not_follow_a_source_symlink() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("outside"), b"canary").unwrap();
        std::os::unix::fs::symlink("outside", dir.path().join("link")).unwrap();
        assert!(copy(&dir.path().join("link"), &dir.path().join("copy")).is_err());
        assert_eq!(
            std::fs::read(dir.path().join("outside")).unwrap(),
            b"canary"
        );
    }

    #[test]
    fn publishing_never_replaces_and_mtime_does_not_follow_symlinks() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("staging");
        let destination = dir.path().join("drive");
        std::fs::write(&source, b"new").unwrap();
        std::fs::write(&destination, b"original").unwrap();
        assert_eq!(
            publish(&source, &destination).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        let before = std::fs::metadata(&destination).unwrap().mtime();
        set_mtime(&link, 17).unwrap();
        assert_eq!(std::fs::symlink_metadata(&link).unwrap().mtime(), 17);
        assert_eq!(std::fs::metadata(&destination).unwrap().mtime(), before);
    }
}
