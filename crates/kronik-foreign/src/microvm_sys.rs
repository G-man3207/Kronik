//! The small Linux-only syscall boundary of the Firecracker backend.
// Allowlisted: the KVM admission ioctls have no safe binding; the file operations below go through rustix.
#![allow(unsafe_code)]

use rustix::io::Errno;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The environment variable that points a debug build's microVM admission at
/// another KVM device (see [`kvm_device`]).
pub(crate) const TEST_KVM_DEVICE: &str = "KRONIK_TEST_KVM_DEVICE";

/// The device the microVM admission checks: `/dev/kvm`. A debug build takes
/// the path from [`TEST_KVM_DEVICE`] when it is set, so that a test can hide
/// KVM from a real daemon on a host that has it (CI's runners do) and prove
/// the refusal without KVM there; a release build never reads the variable.
/// Only the admission check reads this path: the VMM's jail binds
/// `/dev/kvm` itself, so the variable cannot hand a VM another device.
fn kvm_device() -> PathBuf {
    let test_device = if cfg!(debug_assertions) {
        std::env::var_os(TEST_KVM_DEVICE)
    } else {
        None
    };
    test_device.map_or_else(|| PathBuf::from("/dev/kvm"), PathBuf::from)
}

/// Check the real KVM interface, not merely the presence of a path. A temporary
/// empty VM is closed immediately; no image, runtime state or log is written.
pub(crate) fn kvm() -> io::Result<()> {
    let path = kvm_device();
    let device = OpenOptions::new().read(true).write(true).open(&path)?;
    if !device.metadata()?.file_type().is_char_device() {
        return Err(io::Error::other(format!(
            "{} is not a character device",
            path.display()
        )));
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
    rustix::fs::fallocate(file, rustix::fs::FallocateFlags::empty(), 0, bytes)?;
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
    // FICLONE writes only the new destination and shares the source's extents
    // copy-on-write; a file system without reflinks gets a plain copy.
    let bytes = match rustix::fs::ioctl_ficlone(&output, &input) {
        Ok(()) => input.metadata()?.len(),
        Err(Errno::OPNOTSUPP | Errno::XDEV | Errno::INVAL | Errno::NOTTY) => {
            io::copy(&mut input, &mut output)?
        }
        Err(error) => return Err(error.into()),
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
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    // NOREPLACE protects an existing actor drive even when another creator
    // wins the race. rustix makes the renameat2 system call itself: zig's
    // musl, which links the static release, has no renameat2 wrapper.
    Ok(renameat_with(
        CWD,
        source,
        CWD,
        destination,
        RenameFlags::NOREPLACE,
    )?)
}

/// Preserve an OCI entry's timestamp without following a final symlink.
pub(crate) fn set_mtime(path: &Path, seconds: u64) -> io::Result<()> {
    use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, utimensat};
    let seconds = i64::try_from(seconds)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "OCI mtime is out of range"))?;
    let times = Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        last_modification: Timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
    };
    // The caller already confined the entry beneath its private unpack root.
    Ok(utimensat(CWD, path, &times, AtFlags::SYMLINK_NOFOLLOW)?)
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
        assert_eq!(std::fs::symlink_metadata(&link).unwrap().atime(), 0);
        assert_eq!(std::fs::metadata(&destination).unwrap().mtime(), before);
    }

    #[test]
    fn allocation_reserves_the_drive_and_refuses_a_size_above_the_kernel_limit() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let file = File::create(dir.path().join("data.ext4")).unwrap();
        allocate(&file, 4 << 20).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.len(), 4 << 20);
        assert!(metadata.blocks() * 512 >= 4 << 20);
        assert_eq!(
            allocate(&file, u64::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_checkpoint_copy_from_another_file_system_is_copied_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("destination");
        // No file system shares extents with procfs, so FICLONE is refused
        // and the copy falls back to reading and writing.
        let expected = std::fs::read("/proc/version").unwrap();
        assert_eq!(
            copy(Path::new("/proc/version"), &destination).unwrap(),
            expected.len() as u64
        );
        assert_eq!(std::fs::read(&destination).unwrap(), expected);
    }

    #[test]
    fn a_nul_byte_in_a_path_is_refused_as_invalid_input() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("staging");
        std::fs::write(&source, b"new").unwrap();
        let with_nul = dir.path().join("drive\0name");
        assert_eq!(
            publish(&source, &with_nul).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            set_mtime(&with_nul, 17).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        // The staging file is the only entry: nothing was created or moved.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
