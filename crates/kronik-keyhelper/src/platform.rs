//! Linux-only one-shot process protections and owned descriptor handling.
#![allow(unsafe_code)] // libc is confined here for prctl/rlimit and fixed protocol descriptors.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::protocol::{self, Error, Request};

pub fn protect() -> Result<(), Error> {
    // SAFETY: These process-local calls have no borrowed pointer arguments other than rlimit.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        {
            return Err(Error::Resource);
        }
        for (resource, value) in [
            (libc::RLIMIT_CORE, 0),
            (libc::RLIMIT_AS, 256 * 1024 * 1024),
            (libc::RLIMIT_CPU, 5),
            (libc::RLIMIT_NOFILE, 64),
        ] {
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            if libc::setrlimit(resource, &limit) != 0 {
                return Err(Error::Resource);
            }
        }
        if libc::signal(libc::SIGALRM, libc::SIG_DFL) == libc::SIG_ERR {
            return Err(Error::Resource);
        }
        let mut signals: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut signals) != 0
            || libc::sigaddset(&mut signals, libc::SIGALRM) != 0
            || libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) != 0
        {
            return Err(Error::Resource);
        }
        libc::alarm(10);
    }
    Ok(())
}

pub fn private_output() -> Result<File, Error> {
    let null = OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|_| Error::Resource)?;
    // SAFETY: Duplicate stdout into an owned close-on-exec descriptor; mute all module diagnostics.
    unsafe {
        let saved = libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 4);
        if saved < 0 {
            return Err(Error::Resource);
        }
        let output = File::from_raw_fd(saved);
        if libc::dup2(null.as_raw_fd(), 1) < 0 || libc::dup2(null.as_raw_fd(), 2) < 0 {
            return Err(Error::Resource);
        }
        Ok(output)
    }
}

pub fn read_request() -> Result<Zeroizing<Vec<u8>>, Error> {
    // SAFETY: Take the exclusively owned stdin pipe without std::io::Stdin's buffered copy.
    let input = unsafe {
        if libc::fcntl(0, libc::F_GETFD) < 0 {
            return Err(Error::Protocol);
        }
        File::from_raw_fd(0)
    };
    protocol::read_bounded(input, protocol::LIMIT)
}

pub fn read_pin() -> Result<Zeroizing<Vec<u8>>, Error> {
    // SAFETY: Check validity before taking exclusive ownership of the fixed protocol descriptor.
    let file = unsafe {
        if libc::fcntl(3, libc::F_GETFD) < 0 {
            return Err(Error::Pin);
        }
        File::from_raw_fd(3)
    };
    let mut pin = protocol::read_bounded(file, 1024).map_err(|_| Error::Pin)?;
    if pin.last() == Some(&b'\n') {
        // Remove in place without leaving the stripped byte in spare capacity.
        if let Some(last) = pin.last_mut() {
            *last = 0;
        }
        pin.pop();
    }
    if pin.is_empty() || pin.iter().any(|b| *b == 0 || *b == b'\n' || *b == b'\r') {
        return Err(Error::Pin);
    }
    Ok(pin)
}

pub fn module(request: &Request<'_>) -> Result<File, Error> {
    let path = Path::new(request.module.as_ref());
    let canonical = path.canonicalize().map_err(|_| Error::Module)?;
    if canonical != path {
        return Err(Error::Module);
    }
    // SAFETY: geteuid has no preconditions and does not alter process state.
    let uid = unsafe { libc::geteuid() };
    for ancestor in path.ancestors().skip(1) {
        let metadata = ancestor.symlink_metadata().map_err(|_| Error::Module)?;
        let protected_sticky = metadata.uid() == 0 && metadata.mode() & libc::S_ISVTX != 0;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0 && !protected_sticky)
        {
            return Err(Error::Module);
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Module)?;
    let metadata = file.metadata().map_err(|_| Error::Module)?;
    if !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 64 * 1024 * 1024
    {
        return Err(Error::Module);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut total = 0usize;
    loop {
        let count = file.read(&mut buffer).map_err(|_| Error::Module)?;
        if count == 0 {
            break;
        }
        total += count;
        if total > 64 * 1024 * 1024 {
            return Err(Error::Module);
        }
        hash.update(&buffer[..count]);
    }
    if protocol::encode(&hash.finalize()).as_str() != request.module_sha256 {
        return Err(Error::Module);
    }
    // Loading /proc/self/fd pins the validated inode rather than reopening a replaceable pathname.
    Ok(file)
}
