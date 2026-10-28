//! Syscalls without a safe binding in the workspace's dependencies: network
//! namespaces (create, delete, connect inside one) and the effective uid
//! (docs/design/m7-foreign.md §6).
//!
//! Each namespace operation runs on a short-lived thread of its own, never
//! on a pool thread: `unshare(CLONE_NEWNET)` and `setns` change the calling
//! thread's network namespace for the rest of its life, and a pool thread
//! in an empty namespace would break the next blocking job that resolves a
//! name or opens a socket. The thread exits right after; the namespace
//! lives on through its bind mount, a socket keeps the namespace it was
//! created in.

// Allowlisted: unshare(2), setns(2), mount(2), umount2(2), the interface
// flag ioctls and geteuid(2) have no safe binding in libc, and adding a
// crate for five calls is not worth its surface.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Whether the process runs with effective uid 0.
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn cstr(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn check(rc: libc::c_int, what: &str) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        let e = io::Error::last_os_error();
        Err(io::Error::new(e.kind(), format!("{what}: {e}")))
    }
}

/// Runs `f` on a fresh OS thread and waits for it (see the module docs).
fn on_own_thread<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    // A dedicated thread on purpose: its network namespace changes, so it
    // must never be a thread that runs anything else afterwards.
    let handle = std::thread::Builder::new().name(name.to_owned()).spawn(f)?;
    handle
        .join()
        .map_err(|_| io::Error::other(format!("thread {name} panicked")))?
}

/// Creates a network namespace that contains only `lo`, set up, and binds
/// it to the file `path` (created; its parent must exist).
pub fn create_netns(path: &Path) -> io::Result<()> {
    let target = path.to_path_buf();
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|e| io::Error::new(e.kind(), format!("creating {}: {e}", target.display())))?;
    let made = target.clone();
    let result = on_own_thread("kronik-netns", move || {
        // SAFETY: unshare only affects this thread (CLONE_NEWNET is allowed
        // in a multi-threaded process).
        check(unsafe { libc::unshare(libc::CLONE_NEWNET) }, "unshare")?;
        let source = cstr(Path::new("/proc/thread-self/ns/net"))?;
        let dest = cstr(&made)?;
        // SAFETY: both strings are valid NUL-terminated paths; a bind mount
        // takes no filesystem type or data.
        check(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    dest.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            "bind-mounting the namespace",
        )?;
        loopback_up()
    });
    if result.is_err() {
        let _ = delete_netns(path);
    }
    result
}

/// Sets `lo` up in the calling thread's network namespace.
fn loopback_up() -> io::Result<()> {
    // SAFETY: plain socket(2); the descriptor is owned by `sock` below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor that nothing else owns.
    let sock = unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    // SAFETY: ifreq is a plain C struct; all-zero is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in req.ifr_name.iter_mut().zip(b"lo\0") {
        *dst = *src as libc::c_char;
    }
    // SAFETY: SIOCGIFFLAGS reads the flags into `req`, which outlives the
    // call. The request's type is the platform's (`c_ulong` on glibc,
    // `c_int` on musl), hence `as _`.
    check(
        unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut req) },
        "reading the flags of lo",
    )?;
    // SAFETY: SIOCGIFFLAGS filled the flags member of the union.
    unsafe { req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    // SAFETY: as above; SIOCSIFFLAGS reads `req`.
    check(
        unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &req) },
        "setting lo up",
    )
}

/// Unmounts and removes a namespace file made by [`create_netns`] (or
/// runsc's `null-netns`). Bind mounts can be stacked on one path (sandboxes
/// starting at once), so it unmounts until the path is no mount point.
/// Missing files and files that are not mount points are fine.
pub fn delete_netns(path: &Path) -> io::Result<()> {
    let c = cstr(path)?;
    // A bound of layers, so a path that stays a mount point cannot loop.
    for _ in 0..64 {
        // SAFETY: valid NUL-terminated path; MNT_DETACH needs no other state.
        let rc = unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        if rc == 0 {
            continue;
        }
        let e = io::Error::last_os_error();
        // EINVAL: not (or no longer) a mount point; ENOENT: already gone.
        if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOENT)) {
            break;
        }
        return Err(io::Error::new(
            e.kind(),
            format!("unmounting {}: {e}", path.display()),
        ));
    }
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Opens a TCP connection to `127.0.0.1:<port>` inside the namespace bound
/// at `netns` (the bridge of `trusted` actors, which run in that namespace
/// directly).
pub fn connect_in_netns(netns: &Path, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let netns: PathBuf = netns.to_path_buf();
    on_own_thread("kronik-netns-dial", move || {
        let ns = File::open(&netns)?;
        // SAFETY: ns is an open namespace file; setns only affects this
        // thread, which exits after connecting.
        check(
            unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) },
            "entering the namespace",
        )?;
        TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), timeout)
    })
}

/// The interfaces of the namespace bound at `netns` (from
/// `/proc/thread-self/net/dev`), for checks and tests.
pub fn netns_interfaces(netns: &Path) -> io::Result<Vec<String>> {
    let netns: PathBuf = netns.to_path_buf();
    on_own_thread("kronik-netns-list", move || {
        let ns = File::open(&netns)?;
        // SAFETY: as in connect_in_netns.
        check(
            unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) },
            "entering the namespace",
        )?;
        let dev = fs::read_to_string("/proc/thread-self/net/dev")?;
        Ok(dev
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next().map(|n| n.trim().to_owned()))
            .collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_namespace_has_only_loopback_and_it_is_up() {
        if !is_root() {
            eprintln!("skipped: network namespaces need root");
            return;
        }
        let dir = tempfile::Builder::new()
            .prefix("kronik-netns-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let ns = dir.path().join("ns");
        create_netns(&ns).unwrap();
        assert_eq!(netns_interfaces(&ns).unwrap(), ["lo"]);
        // lo is up: a listener inside the namespace accepts a connection.
        let ns2 = ns.clone();
        let listener = on_own_thread("test-listen", move || {
            let f = File::open(&ns2)?;
            check(
                unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) },
                "setns",
            )?;
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        })
        .unwrap();
        let port = listener.local_addr().unwrap().port();
        connect_in_netns(&ns, port, Duration::from_secs(2)).unwrap();
        // The host's namespace does not see that listener.
        assert!(
            TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                Duration::from_millis(200)
            )
            .is_err()
        );
        delete_netns(&ns).unwrap();
        assert!(!ns.exists());
        // Deleting again is fine.
        delete_netns(&ns).unwrap();
    }
}
