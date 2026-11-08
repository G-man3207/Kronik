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
use std::io::{self, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::subid::{COUNT, Range};

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
        // SAFETY: a checked path; never follow a replacement symbolic link.
        let rc = unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
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

/// `ioctl_ns(2)` requests: the namespace type, and a user namespace's owner.
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const NS_GET_OWNER_UID: libc::c_ulong = 0xb704;

/// capset(2): the version 3 header and the bit of `CAP_SYS_ADMIN`.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAP_SYS_ADMIN: u32 = 1 << 21;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Clears every possessed capability and prevents gaining any through exec.
/// Call in the initial namespace after listener binding, before any threads.
pub fn clear_capabilities() -> io::Result<()> {
    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let none = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: prctl uses scalar arguments; capset reads two version-3 records.
    unsafe {
        check(
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ),
            "clearing ambient capabilities",
        )?;
        check(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
            "PR_SET_NO_NEW_PRIVS",
        )?;
        check(
            libc::syscall(libc::SYS_capset, &raw const header, none.as_ptr()) as libc::c_int,
            "clearing capabilities",
        )
    }
}

/// A `uid_map` or `gid_map`: lines of (inside, outside, count).
pub type IdMap = Vec<[u32; 3]>;

/// The map of the Kronik user namespace for the `kronik` user's `id` and
/// its subordinate `range`: 0 is the user, 1–65535 come from the range
/// (ADR 0060).
pub fn kronik_map(id: u32, range: Range) -> IdMap {
    vec![[0, id, 1], [1, range.start, COUNT - 1]]
}

/// A kernel id map. Malformed/extra fields invalidate the entire map.
pub fn parse_map(text: &str) -> IdMap {
    text.lines()
        .map(|line| {
            let mut f = line.split_whitespace();
            let row = [
                f.next()?.parse().ok()?,
                f.next()?.parse().ok()?,
                f.next()?.parse().ok()?,
            ];
            (f.next().is_none() && row[2] != 0).then_some(row)
        })
        .collect::<Option<IdMap>>()
        .unwrap_or_default()
}

/// A pinned user namespace, as this process sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedUserns {
    /// The uid that owns it (`NS_GET_OWNER_UID`).
    pub owner: u32,
    /// Its uid and gid maps, or why they could not be read: reading them
    /// enters the namespace, which only its owner and root may.
    pub maps: Result<(IdMap, IdMap), String>,
}

/// What [`pin_userns`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin {
    /// No namespace was pinned; one is now.
    Created,
    /// The pinned namespace had the right owner and maps.
    Kept,
}

/// The steps a helper child reports as failed, by index (0 is success).
const STEPS: [&str; 9] = [
    "",
    "PR_SET_KEEPCAPS",
    "setgroups",
    "setresgid",
    "setresuid",
    "capset(CAP_SYS_ADMIN)",
    "unshare(CLONE_NEWUSER)",
    "opening /proc/self/ns/user",
    "setns(CLONE_NEWUSER)",
];

/// A forked child that did one privileged step and then waits, so that its
/// `/proc/<pid>` files stay there, until this is dropped (which kills and
/// reaps it). It may pass back one descriptor.
struct Helper {
    pid: libc::pid_t,
    sock: Option<OwnedFd>,
    fd: Option<OwnedFd>,
}

/// Buffer for one `SCM_RIGHTS` descriptor, aligned for `cmsghdr`.
type CmsgBuf = [u64; 4];

impl Helper {
    /// Forks a child that runs `step`, which returns a descriptor to pass
    /// back or the index of its failed step in [`STEPS`]. `step` runs after
    /// fork in a process that may have other threads: it must make only
    /// system calls, without allocating or taking a lock.
    fn spawn(step: impl FnOnce() -> Result<Option<libc::c_int>, u8>) -> io::Result<Helper> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: socketpair writes two descriptors into `fds`.
        check(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            "socketpair",
        )?;
        // SAFETY: both descriptors are fresh and owned by nothing else.
        let (mine, theirs) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // SAFETY: the child runs only `step` and the system calls below,
        // which neither allocate nor lock, and ends with _exit.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(e.kind(), format!("fork: {e}")));
        }
        if pid == 0 {
            let sock = theirs.as_raw_fd();
            let (status, errno, fd) = match step() {
                Ok(fd) => (0, 0, fd),
                Err(s) => (
                    s,
                    io::Error::last_os_error().raw_os_error().unwrap_or(0),
                    None,
                ),
            };
            send_status(sock, status, errno, fd);
            // Close every other descriptor, the parent's end of the socket
            // included: else the EOF it waits for never comes.
            close_descriptors(3, (sock as u32).saturating_sub(1));
            close_descriptors(sock as u32 + 1, u32::MAX);
            let mut byte = 0u8;
            // SAFETY: reads at most one byte into `byte`; returns when the
            // parent closes its end. Then the child ends without running
            // destructors or atexit handlers.
            unsafe {
                libc::read(sock, (&raw mut byte).cast(), 1);
                libc::_exit(0)
            }
        }
        drop(theirs);
        let mut helper = Helper {
            pid,
            sock: Some(mine),
            fd: None,
        };
        let sock = helper.sock.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let (status, errno, fd) = recv_status(sock)?;
        if status != 0 {
            let e = io::Error::from_raw_os_error(errno);
            let step = STEPS.get(usize::from(status)).copied().unwrap_or("a step");
            return Err(io::Error::new(e.kind(), format!("{step}: {e}")));
        }
        helper.fd = fd;
        Ok(helper)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Closing the socket ends the child (it waits for EOF), so this
        // needs no CAP_KILL for a child that switched users.
        self.sock.take();
        // SAFETY: `pid` is this process's own child, not yet reaped.
        unsafe {
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

/// The child's answer: the status byte, errno, and the descriptor (if any)
/// as `SCM_RIGHTS`. Called after fork: system calls only.
fn send_status(sock: libc::c_int, status: u8, errno: i32, fd: Option<libc::c_int>) {
    let mut msg = [0u8; 5];
    msg[0] = status;
    msg[1..].copy_from_slice(&errno.to_ne_bytes());
    send_with_fd(sock, &msg, fd);
}

/// Sends `payload` as one message, with `fd` as `SCM_RIGHTS` when given.
/// System calls only (safe after fork); returns sendmsg's result.
fn send_with_fd(sock: libc::c_int, payload: &[u8], fd: Option<libc::c_int>) -> isize {
    let mut iov = libc::iovec {
        // sendmsg only reads the buffer.
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut control: CmsgBuf = [0; 4];
    // SAFETY: msghdr is a plain C struct; all-zero is valid. The pointers
    // set below point at locals that outlive sendmsg; CMSG_SPACE of one
    // descriptor (24 bytes) fits `control` (32).
    unsafe {
        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &raw mut iov;
        hdr.msg_iovlen = 1;
        if let Some(fd) = fd {
            let len = std::mem::size_of::<libc::c_int>() as u32;
            hdr.msg_control = control.as_mut_ptr().cast();
            hdr.msg_controllen = libc::CMSG_SPACE(len) as _;
            let c = libc::CMSG_FIRSTHDR(&raw const hdr);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(len) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<libc::c_int>(), fd);
        }
        libc::sendmsg(sock, &raw const hdr, libc::MSG_NOSIGNAL)
    }
}

/// Receives one message into `buf`, with at most one descriptor. Returns
/// its length (0: the other end closed) and the descriptor.
fn recv_with_fd(sock: libc::c_int, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control: CmsgBuf = [0; 4];
    // SAFETY: as in send_with_fd; recvmsg fills `buf` and `control`, which
    // outlive the call, and sets msg_controllen to what it wrote.
    unsafe {
        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &raw mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = control.as_mut_ptr().cast();
        hdr.msg_controllen = std::mem::size_of::<CmsgBuf>() as _;
        let n = libc::recvmsg(sock, &raw mut hdr, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // Every descriptor recvmsg installed is owned here, so that whichever
        // way this returns none of them leaks: the message may carry more
        // than one, in one control message or several.
        let mut received = Vec::new();
        let mut c = libc::CMSG_FIRSTHDR(&raw const hdr);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c).cast::<libc::c_int>();
                let count = ((*c).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<libc::c_int>();
                for i in 0..count {
                    // The descriptor was installed in this process by recvmsg.
                    received.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            c = libc::CMSG_NXTHDR(&raw const hdr, c);
        }
        if hdr.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::other(
                "the peer sent more descriptors than one message may carry",
            ));
        }
        if received.len() > 1 {
            return Err(io::Error::other("the peer sent more than one descriptor"));
        }
        Ok((n as usize, received.pop()))
    }
}

/// Reads a helper's answer (see [`send_status`]).
fn recv_status(sock: libc::c_int) -> io::Result<(u8, i32, Option<OwnedFd>)> {
    let mut msg = [0u8; 5];
    let (n, fd) = recv_with_fd(sock, &mut msg)
        .map_err(|e| io::Error::new(e.kind(), format!("reading the helper's answer: {e}")))?;
    if n != msg.len() {
        return Err(io::Error::other(
            "the helper process ended without an answer",
        ));
    }
    let errno = i32::from_ne_bytes([msg[1], msg[2], msg[3], msg[4]]);
    Ok((msg[0], errno, fd))
}

/// Why the API acceptor cannot report true host uids in this process. The
/// texts are the stable ones that `kronik serve --rootless` logs and
/// `kronik doctor --rootless` reports, so each says what to do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AcceptorRefusal {
    /// The effective uid is 0.
    #[error(
        "the nonroot service runs as the unprivileged service user, not as root: start it with \
         the unit's User=, or run `kronik serve` without --rootless"
    )]
    Root,
    /// The real, effective and saved uids are not one and the same uid.
    #[error(
        "the real, effective and saved user ids are not one and the same (real {real}, \
         effective {effective}, saved {saved}): the acceptor could regain another identity, so \
         the nonroot service refuses to start; start it from a unit with User= and no \
         set-user-id program in between"
    )]
    Uids {
        real: u32,
        effective: u32,
        saved: u32,
    },
    /// The user namespace's uid map is not the identity map of the host.
    #[error(
        "this process is in a user namespace whose uid map is not the host's identity map: \
         the kernel would translate every API caller's uid, so audit records and token \
         attribution would name the wrong users. Rootless containers and nested user \
         namespaces are not supported for the nonroot unit: run the root service \
         (`kronik serve --init --root`), or `kronik serve` without --rootless for development"
    )]
    UserNamespace,
    /// `/proc/self/uid_map` could not be read.
    #[error("reading /proc/self/uid_map: {0}")]
    Unreadable(String),
}

/// Whether an acceptor started by a process with the user ids `ids` (real,
/// effective, saved) and the `uid_map` text could read true host uids from
/// `SO_PEERCRED`: it must be one unprivileged uid, in the initial user
/// namespace's identity map (`0 0 4294967295`).
pub fn check_acceptor_view(uid_map: &str, ids: [u32; 3]) -> Result<(), AcceptorRefusal> {
    let [real, effective, saved] = ids;
    if effective == 0 {
        return Err(AcceptorRefusal::Root);
    }
    if real != effective || saved != effective {
        return Err(AcceptorRefusal::Uids {
            real,
            effective,
            saved,
        });
    }
    let map = parse_map(uid_map);
    if map.len() != 1 || map[0] != [0, 0, u32::MAX] {
        return Err(AcceptorRefusal::UserNamespace);
    }
    Ok(())
}

/// [`check_acceptor_view`] for this process.
pub fn acceptor_view() -> Result<(), AcceptorRefusal> {
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    // SAFETY: getresuid writes three uid_t values into valid locals.
    if unsafe { libc::getresuid(&raw mut real, &raw mut effective, &raw mut saved) } < 0 {
        return Err(AcceptorRefusal::Unreadable(
            io::Error::last_os_error().to_string(),
        ));
    }
    let map = fs::read_to_string("/proc/self/uid_map")
        .map_err(|e| AcceptorRefusal::Unreadable(e.to_string()))?;
    check_acceptor_view(&map, [real, effective, saved])
}

/// The API socket's acceptor of the non-root daemon: a child process that
/// stays in the initial user namespace, as the daemon's user without any
/// capability, accepts on the API's Unix listener and passes each
/// connection on with its peer's uid. The daemon cannot read that uid
/// itself once it is in Kronik's user namespace: the kernel translates
/// `SO_PEERCRED` into the reader's namespace, where host root and every
/// operator are the overflow uid 65534 and the `kronik` user is 0.
pub struct Acceptor {
    pid: libc::pid_t,
    chan: OwnedFd,
}

impl Acceptor {
    /// Forks the acceptor for `listener` (a bound, listening Unix socket),
    /// which this process no longer accepts on. Call it while the process
    /// has one thread, before it enters the user namespace. The child ends
    /// with this process (`PR_SET_PDEATHSIG`) or when the channel closes.
    pub fn spawn(listener: OwnedFd) -> io::Result<Acceptor> {
        if threads()? != 1 {
            return Err(io::Error::other(
                "API acceptor requires one initial-namespace thread",
            ));
        }
        acceptor_view().map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: socketpair writes two descriptors into `fds`.
        check(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            "socketpair",
        )?;
        // SAFETY: both descriptors are fresh and owned by nothing else.
        let (mine, theirs) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // SAFETY: getpid has no preconditions.
        let parent = unsafe { libc::getpid() };
        // SAFETY: the child runs `accept_loop`, system calls only, and never
        // returns.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(e.kind(), format!("fork: {e}")));
        }
        if pid == 0 {
            accept_loop(parent, listener.as_raw_fd(), theirs.as_raw_fd());
        }
        drop(theirs);
        let acceptor = Acceptor { pid, chan: mine };
        let mut ready = [0u8; 1];
        if !matches!(
            recv_with_fd(acceptor.chan.as_raw_fd(), &mut ready)?,
            (1, None)
        ) || ready != [1]
        {
            return Err(io::Error::other(
                "API acceptor failed to drop host authority",
            ));
        }
        Ok(acceptor)
    }

    /// Owned helper identity for supervision and boundary diagnostics.
    pub fn pid(&self) -> u32 {
        self.pid as u32
    }

    /// Waits for the next connection: its descriptor and its peer's host
    /// uid (`u32::MAX` when the acceptor could not read it). Blocking: run
    /// it on a thread of its own.
    pub fn recv(&self) -> io::Result<(OwnedFd, u32)> {
        loop {
            let mut msg = [0u8; 4];
            match recv_with_fd(self.chan.as_raw_fd(), &mut msg) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
                Ok((0, _)) => return Err(io::Error::other("the API socket's acceptor ended")),
                Ok((4, Some(fd))) => return Ok((fd, u32::from_ne_bytes(msg))),
                Ok(_) => return Err(io::Error::other("invalid API acceptor message")),
            }
        }
    }
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        // SAFETY: `pid` is this process's own child, with the same host
        // uid, not yet reaped.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

/// The acceptor child (see [`Acceptor`]). It drops every capability,
/// closes every descriptor but `listener` and `chan`, then accepts until
/// the daemon is gone. System calls only.
fn accept_loop(parent: libc::pid_t, listener: libc::c_int, chan: libc::c_int) -> ! {
    let none = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let (lo, hi) = (
        listener.min(chan) as libc::c_uint,
        listener.max(chan) as libc::c_uint,
    );
    // SAFETY: plain system calls on values made before fork; capset reads
    // `header` and both `none`; accept4 and getsockopt write into locals.
    unsafe {
        if libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        ) != 0
            || libc::getppid() != parent
            || libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                0,
                0,
                0,
            ) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::syscall(libc::SYS_capset, &raw const header, none.as_ptr()) != 0
        {
            libc::_exit(1);
        }
        close_descriptors(3, lo.saturating_sub(1));
        close_descriptors(lo + 1, hi.saturating_sub(1));
        close_descriptors(hi + 1, u32::MAX);
        if send_with_fd(chan, &[1], None) != 1 {
            libc::_exit(1);
        }
        loop {
            let conn = libc::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            );
            if conn < 0 {
                // EMFILE and the like: wait a little rather than spin.
                let pause = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 50_000_000,
                };
                libc::nanosleep(&raw const pause, std::ptr::null_mut());
                continue;
            }
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let uid = if libc::getsockopt(
                conn,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &raw mut len,
            ) == 0
            {
                cred.uid
            } else {
                u32::MAX
            };
            let sent = send_with_fd(chan, &uid.to_ne_bytes(), Some(conn));
            libc::close(conn);
            if sent < 0 {
                // The daemon closed the channel: it is gone or stopping.
                libc::_exit(0);
            }
        }
    }
}

/// Reads `/proc/<pid>/uid_map` and `gid_map`.
fn read_maps(pid: libc::pid_t) -> io::Result<(IdMap, IdMap)> {
    let read = |which: &str| {
        let path = format!("/proc/{pid}/{which}");
        fs::read_to_string(&path)
            .map(|t| parse_map(&t))
            .map_err(|e| io::Error::new(e.kind(), format!("reading {path}: {e}")))
    };
    Ok((read("uid_map")?, read("gid_map")?))
}

/// The user namespace bound at `path`, or `None` when nothing is there or
/// the file is not a user namespace.
pub fn inspect_userns(path: &Path) -> io::Result<Option<PinnedUserns>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let ns = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        r => r.map_err(|e| io::Error::new(e.kind(), format!("opening {}: {e}", path.display())))?,
    };
    inspect_userns_fd(&ns)
}

/// Inspects exactly this open namespace descriptor, without reopening a path.
/// Trusted callers may open an owned PID's procfs namespace magic link and
/// compare its FD metadata first. Map inspection forks a syscall-only helper:
/// call before loading protected key material.
pub fn inspect_userns_fd(ns: &File) -> io::Result<Option<PinnedUserns>> {
    let fd = ns.as_raw_fd();
    // SAFETY: NS_GET_NSTYPE takes no argument; on a file that is no
    // namespace it fails with ENOTTY.
    if unsafe { libc::ioctl(fd, NS_GET_NSTYPE as _) } != libc::CLONE_NEWUSER {
        return Ok(None);
    }
    let mut owner: libc::uid_t = 0;
    // SAFETY: NS_GET_OWNER_UID writes one uid_t into `owner`.
    check(
        unsafe { libc::ioctl(fd, NS_GET_OWNER_UID as _, &raw mut owner) },
        "NS_GET_OWNER_UID",
    )?;
    let maps = Helper::spawn(|| {
        // SAFETY: setns on the inherited descriptor, in the single-threaded
        // child.
        if unsafe { libc::setns(fd, libc::CLONE_NEWUSER) } != 0 {
            return Err(8);
        }
        Ok(None)
    })
    .and_then(|helper| read_maps(helper.pid))
    .map_err(|e| e.to_string());
    Ok(Some(PinnedUserns { owner, maps }))
}

/// Pins the Kronik user namespace at `path` (ADR 0060): owned by `uid`,
/// mapping 0 to `uid`/`gid` and 1–65535 to `uids`/`gids`. Needs root.
///
/// A child switches to `uid` and `gid` but keeps `CAP_SYS_ADMIN`, so that
/// `uid` owns the namespace and its creation is privileged, creates it and
/// passes its file back. This process writes both maps, each in one
/// write(2) as the kernel requires, and bind-mounts the file at `path`
/// (the parent directory is created with mode 0755). A namespace already
/// pinned there with the same owner and maps is kept; mismatches are refused.
pub fn pin_userns(uid: u32, gid: u32, uids: Range, gids: Range, path: &Path) -> io::Result<Pin> {
    if uid == 0
        || gid == 0
        || uid == u32::MAX
        || gid == u32::MAX
        || [uids, gids]
            .iter()
            .any(|r| r.start < crate::subid::FLOOR || r.count < COUNT || r.end().is_none())
        || (uids.start..uids.end().unwrap_or(0)).contains(&uid)
        || (gids.start..gids.end().unwrap_or(0)).contains(&gid)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe namespace identity or subordinate range",
        ));
    }
    root_dir(
        path.parent()
            .ok_or_else(|| io::Error::other("pin has no parent"))?,
    )?;
    let want = (kronik_map(uid, uids), kronik_map(gid, gids));
    let outcome = match inspect_userns(path)? {
        Some(p) if p.owner == uid && p.maps.as_ref().is_ok_and(|m| *m == want) => {
            match validate_owned_userns(path) {
                Ok(_) => {}
                // A crash between the bind mount and the record leaves a
                // namespace that is exactly the wanted one, in a directory
                // only root writes, and no record: without it nothing could
                // unpin it, and the next `pin` would refuse it for good.
                // Only an absent record is repaired; one that disagrees is
                // not (a replacement mounted over the pin keeps failing).
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    let ns = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                        .open(path)?;
                    let pinned = inspect_userns_fd(&ns)?
                        .ok_or_else(|| io::Error::other("pin was replaced by a non-namespace"))?;
                    if pinned.owner != uid || pinned.maps.as_ref().ok() != Some(&want) {
                        return Err(e);
                    }
                    write_pin_record(path, uid, &ns)?;
                }
                Err(e) => return Err(e),
            }
            return Ok(Pin::Kept);
        }
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace a pinned namespace; stop its consumers and unpin its owned token first",
            ));
        }
        None => Pin::Created,
    };
    match fs::symlink_metadata(path.with_extension("owner")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "pin creation record already exists without its namespace",
            ));
        }
    }
    let helper = Helper::spawn(|| {
        let caps = [
            CapData {
                effective: CAP_SYS_ADMIN,
                permitted: CAP_SYS_ADMIN,
                inheritable: 0,
            },
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        let header = CapHeader {
            version: CAPABILITY_VERSION_3,
            pid: 0,
        };
        // SAFETY: plain system calls in the child on values made before
        // fork; capset reads `header` and two `caps` (version 3).
        unsafe {
            if libc::prctl(libc::PR_SET_KEEPCAPS, 1 as libc::c_ulong, 0, 0, 0) != 0 {
                return Err(1);
            }
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(2);
            }
            if libc::setresgid(gid, gid, gid) != 0 {
                return Err(3);
            }
            if libc::setresuid(uid, uid, uid) != 0 {
                return Err(4);
            }
            if libc::syscall(libc::SYS_capset, &raw const header, caps.as_ptr()) != 0 {
                return Err(5);
            }
            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                return Err(6);
            }
            let fd = libc::open(
                c"/proc/self/ns/user".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                return Err(7);
            }
            Ok(Some(fd))
        }
    })
    .map_err(|e| io::Error::new(e.kind(), format!("creating the user namespace: {e}")))?;
    let ns = helper
        .fd
        .as_ref()
        .ok_or_else(|| io::Error::other("the helper passed no namespace"))?;
    for (which, map) in [("uid_map", &want.0), ("gid_map", &want.1)] {
        let file = format!("/proc/{}/{which}", helper.pid);
        let text: String = map
            .iter()
            .map(|[a, b, c]| format!("{a} {b} {c}\n"))
            .collect();
        let written = OpenOptions::new()
            .write(true)
            .open(&file)
            .and_then(|mut f| f.write(text.as_bytes()))
            .map_err(|e| io::Error::new(e.kind(), format!("writing {file}: {e}")))?;
        if written != text.len() {
            return Err(io::Error::other(format!("writing {file}: short write")));
        }
    }
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| io::Error::new(e.kind(), format!("creating {}: {e}", path.display())))?;
    }
    let source = CString::new(format!("/proc/self/fd/{}", ns.as_raw_fd()))
        .map_err(|_| io::Error::other("descriptor path"))?;
    let dest = cstr(path)?;
    // SAFETY: both strings are valid NUL-terminated paths; a bind mount
    // takes no filesystem type or data.
    let mounted = check(
        unsafe {
            libc::mount(
                source.as_ptr(),
                dest.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        "bind-mounting the user namespace",
    );
    drop(helper);
    if mounted.is_err() {
        let _ = fs::remove_file(path);
    }
    mounted?;
    write_pin_record(path, uid, &File::open(path)?)?;
    Ok(outcome)
}

/// The record that proves this process made the pin: the owner and the
/// identity of the namespace `ns` is open on. `unpin` removes only a pin whose
/// record matches.
fn write_pin_record(path: &Path, uid: u32, ns: &File) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let meta = ns.metadata()?;
    let mut token = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.with_extension("owner"))?;
    writeln!(token, "1 {} {} {}", uid, meta.dev(), meta.ino())?;
    token.sync_all()
}

fn owned_userns_file(path: &Path) -> io::Result<Option<File>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
        Ok(meta) if !meta.is_file() => return Err(io::Error::other("pin is not a namespace file")),
        Ok(_) => {}
    }
    root_dir(
        path.parent()
            .ok_or_else(|| io::Error::other("pin has no parent"))?,
    )?;
    let ns = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    let record = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.with_extension("owner"))?;
    let meta = record.metadata()?;
    if meta.uid() != 0 || meta.mode() & 0o077 != 0 || !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted pin creation record",
        ));
    }
    use std::io::Read as _;
    let mut text = String::new();
    record.take(256).read_to_string(&mut text)?;
    let pinned = inspect_userns_fd(&ns)?
        .ok_or_else(|| io::Error::other("pin was replaced by a non-namespace"))?;
    let meta = ns.metadata()?;
    if text != format!("1 {} {} {}\n", pinned.owner, meta.dev(), meta.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pin creation token does not match",
        ));
    }
    let current = fs::symlink_metadata(path)?;
    if current.dev() != meta.dev() || current.ino() != meta.ino() {
        return Err(io::Error::other("pin changed during cleanup"));
    }
    Ok(Some(ns))
}

/// Read-only admission for explicit unpin, including dry-run.
pub fn validate_owned_userns(path: &Path) -> io::Result<bool> {
    Ok(owned_userns_file(path)?.is_some())
}

/// Removes only a namespace matching its root-owned creation record.
pub fn unpin_userns(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let Some(ns) = owned_userns_file(path)? else {
        return Ok(false);
    };
    let held = ns.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
        return Err(io::Error::other("pin changed before unmount"));
    }
    let target = cstr(path)?;
    // SAFETY: checked root-owned mount point; do not follow symbolic links.
    check(
        unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) },
        "unpinning userns",
    )?;
    fs::remove_file(path)?;
    fs::remove_file(path.with_extension("owner"))?;
    Ok(true)
}

/// Creates `dir` (its parent must exist) with mode 0755, or checks that it
/// is a directory owned by root and no symbolic link: the pin never
/// follows a path that another user could have planted.
fn root_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    let shown = |e: io::Error| io::Error::new(e.kind(), format!("creating {}: {e}", dir.display()));
    if !dir.is_absolute()
        || dir
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pin parent must be absolute without traversal",
        ));
    }
    for ancestor in dir.ancestors().skip(1) {
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir() || m.uid() != 0 || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted pin ancestor",
            ));
        }
    }
    match fs::DirBuilder::new().mode(0o755).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(shown(e)),
        _ => {}
    }
    let m = fs::symlink_metadata(dir).map_err(shown)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a directory owned by root", dir.display()),
        ));
    }
    Ok(())
}

/// The number of threads of this process (`/proc/self/status`).
fn threads() -> io::Result<u64> {
    let status = fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|n| n.trim().parse().ok())
        .ok_or_else(|| io::Error::other("/proc/self/status has no Threads line"))
}

/// The number of threads of this process once it has settled to `at_most` or
/// below. A thread that has been joined is still counted by the kernel for a
/// moment, until it has left the thread group, so a process that has just
/// dropped a runtime can show one more than it has: a count above `at_most` is
/// read again, for up to two seconds, before it is believed.
pub fn threads_settled(at_most: u64) -> io::Result<u64> {
    let mut seen = threads()?;
    for _ in 0..400 {
        if seen <= at_most {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        seen = threads()?;
    }
    Ok(seen)
}

/// Moves this process into the user namespace pinned at `path`, then into
/// a private mount namespace of its own whose `/` receives the host's
/// mounts but does not send its own (the network namespaces' bind mounts).
/// From then on the process is uid 0 inside: no capability in the initial
/// namespace, all capabilities in Kronik's.
///
/// Refused unless the process has one thread (the kernel requires it; call
/// this before any thread starts), the namespace is owned by this
/// process's uid, and its uid and gid maps are `maps` exactly: never a
/// namespace that maps host root, or ids that are not ours.
pub fn enter_userns(path: &Path, maps: &(IdMap, IdMap)) -> io::Result<()> {
    let n = threads()?;
    if n != 1 {
        return Err(io::Error::other(format!(
            "entering the user namespace {} needs a process with one thread, not {n}",
            path.display()
        )));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    let safe = |map: &IdMap, owner: u32| {
        map.len() == 2
            && map[0] == [0, owner, 1]
            && owner != 0
            && map[1][0] == 1
            && map[1][1] >= crate::subid::FLOOR
            && map[1][2] == COUNT - 1
            && map[1][1]
                .checked_add(map[1][2])
                .is_some_and(|end| !(map[1][1]..end).contains(&owner))
    };
    // SAFETY: getegid has no preconditions and cannot fail.
    if !safe(&maps.0, me) || !safe(&maps.1, unsafe { libc::getegid() }) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe namespace map",
        ));
    }
    use std::os::unix::fs::OpenOptionsExt as _;
    let ns = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    match inspect_userns_fd(&ns)? {
        None => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is no pinned user namespace", path.display()),
            ));
        }
        Some(p) if p.owner != me => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "the user namespace {} is owned by uid {}, not by this process's uid {me}",
                    path.display(),
                    p.owner
                ),
            ));
        }
        Some(p) => match p.maps {
            Ok(m) if m == *maps => {}
            Ok(m) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "the user namespace {} maps uids {:?} and gids {:?}, not {:?} and {:?}",
                        path.display(),
                        m.0,
                        m.1,
                        maps.0,
                        maps.1
                    ),
                ));
            }
            Err(e) => {
                return Err(io::Error::other(format!(
                    "reading the maps of {}: {e}",
                    path.display()
                )));
            }
        },
    }
    // SAFETY: setns on an open namespace file; it changes this process's
    // credentials and nothing in memory.
    if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWUSER) } != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(
            e.kind(),
            format!("entering the user namespace {}: {e}", path.display()),
        ));
    }
    // SAFETY: unshare without shared state; allowed with CAP_SYS_ADMIN in
    // the namespace just entered.
    check(
        unsafe { libc::unshare(libc::CLONE_NEWNS) },
        "unshare(CLONE_NEWNS)",
    )?;
    // SAFETY: a propagation change takes no source, type or data.
    check(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_SLAVE,
                std::ptr::null(),
            )
        },
        "making / a slave mount",
    )
}

/// This process's cgroup v2 path (`0::<path>` in `/proc/self/cgroup`):
/// `/` inside a private cgroup namespace (`ProtectControlGroups=private`,
/// systemd 257), `/system.slice/kronik.service` without one.
pub fn own_cgroup() -> io::Result<String> {
    let text = fs::read_to_string("/proc/self/cgroup")?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("/proc/self/cgroup has no cgroup v2 entry"))
}

/// The directory of `cgroup` under `/sys/fs/cgroup`.
pub fn cgroup_dir(cgroup: &str) -> PathBuf {
    Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'))
}

/// Whether this process may move processes into `cgroup` and turn on its
/// children's controllers: systemd delegated it (`Delegate=yes`).
pub fn cgroup_delegated(cgroup: &str) -> bool {
    let dir = cgroup_dir(cgroup);
    ["cgroup.procs", "cgroup.subtree_control"]
        .iter()
        .all(|f| OpenOptions::new().write(true).open(dir.join(f)).is_ok())
}

/// When this process's cgroup C is delegated to it, moves the process into
/// `C/daemon` and returns C, under which the sandboxes' cgroups then go
/// (ADR 0061): a cgroup whose children get controllers may hold no process
/// itself. `None` when C is not delegated.
pub fn cgroup_leaf() -> io::Result<Option<String>> {
    let own = own_cgroup()?;
    if !cgroup_delegated(&own) {
        return Ok(None);
    }
    let leaf = cgroup_dir(&own).join("daemon");
    match fs::create_dir(&leaf) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
            return Err(io::Error::new(
                e.kind(),
                format!("creating {}: {e}", leaf.display()),
            ));
        }
        _ => {}
    }
    fs::write(leaf.join("cgroup.procs"), std::process::id().to_string())
        .map_err(|e| io::Error::new(e.kind(), format!("moving into {}: {e}", leaf.display())))?;
    Ok(Some(own))
}

/// Makes this process `uid` and `gid` for good, without supplementary
/// groups: an offline command run as root that works on the non-root
/// daemon's data directory. Call it while the process has one thread.
pub fn become_user(uid: u32, gid: u32) -> io::Result<()> {
    if uid == 0 || gid == 0 || uid == u32::MAX || gid == u32::MAX || threads_settled(1)? != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "becoming a service user requires valid nonroot IDs and one thread",
        ));
    }
    // SAFETY: plain credential system calls; setgroups reads no memory
    // with a count of 0.
    unsafe {
        check(libc::setgroups(0, std::ptr::null()), "setgroups")?;
        check(libc::setresgid(gid, gid, gid), "setresgid")?;
        check(libc::setresuid(uid, uid, uid), "setresuid")?;
        // UID transitions reset dumpability; protect preloaded keys before
        // any later capability/NNP operation can fail.
        check(
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0),
            "PR_SET_DUMPABLE",
        )?;
    }
    clear_capabilities()
}

/// Trusted executable-fixture seam, not a daemon option: expose only owned
/// identity/runtime directories in a private mount view. It does not isolate
/// PID 1 or systemctl; installed-service tests need their own service manager.
pub fn bootstrap_owned_rootless_fixture(etc: &Path, run: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    if !is_root() || threads()? != 1 {
        return Err(io::Error::other(
            "fixture bootstrap requires one root thread",
        ));
    }
    let open = |path: &Path| -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)?;
        let meta = file.metadata()?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture view is not privately root-owned",
            ));
        }
        Ok(file)
    };
    // SAFETY: one setup thread; mount propagation is cut before either bind.
    check(
        unsafe { libc::unshare(libc::CLONE_NEWNS) },
        "unsharing fixture mounts",
    )?;
    check(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                std::ptr::null(),
            )
        },
        "privatizing fixture mounts",
    )?;
    // Ordinary directory FDs from the old mount namespace cannot be bind sources here.
    let sources = [open(etc)?, open(run)?];
    for (file, target) in sources.iter().zip([c"/etc", c"/run"]) {
        let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| io::Error::other("descriptor path"))?;
        let context = if target == c"/etc" {
            "binding owned /etc fixture view"
        } else {
            "binding owned /run fixture view"
        };
        // SAFETY: source descriptor is held and target is one fixed directory.
        check(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            context,
        )?;
    }
    Ok(())
}

/// Fixed inputs for the child-only Firecracker jail; never an operator command template.
pub struct MicrovmJail<'a> {
    pub root: &'a Path,
    pub cgroup: &'a str,
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub firecracker: &'a Path,
    pub kernel: &'a Path,
    pub initrd: &'a Path,
    pub rootfs: &'a Path,
    pub data: &'a Path,
    pub output: &'a Path,
    pub parent_pid: u32,
}

// Classic BPF and seccomp, for `deny_io_uring`: the four instructions it uses
// (BPF_LD|BPF_W|BPF_ABS, BPF_JMP|BPF_JEQ|BPF_K, BPF_JMP|BPF_JSET|BPF_K,
// BPF_RET|BPF_K), the offsets of `struct seccomp_data` (nr at 0, arch at 4) and
// the return values.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;
/// The x32 ABI keeps the architecture value of x86-64 and marks its system call
/// numbers with this bit, so that its `io_uring_setup` is not the number a
/// filter compares with.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;

/// Makes `io_uring_setup`, `io_uring_enter` and `io_uring_register` fail with
/// `EPERM` in this process and in everything it executes, forever (a seccomp
/// filter cannot be removed, survives `exec` and stacks with the filters that
/// the program installs for itself: the strictest answer of all of them wins).
///
/// Firecracker's own filter allows these calls in its VMM thread, for its
/// asynchronous block engine, and io_uring can symlink, make directories,
/// rename and unlink (`IORING_OP_SYMLINKAT`, `MKDIRAT`, `RENAMEAT`,
/// `UNLINKAT`) without any of the plain system calls that the same filter
/// denies: a VMM compromised by a guest escape could change its jail's
/// directories despite the short list. Kronik uses the synchronous engine, so
/// nothing needs them.
///
/// The program, eleven instructions: a process of another architecture than
/// this one is killed (its numbers mean something else), and so is a call with
/// the x32 bit set (see [`X32_SYSCALL_BIT`]); the three numbers answer `EPERM`;
/// everything else is left to the other filters. Call it after the last step
/// that needs privilege; it sets `no_new_privs` itself.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn deny_io_uring() -> io::Result<()> {
    let mut program = io_uring_filter();
    let filter = libc::sock_fprog {
        len: program.len() as libc::c_ushort,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: prctl with scalar arguments.
    check(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        "PR_SET_NO_NEW_PRIVS",
    )?;
    // SAFETY: the kernel copies the program out of `filter` and `program`,
    // which live until this returns.
    check(
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &raw const filter,
            )
        },
        "installing the io_uring filter",
    )
}

/// The filter of [`deny_io_uring`]. Jumps are forward and relative to the next
/// instruction.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn io_uring_filter() -> [libc::sock_filter; 11] {
    let op = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    [
        // 0-2: only this architecture's numbers are understood below.
        op(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH),
        op(BPF_JEQ_K, 1, 0, AUDIT_ARCH_NATIVE),
        op(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        // 3-5: nor the x32 flavour of them.
        op(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR),
        op(BPF_JSET_K, 0, 1, X32_SYSCALL_BIT),
        op(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        // 6-8: the three calls go to the last instruction.
        op(BPF_JEQ_K, 3, 0, libc::SYS_io_uring_setup as u32),
        op(BPF_JEQ_K, 2, 0, libc::SYS_io_uring_enter as u32),
        op(BPF_JEQ_K, 1, 0, libc::SYS_io_uring_register as u32),
        // 9: everything else is for the filters of the program itself.
        op(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
        // 10
        op(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ]
}

/// Other architectures than the two Kronik supports have no filter here.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn deny_io_uring() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no io_uring filter for this architecture",
    ))
}

/// Installs the VMM's fixed jail in its single-threaded launcher process.
/// Every resource write is mandatory: delegation errors never remove limits.
pub fn jail_microvm(jail: &MicrovmJail<'_>) -> io::Result<()> {
    if threads()? != 1 || jail.cpu_millis == 0 || jail.memory_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid microVM launcher or limits",
        ));
    }
    // SAFETY: scalar prctl/getppid; check the parent after arming the signal.
    unsafe {
        check(
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0),
            "PR_SET_PDEATHSIG",
        )?;
        if libc::getppid() as u32 != jail.parent_pid {
            return Err(io::Error::other("microVM launcher parent changed"));
        }
    }
    let own = own_cgroup()?;
    let delegated = own
        .strip_suffix("/daemon")
        .ok_or_else(|| io::Error::other("microVM launcher is outside the daemon cgroup leaf"))?;
    validate_child_cgroup(delegated, jail.cgroup)?;
    let parent = cgroup_dir(delegated);
    fs::write(parent.join("cgroup.subtree_control"), "+cpu +memory +pids")?;
    let group = cgroup_dir(jail.cgroup);
    fs::create_dir(&group)?;
    fs::write(
        group.join("cpu.max"),
        format!("{} 100000", u64::from(jail.cpu_millis) * 100),
    )?;
    fs::write(group.join("memory.max"), jail.memory_bytes.to_string())?;
    fs::write(group.join("memory.swap.max"), "0")?;
    fs::write(group.join("pids.max"), "1024")?;
    fs::write(group.join("cgroup.procs"), std::process::id().to_string())?;
    isolate(jail, Path::new("/dev/kvm"))
}

/// The rest of the jail, after the cgroup: new namespaces, a fork into the PID
/// one, the mounts and the capabilities. It returns in the child only, which is
/// init of the new PID namespace and goes on to exec the VMM. The process that
/// called it, still in the VM's cgroup and so under its limits, gives up every
/// capability, waits for that child and exits with its status.
///
/// The VMM has a PID namespace of its own because a process that escapes the
/// guest must not be able to address any process of the host. Firecracker's
/// seccomp filter lets `tkill` through for two signals but looks at no thread
/// id, and "the daemon's uid" on a root installation is every root process of
/// the host, PID 1 included: systemd's SIGABRT handler freezes the manager.
/// In a namespace of its own, `kill(1, ...)` is the VMM itself and every host
/// thread id is `ESRCH`.
pub(crate) fn isolate(jail: &MicrovmJail<'_>, kvm: &Path) -> io::Result<()> {
    // SAFETY: only this launcher is affected; no shared runtime threads exist.
    check(
        unsafe {
            libc::unshare(
                libc::CLONE_NEWNS
                    | libc::CLONE_NEWNET
                    | libc::CLONE_NEWIPC
                    | libc::CLONE_NEWUTS
                    | libc::CLONE_NEWCGROUP
                    | libc::CLONE_NEWPID,
            )
        },
        "unsharing microVM namespaces",
    )?;
    match fork_into_pid_namespace()? {
        Forked::Parent(child) => {
            // Waiting needs no privilege, and this process shares the jail's
            // mount namespace: nothing it holds may outlive the setup.
            seal_capabilities()?;
            std::process::exit(child.wait()?)
        }
        Forked::Child => {}
    }
    jail_mounts(jail, kvm)?;
    seal_capabilities()
}

/// What no process of the jail may gain back through `exec`. The bounding set
/// decides what an `exec` as uid 0 can gain (root's file capabilities count as
/// all ones), so it is emptied: every capability the kernel has, which needs
/// `CAP_SETPCAP`; `EINVAL` marks a number past the last one. Then the secure
/// bits make uid 0 an ordinary uid for `exec` and cannot be undone, and the
/// rest is cleared as [`clear_capabilities`] does. Without this only
/// `no_new_privs` stands between a root VMM and the capabilities of root.
fn seal_capabilities() -> io::Result<()> {
    for cap in 0..64 {
        // SAFETY: prctl with scalar arguments.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) } != 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(io::Error::new(
                e.kind(),
                format!("dropping capability {cap} from the bounding set: {e}"),
            ));
        }
    }
    // SAFETY: prctl with scalar arguments.
    check(
        unsafe {
            libc::prctl(
                libc::PR_SET_SECUREBITS,
                SECBIT_NOROOT | SECBIT_NOROOT_LOCKED,
                0,
                0,
                0,
            )
        },
        "PR_SET_SECUREBITS",
    )?;
    clear_capabilities()
}

// The secure bits of linux/securebits.h that `seal_capabilities` sets.
const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;

/// The two ways out of [`fork_into_pid_namespace`], one in each process.
pub(crate) enum Forked {
    /// In the child, which is init of the new PID namespace.
    Child,
    /// In the caller: the child to wait for.
    Parent(Waiting),
}

/// The child of a fork into a new PID namespace, as its parent sees it.
pub(crate) struct Waiting {
    pid: libc::pid_t,
    /// The write end of the pipe whose closing tells the child that its
    /// parent is gone; it lives as long as the parent does.
    _alive: OwnedFd,
}

impl Waiting {
    /// The child's pid in the caller's PID namespace.
    #[cfg(test)]
    pub(crate) fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Waits for the child and returns the code to exit with: its exit status,
    /// or 128 plus the signal that ended it.
    pub(crate) fn wait(self) -> io::Result<i32> {
        let mut raw: libc::c_int = 0;
        loop {
            // SAFETY: `pid` is this process's own child, not yet reaped.
            let reaped = unsafe { libc::waitpid(self.pid, &raw mut raw, 0) };
            if reaped == self.pid {
                return Ok(exit_code(raw));
            }
            let e = io::Error::last_os_error();
            if reaped < 0 && e.kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::new(
                    e.kind(),
                    format!("waiting for the VMM: {e}"),
                ));
            }
        }
    }
}

/// The exit code that stands for a `wait` status: the exit status, or 128 plus
/// the number of the signal that ended the process (as a shell reports it).
pub(crate) fn exit_code(raw: libc::c_int) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    let status = std::process::ExitStatus::from_raw(raw);
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// Forks the first child into the PID namespace that the caller has just
/// unshared (`unshare(CLONE_NEWPID)` puts only children into it, never the
/// caller): the child is its init, pid 1.
///
/// Fork clears the parent-death signal, so the child arms it again, and then
/// looks at a pipe whose write end only the parent holds: if the parent died
/// before the signal was armed, the pipe is closed and the child ends rather
/// than run without a parent (`getppid()` cannot tell: it is 0 for the init
/// of a namespace whose parent is outside). The signal reaches a namespace's
/// init because its sender is outside the namespace, and killing it kills
/// everything in the namespace.
///
/// The caller must have one thread: only the forking thread survives in the
/// child, and the signal fires when that thread ends.
pub(crate) fn fork_into_pid_namespace() -> io::Result<Forked> {
    let mut ends = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two descriptors.
    check(
        unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
        "pipe2",
    )?;
    // SAFETY: both are fresh and owned here.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
    // SAFETY: the caller has one thread, so the child cannot inherit a lock
    // that another thread holds; it runs on in the same stack frames.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(
            e.kind(),
            format!("forking into the PID namespace: {e}"),
        ));
    }
    if pid > 0 {
        drop(read);
        return Ok(Forked::Parent(Waiting { pid, _alive: write }));
    }
    drop(write);
    // SAFETY: prctl with scalar arguments.
    check(
        unsafe {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            )
        },
        "PR_SET_PDEATHSIG",
    )?;
    let mut probe = libc::pollfd {
        fd: read.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    // SAFETY: poll reads and writes one pollfd; a zero timeout does not block.
    if unsafe { libc::poll(&raw mut probe, 1, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if probe.revents & libc::POLLHUP != 0 {
        return Err(io::Error::other(
            "the microVM launcher died before its VMM started",
        ));
    }
    Ok(Forked::Child)
}

// statvfs(3) `f_flag` bits of a mount.
const ST_RDONLY: libc::c_ulong = 1;
const ST_NOSUID: libc::c_ulong = 2;
const ST_NODEV: libc::c_ulong = 4;
pub(crate) const ST_NOEXEC: libc::c_ulong = 8;

/// The mount flag of a source mount that a read-only bind of it must carry.
/// In a user namespace the kernel locks `noexec`, `nosuid`, `nodev`, read-only
/// and the atime mode of every mount it inherited, and a remount may not
/// clear a locked flag. Read-only, `nosuid` and `nodev` are always named. A
/// remount that names no flag clears `noexec`, so `noexec` has to be named
/// when the source has it (otherwise `EPERM`). The atime mode must not be
/// named: a remount that names none keeps the mount's atime mode (kernel
/// `path_mount`: "the default atime for remount is preservation"), whereas
/// naming some of its flags, `nodiratime` without `strictatime` for example,
/// makes the kernel add its default `relatime`, which differs from the locked
/// mode and fails.
fn carried_mount_flags(f_flag: libc::c_ulong) -> libc::c_ulong {
    if f_flag & ST_NOEXEC != 0 {
        libc::MS_NOEXEC
    } else {
        0
    }
}

/// The flags of the mount that `file` is on (`fstatvfs(3)`).
pub(crate) fn mount_flags(file: &File) -> io::Result<libc::c_ulong> {
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: fstatvfs writes one statvfs into the buffer for a live descriptor.
    check(
        unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) },
        "reading the flags of a microVM input's mount",
    )?;
    // SAFETY: fstatvfs succeeded and initialized it.
    Ok(unsafe { stat.assume_init() }.f_flag)
}

/// The mount half of the jail, in the mount namespace the caller made: makes
/// the mounts private, binds the fixed inputs into the jail root (the
/// read-only ones read-only, nosuid and nodev, with the source mount's other
/// flags), pivots into the root and detaches the old one. `kvm` is the device
/// to bind; a test passes a regular file.
pub(crate) fn jail_mounts(jail: &MicrovmJail<'_>, kvm: &Path) -> io::Result<()> {
    // SAFETY: only this process's mount namespace is affected.
    check(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        "making microVM mounts private",
    )?;
    let root = cstr(jail.root)?;
    // SAFETY: bind the precreated private directory onto itself for pivot_root.
    check(
        unsafe {
            libc::mount(
                root.as_ptr(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        "binding microVM root",
    )?;
    for (source, target, readonly, directory) in [
        (jail.firecracker, "firecracker", true, false),
        (jail.kernel, "vmlinux", true, false),
        (jail.initrd, "initrd", true, false),
        (jail.rootfs, "root.ext4", true, false),
        (jail.data, "data.ext4", false, false),
        (jail.output, "out", false, true),
        (kvm, "dev/kvm", false, false),
    ] {
        bind_input(jail.root, source, target, readonly, directory)?;
    }
    // Nothing the daemon left open may follow the VMM into its jail: a
    // descriptor on a host directory is a way out of any root. The launcher
    // is single-threaded and has opened nothing it still needs.
    close_descriptors(3, u32::MAX);
    let old = jail.root.join(".old");
    fs::create_dir(&old)?;
    let old = cstr(&old)?;
    // SAFETY: both paths refer to private mounts created above.
    check(
        unsafe { libc::syscall(libc::SYS_pivot_root, root.as_ptr(), old.as_ptr()) as libc::c_int },
        "pivot_root",
    )?;
    std::env::set_current_dir("/")?;
    check(
        unsafe { libc::umount2(c"/.old".as_ptr(), libc::MNT_DETACH) },
        "detaching old microVM root",
    )?;
    fs::remove_dir("/.old")?;
    Ok(())
}

/// The system call number of `openat2` (Linux 5.6): the same on every
/// architecture that uses the generic table, x86-64 and aarch64 included.
const SYS_OPENAT2: libc::c_long = 437;

/// Opens the entry `name` of the directory `dir`, a socket that a process the
/// daemon does not trust can rename or replace, without following a symbolic
/// link, and returns a descriptor that stands for the entry itself (`O_PATH`)
/// once it is known to be a socket that `owner` made.
///
/// `connect(2)` to a path follows links, so a link planted in place of the
/// socket would be connected to with the caller's authority, and whatever a
/// connection to that socket does would happen. The descriptor names the inode
/// that was checked whatever the name becomes afterwards: connecting to
/// `/proc/self/fd/<n>` (see [`fd_path`]) reaches that inode and no other.
/// `name` is one plain component; no link on the way is followed
/// (`RESOLVE_NO_SYMLINKS`), and none that the kernel makes up (`/proc` links).
pub fn open_socket_entry(dir: &Path, name: &str, owner: u32) -> io::Result<OwnedFd> {
    use std::os::unix::fs::OpenOptionsExt as _;
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not the plain name of a socket"),
        ));
    }
    // The directory is the daemon's own path to the jail: by path, as a path.
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(dir)?;
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: open_how is a plain C struct; zero is a valid value for every field.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_BENEATH;
    // SAFETY: `name` is a NUL-terminated string and `how` a live open_how of the
    // size passed; the kernel only reads them.
    let raw = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dir.as_raw_fd(),
            name.as_ptr(),
            &raw const how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if raw < 0 {
        return Err(explain_openat2(io::Error::last_os_error()));
    }
    // SAFETY: openat2 returned a new descriptor that nothing else owns.
    let entry = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };
    // SAFETY: stat is a plain C struct that fstat fills in for a live descriptor.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    check(
        unsafe { libc::fstat(entry.as_raw_fd(), &raw mut stat) },
        "fstat",
    )?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the entry is not a socket (a link, a file or a directory in its place)",
        ));
    }
    if stat.st_uid != owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the socket belongs to user {}, not {owner}", stat.st_uid),
        ));
    }
    Ok(entry)
}

/// What a failed `openat2` means to the operator. `ENOSYS` is not a bug of the
/// daemon: the kernel is older than Linux 5.6, or the service runs with
/// `RestrictSUIDSGID=yes`, which makes systemd's seccomp filter answer `ENOSYS`
/// to every `openat2` because the filter cannot read the flags in its argument
/// (ADR 0027). An operator who adds that setting to a drop-in as hardening would
/// otherwise get a microVM that never starts and "function not implemented".
fn explain_openat2(error: io::Error) -> io::Error {
    if error.raw_os_error() == Some(libc::ENOSYS) {
        return io::Error::new(
            io::ErrorKind::Unsupported,
            "openat2 is not available to the daemon: the kernel is older than Linux 5.6, or the service runs with RestrictSUIDSGID=yes, whose seccomp filter answers ENOSYS to openat2 (ADR 0027); remove that setting from the unit and its drop-ins",
        );
    }
    error
}

/// The path through which `connect(2)` reaches exactly the inode that `fd`
/// stands for, as long as `fd` is open.
pub fn fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// The effective user id of this process.
pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Closes every descriptor from `from` through `to`. `close_range` does it in
/// one call (Linux 5.9); where the kernel lacks it, or a filter refuses it,
/// each possible descriptor up to the process's hard limit is closed on its
/// own (the daemon supports Linux 5.6). A descriptor that survives into a
/// sandbox is a hole, so a failure to ask is not a reason to leave them open.
/// System calls only: it runs in forked children.
pub(crate) fn close_descriptors(from: u32, to: u32) {
    if from > to {
        return;
    }
    // SAFETY: close_range takes plain numbers.
    if unsafe { libc::syscall(libc::SYS_close_range, from, to, 0u32) } == 0 {
        return;
    }
    close_range_by_hand(from, to);
}

/// What [`close_descriptors`] does where `close_range` fails.
fn close_range_by_hand(from: u32, to: u32) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit.
    let known = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0;
    // An unlimited or unreadable limit is capped, not walked to the end.
    let highest = if known {
        limit.rlim_max.min(1 << 20)
    } else {
        1 << 20
    };
    let last = u64::from(to).min(highest.max(u64::from(from)));
    for fd in u64::from(from)..=last {
        // SAFETY: closing a number that is not open fails with EBADF; one that
        // is open belongs to no live object of this process by the callers' contract.
        unsafe { libc::close(fd as libc::c_int) };
    }
}

/// Binds `source` onto the placeholder `root/target`. A read-only input is
/// then remounted read-only, nosuid and nodev.
///
/// The remount goes through a descriptor opened after the bind. A descriptor
/// opened on the placeholder before it keeps naming the placeholder under the
/// new mount, so a remount through its `/proc/self/fd` path fails with
/// `EINVAL` and leaves the input writable. The source mount's own flags are
/// carried (see [`carried_mount_flags`]), and the outcome is checked, so a
/// remount that did not take cannot pass for a read-only input.
fn bind_input(
    root: &Path,
    source: &Path,
    target: &str,
    readonly: bool,
    directory: bool,
) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let open = |path: &Path| {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    };
    let descriptor_path = |file: &File| {
        CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| io::Error::other("descriptor path"))
    };
    let src = open(source)?;
    let placeholder = open(&root.join(target))?;
    let metadata = src.metadata()?;
    if metadata.is_dir() != directory || (!directory && target != "dev/kvm" && !metadata.is_file())
    {
        return Err(io::Error::other("invalid microVM mount source type"));
    }
    let from = descriptor_path(&src)?;
    let onto = descriptor_path(&placeholder)?;
    // SAFETY: both descriptors stay open throughout the bind.
    check(
        unsafe {
            libc::mount(
                from.as_ptr(),
                onto.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        "binding microVM input",
    )?;
    if !readonly {
        return Ok(());
    }
    let carried = carried_mount_flags(mount_flags(&src)?);
    let mounted = open(&root.join(target))?;
    let onto = descriptor_path(&mounted)?;
    // SAFETY: the descriptor stays open throughout the remount.
    check(
        unsafe {
            libc::mount(
                std::ptr::null(),
                onto.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV
                    | carried,
                std::ptr::null(),
            )
        },
        "making microVM input read-only",
    )?;
    // Read-only, nosuid and nodev are always asked for, and noexec when the
    // source mount has it.
    let wanted = ST_RDONLY | ST_NOSUID | ST_NODEV | (mount_flags(&src)? & ST_NOEXEC);
    if mount_flags(&mounted)? & wanted != wanted {
        return Err(io::Error::other(
            "a microVM input is not read-only, nosuid and nodev (with the source's noexec) after its remount",
        ));
    }
    Ok(())
}

fn validate_child_cgroup(parent: &str, child: &str) -> io::Result<()> {
    let valid = child.starts_with('/')
        && !child.as_bytes().contains(&0)
        && child
            .split('/')
            .skip(1)
            .all(|c| !c.is_empty() && c != "." && c != "..")
        && child
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1);
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "microVM cgroup escapes delegated subtree",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_maps_never_validate_a_prefix() {
        assert_eq!(
            parse_map("0 1000 1\n1 200000 65535\n"),
            [[0, 1000, 1], [1, 200000, 65535]]
        );
        for text in ["0 1000 1 extra\n", "0 1000 1\nbroken\n", "0 1000 0\n"] {
            assert!(parse_map(text).is_empty());
        }
    }

    #[test]
    fn the_acceptor_needs_the_identity_uid_map_and_one_unprivileged_uid() {
        const IDENTITY: &str = "         0          0 4294967295\n";
        assert_eq!(check_acceptor_view(IDENTITY, [1000; 3]), Ok(()));
        // The maps of a rootless container and of a nested user namespace, an
        // identity map with another line, an empty and a malformed one.
        for map in [
            "         0       1000          1\n         1     100000      65536\n",
            "      1000       1000          1\n",
            "         0          0          1\n",
            "         0          0 4294967295\n         5          5          1\n",
            "",
            "garbage\n",
        ] {
            assert_eq!(
                check_acceptor_view(map, [1000; 3]),
                Err(AcceptorRefusal::UserNamespace),
                "{map:?}"
            );
        }
        // A saved or real uid that differs, even when the effective uid is right.
        for ids in [[1000, 1000, 0], [0, 1000, 1000], [1000, 1001, 1000]] {
            assert!(
                matches!(
                    check_acceptor_view(IDENTITY, ids),
                    Err(AcceptorRefusal::Uids { .. })
                ),
                "{ids:?}"
            );
        }
        assert_eq!(
            check_acceptor_view(IDENTITY, [0, 0, 0]),
            Err(AcceptorRefusal::Root)
        );
        // The refusals say what to do.
        let nested = check_acceptor_view("0 1000 1\n", [1000; 3])
            .unwrap_err()
            .to_string();
        assert!(nested.contains("Rootless containers"), "{nested}");
        assert!(nested.contains("nested user namespaces"), "{nested}");
        assert!(nested.contains("--init --root"), "{nested}");
        let uids = check_acceptor_view(IDENTITY, [1000, 1000, 0])
            .unwrap_err()
            .to_string();
        assert!(uids.contains("saved 0"), "{uids}");
    }

    #[test]
    fn credential_sentinels_are_rejected_before_any_identity_change() {
        // SAFETY: credential reads have no preconditions.
        let before = unsafe { (libc::geteuid(), libc::getegid()) };
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("must-not-exist");
        let range = Range {
            start: 200000,
            count: COUNT,
        };
        for (uid, gid) in [(0, 1001), (1001, 0), (u32::MAX, 1001), (1001, u32::MAX)] {
            assert!(become_user(uid, gid).is_err());
            assert!(pin_userns(uid, gid, range, range, &pin).is_err());
        }
        assert!(!pin.exists());
        // SAFETY: as above.
        assert_eq!(unsafe { (libc::geteuid(), libc::getegid()) }, before);
    }

    #[test]
    fn cgroups_cannot_escape_or_name_the_delegated_parent() {
        assert!(validate_child_cgroup("/unit", "/unit/vm-a").is_ok());
        assert!(validate_child_cgroup("", "/vm-a").is_ok());
        for path in [
            "/unit",
            "/unit2/vm",
            "/unit/../other",
            "/unit//vm",
            "/unit/./vm",
            "/unit/vm\0x",
        ] {
            assert!(validate_child_cgroup("/unit", path).is_err(), "{path}");
        }
    }

    #[test]
    fn namespace_inspection_rejects_symlink_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pin");
        std::os::unix::fs::symlink("/proc/self/ns/user", &path).unwrap();
        assert!(inspect_userns(&path).is_err());
        let ns = File::open("/proc/self/ns/user").unwrap();
        assert!(inspect_userns_fd(&ns).unwrap().is_some());
        fs::remove_file(&path).unwrap();
        fs::write(&path, "replacement").unwrap();
        assert!(inspect_userns(&path).unwrap().is_none());
        assert!(inspect_userns_fd(&ns).unwrap().is_some());
    }

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

    // The mount half of the microVM jail, rehearsed for real in throwaway
    // user and mount namespaces. It is the code `kronik foreign launch-microvm`
    // runs before it execs the VMM, and it needs neither KVM nor Firecracker.
    // The cgroup half cannot be rehearsed without a delegated cgroup.

    const REHEARSAL_DIR: &str = "KRONIK_JAIL_REHEARSAL_DIR";
    const REHEARSAL_CASE: &str = "KRONIK_JAIL_REHEARSAL_CASE";
    /// Set: after its checks the VMM of the rehearsal writes `/out/ready` and
    /// waits for `/out/go`, so that a test can look at the processes from outside
    /// while the launcher waits for it.
    const REHEARSAL_HOLD: &str = "KRONIK_JAIL_REHEARSAL_HOLD";

    // statvfs(3) `f_flag` bits that only the rehearsal looks at.
    const ST_NOATIME: libc::c_ulong = 1024;
    const ST_NODIRATIME: libc::c_ulong = 2048;
    const ST_RELATIME: libc::c_ulong = 4096;

    #[test]
    fn only_noexec_is_carried_into_the_remount() {
        assert_eq!(carried_mount_flags(0), 0);
        assert_eq!(carried_mount_flags(ST_RDONLY | ST_NOSUID | ST_NODEV), 0);
        assert_eq!(carried_mount_flags(ST_NOEXEC), libc::MS_NOEXEC);
        // The atime mode is never named: naming part of it fails the locked
        // atime check (`strictatime,nodiratime` in a user namespace).
        for atime in [
            ST_NOATIME,
            ST_NODIRATIME,
            ST_RELATIME,
            ST_NOATIME | ST_NODIRATIME,
            ST_RELATIME | ST_NODIRATIME,
        ] {
            assert_eq!(carried_mount_flags(atime), 0, "{atime:#x}");
            assert_eq!(
                carried_mount_flags(atime | ST_NOEXEC | ST_RDONLY),
                libc::MS_NOEXEC
            );
        }
    }

    /// Whether this host lets a test make user and mount namespaces; the
    /// reason when it does not. With `KRONIK_FOREIGN_TESTS=require`, the
    /// convention of the foreign tests, a host that cannot is a failure and
    /// not a skip: Ubuntu 24.04 restricts unprivileged user namespaces with
    /// AppArmor, which is exactly where a silent skip would hide the test.
    fn rehearsal_unavailable() -> Option<String> {
        let why = match std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "true"])
            .output()
        {
            Ok(out) if out.status.success() => return None,
            other => {
                format!("this host does not let a test make user and mount namespaces ({other:?})")
            }
        };
        if std::env::var("KRONIK_FOREIGN_TESTS").as_deref() == Ok("require") {
            panic!("KRONIK_FOREIGN_TESTS=require, but the jail rehearsal cannot run: {why}");
        }
        Some(why)
    }

    /// Runs the real mount sequence in user and mount namespaces made for the
    /// test, with the inputs on a plain mount and on mounts whose flags the
    /// kernel locks in a child user namespace. Skips where the host does not
    /// let a test make such namespaces.
    #[test]
    fn the_jail_mounts_read_only_inputs_whatever_mount_they_come_from() {
        use std::process::Command;
        if let Some(why) = rehearsal_unavailable() {
            eprintln!("skipped: {why}");
            return;
        }
        let exe = std::env::current_exe().unwrap();
        for (case, options) in [
            ("plain", ""),
            ("noatime", "noatime"),
            ("noexec", "noexec"),
            ("locked", "nosuid,nodev,noexec,noatime"),
            // Atime modes that name only part of the mode: carrying them
            // into the remount would fail (see `carried_mount_flags`).
            ("strictatime_nodiratime", "strictatime,nodiratime"),
            ("noatime_nodiratime", "noatime,nodiratime"),
            ("relatime_nodiratime", "relatime,nodiratime"),
        ] {
            let dir = tempfile::Builder::new()
                .prefix("kronik-jail-")
                .tempdir()
                .unwrap();
            fs::create_dir(dir.path().join("src")).unwrap();
            // The outer namespace mounts the source tmpfs. The inner one, made
            // by the second unshare, is the jail's: it inherits that mount
            // with its flags locked, as the launcher inherits the daemon's.
            let out = Command::new("unshare")
                .args(["--user", "--map-root-user", "--mount", "sh", "-ec"])
                .arg(
                    "if [ -n \"$OPTIONS\" ]; then \
                         mount -t tmpfs -o \"$OPTIONS,size=8m\" tmpfs \"$DIR/src\"; fi; \
                     exec unshare --user --map-root-user --mount \"$EXE\" \
                         --exact sys::tests::jail_rehearsal_child --ignored --nocapture \
                         --test-threads=1",
                )
                .env("EXE", &exe)
                .env("OPTIONS", options)
                .env("DIR", dir.path())
                .env(REHEARSAL_DIR, dir.path())
                .env(REHEARSAL_CASE, case)
                .output()
                .unwrap();
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                out.status.success() && text.contains("jail rehearsal ok"),
                "{case}: {text}"
            );
        }
    }

    /// The `Key:` lines of `/proc/<pid>/task/<tid>/status`, as (key, value).
    fn status_of(pid: u32, tid: u32) -> Vec<(String, String)> {
        fs::read_to_string(format!("/proc/{pid}/task/{tid}/status"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.to_owned(), value.trim().to_owned()))
            .collect()
    }

    /// The threads of a process that wait: the only thread of the launcher in
    /// production, and in this test binary the thread that runs the test (the
    /// capabilities and `no_new_privs` are per thread, and the main thread of
    /// the harness only waits for the test).
    fn waiting_threads(pid: u32) -> Vec<u32> {
        let all: Vec<u32> = fs::read_dir(format!("/proc/{pid}/task"))
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| e.file_name().to_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        if all.len() <= 1 {
            all
        } else {
            all.into_iter().filter(|tid| *tid != pid).collect()
        }
    }

    /// Both processes of a running jail, seen from outside: the launcher, which
    /// waits for its VMM in the VM's cgroup and in the jail's mount namespace,
    /// and the VMM, init of a PID namespace of its own, hold no capability of
    /// any kind and cannot gain one.
    #[test]
    fn while_the_launcher_waits_neither_it_nor_its_vmm_holds_a_capability() {
        use std::process::{Command, Stdio};
        if let Some(why) = rehearsal_unavailable() {
            eprintln!("skipped: {why}");
            return;
        }
        let dir = tempfile::Builder::new()
            .prefix("kronik-jail-")
            .tempdir()
            .unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        let mut launcher = Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "sh", "-ec"])
            .arg(
                "exec unshare --user --map-root-user --mount \"$EXE\" \
                     --exact sys::tests::jail_rehearsal_child --ignored --nocapture \
                     --test-threads=1",
            )
            .env("EXE", rehearsal_exe())
            .env(REHEARSAL_DIR, dir.path())
            .env(REHEARSAL_CASE, "hold")
            .env(REHEARSAL_HOLD, "1")
            .stdout(Stdio::from(File::create(dir.path().join("log")).unwrap()))
            .stderr(Stdio::from(
                File::create(dir.path().join("log-err")).unwrap(),
            ))
            .spawn()
            .unwrap();
        let ready = dir.path().join("src/out/ready");
        let go = dir.path().join("src/out/go");
        let mut looked_at = Ok(());
        for _ in 0..1500 {
            if ready.exists() || launcher.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if ready.exists() {
            looked_at = (|| {
                let parent = launcher.id();
                // The VMM: a child of the launcher that is pid 1 in its namespace.
                let vmm = fs::read_dir("/proc")
                    .map_err(|e| e.to_string())?
                    .flatten()
                    .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                    .find(|pid| {
                        let status = status_of(*pid, *pid);
                        let get = |key: &str| {
                            status
                                .iter()
                                .find(|(k, _)| k == key)
                                .map(|(_, v)| v.clone())
                                .unwrap_or_default()
                        };
                        get("PPid") == parent.to_string()
                            && get("NSpid").split_whitespace().last() == Some("1")
                    })
                    .ok_or("the launcher has no child that is pid 1 of its namespace")?;
                let mut seen = 0;
                for (who, pid) in [("launcher", parent), ("VMM", vmm)] {
                    for tid in waiting_threads(pid) {
                        seen += 1;
                        let status = status_of(pid, tid);
                        let get = |key: &str| {
                            status
                                .iter()
                                .find(|(k, _)| k == key)
                                .map(|(_, v)| v.clone())
                                .unwrap_or_default()
                        };
                        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
                            if get(key) != "0000000000000000" {
                                return Err(format!(
                                    "the {who} (thread {tid}) holds {key} {}",
                                    get(key)
                                ));
                            }
                        }
                        if get("NoNewPrivs") != "1" {
                            return Err(format!(
                                "the {who} (thread {tid}) can gain privilege: NoNewPrivs {}",
                                get("NoNewPrivs")
                            ));
                        }
                    }
                }
                if seen < 2 {
                    return Err(format!("only {seen} thread(s) were looked at"));
                }
                Ok(())
            })();
        }
        // Let the VMM finish and the launcher relay its status, whatever was found.
        fs::write(&go, b"").unwrap();
        let waited = (0..1500).find_map(|_| match launcher.try_wait().unwrap() {
            Some(status) => Some(status),
            None => {
                std::thread::sleep(std::time::Duration::from_millis(20));
                None
            }
        });
        let Some(status) = waited else {
            launcher.kill().unwrap();
            launcher.wait().unwrap();
            panic!("the launcher did not end");
        };
        let log = fs::read_to_string(dir.path().join("log")).unwrap_or_default()
            + &fs::read_to_string(dir.path().join("log-err")).unwrap_or_default();
        assert!(ready.exists(), "the VMM never got ready: {log}");
        assert_eq!(looked_at, Ok(()), "{log}");
        assert!(
            status.success() && log.contains("jail rehearsal ok"),
            "{status}: {log}"
        );
    }

    /// Sends one byte with `count` copies of `fd` in one control message.
    fn send_descriptors(sock: libc::c_int, fd: libc::c_int, count: usize) {
        let mut byte = 1u8;
        let mut iov = libc::iovec {
            iov_base: (&raw mut byte).cast(),
            iov_len: 1,
        };
        let fds = vec![fd; count];
        let data = count * std::mem::size_of::<libc::c_int>();
        // SAFETY: the buffer is sized by CMSG_SPACE and aligned as a cmsghdr.
        let mut control = vec![0u64; unsafe { libc::CMSG_SPACE(data as u32) } as usize / 8 + 1];
        // SAFETY: msghdr is a plain C struct; the pointers set below point at
        // locals that outlive sendmsg.
        unsafe {
            let mut hdr: libc::msghdr = std::mem::zeroed();
            hdr.msg_iov = &raw mut iov;
            hdr.msg_iovlen = 1;
            hdr.msg_control = control.as_mut_ptr().cast();
            hdr.msg_controllen = libc::CMSG_SPACE(data as u32) as _;
            let c = libc::CMSG_FIRSTHDR(&raw const hdr);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(data as u32) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast(), count);
            assert_eq!(libc::sendmsg(sock, &raw const hdr, 0), 1);
        }
    }

    /// How many descriptors of this process name `path`.
    fn descriptors_on(path: &Path) -> usize {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|e| fs::read_link(e.path()).is_ok_and(|target| target == path))
            .count()
    }

    #[test]
    fn a_message_with_more_descriptors_than_one_is_refused_and_none_of_them_leak() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("marker");
        let held = File::create(&marker).unwrap();
        let mut pair = [0; 2];
        // SAFETY: socketpair writes two descriptors.
        check(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            "socketpair",
        )
        .unwrap();
        // SAFETY: both are fresh and owned here.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
        let mut buf = [0u8; 4];
        // One descriptor is the protocol: it arrives, close-on-exec.
        send_descriptors(a.as_raw_fd(), held.as_raw_fd(), 1);
        let (n, fd) = recv_with_fd(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(n, 1);
        let fd = fd.expect("one descriptor");
        assert_eq!(descriptors_on(&marker), 2);
        // SAFETY: F_GETFD takes no pointer.
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(fd);
        assert_eq!(descriptors_on(&marker), 1);
        // No descriptor at all is a message, not an error.
        send_descriptors(a.as_raw_fd(), held.as_raw_fd(), 0);
        assert!(matches!(
            recv_with_fd(b.as_raw_fd(), &mut buf),
            Ok((1, None))
        ));
        // Two in one control message are refused, and both are closed again.
        send_descriptors(a.as_raw_fd(), held.as_raw_fd(), 2);
        let error = recv_with_fd(b.as_raw_fd(), &mut buf).unwrap_err();
        assert!(
            error.to_string().contains("more than one descriptor"),
            "{error}"
        );
        assert_eq!(descriptors_on(&marker), 1, "a received descriptor leaked");
        // More than the control buffer holds: the kernel truncates the message,
        // which is refused, and what it installed is closed too.
        send_descriptors(a.as_raw_fd(), held.as_raw_fd(), 7);
        let error = recv_with_fd(b.as_raw_fd(), &mut buf).unwrap_err();
        assert!(error.to_string().contains("more descriptors"), "{error}");
        assert_eq!(descriptors_on(&marker), 1, "a received descriptor leaked");
    }

    #[test]
    fn the_record_of_a_pin_names_its_owner_and_the_namespace_and_is_written_once() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("user");
        let stand_in = File::create(&pin).unwrap();
        let meta = stand_in.metadata().unwrap();
        write_pin_record(&pin, 998, &stand_in).unwrap();
        let record = pin.with_extension("owner");
        assert_eq!(
            fs::read_to_string(&record).unwrap(),
            format!("1 998 {} {}\n", meta.dev(), meta.ino())
        );
        assert_eq!(
            fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // An existing record is never overwritten, a link in its place is not followed.
        assert!(write_pin_record(&pin, 999, &stand_in).is_err());
        fs::remove_file(&record).unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &record).unwrap();
        assert!(write_pin_record(&pin, 998, &stand_in).is_err());
        assert!(!dir.path().join("elsewhere").exists());
    }

    /// What the kernel would answer for a call: the four instructions of the
    /// filter, run by hand over (architecture, number).
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn answer_of(program: &[libc::sock_filter], arch: u32, nr: u32) -> u32 {
        let mut acc = 0u32;
        let mut pc = 0usize;
        for _ in 0..program.len() {
            let ins = &program[pc];
            pc += 1;
            match ins.code {
                BPF_LD_W_ABS => {
                    acc = match ins.k {
                        SECCOMP_DATA_NR => nr,
                        SECCOMP_DATA_ARCH => arch,
                        other => panic!("the filter reads offset {other}"),
                    };
                }
                BPF_JEQ_K => pc += usize::from(if acc == ins.k { ins.jt } else { ins.jf }),
                BPF_JSET_K => pc += usize::from(if acc & ins.k != 0 { ins.jt } else { ins.jf }),
                BPF_RET_K => return ins.k,
                other => panic!("an instruction the test does not know: {other:#x}"),
            }
        }
        panic!("the filter ran off its end");
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn the_io_uring_filter_answers_for_every_architecture_and_number_it_can_be_asked() {
        let program = io_uring_filter();
        // Well formed: every jump lands inside, the last instruction returns.
        for (at, ins) in program.iter().enumerate() {
            if ins.code == BPF_JEQ_K || ins.code == BPF_JSET_K {
                assert!(
                    at + 1 + usize::from(ins.jt.max(ins.jf)) < program.len(),
                    "{at}"
                );
            }
        }
        assert_eq!(program[program.len() - 1].code, BPF_RET_K);
        let eperm = SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let ask = |nr: u32| answer_of(&program, AUDIT_ARCH_NATIVE, nr);
        for nr in [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert_eq!(ask(nr as u32), eperm, "{nr}");
        }
        // Everything else, the neighbours of the three included, is left to the
        // other filters.
        for nr in [
            libc::SYS_read,
            libc::SYS_getpid,
            libc::SYS_openat,
            libc::SYS_symlinkat,
            libc::SYS_io_uring_setup - 1,
            libc::SYS_io_uring_register + 1,
            0,
            1000,
        ] {
            assert_eq!(ask(nr as u32), SECCOMP_RET_ALLOW, "{nr}");
        }
        // The x32 flavour of the three, and of anything, kills the process: its
        // numbers carry a bit that the comparisons above would never match.
        for nr in [
            X32_SYSCALL_BIT | libc::SYS_io_uring_setup as u32,
            X32_SYSCALL_BIT | libc::SYS_getpid as u32,
            X32_SYSCALL_BIT,
            u32::MAX,
        ] {
            assert_eq!(ask(nr), SECCOMP_RET_KILL_PROCESS, "{nr:#x}");
        }
        // Another architecture's numbers mean other calls: killed, whatever
        // the number is.
        for arch in [0x4000_0003, 0xC000_00B7, 0xC000_003E, 0x4000_003E, 0] {
            if arch == AUDIT_ARCH_NATIVE {
                continue;
            }
            for nr in [libc::SYS_io_uring_setup as u32, libc::SYS_getpid as u32, 0] {
                assert_eq!(
                    answer_of(&program, arch, nr),
                    SECCOMP_RET_KILL_PROCESS,
                    "{arch:#x} {nr}"
                );
            }
        }
    }

    const URING_CHILD: &str = "KRONIK_TEST_IO_URING";
    const URING_STUB: &str = "KRONIK_TEST_IO_URING_STUB";
    /// The exit code of the helper for "this host does not let a test use
    /// io_uring at all", where the positive control cannot be had.
    const URING_UNAVAILABLE: i32 = 77;

    /// What a program executed after the filter sees: the three calls answer
    /// EPERM and an ordinary call works.
    const URING_STUB_SOURCE: &str = r#"
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char params[120] = {0};
    for (int nr = 425; nr <= 427; nr++) {
        long r = syscall(nr, 1, params, 0, 0, 0, 0);
        if (r != -1 || errno != EPERM) return 10 + (nr - 425);
    }
    if (syscall(SYS_getpid) <= 0) return 20;
    return 0;
}
"#;

    fn io_uring(nr: libc::c_long) -> (libc::c_long, i32) {
        let params = [0u8; 120];
        // SAFETY: the three calls read at most `params`; with a descriptor
        // that is not an io_uring they fail before they use it.
        let r = unsafe { libc::syscall(nr, 1, params.as_ptr(), 0, 0, 0, 0) };
        (r, io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    #[test]
    #[ignore = "a helper process of the io_uring filter test"]
    fn io_uring_filter_child() {
        if std::env::var_os(URING_CHILD).is_none() {
            return;
        }
        // The positive control: without the filter the host answers io_uring.
        let (fd, errno) = io_uring(libc::SYS_io_uring_setup);
        let usable = fd >= 0;
        if usable {
            // SAFETY: closing the descriptor just made.
            unsafe { libc::close(fd as libc::c_int) };
        }
        // The filter is installed whether or not the host has io_uring: the
        // kernel's own validation of the program is exercised either way.
        deny_io_uring().unwrap();
        if !usable {
            println!("io_uring is not usable here (errno {errno}); the program was accepted");
            std::process::exit(URING_UNAVAILABLE);
        }
        for (name, nr) in [
            ("setup", libc::SYS_io_uring_setup),
            ("enter", libc::SYS_io_uring_enter),
            ("register", libc::SYS_io_uring_register),
        ] {
            let (r, errno) = io_uring(nr);
            assert_eq!((r, errno), (-1, libc::EPERM), "io_uring_{name}");
        }
        // Ordinary calls are left to the other filters.
        assert!(std::process::id() > 0);
        File::open("/dev/null").unwrap();
        // And the filter is still there after an exec.
        if let Some(stub) = std::env::var_os(URING_STUB) {
            let status = std::process::Command::new(stub).status().unwrap();
            assert_eq!(status.code(), Some(0), "the executed program: {status}");
        }
        println!("io_uring filter ok");
        std::process::exit(0);
    }

    /// The filter turns the three io_uring calls into EPERM, leaves the rest
    /// alone and survives exec. It is irreversible, so it runs in a process of
    /// its own, and it has a control: on a host where io_uring is off to begin
    /// with (`kernel.io_uring_disabled`, the default seccomp profile of a
    /// container) there is nothing to show beyond the kernel accepting the
    /// program (which the helper checks first), and the test says so and
    /// skips, even under `KRONIK_FOREIGN_TESTS=require`: that is the host's
    /// choice and not a flaw of the test setup. The filter's instructions are tested by
    /// hand in [`the_io_uring_filter_answers_for_every_architecture_and_number_it_can_be_asked`]
    /// whatever the host does.
    #[test]
    fn the_io_uring_calls_answer_eperm_after_the_filter_and_in_what_is_executed() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("stub");
        let source = dir.path().join("stub.c");
        fs::write(&source, URING_STUB_SOURCE).unwrap();
        let built = std::process::Command::new("cc")
            .args(["-static", "-O1", "-o"])
            .arg(&stub)
            .arg(&source)
            .output();
        let have_stub = matches!(&built, Ok(out) if out.status.success());
        if !have_stub && std::env::var("KRONIK_FOREIGN_TESTS").as_deref() == Ok("require") {
            panic!("KRONIK_FOREIGN_TESTS=require, but no static C program can be made: {built:?}");
        }
        let mut command = std::process::Command::new(rehearsal_exe());
        command
            .args([
                "--exact",
                "sys::tests::io_uring_filter_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(URING_CHILD, "1");
        if have_stub {
            command.env(URING_STUB, &stub);
        }
        let out = command.output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if out.status.code() == Some(URING_UNAVAILABLE) {
            eprintln!("skipped: {text}");
            return;
        }
        assert!(
            out.status.success() && text.contains("io_uring filter ok"),
            "{text}"
        );
    }

    const DESCRIPTOR_CHILD: &str = "KRONIK_TEST_CLOSE_DESCRIPTORS";

    #[test]
    fn a_socket_entry_is_opened_without_following_links_and_only_for_a_socket_of_the_owner() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::{UnixListener, UnixStream};
        let dir = tempfile::tempdir().unwrap();
        let me = euid();
        let real = dir.path().join("real.sock");
        let listener = UnixListener::bind(&real).unwrap();
        // The socket itself, reached through the descriptor.
        let entry = open_socket_entry(dir.path(), "real.sock", me).unwrap();
        drop(UnixStream::connect(fd_path(&entry)).unwrap());
        listener.accept().unwrap();
        // The name is replaced after the check: the connection still goes to the
        // inode that was checked, and the newcomer sees none.
        let moved = dir.path().join("moved.sock");
        fs::rename(&real, &moved).unwrap();
        let newcomer = UnixListener::bind(&real).unwrap();
        newcomer.set_nonblocking(true).unwrap();
        drop(UnixStream::connect(fd_path(&entry)).unwrap());
        listener.accept().unwrap();
        assert_eq!(
            newcomer.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(entry);
        // Links, files, directories and FIFOs in its place are not sockets.
        symlink(&moved, dir.path().join("link.sock")).unwrap();
        symlink(dir.path(), dir.path().join("dirlink.sock")).unwrap();
        fs::write(dir.path().join("file.sock"), b"x").unwrap();
        fs::create_dir(dir.path().join("dir.sock")).unwrap();
        let fifo = std::process::Command::new("mkfifo")
            .arg(dir.path().join("fifo.sock"))
            .status();
        let mut bad = vec!["link.sock", "dirlink.sock", "file.sock", "dir.sock"];
        if matches!(fifo, Ok(status) if status.success()) {
            bad.push("fifo.sock");
        }
        for name in bad {
            let error = open_socket_entry(dir.path(), name, me).unwrap_err();
            assert_ne!(error.kind(), io::ErrorKind::NotFound, "{name}: {error}");
        }
        // Another user's socket, a missing entry, and names that are not plain.
        let error = open_socket_entry(dir.path(), "moved.sock", me + 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        let error = open_socket_entry(dir.path(), "absent.sock", me).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
        for name in ["", ".", "..", "a/b", "/etc/passwd"] {
            let error = open_socket_entry(dir.path(), name, me).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name:?}");
        }
    }

    #[test]
    fn a_missing_openat2_is_explained_with_the_setting_that_causes_it() {
        let explained = explain_openat2(io::Error::from_raw_os_error(libc::ENOSYS));
        assert_eq!(explained.kind(), io::ErrorKind::Unsupported);
        let text = explained.to_string();
        for needle in ["openat2", "RestrictSUIDSGID=yes", "Linux 5.6", "ADR 0027"] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        // Every other failure is left as the system said it.
        let other = explain_openat2(io::Error::from_raw_os_error(libc::ELOOP));
        assert_eq!(other.raw_os_error(), Some(libc::ELOOP));
    }

    fn open_plain() -> libc::c_int {
        // No O_CLOEXEC: the kind of descriptor that a child inherits.
        // SAFETY: opens a path with fixed flags.
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 3, "{fd}");
        fd
    }

    fn is_open(fd: libc::c_int) -> bool {
        // SAFETY: F_GETFD takes no pointer.
        unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
    }

    #[test]
    #[ignore = "a helper process of the descriptor tests"]
    fn close_descriptors_child() {
        let Ok(mode) = std::env::var(DESCRIPTOR_CHILD) else {
            return;
        };
        // Three descriptors above the harness's own, with room between them.
        let first = open_plain();
        // SAFETY: duplicates onto numbers at least as high as asked.
        let (second, third) = unsafe {
            (
                libc::fcntl(first, libc::F_DUPFD, first + 40),
                libc::fcntl(first, libc::F_DUPFD, first + 80),
            )
        };
        assert!(is_open(first) && is_open(second) && is_open(third));
        let (low, high) = (second, second);
        if mode == "fallback" {
            close_range_by_hand(low as u32, high as u32);
        } else {
            close_descriptors(low as u32, high as u32);
        }
        // Only the range goes; what is below and above it stays.
        assert!(is_open(first), "below the range");
        assert!(!is_open(second), "in the range");
        assert!(is_open(third), "above the range");
        close_descriptors(3, u32::MAX);
        assert!(!is_open(first) && !is_open(third), "everything above 2");
        // Standard input, output and error are not touched.
        assert!(is_open(0) && is_open(1) && is_open(2));
        std::process::exit(0);
    }

    /// Descriptors really close, in a process of their own so that no other
    /// test loses a descriptor: with `close_range`, and by hand where the
    /// kernel has none or refuses it.
    #[test]
    fn descriptors_above_the_standard_three_are_closed_with_and_without_close_range() {
        for mode in ["quick", "fallback"] {
            let out = std::process::Command::new(rehearsal_exe())
                .args([
                    "--exact",
                    "sys::tests::close_descriptors_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env(DESCRIPTOR_CHILD, mode)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{mode}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// The helper process of the test above; it does nothing on its own.
    #[test]
    #[ignore = "a helper process of the jail rehearsal"]
    fn jail_rehearsal_child() {
        let Some(dir) = std::env::var_os(REHEARSAL_DIR) else {
            return;
        };
        let case = std::env::var(REHEARSAL_CASE).unwrap_or_default();
        match rehearse_jail(Path::new(&dir), &case) {
            Ok(()) => {
                println!("jail rehearsal ok: {case}");
                std::process::exit(0);
            }
            Err(why) => {
                println!("jail rehearsal failed: {case}: {why}");
                std::process::exit(1);
            }
        }
    }

    /// Builds the jail root the way `Vm::spawn` does, runs the mount sequence
    /// and looks at the result from inside the jail.
    fn rehearse_jail(dir: &Path, case: &str) -> io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        let fail = |what: String| Err(io::Error::other(what));
        let src = dir.join("src");
        let root = dir.join("root");
        for name in [
            "firecracker",
            "vmlinux",
            "initrd",
            "root.ext4",
            "data.ext4",
            "kvm",
        ] {
            fs::write(src.join(name), b"input")?;
        }
        fs::create_dir(src.join("out"))?;
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(root.join("dev"))?;
        fs::create_dir(root.join("out"))?;
        for name in [
            "firecracker",
            "vmlinux",
            "initrd",
            "root.ext4",
            "data.ext4",
            "dev/kvm",
        ] {
            fs::write(root.join(name), b"")?;
        }
        // The case must really have the mount it claims, or it proves nothing.
        let source_flags = mount_flags(&File::open(src.join("firecracker"))?)?;
        // The flags the case's source mount must have, and the ones it must
        // not: the case proves nothing if the mount is not what it claims.
        let (has, lacks) = match case {
            "noatime" => (ST_NOATIME, ST_NOEXEC),
            "noexec" => (ST_NOEXEC, ST_NOATIME),
            "locked" => (ST_NOSUID | ST_NODEV | ST_NOEXEC | ST_NOATIME, 0),
            "strictatime_nodiratime" => (ST_NODIRATIME, ST_NOATIME | ST_RELATIME),
            "noatime_nodiratime" => (ST_NOATIME | ST_NODIRATIME, ST_RELATIME),
            "relatime_nodiratime" => (ST_RELATIME | ST_NODIRATIME, ST_NOATIME),
            _ => (0, ST_NOEXEC | ST_NOATIME | ST_NODIRATIME),
        };
        if source_flags & has != has || source_flags & lacks != 0 {
            return fail(format!(
                "the {case} source has mount flags {source_flags:#x}, not the expected ones"
            ));
        }
        // The positive control of the descriptor sweep: a descriptor of the kind a daemon
        // leaves open for its child, on a file outside the jail. It exists
        // here and must not exist in the jail.
        let inherited = open_plain();
        if !is_open(inherited) {
            return fail("the control descriptor was not open to begin with".into());
        }
        // A program to exec in the jail, to see what an exec gains: where the
        // source mount allows execution and a static C program can be made.
        let exec_stub = source_flags & ST_NOEXEC == 0 && make_stub(dir, &src.join("firecracker"))?;
        let launcher = std::process::id() as libc::pid_t;
        // The real sequence after the cgroup: namespaces (the PID one
        // included), the fork into it, the mounts and the sealed capabilities.
        // This returns in the child only; the process that called it waits for
        // the child and exits with its status, which the test reads.
        isolate(
            &MicrovmJail {
                root: &root,
                cgroup: "/unused",
                cpu_millis: 1,
                memory_bytes: 1,
                firecracker: &src.join("firecracker"),
                kernel: &src.join("vmlinux"),
                initrd: &src.join("initrd"),
                rootfs: &src.join("root.ext4"),
                data: &src.join("data.ext4"),
                output: &src.join("out"),
                parent_pid: 0,
            },
            &src.join("kvm"),
        )?;

        // From here on this process is inside the jail, and it is init of a
        // PID namespace of its own.
        if is_open(inherited) {
            return fail("a descriptor inherited from before the jail survived it".into());
        }
        if std::process::id() != 1 {
            return fail("the VMM is not init of its PID namespace".into());
        }
        // SAFETY: signal 0 only asks whether the target can be signalled.
        if unsafe { libc::kill(1, 0) } != 0 {
            return fail("pid 1 is not the VMM itself".into());
        }
        // The launcher is a real process of the host, and so is its thread.
        // None of them exists here: a compromised VMM cannot signal them.
        // SAFETY: signal 0 only asks; the thread calls take scalar arguments.
        let reached = unsafe {
            [
                ("kill", libc::kill(launcher, 0)),
                (
                    "tkill",
                    libc::syscall(libc::SYS_tkill, launcher, 0) as libc::c_int,
                ),
                (
                    "tgkill",
                    libc::syscall(libc::SYS_tgkill, launcher, launcher, 0) as libc::c_int,
                ),
            ]
        };
        for (call, result) in reached {
            if result != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return fail(format!("{call} of a host process did not fail with ESRCH"));
            }
        }
        // SAFETY: getppid takes no argument.
        if unsafe { libc::getppid() } != 0 {
            return fail("the VMM has a parent in its own namespace".into());
        }
        let mut names: Vec<String> = fs::read_dir("/")?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<_>>()?;
        names.sort();
        let expected = [
            "data.ext4",
            "dev",
            "firecracker",
            "initrd",
            "out",
            "root.ext4",
            "vmlinux",
        ];
        if names != expected {
            return fail(format!("the jail shows {names:?}"));
        }
        let read_only = ST_RDONLY | ST_NOSUID | ST_NODEV | (source_flags & ST_NOEXEC);
        for name in ["firecracker", "vmlinux", "initrd", "root.ext4"] {
            let path = Path::new("/").join(name);
            match OpenOptions::new().write(true).open(&path) {
                Err(e) if e.raw_os_error() == Some(libc::EROFS) => {}
                other => return fail(format!("{name} is not read-only: {other:?}")),
            }
            let flags = mount_flags(&File::open(&path)?)?;
            if flags & read_only != read_only {
                return fail(format!(
                    "{name} has mount flags {flags:#x}, not {read_only:#x}"
                ));
            }
        }
        OpenOptions::new()
            .append(true)
            .open("/data.ext4")?
            .write_all(b"more")?;
        fs::write("/out/probe", b"output")?;
        fs::metadata("/dev/kvm")?;
        // The old root is gone and `..` does not lead out of the jail.
        for gone in ["/.old", "/proc", "/etc/passwd"] {
            if fs::symlink_metadata(gone).is_ok() {
                return fail(format!("{gone} is still reachable"));
            }
        }
        std::env::set_current_dir("/..")?;
        if fs::read_dir(".")?.count() != expected.len() {
            return fail("`..` of the jail root leads somewhere else".into());
        }
        // `isolate` has done the last step of the launcher's jail.
        // SAFETY: scalar prctl.
        if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
            return fail("no_new_privs is not set".into());
        }
        // What an exec as uid 0 would gain is the bounding set, and the secure
        // bits decide whether uid 0 counts: both are sealed, not only zeroed.
        for cap in 0..64 {
            // SAFETY: scalar prctl; a number past the last capability is -1.
            if unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0) } == 1 {
                return fail(format!("capability {cap} is still in the bounding set"));
            }
        }
        // SAFETY: scalar prctl.
        let bits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } as libc::c_ulong;
        if bits & (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED) != SECBIT_NOROOT | SECBIT_NOROOT_LOCKED {
            return fail(format!("the secure bits are {bits:#x}, not sealed"));
        }
        let mut header = CapHeader {
            version: CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut held = [CapData {
            effective: 1,
            permitted: 1,
            inheritable: 1,
        }; 2];
        // SAFETY: capget fills two version-3 records.
        check(
            unsafe { libc::syscall(libc::SYS_capget, &raw mut header, held.as_mut_ptr()) }
                as libc::c_int,
            "capget",
        )?;
        if held
            .iter()
            .any(|c| c.effective | c.permitted | c.inheritable != 0)
        {
            return fail("capabilities remain after the jail".into());
        }
        // And what an exec of a program of the jail gets: nothing. The program
        // asks the kernel for its capability sets, bounding set, secure bits,
        // no_new_privs and ambient set.
        if exec_stub {
            let status = std::process::Command::new("/firecracker").status()?;
            if status.code() != Some(0) {
                return fail(format!(
                    "a program executed in the jail found capabilities or a missing seal: {status}"
                ));
            }
        }
        if std::env::var_os(REHEARSAL_HOLD).is_some() {
            fs::write("/out/ready", b"")?;
            for _ in 0..1500 {
                if Path::new("/out/go").exists() {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            return fail("nobody looked at the launcher".into());
        }
        Ok(())
    }

    /// Writes the static program that `rehearse_jail` executes in the jail over
    /// `target`. False where no static C program can be made (a host without a
    /// C compiler and static libc), which fails under
    /// `KRONIK_FOREIGN_TESTS=require`.
    fn make_stub(dir: &Path, target: &Path) -> io::Result<bool> {
        use std::os::unix::fs::PermissionsExt as _;
        let source = dir.join("stub.c");
        let program = dir.join("stub");
        fs::write(&source, STUB)?;
        let built = std::process::Command::new("cc")
            .args(["-static", "-O1", "-o"])
            .arg(&program)
            .arg(&source)
            .output();
        match built {
            Ok(out) if out.status.success() => {
                fs::copy(&program, target)?;
                fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
                Ok(true)
            }
            other => {
                let why = format!("no static C program can be made here ({other:?})");
                if std::env::var("KRONIK_FOREIGN_TESTS").as_deref() == Ok("require") {
                    return Err(io::Error::other(why));
                }
                eprintln!("skipped the exec check: {why}");
                Ok(false)
            }
        }
    }

    /// What the program executed in the jail looks at. Exit codes name the
    /// first thing it finds wrong.
    const STUB: &str = r#"
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PR_CAPBSET_READ
#define PR_CAPBSET_READ 23
#endif
#ifndef PR_GET_SECUREBITS
#define PR_GET_SECUREBITS 27
#endif

int main(void) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2];
    if (syscall(SYS_capget, &header, data) != 0) return 90;
    for (int i = 0; i < 2; i++)
        if (data[i].effective || data[i].permitted || data[i].inheritable) return 91;
    for (int cap = 0; cap < 64; cap++)
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) == 1) return 92;
    if ((prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) & 3) != 3) return 93;
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 94;
    for (int cap = 0; cap < 64; cap++)
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) == 1) return 95;
    return 0;
}
"#;

    #[test]
    fn exit_codes_stand_for_wait_statuses_as_a_shell_reports_them() {
        assert_eq!(exit_code(0), 0);
        assert_eq!(exit_code(37 << 8), 37);
        assert_eq!(exit_code(libc::SIGKILL), 128 + libc::SIGKILL);
        // A core dump flag does not change the signal.
        assert_eq!(exit_code(libc::SIGSEGV | 0x80), 128 + libc::SIGSEGV);
    }

    /// The test binary to re-exec from a rehearsal namespace.
    ///
    /// `unshare --user --map-root-user` runs the command as uid 0 of a *new*
    /// user namespace. That uid is privileged only for inodes of its own
    /// namespace; for this namespace's files it is an ordinary uid with no
    /// `CAP_DAC_OVERRIDE`, so the file must be executable through its own mode
    /// bits. A cargo test binary can be 0750 (a restrictive umask) and a CI
    /// checkout can be owned by another uid; copy it once, 0755, under `/tmp`
    /// (whose ancestors are world-searchable) and give every rehearsal the copy.
    fn rehearsal_exe() -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        static COPY: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        COPY.get_or_init(|| {
            let exe = std::env::current_exe().unwrap();
            let dir = std::path::Path::new("/tmp")
                .join(format!("kronik-foreign-rehearsal-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let copy = dir.join("kronik-foreign");
            std::fs::copy(&exe, &copy).unwrap();
            std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
            copy
        })
        .clone()
    }

    const PIDNS_DIR: &str = "KRONIK_TEST_PIDNS_DIR";
    const PIDNS_CASE: &str = "KRONIK_TEST_PIDNS_CASE";

    /// The helper process of the PID namespace tests: a launcher that forks
    /// its VMM into a PID namespace of its own and does what the case says.
    #[test]
    #[ignore = "a helper process of the PID namespace tests"]
    fn pid_namespace_child() {
        let (Some(dir), Ok(case)) = (std::env::var_os(PIDNS_DIR), std::env::var(PIDNS_CASE)) else {
            return;
        };
        let dir = PathBuf::from(dir);
        // SAFETY: unshare with one flag; this process has one thread.
        check(unsafe { libc::unshare(libc::CLONE_NEWPID) }, "unshare").unwrap();
        match fork_into_pid_namespace().unwrap() {
            Forked::Parent(child) => {
                fs::write(dir.join("child-pid"), child.pid().to_string()).unwrap();
                std::process::exit(child.wait().unwrap());
            }
            Forked::Child => match case.as_str() {
                "status" => std::process::exit(37),
                "wait" => {
                    fs::write(dir.join("ready"), b"").unwrap();
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                }
                other => panic!("no PID namespace case {other}"),
            },
        }
    }

    /// Starts the helper in a user namespace made for the test (it is root in
    /// there, and nowhere else) and returns it with its directory.
    fn start_pid_namespace_helper(case: &str) -> (std::process::Child, tempfile::TempDir) {
        use std::process::{Command, Stdio};
        let dir = tempfile::Builder::new()
            .prefix("kronik-pidns-")
            .tempdir()
            .unwrap();
        let log = File::create(dir.path().join("log")).unwrap();
        // `unshare --map-root-user` execs the command as uid 0 of a *new* user
        // namespace. That uid is not privileged for inodes of the namespace it
        // was made in, so the file must be executable through its own mode
        // bits: a cargo test binary can be 0750 (or 0700) when the build ran
        // with a restrictive umask, and a CI checkout owned by another uid is
        // then not executable at all. Copy it beside the run as 0755 and exec
        // the copy - the rehearsal is about the launcher, not about the mode
        // of the test binary.
        let helper = dir.path().join("kronik-foreign-jail-rehearsal");
        std::fs::copy(rehearsal_exe(), &helper).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let child = Command::new("unshare")
            .args(["--user", "--map-root-user"])
            .arg(&helper)
            .args([
                "--exact",
                "sys::tests::pid_namespace_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PIDNS_DIR, dir.path())
            .env(PIDNS_CASE, case)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        (child, dir)
    }

    fn wait_for(path: &Path, what: &str) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("{what}: {} did not appear", path.display());
    }

    /// Whether a process is gone or only a zombie waiting to be reaped.
    fn is_dead(pid: libc::pid_t) -> bool {
        match fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(status) => status.lines().any(|l| l.starts_with("State:\tZ")),
            Err(_) => true,
        }
    }

    #[test]
    fn the_launcher_exits_with_the_status_of_the_vmm_and_with_128_plus_its_signal() {
        if let Some(why) = rehearsal_unavailable() {
            eprintln!("skipped: {why}");
            return;
        }
        // An exit status is relayed as it is.
        let (mut helper, dir) = start_pid_namespace_helper("status");
        let status = helper.wait().unwrap();
        let log = fs::read_to_string(dir.path().join("log")).unwrap_or_default();
        assert_eq!(status.code(), Some(37), "{log}");
        assert!(dir.path().join("child-pid").exists(), "{log}");
        // A VMM killed by a signal is 128 plus the signal, which is what the
        // supervisor reads as "the sandbox exited": the signal comes from the
        // host, the only place that can kill the init of a namespace.
        let (mut helper, dir) = start_pid_namespace_helper("wait");
        wait_for(&dir.path().join("ready"), "the VMM");
        let pid: libc::pid_t = fs::read_to_string(dir.path().join("child-pid"))
            .unwrap()
            .parse()
            .unwrap();
        // SAFETY: SIGKILL to a process of this test's own making.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
        let status = helper.wait().unwrap();
        assert_eq!(status.code(), Some(128 + libc::SIGKILL), "{status}");
    }

    #[test]
    fn the_vmm_dies_with_its_launcher() {
        if let Some(why) = rehearsal_unavailable() {
            eprintln!("skipped: {why}");
            return;
        }
        let (mut helper, dir) = start_pid_namespace_helper("wait");
        wait_for(&dir.path().join("ready"), "the VMM");
        let pid: libc::pid_t = fs::read_to_string(dir.path().join("child-pid"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(!is_dead(pid), "the VMM runs while its launcher does");
        // The daemon kills the launcher: nothing else tells the VMM.
        helper.kill().unwrap();
        helper.wait().unwrap();
        for _ in 0..200 {
            if is_dead(pid) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // SAFETY: do not leave the process behind when the assertion fails.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        panic!("the VMM outlived its launcher");
    }
}
