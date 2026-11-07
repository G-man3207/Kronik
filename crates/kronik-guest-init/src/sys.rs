//! Linux-only PID1 setup, process supervision and AF_VSOCK bridge.
// Allowlisted: mount/chroot, capability, signal, fork/exec, reboot, ioctl and
// AF_VSOCK/poll syscalls have no safe binding in the allowed dependencies.
// Every pointer refers to a live Rust value; owned descriptors close on drop.
#![allow(unsafe_code)]
// Guest supervision uses its own monotonic kernel clock; it has no daemon Env.
#![allow(clippy::disallowed_methods)]

use crate::{
    CONTROL_PORT, GuestConfig, MAX_CONNECTIONS, READY, STOP, STOP_OK, VSOCK_PORT, capability,
    invalid,
};
use std::ffi::CString;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn check(rc: libc::c_int, operation: &str) -> io::Result<()> {
    if rc < 0 {
        let error = io::Error::last_os_error();
        Err(io::Error::new(
            error.kind(),
            format!("{operation}: {error}"),
        ))
    } else {
        Ok(())
    }
}

fn cstring(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| invalid("NUL in guest setting"))
}

fn owned(fd: RawFd, operation: &str) -> io::Result<OwnedFd> {
    check(fd, operation)?;
    // SAFETY: successful descriptor-creating syscall, transferred exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn mount(
    source: &str,
    target: &str,
    kind: &str,
    flags: libc::c_ulong,
    data: &str,
) -> io::Result<()> {
    let source = cstring(source)?;
    let target = cstring(target)?;
    let kind = cstring(kind)?;
    let data = cstring(data)?;
    // SAFETY: the strings remain live throughout the call.
    check(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                kind.as_ptr(),
                flags,
                data.as_ptr().cast(),
            )
        },
        "mounting guest filesystem",
    )
}

fn directory(path: &str) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(invalid("guest mountpoint is not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(path),
        Err(error) => Err(error),
    }
}

fn setup_root() -> io::Result<()> {
    for path in ["/dev", "/proc", "/sys", "/lower", "/writable", "/newroot"] {
        directory(path)?;
    }
    mount(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755",
    )?;
    mount(
        "proc",
        "/proc",
        "proc",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )?;
    mount(
        "sysfs",
        "/sys",
        "sysfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY,
        "",
    )?;
    mount(
        "/dev/vda",
        "/lower",
        "ext4",
        libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID,
        "noload",
    )?;
    mount(
        "tmpfs",
        "/writable",
        "tmpfs",
        libc::MS_NODEV | libc::MS_NOSUID,
        "mode=0700,size=50%",
    )?;
    directory("/writable/upper")?;
    directory("/writable/work")?;
    mount(
        "overlay",
        "/newroot",
        "overlay",
        libc::MS_NODEV | libc::MS_NOSUID,
        "lowerdir=/lower,upperdir=/writable/upper,workdir=/writable/work",
    )?;
    for path in [
        "/newroot/dev",
        "/newroot/proc",
        "/newroot/sys",
        "/newroot/data",
    ] {
        directory(path)?;
    }
    // Do not expose virtio block devices or the bootstrap manifest to the app.
    mount(
        "tmpfs",
        "/newroot/dev",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755,size=1m",
    )?;
    for (name, major, minor, mode) in [
        ("null", 1, 3, 0o666),
        ("zero", 1, 5, 0o666),
        ("full", 1, 7, 0o666),
        ("random", 1, 8, 0o666),
        ("urandom", 1, 9, 0o666),
        ("tty", 5, 0, 0o666),
        ("console", 5, 1, 0o600),
    ] {
        let path = cstring(&format!("/newroot/dev/{name}"))?;
        // SAFETY: valid path and Linux character-device number.
        check(
            unsafe {
                libc::mknod(
                    path.as_ptr(),
                    libc::S_IFCHR | mode,
                    libc::makedev(major, minor),
                )
            },
            "creating guest character device",
        )?;
        // The process umask must not make /dev/null unwritable for image users.
        // SAFETY: same live path and ordinary Unix permission bits.
        check(
            unsafe { libc::chmod(path.as_ptr(), mode) },
            "setting guest device permissions",
        )?;
    }
    directory("/newroot/dev/pts")?;
    directory("/newroot/dev/shm")?;
    mount(
        "devpts",
        "/newroot/dev/pts",
        "devpts",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "newinstance,ptmxmode=0666,mode=0620",
    )?;
    mount(
        "tmpfs",
        "/newroot/dev/shm",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=1777,size=64m",
    )?;
    for (source, target) in [
        ("pts/ptmx", "/newroot/dev/ptmx"),
        ("/proc/self/fd", "/newroot/dev/fd"),
        ("/proc/self/fd/0", "/newroot/dev/stdin"),
        ("/proc/self/fd/1", "/newroot/dev/stdout"),
        ("/proc/self/fd/2", "/newroot/dev/stderr"),
    ] {
        std::os::unix::fs::symlink(source, target)?;
    }
    // The host contract fixes the persistent drive capacity at 1 GiB.
    let disk = fs::File::open("/dev/vdb")?;
    let mut size = 0u64;
    // SAFETY: BLKGETSIZE64 writes a u64 into the supplied live pointer.
    check(
        unsafe { libc::ioctl(disk.as_raw_fd(), 0x8008_1272_u32 as _, &mut size) },
        "reading guest data disk capacity",
    )?;
    if size != 1024 * 1024 * 1024 {
        return Err(invalid("guest data disk must have fixed 1 GiB capacity"));
    }
    drop(disk);
    mount(
        "/dev/vdb",
        "/newroot/data",
        "ext4",
        libc::MS_NOSUID | libc::MS_NODEV,
        "",
    )?;
    for path in ["proc", "sys"] {
        mount(
            &format!("/{path}"),
            &format!("/newroot/{path}"),
            "",
            libc::MS_MOVE,
            "",
        )?;
    }
    fs::remove_file("/config.json")?;
    fs::remove_file("/init")?;
    std::env::set_current_dir("/newroot")?;
    // Linux initramfs rootfs cannot be pivot_root'd. switch_root's move+chroot
    // removes all process references to it without writing into the image.
    mount(".", "/", "", libc::MS_MOVE, "")?;
    // SAFETY: cwd is the mounted overlay, and no old-root descriptor survives.
    check(
        unsafe { libc::chroot(c".".as_ptr()) },
        "switching guest root",
    )?;
    std::env::set_current_dir("/")?;
    Ok(())
}

fn loopback_up() -> io::Result<()> {
    // SAFETY: socket has no pointer parameters.
    let socket = owned(
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) },
        "opening loopback control",
    )?;
    // SAFETY: zero is a valid initial ifreq representation.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[0] = b'l' as libc::c_char;
    request.ifr_name[1] = b'o' as libc::c_char;
    // SAFETY: ioctl writes the flags union in this live ifreq.
    check(
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut request) },
        "reading loopback flags",
    )?;
    // SAFETY: the preceding ioctl initialized this member.
    unsafe {
        request.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    }
    // SAFETY: initialized ifreq with the interface name and flags.
    check(
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) },
        "enabling loopback",
    )
}

const SIGNALS: [libc::c_int; 6] = [
    libc::SIGCHLD,
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGPWR,
];

fn signal_fd() -> io::Result<OwnedFd> {
    // SAFETY: sigemptyset initializes all members before use.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: mask is a valid writable signal set.
    check(
        unsafe { libc::sigemptyset(&mut mask) },
        "initializing signal mask",
    )?;
    for signal in SIGNALS {
        // SAFETY: every signal is a valid Linux signal number.
        check(
            unsafe { libc::sigaddset(&mut mask, signal) },
            "adding supervised signal",
        )?;
    }
    // SAFETY: called before fork or threads; the application resets this mask.
    check(
        unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) },
        "blocking supervised signals",
    )?;
    // SAFETY: initialized mask and valid flags; new descriptor is owned below.
    owned(
        unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) },
        "opening signal descriptor",
    )
}

fn listener(port: u32) -> io::Result<OwnedFd> {
    // SAFETY: no pointer parameters; new descriptor is owned immediately.
    let fd = owned(
        unsafe {
            libc::socket(
                libc::AF_VSOCK,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        },
        "opening vsock listener",
    )?;
    // SAFETY: zero is valid for sockaddr_vm's reserved fields.
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_cid = libc::VMADDR_CID_ANY;
    address.svm_port = port;
    // SAFETY: correct sockaddr_vm pointer and length.
    check(
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_vm).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        },
        "binding fixed guest vsock port",
    )?;
    // SAFETY: fd is a bound stream socket.
    check(
        unsafe { libc::listen(fd.as_raw_fd(), MAX_CONNECTIONS as libc::c_int) },
        "listening on guest vsock",
    )?;
    Ok(fd)
}

fn accept_host(fd: RawFd) -> io::Result<Option<OwnedFd>> {
    // SAFETY: zeroed address is writable and length matches its allocation.
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: address and length are valid output buffers.
    let accepted = unsafe {
        libc::accept4(
            fd,
            (&mut address as *mut libc::sockaddr_vm).cast(),
            &mut length,
            libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        )
    };
    // Preserve errno so transport reset and a drained accept queue are distinct.
    if accepted < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: accept4 returned a new owned descriptor.
    let stream = unsafe { OwnedFd::from_raw_fd(accepted) };
    if length as usize != std::mem::size_of_val(&address)
        || address.svm_family != libc::AF_VSOCK as libc::sa_family_t
        || address.svm_cid != libc::VMADDR_CID_HOST
    {
        return Ok(None);
    }
    Ok(Some(stream))
}

struct Exec {
    args: Vec<CString>,
    env: Vec<CString>,
    paths: Vec<CString>,
    cwd: CString,
    caps: u64,
    last_cap: u32,
}

impl Exec {
    fn new(config: &GuestConfig) -> io::Result<Self> {
        let path = config
            .env
            .iter()
            .find_map(|s| s.strip_prefix("PATH="))
            .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        let paths = if config.args[0].contains('/') {
            vec![cstring(&config.args[0])?]
        } else {
            let mut bytes = 0usize;
            path.split(':')
                .map(|entry| {
                    let directory = if entry.is_empty() { "." } else { entry };
                    let length = directory
                        .len()
                        .saturating_add(config.args[0].len())
                        .saturating_add(2);
                    bytes = bytes.saturating_add(length);
                    if length > 4096 || bytes > crate::MAX_PROCESS_BYTES {
                        return Err(invalid("guest executable search exceeds byte limit"));
                    }
                    cstring(&format!("{directory}/{}", config.args[0]))
                })
                .collect::<io::Result<Vec<_>>>()?
        };
        let mut caps = 0u64;
        for name in &config.capabilities {
            caps |=
                1u64 << capability(name).ok_or_else(|| invalid("unsupported guest capability"))?;
        }
        let last_cap = fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
            .trim()
            .parse::<u32>()
            .map_err(|_| invalid("invalid kernel capability bound"))?;
        if last_cap > 63 {
            return Err(invalid("unsupported kernel capability bound"));
        }
        Ok(Self {
            args: config
                .args
                .iter()
                .map(|s| cstring(s))
                .collect::<io::Result<_>>()?,
            env: config
                .env
                .iter()
                .map(|s| cstring(s))
                .collect::<io::Result<_>>()?,
            paths,
            cwd: cstring(&config.cwd)?,
            caps,
            last_cap,
        })
    }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn child_setup(config: &GuestConfig, exec: &Exec) -> io::Result<()> {
    // SAFETY: all prctl arguments are numeric values defined by Linux.
    check(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        "setting no-new-privileges",
    )?;
    // SAFETY: clearing all ambient capabilities requires no pointers.
    check(
        unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        },
        "clearing ambient capabilities",
    )?;
    for cap in 0..=exec.last_cap {
        if exec.caps & (1u64 << cap) == 0 {
            // SAFETY: cap is bounded by the kernel's reported last capability.
            check(
                unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) },
                "dropping application capability bound",
            )?;
        }
    }
    // SAFETY: empty supplementary groups uses a null buffer with zero length.
    check(
        unsafe { libc::setgroups(0, std::ptr::null()) },
        "clearing supplementary groups",
    )?;
    // SAFETY: validated UID/GID, with no sentinel values.
    check(
        unsafe { libc::setresgid(config.gid, config.gid, config.gid) },
        "setting application group",
    )?;
    // SAFETY: same validated user identity for real/effective/saved IDs.
    check(
        unsafe { libc::setresuid(config.uid, config.uid, config.uid) },
        "setting application user",
    )?;
    let header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let data = [
        CapData {
            effective: exec.caps as u32,
            permitted: exec.caps as u32,
            inheritable: 0,
        },
        CapData {
            effective: (exec.caps >> 32) as u32,
            permitted: (exec.caps >> 32) as u32,
            inheritable: 0,
        },
    ];
    // SAFETY: Linux capability v3 expects one header and two data structures.
    check(
        unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) as libc::c_int },
        "setting application capabilities",
    )?;
    // SAFETY: own process group, valid cwd C string.
    check(
        unsafe { libc::setpgid(0, 0) },
        "creating application process group",
    )?;
    // SAFETY: cwd was validated and its CString is live.
    check(
        unsafe { libc::chdir(exec.cwd.as_ptr()) },
        "entering application working directory",
    )?;
    // SAFETY: initialized before passing to sigprocmask.
    let mut empty: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: valid writable signal set.
    check(
        unsafe { libc::sigemptyset(&mut empty) },
        "initializing child signal mask",
    )?;
    for signal in SIGNALS {
        // SAFETY: resetting to the default disposition uses no function pointer.
        if unsafe { libc::signal(signal, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: empty valid signal set unblocks all application signals.
    check(
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) },
        "unblocking application signals",
    )
}

fn spawn(config: &GuestConfig, exec: &Exec) -> io::Result<libc::pid_t> {
    let args: Vec<_> = exec
        .args
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env: Vec<_> = exec
        .env
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // SAFETY: this is the only fork, before any thread is created. The child
    // uses syscall-only setup and exec; no inherited lock can be held by a peer.
    let pid = unsafe { libc::fork() };
    check(pid, "forking application")?;
    if pid == 0 {
        if let Err(error) = child_setup(config, exec) {
            eprintln!("kronik-guest-init: application setup failed: {error}");
            // SAFETY: terminate the forked child without running parent destructors.
            unsafe { libc::_exit(126) };
        }
        // SAFETY: descriptors >=3 are not part of the application's interface.
        if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } < 0 {
            eprintln!("kronik-guest-init: closing inherited descriptors failed");
            // SAFETY: terminate the child without inherited Rust destructors.
            unsafe { libc::_exit(126) };
        }
        let mut denied = false;
        for path in &exec.paths {
            // SAFETY: args/env are NUL-terminated pointer arrays backed by live
            // CStrings; no shell fallback or inherited environment is used.
            unsafe {
                libc::execve(path.as_ptr(), args.as_ptr(), env.as_ptr());
            }
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOENT | libc::ENOTDIR) => {}
                Some(libc::EACCES) => denied = true,
                _ => {
                    eprintln!(
                        "kronik-guest-init: application exec failed: {}",
                        io::Error::last_os_error()
                    );
                    // SAFETY: failed exec is fatal to this child only.
                    unsafe { libc::_exit(126) };
                }
            }
        }
        eprintln!(
            "kronik-guest-init: application executable {}",
            if denied {
                "is not executable"
            } else {
                "was not found"
            }
        );
        // SAFETY: all PATH candidates failed; no user argument is printed.
        unsafe { libc::_exit(127) };
    }
    // Close the pre-exec group-creation race with an immediately arriving stop.
    // SAFETY: only our freshly forked child is moved into its own group.
    if unsafe { libc::setpgid(pid, pid) } < 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EACCES | libc::ESRCH)) {
            return Err(error);
        }
    }
    Ok(pid)
}

// One fixed-size buffer per direction, regardless of peer behavior.
struct Direction {
    bytes: [u8; 16 * 1024],
    start: usize,
    end: usize,
    eof: bool,
    shut: bool,
}

impl Direction {
    fn new() -> Self {
        Self {
            bytes: [0; 16 * 1024],
            start: 0,
            end: 0,
            eof: false,
            shut: false,
        }
    }

    fn read(&mut self, fd: RawFd) -> io::Result<()> {
        if self.eof || self.end == self.bytes.len() {
            return Ok(());
        }
        // SAFETY: spare slice is valid writable storage for the supplied length.
        let count = unsafe {
            libc::recv(
                fd,
                self.bytes[self.end..].as_mut_ptr().cast(),
                self.bytes.len() - self.end,
                0,
            )
        };
        if count > 0 {
            self.end += count as usize;
        } else if count == 0 {
            self.eof = true;
        } else {
            transient(io::Error::last_os_error())?;
        }
        Ok(())
    }

    fn write(&mut self, fd: RawFd) -> io::Result<()> {
        if self.start < self.end {
            // SAFETY: initialized pending buffer, MSG_NOSIGNAL prevents SIGPIPE.
            let count = unsafe {
                libc::send(
                    fd,
                    self.bytes[self.start..self.end].as_ptr().cast(),
                    self.end - self.start,
                    libc::MSG_NOSIGNAL,
                )
            };
            if count > 0 {
                self.start += count as usize;
            } else if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "proxy write returned zero",
                ));
            } else {
                transient(io::Error::last_os_error())?;
            }
            if self.start == self.end {
                self.start = 0;
                self.end = 0;
            }
        }
        if self.eof && self.start == self.end && !self.shut {
            // SAFETY: shuts down only the write half of a live connected socket.
            check(
                unsafe { libc::shutdown(fd, libc::SHUT_WR) },
                "half-closing proxy stream",
            )?;
            self.shut = true;
        }
        Ok(())
    }
}

fn transient(error: io::Error) -> io::Result<()> {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        Ok(())
    } else {
        Err(error)
    }
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl only reads/updates flags on the supplied live descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    check(flags, "reading proxy socket flags")?;
    // SAFETY: existing flags plus O_NONBLOCK is a valid F_SETFL value.
    check(
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
        "setting nonblocking proxy socket",
    )
}

fn relay(left: OwnedFd, right: OwnedFd) -> io::Result<()> {
    nonblocking(left.as_raw_fd())?;
    nonblocking(right.as_raw_fd())?;
    let mut outbound = Direction::new();
    let mut inbound = Direction::new();
    loop {
        outbound.write(right.as_raw_fd())?;
        inbound.write(left.as_raw_fd())?;
        if outbound.shut && inbound.shut {
            return Ok(());
        }
        let events = |read: &Direction, write: &Direction| {
            (if !read.eof && read.end < read.bytes.len() {
                libc::POLLIN
            } else {
                0
            }) | (if write.start < write.end {
                libc::POLLOUT
            } else {
                0
            })
        };
        let mut poll = [
            libc::pollfd {
                fd: left.as_raw_fd(),
                events: events(&outbound, &inbound),
                revents: 0,
            },
            libc::pollfd {
                fd: right.as_raw_fd(),
                events: events(&inbound, &outbound),
                revents: 0,
            },
        ];
        for item in &mut poll {
            if item.events == 0 {
                item.fd = -1;
            }
        }
        // SAFETY: poll array contains two valid descriptors, no retained pointer.
        let rc = unsafe { libc::poll(poll.as_mut_ptr(), poll.len() as libc::nfds_t, -1) };
        if rc < 0 {
            transient(io::Error::last_os_error())?;
            continue;
        }
        for item in &poll {
            if item.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::other("invalid proxy socket"));
            }
        }
        // recv drains readable data before treating HUP as EOF; the opposite
        // direction remains alive until its own FIN and pending bytes drain.
        if poll[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            outbound.read(left.as_raw_fd())?;
        }
        if poll[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            inbound.read(right.as_raw_fd())?;
        }
    }
}

struct Connection(Arc<AtomicUsize>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

fn proxy(stream: OwnedFd, port: u16, connections: &Arc<AtomicUsize>) -> io::Result<()> {
    if connections.load(Ordering::Acquire) >= MAX_CONNECTIONS {
        return Ok(());
    }
    connections.fetch_add(1, Ordering::AcqRel);
    let slot = Connection(Arc::clone(connections));
    thread::Builder::new()
        .name("guest-proxy".into())
        .spawn(move || {
            let _slot = slot;
            let result = TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                Duration::from_secs(5),
            )
            .and_then(|tcp| {
                write_socket(
                    stream.as_raw_fd(),
                    READY,
                    Instant::now() + Duration::from_secs(5),
                )?;
                relay(stream, tcp.into())
            });
            if let Err(error) = result {
                eprintln!("kronik-guest-init: proxy connection failed: {error}");
            }
        })?;
    Ok(())
}

fn wait_socket(fd: RawFd, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guest protocol deadline exceeded",
            ));
        }
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        // SAFETY: one initialized pollfd backed by a live socket descriptor.
        let rc = unsafe { libc::poll(&mut poll, 1, millis) };
        if rc > 0 {
            if poll.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::other("invalid guest protocol socket"));
            }
            return Ok(());
        }
        if rc < 0 {
            transient(io::Error::last_os_error())?;
        }
    }
}

fn write_socket(fd: RawFd, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        wait_socket(fd, libc::POLLOUT, deadline)?;
        // SAFETY: initialized bytes; no SIGPIPE and no unbounded blocking send.
        let count = unsafe {
            libc::send(
                fd,
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if count > 0 {
            bytes = &bytes[count as usize..];
        } else if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "guest protocol write returned zero",
            ));
        } else {
            transient(io::Error::last_os_error())?;
        }
    }
    Ok(())
}

// A single fixed frame, never a command dispatcher. Main owns this short-lived
// socket, so control cannot consume proxy slots or create additional threads.
fn receive_stop(stream: OwnedFd) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut bytes = [0u8; 6];
    let mut used = 0;
    loop {
        wait_socket(stream.as_raw_fd(), libc::POLLIN, deadline)?;
        // SAFETY: bounded writable slice; nonblocking even for test sockets.
        let count = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                bytes[used..].as_mut_ptr().cast(),
                bytes.len() - used,
                libc::MSG_DONTWAIT,
            )
        };
        if count > 0 {
            used += count as usize;
        } else if count == 0 {
            return Err(invalid("incomplete guest stop command"));
        } else {
            transient(io::Error::last_os_error())?;
            continue;
        }
        if used > STOP.len() || bytes[..used] != STOP[..used] {
            return Err(invalid("invalid guest stop command"));
        }
        if used == STOP.len() {
            let mut extra = 0u8;
            // SAFETY: a one-byte peek checks already queued trailing input.
            let count = unsafe {
                libc::recv(
                    stream.as_raw_fd(),
                    (&mut extra as *mut u8).cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            if count > 0 {
                return Err(invalid("trailing guest stop command bytes"));
            }
            if count < 0 {
                transient(io::Error::last_os_error())?;
            }
            return write_socket(stream.as_raw_fd(), STOP_OK, deadline);
        }
    }
}

fn forward(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: only the supervised guest application process group is targeted.
    if unsafe { libc::kill(-pid, signal) } < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

fn reap(application: libc::pid_t) -> io::Result<bool> {
    let mut app_exited = false;
    loop {
        let mut status = 0;
        // SAFETY: waitpid writes only this live status variable and never blocks.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid > 0 {
            if pid == application {
                app_exited = true;
                eprintln!("kronik-guest-init: application exited (wait status {status})");
            }
        } else if pid == 0 {
            return Ok(app_exited);
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(app_exited);
            }
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

fn stop_children(application: libc::pid_t) -> io::Result<()> {
    // SAFETY: run_guest verified PID1, so -1 reaches guest children only and
    // Linux explicitly excludes PID1/the caller from broadcast delivery.
    let rc = unsafe { libc::kill(-1, libc::SIGTERM) };
    if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err(io::Error::last_os_error());
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        reap(application)?;
        thread::sleep(Duration::from_millis(20));
    }
    // SAFETY: same guest-only broadcast, after a bounded graceful shutdown.
    let rc = unsafe { libc::kill(-1, libc::SIGKILL) };
    if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err(io::Error::last_os_error());
    }
    reap(application)?;
    Ok(())
}

fn supervise(
    config: &GuestConfig,
    application: libc::pid_t,
    signals: OwnedFd,
    vsock: OwnedFd,
    control: OwnedFd,
) -> io::Result<()> {
    let mut listeners = [Some(vsock), Some(control)];
    let connections = Arc::new(AtomicUsize::new(0));
    let mut shutdown = None;
    loop {
        if reap(application)? {
            return Ok(());
        }
        if shutdown.is_some_and(|deadline| Instant::now() >= deadline) {
            forward(application, libc::SIGKILL)?;
        }
        let mut poll = [
            libc::pollfd {
                fd: signals.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: listeners[0].as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: listeners[1].as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: initialized pollfd array, bounded wakeup for child reaping.
        let rc = unsafe { libc::poll(poll.as_mut_ptr(), poll.len() as libc::nfds_t, 100) };
        if rc < 0 {
            transient(io::Error::last_os_error())?;
            continue;
        }
        if poll[0].revents & libc::POLLIN != 0 {
            // SAFETY: zero is a valid initial signalfd_siginfo representation.
            let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            // SAFETY: buffer is exactly one signalfd record.
            let bytes = unsafe {
                libc::read(
                    signals.as_raw_fd(),
                    (&mut info as *mut libc::signalfd_siginfo).cast(),
                    std::mem::size_of_val(&info),
                )
            };
            if bytes < 0 {
                transient(io::Error::last_os_error())?;
            } else if bytes as usize != std::mem::size_of_val(&info) {
                return Err(io::Error::other("short signal descriptor read"));
            } else if info.ssi_signo as libc::c_int != libc::SIGCHLD {
                let signal = if info.ssi_signo as libc::c_int == libc::SIGPWR {
                    libc::SIGTERM
                } else {
                    info.ssi_signo as libc::c_int
                };
                forward(application, signal)?;
                shutdown.get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
            }
        }
        for (index, port) in [VSOCK_PORT, CONTROL_PORT].into_iter().enumerate() {
            if poll[index + 1].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) == 0 {
                continue;
            }
            let fd = listeners[index]
                .as_ref()
                .ok_or_else(|| io::Error::other("missing guest listener"))?
                .as_raw_fd();
            match accept_host(fd) {
                Ok(Some(stream)) if index == 0 => proxy(stream, config.port, &connections)?,
                Ok(Some(stream)) => {
                    match receive_stop(stream) {
                        Ok(()) => {
                            // SAFETY: PID1 sends itself the supervised stop signal
                            // only after the exact control acknowledgement is sent.
                            check(
                                unsafe { libc::kill(1, libc::SIGTERM) },
                                "signalling guest shutdown",
                            )?;
                        }
                        Err(error) => {
                            eprintln!("kronik-guest-init: rejected control request: {error}")
                        }
                    }
                }
                Ok(None) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ECONNABORTED | libc::EPROTO)
                    ) => {}
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ENETRESET | libc::ECONNRESET | libc::ENOTCONN | libc::EPIPE)
                    ) =>
                {
                    eprintln!("kronik-guest-init: reopening vsock after transport reset: {error}");
                    listeners[index] = None;
                    thread::sleep(Duration::from_millis(100));
                    listeners[index] = Some(listener(port)?);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) fn run_guest(config: GuestConfig) -> io::Result<()> {
    if std::process::id() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "guest init must be PID1",
        ));
    }
    // SAFETY: setting a private guest umask has no pointer preconditions.
    unsafe {
        libc::umask(0o022);
    }
    setup_root()?;
    // Match the OCI backend on reused data: only the mounted directory itself
    // changes identity; application files keep their existing owners.
    // SAFETY: fixed mounted guest path and validated resolved process identity.
    check(
        unsafe { libc::chown(c"/data".as_ptr(), config.uid, config.gid) },
        "setting guest data root owner",
    )?;
    loopback_up()?;
    // SAFETY: hostname is validated and the byte slice is live for this call.
    check(
        unsafe { libc::sethostname(config.hostname.as_ptr().cast(), config.hostname.len()) },
        "setting guest hostname",
    )?;
    fs::create_dir_all(&config.cwd)?;
    let exec = Exec::new(&config)?;
    let signals = signal_fd()?;
    let vsock = listener(VSOCK_PORT)?;
    let control = listener(CONTROL_PORT)?;
    let application = spawn(&config, &exec)?;
    let result = supervise(&config, application, signals, vsock, control);
    let stopped = stop_children(application);
    result.and(stopped)
}

/// The `reboot(2)` command that ends the VM. Firecracker has no guest power
/// management, so `LINUX_REBOOT_CMD_POWER_OFF` is no way out of the VM: with
/// no power-off handler the kernel turns it into a halt (`kernel/reboot.c`),
/// and on x86_64 a halted vCPU leaves the VMM running. A restart is what
/// Firecracker documents ("issuing a `reboot` command inside the guest will
/// gracefully shutdown Firecracker"): with `reboot=k` on the kernel command
/// line x86_64 resets through the keyboard controller, which the VMM turns
/// into an exit, and aarch64 resets through PSCI.
const END_VM: libc::c_int = libc::LINUX_REBOOT_CMD_RESTART;

/// Ends the VM: syncs the guest file systems, then restarts the machine,
/// which makes Firecracker exit.
pub(super) fn power_off() -> io::Result<()> {
    if std::process::id() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "only guest PID1 may end the VM",
        ));
    }
    // SAFETY: sync flushes guest filesystems; reboot affects this VM only.
    unsafe {
        libc::sync();
    }
    // SAFETY: the restart command takes no pointer arguments.
    check(unsafe { libc::reboot(END_VM) }, "ending the guest")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    /// The command is pinned so that nobody turns it back into a power-off,
    /// which would leave a finished guest halted instead of gone (see
    /// [`END_VM`]). The test cannot call it: it would restart this machine.
    #[test]
    fn the_vm_is_ended_with_a_restart_and_not_a_power_off() {
        assert_eq!(END_VM, 0x0123_4567);
        assert_eq!(END_VM, libc::LINUX_REBOOT_CMD_RESTART);
        assert_ne!(END_VM, libc::LINUX_REBOOT_CMD_POWER_OFF);
        assert_ne!(END_VM, libc::LINUX_REBOOT_CMD_HALT);
    }

    #[test]
    fn relay_drains_large_payload_and_preserves_response_after_request_half_close() {
        let (mut client, incoming) = UnixStream::pair().unwrap();
        let (outgoing, mut server) = UnixStream::pair().unwrap();
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
        }
        let bridge = thread::spawn(move || relay(incoming.into(), outgoing.into()));
        let server = thread::spawn(move || {
            let mut request = Vec::new();
            server.read_to_end(&mut request).unwrap();
            assert_eq!(request, vec![b'q'; 1024 * 1024]);
            server.write_all(&vec![b'r'; 1024 * 1024]).unwrap();
            server.shutdown(Shutdown::Write).unwrap();
        });
        client.write_all(&vec![b'q'; 1024 * 1024]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, vec![b'r'; 1024 * 1024]);
        server.join().unwrap();
        bridge.join().unwrap().unwrap();
    }

    #[test]
    fn relay_reports_peer_reset_and_releases_connection_slot() {
        let slots = Arc::new(AtomicUsize::new(1));
        {
            let _slot = Connection(Arc::clone(&slots));
        }
        assert_eq!(slots.load(Ordering::Acquire), 0);
        let (mut client, incoming) = UnixStream::pair().unwrap();
        let (outgoing, server) = UnixStream::pair().unwrap();
        drop(server);
        let bridge = thread::spawn(move || relay(incoming.into(), outgoing.into()));
        let _ = client.write_all(b"pending");
        client.shutdown(Shutdown::Write).unwrap();
        assert!(bridge.join().unwrap().is_err());
    }

    #[test]
    fn proxy_connects_only_to_configured_loopback_port() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let slots = Arc::new(AtomicUsize::new(0));
        let (mut client, incoming) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let server = thread::spawn(move || {
            let (mut stream, address) = listener.accept().unwrap();
            assert!(address.ip().is_loopback());
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request");
            stream.write_all(b"response").unwrap();
        });
        proxy(incoming.into(), port, &slots).unwrap();
        let mut ready = [0u8; READY.len()];
        client.read_exact(&mut ready).unwrap();
        assert_eq!(ready, READY);
        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response");
        server.join().unwrap();
    }

    #[test]
    fn full_connection_budget_closes_new_stream_without_connecting() {
        let slots = Arc::new(AtomicUsize::new(MAX_CONNECTIONS));
        let (mut client, incoming) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        proxy(incoming.into(), 1, &slots).unwrap();
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        assert_eq!(slots.load(Ordering::Acquire), MAX_CONNECTIONS);
    }

    #[test]
    fn proxy_does_not_emit_ready_when_fixed_tcp_target_refuses_connection() {
        // Port zero cannot name a listening TCP service (bind assigns a real
        // nonzero port), so no concurrent test can turn this into a false pass.
        let slots = Arc::new(AtomicUsize::new(0));
        let (mut client, incoming) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(6)))
            .unwrap();
        proxy(incoming.into(), 0, &slots).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(reply.is_empty());
    }

    #[test]
    fn stop_control_accepts_fragmented_exact_frame_and_returns_ack() {
        let (mut host, guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let receiver = thread::spawn(move || receive_stop(guest.into()));
        host.write_all(b"ST").unwrap();
        thread::sleep(Duration::from_millis(10));
        host.write_all(b"OP\n").unwrap();
        let mut ack = [0u8; STOP_OK.len()];
        host.read_exact(&mut ack).unwrap();
        assert_eq!(ack, STOP_OK);
        receiver.join().unwrap().unwrap();
        let mut byte = [0];
        assert_eq!(host.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn stop_control_rejects_incomplete_oversized_and_non_stop_commands() {
        for bytes in [
            b"STOP".as_slice(),
            b"STOP\nx",
            b"REBOOT\n",
            b"stop\n",
            b"STOP\0",
            b"",
        ] {
            let (mut host, guest) = UnixStream::pair().unwrap();
            host.write_all(bytes).unwrap();
            host.shutdown(Shutdown::Write).unwrap();
            assert!(receive_stop(guest.into()).is_err());
        }
    }

    #[test]
    fn stop_control_has_a_bounded_partial_frame_deadline() {
        let (mut host, guest) = UnixStream::pair().unwrap();
        host.write_all(b"S").unwrap();
        let error = receive_stop(guest.into()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
