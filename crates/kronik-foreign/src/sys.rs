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

/// capset(2): the version 3 header.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

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

/// The number of threads of this process (`/proc/self/status`).
fn threads() -> io::Result<u64> {
    let status = fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|n| n.trim().parse().ok())
        .ok_or_else(|| io::Error::other("/proc/self/status has no Threads line"))
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
    // SAFETY: only this launcher is affected; no shared runtime threads exist.
    check(
        unsafe {
            libc::unshare(
                libc::CLONE_NEWNS
                    | libc::CLONE_NEWNET
                    | libc::CLONE_NEWIPC
                    | libc::CLONE_NEWUTS
                    | libc::CLONE_NEWCGROUP,
            )
        },
        "unsharing microVM namespaces",
    )?;
    jail_mounts(jail, Path::new("/dev/kvm"))?;
    clear_capabilities()
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
                         --exact sys::tests::jail_rehearsal_child --ignored --nocapture",
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

    const DESCRIPTOR_CHILD: &str = "KRONIK_TEST_CLOSE_DESCRIPTORS";

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
            let out = std::process::Command::new(std::env::current_exe().unwrap())
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
        jail_mounts(
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

        // From here on this process is inside the jail.
        if is_open(inherited) {
            return fail("a descriptor inherited from before the jail survived it".into());
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
        // The last step of the launcher's jail.
        clear_capabilities()?;
        // SAFETY: scalar prctl.
        if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
            return fail("no_new_privs is not set".into());
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
        Ok(())
    }
}
