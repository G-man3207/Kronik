//! A one-shot supervisor independent of the async runtime, including shutdown.
//! Completed operations join their owner before returning; cancellation keeps
//! the independent owner alive until its process-group cleanup and reap finish.
// Linux pre-exec descriptor isolation and nonblocking pipe syscalls need unsafe.
#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use tokio::sync::oneshot;
use zeroize::{Zeroize as _, Zeroizing};

use crate::env::{BoxFuture, SensitiveProcessRequest};

const LIMIT: usize = 4096;
const POLL_MS: i32 = 5;

fn error(kind: io::ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, message)
}

// Never preserve path, executable, stderr or response bytes in an error.
fn private_error(e: io::Error) -> io::Error {
    error(e.kind(), "sensitive helper I/O failed")
}

pub(super) fn exchange(
    request: SensitiveProcessRequest,
) -> BoxFuture<'static, io::Result<Zeroizing<Vec<u8>>>> {
    Box::pin(async move {
        if request.stdin.is_empty() || request.stdin.len() > LIMIT || request.timeout.is_zero() {
            return Err(error(
                io::ErrorKind::InvalidInput,
                "invalid sensitive helper bounds",
            ));
        }
        let deadline = Instant::now().checked_add(request.timeout).ok_or_else(|| {
            error(
                io::ErrorKind::InvalidInput,
                "invalid sensitive helper deadline",
            )
        })?;
        let (tx, rx) = oneshot::channel();
        // A dropped receiver is cancellation. This thread owns kill+wait even
        // after tokio has stopped polling tasks; kill_on_drop is not a reaper.
        let owner = std::thread::Builder::new()
            .name("kronik-key-exchange".into())
            .spawn(move || {
                let result = run(request, deadline, &tx).map_err(private_error);
                let _ = tx.send(result);
            })
            .map_err(private_error)?;
        let result = rx.await;
        // Receiving the result proves child cleanup, not thread termination.
        // Startup must join this owner before shutting down its temporary
        // runtime and entering a user namespace with exactly one OS thread.
        let joined = if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime
                .spawn_blocking(move || owner.join())
                .await
                .map_err(|_| error(io::ErrorKind::Other, "sensitive helper owner join stopped"))?
        } else {
            owner.join()
        };
        joined.map_err(|_| error(io::ErrorKind::Other, "sensitive helper supervisor stopped"))?;
        result.map_err(|_| error(io::ErrorKind::Other, "sensitive helper supervisor stopped"))?
    })
}

fn open_pin(path: &std::path::Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    // Trust this effective user or CURRENT-namespace root, never infer host
    // root from a translated UID (including the overflow UID).
    let uid = unsafe { libc::geteuid() };
    if !m.is_file() || (m.uid() != uid && m.uid() != 0) || m.mode() & 0o177 != 0 {
        return Err(error(
            io::ErrorKind::PermissionDenied,
            "invalid private PIN file",
        ));
    }
    if file.as_raw_fd() >= 3 {
        return Ok(file);
    }
    // A daemon with a closed standard descriptor must not lose the PIN when
    // Command installs its private stdio before calling pre_exec.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn prepare_child(pin: i32) -> io::Result<()> {
    // Preserve kill authority across exec; the helper reapplies its own
    // non-dumpability before reading input, since exec resets that flag.
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } < 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // CLOEXEC, not close: std's exec-error pipe must report a failed exec.
    // Fail closed on kernels without close_range(CLOEXEC).
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if pin != 3 && unsafe { libc::dup2(pin, 3) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // dup2(fd, fd) does not clear CLOEXEC; only the intended fd3 survives.
    if unsafe { libc::fcntl(3, libc::F_SETFD, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct Reap {
    child: Child,
}

impl Reap {
    fn kill_group(&self) -> io::Result<()> {
        // The unreaped leader pins this PID/PGID against reuse.
        loop {
            if unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) } == 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    fn exited(&self) -> io::Result<Option<bool>> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(None)
            } else {
                Err(e)
            };
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        Ok(Some(
            info.si_code == libc::CLD_EXITED && unsafe { info.si_status() } == 0,
        ))
    }
}

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.kill_group();
        let _ = self.child.kill();
        loop {
            match self.child.wait() {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                _ => break,
            }
        }
    }
}

fn run(
    mut request: SensitiveProcessRequest,
    deadline: Instant,
    reply: &oneshot::Sender<io::Result<Zeroizing<Vec<u8>>>>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let check = || {
        if reply.is_closed() {
            Err(error(
                io::ErrorKind::Interrupted,
                "sensitive helper cancelled",
            ))
        } else if Instant::now() >= deadline {
            Err(error(io::ErrorKind::TimedOut, "sensitive helper timed out"))
        } else {
            Ok(())
        }
    };
    check()?;
    let pin = open_pin(&request.pin_file)?;
    let mut command = Command::new(&request.spec.program);
    command
        .args(&request.spec.args)
        .env_clear()
        .envs(request.spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // A private group bounds cleanup to this helper and its descendants.
    // This is not containment for a trusted module deliberately using setsid.
    command.process_group(0);
    if let Some(cwd) = &request.spec.cwd {
        command.current_dir(cwd);
    }
    let fd = pin.as_raw_fd();
    // Only async-signal-safe syscalls, no locks/allocations after fork.
    unsafe {
        command.pre_exec(move || prepare_child(fd));
    }
    check()?;
    let mut child = Reap {
        child: command.spawn()?,
    };
    drop(pin);
    let stdin = child
        .child
        .stdin
        .take()
        .ok_or_else(|| error(io::ErrorKind::Other, "sensitive helper stdin unavailable"))?;
    let mut stdout = child
        .child
        .stdout
        .take()
        .ok_or_else(|| error(io::ErrorKind::Other, "sensitive helper stdout unavailable"))?;
    nonblocking(stdin.as_raw_fd())?;
    nonblocking(stdout.as_raw_fd())?;
    let mut input = Some(stdin);
    let mut written = 0;
    let mut output = Zeroizing::new(vec![0u8; LIMIT + 1]);
    let mut used = 0;
    let mut eof = false;
    let mut status = None;
    loop {
        check()?;
        if let Some(pipe) = input.as_mut() {
            match pipe.write(&request.stdin[written..]) {
                Ok(0) => {
                    return Err(error(
                        io::ErrorKind::WriteZero,
                        "sensitive helper stdin closed",
                    ));
                }
                Ok(n) => {
                    request.stdin[written..written + n].zeroize();
                    written += n;
                    if written == request.stdin.len() {
                        // EOF before waiting for a response, not on function exit.
                        input = None;
                        request.stdin.zeroize();
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        if !eof {
            match stdout.read(&mut output[used..]) {
                Ok(0) => eof = true,
                Ok(n) => {
                    used += n;
                    if used > LIMIT {
                        return Err(error(
                            io::ErrorKind::InvalidData,
                            "sensitive helper output exceeds bound",
                        ));
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        if status.is_none() {
            status = child.exited()?;
            if status.is_some() {
                // Kill descendants holding stdout before waiting for EOF;
                // WNOWAIT leaves the leader's PID pinned until final reap.
                child.kill_group()?;
            }
        }
        if let Some(exit) = status {
            if !exit {
                return Err(error(io::ErrorKind::Other, "sensitive helper failed"));
            }
            if eof {
                if input.is_some() || used == 0 {
                    return Err(error(
                        io::ErrorKind::InvalidData,
                        "incomplete sensitive helper exchange",
                    ));
                }
                output.truncate(used);
                return Ok(output);
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: input.as_ref().map_or(-1, |p| p.as_raw_fd()),
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: if eof { -1 } else { stdout.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining.as_millis().clamp(1, POLL_MS as u128) as i32;
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LIMIT, exchange, open_pin, prepare_child};
    use crate::env::{ProcessRunner as _, ProcessSpec, SensitiveProcessRequest, Stdio as EnvStdio};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    const SECRET: &str = "exchange-private-needle";

    struct WakeThread(std::thread::Thread);
    impl Wake for WakeThread {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(WakeThread(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    fn request(dir: &Path, script: &str) -> SensitiveProcessRequest {
        let pin = dir.join("pin");
        std::fs::write(&pin, b"private-pin\n").unwrap();
        std::fs::set_permissions(&pin, std::fs::Permissions::from_mode(0o600)).unwrap();
        SensitiveProcessRequest {
            spec: ProcessSpec {
                program: "/bin/sh".into(),
                args: vec![
                    "-c".into(),
                    script.into(),
                    "helper".into(),
                    dir.join("pid").display().to_string(),
                ],
                env: vec![("EXPLICIT_SETTING".into(), "configured".into())],
                cwd: Some(dir.into()),
                stdout: EnvStdio::Append(dir.join("forbidden-stdout")),
                stderr: EnvStdio::Append(dir.join("forbidden-stderr")),
            },
            stdin: Zeroizing::new(SECRET.as_bytes().to_vec()),
            pin_file: pin,
            timeout: Duration::from_secs(2),
        }
    }

    fn pid(dir: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok(text) = std::fs::read_to_string(dir.join("pid")) {
                if let Ok(pid) = text.parse() {
                    return pid;
                }
            }
            assert!(Instant::now() < deadline, "helper did not publish its pid");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn assert_reaped(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let path = PathBuf::from(format!("/proc/{pid}"));
        while path.exists() {
            assert!(Instant::now() < deadline, "helper remains live or zombie");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn assert_private(dir: &Path, e: &io::Error) {
        let text = format!("{e:?}");
        assert!(!text.contains(SECRET));
        assert!(!text.contains("private-pin"));
        assert!(!text.contains(&dir.display().to_string()));
        assert!(!dir.join("forbidden-stdout").exists());
        assert!(!dir.join("forbidden-stderr").exists());
    }

    #[test]
    fn bad_exec_reports_error_instead_of_losing_the_exec_error_pipe() {
        let dir = tempfile::tempdir().unwrap();
        for (name, contents, mode) in [
            ("missing", None, 0o700),
            (
                "bad-executable",
                Some(b"not an executable\n".as_slice()),
                0o700,
            ),
            ("not-executable", Some(b"#!/bin/sh\n".as_slice()), 0o600),
        ] {
            let mut req = request(dir.path(), "exit 99");
            req.spec.program = dir.path().join(name);
            if let Some(bytes) = contents {
                std::fs::write(&req.spec.program, bytes).unwrap();
                std::fs::set_permissions(&req.spec.program, std::fs::Permissions::from_mode(mode))
                    .unwrap();
            }
            let e = block_on(super::super::RealProcs.exchange(req)).unwrap_err();
            if name == "missing" {
                assert_eq!(e.kind(), io::ErrorKind::NotFound);
            }
            assert_private(dir.path(), &e);
        }
    }

    #[test]
    fn overflow_timeout_crash_and_empty_response_reap_without_leaking_output() {
        let dir = tempfile::tempdir().unwrap();
        for (script, kind) in [
            (
                "printf '%s' \"$$\" > \"$1\"; IFS= read -r value; printf '%s' \"$value\"; printf '%05000d' 0; exec /bin/sleep 30",
                io::ErrorKind::InvalidData,
            ),
            (
                "printf '%s' \"$$\" > \"$1\"; exec /bin/sleep 30",
                io::ErrorKind::TimedOut,
            ),
            (
                "printf '%s' \"$$\" > \"$1\"; IFS= read -r value; printf '%s' \"$value\"; printf '%s' \"$value\" >&2; kill -TERM \"$$\"",
                io::ErrorKind::Other,
            ),
            (
                "printf '%s' \"$$\" > \"$1\"; IFS= read -r value; exit 0",
                io::ErrorKind::InvalidData,
            ),
        ] {
            let mut req = request(dir.path(), script);
            req.timeout = Duration::from_millis(300);
            let e = block_on(exchange(req)).unwrap_err();
            assert_eq!(e.kind(), kind);
            assert_reaped(pid(dir.path()));
            assert_private(dir.path(), &e);
            std::fs::remove_file(dir.path().join("pid")).unwrap();
        }
    }

    #[test]
    fn cancellation_keeps_a_supervisor_until_kill_and_reap() {
        let dir = tempfile::tempdir().unwrap();
        let req = request(
            dir.path(),
            "printf '%s' \"$$\" > \"$1\"; exec /bin/sleep 30",
        );
        let mut future = exchange(req);
        let waker = Waker::from(Arc::new(WakeThread(std::thread::current())));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let child = pid(dir.path());
        drop(future);
        assert_reaped(child);
    }

    #[test]
    fn runtime_shutdown_cancels_but_does_not_drop_the_reaper() {
        let dir = tempfile::tempdir().unwrap();
        let req = request(
            dir.path(),
            "printf '%s' \"$$\" > \"$1\"; exec /bin/sleep 30",
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let task = runtime.block_on(async {
            let task = tokio::spawn(exchange(req));
            let deadline = Instant::now() + Duration::from_secs(3);
            while !dir.path().join("pid").exists() {
                assert!(Instant::now() < deadline, "helper did not publish its pid");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            task
        });
        let child = pid(dir.path());
        drop(runtime);
        drop(task);
        assert_reaped(child);
    }

    #[test]
    fn untrusted_pin_and_invalid_bounds_never_launch_a_child() {
        let dir = tempfile::tempdir().unwrap();
        for variant in 0..7 {
            let mut req = request(dir.path(), "printf '%s' \"$$\" > \"$1\"");
            match variant {
                0 => {
                    std::fs::set_permissions(&req.pin_file, std::fs::Permissions::from_mode(0o644))
                        .unwrap()
                }
                1 => {
                    let link = dir.path().join("pin-link");
                    symlink(&req.pin_file, &link).unwrap();
                    req.pin_file = link;
                }
                2 => req.pin_file = dir.path().to_owned(),
                3 => req.stdin.resize(LIMIT + 1, b'x'),
                4 => req.stdin = Zeroizing::new(Vec::new()),
                5 => req.timeout = Duration::ZERO,
                _ => req.timeout = Duration::MAX,
            }
            let e = block_on(exchange(req)).unwrap_err();
            assert_private(dir.path(), &e);
            assert!(!dir.path().join("pid").exists());
        }
    }

    #[test]
    fn exact_four_kibibyte_request_and_response_are_not_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let mut req = request(
            dir.path(),
            "printf '%s' \"$$\" > \"$1\"; IFS= read -r value; \
             [ \"${#value}\" -eq 4096 ] || exit 9; printf '%04096d' 0",
        );
        req.stdin.resize(LIMIT, b'x');
        let output = block_on(exchange(req)).unwrap();
        assert_eq!(output.len(), LIMIT);
        assert_reaped(pid(dir.path()));
    }

    #[test]
    fn opaque_malformed_response_is_already_reaped_before_protocol_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let req = request(
            dir.path(),
            "printf '%s' \"$$\" > \"$1\"; IFS= read -r value; printf '{broken'",
        );
        let output = block_on(exchange(req)).unwrap();
        assert_reaped(pid(dir.path()));
        assert!(serde_json::from_slice::<serde_json::Value>(&output).is_err());
    }

    #[test]
    fn fd3_same_number_and_duplicate_cases_keep_only_the_pin() {
        for same in [true, false] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "env::real::exchange::tests::fd3_driver",
                    "--nocapture",
                ])
                .env(
                    "KRONIK_EXCHANGE_FD_DRIVER",
                    if same { "same" } else { "different" },
                )
                .env("HOME", "parent-setting-must-not-inherit")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            for stream in [&output.stdout, &output.stderr] {
                assert!(!String::from_utf8_lossy(stream).contains(SECRET));
                assert!(!String::from_utf8_lossy(stream).contains("private-pin"));
            }
        }
    }

    // This runs in its own process: assigning fd3 must not damage test-harness
    // descriptors belonging to concurrently running boundary tests.
    #[test]
    fn fd3_driver() {
        let Ok(mode) = std::env::var("KRONIK_EXCHANGE_FD_DRIVER") else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let req = request(dir.path(), "");
        let pin = open_pin(&req.pin_file).unwrap();
        let extra = unsafe { libc::fcntl(pin.as_raw_fd(), libc::F_DUPFD, 80) };
        assert!(extra >= 80);
        let extra = unsafe { File::from_raw_fd(extra) };
        let source = if mode == "same" {
            assert_eq!(unsafe { libc::dup2(pin.as_raw_fd(), 3) }, 3);
            assert_eq!(
                unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
            3
        } else {
            extra.as_raw_fd()
        };
        let script = format!(
            "IFS= read -r pin <&3 || exit 20; [ \"${{#pin}}\" -eq 11 ] || exit 21; \
             if printf x >&3; then exit 22; fi; [ ! -e /proc/self/fd/{} ] || exit 23; \
             [ -z \"${{HOME+x}}\" ] || exit 24; [ \"$EXPLICIT_SETTING\" = configured ] || exit 25; \
             printf public-result",
            extra.as_raw_fd()
        );
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", &script])
            .env_clear()
            .env("EXPLICIT_SETTING", "configured")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || prepare_child(source));
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{:?}", output.status);
        assert_eq!(output.stdout, b"public-result");
        // The production transport must force private stdio and EOF as well.
        let script = "IFS= read -r value; [ \"${#value}\" -eq 23 ] || exit 31; \
                      if IFS= read -r more; then exit 32; fi; printf '%s' \"$value\" >&2; printf public-result";
        let req = request(dir.path(), script);
        let result = block_on(exchange(req)).unwrap();
        assert_eq!(&*result, b"public-result");
        assert!(!dir.path().join("forbidden-stdout").exists());
        assert!(!dir.path().join("forbidden-stderr").exists());
    }

    #[test]
    fn descendants_are_killed_on_cancel_overflow_timeout_crash_and_success() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "env::real::exchange::tests::group_driver",
                "--nocapture",
            ])
            .env("KRONIK_EXCHANGE_GROUP_DRIVER", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Isolate the test-only subreaper from every other test and use only the
    // known descendant PID: production never changes daemon subreaper policy.
    #[test]
    fn group_driver() {
        if std::env::var_os("KRONIK_EXCHANGE_GROUP_DRIVER").is_none() {
            return;
        }
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        for (case, action, kind) in [
            ("cancel", "wait", Some(io::ErrorKind::Interrupted)),
            ("timeout", "wait", Some(io::ErrorKind::TimedOut)),
            (
                "overflow",
                "printf '%05000d' 0; wait",
                Some(io::ErrorKind::InvalidData),
            ),
            ("crash", "kill -TERM \"$$\"", Some(io::ErrorKind::Other)),
            ("success", "printf public-result; exit 0", None),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let script = format!(
                "/bin/sleep 30 & printf '%s' \"$!\" > descendant; \
                 printf '%s' \"$$\" > \"$1\"; IFS= read -r value; {action}"
            );
            let mut req = request(dir.path(), &script);
            req.timeout = Duration::from_millis(500);
            if case == "cancel" {
                let mut future = exchange(req);
                let waker = Waker::from(Arc::new(WakeThread(std::thread::current())));
                assert!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                let _ = pid(dir.path());
                drop(future);
            } else {
                let result = block_on(exchange(req));
                if let Some(kind) = kind {
                    assert_eq!(result.unwrap_err().kind(), kind, "{case}");
                } else {
                    assert_eq!(&*result.unwrap(), b"public-result");
                }
            }
            let child = pid(dir.path());
            assert_reaped(child);
            let descendant: libc::pid_t = std::fs::read_to_string(dir.path().join("descendant"))
                .unwrap()
                .parse()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let mut status = 0;
                let reaped = unsafe { libc::waitpid(descendant, &mut status, libc::WNOHANG) };
                if reaped == descendant {
                    assert!(libc::WIFSIGNALED(status), "{case}");
                    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL, "{case}");
                    break;
                }
                if reaped < 0 {
                    let e = io::Error::last_os_error();
                    assert_eq!(e.raw_os_error(), Some(libc::ECHILD), "{case}");
                    // A shell may win the race to reap its child before the
                    // same group-wide signal kills the shell itself.
                    if !Path::new(&format!("/proc/{descendant}")).exists() {
                        break;
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "{case}: descendant still live or zombie"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(
                !Path::new(&format!("/proc/{descendant}")).exists(),
                "{case}"
            );
        }
    }
}
