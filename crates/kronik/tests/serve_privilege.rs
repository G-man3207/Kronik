//! `kronik serve` without `--rootless` starts as it did before M21, for root
//! and for an ordinary user alike (developer and CI use): it makes no
//! acceptor process and sets no `no_new_privs`. `--rootless` is the nonroot
//! service, which the unit that `serve --init --rootless` writes asks for: it
//! refuses to run as root, and as an ordinary user it empties every capability
//! set and serves the API through an acceptor of its own.
//!
//! Whoever runs this test is who `serve` runs as, so each arm covers one
//! kind of host: the plain daemon (root on a developer's machine, an ordinary
//! user on a CI runner) always, `--rootless` as root for the refusal, and
//! `--rootless` as an ordinary user for the nonroot service.

// Test harness code: unwraps and std threads are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::free_port;

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");

fn command() -> Command {
    let mut c = Command::new(KRONIK);
    for var in [
        "KRONIK_CONFIG",
        "KRONIK_DATA_DIR",
        "KRONIK_HTTP_LISTEN",
        "KRONIK_ADMIN_LISTEN",
        "KRONIK_API_SOCKET",
        "KRONIK_API_LISTEN",
        "KRONIK_TOKEN",
        "KRONIK_MASTER_KEY_FILE",
        "KRONIK_MASTER_KEY",
    ] {
        c.env_remove(var);
    }
    // The tests' temporary file system may have less than the reserve.
    c.env("KRONIK_DISK_RESERVE", "0B");
    c.stdin(Stdio::null());
    c
}

/// `kronik serve` with every path in `dir`.
fn serve(dir: &Path, extra: &[&str]) -> Command {
    let mut c = command();
    c.arg("serve")
        .arg("--data-dir")
        .arg(dir.join("data"))
        .args(["--http-listen", &format!("127.0.0.1:{}", free_port())])
        .args(["--admin-listen", &format!("127.0.0.1:{}", free_port())])
        .arg("--api-socket")
        .arg(dir.join("api.sock"))
        .args(extra);
    c
}

/// A running daemon, killed when dropped.
struct Daemon {
    child: Child,
    dir: std::path::PathBuf,
}

impl Daemon {
    fn start(dir: &Path, extra: &[&str]) -> Daemon {
        let log = std::fs::File::create(dir.join("serve.log")).unwrap();
        let child = serve(dir, extra)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let daemon = Daemon {
            child,
            dir: dir.to_owned(),
        };
        let socket = dir.join("api.sock");
        let up = (0..600).any(|_| {
            let ok = command()
                .arg("--socket")
                .arg(&socket)
                .args(["--json", "actors", "list"])
                .output()
                .unwrap()
                .status
                .success();
            if !ok {
                std::thread::sleep(Duration::from_millis(100));
            }
            ok
        });
        assert!(up, "kronik serve did not start:\n{}", daemon.log());
        daemon
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn status_field(pid: u32, field: &str) -> String {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    text.lines()
        .find_map(|l| l.strip_prefix(field))
        .unwrap_or_else(|| panic!("no {field} in /proc/{pid}/status"))
        .trim()
        .to_owned()
}

/// The processes whose parent is `pid` and that run the same program: a
/// forked helper of the daemon, not `runsc` or another tool it starts.
///
/// The daemon that has loaded its master key is not dumpable (no core dump can
/// carry the key, `protect_process` in kronik-privacy), and `/proc/<pid>/exe`
/// and `cmdline` are EACCES to the same uid once that is so, unless it has
/// CAP_SYS_PTRACE. That is why root can ask for the executable and an ordinary
/// runner cannot: fall back to the command name, which `/proc/<pid>/comm`
/// exposes to everyone and which a forked helper shares with its parent.
fn forked_children(pid: u32) -> Vec<u32> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok();
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&child| {
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{child}/stat")) else {
                return false;
            };
            // The command name may hold spaces and parentheses; the parent pid
            // is the second field after the last `)`.
            let ppid = stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().nth(1))
                .and_then(|p| p.parse::<u32>().ok());
            if ppid != Some(pid) {
                return false;
            }
            match &exe {
                Some(exe) => {
                    std::fs::read_link(format!("/proc/{child}/exe")).ok() == Some(exe.clone())
                }
                None => std::fs::read_to_string(format!("/proc/{child}/comm")).ok() == comm,
            }
        })
        .collect()
}

#[test]
fn serve_without_rootless_keeps_the_process_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path(), &[]);
    // No no_new_privs: the nonroot service sets it, a plain daemon never did.
    assert_eq!(
        status_field(daemon.pid(), "NoNewPrivs:"),
        "0",
        "{}",
        daemon.log()
    );
    // No acceptor: the daemon serves the API socket itself.
    assert!(forked_children(daemon.pid()).is_empty(), "{}", daemon.log());
    assert!(
        !daemon.log().contains("ROOTLESS_UNAVAILABLE"),
        "{}",
        daemon.log()
    );
}

#[test]
fn serve_rootless_refuses_to_run_as_root() {
    if !kronik_foreign::sys::is_root() {
        eprintln!("skipped: only root can show the refusal");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = serve(dir.path(), &["--rootless"]).output().unwrap();
    assert!(!out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("ROOTLESS_UNAVAILABLE"), "{text}");
    assert!(text.contains("unprivileged service user"), "{text}");
    // Refused before anything was created or bound.
    assert!(!dir.path().join("data").exists());
    assert!(!dir.path().join("api.sock").exists());
}

#[test]
fn serve_rootless_as_an_ordinary_user_drops_every_capability_and_forks_an_acceptor() {
    if kronik_foreign::sys::is_root() {
        eprintln!("skipped: root is refused (see above); the nonroot service needs a user");
        return;
    }
    if let Err(why) = kronik_foreign::sys::acceptor_view() {
        // A rootless container or a nested user namespace: the very case the
        // service refuses, which the daemon's own start would show.
        let dir = tempfile::tempdir().unwrap();
        let out = serve(dir.path(), &["--rootless"]).output().unwrap();
        assert!(!out.status.success(), "{out:?}");
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(text.contains("ROOTLESS_UNAVAILABLE"), "{text}");
        assert!(text.contains(&why.to_string()), "{text}");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path(), &["--rootless"]);
    let pid = daemon.pid();
    let log = daemon.log();
    // Every capability set of the daemon is empty and it cannot gain any.
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        assert_eq!(
            status_field(pid, field),
            "0000000000000000",
            "{field} {log}"
        );
    }
    assert_eq!(status_field(pid, "NoNewPrivs:"), "1", "{log}");
    // One acceptor, with the same user, no capability and no new privileges.
    let acceptors = forked_children(pid);
    assert_eq!(acceptors.len(), 1, "{acceptors:?}\n{log}");
    let acceptor = acceptors[0];
    assert_eq!(
        status_field(acceptor, "CapEff:"),
        "0000000000000000",
        "{log}"
    );
    assert_eq!(status_field(acceptor, "NoNewPrivs:"), "1", "{log}");
    assert_eq!(
        status_field(acceptor, "Uid:"),
        status_field(pid, "Uid:"),
        "{log}"
    );
    // Without the pinned namespace foreign actors say so; Wasm actors run.
    assert!(log.contains("foreign actors are unavailable"), "{log}");
}
