//! `isolation = "microvm"` against a real `kronik serve` on a host without
//! KVM (M20): the add is refused with `KVM_UNAVAILABLE` and the gVisor
//! suggestion, and nothing is declared or recorded. It needs neither root,
//! `runsc` nor an image: the admission check comes before all of them.

// Test harness code: unwraps and std threads are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use common::free_port;
use serde_json::Value;

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
    ] {
        c.env_remove(var);
    }
    // The tests' temporary file system may have less than the reserve.
    c.env("KRONIK_DISK_RESERVE", "0B");
    c.stdin(Stdio::null());
    c
}

/// `kronik serve` with every directory in a temporary one; killed when
/// dropped.
struct Daemon {
    child: Child,
    socket: PathBuf,
    dir: tempfile::TempDir,
}

impl Daemon {
    fn start() -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let config = dir.path().join("kronik.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\n\n[foreign]\nrun_dir = {:?}\nmicrovm_dir = {:?}\n",
                dir.path().join("data"),
                dir.path().join("run"),
                dir.path().join("no-tools"),
            ),
        )
        .unwrap();
        let log = std::fs::File::create(dir.path().join("serve.log")).unwrap();
        let child = command()
            .arg("serve")
            .arg("--config")
            .arg(&config)
            .args(["--http-listen", &format!("127.0.0.1:{}", free_port())])
            .args(["--admin-listen", &format!("127.0.0.1:{}", free_port())])
            .arg("--api-socket")
            .arg(&socket)
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon { child, socket, dir };
        let up = (0..600).any(|_| {
            let ok = d.cli(&["--json", "actors", "list"]).status.success();
            if !ok {
                std::thread::sleep(Duration::from_millis(100));
            }
            ok
        });
        assert!(up, "kronik serve did not start:\n{}", d.log());
        d
    }

    fn cli(&self, args: &[&str]) -> Output {
        command()
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .unwrap()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("serve.log")).unwrap_or_default()
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn microvm_without_kvm_is_a_503_with_the_gvisor_suggestion_and_declares_nothing() {
    if Path::new("/dev/kvm").exists() {
        eprintln!("skipped: this host has /dev/kvm");
        return;
    }
    let d = Daemon::start();
    let head_before = d.cli(&["--json", "foreign", "list"]);
    assert!(head_before.status.success(), "{head_before:?}");
    let out = d.cli(&[
        "--json",
        "foreign",
        "add",
        "vm",
        "--image",
        &format!(
            "oci-layout:{}@sha256:{}",
            d.path().display(),
            "0".repeat(64)
        ),
        "--port",
        "8080",
        "--isolation",
        "microvm",
        "--reason",
        "test",
    ]);
    assert!(!out.status.success(), "{out:?}");
    let error: Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {out:?}\n{}", d.log()));
    assert_eq!(error["error"]["code"], "KVM_UNAVAILABLE", "{error}");
    assert!(
        error["error"]["hint"].as_str().unwrap().contains("gvisor"),
        "{error}"
    );
    // The refusal names the device; the level is an opt-in, not an experiment.
    let message = error["error"]["message"].as_str().unwrap();
    assert!(message.contains("/dev/kvm"), "{error}");
    assert!(!message.contains("experimental"), "{error}");
    let after = d.cli(&["--json", "foreign", "list"]);
    assert!(after.status.success(), "{after:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&after.stdout).unwrap()["foreign"],
        serde_json::from_slice::<Value>(&head_before.stdout).unwrap()["foreign"]
    );
    assert!(
        serde_json::from_slice::<Value>(&after.stdout).unwrap()["foreign"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
