//! `isolation = "microvm"` against a real `kronik serve` without KVM (M20):
//! the add is refused with `KVM_UNAVAILABLE` and the gVisor suggestion, and
//! nothing is declared or recorded. It needs neither root, `runsc` nor an
//! image: the admission check comes before all of them.
//!
//! It runs on every host. The daemon, a debug build like this test, checks
//! the KVM device that `KRONIK_TEST_KVM_DEVICE` names, a path that does not
//! exist, so a host's own `/dev/kvm` (GitHub's runners have one) does not
//! turn the test into a skip. A release build ignores the variable, so there
//! the test runs only on a host without `/dev/kvm`.

// Test harness code: unwraps and std threads are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::path::Path;
use std::process::Output;

use common::{Daemon, command};
use serde_json::Value;

impl Daemon {
    /// `kronik serve` in `dir`, with the foreign directories in it and the
    /// host's KVM hidden from admission (a debug build reads it; see the
    /// module's documentation).
    fn start(dir: &Path) -> Daemon {
        let mut serve = Daemon::command(
            env!("CARGO_BIN_EXE_kronik"),
            dir,
            Some(&format!(
                "[foreign]\nrun_dir = {:?}\nmicrovm_dir = {:?}\n",
                dir.join("run"),
                dir.join("no-tools"),
            )),
        );
        serve.env("KRONIK_TEST_KVM_DEVICE", dir.join("no-kvm"));
        Daemon::spawn(dir, serve)
    }

    fn cli(&self, args: &[&str]) -> Output {
        command()
            .arg("--socket")
            .arg(self.socket())
            .args(args)
            .output()
            .unwrap()
    }
}

#[test]
fn microvm_without_kvm_is_a_503_with_the_gvisor_suggestion_and_declares_nothing() {
    if Path::new("/dev/kvm").exists() && !cfg!(debug_assertions) {
        eprintln!("skipped: a release daemon sees this host's /dev/kvm");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path());
    assert!(!d.dir.join("no-kvm").exists());
    let head_before = d.cli(&["--json", "foreign", "list"]);
    assert!(head_before.status.success(), "{head_before:?}");
    let out = d.cli(&[
        "--json",
        "foreign",
        "add",
        "vm",
        "--image",
        &format!("oci-layout:{}@sha256:{}", d.dir.display(), "0".repeat(64)),
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
