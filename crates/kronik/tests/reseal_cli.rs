//! `kronik privacy reseal` against a real `kronik serve`. Fails if the route
//! is not wired.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::Value;

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl std::fmt::Debug for Out {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit {}\nstdout:\n{}\nstderr:\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("{e}: {self:?}"))
    }
}

fn kronik(args: &[&str]) -> Out {
    let mut command = Command::new(KRONIK);
    for var in [
        "KRONIK_CONFIG",
        "KRONIK_DATA_DIR",
        "KRONIK_API_SOCKET",
        "KRONIK_TOKEN",
    ] {
        command.env_remove(var);
    }
    let out = command.args(args).stdin(Stdio::null()).output().unwrap();
    Out {
        code: out.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

struct Serve {
    child: Child,
    socket: std::path::PathBuf,
}

impl Serve {
    fn start(dir: &Path) -> Serve {
        let socket = dir.join("api.sock");
        let child = Command::new(KRONIK)
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .arg("--data-dir")
            .arg(dir.join("data"))
            .arg("--api-socket")
            .arg(&socket)
            .arg("--http-listen")
            .arg("127.0.0.1:0")
            .env_remove("KRONIK_CONFIG")
            .env_remove("KRONIK_DATA_DIR")
            .env_remove("KRONIK_API_SOCKET")
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let serve = Serve { child, socket };
        let up = (0..600).any(|_| {
            if kronik(&[
                "--socket",
                serve.socket.to_str().unwrap(),
                "--json",
                "privacy",
                "status",
            ])
            .code
                == 0
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
            false
        });
        assert!(up, "the API did not come up");
        serve
    }

    fn run(&self, args: &[&str]) -> Out {
        let mut all = vec!["--socket", self.socket.to_str().unwrap()];
        all.extend_from_slice(args);
        kronik(&all)
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn privacy_reseal_is_wired() {
    let dir = tempfile::tempdir().unwrap();
    let serve = Serve::start(dir.path());

    let off = serve.run(&["privacy", "reseal", "--reason", "too soon"]);
    assert_eq!(off.code, 1, "{off:?}");
    assert!(off.stderr.contains("BAD_REQUEST"), "{off:?}");
    assert!(off.stderr.contains("privacy mode is off"), "{off:?}");

    assert_eq!(
        serve
            .run(&["privacy", "mode", "on", "--reason", "gdpr"])
            .code,
        0
    );

    let dry = serve.run(&["privacy", "reseal", "--reason", "seal history", "--dry-run"]);
    assert_eq!(dry.code, 0, "{dry:?}");
    assert!(dry.stdout.contains("nothing was written"), "{dry:?}");
    assert!(
        dry.stdout
            .contains("Next     kronik privacy reseal --reason 'seal history'"),
        "{dry:?}"
    );

    let done = serve.run(&["--json", "privacy", "reseal", "--reason", "seal history"]);
    assert_eq!(done.code, 0, "{done:?}");
    let v = done.json();
    assert_eq!(v["dry_run"], false, "{v}");
    assert!(v["segments"].is_u64(), "{v}");

    let status = serve.run(&["--json", "privacy", "status"]);
    assert_eq!(status.code, 0, "{status:?}");
    let s = status.json();
    for field in [
        "segments_done",
        "segments_total",
        "values_sealed",
        "tombstones",
        "pending_segments",
    ] {
        assert!(s["reseal"][field].is_u64(), "{field}: {s}");
    }
    assert!(s["pending_erasures"].is_u64(), "{s}");

    let human = serve.run(&["privacy", "status"]);
    assert!(human.stdout.contains("Reseal"), "{human:?}");
    assert!(human.stdout.contains("Erasures"), "{human:?}");
}
