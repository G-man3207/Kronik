//! The M6 operator commands against a real `kronik` binary: snapshot list
//! and create, integrity, upgrade check, and restore from a `file://` bucket.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use serde_json::Value;

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const COUNTER_STEP2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter-step2.wasm"
);

const SETTINGS_ENV: [&str; 6] = [
    "KRONIK_CONFIG",
    "KRONIK_DATA_DIR",
    "KRONIK_HTTP_LISTEN",
    "KRONIK_ADMIN_LISTEN",
    "KRONIK_API_SOCKET",
    "KRONIK_MASTER_KEY_FILE",
];

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

fn command() -> Command {
    let mut command = Command::new(KRONIK);
    for var in SETTINGS_ENV {
        command.env_remove(var);
    }
    command.env_remove("KRONIK_TOKEN");
    // The tests' temporary file system may have less than the reserve.
    command.env("KRONIK_DISK_RESERVE", "0B");
    command.stdin(Stdio::null());
    command
}

fn kronik(args: &[&str]) -> Out {
    let out = command().args(args).output().unwrap();
    finish(out)
}

fn finish(out: Output) -> Out {
    Out {
        code: out.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

struct Serve {
    child: Child,
    socket: std::path::PathBuf,
    data: std::path::PathBuf,
}

impl Serve {
    fn start(dir: &Path) -> Serve {
        let socket = dir.join("api.sock");
        let data = dir.join("data");
        let child = command()
            .arg("serve")
            .arg("--data-dir")
            .arg(&data)
            .arg("--api-socket")
            .arg(&socket)
            .arg("--http-listen")
            .arg("127.0.0.1:0")
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let serve = Serve {
            child,
            socket,
            data,
        };
        let up = (0..600).any(|_| {
            if kronik(&[
                "--socket",
                serve.socket.to_str().unwrap(),
                "--json",
                "actors",
                "list",
            ])
            .code
                == 0
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
            false
        });
        assert!(up, "the API did not come up on {}", serve.socket.display());
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
fn snapshot_list_create_and_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let serve = Serve::start(dir.path());

    let empty = serve.run(&["snapshot", "list"]);
    assert_eq!(empty.code, 0, "{empty:?}");
    assert!(empty.stdout.starts_with("No snapshots yet."), "{empty:?}");
    assert!(
        empty
            .stdout
            .contains("Next     kronik snapshot create --reason \"...\""),
        "{empty:?}"
    );

    let missing = serve.run(&["snapshot", "create"]);
    assert_eq!(missing.code, 1, "{missing:?}");
    assert!(missing.stderr.contains("REASON_REQUIRED"), "{missing:?}");

    let dry = serve.run(&["snapshot", "create", "--reason", "before", "--dry-run"]);
    assert_eq!(dry.code, 0, "{dry:?}");
    assert!(dry.stdout.contains("nothing was written"), "{dry:?}");
    assert!(
        dry.stdout
            .contains("Next     kronik snapshot create --reason before"),
        "{dry:?}"
    );
    let still = serve.run(&["--json", "snapshot", "list"]).json();
    assert_eq!(still["snapshots"].as_array().unwrap().len(), 0);

    let deployed = serve.run(&["deploy", COUNTER, "--reason", "test"]);
    assert_eq!(deployed.code, 0, "{deployed:?}");
    let sent = serve.run(&["send", "counter/a", "increment", "--reason", "test"]);
    assert_eq!(sent.code, 0, "{sent:?}");

    let created = serve.run(&["--json", "snapshot", "create", "--reason", "test"]);
    assert_eq!(created.code, 0, "{created:?}");
    let v = created.json();
    assert_eq!(v["dry_run"], false);
    let snap = &v["snapshot"];
    assert!(snap["id"].as_str().unwrap().starts_with("main-"), "{v}");
    assert!(snap["lsn"].as_u64().unwrap() > 0, "{v}");
    assert!(
        snap["state_hash"].as_str().unwrap().starts_with("b3:"),
        "{v}"
    );
    assert!(snap["bytes"].as_u64().unwrap() > 0, "{v}");

    let human = serve.run(&["snapshot", "list"]);
    assert_eq!(human.code, 0, "{human:?}");
    assert!(
        human.stdout.contains(snap["id"].as_str().unwrap()),
        "{human:?}"
    );
    assert!(
        human.stdout.contains(snap["state_hash"].as_str().unwrap()),
        "{human:?}"
    );
    assert!(
        human.stdout.contains("Next     kronik snapshot list")
            || human.stdout.contains("Next     kronik snapshot create"),
        "{human:?}"
    );

    let listed = serve.run(&["--json", "snapshot", "list"]).json();
    assert_eq!(listed["snapshots"][0], *snap);

    let integrity = serve.run(&["--json", "integrity"]);
    assert_eq!(integrity.code, 0, "{integrity:?}");
    let i = integrity.json();
    assert!(i["applied_lsn"].as_u64().unwrap() > snap["lsn"].as_u64().unwrap());
    assert!(i["state_hash"].as_str().unwrap().starts_with("b3:"));
    assert!(i["log_hash"].as_str().unwrap().starts_with("b3:"));

    let text = serve.run(&["integrity"]);
    assert_eq!(text.code, 0, "{text:?}");
    for label in ["Applied LSN", "State hash", "Log hash", "Window"] {
        assert!(text.stdout.contains(label), "{label}: {text:?}");
    }
    assert!(
        text.stdout.contains(i["state_hash"].as_str().unwrap()),
        "{text:?}"
    );
    assert!(
        text.stdout.contains(i["log_hash"].as_str().unwrap()),
        "{text:?}"
    );
    assert!(
        text.stdout.contains("Next     kronik snapshot list"),
        "{text:?}"
    );
}

#[test]
fn upgrade_check_writes_a_report_and_rejects_a_bad_window() {
    let bad = kronik(&[
        "--json",
        "upgrade",
        "check",
        "--window",
        "nope",
        "--data-dir",
        "/tmp/kronik-upgrade-unused",
    ]);
    assert_eq!(bad.code, 1, "{bad:?}");
    assert_eq!(bad.json()["error"]["code"], "BAD_REQUEST");

    let empty = tempfile::tempdir().unwrap();
    let missing = kronik(&[
        "--json",
        "upgrade",
        "check",
        "--data-dir",
        empty.path().to_str().unwrap(),
    ]);
    assert_eq!(missing.code, 1, "{missing:?}");
    assert_eq!(missing.json()["error"]["code"], "BAD_REQUEST");
    assert!(
        missing.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("holds no log"),
        "{missing:?}"
    );

    let dir = tempfile::tempdir().unwrap();
    let serve = Serve::start(dir.path());
    assert_eq!(serve.run(&["deploy", COUNTER, "--reason", "test"]).code, 0);
    assert_eq!(
        serve
            .run(&["send", "counter/a", "increment", "--reason", "test"])
            .code,
        0
    );
    let data = serve.data.clone();
    drop(serve);

    let dry = kronik(&[
        "--json",
        "upgrade",
        "check",
        "--data-dir",
        data.to_str().unwrap(),
        "--window",
        "6h",
        "--dry-run",
    ]);
    assert_eq!(dry.code, 0, "{dry:?}");
    let dry_v = dry.json();
    assert_eq!(dry_v["passed"], true, "{dry:?}");
    assert_eq!(dry_v["dry_run"], true);
    assert!(dry_v.get("report_path").is_none(), "{dry:?}");
    assert!(!data.join("upgrade").exists(), "dry-run wrote a report");

    let ran = kronik(&[
        "--json",
        "upgrade",
        "check",
        "--data-dir",
        data.to_str().unwrap(),
        "--window",
        "6h",
    ]);
    assert_eq!(ran.code, 0, "{ran:?}");
    let v = ran.json();
    assert_eq!(v["passed"], true, "{ran:?}");
    assert!(v["diff_hash"].as_str().unwrap().starts_with("b3:"), "{v}");
    let report = v["report_path"].as_str().unwrap();
    assert!(Path::new(report).is_file(), "{report}");
    assert!(
        report.contains("/upgrade/"),
        "report is not next to the data directory: {report}"
    );
    let file: Value = serde_json::from_str(&std::fs::read_to_string(report).unwrap()).unwrap();
    assert_eq!(file["passed"], true);
    assert_eq!(file["to_engine"], v["to_engine"]);
}

/// The one precompiled code artifact in `dir` (`code/<hash>.<engine>.cwasm`).
fn one_cwasm(dir: &Path) -> std::path::PathBuf {
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(dir.join("code"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "cwasm"))
        .collect();
    assert_eq!(found.len(), 1, "one cwasm expected in {}", dir.display());
    found.pop().unwrap()
}

#[test]
fn upgrade_check_diverged_writes_the_diff_and_exits_one() {
    // A history written by `counter` (+1), and a second data directory that
    // only deployed `counter-step2` (+2) to harvest its precompiled code
    // artifact. Copying that artifact over the first directory's cache
    // (same engine version, so it deserializes) makes the identity replay
    // run different code than the one that wrote the log — the disagreement
    // the check exists to catch, at the data level.
    let dir = tempfile::tempdir().unwrap();
    let serve = Serve::start(dir.path());
    assert_eq!(serve.run(&["deploy", COUNTER, "--reason", "test"]).code, 0);
    assert_eq!(
        serve
            .run(&["send", "counter/a", "increment", "--reason", "test"])
            .code,
        0
    );
    let data = serve.data.clone();
    drop(serve);

    let step2 = tempfile::tempdir().unwrap();
    let serve2 = Serve::start(step2.path());
    assert_eq!(
        serve2
            .run(&["deploy", COUNTER_STEP2, "--reason", "test"])
            .code,
        0
    );
    let other = serve2.data.clone();
    drop(serve2);

    let check = |data: &Path| {
        kronik(&[
            "--json",
            "upgrade",
            "check",
            "--data-dir",
            data.to_str().unwrap(),
            "--window",
            "6h",
        ])
    };
    assert_eq!(check(&data).code, 0, "the untampered history passes");
    std::fs::copy(one_cwasm(&other), one_cwasm(&data)).unwrap();

    let out = check(&data);
    assert_eq!(out.code, 1, "{out:?}");
    let v = out.json();
    assert_eq!(v["passed"], false, "{v}");
    assert_eq!(v["code"], "ENGINE_UPGRADE_DIVERGED");
    let diff = v["diff_path"].as_str().unwrap();
    assert!(diff.ends_with(".diff.json"), "{diff}");
    assert!(Path::new(diff).is_file(), "{diff}");
    assert!(Path::new(v["report_path"].as_str().unwrap()).is_file());
    // The replay disagreed with the recorded turn: the counter's state
    // holds n=1, the swapped code writes n=2.
    let d: Value = serde_json::from_slice(&std::fs::read(diff).unwrap()).unwrap();
    assert_eq!(d["schema"], "kronik.diff/v1");
    assert_eq!(d["summary"]["changed"], true);
    assert!(
        d["summary"]["divergent_turns"].as_u64().unwrap() > 0,
        "{}",
        d["summary"]
    );
    assert_eq!(
        d["state"]["continuous"][0]["keys"][0],
        serde_json::json!({"key": "n", "op": "set", "prod": "1", "fork": "2"}),
        "{}",
        d["state"]
    );
}

#[test]
fn restore_refuses_an_existing_directory_and_dry_run_writes_nothing() {
    let bucket = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let url = format!("file://{}", bucket.path().display());
    let state = dest.path().join("branches/main/state.db");
    std::fs::create_dir_all(state.parent().unwrap()).unwrap();
    std::fs::write(&state, b"keep-me").unwrap();

    let refused = kronik(&[
        "--json",
        "restore",
        "--from",
        &url,
        "--data-dir",
        dest.path().to_str().unwrap(),
    ]);
    assert_eq!(refused.code, 1, "{refused:?}");
    assert_eq!(refused.json()["error"]["code"], "BAD_REQUEST");
    assert!(
        refused.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("already holds state"),
        "{refused:?}"
    );
    assert_eq!(std::fs::read(&state).unwrap(), b"keep-me");

    let fresh = tempfile::tempdir().unwrap();
    let marker = fresh.path().join("keep");
    std::fs::write(&marker, b"x").unwrap();
    let dry = kronik(&[
        "restore",
        "--from",
        &url,
        "--data-dir",
        fresh.path().to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(dry.code, 0, "{dry:?}");
    assert!(dry.stdout.contains("Nothing was written"), "{dry:?}");
    assert!(marker.is_file());
    assert!(
        !fresh.path().join("branches").exists(),
        "dry-run wrote into the data directory"
    );
}

#[test]
fn restore_from_a_file_bucket_lands_in_the_named_directory() {
    let dir = tempfile::tempdir().unwrap();
    let bucket = tempfile::tempdir().unwrap();
    let url = format!("file://{}", bucket.path().display());
    let config = dir.path().join("kronik.toml");
    std::fs::write(&config, format!("[ship]\nenabled = true\nurl = {url:?}\n")).unwrap();
    let socket = dir.path().join("api.sock");
    let data = dir.path().join("data");
    let mut child = command()
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .arg("--data-dir")
        .arg(&data)
        .arg("--api-socket")
        .arg(&socket)
        .arg("--http-listen")
        .arg("127.0.0.1:0")
        .env("KRONIK_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let up = (0..600).any(|_| {
        if kronik(&[
            "--socket",
            socket.to_str().unwrap(),
            "--json",
            "actors",
            "list",
        ])
        .code
            == 0
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
        false
    });
    assert!(up, "serve with shipping did not come up");
    let run = |args: &[&str]| {
        let mut all = vec!["--socket", socket.to_str().unwrap()];
        all.extend_from_slice(args);
        kronik(&all)
    };
    assert_eq!(run(&["deploy", COUNTER, "--reason", "test"]).code, 0);
    assert_eq!(
        run(&["send", "counter/a", "increment", "--reason", "test"]).code,
        0
    );
    let created = run(&["--json", "snapshot", "create", "--reason", "ship"]);
    assert_eq!(created.code, 0, "{created:?}");
    let lsn = created.json()["snapshot"]["lsn"].as_u64().unwrap();
    let hash = created.json()["snapshot"]["state_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let shipped = wait_until_shipped(&data, lsn, 225);
    let _ = child.kill();
    let _ = child.wait();
    assert!(shipped, "the snapshot was not in the bucket after 45s");

    // The master key is never in the bucket: it goes into place first.
    let with_key = |dir: &Path| {
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        std::fs::copy(data.join("keys/master.key"), dir.join("keys/master.key")).unwrap();
    };
    let dest = tempfile::tempdir().unwrap();
    with_key(dest.path());
    let restored = kronik(&[
        "--json",
        "restore",
        "--from",
        &url,
        "--data-dir",
        dest.path().to_str().unwrap(),
    ]);
    assert_eq!(restored.code, 0, "{restored:?}");
    let v = restored.json();
    assert_eq!(v["snapshot_lsn"], lsn, "{v}");
    assert_eq!(v["state_hash"], hash, "{v}");
    assert_eq!(v["data_dir"], dest.path().display().to_string());
    assert!(
        dest.path().join("branches/main/state.db").is_file(),
        "restore wrote state outside the named directory"
    );
    assert!(data.join("branches/main/state.db").is_file());

    // The next serve records the restore in the log and deletes the marker
    // (M28 review H4).
    let marker = dest.path().join("branches/main/restored.json");
    assert!(marker.is_file(), "restore left no marker");
    let dest_socket = dest.path().join("api.sock");
    let mut served = command()
        .arg("serve")
        .arg("--data-dir")
        .arg(dest.path())
        .arg("--api-socket")
        .arg(&dest_socket)
        .arg("--http-listen")
        .arg("127.0.0.1:0")
        .env("KRONIK_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let up = (0..600).any(|_| {
        let ok = kronik(&["--socket", dest_socket.to_str().unwrap(), "actors", "list"]).code == 0;
        if !ok {
            std::thread::sleep(Duration::from_millis(100));
        }
        ok
    });
    let _ = served.kill();
    let _ = served.wait();
    assert!(up, "serve on the restored directory did not come up");
    assert!(!marker.exists(), "the marker outlived the recorded restore");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let events = rt.block_on(async {
        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
        let reader = kronik_log::LogReader::new(env, dest.path().join("branches/main/log"), "main");
        let mut out = Vec::new();
        reader
            .read(1, u64::MAX, |c| {
                if let kronik_proto::Record::AuditEvent(e) = c.record {
                    out.push(e);
                }
                Ok(())
            })
            .await
            .unwrap();
        out
    });
    let restore: Vec<_> = events.iter().filter(|e| e.action == "restore").collect();
    assert_eq!(restore.len(), 1, "{events:?}");
    let through: u64 = restore[0].details["through_lsn"].parse().unwrap();
    assert!(through >= lsn, "{events:?}");
    assert_eq!(restore[0].audit.as_ref().unwrap().token_id, "system");

    let again = kronik(&[
        "--json",
        "restore",
        "--from",
        &url,
        "--data-dir",
        dest.path().to_str().unwrap(),
    ]);
    assert_eq!(again.code, 1, "{again:?}");
    assert!(
        again.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--force")
            || again.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("already holds state"),
        "{again:?}"
    );

    // A torn object must not be reported as a successful restore.
    let object = first_zst(bucket.path()).expect("the bucket has a shipped object");
    let mut bytes = std::fs::read(&object).unwrap();
    if let Some(last) = bytes.last_mut() {
        *last ^= 0xff;
    }
    std::fs::write(&object, &bytes).unwrap();
    let other = tempfile::tempdir().unwrap();
    with_key(other.path());
    let bad = kronik(&[
        "--json",
        "restore",
        "--from",
        &url,
        "--data-dir",
        other.path().to_str().unwrap(),
    ]);
    assert_ne!(bad.code, 0, "{bad:?}");
    assert!(bad.json()["error"]["code"].is_string(), "{bad:?}");
}

fn wait_until_shipped(data: &Path, lsn: u64, rounds: u32) -> bool {
    for _ in 0..rounds {
        if let Ok(text) = std::fs::read_to_string(data.join("ship.json"))
            && let Ok(v) = serde_json::from_str::<Value>(&text)
        {
            let snaps = v["snapshots"]
                .as_array()
                .is_some_and(|a| a.iter().any(|n| n.as_u64() == Some(lsn)));
            let code = v["code"].as_array().is_some_and(|a| !a.is_empty());
            if snaps && code && segment_caught_up(data, &v) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn segment_caught_up(data: &Path, v: &Value) -> bool {
    let Some(active) = v["active"].as_array() else {
        return false;
    };
    let Some(start) = active.first().and_then(|n| n.as_u64()) else {
        return false;
    };
    let Some(size) = active.get(1).and_then(|n| n.as_u64()) else {
        return false;
    };
    let path = data
        .join("branches/main/log")
        .join(format!("{start:020}.seg"));
    std::fs::metadata(path).is_ok_and(|m| m.len() == size)
}

fn first_zst(dir: &Path) -> Option<std::path::PathBuf> {
    let mut stack = vec![dir.to_owned()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "zst") {
                return Some(path);
            }
        }
    }
    None
}
