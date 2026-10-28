//! The master key wherever the daemon was told it is: a configured file
//! outside the data directory, or `KRONIK_MASTER_KEY`. Shipping, restore
//! and start must all find it there, so a restored node reads its secrets
//! and its sealed values; and a start without the key, or with another key,
//! over existing stores is refused instead of making a new key.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const KEY_HEX: &str = "5a1f0c2e9d8b7a6f5e4d3c2b1a0f9e8d7c6b5a49382716051f2e3d4c5b6a7980";
const SECRET: &str = "restore-me-7c41e2";

/// Where the key is: a file next to (not in) the data directory, or the
/// environment.
#[derive(Clone, Copy)]
enum KeyAt {
    File,
    Env,
}

/// A `kronik` command with no setting from the developer's shell.
fn command(key: KeyAt) -> Command {
    let mut c = Command::new(KRONIK);
    for var in [
        "KRONIK_CONFIG",
        "KRONIK_DATA_DIR",
        "KRONIK_API_SOCKET",
        "KRONIK_MASTER_KEY_FILE",
        "KRONIK_MASTER_KEY",
        "KRONIK_TOKEN",
    ] {
        c.env_remove(var);
    }
    if let KeyAt::Env = key {
        c.env("KRONIK_MASTER_KEY", KEY_HEX);
    }
    c.env("KRONIK_DISK_RESERVE", "0B").stdin(Stdio::null());
    c
}

/// `kronik.toml` for a node in `dir/<name>`: its data directory, the
/// `file://` bucket when shipping, and the key file outside the data
/// directory (as `kronik serve --init` puts it in /etc/kronik).
fn config(dir: &Path, name: &str, key: KeyAt, bucket: Option<&Path>) -> PathBuf {
    let mut text = format!("[server]\ndata_dir = {:?}\n", dir.join(name).join("data"));
    if let KeyAt::File = key {
        text.push_str(&format!(
            "\n[keys]\nmaster_key_file = {:?}\n",
            dir.join("etc/master.key")
        ));
    }
    if let Some(b) = bucket {
        text.push_str(&format!(
            "\n[ship]\nenabled = true\nurl = \"file://{}\"\n",
            b.display()
        ));
    }
    let path = dir.join(format!("{name}.toml"));
    std::fs::write(&path, text).unwrap();
    path
}

struct Daemon {
    child: Option<Child>,
    socket: PathBuf,
    log: PathBuf,
}

impl Daemon {
    /// Starts `kronik serve`; `None` with the log when it exits instead.
    fn try_start(dir: &Path, name: &str, config: &Path, key: KeyAt) -> Result<Daemon, String> {
        let socket = dir.join(format!("{name}.sock"));
        let log = dir.join(format!("{name}.log"));
        let out = std::fs::File::create(&log).unwrap();
        let mut child = command(key)
            .arg("serve")
            .arg("--config")
            .arg(config)
            .args([
                "--http-listen",
                "127.0.0.1:0",
                "--admin-listen",
                "127.0.0.1:0",
            ])
            .arg("--api-socket")
            .arg(&socket)
            .env("KRONIK_LOG", "info")
            .stdout(Stdio::null())
            .stderr(out)
            .spawn()
            .unwrap();
        for _ in 0..1200 {
            if let Some(status) = child.try_wait().unwrap() {
                return Err(format!(
                    "exited {status}: {}",
                    std::fs::read_to_string(&log).unwrap_or_default()
                ));
            }
            if let Some((200, _)) = call(&socket, "GET", "/v1/health", Value::Null) {
                return Ok(Daemon {
                    child: Some(child),
                    socket,
                    log,
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        Err(format!(
            "did not start: {}",
            std::fs::read_to_string(&log).unwrap_or_default()
        ))
    }

    fn start(dir: &Path, name: &str, config: &Path, key: KeyAt) -> Daemon {
        Daemon::try_start(dir, name, config, key).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn api(&self, method: &str, path: &str, body: Value) -> Value {
        let (s, v) = call(&self.socket, method, path, body).unwrap_or_else(|| {
            panic!(
                "{method} {path}: no answer\n{}",
                std::fs::read_to_string(&self.log).unwrap_or_default()
            )
        });
        assert_eq!(s, 200, "{method} {path}: {v}");
        v
    }

    fn send(&self, actor: &str, name: &str, text: &str) -> Value {
        self.api(
            "POST",
            &format!("/v1/actors/{actor}/messages"),
            json!({"name": name, "text": text, "reason": "master key test"}),
        )
    }

    /// The counter's `hmac` reply: proof that the secret decrypts.
    fn hmac(&self) -> String {
        let v = self.send("counter/h", "hmac", "api-key\nsome data");
        v["reply"]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("no hmac reply: {v}"))
            .to_owned()
    }

    /// The sealed value `counter/on` holds for `user:1`, as an admin reads it.
    fn sealed_value(&self) -> Value {
        let v = self.api("GET", "/v1/actors/counter/on", Value::Null);
        v["state"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["key"] == "s")
            .unwrap_or_else(|| panic!("no key s: {v}"))["text"]
            .clone()
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(c.id().to_string())
                .status();
            let _ = c.wait();
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

fn call(socket: &Path, method: &str, path: &str, body: Value) -> Option<(u16, Value)> {
    let mut s = UnixStream::connect(socket).ok()?;
    let body = if body.is_null() {
        String::new()
    } else {
        body.to_string()
    };
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nhost: kronik\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).ok()?;
    let status: u16 = line.split_whitespace().nth(1)?.parse().ok()?;
    let mut len = 0;
    loop {
        let mut h = String::new();
        r.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            len = v.trim().parse().ok()?;
        }
    }
    let mut buf = vec![0; len];
    r.read_exact(&mut buf).ok()?;
    Some((status, serde_json::from_slice(&buf).ok()?))
}

/// Polls `f` for up to `secs` seconds.
fn wait(secs: u64, f: impl Fn() -> bool) -> bool {
    (0..secs * 10).any(|_| {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
        false
    })
}

fn objects(bucket: &Path, prefix: &str) -> Vec<String> {
    std::fs::read_dir(bucket.join(prefix))
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// A node with a secret and a sealed value ships to a bucket; a fresh
/// directory restored from it with the same key source serves both.
fn restore_round_trip(key: KeyAt) {
    let tmp = tempfile::Builder::new()
        .prefix("kronik-mk-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    if let KeyAt::File = key {
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/master.key"), format!("{KEY_HEX}\n")).unwrap();
    }
    let bucket = dir.join("bucket");
    std::fs::create_dir_all(&bucket).unwrap();

    // A: a secret and a sealed value, before shipping is on, so the first
    // keystore backup already holds the subject's key.
    let plain = config(dir, "a", key, None);
    let mut a = Daemon::start(dir, "a", &plain, key);
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(COUNTER).unwrap());
    a.api(
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "master key test"}),
    );
    a.api(
        "PUT",
        "/v1/secrets/api-key",
        json!({"text": SECRET, "reason": "master key test"}),
    );
    a.api(
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "secret:api-key", "reason": "master key test"}),
    );
    a.api(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "on", "reason": "master key test"}),
    );
    a.send("counter/on", "subject", "");
    let mac = a.hmac();
    assert_eq!(a.sealed_value(), "personal");
    a.stop();

    let shipping = config(dir, "a", key, Some(&bucket));
    let a = Daemon::start(dir, "a", &shipping, key);
    assert!(
        wait(60, || !objects(&bucket, "keystore").is_empty()),
        "no keystore backup was shipped\n{}",
        std::fs::read_to_string(&a.log).unwrap_or_default()
    );
    let snap = a.api(
        "POST",
        "/v1/snapshots",
        json!({"reason": "master key test"}),
    );
    let lsn = snap["snapshot"]["lsn"].as_u64().unwrap();
    let shipped = || {
        std::fs::read_to_string(dir.join("a/data/ship.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .is_some_and(|v| {
                v["snapshots"]
                    .as_array()
                    .is_some_and(|s| s.iter().any(|n| n.as_u64() == Some(lsn)))
            })
    };
    assert!(wait(60, shipped), "snapshot {lsn} was not shipped");
    drop(a);

    // B: restored with the same key source, then served.
    let b_config = config(dir, "b", key, None);
    if let KeyAt::File = key {
        // Without the key, or with another one, the keystore backup can't
        // be installed: restore fails with the code and writes nothing.
        let other = dir.join("other.key");
        std::fs::write(&other, format!("{}\n", "7".repeat(64))).unwrap();
        for (file, code) in [
            (dir.join("missing.key"), "MASTER_KEY_MISSING"),
            (other, "MASTER_KEY_MISMATCH"),
        ] {
            let out = command(key)
                .args(["--json", "restore", "--from"])
                .arg(format!("file://{}", bucket.display()))
                .arg("--config")
                .arg(&b_config)
                .arg("--master-key-file")
                .arg(&file)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(!out.status.success(), "restore without the key: {stdout}");
            assert!(stdout.contains(code), "{code}: {stdout}");
            assert!(
                !dir.join("b/data/keys").exists() && !dir.join("b/data/branches").exists(),
                "a failed restore wrote into the data directory"
            );
        }
    }
    let out = command(key)
        .args(["--json", "restore", "--from"])
        .arg(format!("file://{}", bucket.display()))
        .arg("--config")
        .arg(&b_config)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "restore: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["keystore"], "installed", "{report}");
    let b = Daemon::start(dir, "b", &b_config, key);
    assert_eq!(b.hmac(), mac, "the restored node computes another HMAC");
    assert_eq!(
        b.sealed_value(),
        "personal",
        "the restored node cannot read its sealed value"
    );
    assert!(
        !dir.join("b/data/keys/master.key").exists(),
        "a key was made in the restored data directory"
    );
}

#[test]
fn a_restore_with_the_key_in_a_configured_file_reads_secrets_and_sealed_values() {
    restore_round_trip(KeyAt::File);
}

#[test]
fn a_restore_with_the_key_in_the_environment_reads_secrets_and_sealed_values() {
    restore_round_trip(KeyAt::Env);
}

/// Without its key, or with another one, a data directory that holds
/// encrypted stores does not start; a new, empty one gets a key.
#[test]
fn a_start_without_the_key_over_existing_stores_is_refused() {
    let tmp = tempfile::Builder::new()
        .prefix("kronik-mk-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let dir = tmp.path();
    let cfg = config(dir, "n", KeyAt::File, None);
    // Make the key file in the data directory: the default place.
    let default_cfg = dir.join("default.toml");
    std::fs::write(
        &default_cfg,
        format!("[server]\ndata_dir = {:?}\n", dir.join("n/data")),
    )
    .unwrap();
    let mut n = Daemon::start(dir, "n", &default_cfg, KeyAt::File);
    let key = dir.join("n/data/keys/master.key");
    assert!(key.exists(), "an empty data directory gets a key");
    n.api(
        "PUT",
        "/v1/secrets/api-key",
        json!({"text": SECRET, "reason": "master key test"}),
    );
    n.stop();
    let kept = std::fs::read(&key).unwrap();

    std::fs::remove_file(&key).unwrap();
    let err = Daemon::try_start(dir, "n", &default_cfg, KeyAt::File)
        .err()
        .expect("started without its key");
    assert!(err.contains("MASTER_KEY_MISSING"), "{err}");
    assert!(!key.exists(), "a new key was made over existing stores");

    // Another key (here: the configured file of another node) is refused.
    std::fs::create_dir_all(dir.join("etc")).unwrap();
    std::fs::write(dir.join("etc/master.key"), format!("{KEY_HEX}\n")).unwrap();
    let err = Daemon::try_start(dir, "n", &cfg, KeyAt::File)
        .err()
        .expect("started with another key");
    assert!(err.contains("MASTER_KEY_MISMATCH"), "{err}");

    std::fs::write(&key, kept).unwrap();
    let n = Daemon::start(dir, "n", &default_cfg, KeyAt::File);
    drop(n);
}
