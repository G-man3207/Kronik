//! M7 acceptance with a real `kronik serve`, real runsc and the
//! `foreign-echo` image (docs/design/m7-foreign.md §14). Needs root, runsc
//! and `scripts/build-foreign-examples.sh`; without them the tests say why
//! and pass, unless `KRONIK_FOREIGN_TESTS=require` (`scripts/ci.sh foreign`),
//! which turns that into a failure.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Value, json};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const RUNSC: &str = "/usr/local/bin/runsc";
const SECRET: &str = "s3cr3t-echo-token-7f1c";

fn layout() -> PathBuf {
    Path::new(ROOT).join("examples/dist/foreign-echo.oci")
}

/// Why the tests cannot run here, if they cannot.
fn missing() -> Option<String> {
    if !kronik_foreign::sys::is_root() {
        return Some("needs root".into());
    }
    if !Path::new(RUNSC).exists() {
        return Some(format!("needs runsc at {RUNSC}"));
    }
    if !layout().join("index.json").exists() {
        return Some(format!(
            "needs {} (run scripts/build-foreign-examples.sh)",
            layout().display()
        ));
    }
    None
}

fn should_run() -> bool {
    match missing() {
        None => true,
        Some(why) if std::env::var("KRONIK_FOREIGN_TESTS").as_deref() == Ok("require") => {
            panic!("KRONIK_FOREIGN_TESTS=require, but the foreign tests cannot run: {why}")
        }
        Some(why) => {
            eprintln!("skipped: the foreign tests {why}");
            false
        }
    }
}

struct Daemon {
    dir: PathBuf,
    child: Option<Child>,
}

impl Daemon {
    fn start(dir: &Path) -> Daemon {
        Daemon::start_with(dir, &[])
    }

    fn start_with(dir: &Path, extra: &[&str]) -> Daemon {
        let config = dir.join("kronik.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\n\n[foreign]\nrun_dir = {:?}\n",
                dir.join("data"),
                dir.join("run")
            ),
        )
        .unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_kronik"))
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .arg("--config")
            .arg(&config)
            .args([
                "--http-listen",
                "127.0.0.1:0",
                "--admin-listen",
                "127.0.0.1:0",
                "--api-socket",
            ])
            .arg(dir.join("api.sock"))
            .args(extra)
            .env("KRONIK_LOG", "info")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon {
            dir: dir.to_path_buf(),
            child: Some(child),
        };
        for _ in 0..2400 {
            if d.try_api("GET", "/v1/health", Value::Null)
                .is_some_and(|(s, _)| s == 200)
            {
                return d;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("daemon did not start: {}", d.serve_log());
    }

    fn serve_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    fn kill9(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// SIGTERM: a graceful stop.
    fn term(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(c.id().to_string())
                .status();
            let _ = c.wait();
        }
    }

    fn try_api(&self, method: &str, path: &str, body: Value) -> Option<(u16, Value)> {
        let mut s = UnixStream::connect(self.dir.join("api.sock")).ok()?;
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

    fn api(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        self.try_api(method, path, body)
            .unwrap_or_else(|| panic!("API {method} {path} failed: {}", self.serve_log()))
    }

    fn ok(&self, method: &str, path: &str, body: Value) -> Value {
        let (s, v) = self.api(method, path, body);
        assert_eq!(s, 200, "{method} {path}: {v}");
        v
    }

    /// The counter guest's `fetch-ok`: one request, the reply is
    /// `<status> <body>` or `error <e>`.
    fn fetch(&self, spec: &str) -> String {
        let v = self.ok(
            "POST",
            "/v1/actors/counter/c1/messages",
            json!({"name": "fetch-ok", "text": spec, "reason": "foreign test"}),
        );
        v["reply"]["text"].as_str().unwrap_or_default().to_owned()
    }

    /// Like `fetch`, with the LSN of the turn.
    fn fetch_lsn(&self, spec: &str) -> (String, u64) {
        let v = self.ok(
            "POST",
            "/v1/actors/counter/c1/messages",
            json!({"name": "fetch-ok", "text": spec, "reason": "foreign test"}),
        );
        let lsn = v["turn_id"]
            .as_str()
            .and_then(|t| t.rsplit(':').next())
            .and_then(|n| n.parse().ok())
            .unwrap();
        (
            v["reply"]["text"].as_str().unwrap_or_default().to_owned(),
            lsn,
        )
    }

    fn foreign(&self, name: &str) -> Value {
        self.ok("GET", &format!("/v1/foreign/{name}"), Value::Null)["foreign"].clone()
    }

    fn wait_until(&self, what: &str, f: impl Fn(&Daemon) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if f(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for {what}: {}", self.serve_log());
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.term();
    }
}

/// Removes every sandbox, namespace and mount the test left behind.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let run = self.0.join("run");
        for (bin, root, quiet) in [
            (RUNSC, run.join("runsc"), "-quiet"),
            ("/usr/bin/runc", run.join("runc"), "-q"),
        ] {
            for id in containers(bin, &root, quiet) {
                let _ = Command::new(bin)
                    .arg("--root")
                    .arg(&root)
                    .args(["delete", "--force", &id])
                    .output();
            }
            let _ = Command::new("umount").arg(root.join("null-netns")).output();
        }
        if let Ok(entries) = std::fs::read_dir(run.join("netns")) {
            for e in entries.flatten() {
                let _ = kronik_foreign::sys::delete_netns(&e.path());
            }
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn containers(bin: &str, root: &Path, quiet: &str) -> Vec<String> {
    Command::new(bin)
        .arg("--root")
        .arg(root)
        .args(["list", quiet])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        let Ok(md) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if md.is_dir() {
            out.extend(files_containing(&p, needle));
        } else if md.is_file()
            && std::fs::read(&p).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle))
        {
            out.push(p);
        }
    }
    out
}

#[test]
fn foreign_actors_end_to_end() {
    if !should_run() {
        return;
    }
    let dir = tempfile::Builder::new()
        .prefix("kronik-m7-")
        .tempdir_in("/var/tmp")
        .unwrap()
        .keep();
    let _cleanup = Cleanup(dir.clone());
    let mut d = Daemon::start(&dir);
    let runsc_root = dir.join("run/runsc");
    let image = format!("oci-layout:{}", layout().canonicalize().unwrap().display());

    // A counter actor that makes the calls.
    let wasm = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(ROOT).join("tests/guests/counter.wasm")).unwrap());
    d.ok(
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "foreign test"}),
    );
    d.ok(
        "PUT",
        "/v1/secrets/echo-token",
        json!({"text": SECRET, "reason": "foreign test"}),
    );

    // microvm is reserved; an unpinned registry image is refused.
    let (s, v) = d.api(
        "POST",
        "/v1/foreign",
        json!({"name": "vm", "image": image, "port": 8080, "isolation": "microvm", "reason": "t"}),
    );
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (501, Some("NOT_IMPLEMENTED")),
        "{v}"
    );
    let (s, v) = d.api(
        "POST",
        "/v1/foreign",
        json!({"name": "x", "image": "ghcr.io/org/x:latest", "port": 8080, "reason": "t"}),
    );
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("IMAGE_INVALID")),
        "{v}"
    );

    // Add echo; it runs in gVisor.
    let v = d.ok(
        "POST",
        "/v1/foreign",
        json!({"name": "echo", "image": image, "port": 8080, "cpu_millis": 1000,
               "memory_bytes": 268435456u64, "secrets": ["ECHO_TOKEN=echo-token"],
               "reason": "foreign test"}),
    );
    assert_eq!(v["foreign"]["status"]["state"], "running", "{v}");
    assert_eq!(v["foreign"]["platform"], "systrap");
    assert!(v["foreign"]["image"].as_str().unwrap().contains("@sha256:"));
    let (s, v) = d.api(
        "POST",
        "/v1/foreign",
        json!({"name": "echo", "image": image, "port": 8080, "reason": "again"}),
    );
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (409, Some("FOREIGN_EXISTS")),
        "{v}"
    );
    assert_eq!(
        containers(RUNSC, &runsc_root, "-quiet"),
        [kronik_foreign::Foreign::container_id("echo")]
    );

    // Default deny (I6): no grant, no call.
    let r = d.fetch("GET foreign://echo/healthz");
    assert!(r.contains("CAPABILITY_NOT_GRANTED"), "{r}");
    d.ok(
        "POST",
        "/v1/grants",
        json!({"kind": "counter", "capability": "foreign:echo", "reason": "foreign test"}),
    );
    // A fork of the history so far: the calls below are replayed in it.
    let fork = d.ok(
        "POST",
        "/v1/forks",
        json!({"at": "now", "reason": "foreign test"}),
    )["fork"]["name"]
        .as_str()
        .unwrap()
        .to_owned();

    // The actor calls echo through the bridge.
    assert_eq!(d.fetch("GET foreign://echo/healthz"), "200 ok");
    let r = d.fetch("POST foreign://echo/echo?x=1\nH content-type text/plain\n\nhello sandbox");
    assert!(r.starts_with("200 "), "{r}");
    let echoed: Value = serde_json::from_str(&r[4..]).unwrap();
    assert_eq!(echoed["body"], "hello sandbox");
    assert_eq!(echoed["headers"]["host"], "echo");
    assert_eq!(
        echoed["headers"]["idempotency-key"].as_str().unwrap().len(),
        64
    );
    // The secret reached the program's environment.
    let r = d.fetch("GET foreign://echo/env?name=ECHO_TOKEN");
    let env: Value = serde_json::from_str(&r[4..]).unwrap();
    assert_eq!(env["set"], true, "{r}");
    assert_eq!(env["sha256"], sha256_hex(SECRET.as_bytes()));

    // Egress is blocked: TCP, UDP and DNS from inside the sandbox all fail,
    // and its namespace has only lo.
    let host_ip = String::from_utf8(Command::new("hostname").arg("-I").output().unwrap().stdout)
        .unwrap()
        .split_whitespace()
        .find(|a| a.contains('.'))
        .unwrap_or("10.0.0.1")
        .to_owned();
    let r = d.fetch(&format!("GET foreign://echo/egress?target={host_ip}:22"));
    let egress: Value = serde_json::from_str(&r[4..]).unwrap();
    let attempts = egress["attempts"].as_array().unwrap();
    assert!(attempts.len() >= 8, "{r}");
    assert_eq!(
        egress["succeeded"], 0,
        "egress from the sandbox succeeded: {r}"
    );
    assert!(attempts.iter().all(|a| a["ok"] == false), "{r}");
    eprintln!("egress attempts from the sandbox: {r}");
    let ns = dir.join("run/netns/echo");
    assert_eq!(kronik_foreign::sys::netns_interfaces(&ns).unwrap(), ["lo"]);

    // The calls are recorded as foreign.http.
    let hist = d.ok(
        "GET",
        "/v1/actors/counter/c1/history?limit=100",
        Value::Null,
    );
    let effects: Vec<Value> = hist["turns"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|t| t["effects"].as_array().cloned().unwrap_or_default())
        .collect();
    let live: Vec<&Value> = effects
        .iter()
        .filter(|e| e["kind"] == "foreign.http" && e["status"] == "ok")
        .collect();
    assert_eq!(live.len(), 4, "{effects:?}");
    assert!(live.iter().all(|e| e["target"] == "foreign:echo"));
    assert!(
        effects
            .iter()
            .any(|e| e["kind"] == "foreign.http" && e["status"] == "denied")
    );

    // A crash restarts it with backoff.
    let r = d.fetch("POST foreign://echo/exit?code=3");
    assert!(r.starts_with("200"), "{r}");
    d.wait_until("echo restarted", |d| {
        let f = d.foreign("echo");
        f["status"]["restarts"].as_u64() >= Some(1) && f["status"]["state"] == "running"
    });
    let f = d.foreign("echo");
    assert_eq!(f["status"]["last_exit"]["code"], 3, "{f}");
    let gap = f["status"]["since_ms"].as_u64().unwrap()
        - f["status"]["last_exit"]["at_ms"].as_u64().unwrap();
    assert!(
        gap >= 450,
        "restarted {gap} ms after the exit, before the backoff"
    );
    assert_eq!(d.fetch("GET foreign://echo/healthz"), "200 ok");

    // The daemon dies with the sandbox running: the next start removes the
    // leftover and starts it fresh before serving.
    d.kill9();
    assert_eq!(
        containers(RUNSC, &runsc_root, "-quiet"),
        [kronik_foreign::Foreign::container_id("echo")]
    );
    d = Daemon::start(&dir);
    assert_eq!(d.foreign("echo")["status"]["state"], "running");
    assert_eq!(d.foreign("echo")["status"]["starts"], 1);
    assert_eq!(
        containers(RUNSC, &runsc_root, "-quiet"),
        [kronik_foreign::Foreign::container_id("echo")]
    );
    let (r, last_call) = d.fetch_lsn("GET foreign://echo/healthz");
    assert_eq!(r, "200 ok");

    // trusted: plain runc, with a warning; still no network out.
    if Path::new("/usr/bin/runc").exists() {
        let v = d.ok(
            "POST",
            "/v1/foreign",
            json!({"name": "echo-t", "image": image, "port": 8080, "isolation": "trusted",
                   "reason": "foreign test"}),
        );
        assert!(
            v["warnings"][0].as_str().unwrap().contains("plain runc"),
            "{v}"
        );
        assert_eq!(v["foreign"]["status"]["state"], "running", "{v}");
        d.ok(
            "POST",
            "/v1/grants",
            json!({"kind": "counter", "capability": "foreign:echo-t", "reason": "t"}),
        );
        assert_eq!(d.fetch("GET foreign://echo-t/healthz"), "200 ok");
        let r = d.fetch("GET foreign://echo-t/egress");
        let egress: Value = serde_json::from_str(&r[4..]).unwrap();
        let attempts = egress["attempts"].as_array().unwrap();
        assert!(attempts.len() >= 8, "{r}");
        assert_eq!(
            egress["succeeded"], 0,
            "egress from the trusted sandbox succeeded: {r}"
        );
        assert!(attempts.iter().all(|a| a["ok"] == false), "{r}");
        d.ok(
            "DELETE",
            "/v1/foreign/echo-t",
            json!({"reason": "foreign test"}),
        );
    }

    // Remove stops the sandbox: no container, namespace or cgroup is left.
    let logs = d.ok("GET", "/v1/foreign/echo/logs?tail=50", Value::Null);
    assert!(
        logs["lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str().unwrap().contains("listening")),
        "{logs}"
    );
    // Only this daemon's cgroup: kronik-foreign puts it at
    // /sys/fs/cgroup/kronik/<first 8 hex of the runsc root's blake3>/echo,
    // and the other foreign tests run their own daemons (and their own
    // `echo` cgroups) under /sys/fs/cgroup/kronik at the same time.
    let instance = blake3::hash(runsc_root.as_os_str().as_encoded_bytes()).to_hex();
    let cgroup = Path::new("/sys/fs/cgroup/kronik")
        .join(&instance.as_str()[..8])
        .join("echo");
    assert!(cgroup.exists(), "no cgroup for echo");
    d.ok(
        "DELETE",
        "/v1/foreign/echo",
        json!({"reason": "foreign test"}),
    );
    assert!(containers(RUNSC, &runsc_root, "-quiet").is_empty());
    assert!(!ns.exists());
    assert!(
        !cgroup.exists(),
        "the echo cgroup is still there: {cgroup:?}"
    );
    let (s, v) = d.api("GET", "/v1/foreign/echo", Value::Null);
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (404, Some("FOREIGN_NOT_FOUND"))
    );
    let r = d.fetch("GET foreign://echo/healthz");
    assert!(r.contains("FOREIGN_NOT_FOUND"), "{r}");

    // Replay matches the recorded calls and starts nothing (I7): echo is
    // removed, and the fork still answers every call exactly. The window
    // ends before the configuration changes below the fork point would
    // make turns differ (trusted's grant, the removal).
    let v = d.ok(
        "POST",
        &format!("/v1/forks/{fork}/replay"),
        json!({"mode": "isolated", "to_lsn": last_call, "reason": "foreign test"}),
    );
    let summary = &v["summary"];
    assert_eq!(summary["synthetic"], 0, "{v}");
    assert!(summary["exact"].as_u64() >= Some(5), "{v}");
    assert_eq!(summary["changed"], false, "{v}");
    let diff = d.ok("GET", &format!("/v1/forks/{fork}/diff"), Value::Null);
    let g = diff["grounding"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["kind"] == "foreign.http")
        .cloned()
        .unwrap_or_default();
    assert_eq!(g["host"], "echo", "{diff}");
    assert_eq!(g["synthetic"], 0);
    assert!(containers(RUNSC, &runsc_root, "-quiet").is_empty());

    // The injected secret never reached the log, state or any file.
    d.term();
    let leaks = files_containing(&dir.join("data"), SECRET.as_bytes());
    assert!(leaks.is_empty(), "the secret is in {leaks:?}");
    let serve_log = std::fs::read_to_string(dir.join("serve.log")).unwrap();
    assert!(!serve_log.contains(SECRET));
}

fn tool(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Removes the test's registry container (Docker is shared: only ours).
struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}

/// `foreign add` from a registry, pinned by digest (the brief's other
/// source), and from a layout by ref name.
#[test]
fn foreign_add_from_a_registry_and_by_ref_name() {
    if !should_run() {
        return;
    }
    if !tool("docker") || !tool("skopeo") {
        eprintln!("skipped: the registry test needs docker and skopeo");
        return;
    }
    let dir = tempfile::Builder::new()
        .prefix("kronik-m7-reg-")
        .tempdir_in("/var/tmp")
        .unwrap()
        .keep();
    let _cleanup = Cleanup(dir.clone());
    let name = format!("kronik-m7-registry-{}", std::process::id());
    let _ = Command::new("docker").args(["rm", "-f", &name]).output();
    run(Command::new("docker").args([
        "run",
        "-d",
        "--rm",
        "--name",
        &name,
        "-p",
        "127.0.0.1::5000",
        "registry:2",
    ]));
    let _container = Container(name.clone());
    let port = run(Command::new("docker").args(["port", &name, "5000"]))
        .lines()
        .next()
        .and_then(|l| l.rsplit(':').next())
        .unwrap()
        .trim()
        .to_owned();
    let registry = format!("127.0.0.1:{port}");
    // Push the echo image; the registry may need a moment to listen.
    let src = format!("oci:{}:foreign-echo:dev", layout().display());
    let dest = format!("docker://{registry}/kronik/echo:test");
    let mut pushed = false;
    for _ in 0..50 {
        let out = Command::new("skopeo")
            .args(["copy", "--dest-tls-verify=false", &src, &dest])
            .output()
            .unwrap();
        if out.status.success() {
            pushed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(pushed, "skopeo could not push to {registry}");
    let raw = Command::new("skopeo")
        .args(["inspect", "--raw", "--tls-verify=false", &dest])
        .output()
        .unwrap()
        .stdout;
    let digest = format!("sha256:{}", sha256_hex(&raw));

    let d = Daemon::start_with(&dir, &["--test-insecure-registry", &registry]);
    let wasm = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(ROOT).join("tests/guests/counter.wasm")).unwrap());
    d.ok(
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "registry test"}),
    );
    // A tag alone is not a pin.
    let (s, v) = d.api(
        "POST",
        "/v1/foreign",
        json!({"name": "echo", "image": format!("{registry}/kronik/echo:test"), "port": 8080,
               "reason": "registry test"}),
    );
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("IMAGE_INVALID")),
        "{v}"
    );
    // By digest: fetched, verified, run.
    let image = format!("{registry}/kronik/echo@{digest}");
    let v = d.ok(
        "POST",
        "/v1/foreign",
        json!({"name": "echo", "image": image, "port": 8080, "reason": "registry test"}),
    );
    assert_eq!(v["foreign"]["status"]["state"], "running", "{v}");
    assert_eq!(v["foreign"]["image"], image);
    // A digest the registry does not have is refused before anything is written.
    let other = format!("{registry}/kronik/echo@sha256:{}", "0".repeat(64));
    let (s, v) = d.api(
        "POST",
        "/v1/foreign",
        json!({"name": "echo-x", "image": other, "port": 8080, "reason": "registry test"}),
    );
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (400, Some("IMAGE_INVALID")),
        "{v}"
    );
    // A local layout by ref name; the record is pinned by digest.
    let named = format!(
        "oci-layout:{}:foreign-echo:dev",
        layout().canonicalize().unwrap().display()
    );
    let v = d.ok(
        "POST",
        "/v1/foreign",
        json!({"name": "echo-named", "image": named, "port": 8080, "reason": "registry test"}),
    );
    assert_eq!(v["foreign"]["status"]["state"], "running", "{v}");
    assert!(
        v["foreign"]["image"].as_str().unwrap().contains("@sha256:"),
        "{v}"
    );
    for target in ["echo", "echo-named"] {
        d.ok(
            "POST",
            "/v1/grants",
            json!({"kind": "counter", "capability": format!("foreign:{target}"), "reason": "t"}),
        );
        assert_eq!(
            d.fetch(&format!("GET foreign://{target}/healthz")),
            "200 ok"
        );
    }
}

/// runsc resolves a container id by prefix and refuses an id that is a
/// prefix of another (`pay` of `payments`), or acts on the longer one when
/// the shorter is gone. Actors whose names are prefixes of each other each
/// keep their own sandbox through calls, restarts, removal and the
/// cleanup at daemon start, also of sandboxes named before the ids were
/// fixed-length (`kronik-foreign-<name>`).
#[test]
fn actor_names_that_prefix_each_other_keep_their_own_sandboxes() {
    if !should_run() {
        return;
    }
    let dir = tempfile::Builder::new()
        .prefix("kronik-ids-")
        .tempdir_in("/var/tmp")
        .unwrap()
        .keep();
    let _cleanup = Cleanup(dir.clone());
    let mut d = Daemon::start(&dir);
    let runsc_root = dir.join("run/runsc");
    let image = format!("oci-layout:{}", layout().canonicalize().unwrap().display());
    let wasm = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(ROOT).join("tests/guests/counter.wasm")).unwrap());
    d.ok(
        "POST",
        "/v1/deployments",
        json!({"wasm_base64": wasm, "reason": "ids test"}),
    );
    for name in ["pay", "payments"] {
        d.ok(
            "POST",
            "/v1/grants",
            json!({"kind": "counter", "capability": format!("foreign:{name}"), "reason": "ids test"}),
        );
    }
    let add = |d: &Daemon, name: &str| {
        let v = d.ok(
            "POST",
            "/v1/foreign",
            json!({"name": name, "image": image, "port": 8080, "reason": "ids test"}),
        );
        assert_eq!(v["foreign"]["status"]["state"], "running", "{v}");
    };
    let remove = |d: &Daemon, name: &str| {
        d.ok(
            "DELETE",
            &format!("/v1/foreign/{name}"),
            json!({"reason": "ids test"}),
        );
    };
    // `/data` counts calls in the actor's own data directory: each answer
    // names the sandbox that gave it.
    let count = |d: &Daemon, name: &str| -> u64 {
        let r = d.fetch(&format!("GET foreign://{name}/data"));
        assert!(r.starts_with("200 "), "{name}: {r}");
        serde_json::from_str::<Value>(&r[4..]).unwrap()["count"]
            .as_u64()
            .unwrap()
    };
    let restarts = |d: &Daemon, name: &str| d.foreign(name)["status"]["restarts"].as_u64();
    let ids = |names: &[&str]| {
        let mut v: Vec<String> = names
            .iter()
            .map(|n| kronik_foreign::Foreign::container_id(n))
            .collect();
        v.sort();
        v
    };
    let listed = || {
        let mut v = containers(RUNSC, &runsc_root, "-quiet");
        v.sort();
        v
    };

    // pay, then payments: both answer, each from its own sandbox.
    add(&d, "pay");
    add(&d, "payments");
    assert_eq!(listed(), ids(&["pay", "payments"]));
    assert_eq!((count(&d, "pay"), count(&d, "pay")), (1, 2));
    assert_eq!(count(&d, "payments"), 1);
    // pay exits and restarts after its backoff; payments is not touched.
    let r = d.fetch("POST foreign://pay/exit?code=3");
    assert!(r.starts_with("200"), "{r}");
    d.wait_until("pay restarted", |d| {
        let f = d.foreign("pay");
        f["status"]["restarts"].as_u64() >= Some(1) && f["status"]["state"] == "running"
    });
    assert_eq!(count(&d, "pay"), 3);
    assert_eq!(count(&d, "payments"), 2);
    assert_eq!(restarts(&d, "payments"), Some(0));
    // Removing pay leaves payments running.
    remove(&d, "pay");
    assert_eq!(listed(), ids(&["payments"]));
    assert_eq!(count(&d, "payments"), 3);
    assert_eq!(restarts(&d, "payments"), Some(0));

    // The reverse: payments first, then pay; payments exits, then goes.
    add(&d, "pay");
    assert_eq!(listed(), ids(&["pay", "payments"]));
    assert_eq!(count(&d, "pay"), 4);
    let r = d.fetch("POST foreign://payments/exit?code=3");
    assert!(r.starts_with("200"), "{r}");
    d.wait_until("payments restarted", |d| {
        let f = d.foreign("payments");
        f["status"]["restarts"].as_u64() >= Some(1) && f["status"]["state"] == "running"
    });
    assert_eq!(restarts(&d, "pay"), Some(0));
    remove(&d, "payments");
    assert_eq!(listed(), ids(&["pay"]));
    assert_eq!(count(&d, "pay"), 5);
    assert_eq!(restarts(&d, "pay"), Some(0));
    add(&d, "payments");

    // The daemon dies with both running. Next to their leftovers are
    // sandboxes named the old way, `kronik-foreign-<name>`, as an upgraded
    // node finds them: the next start removes all four and starts both
    // actors fresh.
    d.kill9();
    assert_eq!(listed(), ids(&["pay", "payments"]));
    for name in ["pay", "payments"] {
        let bundle = dir.join("old").join(name);
        std::fs::create_dir_all(&bundle).unwrap();
        // The daemon deletes config.json once a sandbox runs, so the old
        // sandbox gets a minimal spec on the same rootfs.
        let rootfs = dir
            .join("data/foreign/actors")
            .join(name)
            .join("bundle/rootfs");
        assert!(rootfs.is_dir(), "{}", rootfs.display());
        assert!(
            !rootfs.with_file_name("config.json").exists(),
            "config.json outlived the start"
        );
        let spec = json!({
            "ociVersion": "1.0.2",
            "process": {"args": ["/bin/foreign-echo"], "env": ["PATH=/bin"], "cwd": "/",
                        "user": {"uid": 0, "gid": 0}},
            "root": {"path": rootfs, "readonly": true},
            "hostname": name,
            "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"}],
            "linux": {"namespaces": [{"type": "pid"}, {"type": "ipc"}, {"type": "uts"},
                                     {"type": "mount"}]},
        });
        std::fs::write(bundle.join("config.json"), spec.to_string()).unwrap();
        // Not piped: the detached sandbox would hold a pipe open.
        let err = bundle.join("run.err");
        let status = Command::new(RUNSC)
            .arg("--root")
            .arg(&runsc_root)
            .args(["--network=none", "run", "--detach", "--bundle"])
            .arg(&bundle)
            .arg(format!("kronik-foreign-{name}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&err).unwrap())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "{}",
            std::fs::read_to_string(&err).unwrap_or_default()
        );
    }
    let mut all = ids(&["pay", "payments"]);
    all.extend([
        "kronik-foreign-pay".to_owned(),
        "kronik-foreign-payments".to_owned(),
    ]);
    all.sort();
    assert_eq!(listed(), all);
    d = Daemon::start(&dir);
    assert_eq!(listed(), ids(&["pay", "payments"]), "{}", d.serve_log());
    // The data directories outlive removal: pay's sixth call, payments'
    // fourth.
    assert_eq!(count(&d, "pay"), 6);
    assert_eq!(count(&d, "payments"), 4);
    for name in ["pay", "payments"] {
        assert_eq!(d.foreign(name)["status"]["starts"], 1);
    }
}
