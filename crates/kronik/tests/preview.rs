//! M11 previews with a real `kronik serve` (docs/design/m11-preview.md): a
//! preview fork takes new requests through the gateway, by host with a
//! preview domain and by path prefix without one, against the proposal's
//! code and HEAD's state, without live effects but the `[fork]
//! live_allowlist`; its requests show as preview inputs in its diff; it is
//! deleted after its time to live, also when that ran out while the daemon
//! was down.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};

const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests");

struct Daemon {
    dir: PathBuf,
    child: Option<Child>,
    http: String,
}

impl Daemon {
    fn start(dir: &Path, config: &str) -> Daemon {
        let file = dir.join("kronik.toml");
        std::fs::write(
            &file,
            format!("[server]\ndata_dir = {:?}\n\n{config}", dir.join("data")),
        )
        .unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_kronik"))
            .arg("serve")
            .arg("--config")
            .arg(&file)
            .args([
                "--http-listen",
                "127.0.0.1:0",
                "--admin-listen",
                "127.0.0.1:0",
                "--test-preview-sweep-ms",
                "100",
                "--api-socket",
            ])
            .arg(dir.join("api.sock"))
            .env("KRONIK_LOG", "info")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut d = Daemon {
            dir: dir.to_path_buf(),
            child: Some(child),
            http: String::new(),
        };
        for _ in 0..800 {
            if let Some((200, v)) = d.try_api("GET", "/v1/health", Value::Null) {
                d.http = v["http_listen"].as_str().unwrap().to_owned();
                return d;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("daemon did not start: {}", d.serve_log());
    }

    fn serve_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
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

    fn api(&self, method: &str, path: &str, body: Value) -> Value {
        let (s, v) = self
            .try_api(method, path, body)
            .unwrap_or_else(|| panic!("API {method} {path} failed: {}", self.serve_log()));
        assert_eq!(s, 200, "{method} {path}: {v}");
        v
    }

    /// A gateway request: (status, body).
    fn request(&self, method: &str, path: &str, host: &str, body: &str) -> (u16, String) {
        let mut s = TcpStream::connect(&self.http).unwrap();
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nhost: {host}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, body.to_owned())
    }

    /// The CLI with `--json`, parsed.
    fn cli(&self, args: &[&str]) -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_kronik"))
            .arg("--socket")
            .arg(self.dir.join("api.sock"))
            .args(args)
            .arg("--json")
            .env_remove("KRONIK_TOKEN")
            .env_remove("KRONIK_API_SOCKET")
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn deploy(&self, guest: &str) {
        self.api(
            "POST",
            "/v1/deployments",
            json!({"wasm_base64": wasm(guest), "reason": "preview test"}),
        );
    }

    fn propose(&self, guest: &str) -> String {
        let v = self.api(
            "POST",
            "/v1/proposals",
            json!({"wasm_base64": [wasm(guest)], "reason": "preview test"}),
        );
        v["proposal"]["id"].as_str().unwrap().to_owned()
    }

    fn preview(&self, proposal: &str, ttl_ms: u64) -> Value {
        self.api(
            "POST",
            "/v1/previews",
            json!({"proposal": proposal, "ttl_ms": ttl_ms, "reason": "preview test"}),
        )["preview"]
            .clone()
    }

    fn preview_ids(&self) -> Vec<String> {
        self.api("GET", "/v1/previews", Value::Null)["previews"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap().to_owned())
            .collect()
    }

    fn fork_dir(&self, id: &str) -> PathBuf {
        self.dir.join("data").join("branches").join(id)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wasm(guest: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(Path::new(GUESTS).join(format!("{guest}.wasm"))).unwrap())
}

/// A plain HTTP server on `ip` that answers `pong` and counts the
/// requests it got. Returns its address and the count.
fn counting_target(ip: &str) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((ip, 0)).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            counted.fetch_add(1, Ordering::SeqCst);
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong",
            );
        }
    });
    (addr, hits)
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    for _ in 0..200 {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting until {what}");
}

#[test]
fn a_preview_runs_new_requests_on_the_new_code_without_live_effects() {
    let tmp = tempfile::tempdir().unwrap();
    // 127.0.0.2 is loopback too: the allowlisted host, next to a denied one.
    let (denied, denied_hits) = counting_target("127.0.0.1");
    let (allowed, allowed_hits) = counting_target("127.0.0.2");
    let d = Daemon::start(
        tmp.path(),
        "[gateway]\npreview_domain = \"preview.test\"\n\n[fork]\nlive_allowlist = [\"127.0.0.2\"]\n",
    );
    d.deploy("counter");
    for capability in ["http:127.0.0.1", "http:127.0.0.2"] {
        d.api(
            "POST",
            "/v1/grants",
            json!({"kind": "counter", "capability": capability, "reason": "preview test"}),
        );
    }
    // Main's state: counter/x is 1.
    assert_eq!(
        d.request("POST", "/counter/x/increment", "x", ""),
        (200, "1".into())
    );
    let proposal = d.propose("counter-step2");

    let v = d.cli(&["preview", "create", &proposal, "--reason", "try step2"]);
    assert_eq!(v["dry_run"], false, "{v}");
    let id = v["preview"]["id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("v-") && id.len() == 14, "{v}");
    assert_eq!(v["preview"]["proposal"], proposal.as_str());
    let port = d.http.rsplit_once(':').unwrap().1;
    assert_eq!(
        v["preview"]["url"],
        format!("http://{id}.preview.test:{port}/")
    );
    assert!(
        d.cli(&["preview", "list"])["previews"]
            .to_string()
            .contains(&id)
    );

    // The new code (+2) on HEAD's state (1), by host in any case, with a
    // port or a trailing dot.
    let host = format!("{id}.preview.test:8080");
    assert_eq!(
        d.request("POST", "/counter/x/increment", &host, ""),
        (200, "3".into())
    );
    assert_eq!(
        d.request(
            "POST",
            "/counter/x/increment",
            &format!("{}.PREVIEW.test.", id.to_uppercase()),
            ""
        ),
        (200, "5".into())
    );
    // With a preview domain the prefix is main's path, not the preview's
    // (P-F1: proposal code never answers on main's origin).
    let prefix = format!("/__preview/{id}");
    let (status, body) = d.request("POST", &format!("{prefix}/counter/x/increment"), "x", "");
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("ROUTE_NOT_FOUND"), "{body}");
    // Main did not move.
    let main = d.api("GET", "/v1/actors/counter/x", Value::Null);
    assert!(main["state"].to_string().contains("\"1\""), "{main}");

    // No live effect: an unrecorded fetch is denied and never reaches the
    // server; only an allowlisted GET goes out (I7).
    let (status, body) = d.request(
        "POST",
        "/counter/x/fetch-ok",
        &host,
        &format!("GET http://{denied}/ping"),
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        body.starts_with("error") && body.contains("no recording"),
        "{body}"
    );
    assert_eq!(denied_hits.load(Ordering::SeqCst), 0);
    let (status, body) = d.request(
        "POST",
        "/counter/x/fetch-ok",
        &host,
        &format!("GET http://{allowed}/ping"),
    );
    assert_eq!((status, body.as_str()), (200, "200 pong"));
    assert_eq!(allowed_hits.load(Ordering::SeqCst), 1);
    let (status, body) = d.request(
        "POST",
        "/counter/x/fetch-ok",
        &host,
        &format!("POST http://{allowed}/ping\n\nbody"),
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("no recording"), "{body}");
    assert_eq!(allowed_hits.load(Ordering::SeqCst), 1);
    assert_eq!(denied_hits.load(Ordering::SeqCst), 0);

    // The diff lists the requests as preview inputs, not as divergence.
    let diff = d.api("GET", &format!("/v1/forks/{id}/diff"), Value::Null);
    let s = &diff["summary"];
    assert_eq!(s["preview_inputs"], 5, "{diff}");
    assert_eq!(s["divergent_turns"], 0, "{diff}");
    assert_eq!(s["turns_fork"], 0, "{diff}");
    let samples = diff["samples"]["preview"].as_array().unwrap();
    assert_eq!(samples.len(), 5, "{diff}");
    for p in samples {
        assert_eq!(p["method"], "POST", "{p}");
        assert_eq!(p["route"], "/counter/{key}/{op}", "{p}");
        assert_eq!(p["outcome"], "committed", "{p}");
        assert!(
            p["turn"].as_str().unwrap().starts_with(&format!("{id}:")),
            "{p}"
        );
    }
    // Each is a turn of the fork's log, sealed like main's and readable.
    let first = samples[0]["turn"].as_str().unwrap();
    let turn = d.api("GET", &format!("/v1/turns/{first}"), Value::Null);
    assert!(turn.to_string().contains("increment"), "{turn}");
    let md = Command::new(env!("CARGO_BIN_EXE_kronik"))
        .arg("--socket")
        .arg(d.dir.join("api.sock"))
        .args(["diff", "show", &id, "--md"])
        .env_remove("KRONIK_TOKEN")
        .output()
        .unwrap();
    let md = String::from_utf8(md.stdout).unwrap();
    assert!(md.contains("| Preview inputs | 5 "), "{md}");
    assert!(md.contains("## Preview inputs"), "{md}");

    // An unknown preview is a 404 with its code, whatever the label.
    for unknown in ["v-000000000000.preview.test", "x.y.preview.test"] {
        let (status, body) = d.request("POST", "/counter/x/increment", unknown, "");
        assert_eq!(status, 404, "{body}");
        assert!(body.contains("PREVIEW_NOT_FOUND"), "{body}");
    }

    // P-F11: an erasure through the API makes the preview start again from
    // its fork point (1, +2) instead of its own state (5).
    d.api(
        "POST",
        "/v1/privacy/erase",
        json!({"subject": "user:gone", "reason": "preview test"}),
    );
    assert_eq!(
        d.request("POST", "/counter/x/increment", &host, ""),
        (200, "3".into())
    );

    // Deleting it stops its routes and removes its directory.
    let v = d.cli(&["preview", "delete", &id, "--reason", "done"]);
    assert_eq!(v["deleted"], id.as_str());
    assert!(!d.fork_dir(&id).exists());
    let (status, _) = d.request("POST", "/counter/x/increment", &host, "");
    assert_eq!(status, 404);
}

#[test]
fn previews_are_deleted_after_their_ttl_also_across_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let mut d = Daemon::start(tmp.path(), "");
    d.deploy("counter");
    assert_eq!(
        d.request("POST", "/counter/y/increment", "x", ""),
        (200, "1".into())
    );
    let proposal = d.propose("counter-step2");

    // Expires while the daemon runs.
    let id = d.preview(&proposal, 2_000)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(d.fork_dir(&id).exists());
    let path = format!("/__preview/{id}/counter/x/increment");
    assert_eq!(d.request("POST", &path, "x", ""), (200, "2".into()));
    wait_until("the preview expired", || {
        d.request("POST", &path, "x", "").0 == 404
    });
    assert!(!d.preview_ids().contains(&id));
    wait_until("its directory is gone", || !d.fork_dir(&id).exists());
    assert!(
        !d.api("GET", "/v1/forks", Value::Null)
            .to_string()
            .contains(&id)
    );

    // Expires while the daemon is down: gone after the restart.
    let id = d.preview(&proposal, 1_500)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let kept = d.preview(&proposal, 3_600_000)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    d.stop();
    std::thread::sleep(Duration::from_millis(2_000));
    let d = Daemon::start(tmp.path(), "");
    wait_until("its directory is gone", || !d.fork_dir(&id).exists());
    let (status, body) = d.request(
        "POST",
        &format!("/__preview/{id}/counter/x/increment"),
        "x",
        "",
    );
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("PREVIEW_NOT_FOUND"), "{body}");
    assert_eq!(d.preview_ids(), std::slice::from_ref(&kept));
    // The one still alive answers after the restart, its state rebuilt
    // from its fork point.
    assert_eq!(
        d.request(
            "POST",
            &format!("/__preview/{kept}/counter/x/increment"),
            "x",
            ""
        ),
        (200, "2".into())
    );
}
