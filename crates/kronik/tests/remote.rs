//! Remote control (M10) against a real `kronik serve`: the CLI over TLS with
//! `$KRONIK_URL` and `$KRONIK_TOKEN` (or `--url` and `--token`), plain HTTP
//! refused except to this machine; a proposal whose replay outlives the CLI
//! that started it, followed with `kronik proposal status` and `wait`.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use common::free_port;
use serde_json::Value;

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests");

fn guest(name: &str) -> String {
    format!("{GUESTS}/{name}.wasm")
}

/// A `kronik` command with no setting from the developer's shell.
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
        "KRONIK_URL",
        "KRONIK_MASTER_KEY_FILE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        c.env_remove(var);
    }
    c.stdin(Stdio::null());
    c
}

struct Daemon {
    child: Child,
    dir: tempfile::TempDir,
    /// `host:port` of the TCP API.
    api: String,
}

impl Daemon {
    /// `kronik serve` with the API on TCP; with TLS from a self-signed
    /// certificate for `localhost` and 127.0.0.1 when `tls`.
    fn start(tls: bool, extra: &[&str]) -> Daemon {
        Daemon::start_with(tls.then_some(&["localhost", "127.0.0.1"][..]), extra)
    }

    /// [`Daemon::start`] with TLS from a self-signed certificate for
    /// `cert_names`, when given.
    fn start_with(cert_names: Option<&[&str]>, extra: &[&str]) -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let mut config = format!(
            "[server]\nhttp_listen = \"127.0.0.1:{}\"\nadmin_listen = \"127.0.0.1:{}\"\n\
             api_listen = \"127.0.0.1:{port}\"\n",
            free_port(),
            free_port(),
        );
        if let Some(names) = cert_names {
            let key = rcgen::KeyPair::generate().unwrap();
            let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
            let cert = rcgen::CertificateParams::new(names)
                .unwrap()
                .self_signed(&key)
                .unwrap();
            std::fs::write(dir.path().join("cert.pem"), cert.pem()).unwrap();
            std::fs::write(dir.path().join("key.pem"), key.serialize_pem()).unwrap();
            config.push_str(&format!(
                "\n[tls]\nmode = \"files\"\ncert_file = {:?}\nkey_file = {:?}\n",
                dir.path().join("cert.pem"),
                dir.path().join("key.pem"),
            ));
        }
        std::fs::write(dir.path().join("kronik.toml"), config).unwrap();
        let log = std::fs::File::create(dir.path().join("serve.log")).unwrap();
        let child = command()
            .args(["serve", "--config"])
            .arg(dir.path().join("kronik.toml"))
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            .arg("--api-socket")
            .arg(dir.path().join("api.sock"))
            .args(extra)
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon {
            child,
            dir,
            api: format!("127.0.0.1:{port}"),
        };
        let up = (0..600).any(|_| {
            let ok = d.local(&["--json", "actors", "list"]).status.success();
            if !ok {
                std::thread::sleep(Duration::from_millis(100));
            }
            ok
        });
        assert!(up, "kronik serve did not start:\n{}", d.log());
        d
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path("serve.log")).unwrap_or_default()
    }

    /// `kronik` on the daemon's socket.
    fn local(&self, args: &[&str]) -> Output {
        command()
            .arg("--socket")
            .arg(self.path("api.sock"))
            .args(args)
            .output()
            .unwrap()
    }

    fn local_json(&self, args: &[&str]) -> Value {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        let out = self.local(&all);
        assert!(out.status.success(), "{args:?}: {out:?}");
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// A token with every scope, made on the socket.
    fn token(&self) -> String {
        self.local_json(&[
            "token",
            "create",
            "--name",
            "ci",
            "--scopes",
            "admin",
            "--reason",
            "remote test",
        ])["secret"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `kronik` with only environment variables (no --socket).
fn remote(env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut c = command();
    c.args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn error_code(out: &Output) -> String {
    let v: Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("no error JSON: {out:?}"));
    v["error"]["code"].as_str().unwrap_or_default().to_owned()
}

/// Criterion 1: the CLI against a remote API with `$KRONIK_URL` and
/// `$KRONIK_TOKEN`, over TLS; plain HTTP only to this machine.
#[test]
fn the_cli_drives_a_remote_api_over_tls() {
    let d = Daemon::start(true, &[]);
    let token = d.token();
    let port = d.api.rsplit(':').next().unwrap().to_owned();
    let url = format!("https://localhost:{port}");
    let ca = d.path("cert.pem");
    let ca = ca.to_str().unwrap();
    let env = [
        ("KRONIK_URL", url.as_str()),
        ("KRONIK_TOKEN", token.as_str()),
        ("SSL_CERT_FILE", ca),
    ];

    // A mutation and reads, with nothing but the environment.
    let out = remote(
        &env,
        &["--json", "deploy", &guest("counter"), "--reason", "remote"],
    );
    assert!(out.status.success(), "{out:?}");
    let out = remote(
        &env,
        &["send", "counter/a", "increment", "--reason", "remote"],
    );
    assert!(out.status.success(), "{out:?}");
    let v: Value =
        serde_json::from_slice(&remote(&env, &["--json", "actors", "list"]).stdout).unwrap();
    assert_eq!(v["actors"][0]["key"], "a", "{v}");
    // The same with --url and --token, also to the IP address.
    let ip_url = format!("https://127.0.0.1:{port}");
    let out = remote(
        &[("SSL_CERT_FILE", ca)],
        &[
            "--json", "--url", &ip_url, "--token", &token, "actors", "list",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    // The token is what the daemon records with the mutation.
    let v: Value =
        serde_json::from_slice(&remote(&env, &["--json", "deployments", "list"]).stdout).unwrap();
    assert_eq!(v["deployments"][0]["token_id"], "token:ci", "{v}");

    // Without a token the remote API answers 401; without trusting the CA,
    // TLS fails before anything is sent.
    let out = remote(
        &[("KRONIK_URL", &url), ("SSL_CERT_FILE", ca)],
        &["--json", "actors", "list"],
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(error_code(&out), "UNAUTHENTICATED", "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("needs a bearer token"),
        "{out:?}"
    );
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(d.path("other.pem"), other.cert.pem()).unwrap();
    let out = remote(
        &[
            ("KRONIK_URL", &url),
            ("KRONIK_TOKEN", &token),
            ("SSL_CERT_FILE", d.path("other.pem").to_str().unwrap()),
        ],
        &["--json", "actors", "list"],
    );
    assert_eq!(error_code(&out), "UNAVAILABLE", "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("TLS"),
        "{out:?}"
    );

    // Plain HTTP to another machine is refused by the CLI itself; the TEST-NET
    // address is never dialled.
    for url in ["http://192.0.2.10:7443", "http://kronik.example.com"] {
        let out = remote(
            &[("KRONIK_URL", url), ("KRONIK_TOKEN", &token)],
            &["--json", "actors", "list"],
        );
        assert_eq!(error_code(&out), "BAD_REQUEST", "{url}: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("in the clear"),
            "{out:?}"
        );
    }
}

/// L7 and N4: a certificate for another name fails with UNAVAILABLE "TLS to
/// … failed", and `proposal wait` does not retry it until its timeout.
#[test]
fn a_certificate_for_another_name_fails_at_once() {
    let d = Daemon::start_with(Some(&["kronik.example"]), &[]);
    let token = d.token();
    let url = format!("https://{}", d.api);
    let ca = d.path("cert.pem");
    let env = [
        ("KRONIK_URL", url.as_str()),
        ("KRONIK_TOKEN", token.as_str()),
        ("SSL_CERT_FILE", ca.to_str().unwrap()),
    ];
    let started = std::time::Instant::now();
    let out = remote(
        &env,
        &[
            "--json",
            "proposal",
            "wait",
            "p-000000000001",
            "--timeout",
            "30s",
        ],
    );
    let took = started.elapsed();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(error_code(&out), "UNAVAILABLE", "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("TLS to") && stdout.contains("not valid for name"),
        "{out:?}"
    );
    assert!(
        took < Duration::from_secs(10),
        "retried for {took:?}: {out:?}"
    );
}

/// Criterion 1, the exception: plain HTTP to a loopback API, by address
/// and by `localhost`, which the CLI dials as [::1] then 127.0.0.1 without
/// looking it up (M2).
#[test]
fn plain_http_is_accepted_to_this_machine() {
    let d = Daemon::start(false, &[]);
    let token = d.token();
    let port = d.api.rsplit(':').next().unwrap().to_owned();
    for url in [
        format!("http://{}", d.api),
        format!("http://localhost:{port}"),
    ] {
        let out = remote(
            &[("KRONIK_URL", &url), ("KRONIK_TOKEN", &token)],
            &["--json", "actors", "list"],
        );
        assert!(out.status.success(), "{url}: {out:?}");
    }
    // A port is required: 80 is usually the gateway's.
    let out = remote(
        &[("KRONIK_URL", "http://localhost"), ("KRONIK_TOKEN", &token)],
        &["--json", "actors", "list"],
    );
    assert_eq!(error_code(&out), "BAD_REQUEST", "{out:?}");
}

fn proposals(d: &Daemon) -> Vec<Value> {
    d.local_json(&["proposals", "list"])["proposals"]
        .as_array()
        .unwrap()
        .clone()
}

fn wait_for(what: &str, done: impl Fn() -> bool) {
    for _ in 0..1200 {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("never: {what}");
}

/// Criterion 2: a proposal's replay survives the CLI that started it, and
/// `kronik proposal wait` shows its progress. The replay is held at known
/// points (the hidden `--test-replay-permits`), so nothing here depends on
/// how long the replay takes.
#[test]
fn a_proposal_outlives_its_client_and_wait_shows_progress() {
    let dir = tempfile::tempdir().unwrap();
    let permits = dir.path().join("permits");
    std::fs::write(&permits, "0").unwrap();
    let d = Daemon::start(false, &["--test-replay-permits", permits.to_str().unwrap()]);
    d.local_json(&["deploy", &guest("counter"), "--reason", "jobs"]);
    for i in 0..20 {
        let key = format!("counter/k{}", i % 4);
        let out = d.local(&["send", &key, "increment", "--reason", "traffic"]);
        assert!(out.status.success(), "{out:?}");
    }
    let socket = d.path("api.sock");

    // A plain (waiting) propose, killed while its replay is held.
    let mut client = command()
        .arg("--socket")
        .arg(&socket)
        .args([
            "propose",
            &guest("counter-step2"),
            "--mode",
            "isolated",
            "--threads",
            "1",
            "--reason",
            "outlive the client",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for("the running proposal", || {
        proposals(&d)
            .iter()
            .any(|p| p["status"] == "running" && p["progress"]["isolated_total"] == 20)
    });
    client.kill().unwrap();
    client.wait().unwrap();
    let id = proposals(&d)[0]["id"].as_str().unwrap().to_owned();

    // M10 criterion 2 at full length: KRONIK_TEST_HOLD_SECS (default 0)
    // keeps the replay held that long with no client attached but one
    // `wait` started before the hold, so no job reaping, token or
    // connection timeout and not `wait`'s own clock may end it (the
    // testbench runs it at 31 minutes).
    let hold: u64 = std::env::var("KRONIK_TEST_HOLD_SECS").map_or(0, |s| {
        s.parse()
            .unwrap_or_else(|e| panic!("KRONIK_TEST_HOLD_SECS={s:?}: {e}"))
    });
    let long_wait = (hold > 0).then(|| {
        command()
            .arg("--socket")
            .arg(&socket)
            .args(["proposal", "wait", &id, "--timeout"])
            .arg(format!("{}s", hold + 600))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    });
    std::thread::sleep(Duration::from_secs(hold));
    assert_eq!(
        d.local_json(&["proposal", "status", &id])["status"],
        "running",
        "the held proposal ended during the hold\n{}",
        d.log()
    );

    // Held: status shows the progress, and what needs the finished
    // proposal says it is still running.
    std::fs::write(&permits, "5").unwrap();
    wait_for("5 root inputs replayed", || {
        d.local_json(&["proposal", "status", &id])["progress"]["isolated_done"] == 5
    });
    let out = d.local(&["proposal", "status", &id]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("isolated 5 of 20 root inputs"),
        "{out:?}"
    );
    let out = d.local(&["--json", "promote", &id, "--reason", "too early"]);
    assert_eq!(error_code(&out), "PROPOSAL_RUNNING", "{out:?}");
    let out = d.local(&["--json", "proposal", "wait", &id, "--timeout", "1s"]);
    assert_eq!(error_code(&out), "PROPOSAL_RUNNING", "{out:?}");

    // `wait` prints the progress it sees, then the finished proposal.
    let mut wait = command()
        .arg("--socket")
        .arg(&socket)
        .args(["proposal", "wait", &id, "--timeout", "10m"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let stderr = wait.stderr.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let first = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert_eq!(first, format!("{id}: isolated 5 of 20 root inputs"));
    std::fs::write(&permits, "12").unwrap();
    let mut seen = vec![first];
    while !seen.last().unwrap().contains("12 of 20") {
        seen.push(rx.recv_timeout(Duration::from_secs(60)).unwrap());
    }
    std::fs::write(&permits, "1000").unwrap();
    let out = wait.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?} {seen:?}\n{}", d.log());
    let shown = String::from_utf8_lossy(&out.stdout);
    assert!(
        shown.starts_with(&format!("Proposal {id}   counter   b3:"))
            && shown.contains("(evaluated)"),
        "{shown}"
    );
    if let Some(long_wait) = long_wait {
        let out = long_wait.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "the wait started before the hold: {out:?}"
        );
    }
    let v = d.local_json(&["proposal", "wait", &id]);
    assert_eq!(v["status"], "evaluated", "{v}");
    assert_eq!(v["summary"]["replayed"], 20, "{v}");
    assert!(v.get("progress").is_none(), "{v}");

    // --async returns at once with the running proposal.
    let v = d.local_json(&[
        "propose",
        &guest("counter-step2"),
        "--async",
        "--reason",
        "async",
    ]);
    assert_eq!(v["proposal"]["status"], "running", "{v}");
    let id2 = v["proposal"]["id"].as_str().unwrap().to_owned();
    let v = d.local_json(&["proposal", "wait", &id2, "--timeout", "10m"]);
    assert_eq!(v["status"], "evaluated", "{v}");
    let out = d.local(&[
        "propose",
        &guest("counter-step2"),
        "--async",
        "--dry-run",
        "--reason",
        "x",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "--async with --dry-run: {out:?}"
    );
}

/// A fake API on 127.0.0.1: the n-th connection (from 0) gets
/// `answer(n, request line)`, a status and a JSON body, after its request
/// is read; `None` closes it unanswered.
fn fake_api(answer: impl Fn(usize, &str) -> Option<(u16, String)> + Send + 'static) -> String {
    fake_api_raw(move |n, request| {
        answer(n, request).map(|(status, body)| {
            format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        })
    })
}

/// [`fake_api`] whose `answer` is the whole response as sent.
fn fake_api_raw(answer: impl Fn(usize, &str) -> Option<String> + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    std::thread::spawn(move || {
        for (n, stream) in listener.incoming().enumerate() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            let _ = reader.read_line(&mut request);
            let mut length = 0;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                    break;
                }
                if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; length];
            let _ = reader.read_exact(&mut body);
            if let Some(response) = answer(n, request.trim_end()) {
                let _ = stream.write_all(response.as_bytes());
            }
        }
    });
    url
}

/// A proposal as `GET /v1/proposals/{id}` answers it.
fn proposal_json(status: &str) -> String {
    let mut p = serde_json::json!({
        "id": "p-000000000001", "fork": "p-000000000001", "status": status,
        "fork_lsn": 1, "verified_through_lsn": 1, "diff_hash": "",
        "policy": null, "summary": null, "kinds": [],
    });
    match status {
        "running" => {
            p["progress"] = serde_json::json!({
                "isolated_done": 1, "isolated_total": 2,
                "continuous_done": 0, "continuous_total": 0,
            });
        }
        "failed" => {
            p["error"] = serde_json::json!({"error": {"code": "INTERNAL", "message": "boom"}});
        }
        _ => {}
    }
    p.to_string()
}

/// M3: a daemon that accepts and never answers ends `proposal wait` at its
/// timeout instead of hanging.
#[test]
fn wait_gives_up_on_a_silent_daemon_at_its_timeout() {
    // Never accepted: the kernel completes the connection, nothing answers.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", silent.local_addr().unwrap().port());
    let started = std::time::Instant::now();
    let out = remote(
        &[("KRONIK_URL", &url)],
        &[
            "--json",
            "proposal",
            "wait",
            "p-000000000001",
            "--timeout",
            "2s",
        ],
    );
    let took = started.elapsed();
    assert!(took < Duration::from_secs(10), "took {took:?}: {out:?}");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(error_code(&out), "UNAVAILABLE", "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("did not answer within"),
        "{out:?}"
    );
}

/// M3 and L6: `proposal wait` retries connections that break and a proxy's
/// 502, and with --json still prints its progress on stderr.
#[test]
fn wait_retries_broken_connections_and_reports_progress() {
    let url = fake_api(|n, _| match n {
        0 | 1 => None,
        2 => Some((502, "<html>bad gateway</html>".into())),
        3 => Some((200, proposal_json("running"))),
        _ => Some((200, proposal_json("evaluated"))),
    });
    let out = remote(
        &[("KRONIK_URL", &url)],
        &[
            "--json",
            "proposal",
            "wait",
            "p-000000000001",
            "--timeout",
            "30s",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["status"], "evaluated", "{v}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("retrying"), "{stderr}");
    assert!(
        stderr.contains("p-000000000001: isolated 1 of 2 root inputs"),
        "{stderr}"
    );
}

/// N4: a response cut short by a clean close (fewer bytes than its
/// Content-Length) is retried like a broken connection, not reported as a
/// malformed reply.
#[test]
fn wait_retries_a_response_cut_short() {
    let url = fake_api_raw(|n, _| {
        Some(match n {
            0 => "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{".to_owned(),
            _ => {
                let body = proposal_json("evaluated");
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }
        })
    });
    let out = remote(
        &[("KRONIK_URL", &url)],
        &[
            "--json",
            "proposal",
            "wait",
            "p-000000000001",
            "--timeout",
            "30s",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("retrying"), "{stderr}");
}

/// L13: with --url, an error whose hint names a command reminds that the
/// command needs --url too, as the `Next` lines do.
#[test]
fn an_error_hint_reminds_of_the_url() {
    let url = fake_api(|_, _| Some((200, proposal_json("running"))));
    let out = remote(
        &[],
        &[
            "--url",
            &url,
            "proposal",
            "wait",
            "p-000000000001",
            "--timeout",
            "1s",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("hint:  Wait longer: kronik proposal wait"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("with --url {url}, or export KRONIK_URL={url}")),
        "{stderr}"
    );
}

/// L2: with --json, a proxy's HTML error page becomes an UNAVAILABLE error
/// JSON on stdout.
#[test]
fn a_proxy_error_page_is_reported_as_error_json() {
    let url = fake_api(|_, _| Some((502, "<html>bad gateway</html>".into())));
    let out = remote(&[("KRONIK_URL", &url)], &["--json", "actors", "list"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(error_code(&out), "UNAVAILABLE", "{out:?}");
}

/// L8: a failed proposal exits 1 with and without --json, and `proposals
/// show` works for a running and a failed proposal.
#[test]
fn status_and_show_agree_on_failed_and_running_proposals() {
    let failed = fake_api(|_, _| Some((200, proposal_json("failed"))));
    let id = "p-000000000001";
    for args in [
        vec!["proposal", "status", id],
        vec!["--json", "proposal", "status", id],
        vec!["proposals", "show", id],
        vec!["--json", "proposals", "show", id],
    ] {
        let out = remote(&[("KRONIK_URL", &failed)], &args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {out:?}");
    }
    let out = remote(&[("KRONIK_URL", &failed)], &["proposals", "show", id]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("boom"),
        "{out:?}"
    );
    let out = remote(
        &[("KRONIK_URL", &failed)],
        &["--json", "proposal", "status", id],
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["status"], "failed", "{v}");

    let running = fake_api(|_, _| Some((200, proposal_json("running"))));
    let out = remote(&[("KRONIK_URL", &running)], &["proposals", "show", id]);
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("isolated 1 of 2 root inputs"),
        "{out:?}"
    );
}

/// L9: `propose` starts a job and follows it; when following it fails, the
/// error names the proposal and how to follow it.
#[test]
fn propose_names_its_proposal_when_following_it_fails() {
    let url = fake_api(|n, request| match n {
        0 => {
            assert!(request.starts_with("POST /v1/proposals "), "{request}");
            Some((
                202,
                format!(
                    r#"{{"dry_run": false, "proposal": {}}}"#,
                    proposal_json("running")
                ),
            ))
        }
        _ => None,
    });
    let out = remote(
        &[("KRONIK_URL", &url)],
        &[
            "--json",
            "propose",
            &guest("counter-step2"),
            "--reason",
            "follow",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "UNAVAILABLE", "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("p-000000000001"),
        "{v}"
    );
    assert!(
        v["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("kronik proposal wait p-000000000001"),
        "{v}"
    );
}

/// H2 and L13: commands that do not talk to the API refuse --url and
/// --token instead of ignoring them.
#[test]
fn commands_without_the_api_refuse_url_and_token() {
    for args in [
        &["doctor", "--url", "https://kronik.example.com:7443"][..],
        &["init", "x", "--token", "t"],
        &["serve", "--token", "t"],
    ] {
        let out = remote(&[], args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--url") && stderr.contains("--token"),
            "{stderr}"
        );
    }
}
