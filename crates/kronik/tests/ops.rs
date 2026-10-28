//! Operations: `kronik serve` reads kronik.toml and its flags override it;
//! `serve --init --dry-run` prints the plan and changes nothing.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use common::free_port;

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

/// The environment variables `kronik serve` and the CLI read, cleared so
/// that the developer's shell can't override the tests' files and flags.
const SETTINGS_ENV: [&str; 7] = [
    "KRONIK_CONFIG",
    "KRONIK_DATA_DIR",
    "KRONIK_HTTP_LISTEN",
    "KRONIK_ADMIN_LISTEN",
    "KRONIK_API_SOCKET",
    "KRONIK_MASTER_KEY_FILE",
    "KRONIK_MASTER_KEY",
];

fn command() -> Command {
    let mut command = Command::new(KRONIK);
    for var in SETTINGS_ENV {
        command.env_remove(var);
    }
    // The tests' temporary file system may have less than the reserve.
    command.env("KRONIK_DISK_RESERVE", "0B");
    command.stdin(Stdio::null());
    command
}

fn kronik(args: &[&str]) -> Output {
    command().args(args).output().unwrap()
}

/// `kronik serve` with `args`, killed when dropped.
struct Serve(Child);

impl Serve {
    fn start(args: &[&str]) -> Serve {
        Self::start_with_master_key(args, "")
    }

    /// `kronik serve` with `args` and the `KRONIK_MASTER_KEY` material,
    /// killed when dropped. An empty key leaves the variable unset.
    fn start_with_master_key<I, S>(args: I, key: &str) -> Serve
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut command = command();
        command.arg("serve").args(args).env("KRONIK_LOG", "warn");
        if !key.is_empty() {
            command.env("KRONIK_MASTER_KEY", key);
        }
        Serve(
            command
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits for the API on `socket` and returns the gateway's answer to `GET /`.
fn gateway_answer(socket: &Path, http: &str) -> String {
    let up = (0..600).any(|_| {
        let ok = kronik(&[
            "--socket",
            socket.to_str().unwrap(),
            "--json",
            "actors",
            "list",
        ])
        .status
        .success();
        if !ok {
            std::thread::sleep(Duration::from_millis(100));
        }
        ok
    });
    assert!(up, "the API did not come up on {}", socket.display());
    let mut stream = TcpStream::connect(http).unwrap();
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn serve_takes_its_settings_from_the_file_and_flags_override_them() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let (file_port, flag_port) = (free_port(), free_port());
    let config = dir.path().join("kronik.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\ndata_dir = {:?}\napi_socket = {:?}\nhttp_listen = \"127.0.0.1:{file_port}\"\n\n[gateway]\ntimeout = \"5s\"\n",
            dir.path().join("data"),
            socket,
        ),
    )
    .unwrap();

    let serve = Serve::start(&["--config", config.to_str().unwrap()]);
    let answer = gateway_answer(&socket, &format!("127.0.0.1:{file_port}"));
    assert!(answer.contains("ROUTE_NOT_FOUND"), "{answer}");
    assert!(dir.path().join("data").is_dir());
    drop(serve);

    let _serve = Serve::start(&[
        "--config",
        config.to_str().unwrap(),
        "--http-listen",
        &format!("127.0.0.1:{flag_port}"),
    ]);
    let answer = gateway_answer(&socket, &format!("127.0.0.1:{flag_port}"));
    assert!(answer.contains("ROUTE_NOT_FOUND"), "{answer}");
    assert!(TcpStream::connect(format!("127.0.0.1:{file_port}")).is_err());
}

#[test]
fn a_bad_configuration_stops_serve_with_the_file_and_line() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("kronik.toml");
    std::fs::write(&config, "[server]\n\nhttp_lisen = \"127.0.0.1:1\"\n").unwrap();
    let out = kronik(&["serve", "--config", config.to_str().unwrap()]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains(&format!(
            "{}:3: unknown field `http_lisen`",
            config.display()
        )),
        "{stderr}"
    );
    let out = kronik(&[
        "serve",
        "--config",
        dir.path().join("none.toml").to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("cannot read the configuration")
    );
}

#[test]
fn init_dry_run_prints_the_plan_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("etc/kronik.toml");
    let out = kronik(&[
        "serve",
        "--init",
        "--domain",
        "app.example.com",
        "--acme-email",
        "ops@example.com",
        "--dry-run",
        "--config",
        config.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("kronik serve --init would do this (dry run, nothing changed):"));
    for line in [
        format!("create  {} (mode 0644)", config.display()),
        "/etc/kronik/master.key (mode 0600, 32 random bytes)".into(),
        "group kronik (groupadd --system kronik)".into(),
        "/etc/systemd/system/kronik.service (mode 0644)".into(),
        "run     systemctl daemon-reload".into(),
        "run     systemctl enable --now kronik.service".into(),
    ] {
        assert!(stdout.contains(&line), "{line:?} missing from:\n{stdout}");
    }
    assert!(!config.exists());

    // --domain needs --acme-email, and both need --init.
    assert!(
        !kronik(&["serve", "--init", "--domain", "a.example", "--dry-run"])
            .status
            .success()
    );
    assert!(
        !kronik(&[
            "serve",
            "--domain",
            "a.example",
            "--acme-email",
            "x@a.example"
        ])
        .status
        .success()
    );
}

/// `GET /` over TLS to `addr`, trusting only `root`.
fn https_get(addr: &str, root: &rcgen::Certificate) -> String {
    use std::sync::Arc;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.der().clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let mut sock = TcpStream::connect(addr).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = Vec::new();
    // The server may close without close_notify after the response.
    let _ = tls.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn tls_from_files_serves_https_and_a_bad_file_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(dir.path().join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.path().join("key.pem"), key.serialize_pem()).unwrap();
    let socket = dir.path().join("api.sock");
    let port = free_port();
    let config = dir.path().join("kronik.toml");
    let write_config = |cert_file: &str| {
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\napi_socket = {:?}\nhttp_listen = \"127.0.0.1:{port}\"\n\n\
                 [tls]\nmode = \"files\"\ncert_file = {:?}\nkey_file = {:?}\n",
                dir.path().join("data"),
                socket,
                dir.path().join(cert_file),
                dir.path().join("key.pem"),
            ),
        )
        .unwrap();
    };

    write_config("cert.pem");
    let _serve = Serve::start(&["--config", config.to_str().unwrap()]);
    let up = (0..600).any(|_| {
        let ok = kronik(&[
            "--socket",
            socket.to_str().unwrap(),
            "--json",
            "actors",
            "list",
        ])
        .status
        .success();
        if !ok {
            std::thread::sleep(Duration::from_millis(100));
        }
        ok
    });
    assert!(up);
    let answer = https_get(&format!("127.0.0.1:{port}"), &cert);
    assert!(answer.contains("ROUTE_NOT_FOUND"), "{answer}");
    drop(_serve);

    write_config("missing.pem");
    let out = kronik(&["serve", "--config", config.to_str().unwrap()]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("gateway TLS:") && stderr.contains("missing.pem"),
        "{stderr}"
    );
}

/// `kronik --json doctor --config <file>`: the report and the exit code.
fn doctor(config: &Path) -> (serde_json::Value, bool) {
    let out = kronik(&["--json", "doctor", "--config", config.to_str().unwrap()]);
    let report = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {out:?}"));
    (report, out.status.success())
}

fn status<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name} check in {report}"))
}

#[test]
fn doctor_checks_the_host_and_the_configured_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let valid = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let mut expired = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    expired.not_before = rcgen::date_time_ymd(2019, 1, 1);
    expired.not_after = rcgen::date_time_ymd(2020, 1, 1);
    std::fs::write(dir.path().join("key.pem"), key.serialize_pem()).unwrap();
    let config = dir.path().join("kronik.toml");
    let write = |cert: &rcgen::CertificateParams, platform: &str| {
        std::fs::write(
            dir.path().join("cert.pem"),
            cert.self_signed(&key).unwrap().pem(),
        )
        .unwrap();
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\n\n[tls]\nmode = \"files\"\ncert_file = {:?}\nkey_file = {:?}\n\n[foreign]\nplatform = \"{platform}\"\n",
                dir.path().join("data"),
                dir.path().join("cert.pem"),
                dir.path().join("key.pem"),
            ),
        )
        .unwrap();
    };

    write(&valid, "auto");
    let (report, ok) = doctor(&config);
    let names: Vec<&str> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "config", "kernel", "runsc", "kvm", "cgroup", "root", "runc", "netns", "run_dir",
            "caps", "sandbox", "disk", "clock", "tls", "ship"
        ]
    );
    assert_eq!(status(&report, "config")["status"], "pass");
    assert_eq!(status(&report, "tls")["status"], "pass", "{report}");
    assert_ne!(status(&report, "kvm")["status"], "fail", "{report}");
    assert_ne!(status(&report, "runsc")["status"], "fail", "{report}");
    for c in report["checks"].as_array().unwrap() {
        assert!(
            ["pass", "warn", "fail"].contains(&c["status"].as_str().unwrap()),
            "{c}"
        );
        assert!(c["message"].is_string(), "{c}");
    }
    let failed = report["fail"].as_u64().unwrap();
    assert_eq!(ok, failed == 0, "{report}");

    // An expired certificate fails; KVM asked for but missing fails too.
    write(&expired, "kvm");
    let (report, ok) = doctor(&config);
    assert!(!ok);
    let tls = status(&report, "tls");
    assert_eq!(tls["status"], "fail", "{report}");
    assert!(
        tls["message"].as_str().unwrap().contains("expired"),
        "{report}"
    );
    let kvm = status(&report, "kvm");
    // Usable, as doctor judges it: CI runners have a /dev/kvm only the kvm
    // group may open.
    let usable = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    if usable {
        assert_eq!(kvm["status"], "pass", "{report}");
    } else {
        assert_eq!(kvm["status"], "fail", "{report}");
        assert_eq!(kvm["code"], "KVM_UNAVAILABLE", "{report}");
    }

    // A broken file is a failed check, and the rest still runs.
    std::fs::write(&config, "[tls]\nmode = \"ftp\"\n").unwrap();
    let (report, ok) = doctor(&config);
    assert!(!ok);
    assert_eq!(status(&report, "config")["status"], "fail");
    assert_eq!(report["checks"].as_array().unwrap().len(), 15);
}

/// `GET path` on plain HTTP: the status line's code and the body.
fn http_get(addr: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

#[test]
fn metrics_healthz_and_json_logs() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let (http, admin) = (
        format!("127.0.0.1:{}", free_port()),
        format!("127.0.0.1:{}", free_port()),
    );
    let log = std::fs::File::create(dir.path().join("serve.log")).unwrap();
    let mut child = command()
        .arg("serve")
        .args(["--data-dir", dir.path().join("data").to_str().unwrap()])
        .args(["--api-socket", socket.to_str().unwrap()])
        .args([
            "--http-listen",
            &http,
            "--admin-listen",
            &admin,
            "--log-format",
            "json",
        ])
        .env("KRONIK_LOG", "info")
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    let sock = socket.to_str().unwrap();
    let up = (0..600).any(|_| {
        let ok = kronik(&["--socket", sock, "--json", "actors", "list"])
            .status
            .success();
        if !ok {
            std::thread::sleep(Duration::from_millis(100));
        }
        ok
    });
    assert!(up);
    assert!(
        kronik(&["--socket", sock, "deploy", COUNTER, "--reason", "metrics"])
            .status
            .success()
    );
    assert!(
        kronik(&[
            "--socket",
            sock,
            "send",
            "counter/a",
            "increment",
            "--reason",
            "metrics"
        ])
        .status
        .success()
    );
    assert_eq!(http_get(&http, "/nowhere").0, 404);

    let (status, metrics) = http_get(&admin, "/metrics");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(status, 200);
    let value = |series: &str| -> f64 {
        metrics
            .lines()
            .find_map(|l| {
                l.strip_prefix(series)
                    .and_then(|rest| rest.strip_prefix(' '))
            })
            .unwrap_or_else(|| panic!("no {series} in:\n{metrics}"))
            .parse()
            .unwrap()
    };
    assert!(value("kronik_turns_total{kind=\"counter\",outcome=\"committed\"}") >= 1.0);
    assert!(value("kronik_turn_duration_seconds_count{kind=\"counter\"}") >= 1.0);
    assert!(value("kronik_log_records_appended_total") >= 2.0);
    assert!(value("kronik_log_fsync_duration_seconds_count") >= 1.0);
    assert!(value("kronik_applied_lsn") >= 2.0);
    assert!(value("kronik_gateway_requests_total{status=\"404\"}") >= 1.0);
    assert!(metrics.contains("kronik_build_info{engine=\""), "{metrics}");

    // Every log line is a JSON object with a level and a target.
    let log = std::fs::read_to_string(dir.path().join("serve.log")).unwrap();
    let lines: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect();
    assert!(
        lines
            .iter()
            .any(|l| l["fields"]["message"] == "kronik is serving"),
        "{log}"
    );
    assert!(
        lines
            .iter()
            .all(|l| l["level"].is_string() && l["target"].is_string()),
        "{log}"
    );
}

#[test]
fn healthz_answers_while_the_node_runs() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let admin = format!("127.0.0.1:{}", free_port());
    let _serve = Serve::start(&[
        "--data-dir",
        dir.path().join("data").to_str().unwrap(),
        "--api-socket",
        socket.to_str().unwrap(),
        "--http-listen",
        &format!("127.0.0.1:{}", free_port()),
        "--admin-listen",
        &admin,
    ]);
    let health = (0..600).find_map(|_| match TcpStream::connect(&admin) {
        Ok(_) => Some(http_get(&admin, "/healthz")),
        Err(_) => {
            std::thread::sleep(Duration::from_millis(100));
            None
        }
    });
    let (status, body) = health.expect("the admin listener did not come up");
    assert_eq!(status, 200, "{body}");
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(http_get(&admin, "/other").0, 404);
}

#[test]
fn the_master_key_can_come_from_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let port = free_port();
    let http = format!("127.0.0.1:{port}");
    let args = |data: &Path| {
        vec![
            "--data-dir".into(),
            data.to_str().unwrap().into(),
            "--api-socket".into(),
            socket.to_str().unwrap().into(),
            "--http-listen".into(),
            http.clone(),
            "--admin-listen".into(),
            "127.0.0.1:0".into(),
        ]
    };
    // 64 hex characters of material: `01` and `02` repeated 32 times.
    let material = |byte: u8| vec![format!("{byte:02x}"); 32].concat();

    // Material that is not 64 hex characters stops the start.
    let out = command()
        .arg("serve")
        .args(args(&dir.path().join("bad")))
        .env("KRONIK_MASTER_KEY", "not-hex")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("master key environment variable KRONIK_MASTER_KEY must hold 64 hex"),
        "serve must refuse material that is not 64 hex characters"
    );

    // Material and a key file together is ambiguous and refused.
    let out = command()
        .arg("serve")
        .args(args(&dir.path().join("bad")))
        .arg("--master-key-file")
        .arg(dir.path().join("master.key"))
        .env("KRONIK_MASTER_KEY", material(1))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("KRONIK_MASTER_KEY and a master key file"),
        "serve must refuse material and a key file together"
    );

    // The material is the key: no key file appears, the secret set under it
    // survives a restart with the same material, and the same secret's
    // version hash (keyed by the master key) differs under another material.
    let set_secret = || -> String {
        let mut child = command()
            .args([
                "--socket",
                socket.to_str().unwrap(),
                "--json",
                "secret",
                "set",
                "demo",
                "--reason",
                "ops: the master key from the environment",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"the value").unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["secret"]["version_hash"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    let a = dir.path().join("a");
    let serve = Serve::start_with_master_key(args(&a), &material(1));
    let answer = gateway_answer(&socket, &format!("127.0.0.1:{port}"));
    assert!(answer.contains("ROUTE_NOT_FOUND"), "{answer}");
    assert!(!a.join("keys/master.key").exists());
    let hash_a = set_secret();
    drop(serve);
    assert!(!a.join("keys/master.key").exists());

    let _serve = Serve::start_with_master_key(args(&a), &material(1));
    let answer = gateway_answer(&socket, &format!("127.0.0.1:{port}"));
    assert!(answer.contains("ROUTE_NOT_FOUND"), "{answer}");
    let out = kronik(&[
        "--socket",
        socket.to_str().unwrap(),
        "--json",
        "secret",
        "list",
    ]);
    assert!(out.status.success());
    let list: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        list["secrets"][0]["version_hash"].as_str(),
        Some(hash_a.as_str())
    );
    drop(_serve);

    let b = dir.path().join("b");
    let _serve = Serve::start_with_master_key(args(&b), &material(2));
    let answer = gateway_answer(&socket, &format!("127.0.0.1:{port}"));
    assert!(answer.contains("ROUTE_NOT_FOUND"), "{answer}");
    let hash_b = set_secret();
    assert_ne!(
        hash_a, hash_b,
        "the version hash is keyed by the master key"
    );
    assert!(!b.join("keys/master.key").exists());
}

/// `GET /v1/health` over the API socket: the body.
fn health(socket: &Path) -> String {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    write!(
        stream,
        "GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

/// Below `[log] disk_reserve`: health and metrics say so, and forks and
/// `foreign add` are refused before they write anything (an add before it
/// fetches the image).
#[test]
fn below_the_disk_reserve_health_says_so_and_forks_and_adds_wait() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let admin = format!("127.0.0.1:{}", free_port());
    let config = dir.path().join("kronik.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\ndata_dir = {:?}\napi_socket = {:?}\nhttp_listen = \"127.0.0.1:{}\"\n\
             admin_listen = {admin:?}\n\n\
             [foreign]\nrun_dir = {:?}\n",
            dir.path().join("data"),
            socket,
            free_port(),
            dir.path().join("run"),
        ),
    )
    .unwrap();
    // The flag wins over the tests' KRONIK_DISK_RESERVE=0B; more than any
    // disk has, so the reserve is never met.
    let _serve = Serve::start(&[
        "--config",
        config.to_str().unwrap(),
        "--disk-reserve",
        "1000TiB",
    ]);
    let sock = socket.to_str().unwrap();
    let up = (0..600).any(|_| {
        let ok = socket.exists() && health(&socket).contains("applied_lsn");
        if !ok {
            std::thread::sleep(Duration::from_millis(100));
        }
        ok
    });
    assert!(up, "the API did not come up");
    let h = health(&socket);
    assert!(
        h.contains("\"status\":\"ok\"") && h.contains("\"low_disk\":true"),
        "{h}"
    );
    let (code, body) = http_get(&admin, "/healthz");
    assert_eq!(code, 200);
    assert!(
        body.contains("\"status\":\"ok\"") && body.contains("\"low_disk\":true"),
        "{body}"
    );
    let (_, metrics) = http_get(&admin, "/metrics");
    assert!(metrics.contains("kronik_disk_below_reserve 1"), "{metrics}");
    let refused = |args: &[&str]| {
        let out = kronik(&[&["--socket", sock, "--json"][..], args].concat());
        assert!(!out.status.success(), "{args:?} was not refused");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(text.contains("disk_reserve"), "{args:?}: {text}");
    };
    refused(&["fork", "create", "--at", "now", "--reason", "r"]);
    let layout = dir.path().join("layout");
    std::fs::create_dir_all(&layout).unwrap();
    refused(&[
        "foreign",
        "add",
        "echo",
        "--image",
        &format!("oci-layout:{}", layout.display()),
        "--port",
        "8080",
        "--reason",
        "r",
    ]);
    assert!(
        !dir.path()
            .join("data/branches")
            .read_dir()
            .unwrap()
            .any(|e| { e.unwrap().file_name().to_string_lossy().starts_with("f-") })
    );
}
