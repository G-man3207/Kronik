//! Operations: `kronik serve` reads kronik.toml and its flags override it;
//! `serve --init --dry-run` prints the plan and changes nothing.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

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
        stderr.contains(&format!("{}:3:", config.display())),
        "{stderr}"
    );
    assert!(stderr.contains("http_lisen"), "{stderr}");
    let out = kronik(&[
        "serve",
        "--config",
        dir.path().join("none.toml").to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr).unwrap().contains("none.toml"));
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
    assert!(!config.exists());
    assert!(!dir.path().join("etc").exists());
    let data = dir.path().join("data");
    let key = dir.path().join("master.key");
    let config = dir.path().join("existing.toml");
    let contents = format!(
        "[server]\ndata_dir = {:?}\n[keys]\nmaster_key_file = {:?}\n",
        data, key
    );
    std::fs::write(&config, &contents).unwrap();
    let out = kronik(&[
        "serve",
        "--init",
        "--dry-run",
        "--config",
        config.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), contents);
    assert!(!data.exists());
    assert!(!key.exists());

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

/// Whether this host can take the nonroot service: the prerequisites that
/// `serve --init` checks before it plans anything (systemd 255 or newer,
/// cgroup v2, user namespaces).
fn nonroot_host() -> bool {
    let systemd = Command::new("systemctl")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| text.split_whitespace().nth(1)?.parse::<u32>().ok());
    systemd.is_some_and(|version| version >= 255)
        && Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
        && std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .is_some_and(|max| max != 0)
}

/// A plain `serve --init` plans the root service of v0.4.0 on any host, and
/// the nonroot service is opt-in with `--rootless`: it is planned where the
/// host can run it, and otherwise the command stops with an error that names
/// the root service. Missing prerequisites never install the root service by
/// themselves.
#[test]
fn the_default_init_plans_the_root_service_and_rootless_is_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let config = dir.path().join("kronik.toml");
    // The key is outside the data directory, as the nonroot service requires.
    std::fs::write(
        &config,
        format!(
            "[server]\ndata_dir = {:?}\n[keys]\nmaster_key_file = {:?}\n",
            data,
            dir.path().join("master.key")
        ),
    )
    .unwrap();
    // The default: the root service, no user, pin or subordinate range.
    let out = kronik(&[
        "serve",
        "--init",
        "--dry-run",
        "--json",
        "--config",
        config.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let plan: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(plan["mode"], "root");
    assert_eq!(plan["dry_run"], true);
    let steps = plan["steps"].to_string();
    assert!(!steps.contains("kronik-userns.service"), "{steps}");
    assert!(!steps.contains("system user kronik"), "{steps}");
    assert!(!data.exists());
    // `--rootless` on a host without systemd on its path: the error names the
    // root service, whatever this machine is.
    let empty = dir.path().join("empty-path");
    std::fs::create_dir(&empty).unwrap();
    let out = command()
        .args([
            "serve",
            "--init",
            "--rootless",
            "--dry-run",
            "--json",
            "--config",
        ])
        .arg(&config)
        .env("PATH", &empty)
        .output()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("ROOTLESS_UNAVAILABLE"), "{text}");
    assert!(text.contains("kronik serve --init --root"), "{text}");
    assert!(!data.exists());
    if nonroot_host() {
        let out = kronik(&[
            "serve",
            "--init",
            "--rootless",
            "--dry-run",
            "--json",
            "--config",
            config.to_str().unwrap(),
        ]);
        assert!(out.status.success(), "{out:?}");
        let plan: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(plan["mode"], "rootless");
        let steps = plan["steps"].to_string();
        assert!(steps.contains("kronik-userns.service"), "{steps}");
        assert!(!data.exists());
    }
}

#[test]
fn root_init_json_plan_does_not_create_a_minimal_keys_directory() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let config = dir.path().join("kronik.toml");
    std::fs::write(&config, format!("[server]\ndata_dir = {:?}\n", data)).unwrap();
    let out = kronik(&[
        "serve",
        "--init",
        "--root",
        "--dry-run",
        "--json",
        "--config",
        config.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["mode"], "root");
    assert_eq!(value["dry_run"], true);
    assert!(value["steps"].as_array().unwrap().len() >= 3);
    assert!(!data.exists());
    let selected = dir.path().join("selected.key");
    // The root unit starts the daemon with the configuration alone, so a key
    // file the configuration does not name would be used by the key step and
    // not by the daemon: refused, with the way out.
    let out = kronik(&[
        "serve",
        "--init",
        "--root",
        "--dry-run",
        "--json",
        "--master-key-file",
        selected.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "{out:?}");
    let refusal: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(refusal["error"]["code"], "BAD_REQUEST", "{refusal}");
    let message = refusal["error"]["message"].as_str().unwrap();
    assert!(
        message.starts_with(&format!(
            "--master-key-file {} would not reach the root service: its unit starts the daemon with the configuration alone, and the configuration names ",
            selected.display()
        )),
        "{message}"
    );
    assert!(
        refusal["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("[keys] master_key_file"),
        "{refusal}"
    );
    // The file the configuration names is accepted, and the plan names it.
    std::fs::write(
        &config,
        format!(
            "[server]\ndata_dir = {:?}\n[keys]\nmaster_key_file = {:?}\n",
            data, selected
        ),
    )
    .unwrap();
    let out = kronik(&[
        "serve",
        "--init",
        "--root",
        "--dry-run",
        "--json",
        "--master-key-file",
        selected.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        value["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["what"]
                .as_str()
                .unwrap()
                .contains(selected.to_str().unwrap())),
        "{value}"
    );
    assert!(!data.exists());
    assert!(!selected.exists());
}

#[test]
fn init_environment_dry_run_names_effective_source_without_persisting_seed() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let config = dir.path().join("kronik.toml");
    let base = format!(
        "[server]\ndata_dir = {:?}\n[foreign]\nmicrovm_dir = {:?}\n",
        data,
        dir.path().join("no-tools")
    );
    std::fs::write(&config, &base).unwrap();
    let args = [
        "serve",
        "--init",
        "--root",
        "--dry-run",
        "--json",
        "--config",
        config.to_str().unwrap(),
    ];
    let implicit = command()
        .args(args)
        .env("KRONIK_MASTER_KEY", "07".repeat(32))
        .output()
        .unwrap();
    assert!(implicit.status.success(), "{implicit:?}");
    let plan: serde_json::Value = serde_json::from_slice(&implicit.stdout).unwrap();
    assert!(
        plan["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["what"]
                .as_str()
                .unwrap()
                .contains("env master key from KRONIK_MASTER_KEY (no key file)")),
        "{plan}"
    );
    assert!(!data.exists());
    std::fs::write(&config, format!("{base}\n[keys]\nsource = \"env\"\n")).unwrap();
    let explicit = command()
        .args(args)
        .env("KRONIK_MASTER_KEY", "07".repeat(32))
        .output()
        .unwrap();
    assert!(explicit.status.success(), "{explicit:?}");
    assert!(!data.exists());
}

#[test]
fn stopped_cleanup_missing_runtime_is_idempotent_but_never_bypasses_data_lock() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let run = dir.path().join("missing-run");
    std::fs::create_dir(&data).unwrap();
    let config = dir.path().join("kronik.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\ndata_dir = {:?}\n[foreign]\nrun_dir = {:?}\n",
            data, run
        ),
    )
    .unwrap();
    let held = kronik_privacy::key_source::lock_data(&data).unwrap();
    let args = [
        "foreign",
        "cleanup",
        "--json",
        "--config",
        config.to_str().unwrap(),
    ];
    let refused = kronik(&args);
    assert!(!refused.status.success(), "{refused:?}");
    let error: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(error["error"]["code"], "UNAVAILABLE", "{error}");
    assert!(!run.exists());
    drop(held);
    let private_config = data.join("foreign/actors/echo/bundle/config.json");
    std::fs::create_dir_all(private_config.parent().unwrap()).unwrap();
    std::fs::write(
        &private_config,
        b"{\"env\":[\"SECRET=private-test-value\"]}",
    )
    .unwrap();
    for iteration in 0..2 {
        let out = kronik(&args);
        assert!(out.status.success(), "{out:?}");
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(value["failed"], 0);
        assert_eq!(value["sandboxes"], 0);
        assert_eq!(value["configs"], if iteration == 0 { 1 } else { 0 });
        assert!(
            !private_config.exists(),
            "a dead pin is not needed to remove owned secret config"
        );
        assert!(!run.exists(), "cleanup must not recreate runtime state");
    }
    // Without a data directory there is no lock to take and nothing of the
    // daemon's to clean: that is still a success, as it was before the lock.
    std::fs::remove_dir_all(&data).unwrap();
    let out = kronik(&args);
    assert!(out.status.success(), "{out:?}");
    assert!(!data.exists() && !run.exists());
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
    let out = command()
        .env_remove("KRONIK_TOKEN")
        .env_remove("KRONIK_AUDIT_SINK")
        .env_remove("KRONIK_OTEL_ENDPOINT")
        .args(["--json", "doctor", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
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
    // Plain doctor, as root or as an ordinary user, lists what it always did:
    // the nonroot service's checks come with --rootless only.
    let expected = [
        "config",
        "kernel",
        "runsc",
        "kvm",
        "cgroup",
        "root",
        "runc",
        "netns",
        "run_dir",
        "caps",
        "sandbox",
        "disk",
        "clock",
        "tls",
        "ship",
        "export",
        "key_source",
        "secrets",
    ];
    assert_eq!(names, expected);
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
    assert_eq!(tls["code"], "CERTIFICATE_INVALID", "{report}");
    assert!(
        tls["hint"].as_str().is_some_and(|hint| !hint.is_empty()),
        "{report}"
    );
    assert!(
        tls["message"].as_str().unwrap().contains("expired"),
        "{report}"
    );
    let human = command()
        .env_remove("KRONIK_TOKEN")
        .args(["doctor", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(
        text.contains("FAIL") && text.contains("(CERTIFICATE_INVALID)") && text.contains("hint:"),
        "{text}"
    );
    assert!(!human.status.success(), "{text}");
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

    // A ship endpoint without a scheme fails with a code and a hint.
    std::fs::write(
        &config,
        format!(
            "[server]\ndata_dir = {:?}\n[ship]\nenabled = true\nurl = \"s3://bucket/kronik\"\nendpoint = \"s3.example.com\"\n",
            dir.path().join("data"),
        ),
    )
    .unwrap();
    let (report, ok) = doctor(&config);
    assert!(!ok);
    let ship = status(&report, "ship");
    assert_eq!(ship["status"], "fail", "{report}");
    assert_eq!(ship["code"], "BAD_REQUEST", "{report}");
    assert!(
        ship["hint"].as_str().is_some_and(|hint| !hint.is_empty()),
        "{report}"
    );
    let human = command()
        .env_remove("KRONIK_TOKEN")
        .args(["doctor", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(
        text.contains("(BAD_REQUEST)") && text.contains("hint:"),
        "{text}"
    );
    assert!(!human.status.success(), "{text}");

    // A broken file is a failed check, and the rest still runs.
    std::fs::write(&config, "[tls]\nmode = \"ftp\"\n").unwrap();
    let (report, ok) = doctor(&config);
    assert!(!ok);
    assert_eq!(status(&report, "config")["status"], "fail");
    assert_eq!(report["checks"].as_array().unwrap().len(), 18);
}

#[test]
fn explicit_rootless_doctor_never_counts_a_root_smoke_as_service_identity() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("kronik.toml");
    std::fs::write(
        &config,
        "[foreign]\nrunsc_path = \"/no-such-kronik-runsc\"\n",
    )
    .unwrap();
    let out = kronik(&[
        "--json",
        "doctor",
        "--rootless",
        "--config",
        config.to_str().unwrap(),
    ]);
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {out:?}"));
    for name in ["userns", "uid_view", "subid", "pin", "delegate"] {
        assert!(status(&report, name)["status"].is_string(), "{report}");
    }
    if kronik_foreign::sys::is_root() {
        let identity = status(&report, "service_identity");
        if identity["status"] != "pass" {
            assert_ne!(status(&report, "netns")["status"], "pass", "{report}");
            assert_ne!(status(&report, "sandbox")["status"], "pass", "{report}");
        } else {
            assert!(
                identity["message"].as_str().unwrap().contains("host uid"),
                "{report}"
            );
        }
    }
}

#[test]
fn doctor_queries_live_exports_and_warns_on_real_api_failures() {
    use std::os::unix::net::UnixListener;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let config = dir.path().join("kronik.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\ndata_dir = {:?}\napi_socket = {:?}\n[tls]\nmode = \"off\"\n",
            dir.path().join("data"),
            socket,
        ),
    )
    .unwrap();
    let (report, ok) = doctor(&config);
    assert_eq!(status(&report, "export")["status"], "pass", "{report}");
    assert_eq!(ok, report["fail"] == 0, "{report}");

    let stalled = serde_json::json!({"streams": [{
        "name": "audit", "enabled": true, "sink": "https://example.test",
        "cursor": 0, "applied_lsn": 1, "lag": 1,
        "last_success_wall_ms": null, "stalled_ms": 86_400_000,
        "last_error": "timeout", "gaps": 0
    }]})
    .to_string();
    const NEEDLE: &str = "doctor-response-secret-c51b7093";
    let invalid = serde_json::json!({"streams": NEEDLE}).to_string();
    let responses = [
        Some(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{stalled}",
            stalled.len()
        )),
        Some("this is not HTTP\r\n\r\n".into()),
        Some("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{".into()),
        Some(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{invalid}",
            invalid.len()
        )),
        Some("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".into()),
        None,
    ];
    for response in responses {
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "doctor never queried the daemon"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = [0; 4096];
            let n = stream.read(&mut request).unwrap();
            assert!(request[..n].starts_with(b"GET /v1/export HTTP/1.1\r\n"));
            if let Some(response) = response {
                stream.write_all(response.as_bytes()).unwrap();
            } else {
                std::thread::sleep(Duration::from_secs(6));
            }
        });
        let (report, ok) = doctor(&config);
        server.join().unwrap();
        std::fs::remove_file(&socket).unwrap();
        assert_eq!(status(&report, "export")["status"], "warn", "{report}");
        assert_eq!(
            ok,
            report["fail"] == 0,
            "warnings must not fail doctor: {report}"
        );
        assert!(!report.to_string().contains(NEEDLE));
    }
    // A stale socket exists, but connection refusal is not daemon absence.
    drop(UnixListener::bind(&socket).unwrap());
    let (report, ok) = doctor(&config);
    assert_eq!(status(&report, "export")["status"], "warn", "{report}");
    assert_eq!(ok, report["fail"] == 0, "{report}");
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
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let manifest = data.join(kronik_otel::cursor::Cursors::FILE);
    let unknown = b"{unknown truncated export state";
    std::fs::write(&manifest, unknown).unwrap();
    let _serve = Serve::start(&[
        "--data-dir",
        data.to_str().unwrap(),
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
    assert_eq!(std::fs::read(manifest).unwrap(), unknown);
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
    assert!(!dir.path().join("bad/keys/master.key").exists());

    // Material and a key file together is ambiguous and refused.
    let out = command()
        .arg("serve")
        .args(args(&dir.path().join("conflict")))
        .arg("--master-key-file")
        .arg(dir.path().join("master.key"))
        .env("KRONIK_MASTER_KEY", material(1))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!dir.path().join("conflict").exists());
    assert!(!dir.path().join("master.key").exists());

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
    let out = kronik(&[
        "--socket",
        socket.to_str().unwrap(),
        "--json",
        "keys",
        "status",
    ]);
    assert!(out.status.success(), "{out:?}");
    let status: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(status["source"], "env");
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

/// Below `[log] disk_reserve`: health and metrics say so, and forks,
/// previews (create and requests) and `foreign add` are refused before
/// they write anything (an add before it fetches the image).
#[test]
fn below_the_disk_reserve_health_says_so_and_forks_and_adds_wait() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let admin = format!("127.0.0.1:{}", free_port());
    let gateway = format!("127.0.0.1:{}", free_port());
    let config = dir.path().join("kronik.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\ndata_dir = {:?}\napi_socket = {:?}\nhttp_listen = {gateway:?}\n\
             admin_listen = {admin:?}\n\n\
             [foreign]\nrun_dir = {:?}\n",
            dir.path().join("data"),
            socket,
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
    refused(&["preview", "create", "p-000000000000", "--reason", "r"]);
    let (code, body) = http_get(&gateway, "/__preview/v-000000000000/counter/x");
    assert_eq!(code, 503, "{body}");
    assert!(body.contains("disk_reserve"), "{body}");
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

// The real TLS peer is an I/O harness; the client under test still uses Env.
#[allow(clippy::disallowed_methods)]
#[tokio::test]
async fn scoped_provider_tls_does_not_change_guest_trust_or_identity() {
    use kronik_core::env::{Env, HttpRequest, TlsConfig};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;

    fn server(
        config: rustls::ServerConfig,
    ) -> (String, std::thread::JoinHandle<std::io::Result<()>>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", free_port())).unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => return Err(e),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            while connection.is_handshaking() {
                connection.complete_io(&mut socket)?;
            }
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut request = [0u8; 512];
            if stream.read(&mut request)? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
            stream.flush()
        });
        (format!("https://localhost:{}", address.port()), worker)
    }
    async fn get(
        env: &Env,
        net: &Arc<dyn kronik_core::env::Net>,
        url: String,
    ) -> Result<kronik_core::env::HttpResponse, kronik_core::env::NetError> {
        env.timeout(
            Duration::from_secs(5),
            net.http(HttpRequest {
                method: "GET".into(),
                url,
                headers: vec![],
                body: bytes::Bytes::new(),
                max_response_bytes: 64,
            }),
        )
        .await
        .unwrap()
    }
    let root_key = rcgen::KeyPair::generate().unwrap();
    let mut root_params = rcgen::CertificateParams::new(vec![]).unwrap();
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let root = root_params.self_signed(&root_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&root_params, &root_key);
    let server_key = rcgen::KeyPair::generate().unwrap();
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
    let client_key = rcgen::KeyPair::generate().unwrap();
    let mut client_params = rcgen::CertificateParams::new(vec![]).unwrap();
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let builder = || {
        rustls::ServerConfig::builder_with_provider(crypto.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
    };
    let certificate = || vec![server_cert.der().clone()];
    let key = || PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let ordinary_server = builder()
        .with_no_client_auth()
        .with_single_cert(certificate(), key())
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        crypto.clone(),
    )
    .build()
    .unwrap();
    let authenticated_server = builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate(), key())
        .unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let trusted_guest = env
        .net
        .with_tls(TlsConfig {
            ca: vec![root.der().to_vec()],
            identity: None,
        })
        .unwrap();
    let provider = trusted_guest
        .with_tls(TlsConfig {
            ca: vec![root.der().to_vec()],
            identity: Some((vec![client_cert.der().to_vec()], client_key.serialize_der())),
        })
        .unwrap();
    // No client auth here: a failure specifically proves the private CA did
    // not leak into the original guest client's trust roots.
    let (url, worker) = server(ordinary_server);
    assert!(get(&env, &env.net, url).await.is_err());
    assert!(worker.join().unwrap().is_err());
    let (url, worker) = server(authenticated_server.clone());
    assert_eq!(get(&env, &provider, url).await.unwrap().status, 200);
    worker.join().unwrap().unwrap();
    // This base trusts the same CA, so the rejection proves the provider's
    // client identity was not installed on its parent.
    let (url, worker) = server(authenticated_server);
    assert!(get(&env, &trusted_guest, url).await.is_err());
    assert!(worker.join().unwrap().is_err());
}
