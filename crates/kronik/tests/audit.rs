//! M28's second acceptance (docs/design/m28-otel.md §4.5): a real `kronik
//! serve` exports its audit log to a `file://` sink, and the export is
//! complete compared with the log's records. The expectations come from
//! what the test drove (review M4), not from the exporter's classifier.
//! Also: a reseal changes no exported line (review M2), a torn line is
//! truncated at start (review M7), a restore from an older ship point is
//! told apart by hash (review H4), and an injected conflict is reported.

// Test helpers outside #[test] functions may unwrap.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use kronik_otel::audit::Line;
use serde_json::{Value, json};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const STEP2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter-step2.wasm"
);

/// The needles: none may appear in any exported line.
const SECRET: &str = "s3cr3t-needle-91ab";
const SUBJECT: &str = "customer-needle-4711";
const BODY: &str = "body-needle-c0ffee";

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
        "KRONIK_MASTER_KEY",
        "KRONIK_OTEL_ENDPOINT",
        "KRONIK_AUDIT_SINK",
    ] {
        c.env_remove(var);
    }
    // The tests' temporary file system may have less than the reserve.
    c.env("KRONIK_DISK_RESERVE", "0B");
    c.stdin(Stdio::null());
    c
}

fn b64(path: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(std::fs::read(path).unwrap())
}

/// `kronik serve` with `[audit] sink` on `<dir>/audit`; killed when
/// dropped.
struct Daemon {
    child: Child,
    dir: PathBuf,
    data: PathBuf,
    config: PathBuf,
    socket: PathBuf,
}

impl Daemon {
    /// `extra` is appended to the configuration file.
    fn start(dir: &Path, data: &Path, extra: &str) -> Daemon {
        Daemon::start_with(dir, data, extra, &[])
    }

    /// With `env` set for `kronik serve` too.
    fn start_with(dir: &Path, data: &Path, extra: &str, env: &[(&str, &str)]) -> Daemon {
        let socket = dir.join("api.sock");
        let config = dir.join("kronik.toml");
        // With the tests' 0B reserve the default hold_release ("2x") is 0,
        // which is refused without max_hold; 30 days never runs out here.
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {data:?}\napi_socket = {socket:?}\n\
                 http_listen = \"127.0.0.1:0\"\nadmin_listen = \"127.0.0.1:0\"\n\n\
                 [audit]\nsink = \"file://{}/\"\ninterval = \"100ms\"\nmax_hold = \"30d\"\n{extra}",
                dir.join("audit").display(),
            ),
        )
        .unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("serve.log"))
            .unwrap();
        let child = command()
            .arg("serve")
            .arg("--config")
            .arg(&config)
            .envs(env.iter().copied())
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon {
            child,
            dir: dir.to_owned(),
            data: data.to_owned(),
            config,
            socket,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        while d.try_api("GET", "/v1/health", None, None).is_none() {
            assert!(
                Instant::now() < deadline,
                "kronik serve did not start:\n{}",
                d.log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        d
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    fn try_api(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        bearer: Option<&str>,
    ) -> Option<(u16, Value)> {
        let mut s = std::os::unix::net::UnixStream::connect(&self.socket).ok()?;
        let body = body.map(Value::to_string).unwrap_or_default();
        let auth = bearer
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{auth}\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .ok()?;
        let mut response = String::new();
        s.read_to_string(&mut response).ok()?;
        let (head, body) = response.split_once("\r\n\r\n")?;
        let status = head.split(' ').nth(1)?.parse().ok()?;
        Some((status, serde_json::from_str(body).unwrap_or(Value::Null)))
    }

    fn api(&self, method: &str, path: &str, body: &Value) -> (u16, Value) {
        self.try_api(method, path, Some(body), None).unwrap()
    }

    fn applied(&self) -> u64 {
        let (_, v) = self.try_api("GET", "/v1/health", None, None).unwrap();
        v["applied_lsn"].as_u64().unwrap()
    }

    /// The applied LSN once it stopped moving: an answer can come before
    /// its record is applied.
    fn settled(&self) -> u64 {
        let mut last = self.applied();
        loop {
            std::thread::sleep(Duration::from_millis(100));
            let now = self.applied();
            if now == last {
                return now;
            }
            last = now;
        }
    }

    fn audit_stream(&self) -> Value {
        let (_, v) = self.try_api("GET", "/v1/export", None, None).unwrap();
        v["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "audit")
            .unwrap()
            .clone()
    }

    /// Waits until the audit cursor reaches the applied LSN.
    fn wait_exported(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let s = self.audit_stream();
            assert_eq!(s["enabled"], true, "{s}");
            if s["cursor"] == s["applied_lsn"] {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "not exported: {s}\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn cli(&self, args: &[&str]) -> Output {
        command()
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The records in `from..=to`, for a failure message.
fn records(data: &Path, from: u64, to: u64) -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
        let reader = kronik_log::LogReader::new(env, data.join("branches/main/log"), "main");
        let mut out = String::new();
        let _ = reader
            .read(from, to, |c| {
                out.push_str(&format!("{}: {:?}\n", c.lsn, c.record));
                Ok(())
            })
            .await;
        out
    })
}

/// The sink's lines, in the order they were written.
fn sink_text(dir: &Path) -> String {
    kronik_otel::sink::files(&dir.join("audit"))
        .unwrap()
        .iter()
        .map(|f| std::fs::read_to_string(f).unwrap())
        .collect()
}

fn sink_lines(dir: &Path) -> Vec<Line> {
    sink_text(dir)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect()
}

/// Deduplicated by (lsn, effect, record_hash), as a consumer would.
fn distinct(lines: Vec<Line>) -> Vec<Line> {
    let mut seen = BTreeSet::new();
    lines
        .into_iter()
        .filter(|l| seen.insert((l.lsn, l.effect, l.record_hash.clone())))
        .collect()
}

/// `kronik audit verify` over the file sink, with the daemon's
/// configuration: its exit code and report.
fn verify(d: &Daemon, data: &Path) -> (i32, Value) {
    let out = command()
        .arg("--json")
        .arg("audit")
        .arg("verify")
        .arg("--sink")
        .arg(format!("file://{}/", d.dir.join("audit").display()))
        .arg("--config")
        .arg(&d.config)
        .arg("--data-dir")
        .arg(data)
        .output()
        .unwrap();
    let report = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {out:?}"));
    (out.status.code().unwrap(), report)
}

/// One mutation the test drives: the route as the OpenAPI table names it,
/// the call, and the line it must export.
struct Step {
    method: &'static str,
    template: &'static str,
    path: String,
    body: Value,
    /// `action` of the expected line; None: the call fails and exports
    /// nothing.
    action: Option<&'static str>,
}

fn step(
    method: &'static str,
    template: &'static str,
    path: &str,
    body: Value,
    action: Option<&'static str>,
) -> Step {
    Step {
        method,
        template,
        path: path.to_owned(),
        body,
        action,
    }
}

/// What one exported line must say: action, reason (None where the export
/// rewrites it: an erasure's subject), token.
type Want = (String, Option<String>, String);

/// Drives `steps` as `token` (with `bearer`, else as the socket's caller),
/// each with a dry run first that must write nothing (fork replay has none;
/// a fork message refuses one), and records the line each must export.
/// `{id}`, `{proposal}` and `{epoch}` are filled from earlier answers,
/// which are returned.
fn drive(
    d: &Daemon,
    steps: Vec<Step>,
    (bearer, token): (Option<&str>, &str),
    want: &mut Vec<Want>,
    seen: &mut Vec<(String, String)>,
) -> Vec<Value> {
    let (mut dead_letter, mut proposal, mut epoch) = (String::new(), String::new(), String::new());
    let (mut preview, mut watch) = (String::new(), String::new());
    let mut answers = Vec::new();
    for mut s in steps {
        seen.push((s.method.to_owned(), s.template.to_owned()));
        let path = s
            .path
            .replace("{id}", &dead_letter)
            .replace("{proposal}", &proposal)
            .replace("{epoch}", &epoch)
            .replace("{preview}", &preview)
            .replace("{watch}", &watch);
        if s.body["proposal"] == "{proposal}" {
            s.body["proposal"] = json!(proposal);
        }
        let reason = format!("audit test {} {}", s.method, s.template);
        // An erasure's subject is replaced by its hash (review M8).
        let reason = match s.template {
            "/v1/privacy/erase" => format!("{reason} {SUBJECT}"),
            _ => reason,
        };
        let mut body = s.body.clone();
        body["reason"] = json!(reason);
        if s.template != "/v1/forks/{name}/replay" {
            let before = d.settled();
            let mut dry = body.clone();
            dry["dry_run"] = json!(true);
            let (status, v) = d.try_api(s.method, &path, Some(&dry), bearer).unwrap();
            let after = d.settled();
            assert_eq!(
                after,
                before,
                "a dry run of {} {path} wrote (HTTP {status}): {v}\n{}",
                s.method,
                records(&d.data, before + 1, after)
            );
        }
        let (status, v) = d.try_api(s.method, &path, Some(&body), bearer).unwrap();
        let Some(action) = s.action else {
            assert_ne!(status, 200, "{} {path}: {v}", s.method);
            continue;
        };
        assert_eq!(status, 200, "{} {path}: {v}\n{}", s.method, d.log());
        let shown = (s.template != "/v1/privacy/erase").then(|| reason.clone());
        want.push((action.into(), shown.clone(), token.into()));
        match s.template {
            "/v1/actors/{kind}/{key}/messages" if s.body["name"] == "fail" => {
                dead_letter = v["turn_id"].as_str().unwrap().into();
            }
            // The test actor reveals the secret inside the operator send:
            // its line carries the send's audit (review H3).
            "/v1/actors/{kind}/{key}/messages" if s.body["name"] == "reveal" => {
                want.push(("secret.reveal".into(), shown, token.into()));
            }
            "/v1/proposals" => proposal = v["proposal"]["id"].as_str().unwrap().into(),
            "/v1/proposals/{id}/promote" => epoch = v["deployment"]["epoch"].to_string(),
            "/v1/previews" => preview = v["preview"]["id"].as_str().unwrap().into(),
            "/v1/deployments/{epoch}/watch" => watch = v["watch"]["id"].as_str().unwrap().into(),
            _ => {}
        }
        answers.push(v);
    }
    answers
}

/// Every mutating route once (plus a dry run each), an operator send and a
/// resend, a test actor revealing a secret, and a restart in between: the
/// file sink then holds exactly one line per action driven, none holds a
/// needle, and `kronik audit verify` reports the sink complete.
#[test]
fn every_mutation_reaches_the_file_sink_and_verify_reports_it_complete() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let uid = format!("unix:uid={}", std::fs::metadata(dir.path()).unwrap().uid());
    let me = (None, uid.as_str());
    let mut want: Vec<Want> = Vec::new();
    let mut seen = Vec::new();

    let d = Daemon::start(dir.path(), &data, "");
    // A first start with a sink records the settings.
    want.push(("audit.config".into(), None, "system".into()));
    drive(
        &d,
        vec![
            step(
                "POST",
                "/v1/deployments",
                "/v1/deployments",
                json!({"wasm_base64": b64(COUNTER)}),
                Some("deploy"),
            ),
            step(
                "PUT",
                "/v1/secrets/{name}",
                "/v1/secrets/db",
                json!({"text": SECRET}),
                Some("secret.set"),
            ),
            step(
                "POST",
                "/v1/grants",
                "/v1/grants",
                json!({"kind": "counter", "capability": "secret-reveal:db"}),
                Some("grant"),
            ),
            step(
                "POST",
                "/v1/actors/{kind}/{key}/messages",
                "/v1/actors/counter/r/messages",
                json!({"name": "reveal", "text": "db"}),
                Some("send"),
            ),
            step(
                "POST",
                "/v1/actors/{kind}/{key}/messages",
                "/v1/actors/counter/a/messages",
                json!({"name": "fail", "text": BODY}),
                Some("send"),
            ),
            step(
                "POST",
                "/v1/dead-letters/{id}/resend",
                "/v1/dead-letters/{id}/resend",
                json!({}),
                Some("resend"),
            ),
            step(
                "POST",
                "/v1/grants/revoke",
                "/v1/grants/revoke",
                json!({"kind": "counter", "capability": "secret-reveal:db"}),
                Some("revoke"),
            ),
        ],
        me,
        &mut want,
        &mut seen,
    );
    // A token acts as itself: its id, never its secret, is in the line.
    let created = drive(
        &d,
        vec![step(
            "POST",
            "/v1/tokens",
            "/v1/tokens",
            json!({"name": "agent-1", "scopes": ["operate"]}),
            Some("token.create"),
        )],
        me,
        &mut want,
        &mut seen,
    );
    let token = created[0]["secret"].as_str().unwrap().to_owned();
    drive(
        &d,
        vec![step(
            "POST",
            "/v1/limits",
            "/v1/limits",
            json!({"kind": "counter", "fuel": 100_000_000}),
            Some("limits"),
        )],
        (Some(&token), "token:agent-1"),
        &mut want,
        &mut seen,
    );
    drive(
        &d,
        vec![step(
            "POST",
            "/v1/tokens/{name}/revoke",
            "/v1/tokens/agent-1/revoke",
            json!({}),
            Some("token.revoke"),
        )],
        me,
        &mut want,
        &mut seen,
    );
    d.wait_exported();
    d.stop();

    // The cursor survives the restart; the same settings record nothing.
    let d = Daemon::start(dir.path(), &data, "");
    drive(
        &d,
        vec![
            step(
                "PUT",
                "/v1/policy",
                "/v1/policy",
                json!({"rules_toml": "[[rule]]\nname = \"quiet\"\nwhen = \"false\"\naction = \"allow\"\n"}),
                Some("policy"),
            ),
            step(
                "PUT",
                "/v1/simulators/{target}",
                "/v1/simulators/http:example.com",
                json!({"neighbor": true}),
                Some("simulators.set"),
            ),
            step(
                "POST",
                "/v1/forks",
                "/v1/forks",
                json!({"at": 1, "name": "try"}),
                Some("fork.create"),
            ),
            step(
                "POST",
                "/v1/forks/{name}/deployments",
                "/v1/forks/try/deployments",
                json!({"wasm_base64": b64(STEP2)}),
                Some("fork.deploy"),
            ),
            step(
                "POST",
                "/v1/forks/{name}/actors/{kind}/{key}/messages",
                "/v1/forks/try/actors/counter/a/messages",
                json!({"name": "increment", "text": BODY}),
                Some("fork.send"),
            ),
            step(
                "POST",
                "/v1/forks/{name}/replay",
                "/v1/forks/try/replay",
                json!({}),
                Some("fork.replay"),
            ),
            step(
                "DELETE",
                "/v1/forks/{name}",
                "/v1/forks/try",
                json!({}),
                Some("fork.delete"),
            ),
            step(
                "POST",
                "/v1/proposals",
                "/v1/proposals",
                json!({"wasm_base64": [b64(STEP2)], "threads": 2}),
                Some("proposal.create"),
            ),
            step(
                "POST",
                "/v1/previews",
                "/v1/previews",
                json!({"proposal": "{proposal}"}),
                Some("preview.create"),
            ),
            step(
                "DELETE",
                "/v1/previews/{id}",
                "/v1/previews/{preview}",
                json!({}),
                Some("preview.delete"),
            ),
            step(
                "POST",
                "/v1/proposals/{id}/request-approval",
                "/v1/proposals/{proposal}/request-approval",
                json!({}),
                Some("request_approval"),
            ),
            step(
                "POST",
                "/v1/proposals/{id}/approve",
                "/v1/proposals/{proposal}/approve",
                json!({}),
                Some("approve"),
            ),
            step(
                "POST",
                "/v1/proposals/{id}/promote",
                "/v1/proposals/{proposal}/promote",
                json!({}),
                Some("promote"),
            ),
            step(
                "POST",
                "/v1/deployments/{epoch}/watch",
                "/v1/deployments/{epoch}/watch",
                json!({"for_ms": 60_000, "async": true}),
                Some("watch.start"),
            ),
            step(
                "POST",
                "/v1/watches/{id}/stop",
                "/v1/watches/{watch}/stop",
                json!({}),
                Some("watch.stop"),
            ),
            // Before the rollback: a rollback via replay undoes main's
            // newest deployment only.
            step(
                "POST",
                "/v1/deployments/{epoch}/rebase",
                "/v1/deployments/{epoch}/rebase",
                json!({}),
                Some("rebase.create"),
            ),
            step(
                "POST",
                "/v1/deployments/{epoch}/rollback",
                "/v1/deployments/{epoch}/rollback",
                json!({}),
                Some("rollback"),
            ),
            step(
                "POST",
                "/v1/privacy/mode",
                "/v1/privacy/mode",
                json!({"mode": "on"}),
                Some("privacy.mode"),
            ),
            step(
                "POST",
                "/v1/actors/{kind}/{key}/messages",
                "/v1/actors/counter/b/messages",
                json!({"name": "increment", "text": BODY, "subject": SUBJECT}),
                Some("send"),
            ),
            step(
                "POST",
                "/v1/privacy/erase",
                "/v1/privacy/erase",
                json!({"subject": SUBJECT}),
                Some("privacy.erase"),
            ),
            step(
                "POST",
                "/v1/privacy/reseal",
                "/v1/privacy/reseal",
                json!({}),
                Some("privacy.reseal"),
            ),
            step(
                "POST",
                "/v1/snapshots",
                "/v1/snapshots",
                json!({}),
                Some("snapshot.create"),
            ),
        ],
        me,
        &mut want,
        &mut seen,
    );
    // A rewind resends what the sink has: verify counts repeats once.
    d.wait_exported();
    let cursor = d.audit_stream()["cursor"].as_u64().unwrap();
    drive(
        &d,
        vec![step(
            "POST",
            "/v1/export/{stream}/rewind",
            "/v1/export/audit/rewind",
            json!({"to": cursor - 5}),
            Some("export.rewind"),
        )],
        me,
        &mut want,
        &mut seen,
    );
    d.wait_exported();
    drive(
        &d,
        vec![
            step(
                "DELETE",
                "/v1/secrets/{name}",
                "/v1/secrets/db",
                json!({}),
                Some("secret.delete"),
            ),
            // shortcut: foreign add and remove fail here (port 0, no such actor) and must export nothing; crates/kronik/tests/foreign.rs covers their records, extend once this test can run a foreign actor.
            step(
                "POST",
                "/v1/foreign",
                "/v1/foreign",
                json!({"name": "echo", "image": "not-an-image", "port": 0}),
                None,
            ),
            step(
                "DELETE",
                "/v1/foreign/{name}",
                "/v1/foreign/echo",
                json!({}),
                None,
            ),
        ],
        me,
        &mut want,
        &mut seen,
    );
    d.wait_exported();

    // Every mutating route of the API was driven.
    let routes: BTreeSet<(String, String)> = kronik_api::openapi::OPERATIONS
        .iter()
        .filter(|op| matches!(op.method, "POST" | "PUT" | "DELETE"))
        .filter(|op| op.path != "/v1/policy/test")
        .map(|op| (op.method.to_owned(), op.path.to_owned()))
        .collect();
    assert_eq!(seen.iter().cloned().collect::<BTreeSet<_>>(), routes);

    // Exactly one line per action driven, and nothing else.
    let text = sink_text(dir.path());
    let lines = distinct(sink_lines(dir.path()));
    let mut got: Vec<Want> = lines
        .iter()
        .map(|l| (l.action.clone(), Some(l.reason.clone()), l.token_id.clone()))
        .collect();
    for (w, g) in want.iter().zip(got.iter_mut()) {
        if w.1.is_none() {
            g.1 = None;
        }
    }
    assert_eq!(got, want, "{text}");
    let erase = lines.iter().find(|l| l.action == "privacy.erase").unwrap();
    assert!(erase.reason.contains(" s:"), "{text}");
    let reveal = lines.iter().find(|l| l.action == "secret.reveal").unwrap();
    assert_eq!(reveal.details["secret"], "db", "{text}");
    assert!(reveal.effect.is_some(), "{text}");
    for needle in [SECRET, SUBJECT, BODY, token.as_str()] {
        assert!(!text.contains(needle), "{needle} left the node:\n{text}");
    }
    // `kronik audit show` builds the same lines from the log.
    let shown = d.cli(&["--json", "audit", "show", "--limit", "1000"]);
    assert!(shown.status.success(), "{shown:?}");
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    let shown_text = shown.to_string();
    assert_eq!(
        shown["lines"].as_array().unwrap().len(),
        lines.len(),
        "{shown}"
    );
    for needle in [SECRET, SUBJECT, BODY, token.as_str()] {
        assert!(!shown_text.contains(needle), "{needle} in audit show");
    }

    let (code, report) = verify(&d, &data);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["complete"], true, "{report}");
    assert_eq!(report["expected"], want.len(), "{report}");
}

/// The lines a reseal would change, if `record_hash` covered sealed
/// payloads, were exported before it: verify still passes (review M2).
#[test]
fn a_reseal_after_the_export_leaves_verify_complete() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    // Segments roll after a second, so the sends land in a closed one.
    let d = Daemon::start(dir.path(), &data, "\n[log]\nsegment_max_age_s = 1\n");
    let r = |s: &str| json!({"reason": s});
    let mut deploy = r("deploy");
    deploy["wasm_base64"] = json!(b64(COUNTER));
    assert_eq!(d.api("POST", "/v1/deployments", &deploy).0, 200);
    let send = json!({"name": "increment", "text": BODY, "subject": SUBJECT, "reason": "send"});
    assert_eq!(d.api("POST", "/v1/actors/counter/a/messages", &send).0, 200);
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(d.api("POST", "/v1/actors/counter/a/messages", &send).0, 200);
    let mut mode = r("mode");
    mode["mode"] = json!("on");
    assert_eq!(d.api("POST", "/v1/privacy/mode", &mode).0, 200);
    d.wait_exported();
    let (status, v) = d.api("POST", "/v1/privacy/reseal", &r("seal history"));
    assert_eq!(status, 200, "{v}");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (_, s) = d.try_api("GET", "/v1/privacy", None, None).unwrap();
        let r = &s["reseal"];
        if r["segments_total"].as_u64() > Some(0) && r["segments_done"] == r["segments_total"] {
            assert!(s["reseal"]["values_sealed"].as_u64().unwrap() > 0, "{s}");
            break;
        }
        assert!(Instant::now() < deadline, "reseal did not finish: {s}");
        std::thread::sleep(Duration::from_millis(100));
    }
    d.wait_exported();
    let (code, report) = verify(&d, &data);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["complete"], true, "{report}");
}

/// A crash mid-append leaves a partial line; the next start truncates it,
/// so the next batch does not continue it (review M7).
#[test]
fn a_torn_line_is_truncated_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let d = Daemon::start(dir.path(), &data, "");
    let grant = json!({"kind": "counter", "capability": "http:example.com", "reason": "one"});
    assert_eq!(d.api("POST", "/v1/grants", &grant).0, 200);
    d.wait_exported();
    d.stop();
    let file = kronik_otel::sink::files(&dir.path().join("audit"))
        .unwrap()
        .pop()
        .unwrap();
    let torn = "{\"schema\":\"kronik.audit/v1\",\"lsn\":99,\"torn";
    std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap()
        .write_all(torn.as_bytes())
        .unwrap();

    let d = Daemon::start(dir.path(), &data, "");
    let grant = json!({"kind": "counter", "capability": "http:example.org", "reason": "two"});
    assert_eq!(d.api("POST", "/v1/grants", &grant).0, 200);
    d.wait_exported();
    let text = sink_text(dir.path());
    assert!(!text.contains("torn"), "{text}");
    let reasons: Vec<String> = sink_lines(dir.path())
        .into_iter()
        .map(|l| l.reason)
        .collect();
    assert!(reasons.contains(&"two".to_owned()), "{text}");
    let (code, report) = verify(&d, &data);
    assert_eq!(code, 0, "{report}");
}

/// A line that shares an exported line's LSN but not its record is a
/// conflict, and verify exits 1 naming it.
#[test]
fn an_injected_conflicting_line_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let d = Daemon::start(dir.path(), &data, "");
    let grant = json!({"kind": "counter", "capability": "http:example.com", "reason": "one"});
    assert_eq!(d.api("POST", "/v1/grants", &grant).0, 200);
    d.wait_exported();
    let (code, _) = verify(&d, &data);
    assert_eq!(code, 0);
    let mut forged = sink_lines(dir.path())
        .into_iter()
        .find(|l| l.action == "grant")
        .unwrap();
    forged.record_hash = format!("b3:{}", "0".repeat(64));
    let file = kronik_otel::sink::files(&dir.path().join("audit"))
        .unwrap()
        .pop()
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap()
        .write_all(format!("{}\n", forged.to_json()).as_bytes())
        .unwrap();
    let (code, report) = verify(&d, &data);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["complete"], false, "{report}");
    let conflicting = report["conflicting"].as_array().unwrap();
    assert_eq!(conflicting.len(), 1, "{report}");
    assert_eq!(conflicting[0]["lsn"], forged.lsn, "{report}");
    // The human report names it too.
    let out = command()
        .args(["audit", "verify", "--config"])
        .arg(&d.config)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("NOT complete"), "{stdout}");
    assert!(stdout.contains("Conflicting (1)"), "{stdout}");
}

/// A restore from an older ship point brings back fewer records than the
/// sink has seen; the next records reuse the lost tail's LSNs. The
/// `restore` line supersedes the old tail, the reused LSNs are told apart
/// by hash, and verify passes (review H4).
#[test]
fn a_restore_from_an_older_ship_point_then_new_mutations_verify() {
    let dir = tempfile::tempdir().unwrap();
    let bucket = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let ship = format!(
        "\n[ship]\nenabled = true\nurl = \"file://{}\"\n",
        bucket.path().display()
    );
    let d = Daemon::start(dir.path(), &data, &ship);
    let mut deploy = json!({"reason": "deploy"});
    deploy["wasm_base64"] = json!(b64(COUNTER));
    assert_eq!(d.api("POST", "/v1/deployments", &deploy).0, 200);
    let (status, v) = d.api("POST", "/v1/snapshots", &json!({"reason": "ship point"}));
    assert_eq!(status, 200, "{v}");
    let lsn = v["snapshot"]["lsn"].as_u64().unwrap();
    assert!(wait_until_shipped(&data, lsn), "the snapshot did not ship");
    // The ship point: a copy of the bucket now.
    let older = tempfile::tempdir().unwrap();
    copy_dir(bucket.path(), older.path());
    for host in ["example.com", "example.org", "example.net"] {
        let grant =
            json!({"kind": "counter", "capability": format!("http:{host}"), "reason": "lost tail"});
        assert_eq!(d.api("POST", "/v1/grants", &grant).0, 200);
    }
    d.wait_exported();
    let lost: Vec<Line> = sink_lines(dir.path())
        .into_iter()
        .filter(|l| l.reason == "lost tail")
        .collect();
    assert_eq!(lost.len(), 3);
    d.stop();

    let dest = dir.path().join("restored");
    // The master key is never in the bucket: it goes into place first.
    std::fs::create_dir_all(dest.join("keys")).unwrap();
    std::fs::copy(data.join("keys/master.key"), dest.join("keys/master.key")).unwrap();
    let out = command()
        .args(["--json", "restore", "--from"])
        .arg(format!("file://{}", older.path().display()))
        .arg("--data-dir")
        .arg(&dest)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    // The restored node exports to the same sink, without shipping.
    let d = Daemon::start(dir.path(), &dest, "");
    for host in ["example.com", "example.org", "example.net", "example.edu"] {
        let grant = json!({"kind": "counter", "capability": format!("http:{host}"), "reason": "after restore"});
        assert_eq!(d.api("POST", "/v1/grants", &grant).0, 200, "{}", d.log());
    }
    d.wait_exported();
    let lines = sink_lines(dir.path());
    let restore = lines.iter().find(|l| l.action == "restore").unwrap();
    let through: u64 = restore.details["through_lsn"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(lost.iter().all(|l| l.lsn > through), "{restore:?} {lost:?}");
    // A reused LSN, told apart by hash.
    let reused = lost.iter().any(|old| {
        lines.iter().any(|l| {
            l.lsn == old.lsn && l.reason == "after restore" && l.record_hash != old.record_hash
        })
    });
    assert!(reused, "{}", sink_text(dir.path()));
    let (code, report) = verify(&d, &dest);
    assert_eq!(code, 0, "{report}");
    assert!(report["superseded"].as_u64().unwrap() >= 3, "{report}");
}

/// Review H-A: `restore --force` over the exported directory itself, whose
/// export cursor is past the restored log. A first start with the audit
/// export off, then one with it on: the `restore` line and every mutation
/// after it are exported, and verify passes.
#[test]
fn a_forced_restore_is_exported_after_a_start_without_audit() {
    restore_over_the_exported_directory(false);
}

/// The same with a first start that stops once the `restore` event is
/// committed, before the cursors are clamped and the marker removed (as a
/// crash there would): the next start finishes the job and records the
/// event once.
#[test]
fn a_forced_restore_is_exported_after_a_start_that_stopped_after_its_event() {
    restore_over_the_exported_directory(true);
}

fn restore_over_the_exported_directory(stop_after_event: bool) {
    let dir = tempfile::tempdir().unwrap();
    let bucket = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let ship = format!(
        "\n[ship]\nenabled = true\nurl = \"file://{}\"\n",
        bucket.path().display()
    );
    let d = Daemon::start(dir.path(), &data, &ship);
    let mut deploy = json!({"reason": "deploy"});
    deploy["wasm_base64"] = json!(b64(COUNTER));
    assert_eq!(d.api("POST", "/v1/deployments", &deploy).0, 200);
    let (status, v) = d.api("POST", "/v1/snapshots", &json!({"reason": "ship point"}));
    assert_eq!(status, 200, "{v}");
    let lsn = v["snapshot"]["lsn"].as_u64().unwrap();
    assert!(wait_until_shipped(&data, lsn), "the snapshot did not ship");
    let older = tempfile::tempdir().unwrap();
    copy_dir(bucket.path(), older.path());
    for host in ["example.com", "example.org", "example.net"] {
        let grant =
            json!({"kind": "counter", "capability": format!("http:{host}"), "reason": "lost tail"});
        assert_eq!(d.api("POST", "/v1/grants", &grant).0, 200);
    }
    d.wait_exported();
    let config = d.config.clone();
    d.stop();
    let out = command()
        .args(["--json", "restore", "--force", "--from"])
        .arg(format!("file://{}", older.path().display()))
        .arg("--data-dir")
        .arg(&data)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    if stop_after_event {
        let out = command()
            .args(["serve", "--config"])
            .arg(&config)
            .arg("--test-stop-after-restore-event")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains("stopped after the restore event"),
            "{out:?}"
        );
    } else {
        let d = Daemon::start_with(dir.path(), &data, "", &[("KRONIK_AUDIT_SINK", "none")]);
        assert_eq!(d.audit_stream()["enabled"], false);
        d.settled();
        d.stop();
    }
    let d = Daemon::start(dir.path(), &data, "");
    for host in ["example.com", "example.org", "example.net", "example.edu"] {
        let grant = json!({"kind": "counter", "capability": format!("http:{host}"), "reason": "after restore"});
        assert_eq!(d.api("POST", "/v1/grants", &grant).0, 200, "{}", d.log());
    }
    d.wait_exported();
    let lines = distinct(sink_lines(dir.path()));
    let restores: Vec<&Line> = lines.iter().filter(|l| l.action == "restore").collect();
    assert_eq!(restores.len(), 1, "{}", sink_text(dir.path()));
    let after = lines.iter().filter(|l| l.reason == "after restore").count();
    assert_eq!(after, 4, "{}", sink_text(dir.path()));
    let (code, report) = verify(&d, &data);
    assert_eq!(code, 0, "{report}");
    assert!(report["superseded"].as_u64().unwrap() >= 3, "{report}");
}

/// The snapshot at `lsn`, the code and the active segment as it is now are
/// in the bucket (as `m6_cli.rs` waits).
fn wait_until_shipped(data: &Path, lsn: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(data.join("ship.json"))
            && let Ok(v) = serde_json::from_str::<Value>(&text)
            && v["snapshots"]
                .as_array()
                .is_some_and(|a| a.iter().any(|n| n.as_u64() == Some(lsn)))
            && v["code"].as_array().is_some_and(|a| !a.is_empty())
            && let Some(start) = v["active"][0].as_u64()
            && let Some(size) = v["active"][1].as_u64()
            && std::fs::metadata(data.join(format!("branches/main/log/{start:020}.seg")))
                .is_ok_and(|m| m.len() == size)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}
