//! The client commands against a real `kronik serve` in a temporary data
//! directory: every command in human and `--json` mode, and the error paths.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::free_port;
use serde_json::{Value, json};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const NOTES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/notes.wasm");
const FS_PROBE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/fs-probe.wasm"
);
const WEBHOOK_RELAY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/webhook-relay.wasm"
);
const STEP2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter-step2.wasm"
);

#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("{e}: {self:?}"))
    }

    /// The second word of the first line, e.g. the turn id in
    /// "Turn main:5 committed on counter/a".
    fn second_word(&self) -> String {
        self.stdout.split_whitespace().nth(1).unwrap().to_owned()
    }
}

/// Runs the CLI against `socket`, with a clean environment for the options
/// it reads.
fn kronik(socket: &Path, args: &[&str], http: Option<&str>) -> Out {
    kronik_with(socket, args, http, None)
}

/// Like [`kronik`], with `input` on stdin (else stdin is empty).
fn kronik_with(socket: &Path, args: &[&str], http: Option<&str>, input: Option<&[u8]>) -> Out {
    let mut cmd = Command::new(KRONIK);
    cmd.arg("--socket")
        .arg(socket)
        .args(args)
        .env_remove("KRONIK_API_SOCKET")
        .env_remove("KRONIK_HTTP_LISTEN")
        .env_remove("KRONIK_TOKEN")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(http) = http {
        cmd.env("KRONIK_HTTP_LISTEN", http);
    }
    let mut child = cmd.spawn().unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// The value after `Reply` in a turn's human output.
fn reply(o: &Out) -> String {
    o.stdout
        .lines()
        .find_map(|l| l.strip_prefix("  Reply"))
        .unwrap_or_else(|| panic!("no reply: {o:?}"))
        .trim()
        .to_owned()
}

/// A plain HTTP server on a free port that answers every request with 200
/// and the body `pong`, until the test process exits. Returns its address.
// A test harness thread, not daemon code (ADR 0004).
#[allow(clippy::disallowed_methods)]
fn http_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
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
    addr
}

/// Asserts the human form of an error: code and message, hint and docs on
/// stderr, exit code 1.
fn assert_error(o: &Out, code: &str) {
    assert_eq!(o.code, 1, "{o:?}");
    assert!(o.stderr.starts_with(&format!("error: {code}: ")), "{o:?}");
    assert!(o.stderr.contains("\nhint:  "), "{o:?}");
    assert!(
        o.stderr
            .ends_with(&format!("\ndocs:  kronik explain {code}\n")),
        "{o:?}"
    );
}

/// Asserts the `--json` form of an error: the error JSON on stdout, exit 1.
fn assert_json_error(o: &Out, code: &str) {
    assert_eq!(o.code, 1, "{o:?}");
    let v = o.json();
    assert_eq!(v["error"]["code"], code, "{o:?}");
    assert_eq!(
        v["error"]["docs"],
        format!("kronik explain {code}"),
        "{o:?}"
    );
    assert!(v["error"]["hint"].is_string(), "{o:?}");
}

/// `kronik serve` on a free port with its socket in a temporary directory;
/// killed when dropped.
struct Daemon {
    child: Child,
    socket: PathBuf,
    http: String,
    dir: tempfile::TempDir,
}

impl Daemon {
    fn start() -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let http = format!("127.0.0.1:{}", free_port());
        let log = std::fs::File::create(dir.path().join("serve.log")).unwrap();
        let child = Command::new(KRONIK)
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            .args(["--http-listen", &http, "--api-socket"])
            .arg(&socket)
            .env("KRONIK_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon {
            child,
            socket,
            http,
            dir,
        };
        for _ in 0..600 {
            if d.run(&["--json", "actors", "list"]).code == 0 {
                return d;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("kronik serve did not start:\n{}", d.log());
    }

    fn run(&self, args: &[&str]) -> Out {
        kronik(&self.socket, args, Some(&self.http))
    }

    fn run_with_input(&self, args: &[&str], input: &str) -> Out {
        kronik_with(&self.socket, args, Some(&self.http), Some(input.as_bytes()))
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("serve.log")).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn explain_needs_no_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let none = dir.path().join("none.sock");

    let o = kronik(&none, &["explain", "actor_not_found"], None);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(
        o.stdout
            .starts_with("ACTOR_NOT_FOUND (HTTP 404): No such actor or actor type\n\n"),
        "{o:?}"
    );
    let o = kronik(&none, &["explain", "Fork"], None);
    assert!(o.stdout.starts_with("fork: "), "{o:?}");
    let v = kronik(&none, &["--json", "explain", "fork"], None).json();
    assert_eq!(
        (&v["name"], &v["kind"]),
        (&json!("fork"), &json!("concept"))
    );

    let o = kronik(&none, &["explain", "--list"], None);
    assert_eq!(o.code, 0, "{o:?}");
    for want in [
        "Concepts\n",
        "\nError codes\n",
        "  turn-id ",
        "  TURN_FAILED ",
        "Next     kronik explain <topic>\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let v = kronik(&none, &["explain", "--list", "--json"], None).json();
    let topics = v["topics"].as_array().unwrap();
    assert!(topics.iter().any(|t| t["name"] == "STORAGE_CORRUPT"));
    assert!(topics.iter().any(|t| t["name"] == "causal-key"));

    let o = kronik(&none, &["explain", "no-such-topic"], None);
    assert_error(&o, "BAD_REQUEST");
    assert!(o.stderr.contains("kronik explain --list"), "{o:?}");
    assert_json_error(
        &kronik(&none, &["--json", "explain", "no-such-topic"], None),
        "BAD_REQUEST",
    );
    // A topic or --list is required.
    assert_eq!(kronik(&none, &["explain"], None).code, 2);
}

#[test]
fn without_a_daemon_the_cli_says_how_to_start_one() {
    let dir = tempfile::tempdir().unwrap();
    let none = dir.path().join("none.sock");
    let shown = none.display().to_string();

    let o = kronik(&none, &["actors", "list"], None);
    assert_error(&o, "UNAVAILABLE");
    assert!(o.stderr.contains(&shown), "{o:?}");
    assert!(
        o.stderr
            .contains(&format!("`kronik serve --api-socket {shown}`")),
        "{o:?}"
    );
    let o = kronik(&none, &["--json", "history", "counter/a"], None);
    assert_json_error(&o, "UNAVAILABLE");
    assert!(o.stderr.is_empty(), "{o:?}");

    // Mutations without a reason and malformed arguments fail before
    // anything is sent, so they fail the same way without a daemon.
    for args in [
        &["deploy", COUNTER][..],
        &["send", "counter/a", "increment", "--reason", "  "],
        &["dead-letters", "resend", "main:1", "--dry-run"],
    ] {
        assert_error(&kronik(&none, args, None), "REASON_REQUIRED");
    }
    assert_json_error(
        &kronik(&none, &["--json", "deploy", COUNTER], None),
        "REASON_REQUIRED",
    );
    assert_error(
        &kronik(&none, &["history", "Counter/a"], None),
        "BAD_REQUEST",
    );
    let o = kronik(
        &none,
        &["deploy", "/no/such/file.wasm", "--reason", "r"],
        None,
    );
    assert_error(&o, "BAD_REQUEST");
    assert!(o.stderr.contains("/no/such/file.wasm"), "{o:?}");
}

#[test]
fn serve_rejects_client_options() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(KRONIK)
        .args(["serve", "--json", "--data-dir"])
        .arg(dir.path())
        .args(["--http-listen", "127.0.0.1:0", "--api-socket"])
        .arg(dir.path().join("api.sock"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(2));
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("kronik serve --json kept running");
}

/// `kronik --json init` and `build` print one JSON object on stdout, and
/// the error JSON on failure (docs/reference/json.md).
#[test]
fn init_and_build_print_json() {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(KRONIK)
            .args(args)
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let o = run(&["--json", "init", "--lang", "rust", "json-demo"]);
    assert!(o.status.success(), "{o:?}");
    let created: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(created["project"], "json-demo");
    assert_eq!(created["kind"], "json-demo");
    assert_eq!(created["lang"], "rust");
    assert!(
        created["files"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("src/lib.rs")),
        "{created}"
    );
    assert_eq!(created["next"][0], "cd json-demo");
    assert!(dir.path().join("json-demo/Cargo.toml").is_file());

    let again = run(&["--json", "init", "json-demo"]);
    assert_eq!(again.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(error["error"]["code"], "BAD_REQUEST", "{error}");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("already exists"),
        "{error}"
    );

    std::fs::create_dir(dir.path().join("empty")).unwrap();
    let build = run(&["--json", "build", "--dir", "empty"]);
    assert_eq!(build.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&build.stdout).unwrap();
    assert_eq!(error["error"]["code"], "BAD_REQUEST", "{error}");
    assert!(
        error["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("kronik init"),
        "{error}"
    );
}

/// `kronik build` of a TypeScript project checks Node.js before it runs the
/// toolchain: a missing or old `node` is a clear error, not one from jco.
#[test]
fn build_checks_node_before_the_typescript_toolchain() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("billing");
    for (file, text) in [
        ("package.json", r#"{"name": "billing"}"#),
        ("src/actor.ts", "export default {};\n"),
        ("node_modules/.bin/jco", ""),
        ("node_modules/@kronik/sdk/package.json", "{}"),
        (
            "node_modules/@bytecodealliance/jco/package.json",
            r#"{"version": "1.39.0"}"#,
        ),
        (
            "node_modules/@bytecodealliance/componentize-js/package.json",
            r#"{"version": "0.23.0"}"#,
        ),
        (
            "node_modules/typescript/package.json",
            r#"{"version": "7.0.2"}"#,
        ),
    ] {
        let path = project.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    // PATH has a `node` that answers like Ubuntu 24.04's, then none at all.
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let build = |path: &Path| {
        let o = Command::new(KRONIK)
            .args(["--json", "build", "--dir"])
            .arg(&project)
            .env("PATH", path)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(1), "{o:?}");
        let error: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(error["error"]["code"], "BAD_REQUEST", "{error}");
        assert!(
            error["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("install Node.js 22.20 or later"),
            "{error}"
        );
        error["error"]["message"].as_str().unwrap().to_owned()
    };
    let node = bin.join("node");
    std::fs::write(&node, "#!/bin/sh\necho v18.19.1\n").unwrap();
    std::fs::set_permissions(&node, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    assert_eq!(
        build(&bin),
        "Node.js v18.19.1 is too old for the TypeScript toolchain, which needs 22.20 or later"
    );
    std::fs::remove_file(&node).unwrap();
    assert!(
        build(&bin).starts_with("Node.js is not installed: "),
        "no node on PATH"
    );
}

#[test]
fn every_command_against_a_daemon() {
    let d = Daemon::start();

    // An empty system.
    let o = d.run(&["actors", "list"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(o.stdout.starts_with("No actors yet"), "{o:?}");
    assert_eq!(
        d.run(&["dead-letters", "list"]).stdout,
        "No dead letters.\n"
    );

    // deploy: a dry run writes nothing.
    let o = d.run(&["deploy", COUNTER, "--reason", "first deploy", "--dry-run"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(o.stdout.starts_with("Dry run: counter b3:"), "{o:?}");
    assert!(o.stdout.contains("nothing was written"), "{o:?}");
    assert!(
        o.stdout.contains(&format!(
            "Next     kronik deploy {COUNTER} --reason 'first deploy'\n"
        )),
        "{o:?}"
    );
    let v = d
        .run(&["--json", "deploy", COUNTER, "--reason", "r", "--dry-run"])
        .json();
    assert_eq!(
        (&v["dry_run"], &v["deployment"]["lsn"]),
        (&json!(true), &json!(0))
    );
    assert_error(
        &d.run(&["send", "counter/a", "increment", "--reason", "r"]),
        "ACTOR_NOT_FOUND",
    );

    // deploy for real, then the same code again, then a second kind.
    let o = d.run(&["deploy", COUNTER, "--reason", "first deploy"]);
    assert_eq!(o.code, 0, "{o:?}\n{}", d.log());
    assert!(o.stdout.starts_with("Deployed counter b3:"), "{o:?}");
    for want in [
        "  Routes        POST /counter/{key}/{op}\n",
        "                GET /counter/{key}\n",
        "  Capabilities  none\n",
        &format!(
            "Next     curl -X POST 'http://{}/counter/<key>/<op>'\n",
            d.http
        ),
        "         kronik send counter/<key> <name> --reason \"...\"\n",
        "         kronik history counter/<key>\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let o = d.run(&["deploy", COUNTER, "--reason", "again"]);
    assert!(o.stdout.starts_with("counter already runs b3:"), "{o:?}");
    let v = d
        .run(&["--json", "deploy", NOTES, "--reason", "notes"])
        .json();
    assert_eq!(v["deployment"]["kind"], "notes");
    assert!(v["deployment"]["lsn"].as_u64().unwrap() > 0, "{v}");
    let o = d.run(&["deploy", FS_PROBE, "--reason", "file system"]);
    assert_error(&o, "IMPORT_NOT_ALLOWED");
    assert!(o.stderr.contains("wasi:filesystem"), "{o:?}");

    // send: replies, a text and a file body, a dry run.
    let o = d.run(&["send", "counter/a", "increment", "--reason", "test"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(o.stdout.starts_with("Turn main:"), "{o:?}");
    for want in [
        " committed on counter/a\n",
        "  Reply         1\n",
        "Next     kronik history counter/a\n",
        "         kronik actors inspect counter/a\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let o = d.run(&[
        "--json",
        "send",
        "counter/a",
        "increment",
        "--reason",
        "test",
    ]);
    assert_eq!(o.code, 0, "{o:?}");
    let v = o.json();
    assert_eq!(
        (&v["outcome"]["kind"], &v["reply"]["text"]),
        (&json!("committed"), &json!("2"))
    );
    let note = d.dir.path().join("note.txt");
    std::fs::write(&note, "from a file").unwrap();
    for body in [["--text", "hello"], ["--file", note.to_str().unwrap()]] {
        let mut args = vec!["send", "notes/n", "add"];
        args.extend(body);
        args.extend(["--reason", "test"]);
        let o = d.run(&args);
        assert_eq!(o.code, 0, "{o:?}");
        assert!(o.stdout.contains(" committed on notes/n\n"), "{o:?}");
    }
    let o = d.run(&[
        "send",
        "counter/a",
        "increment",
        "--reason",
        "test",
        "--dry-run",
    ]);
    assert_eq!(o.code, 0, "{o:?}");
    assert_eq!(
        o.stdout,
        "Dry run: the message is valid; nothing was sent\n\
         Next     kronik send counter/a increment --reason test\n"
    );

    // A failing message is a failed turn and a dead letter.
    let o = d.run(&["send", "counter/a", "fail", "--reason", "test"]);
    assert_eq!(o.code, 1, "{o:?}");
    let failed = o.second_word();
    for want in [
        " failed on counter/a\n",
        "  Error         TURN_FAILED: deliberate failure\n",
        &format!("Next     kronik dead-letters resend {failed} --reason \"...\"\n"),
        "         kronik explain TURN_FAILED\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let o = d.run(&["--json", "send", "counter/a", "reject", "--reason", "test"]);
    assert_eq!(o.code, 1, "{o:?}");
    assert_eq!(o.json()["outcome"]["kind"], "rejected");

    // actors list and inspect.
    let o = d.run(&["actors", "list"]);
    assert_eq!(o.code, 0, "{o:?}");
    let lines: Vec<&str> = o.stdout.lines().collect();
    assert!(lines[0].starts_with("ACTOR "), "{o:?}");
    assert!(
        lines[1].starts_with("counter/a ") && lines[1].ends_with("no"),
        "{o:?}"
    );
    assert!(
        lines[2].starts_with("notes/n ") && lines[2].ends_with("yes"),
        "{o:?}"
    );
    assert_eq!(lines[3], "Next     kronik actors inspect counter/a");
    let v = d.run(&["--json", "actors", "list"]).json();
    let names: Vec<String> = v["actors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            format!(
                "{}/{}",
                a["kind"].as_str().unwrap(),
                a["key"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(names, ["counter/a", "notes/n"]);
    let o = d.run(&["actors", "list", "--kind", "notes"]);
    assert!(
        o.stdout.contains("notes/n") && !o.stdout.contains("counter/a"),
        "{o:?}"
    );
    let o = d.run(&["actors", "list", "--limit", "1"]);
    assert!(
        o.stdout
            .contains("         kronik actors list --limit 1 --after counter/a\n"),
        "{o:?}"
    );
    let o = d.run(&["actors", "inspect", "counter/a"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(
        o.stdout.starts_with("Actor    counter/a (schema 0, "),
        "{o:?}"
    );
    assert!(o.stdout.contains("\nState    n = 2  (lsn "), "{o:?}");
    assert!(
        o.stdout.ends_with(
            "Next     kronik history counter/a\n         kronik actors timers counter/a\n"
        ),
        "{o:?}"
    );
    let o = d.run(&["actors", "inspect", "notes/n"]);
    assert!(o.stdout.contains("\nSQL      notes: 2 rows\n"), "{o:?}");
    let v = d.run(&["--json", "actors", "inspect", "counter/a"]).json();
    assert_eq!(
        (&v["state"][0]["key"], &v["state"][0]["text"]),
        (&json!("n"), &json!("2"))
    );

    // history, with paging.
    let o = d.run(&["history", "counter/a"]);
    assert_eq!(o.code, 0, "{o:?}");
    let code = d.run(&["--json", "history", "counter/a"]).json()["turns"][0]["code_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    for want in [
        "TURN ",
        "CHANGES  CODE\n",
        format!("  {code}\n").as_str(),
        "increment from operator",
        "fail from operator",
        "committed",
        "set n",
        "failed (TURN_FAILED: deliberate failure)",
        "Next     kronik dead-letters list\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let o = d.run(&["history", "counter/a", "--limit", "1"]);
    let lines: Vec<&str> = o.stdout.lines().collect();
    assert_eq!(lines.len(), 4, "{o:?}");
    let before = lines[2]
        .strip_prefix("Next     kronik history counter/a --before ")
        .and_then(|rest| rest.strip_suffix(" --limit 1"))
        .unwrap_or_else(|| panic!("{o:?}"));
    let o2 = d.run(&["history", "counter/a", "--limit", "1", "--before", before]);
    assert_eq!(o2.code, 0, "{o2:?}");
    assert_ne!(o2.stdout.lines().nth(1), o.stdout.lines().nth(1));
    let v = d.run(&["--json", "history", "notes/n"]).json();
    let types: Vec<&str> = v["turns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["input"]["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["message", "message", "migrate"]);

    // dead-letters list and resend.
    let o = d.run(&["dead-letters", "list"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(o.stdout.contains(&failed), "{o:?}");
    assert!(
        o.stdout.contains(&format!(
            "Next     kronik dead-letters resend {failed} --reason \"...\"\n"
        )),
        "{o:?}"
    );
    let v = d.run(&["--json", "dead-letters", "list"]).json();
    assert_eq!(
        (
            &v["dead_letters"][0]["id"],
            &v["dead_letters"][0]["resent_as"]
        ),
        (&json!(failed), &Value::Null)
    );
    let o = d.run(&[
        "dead-letters",
        "resend",
        &failed,
        "--reason",
        "retry",
        "--dry-run",
    ]);
    assert_eq!(
        o.stdout,
        format!(
            "Dry run: the dead letter can be resent; nothing was sent\n\
             Next     kronik dead-letters resend {failed} --reason retry\n"
        )
    );
    // The input runs again as a new turn; `fail` fails every time.
    let o = d.run(&["dead-letters", "resend", &failed, "--reason", "retry"]);
    assert_eq!(o.code, 1, "{o:?}");
    assert!(
        o.stdout
            .starts_with(&format!("Resent {failed} as turn main:")),
        "{o:?}"
    );
    let again = o
        .stdout
        .split_whitespace()
        .nth(4)
        .unwrap()
        .trim_end_matches(',')
        .to_owned();
    let v = d.run(&["--json", "dead-letters", "list"]).json();
    assert_eq!(v["dead_letters"][0]["resent_as"], json!(again), "{v}");
    let o = d.run(&["history", "counter/a"]);
    assert!(
        o.stdout.contains(&format!("fail from resend of {failed}")),
        "{o:?}"
    );
    let o = d.run(&["dead-letters", "resend", &failed, "--reason", "retry"]);
    assert_error(&o, "DEAD_LETTER_ALREADY_RESENT");
    assert_json_error(
        &d.run(&[
            "--json",
            "dead-letters",
            "resend",
            &failed,
            "--reason",
            "retry",
        ]),
        "DEAD_LETTER_ALREADY_RESENT",
    );
    assert_error(
        &d.run(&["dead-letters", "resend", "main:999999", "--reason", "retry"]),
        "DEAD_LETTER_NOT_FOUND",
    );

    // Errors from the daemon: human and --json.
    let o = d.run(&["actors", "inspect", "counter/zzz"]);
    assert_error(&o, "ACTOR_NOT_FOUND");
    assert!(
        o.stderr
            .contains("\nhint:  Check the kind and key with `kronik actors list`.\n"),
        "{o:?}"
    );
    let o = d.run(&["--json", "actors", "inspect", "counter/zzz"]);
    assert_json_error(&o, "ACTOR_NOT_FOUND");
    assert!(o.stderr.is_empty(), "{o:?}");
    assert_error(&d.run(&["history", "nobody/x"]), "ACTOR_NOT_FOUND");
    let o = d.run(&[
        "send",
        "counter/a",
        "increment",
        "--file",
        "/no/such/body",
        "--reason",
        "r",
    ]);
    assert_error(&o, "BAD_REQUEST");
    let o = d.run(&[
        "send",
        "counter/a",
        "increment",
        "--text",
        "x",
        "--file",
        "y",
        "--reason",
        "r",
    ]);
    assert_eq!(o.code, 2, "{o:?}");
}

#[test]
fn m3_commands_against_a_daemon() {
    let d = Daemon::start();
    assert_eq!(
        d.run(&["deploy", COUNTER, "--reason", "first deploy"]).code,
        0
    );
    for _ in 0..3 {
        let o = d.run(&["send", "counter/a", "increment", "--reason", "traffic"]);
        assert_eq!(o.code, 0, "{o:?}");
    }

    // A plain fork: create it, deploy new code in it, replay, diff.
    assert!(d.run(&["fork", "list"]).stdout.starts_with("No forks.\n"));
    let create = [
        "fork",
        "create",
        "--at",
        "1",
        "--name",
        "try",
        "--reason",
        "try step 2",
    ];
    let o = d.run(&[&create[..], &["--dry-run"]].concat());
    assert!(
        o.stdout
            .starts_with("Dry run: main can be forked at lsn 1 as try; nothing was written\n"),
        "{o:?}"
    );
    let o = d.run(&create);
    assert!(
        o.stdout.starts_with("Forked main at lsn 1 -> fork try\n"),
        "{o:?}"
    );
    let o = d.run(&["fork", "deploy", "try", STEP2, "--reason", "step 2"]);
    assert!(
        o.stdout.starts_with("Deployed counter b3:") && o.stdout.contains(" in fork try\n"),
        "{o:?}"
    );
    // A message into the fork runs under the fork's code, from its state at
    // the fork point; it has no dry run.
    let o = d.run(&[
        "send",
        "counter/a",
        "increment",
        "--fork",
        "try",
        "--reason",
        "try it",
    ]);
    assert!(
        o.stdout.starts_with("Turn try:")
            && o.stdout.contains(" committed on counter/a in fork try\n"),
        "{o:?}"
    );
    assert_eq!(reply(&o), "2", "step 2 from the fork point: {o:?}");
    let o = d.run(&[
        "send",
        "counter/a",
        "increment",
        "--fork",
        "try",
        "--dry-run",
        "--reason",
        "x",
    ]);
    assert_eq!(o.code, 2, "{o:?}");
    assert_error(&d.run(&["replay", "try"]), "REASON_REQUIRED");
    let o = d.run(&[
        "replay",
        "try",
        "--threads",
        "2",
        "--reason",
        "see the diff",
    ]);
    for want in [
        "Replayed 3 of 3 root inputs in fork try (isolated and continuous), verified through lsn ",
        "\n  Causes        3 origins, 0 consequences\n",
        "\n  Responses     no HTTP root inputs\n",
        "\n  State         1 actor changed\n",
        "Next     kronik diff show try --md\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let o = d.run(&["diff", "show", "try"]);
    assert!(
        o.stdout.starts_with("Diff of fork try: main lsn ")
            && o.stdout.contains("\n  counter   b3:"),
        "{o:?}"
    );
    let o = d.run(&["diff", "show", "try", "--md"]);
    assert!(o.stdout.starts_with("# Behavior diff: try\n"), "{o:?}");
    let v = d.run(&["--json", "diff", "show", "try"]).json();
    assert_eq!(v["schema"], "kronik.diff/v1");
    assert_json_error(
        &d.run(&["--json", "diff", "show", "try", "--md"]),
        "BAD_REQUEST",
    );
    assert_error(&d.run(&["diff", "show", "nope"]), "FORK_NOT_FOUND");
    let o = d.run(&["fork", "list"]);
    let lines: Vec<&str> = o.stdout.lines().collect();
    assert!(lines[0].starts_with("Main is at lsn "), "{o:?}");
    let words: Vec<&str> = lines[2].split_whitespace().collect();
    assert_eq!((words[0], words[1], words[3]), ("try", "1", "-"), "{o:?}");

    // Policy: the defaults, a test with other rules, then those rules.
    let o = d.run(&["policy", "show"]);
    assert!(
        o.stdout
            .starts_with("The default policy rules (no policy has been set):\n\n[[rule]]\n"),
        "{o:?}"
    );
    assert!(
        d.run(&["policy", "test", "try"])
            .stdout
            .contains("\nPolicy   ALLOW\n")
    );
    let strict = d.dir.path().join("strict.toml");
    std::fs::write(
        &strict,
        "[[rule]]\nname = \"any-change\"\nwhen = \"diff.summary.changed\"\naction = \"require_approval\"\n",
    )
    .unwrap();
    let strict = strict.to_str().unwrap();
    let o = d.run(&["policy", "test", "try", "--rules", strict]);
    assert!(
        o.stdout
            .contains("\nPolicy   any-change -> APPROVAL REQUIRED\n"),
        "{o:?}"
    );
    let o = d.run(&["policy", "set", strict, "--reason", "review every change"]);
    assert!(o.stdout.starts_with("Set the policy at lsn "), "{o:?}");
    assert_eq!(
        d.run(&["--json", "policy", "show"]).json()["default"],
        false
    );

    // Propose under those rules: approve, promote, roll back.
    let o = d.run(&["propose", STEP2, "--threads", "2", "--reason", "step by 2"]);
    assert_eq!(o.code, 0, "{o:?}");
    for want in [
        "\nProposal p-",
        "   counter   b3:",
        "   (evaluated)\n",
        "\nPolicy   any-change -> APPROVAL REQUIRED\n",
        "\n         kronik approve p-",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    assert!(o.stdout.starts_with("Forked main at lsn "), "{o:?}");
    let v = d.run(&["--json", "proposals", "list"]).json();
    let id = v["proposals"][0]["id"].as_str().unwrap().to_owned();
    let o = d.run(&["proposals", "show", &id]);
    assert!(
        o.stdout
            .starts_with(&format!("Proposal {id}   counter   b3:")),
        "{o:?}"
    );
    assert_error(
        &d.run(&["promote", &id, "--reason", "ship it"]),
        "APPROVAL_REQUIRED",
    );
    let o = d.run(&["approve", &id, "--reason", "reviewed the diff"]);
    assert!(
        o.stdout
            .starts_with(&format!("Approved proposal {id} at lsn ")),
        "{o:?}"
    );
    let o = d.run(&["promote", &id, "--reason", "ship it"]);
    let first = o.stdout.lines().next().unwrap_or_default();
    assert!(
        first.starts_with(&format!("Promoted proposal {id} at lsn ")),
        "{o:?}"
    );
    let epoch = first.rsplit(' ').next().unwrap().to_owned();
    let increment =
        |reason: &str| reply(&d.run(&["send", "counter/a", "increment", "--reason", reason]));
    assert_eq!(increment("new code"), "5", "step 2 after 3");
    let o = d.run(&["deployments", "list"]);
    assert!(
        o.stdout.contains("  promote  counter b3:")
            && o.stdout.ends_with(&format!(
                "Next     kronik rollback {epoch} --reason \"...\"\n"
            )),
        "{o:?}"
    );
    let o = d.run(&["rollback", &epoch, "--reason", "back to step 1"]);
    assert!(
        o.stdout
            .starts_with(&format!("Rolled back epoch {epoch} at lsn ")),
        "{o:?}"
    );
    assert_eq!(increment("old code"), "6");
    assert_error(
        &d.run(&["rollback", "99", "--reason", "x"]),
        "DEPLOYMENT_NOT_FOUND",
    );
    assert_error(
        &d.run(&["proposals", "show", "p-000000000000"]),
        "PROPOSAL_NOT_FOUND",
    );
    // A fork without personal data is recorded as one; privacy mode (M8)
    // gives the flag its effect.
    let o = d.run(&[
        "--json", "fork", "create", "--at", "now", "--no-pii", "--reason", "x",
    ]);
    assert_eq!(o.code, 0, "{o:?}");
    let forked: serde_json::Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(forked["fork"]["no_pii"], true, "{o:?}");

    // A causal tree, from either end.
    let o = d.run(&[
        "send",
        "counter/t",
        "fanout",
        "--text",
        "2",
        "--reason",
        "fan out",
    ]);
    let root = o.second_word();
    // `send` answers when the root turn commits; its children (counter/f0,
    // counter/f1) commit after it. Wait for them before tracing.
    for child in ["counter/f0", "counter/f1"] {
        // At most about 30 s (600 polls of 50 ms).
        for attempt in 0.. {
            let v = d.run(&["--json", "history", child]).json();
            let committed = v["turns"]
                .as_array()
                .is_some_and(|t| t.iter().any(|t| t["outcome"]["kind"] == "committed"));
            if committed {
                break;
            }
            assert!(attempt < 600, "{child} never committed: {v}");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    let o = d.run(&["trace", &root]);
    for want in [
        &format!("Trace of {root} on counter/t\n"),
        "\nRoot     message fanout from operator at lsn ",
        &format!("\n{root}  counter/t  message fanout from operator  committed   <- this turn\n"),
        "\n├─ main:",
        "\n└─ main:",
        "  message note from counter/t  committed\n",
        "Next     kronik history counter/t\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let v = d.run(&["--json", "history", "counter/f0"]).json();
    let child = v["turns"][0]["turn_id"].as_str().unwrap().to_owned();
    let o = d.run(&["trace", &child]);
    assert!(
        o.stdout.contains(&format!(
            "\n{root}  message fanout from operator  committed\n└─ {child}  counter/f0  "
        )) && o.stdout.contains("   <- this turn\n"),
        "{o:?}"
    );
    assert_error(&d.run(&["trace", "main:9999"]), "TURN_NOT_FOUND");

    // Deleting the plain fork, and the argument rules.
    let o = d.run(&["fork", "delete", "try", "--reason", "done"]);
    assert!(o.stdout.starts_with("Deleted fork try\n"), "{o:?}");
    assert_error(
        &d.run(&["fork", "delete", "try", "--reason", "again"]),
        "FORK_NOT_FOUND",
    );
    for args in [
        &["propose", "--reason", "x"][..],
        &[
            "propose", STEP2, "--window", "1h", "--at", "3", "--reason", "x",
        ],
        &["replay", "try", "--sample", "150%", "--reason", "x"],
    ] {
        assert_eq!(d.run(args).code, 2, "{args:?}");
    }
}

/// M9: a directory proposes every component in it as one system proposal;
/// a component main already runs is skipped.
#[test]
fn propose_takes_a_directory_of_components() {
    let d = Daemon::start();
    for wasm in [COUNTER, NOTES, WEBHOOK_RELAY] {
        assert_eq!(d.run(&["deploy", wasm, "--reason", "first deploy"]).code, 0);
    }
    for _ in 0..2 {
        let o = d.run(&["send", "counter/a", "increment", "--reason", "traffic"]);
        assert_eq!(o.code, 0, "{o:?}");
    }
    let dist = d.dir.path().join("dist");
    std::fs::create_dir(&dist).unwrap();
    for (name, from) in [
        ("counter.wasm", "counter-calls-tally"),
        ("notes.wasm", "notes-tally"),
        ("webhook-relay.wasm", "webhook-relay"),
    ] {
        std::fs::copy(format!("{}/{from}.wasm", guests()), dist.join(name)).unwrap();
    }
    std::fs::write(dist.join("README.txt"), "not a component").unwrap();
    let dist = dist.to_str().unwrap();

    let o = d.run(&["propose", dist, "--dry-run", "--reason", "tally"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(o.stdout.contains("\nSkipped webhook-relay   b3:"), "{o:?}");
    assert!(
        o.stdout
            .contains(&format!("\nNext     kronik propose {dist} ")),
        "{o:?}"
    );
    let o = d.run(&["propose", dist, "--reason", "tally"]);
    assert_eq!(o.code, 0, "{o:?}");
    for want in [
        "   counter   b3:",
        "\n                          notes   b3:",
        "\nSkipped webhook-relay   b3:",
        "\n  Kinds         counter (changed code): ",
        "\n                notes (changed code): ",
        ", 0 errors introduced\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let v = d.run(&["--json", "proposals", "list"]).json();
    let p = &v["proposals"][0];
    assert_eq!(p["kinds"].as_array().unwrap().len(), 2, "{p}");
    assert_eq!(p["unchanged"][0]["kind"], "webhook-relay", "{p}");
    let diff = d
        .run(&["--json", "diff", "show", p["id"].as_str().unwrap()])
        .json();
    assert_eq!(diff["kinds"].as_array().unwrap().len(), 3, "{diff}");

    // Nothing changed: refused. An empty directory: refused before sending.
    assert_error(
        &d.run(&["propose", COUNTER, NOTES, "--reason", "same"]),
        "BAD_REQUEST",
    );
    let empty = d.dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    assert_error(
        &d.run(&["propose", empty.to_str().unwrap(), "--reason", "x"]),
        "BAD_REQUEST",
    );
}

#[test]
fn deploy_names_the_grants_a_component_asks_for() {
    let d = Daemon::start();
    let o = d.run(&["deploy", WEBHOOK_RELAY, "--reason", "relay webhooks"]);
    assert_eq!(o.code, 0, "{o:?}");
    for want in [
        "  Capabilities  http:webhooks.example.com\n                secret:relay-signing-key\n",
        "  Warnings      capability http:webhooks.example.com is not granted\n\
         \x20               capability secret:relay-signing-key is not granted\n",
        "Next     kronik grant webhook-relay http:webhooks.example.com --reason '...'\n\
         \x20        kronik grant webhook-relay secret:relay-signing-key --reason '...'\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    // Once one is granted, deploying again warns about the other only.
    let o = d.run(&[
        "grant",
        "webhook-relay",
        "http:webhooks.example.com",
        "--reason",
        "the relay target",
    ]);
    assert_eq!(o.code, 0, "{o:?}");
    let o = d.run(&["deploy", WEBHOOK_RELAY, "--reason", "again"]);
    assert!(
        o.stdout.starts_with("webhook-relay already runs b3:"),
        "{o:?}"
    );
    assert!(
        o.stdout
            .contains("  Warnings      capability secret:relay-signing-key is not granted\n")
            && !o
                .stdout
                .contains("http:webhooks.example.com is not granted"),
        "{o:?}"
    );
    assert!(
        o.stdout.contains(
            "Next     kronik grant webhook-relay secret:relay-signing-key --reason '...'\n"
        ),
        "{o:?}"
    );
}

#[test]
fn m2_commands_against_a_daemon() {
    let d = Daemon::start();
    let target = http_target();
    assert_eq!(
        d.run(&["deploy", COUNTER, "--reason", "first deploy"]).code,
        0
    );

    // Without a grant the guest gets denied; history shows the effect and
    // the exact command that grants it.
    let fetch = format!("GET http://{target}/ping");
    let o = d.run(&[
        "send",
        "counter/a",
        "fetch-ok",
        "--text",
        &fetch,
        "--reason",
        "fetch",
    ]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(
        reply(&o).contains("CAPABILITY_NOT_GRANTED: http:127.0.0.1"),
        "{o:?}"
    );
    let o = d.run(&["history", "counter/a"]);
    for want in [
        "committed  1 effect  b3:",
        "http.fetch  http:127.0.0.1  -         denied  CAPABILITY_NOT_GRANTED: http:127.0.0.1\n",
        "Next     kronik grant counter http:127.0.0.1 --reason '...'\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let v = d.run(&["--json", "history", "counter/a"]).json();
    assert_eq!(v["turns"][0]["effects"][0]["status"], "denied");

    // grant: the reason and the delivery class are checked locally.
    assert_error(
        &d.run(&["grant", "counter", "http:127.0.0.1"]),
        "REASON_REQUIRED",
    );
    let o = d.run(&[
        "grant",
        "counter",
        "http:127.0.0.1",
        "--delivery",
        "maybe",
        "--reason",
        "x",
    ]);
    assert_eq!(o.code, 2, "{o:?}");
    let grant = [
        "grant",
        "counter",
        "http:127.0.0.1",
        "--delivery",
        "idempotency-keyed",
        "--rate",
        "5/s",
        "--reason",
        "the test target",
    ];
    let o = d.run(&[&grant[..], &["--dry-run"]].concat());
    assert!(
        o.stdout
            .starts_with("Dry run: counter can be granted http:127.0.0.1 at epoch "),
        "{o:?}"
    );
    let v = d.run(&["--json", "grants", "list"]).json();
    assert_eq!(v["grants"], json!([]), "a dry run writes nothing");
    let o = d.run(&grant);
    assert!(
        o.stdout
            .starts_with("Granted http:127.0.0.1 to counter at lsn "),
        "{o:?}"
    );
    for want in [
        "  Delivery      idempotency-keyed\n",
        "  Rate          5/s\n",
        "Next     kronik grants list --kind counter\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let o = d.run(&["grants", "list"]);
    assert!(
        o.stdout
            .contains("\ncounter  http:127.0.0.1  idempotency-keyed  5/s   "),
        "{o:?}"
    );
    let v = d
        .run(&["--json", "grants", "list", "--kind", "counter"])
        .json();
    let g = &v["grants"][0];
    assert_eq!(
        (&g["capability"], &g["delivery"], &g["rate"]),
        (
            &json!("http:127.0.0.1"),
            &json!("idempotency-keyed"),
            &json!("5/s")
        )
    );
    assert_error(
        &d.run(&["grant", "counter", "ftp:x", "--reason", "x"]),
        "BAD_REQUEST",
    );

    // With the grant the request reaches the target.
    let o = d.run(&[
        "send",
        "counter/a",
        "fetch-ok",
        "--text",
        &fetch,
        "--reason",
        "fetch again",
    ]);
    assert_eq!(reply(&o), "200 pong", "{o:?}");
    let o = d.run(&["history", "counter/a", "--limit", "1"]);
    assert!(
        o.stdout.contains(&format!(
            "http.fetch  GET {target}/ping  idempotency-keyed  ok      -\n"
        )),
        "{o:?}"
    );
    let v = d
        .run(&["--json", "history", "counter/a", "--limit", "1"])
        .json();
    assert_eq!(
        v["turns"][0]["effects"][0]["request"],
        format!("GET {target}/ping"),
        "{v}"
    );

    // revoke
    let o = d.run(&["revoke", "counter", "http:127.0.0.1", "--reason", "done"]);
    assert!(
        o.stdout
            .starts_with("Revoked http:127.0.0.1 from counter at lsn "),
        "{o:?}"
    );
    let again = ["revoke", "counter", "http:127.0.0.1", "--reason", "again"];
    assert_error(&d.run(&again), "CAPABILITY_NOT_GRANTED");
    assert_json_error(
        &d.run(&[&["--json"][..], &again].concat()),
        "CAPABILITY_NOT_GRANTED",
    );
    assert!(
        d.run(&["grants", "list"])
            .stdout
            .starts_with("No grants: every external effect is denied.\n")
    );

    // limits, in human units.
    let o = d.run(&[
        "limits",
        "set",
        "counter",
        "--fuel",
        "100M",
        "--memory",
        "128Mi",
        "--effect-timeout",
        "2s",
        "--reason",
        "bigger turns",
    ]);
    assert_eq!(o.code, 0, "{o:?}");
    for want in [
        "Set the limits of counter at lsn ",
        "\n  Fuel              100000000\n",
        "\n  Memory            128 MiB\n",
        "\n  Effect timeout    2s\n",
        "\n  SQL size          1 GiB\n",
        "Next     kronik limits show --kind counter\n",
    ] {
        assert!(o.stdout.contains(want), "{want}: {o:?}");
    }
    let v = d
        .run(&["--json", "limits", "show", "--kind", "counter"])
        .json();
    let l = &v["limits"][0];
    assert_eq!(
        (&l["fuel"], &l["memory_bytes"], &l["effect_timeout_ms"]),
        (&json!(100_000_000), &json!(134_217_728), &json!(2000))
    );
    let o = d.run(&["limits", "show"]);
    assert!(
        o.stdout.contains("\ncounter  100000000  128 MiB  1 MiB "),
        "{o:?}"
    );
    let o = d.run(&[
        "limits",
        "set",
        "counter",
        "--memory",
        "64Mi",
        "--reason",
        "x",
        "--dry-run",
    ]);
    assert!(
        o.stdout
            .contains("Next     kronik limits set counter --memory 64Mi --reason x\n"),
        "{o:?}"
    );
    // At least one limit, and units that parse.
    assert_eq!(
        d.run(&["limits", "set", "counter", "--reason", "x"]).code,
        2
    );
    let o = d.run(&[
        "limits", "set", "counter", "--memory", "12XB", "--reason", "x",
    ]);
    assert_eq!(o.code, 2, "{o:?}");

    // secrets: read from stdin, never shown.
    const VALUE: &str = "k3y-value-123";
    let o = d.run_with_input(
        &["secret", "set", "api-key", "--reason", "the hmac key"],
        &format!("{VALUE}\n"),
    );
    assert!(
        o.stdout.starts_with("Stored secret api-key, version 1\n"),
        "{o:?}"
    );
    assert!(
        !o.stdout.contains(VALUE) && !o.stderr.contains(VALUE),
        "{o:?}"
    );
    let o = d.run_with_input(
        &["secret", "set", "api-key2", "--reason", "without a newline"],
        VALUE,
    );
    assert_eq!(o.code, 0, "{o:?}");
    let o = d.run(&["secret", "list"]);
    assert!(
        o.stdout.starts_with("NAME      VERSION  VERSION HASH  ") && !o.stdout.contains(VALUE),
        "{o:?}"
    );
    let v = d.run(&["--json", "secret", "list"]).json();
    assert_eq!(
        (&v["secrets"][0]["name"], &v["secrets"][1]["name"]),
        (&json!("api-key"), &json!("api-key2"))
    );
    assert!(!v.to_string().contains(VALUE));
    // Both hold the same value: the trailing newline was dropped.
    for cap in ["secret:api-key", "secret:api-key2"] {
        assert_eq!(
            d.run(&["grant", "counter", cap, "--reason", "sign"]).code,
            0
        );
    }
    let hmac = |secret: &str| {
        reply(&d.run(&[
            "send",
            "counter/h",
            "hmac",
            "--text",
            &format!("{secret}\ndata"),
            "--reason",
            "sign",
        ]))
    };
    let (h1, h2) = (hmac("api-key"), hmac("api-key2"));
    assert!(
        h1.len() == 64 && h1.bytes().all(|b| b.is_ascii_hexdigit()),
        "{h1}"
    );
    assert_eq!(h1, h2);
    let o = d.run(&["history", "counter/h", "--limit", "1"]);
    assert!(
        o.stdout
            .contains("crypto.hmac-sha256  secret:api-key2  -         ok"),
        "{o:?}"
    );
    assert_error(
        &d.run_with_input(&["secret", "set", "empty", "--reason", "x"], ""),
        "BAD_REQUEST",
    );
    assert_error(
        &d.run_with_input(&["secret", "set", "Bad Name", "--reason", "x"], "v"),
        "BAD_REQUEST",
    );
    assert_error(&d.run(&["secret", "set", "api-key"]), "REASON_REQUIRED");
    let delete = ["secret", "delete", "api-key2", "--reason", "not needed"];
    let o = d.run(&[&delete[..], &["--dry-run"]].concat());
    assert!(
        o.stdout
            .starts_with("Dry run: secret api-key2 can be deleted; nothing was written\n"),
        "{o:?}"
    );
    let o = d.run(&delete);
    assert!(
        o.stdout.starts_with("Deleted secret api-key2: 1 version\n"),
        "{o:?}"
    );
    assert_error(&d.run(&delete), "SECRET_NOT_FOUND");

    // Orphaned changes: counter/c calls counter/d, then fails.
    let o = d.run(&["history", "--orphans"]);
    assert!(
        o.stdout.starts_with("No unresolved orphaned changes.\n"),
        "{o:?}"
    );
    let o = d.run(&[
        "send",
        "counter/c",
        "call-fail",
        "--text",
        "counter/d increment",
        "--reason",
        "orphan it",
    ]);
    assert_eq!(o.code, 1, "{o:?}");
    let o = d.run(&["history", "--orphans"]);
    let lines: Vec<&str> = o.stdout.lines().collect();
    let words = |l: &str| l.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(
        words(lines[0]),
        [
            "ACTOR",
            "TURN",
            "CALLER",
            "CALLER",
            "TURN",
            "COMPENSATION",
            "RESOLVED",
            "BY"
        ],
        "{o:?}"
    );
    let row = words(lines[1]);
    assert_eq!(
        (
            row[0].as_str(),
            row[2].as_str(),
            row[4].as_str(),
            row[5].as_str()
        ),
        ("counter/d", "counter/c", "none", "-"),
        "{o:?}"
    );
    assert_eq!(lines[2], "Next     kronik history counter/d", "{o:?}");
    let v = d.run(&["--json", "history", "--orphans"]).json();
    let orphan = &v["orphans"][0];
    assert_eq!(
        (&orphan["actor"], &orphan["caller"], &orphan["compensation"]),
        (&json!("counter/d"), &json!("counter/c"), &Value::Null)
    );
    let v = d.run(&["--json", "history", "--orphans", "--all"]).json();
    assert_eq!(v["orphans"].as_array().unwrap().len(), 1);
    // An actor or --orphans, not both; --all only with --orphans.
    for args in [
        &["history"][..],
        &["history", "counter/a", "--orphans"],
        &["history", "--all"],
    ] {
        assert_eq!(d.run(args).code, 2, "{args:?}");
    }

    // Timers.
    let o = d.run(&[
        "send",
        "counter/t",
        "schedule",
        "--text",
        "3600000 increment",
        "--reason",
        "a timer",
    ]);
    let id = reply(&o);
    let o = d.run(&["actors", "timers", "counter/t"]);
    assert!(o.stdout.starts_with("ID  "), "{o:?}");
    assert!(
        o.stdout.contains(&format!("\n{id}  ")) && o.stdout.contains("Z  increment\n"),
        "{o:?}"
    );
    let v = d.run(&["--json", "actors", "timers", "counter/t"]).json();
    assert_eq!(
        (&v["timers"][0]["id"], &v["timers"][0]["name"]),
        (&json!(id), &json!("increment"))
    );
    assert!(
        d.run(&["actors", "timers", "counter/none"])
            .stdout
            .starts_with("counter/none has no pending timers.\n")
    );
}

#[test]
fn privacy_mode_status_and_erase() {
    let d = Daemon::start();
    let o = d.run(&["privacy", "status"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(
        o.stdout.contains("Mode          off (epoch none yet)"),
        "{o:?}"
    );
    let o = d.run(&["--json", "privacy", "status"]);
    assert_eq!(o.json()["mode"], "off", "{o:?}");

    let o = d.run(&["privacy", "mode", "on", "--reason", "gdpr", "--dry-run"]);
    assert!(
        o.stdout
            .starts_with("Dry run: privacy mode would turn on (epoch "),
        "{o:?}"
    );
    assert_eq!(
        d.run(&["--json", "privacy", "status"]).json()["mode"],
        "off"
    );
    let o = d.run(&["privacy", "mode", "on", "--reason", "gdpr"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(o.stdout.starts_with("Privacy mode is on (epoch "), "{o:?}");
    assert!(
        o.stdout.contains("sealed with their subject's key"),
        "{o:?}"
    );
    let o = d.run(&["privacy", "mode", "on", "--reason", "again"]);
    assert!(
        o.stdout
            .starts_with("Privacy mode was already on; nothing was recorded\n"),
        "{o:?}"
    );
    let v = d.run(&["--json", "privacy", "status"]).json();
    assert_eq!(v["mode"], "on", "{v}");
    assert!(v["epoch"].as_u64().is_some(), "{v}");
    let o = d.run(&["privacy", "status"]);
    assert!(
        o.stdout
            .contains("Next     kronik privacy mode off --reason"),
        "{o:?}"
    );
    assert_error(
        &d.run(&["privacy", "mode", "off", "--reason", " "]),
        "REASON_REQUIRED",
    );

    let o = d.run(&[
        "privacy",
        "erase",
        "user:1",
        "--reason",
        "art. 17",
        "--dry-run",
    ]);
    assert!(
        o.stdout
            .starts_with("Dry run: subject user:1 can be erased (epoch "),
        "{o:?}"
    );
    let o = d.run(&["privacy", "erase", "user:1", "--reason", "art. 17"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(o.stdout.starts_with("Erased subject user:1: "), "{o:?}");
    let v = d
        .run(&[
            "--json", "privacy", "erase", "user:2", "--reason", "art. 17",
        ])
        .json();
    assert_eq!(v["subject"], "user:2", "{v}");
    assert!(v["lsn"].as_u64().is_some(), "{v}");
}

/// `POST path` with `body` to the gateway at `addr`: the response body.
fn gateway_post(addr: &str, path: &str, body: &str) -> String {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    s.read_to_string(&mut response).unwrap();
    response
}

/// `--stub` files answer effects that have no recording; such an effect
/// counts as synthetic grounding, and the diff records the rules.
#[test]
fn replay_and_propose_take_stub_rules() {
    let d = Daemon::start();
    let target = http_target();
    assert_eq!(d.run(&["deploy", COUNTER, "--reason", "stub test"]).code, 0);
    let o = d.run(&[
        "grant",
        "counter",
        "http:127.0.0.1",
        "--reason",
        "stub test",
    ]);
    assert_eq!(o.code, 0, "{o:?}");
    for i in 0..2 {
        let answer = gateway_post(
            &d.http,
            &format!("/counter/s{i}/fetch-ok"),
            &format!("GET http://{target}/items/{i}"),
        );
        assert!(answer.contains("pong"), "{answer}");
    }

    // fetch-extra also GETs <url>/extra, which was never recorded.
    let toml = d.dir.path().join("stubs.toml");
    std::fs::write(
        &toml,
        format!(
            "[[stub]]\nmethod = \"GET\"\nurl_prefix = \"http://{target}/items/\"\n\
             headers = [[\"content-type\", \"text/plain\"]]\nbody = \"stubbed\"\n"
        ),
    )
    .unwrap();
    let extra = format!("{}/counter-fetch-extra.wasm", guests());
    let o = d.run(&[
        "--json",
        "propose",
        &extra,
        "--stub",
        toml.to_str().unwrap(),
        "--reason",
        "stub test",
    ]);
    assert_eq!(o.code, 0, "{o:?}");
    let proposal = o.json()["proposal"].clone();
    assert_eq!(proposal["summary"]["synthetic"], 2, "{proposal}");
    let id = proposal["id"].as_str().unwrap();
    let diff = d.run(&["--json", "diff", "show", id]).json();
    assert_eq!(diff["options"]["stubs"][0]["body"], "stubbed", "{diff}");
    assert!(diff.to_string().contains("200 stubbed"), "{diff}");
    let shown = d.run(&["diff", "show", id]);
    assert!(
        shown
            .stdout
            .contains(&format!("Stubs         GET http://{target}/items/ -> 200")),
        "{shown:?}"
    );

    // Without a rule the effect fails closed, also synthetic.
    let o = d.run(&["--json", "propose", &extra, "--reason", "stub test"]);
    let closed = o.json()["proposal"].clone();
    assert_eq!(closed["summary"]["synthetic"], 2, "{closed}");
    let diff = d
        .run(&["--json", "diff", "show", closed["id"].as_str().unwrap()])
        .json();
    assert_eq!(diff["options"]["stubs"], json!([]), "{diff}");
    assert!(diff.to_string().contains("replay: no recording"), "{diff}");

    // replay takes the same rules, here as a JSON array.
    let json_rules = d.dir.path().join("stubs.json");
    std::fs::write(
        &json_rules,
        format!(r#"[{{"url_prefix": "http://{target}/items/", "error": "timeout"}}]"#),
    )
    .unwrap();
    // The fork starts after the grant (its configuration allows the
    // target) and before the two requests, which the replay runs.
    let grant_lsn = d.run(&["--json", "grants", "list"]).json()["grants"][0]["lsn"]
        .as_u64()
        .unwrap()
        .to_string();
    let fork = d.run(&[
        "--json",
        "fork",
        "create",
        "--at",
        &grant_lsn,
        "--reason",
        "stub test",
    ]);
    let fork = fork.json()["fork"]["name"].as_str().unwrap().to_owned();
    let o = d.run(&["fork", "deploy", &fork, &extra, "--reason", "stub test"]);
    assert_eq!(o.code, 0, "{o:?}");
    let o = d.run(&[
        "--json",
        "replay",
        &fork,
        "--stub",
        json_rules.to_str().unwrap(),
        "--reason",
        "stub test",
    ]);
    assert_eq!(o.code, 0, "{o:?}");
    assert_eq!(o.json()["summary"]["synthetic"], 2, "{o:?}");
    let diff = d.run(&["--json", "diff", "show", &fork]).json();
    assert_eq!(diff["options"]["stubs"][0]["error"], "timeout", "{diff}");

    // A rule the API cannot use, and a file that is not one.
    std::fs::write(
        &json_rules,
        r#"[{"url_prefix": "http://a/", "error": "boom"}]"#,
    )
    .unwrap();
    let o = d.run(&[
        "replay",
        &fork,
        "--stub",
        json_rules.to_str().unwrap(),
        "--reason",
        "x",
    ]);
    assert_error(&o, "BAD_REQUEST");
    assert!(
        o.stderr.contains("network, timeout, too-large or denied"),
        "{o:?}"
    );
    std::fs::write(&toml, "[[stub]]\nurl = \"x\"\n").unwrap();
    let o = d.run(&[
        "propose",
        &extra,
        "--stub",
        toml.to_str().unwrap(),
        "--reason",
        "x",
    ]);
    assert_error(&o, "BAD_REQUEST");
    assert!(o.stderr.contains("is not a stub rules file"), "{o:?}");
}

/// The directory of the test guests.
fn guests() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests").to_owned()
}
