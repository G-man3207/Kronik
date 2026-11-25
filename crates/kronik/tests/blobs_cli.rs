//! `kronik blobs status`, `inspect`, `get` and `gc` against a real `kronik`
//! binary and the test guest `media` (M25
//! slice B11): a turn's response blob is indexed, inspected, verified and
//! downloaded with a secret value scrubbed; a blob a turn wrote and did not
//! keep is listed as loose and collected; a blob nobody knows is
//! BLOB_NOT_FOUND.
//! `kronik actors inspect`, `blobs list --actor`, `blobs inspect` and
//! `blobs gc --dry-run --verify` show what an actor holds (M26 slice B16,
//! §12).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/blob_fixtures.rs"]
mod blob_fixtures;

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::Duration;

use blob_fixtures::{hash, pattern};
use common::{Out, command, free_port};
use serde_json::Value;

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

struct Serve {
    child: Child,
    socket: std::path::PathBuf,
    http: String,
}

impl Serve {
    fn start(dir: &Path) -> Serve {
        let socket = dir.join("api.sock");
        let http = format!("127.0.0.1:{}", free_port());
        let config = dir.join("kronik.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\napi_socket = {:?}\nhttp_listen = {http:?}\n\n\
                 [blobs]\ngc_interval = \"0s\"\n",
                dir.join("data"),
                socket,
            ),
        )
        .unwrap();
        let child = command()
            .arg("serve")
            .arg("--config")
            .arg(&config)
            .env("KRONIK_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let serve = Serve {
            child,
            socket,
            http,
        };
        let up = (0..600).any(|_| {
            if serve.run(&["--json", "actors", "list"]).code == 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
            false
        });
        assert!(up, "the API did not come up on {}", serve.socket.display());
        serve
    }

    fn run(&self, args: &[&str]) -> Out {
        self.run_with(args, None)
    }

    fn run_with(&self, args: &[&str], stdin: Option<&[u8]>) -> Out {
        let mut all = vec!["--socket", self.socket.to_str().unwrap()];
        all.extend_from_slice(args);
        let mut command = command();
        command
            .args(&all)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        if let Some(bytes) = stdin {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        child.wait_with_output().unwrap().into()
    }

    /// `POST /media/a/<op>?<query>` to the gateway: the status line.
    fn post(&self, op: &str, query: &str) -> String {
        let mut s = TcpStream::connect(&self.http).unwrap();
        write!(
            s,
            "POST /media/a/{op}?{query} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Content-Length: 0\r\n\r\n"
        )
        .unwrap();
        // The status line only: a blob answer's body is the blob's bytes
        // (the gateway streams them since M25 slice B8), not text.
        let mut response = Vec::new();
        s.read_to_end(&mut response).unwrap();
        let end = response
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(response.len());
        String::from_utf8_lossy(&response[..end]).into_owned()
    }

    /// `POST /media/a/<op>?<query>` to the gateway, which must answer 200:
    /// the response's body.
    fn post_body(&self, op: &str, query: &str) -> String {
        let mut s = TcpStream::connect(&self.http).unwrap();
        write!(
            s,
            "POST /media/a/{op}?{query} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Content-Length: 0\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        s.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_default()
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn blobs_status_inspect_get_and_gc() {
    let dir = tempfile::tempdir().unwrap();
    let d = Serve::start(dir.path());
    let o = d.run(&["deploy", MEDIA, "--reason", "blob commands"]);
    assert_eq!(o.code, 0, "{o:?}");
    // A secret whose value the response blob holds (bytes 1000..1024).
    let content = pattern(200_000);
    let secret = &content[1000..1024];
    let o = d.run_with(
        &["secret", "set", "token", "--reason", "a value in a blob"],
        Some(secret),
    );
    assert_eq!(o.code, 0, "{o:?}");

    // A response blob, and a blob a turn wrote and did not answer with.
    assert!(d.post("write", "size=200000&chunk=65536").contains(" 200 "));
    assert!(d.post("write-discard", "size=50000").contains(" 200 "));
    let kept = hash(&content);
    let discarded = hash(&pattern(50_000));

    let status = d.run(&["--json", "blobs", "status"]).json();
    assert_eq!(status["enabled"], true, "{status}");
    assert_eq!(status["indexed"], 1, "{status}");
    assert_eq!(status["indexed_bytes"], 200_000, "{status}");
    let o = d.run(&["blobs", "status"]);
    assert!(o.stdout.contains("Indexed      1 blobs"), "{o:?}");

    let inspect = d
        .run(&["--json", "blobs", "inspect", &kept, "--verify"])
        .json();
    assert_eq!(inspect["state"], "live", "{inspect}");
    assert_eq!(inspect["size"], 200_000, "{inspect}");
    assert_eq!(inspect["verified"], true, "{inspect}");
    assert_eq!(inspect["roots"][0]["kind"], "log", "{inspect}");
    let o = d.run(&["blobs", "inspect", &kept]);
    assert!(o.stdout.contains("State        live"), "{o:?}");

    // The turn that wrote it carries its reference in history and trace
    // (M25/M26). The text shows the first 12 hex characters; --json, the
    // whole hash and size.
    let history = d.run(&["--json", "history", "media/a"]).json();
    let write_turn = history["turns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| {
            t["blobs"].as_array().is_some_and(|blobs| {
                blobs
                    .iter()
                    .any(|b| b["hash"].as_str() == Some(kept.as_str()))
            })
        })
        .unwrap_or_else(|| panic!("no turn names {kept}: {history}"));
    assert!(
        write_turn["blobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["hash"].as_str() == Some(kept.as_str()) && b["size"] == 200_000),
        "{write_turn}"
    );
    let short = &kept[..15];
    let o = d.run(&["history", "media/a"]);
    assert!(o.stdout.contains("BLOBS"), "{o:?}");
    assert!(
        o.stdout.contains(&format!("blob {short} (195.3 KiB)")),
        "{o:?}"
    );
    let turn_id = write_turn["turn_id"].as_str().unwrap();
    let o = d.run(&["trace", turn_id]);
    assert!(
        o.stdout.contains(&format!("blob {short} (195.3 KiB)")),
        "{o:?}"
    );
    let trace = d.run(&["--json", "trace", turn_id]).json();
    assert!(
        trace["turn"]["blobs"].as_array().is_some_and(|blobs| blobs
            .iter()
            .any(|b| { b["hash"].as_str() == Some(kept.as_str()) && b["size"] == 200_000 })),
        "{trace}"
    );

    // A send copies the reference into the receiver's turn. The sender's
    // trace has the receiver in `descendants`, and both name the blob.
    fn carries(node: &Value, hash: &str) -> bool {
        node["blobs"]
            .as_array()
            .is_some_and(|blobs| blobs.iter().any(|b| b["hash"].as_str() == Some(hash)))
            || node["children"]
                .as_array()
                .is_some_and(|children| children.iter().any(|n| carries(n, hash)))
    }
    let sent = hash(&pattern(3000));
    let o = d.post("put", "size=3000");
    assert!(o.contains(" 200 "), "{o}");
    let o = d.post("send", "to=b&op=info&with=ref");
    assert!(o.contains(" 200 "), "{o}");
    let mut receiver = None;
    for _ in 0..200 {
        let h = d.run(&["--json", "history", "media/b"]).json();
        if let Some(turn) = h["turns"].as_array().and_then(|turns| turns.first())
            && carries(turn, &sent)
        {
            receiver = Some(turn.clone());
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let receiver = receiver.unwrap_or_else(|| panic!("media/b never received {sent}: {o}"));
    let id = receiver["turn_id"].as_str().unwrap();
    let traced = d.run(&["--json", "trace", id]).json();
    assert_eq!(traced["turn"]["blobs"], receiver["blobs"], "{traced}");
    let root = traced["root"]["lsn"].as_u64().unwrap();
    let sender = d.run(&["--json", "trace", &format!("main:{root}")]).json();
    assert!(
        sender["descendants"]
            .as_array()
            .is_some_and(|nodes| nodes.iter().any(|n| carries(n, &sent))),
        "{sender}"
    );

    // The download scrubs the secret value, and only it. The pattern
    // repeats every 251 bytes, so the value is in it many times.
    let out = dir.path().join("out.bin");
    let o = d.run(&["blobs", "get", &kept, "-o", out.to_str().unwrap()]);
    assert_eq!(o.code, 0, "{o:?}");
    let got = std::fs::read(&out).unwrap();
    let mut expected = Vec::with_capacity(content.len());
    let mut i = 0;
    while i < content.len() {
        if content[i..].starts_with(secret) {
            expected.extend_from_slice(b"[secret:token]");
            i += secret.len();
        } else {
            expected.push(content[i]);
            i += 1;
        }
    }
    assert!(expected.len() < content.len() - 7000);
    assert_eq!(got.len(), expected.len());
    assert!(got == expected, "the download is not the scrubbed blob");
    assert!(!got.windows(secret.len()).any(|w| w == secret));

    // The discarded blob is loose; an immediate pass deletes it, and the
    // response blob stays.
    let plan = d.run(&["--json", "blobs", "gc", "--dry-run"]).json();
    assert_eq!(plan["count"], 1, "{plan}");
    assert_eq!(plan["blobs"][0]["hash"], discarded, "{plan}");
    assert_eq!(plan["blobs"][0]["reason"], "loose", "{plan}");
    let o = d.run(&["blobs", "gc", "--dry-run"]);
    assert!(o.stdout.contains("loose"), "{o:?}");
    let gc = d
        .run(&[
            "--json",
            "blobs",
            "gc",
            "--immediate",
            "--reason",
            "free the disk",
        ])
        .json();
    assert_eq!(gc["deleted"], 1, "{gc}");
    assert!(gc["bytes"].as_u64().unwrap() > 50_000, "{gc}");
    let o = d.run(&["--json", "blobs", "inspect", &discarded]);
    assert_ne!(o.code, 0, "{o:?}");
    assert!(
        o.stdout.contains("BLOB_NOT_FOUND") || o.stderr.contains("BLOB_NOT_FOUND"),
        "{o:?}"
    );
    let inspect = d.run(&["--json", "blobs", "inspect", &kept]).json();
    assert_eq!(inspect["state"], "live", "{inspect}");
    let audit = d.run(&["--json", "audit", "show"]);
    assert!(audit.stdout.contains("blobs.gc"), "{audit:?}");

    // A reasoned dry run goes through the pass's human rendering.
    let o = d.run(&["blobs", "gc", "--dry-run", "--reason", "check"]);
    assert_eq!(o.code, 0, "{o:?}");
    assert!(
        o.stdout
            .contains("Dry run: a pass now would delete 0 files (0 bytes)"),
        "{o:?}"
    );
}

#[test]
fn holds_in_actors_inspect_blobs_list_inspect_and_the_plan() {
    let dir = tempfile::tempdir().unwrap();
    let d = Serve::start(dir.path());
    let o = d.run(&["deploy", MEDIA, "--reason", "what actors hold"]);
    assert_eq!(o.code, 0, "{o:?}");
    // media/a puts two blobs and holds both.
    let first = d.post_body("put", "size=3000");
    let second = d.post_body("put", "size=2000");
    let hash = |answer: &str| answer.split(' ').nth(1).unwrap().to_owned();
    let (first, second) = (hash(&first), hash(&second));

    let actor = d.run(&["--json", "actors", "inspect", "media/a"]).json();
    assert_eq!(actor["blobs"]["held"], 2, "{actor}");
    assert_eq!(actor["blobs"]["bytes"], 5000, "{actor}");
    let o = d.run(&["actors", "inspect", "media/a"]);
    assert!(o.stdout.contains("2 blobs held"), "{o:?}");

    // A page of one, then the rest.
    let page = d
        .run(&[
            "--json", "blobs", "list", "--actor", "media/a", "--limit", "1",
        ])
        .json();
    assert_eq!(page["blobs"].as_array().unwrap().len(), 1, "{page}");
    let next = page["next"].as_str().unwrap().to_owned();
    let rest = d
        .run(&[
            "--json", "blobs", "list", "--actor", "media/a", "--after", &next,
        ])
        .json();
    assert_eq!(rest["blobs"].as_array().unwrap().len(), 1, "{rest}");
    assert!(rest["next"].is_null(), "{rest}");
    let mut listed = vec![
        page["blobs"][0]["hash"].as_str().unwrap().to_owned(),
        rest["blobs"][0]["hash"].as_str().unwrap().to_owned(),
    ];
    listed.sort();
    let mut expected = vec![first.clone(), second.clone()];
    expected.sort();
    assert_eq!(listed, expected);
    let o = d.run(&["blobs", "list", "--actor", "media/a"]);
    assert!(o.stdout.contains(&first), "{o:?}");

    // The hold is a root, named by its holder.
    let inspect = d.run(&["--json", "blobs", "inspect", &first]).json();
    let roots = inspect["roots"].as_array().unwrap();
    assert!(
        roots
            .iter()
            .any(|r| r["kind"] == "held" && r["actor"] == "media/a"),
        "{inspect}"
    );
    let o = d.run(&["blobs", "inspect", &first]);
    assert!(o.stdout.contains("held by media/a"), "{o:?}");

    // The plan: nothing to collect, and the pins match their rows.
    let o = d.run(&["--json", "blobs", "gc", "--dry-run", "--verify"]);
    assert_eq!(o.code, 0, "{o:?}");
    let plan = o.json();
    assert_eq!(plan["count"], 0, "{plan}");
    assert_eq!(plan["drift"], serde_json::json!([]), "{plan}");
    let o = d.run(&["blobs", "gc", "--dry-run", "--verify"]);
    assert!(o.stdout.contains("match the rows they mirror"), "{o:?}");
    // --verify goes with the dry run only.
    let o = d.run(&["blobs", "gc", "--verify", "--reason", "x"]);
    assert_ne!(o.code, 0, "{o:?}");
}
