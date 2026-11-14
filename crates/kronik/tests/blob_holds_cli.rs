//! `kronik actors inspect`, `blobs list --actor`, `blobs inspect` and
//! `blobs gc --dry-run --verify` against a real `kronik` binary with
//! `[blobs] enabled = true` and the test guest `media` (M26 slice B16, §12):
//! what an actor holds, page by page; a held blob's root names its holder;
//! the plan's pins match their rows.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use serde_json::Value;

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

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
                 [blobs]\nenabled = true\ngc_interval = \"0s\"\n",
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
        finish(child.wait_with_output().unwrap())
    }

    /// `POST /media/a/<op>?<query>` to the gateway: the response's body.
    fn post(&self, op: &str, query: &str) -> String {
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

fn finish(out: Output) -> Out {
    Out {
        code: out.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[test]
fn holds_in_actors_inspect_blobs_list_inspect_and_the_plan() {
    let dir = tempfile::tempdir().unwrap();
    let d = Serve::start(dir.path());
    let o = d.run(&["deploy", MEDIA, "--reason", "what actors hold"]);
    assert_eq!(o.code, 0, "{o:?}");
    // media/a puts two blobs and holds both.
    let first = d.post("put", "size=3000");
    let second = d.post("put", "size=2000");
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
