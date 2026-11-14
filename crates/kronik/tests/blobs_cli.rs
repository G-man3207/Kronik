//! `kronik blobs status`, `inspect`, `get` and `gc` against a real `kronik`
//! binary with `[blobs] enabled = true` and the test guest `media` (M25
//! slice B11): a turn's response blob is indexed, inspected, verified and
//! downloaded with a secret value scrubbed; a blob a turn wrote and did not
//! keep is listed as loose and collected; a blob nobody knows is
//! BLOB_NOT_FOUND.

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

/// The bytes the media guest writes for a blob of `n` bytes.
fn pattern(n: u64) -> Vec<u8> {
    (0..n)
        .map(|i| ((i.wrapping_mul(31) + 7) % 251) as u8)
        .collect()
}

fn hash(bytes: &[u8]) -> String {
    format!("b3:{}", blake3::hash(bytes).to_hex())
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
}
