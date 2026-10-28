//! The gateway and the API against hostile actors and clients, on a real
//! `kronik serve`: response headers an actor may not set, end users'
//! credentials in turns, diffs and policy tests, a token checked before the
//! body, a client that sends nothing, idle connections against the log's
//! descriptors, one client's share of the connections and a trusted proxy,
//! a key of 256 bytes, and the modes of the data directory.

// Test harness code: unwraps, std threads and std time are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::free_port;

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");

fn guest(name: &str) -> String {
    format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// The settings `kronik serve` and the CLI read from the environment,
/// cleared so that the developer's shell can't change the tests.
const SETTINGS_ENV: [&str; 8] = [
    "KRONIK_CONFIG",
    "KRONIK_DATA_DIR",
    "KRONIK_HTTP_LISTEN",
    "KRONIK_ADMIN_LISTEN",
    "KRONIK_API_SOCKET",
    "KRONIK_MASTER_KEY_FILE",
    "KRONIK_MASTER_KEY",
    "KRONIK_TOKEN",
];

/// Where the API socket is: beside the data directory, inside it, or inside
/// it in a directory that does not exist yet, both paths relative to the
/// working directory.
enum Socket {
    Beside,
    Inside,
    InsideRelative,
}

/// `kronik serve` on free ports in a fresh directory, killed when dropped.
struct Serve {
    child: Child,
    dir: tempfile::TempDir,
    data: PathBuf,
    socket: PathBuf,
    http: String,
    api: String,
}

impl Serve {
    fn start() -> Serve {
        Serve::start_with(&[], Socket::Beside, "")
    }

    /// With `wrapper` (such as `prlimit`) in front, the API socket where
    /// `socket` says, and `config` as its configuration file.
    fn start_with(wrapper: &[&str], socket: Socket, config: &str) -> Serve {
        let dir = tempfile::tempdir().unwrap();
        let (data_arg, socket_arg) = match socket {
            Socket::Beside => (dir.path().join("data"), dir.path().join("api.sock")),
            Socket::Inside => (dir.path().join("data"), dir.path().join("data/api.sock")),
            Socket::InsideRelative => ("data".into(), "data/run/api.sock".into()),
        };
        let (data, socket) = (dir.path().join(&data_arg), dir.path().join(&socket_arg));
        let config_file = dir.path().join("kronik.toml");
        std::fs::write(&config_file, config).unwrap();
        let (http, api) = (
            format!("127.0.0.1:{}", free_port()),
            format!("127.0.0.1:{}", free_port()),
        );
        let mut command = match wrapper.split_first() {
            Some((program, args)) => {
                let mut c = Command::new(program);
                c.args(args).arg(KRONIK);
                c
            }
            None => Command::new(KRONIK),
        };
        for var in SETTINGS_ENV {
            command.env_remove(var);
        }
        let log_file = std::fs::File::create(dir.path().join("serve.log")).unwrap();
        let child = command
            .current_dir(dir.path())
            .args(["serve", "--config"])
            .arg(&config_file)
            .arg("--data-dir")
            .arg(&data_arg)
            .args(["--http-listen", &http, "--api-listen", &api])
            .args(["--admin-listen", "127.0.0.1:0", "--api-socket"])
            .arg(&socket_arg)
            .env("KRONIK_LOG", "warn")
            .env("KRONIK_DISK_RESERVE", "0B")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log_file)
            .spawn()
            .unwrap();
        let mut serve = Serve {
            child,
            dir,
            data,
            socket,
            http,
            api,
        };
        for _ in 0..600 {
            if serve.cli(&["--json", "actors", "list"]).status.success() {
                return serve;
            }
            assert!(serve.alive(), "kronik serve stopped: {}", serve.log());
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the API did not come up: {}", serve.log());
    }

    fn cli(&self, args: &[&str]) -> Output {
        let mut command = Command::new(KRONIK);
        for var in SETTINGS_ENV {
            command.env_remove(var);
        }
        command
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn deploy(&self, name: &str) {
        let out = self.cli(&["deploy", &guest(name), "--reason", "test"]);
        assert!(out.status.success(), "{out:?}");
    }

    /// A token with `scopes`.
    fn token(&self, name: &str, scopes: &str) -> String {
        let out = self.cli(&[
            "--json", "token", "create", "--name", name, "--scopes", scopes, "--reason", "test",
        ]);
        assert!(out.status.success(), "{out:?}");
        let created: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        created["secret"].as_str().unwrap().to_owned()
    }

    fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    fn log(&self) -> String {
        let log = std::fs::read_to_string(self.dir.path().join("serve.log")).unwrap_or_default();
        // Without the terminal colours.
        let mut plain = String::with_capacity(log.len());
        let mut chars = log.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                chars.by_ref().find(|c| c.is_ascii_alphabetic());
            } else {
                plain.push(c);
            }
        }
        plain
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

type Response = (u16, Vec<(String, String)>, Vec<u8>);

/// One HTTP/1.1 response: status, headers (lower-case names) and the body
/// its `content-length` gives.
fn read_response(r: &mut impl BufRead) -> Response {
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status = line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    loop {
        line.clear();
        r.read_line(&mut line).unwrap();
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((name, value)) = l.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let len = header(&headers, "content-length")
        .first()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    r.read_exact(&mut body).unwrap();
    (status, headers, body)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
        .collect()
}

/// One request on a new connection, with `headers` (`name: value` lines).
fn request(addr: &str, method: &str, path: &str, headers: &str, body: &str) -> Response {
    request_on(
        TcpStream::connect(addr).unwrap(),
        method,
        path,
        headers,
        body,
    )
}

/// One request on `conn`.
fn request_on(
    mut conn: TcpStream,
    method: &str,
    path: &str,
    headers: &str,
    body: &str,
) -> Response {
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        conn,
        "{method} {path} HTTP/1.1\r\nhost: t\r\n{headers}content-length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    read_response(&mut BufReader::new(conn))
}

/// A connection to `addr` from the local address `source`, another client.
fn connect_from(source: &str, addr: &str) -> TcpStream {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let conn = rt.block_on(async {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
        socket.connect(addr.parse().unwrap()).await.unwrap()
    });
    let conn = conn.into_std().unwrap();
    conn.set_nonblocking(false).unwrap();
    conn
}

/// An actor's response cannot set the connection's headers or the turn id:
/// a false `content-length` would hand the rest of its body to the next
/// request on the connection, maybe another user's.
#[test]
fn an_actor_cannot_set_connection_headers_or_the_turn_id() {
    let s = Serve::start();
    s.deploy("counter-respond");
    let smuggled =
        "HTTP/1.1 200 OK\r\nset-cookie: session=attacker\r\ncontent-length: 6\r\n\r\nPWNED!";
    let spelled = format!(
        "200\ncontent-length: 2\nconnection: keep-alive\ntransfer-encoding: identity\n\
         kronik-turn-id: main:999\nx-actor: yes\n\nok{smuggled}"
    );
    let mut conn = TcpStream::connect(&s.http).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    write!(
        conn,
        "POST /counter/a/respond HTTP/1.1\r\nhost: t\r\ncontent-length: {}\r\n\r\n{spelled}",
        spelled.len()
    )
    .unwrap();
    let (status, headers, body) = read_response(&mut reader);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, format!("ok{smuggled}").as_bytes());
    let ids = header(&headers, "kronik-turn-id");
    assert!(
        ids.len() == 1 && ids[0].starts_with("main:") && ids[0] != "main:999",
        "{headers:?}"
    );
    assert_eq!(header(&headers, "x-actor"), ["yes"]);
    assert!(
        header(&headers, "transfer-encoding").is_empty(),
        "{headers:?}"
    );

    // The next request on the same connection gets its own response.
    write!(conn, "GET /counter/a HTTP/1.1\r\nhost: t\r\n\r\n").unwrap();
    let (status, headers, body) = read_response(&mut reader);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(header(&headers, "set-cookie").is_empty(), "{headers:?}");
    assert_ne!(body, b"PWNED!");

    // An informational status is no final response: the actor's mistake.
    let (status, _, body) = request(
        &s.http,
        "POST",
        "/counter/b/respond",
        "",
        "101\nupgrade: websocket\nconnection: upgrade\n\n",
    );
    assert_eq!(status, 500);
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("\"TURN_FAILED\"") && body.contains("status 101"),
        "{body}"
    );
}

/// Over TCP the token is checked before the body is read: a bogus token with
/// a large declared body is refused at once, without the body.
#[test]
fn a_bad_token_is_refused_before_the_body() {
    let s = Serve::start();
    let mut conn = TcpStream::connect(&s.api).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        conn,
        "POST /v1/deployments HTTP/1.1\r\nhost: t\r\nauthorization: Bearer kronik_bogus\r\n\
         content-type: application/json\r\ncontent-length: 60000000\r\n\r\n"
    )
    .unwrap();
    let started = Instant::now();
    let (status, _, body) = read_response(&mut BufReader::new(conn));
    assert_eq!(status, 401, "{}", String::from_utf8_lossy(&body));
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// A client that never finishes its request head is disconnected.
#[test]
fn a_client_that_sends_no_request_is_disconnected() {
    let s = Serve::start();
    let mut conn = TcpStream::connect(&s.http).unwrap();
    conn.write_all(b"GET /counter/a HTTP/1.1\r\nhost: t\r\n")
        .unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(40)))
        .unwrap();
    let started = Instant::now();
    let mut rest = Vec::new();
    let _ = conn.read_to_end(&mut rest);
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(8) && waited < Duration::from_secs(30),
        "{waited:?}"
    );
}

/// Idle connections cannot take the descriptors the log needs: under a
/// limit of 256 open files, with 300 idle connections open, a turn that
/// rolls the log's segment still commits, and serve goes on.
#[test]
fn idle_connections_leave_the_log_its_descriptors() {
    let mut s = Serve::start_with(
        &["prlimit", "--nofile=256:256", "--"],
        Socket::Beside,
        "[log]\nsegment_max_age_s = 1\n",
    );
    s.deploy("counter");
    // Served before the others pile up.
    let conn = TcpStream::connect(&s.http).unwrap();
    let idle: Vec<TcpStream> = (0..300)
        .filter_map(|_| TcpStream::connect(&s.http).ok())
        .collect();
    // Past the segment's age, so that the turn rolls it.
    std::thread::sleep(Duration::from_millis(1500));
    let (status, _, body) = request_on(conn, "POST", "/counter/a/increment", "", "");
    assert_eq!(
        status,
        200,
        "{}: {}",
        String::from_utf8_lossy(&body),
        s.log()
    );
    assert!(s.alive(), "kronik serve stopped: {}", s.log());
    drop(idle);
    let served = (0..100).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        request(&s.http, "POST", "/counter/a/increment", "", "").0 == 200
    });
    assert!(served, "{}", s.log());
    assert!(s.alive());
}

/// One client address holds a quarter of the gateway's connections; over
/// that share it gets 503, not a reset, and another client is still served.
/// A trusted proxy has no share. Under 256 open files the gateway takes 96
/// connections, 24 per client.
#[test]
fn a_client_over_its_share_gets_503_unless_it_is_a_trusted_proxy() {
    let limit = ["prlimit", "--nofile=256:256", "--"];
    // 40 requests at once from 127.0.0.1, each on its own connection, all
    // kept open until every answer is read.
    let statuses = |s: &Serve| -> Vec<Response> {
        let mut conns: Vec<BufReader<TcpStream>> = (0..40)
            .map(|_| {
                let mut c = TcpStream::connect(&s.http).unwrap();
                c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
                write!(c, "GET /counter/a HTTP/1.1\r\nhost: t\r\n\r\n").unwrap();
                BufReader::new(c)
            })
            .collect();
        conns.iter_mut().map(read_response).collect()
    };
    let s = Serve::start_with(&limit, Socket::Beside, "");
    s.deploy("counter");
    let answers = statuses(&s);
    let count = |status: u16| answers.iter().filter(|a| a.0 == status).count();
    assert_eq!(
        (count(200), count(503)),
        (24, 16),
        "{:?}",
        answers.iter().map(|a| a.0).collect::<Vec<_>>()
    );
    for (_, headers, body) in answers.iter().filter(|a| a.0 == 503) {
        assert_eq!(header(headers, "connection"), ["close"], "{headers:?}");
        assert!(String::from_utf8_lossy(body).contains("UNAVAILABLE"));
    }
    let conn = connect_from("127.0.0.2", &s.http);
    assert_eq!(request_on(conn, "GET", "/counter/a", "", "").0, 200);

    let s = Serve::start_with(
        &limit,
        Socket::Beside,
        "[gateway]\ntrusted_proxies = [\"127.0.0.1\"]\n",
    );
    s.deploy("counter");
    let answers = statuses(&s);
    assert!(
        answers.iter().all(|a| a.0 == 200),
        "{:?}",
        answers.iter().map(|a| a.0).collect::<Vec<_>>()
    );
}

/// The API shows an end user's credentials only with `pii:read`.
#[test]
fn credentials_in_a_turn_need_pii_read() {
    let s = Serve::start();
    s.deploy("counter");
    let (status, headers, _) = request(
        &s.http,
        "POST",
        "/counter/a/increment",
        "authorization: Bearer user-s3cret\r\ncookie: session=c00kie\r\nx-api-key: k3y-value\r\n",
        "",
    );
    assert_eq!(status, 200);
    let turn = header(&headers, "kronik-turn-id")[0].to_owned();
    let get = |token: &str| {
        let (status, _, body) = request(
            &s.api,
            "GET",
            &format!("/v1/turns/{turn}"),
            &format!("authorization: Bearer {token}\r\n"),
            "",
        );
        assert_eq!(status, 200);
        String::from_utf8(body).unwrap()
    };
    let read = get(&s.token("reader", "read"));
    for secret in ["user-s3cret", "c00kie", "k3y-value"] {
        assert!(!read.contains(secret), "{secret}: {read}");
    }
    assert_eq!(read.matches("[redacted]").count(), 3, "{read}");
    let pii = get(&s.token("auditor", "read,pii:read"));
    for secret in ["user-s3cret", "c00kie", "k3y-value"] {
        assert!(pii.contains(secret), "{secret}: {pii}");
    }
}

/// A proposal whose diff has a cookie and a token in a response's headers:
/// `counter` has no respond route, so the fork answers otherwise.
fn propose_over_credentials(s: &Serve) -> String {
    s.deploy("counter-respond");
    let (status, _, _) = request(
        &s.http,
        "POST",
        "/counter/a/respond",
        "",
        "200\nset-cookie: session=c00kie-v4lue\nx-refresh-token: r3fresh-v4lue\n\nok",
    );
    assert_eq!(status, 200);
    let out = s.cli(&["--json", "propose", &guest("counter"), "--reason", "test"]);
    assert!(out.status.success(), "{out:?}");
    let proposed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    proposed["proposal"]["id"].as_str().unwrap().to_owned()
}

/// A fork's diff shows the credentials in responses only with `pii:read`,
/// as JSON and as Markdown.
#[test]
fn credentials_in_a_diff_need_pii_read() {
    let s = Serve::start();
    let id = propose_over_credentials(&s);
    let get = |token: &str, format: &str| {
        let (status, _, body) = request(
            &s.api,
            "GET",
            &format!("/v1/proposals/{id}/diff?format={format}"),
            &format!("authorization: Bearer {token}\r\n"),
            "",
        );
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        String::from_utf8(body).unwrap()
    };
    let (reader, auditor) = (
        s.token("reader", "read"),
        s.token("auditor", "read,pii:read"),
    );
    for format in ["json", "md"] {
        let read = get(&reader, format);
        for secret in ["c00kie-v4lue", "r3fresh-v4lue"] {
            assert!(!read.contains(secret), "{format} {secret}: {read}");
        }
        assert!(read.contains("[redacted]"), "{format}: {read}");
        let pii = get(&auditor, format);
        for secret in ["c00kie-v4lue", "r3fresh-v4lue"] {
            assert!(pii.contains(secret), "{format} {secret}: {pii}");
        }
    }
}

/// `policy test` runs the caller's own rules: without `pii:read` on the
/// redacted diff, so a rule that guesses a hidden cookie gets the same
/// outcome right or wrong. With `pii:read` the rule sees the values.
#[test]
fn policy_test_cannot_guess_hidden_credentials() {
    let s = Serve::start();
    let id = propose_over_credentials(&s);
    let outcome = |token: &str, guess: &str| {
        let when = format!(
            "diff.responses.items.exists(r, r.headers.exists(h, h.name == 'set-cookie' \
             && h.prod.exists(v, string(v).startsWith('{guess}'))))"
        );
        let rules = format!("[[rule]]\nname = \"guess\"\nwhen = \"{when}\"\naction = \"deny\"\n");
        let body = serde_json::json!({"proposal": id, "rules_toml": rules}).to_string();
        let (status, _, body) = request(
            &s.api,
            "POST",
            "/v1/policy/test",
            &format!("authorization: Bearer {token}\r\ncontent-type: application/json\r\n"),
            &body,
        );
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let evaluation: serde_json::Value = serde_json::from_slice(&body).unwrap();
        evaluation["outcome"].as_str().unwrap().to_owned()
    };
    let (reader, auditor) = (
        s.token("reader", "read"),
        s.token("auditor", "read,pii:read"),
    );
    assert_eq!(
        outcome(&reader, "session=c00k"),
        outcome(&reader, "session=zzzz")
    );
    assert_eq!(outcome(&auditor, "session=c00k"), "deny");
    assert_eq!(outcome(&auditor, "session=zzzz"), "allow");
}

/// A valid key of 256 bytes is too long for a file name as such; the actor's
/// database still opens.
#[test]
fn an_actor_key_of_256_bytes_has_its_database() {
    let s = Serve::start();
    s.deploy("notes");
    let path = format!("/notes/{}", "k".repeat(256));
    let (status, _, body) = request(&s.http, "POST", &path, "", "a note");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (status, _, body) = request(&s.http, "GET", &path, "", "");
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("a note"));
}

/// The data directory, `keys/` and the key stores are the daemon's alone.
#[test]
fn the_data_directory_and_the_keys_are_private() {
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let s = Serve::start();
    s.token("one", "read");
    assert_eq!(mode(&s.data), 0o700);
    let keys = s.data.join("keys");
    assert_eq!(mode(&keys), 0o700);
    for name in ["master.key", "secrets.db", "keystore.db", "tokens.db"] {
        assert_eq!(mode(&keys.join(name)), 0o600, "{name}");
    }
    // With the API socket inside it, the group may pass through to it, also
    // when both paths are relative and the socket's directory is new.
    for socket in [Socket::Inside, Socket::InsideRelative] {
        let s = Serve::start_with(&[], socket, "");
        assert_eq!(mode(&s.data), 0o710);
    }
}
