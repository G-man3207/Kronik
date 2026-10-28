//! foreign-echo: a small HTTP/1.1 server that plays a foreign actor in
//! Kronik's tests. It reports what the sandbox looks like from the inside
//! (identity, resources, network egress, environment, writable volume) and
//! can be told to exit, to exercise restarts.
//!
//! ```text
//! foreign-echo [--listen ADDR] [--data-dir DIR]
//!
//! GET  /healthz                    200 "ok"
//! *    /echo                       the request as JSON
//! GET  /info                       pid, ids, hostname, cwd, cpus, memory, interfaces
//! POST /exit?code=N                answers, then exits with status N
//! GET  /egress[?target=H:P]...     tries to reach the outside world
//! GET  /env?name=X                 whether X is set, its length and SHA-256
//! GET  /data                       increments DIR/count (default /data/count)
//! ```
//!
//! One thread per connection, keep-alive with `Content-Length` bodies, one
//! log line per request on stdout.

mod http;
mod sha256;

use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use http::{ReadError, Request, Response};

/// The largest request body accepted.
const MAX_BODY: usize = 1024 * 1024;

/// How long an idle keep-alive connection is kept open.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The timeout of every egress attempt.
const EGRESS_TIMEOUT: Duration = Duration::from_secs(1);

/// The most `target` parameters `/egress` accepts.
const MAX_EGRESS_TARGETS: usize = 16;

/// TCP targets `/egress` always tries: public IPv4 and IPv6, the cloud
/// metadata address and the usual Docker bridge gateway.
const EGRESS_TCP: [&str; 5] = [
    "1.1.1.1:443",
    "8.8.8.8:53",
    "[2606:4700:4700::1111]:443",
    "169.254.169.254:80",
    "172.17.0.1:80",
];

/// DNS servers `/egress` sends a UDP query to.
const EGRESS_UDP: [&str; 2] = ["8.8.8.8:53", "1.1.1.1:53"];

/// Serializes `/data` updates so concurrent requests count correctly.
static DATA_LOCK: Mutex<()> = Mutex::new(());

const USAGE: &str = "usage: foreign-echo [--listen ADDR] [--data-dir DIR]";

/// Command-line settings.
struct Config {
    listen: String,
    data_dir: PathBuf,
}

fn main() {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("foreign-echo: {msg}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let listener = match TcpListener::bind(&config.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("foreign-echo: cannot listen on {}: {e}", config.listen);
            std::process::exit(1);
        }
    };
    let local = listener
        .local_addr()
        .map_or_else(|_| config.listen.clone(), |a| a.to_string());
    log(&format!("foreign-echo: listening on {local}"));
    let data_dir: Arc<Path> = Arc::from(config.data_dir);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let data_dir = Arc::clone(&data_dir);
                let spawned = thread::Builder::new()
                    .name("conn".into())
                    .spawn(move || handle_connection(stream, &data_dir));
                if let Err(e) = spawned {
                    log(&format!("foreign-echo: cannot start a thread: {e}"));
                }
            }
            Err(e) => {
                // EMFILE and friends: back off instead of spinning.
                log(&format!("foreign-echo: accept failed: {e}"));
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Config, String> {
    let mut config = Config {
        listen: "0.0.0.0:8080".into(),
        data_dir: PathBuf::from("/data"),
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => config.listen = args.next().ok_or("--listen needs a value")?,
            "--data-dir" => config.data_dir = args.next().ok_or("--data-dir needs a value")?.into(),
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(config)
}

/// Writes one line to stdout. A closed stdout must not kill the server.
fn log(line: &str) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn handle_connection(stream: TcpStream, data_dir: &Path) {
    let peer = stream
        .peer_addr()
        .map_or_else(|_| "?".to_string(), |a| a.to_string());
    let _ = stream.set_read_timeout(Some(IDLE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IDLE_TIMEOUT));
    let _ = stream.set_nodelay(true);
    let reader = match stream.try_clone() {
        Ok(r) => r,
        Err(e) => {
            log(&format!("{peer} cannot clone the socket: {e}"));
            return;
        }
    };
    if let Some(code) = serve(reader, stream, &peer, data_dir) {
        log(&format!(
            "foreign-echo: exiting with status {code} as requested"
        ));
        std::process::exit(code);
    }
}

/// Answers requests on one connection until it closes. Returns the exit
/// status asked for by `POST /exit`, once its answer has been flushed.
fn serve(read: impl Read, mut write: impl Write, peer: &str, data_dir: &Path) -> Option<i32> {
    let mut reader = BufReader::new(read);
    loop {
        let request = match http::read_request(&mut reader, MAX_BODY) {
            Ok(Some(r)) => r,
            Ok(None) | Err(ReadError::Io(_)) => return None,
            Err(ReadError::Malformed(msg)) => {
                let response = Response::json(400, format!("{{\"error\":{}}}", js(&msg)));
                log(&format!("{peer} - - 400 {msg}"));
                let _ = http::write_response(&mut write, &response, false, false);
                return None;
            }
        };
        let (response, exit) = route(&request, data_dir);
        let keep_alive = request.keep_alive && exit.is_none();
        log(&format!(
            "{peer} {} {} {} {}",
            request.method,
            request.target,
            response.status,
            response.body.len()
        ));
        let written =
            http::write_response(&mut write, &response, keep_alive, request.method == "HEAD");
        if exit.is_some() {
            return exit;
        }
        if written.is_err() || !keep_alive {
            return None;
        }
    }
}

/// Answers one request. The second value is an exit status to leave with
/// after the answer is sent.
fn route(request: &Request, data_dir: &Path) -> (Response, Option<i32>) {
    let method = request.method.as_str();
    let get = method == "GET" || method == "HEAD";
    let response = match request.path() {
        "/echo" => echo(request),
        "/healthz" if get => Response::text(200, "ok"),
        "/info" if get => info(),
        "/egress" if get => egress(request),
        "/env" if get => env(request),
        "/data" if get => data(data_dir),
        "/exit" if method == "POST" => {
            let code = request.query("code").unwrap_or_else(|| "0".into());
            return match code.parse::<i32>() {
                Ok(code @ 0..=255) => (
                    Response::json(200, format!("{{\"exit\":{code}}}")),
                    Some(code),
                ),
                _ => (bad_request("code must be an integer from 0 to 255"), None),
            };
        }
        "/healthz" | "/info" | "/egress" | "/env" | "/data" => method_not_allowed("GET, HEAD"),
        "/exit" => method_not_allowed("POST"),
        path => Response::json(
            404,
            format!(
                "{{\"error\":\"not found\",\"method\":{},\"path\":{}}}",
                js(method),
                js(path)
            ),
        ),
    };
    (response, None)
}

fn bad_request(msg: &str) -> Response {
    Response::json(400, format!("{{\"error\":{}}}", js(msg)))
}

fn method_not_allowed(allow: &str) -> Response {
    let mut r = Response::json(405, "{\"error\":\"method not allowed\"}".into());
    r.headers.push(("allow".into(), allow.into()));
    r
}

/// `/echo`: the request as JSON. Repeated headers are joined with `, `.
fn echo(request: &Request) -> Response {
    let mut headers: Vec<(&str, String)> = Vec::new();
    for (name, value) in &request.headers {
        match headers.iter_mut().find(|(n, _)| n == name) {
            Some((_, v)) => {
                v.push_str(", ");
                v.push_str(value);
            }
            None => headers.push((name, value.clone())),
        }
    }
    let headers: Vec<String> = headers
        .iter()
        .map(|(n, v)| format!("{}:{}", js(n), js(v)))
        .collect();
    Response::json(
        200,
        format!(
            "{{\"method\":{},\"path\":{},\"query\":{},\"headers\":{{{}}},\"body\":{}}}",
            js(&request.method),
            js(request.path()),
            js(request.query_string()),
            headers.join(","),
            js(&String::from_utf8_lossy(&request.body)),
        ),
    )
}

/// `/info`: what the process sees of itself and its machine.
fn info() -> Response {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    // "Uid:\t<real>\t<effective>\t..." -- the real id.
    let id = |field: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(field))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
    };
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string());
    let cwd = std::env::current_dir()
        .ok()
        .map(|d| d.to_string_lossy().into_owned());
    let cpus = thread::available_parallelism().ok().map(|n| n.get() as u64);
    let mem_total_kb = fs::read_to_string("/proc/meminfo").ok().and_then(|m| {
        m.lines()
            .find_map(|l| l.strip_prefix("MemTotal:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
    });
    let interfaces: Vec<String> = fs::read_to_string("/proc/net/dev")
        .map(|dev| interface_names(&dev))
        .unwrap_or_default()
        .iter()
        .map(|n| js(n))
        .collect();
    Response::json(
        200,
        format!(
            "{{\"pid\":{},\"uid\":{},\"gid\":{},\"hostname\":{},\"cwd\":{},\"cpus\":{},\"mem_total_kb\":{},\"interfaces\":[{}]}}",
            std::process::id(),
            num(id("Uid:")),
            num(id("Gid:")),
            js_opt(hostname.as_deref()),
            js_opt(cwd.as_deref()),
            num(cpus),
            num(mem_total_kb),
            interfaces.join(","),
        ),
    )
}

/// Interface names from `/proc/net/dev`: two header lines, then
/// `  name: counters...`.
fn interface_names(dev: &str) -> Vec<String> {
    dev.lines()
        .skip(2)
        .filter_map(|l| l.split_once(':'))
        .map(|(name, _)| name.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect()
}

/// One network attempt made by `/egress`.
struct Attempt {
    target: String,
    proto: &'static str,
    result: Result<(), String>,
}

/// `/egress`: tries TCP, UDP DNS and a resolver lookup, all in parallel, and
/// reports each outcome. Inside a Kronik sandbox every attempt should fail.
fn egress(request: &Request) -> Response {
    let extra = request.query_all("target");
    if extra.len() > MAX_EGRESS_TARGETS {
        return bad_request("too many targets");
    }
    let mut jobs: Vec<(String, &'static str)> = Vec::new();
    for target in EGRESS_TCP.iter().map(|t| t.to_string()).chain(extra) {
        jobs.push((target, "tcp"));
    }
    for server in EGRESS_UDP {
        jobs.push((server.to_string(), "udp"));
    }
    jobs.push(("example.com:443".to_string(), "dns"));

    let attempts: Vec<Attempt> = thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .into_iter()
            .map(|(target, proto)| {
                let label = target.clone();
                let spawned = thread::Builder::new().spawn_scoped(scope, move || {
                    let result = match proto {
                        "tcp" => try_tcp(&target),
                        "udp" => try_udp_dns(&target),
                        _ => try_lookup(&target),
                    };
                    Attempt {
                        target,
                        proto,
                        result,
                    }
                });
                (label, proto, spawned)
            })
            .collect();
        handles
            .into_iter()
            .map(|(target, proto, spawned)| {
                let joined = spawned
                    .map_err(|e| format!("cannot start a thread: {e}"))
                    .and_then(|h| h.join().map_err(|_| "the attempt panicked".to_string()));
                joined.unwrap_or_else(|e| Attempt {
                    target,
                    proto,
                    result: Err(e),
                })
            })
            .collect()
    });

    let succeeded = attempts.iter().filter(|a| a.result.is_ok()).count();
    let items: Vec<String> = attempts
        .iter()
        .map(|a| {
            let (ok, error) = match &a.result {
                Ok(()) => (true, "null".to_string()),
                Err(e) => (false, js(e)),
            };
            format!(
                "{{\"target\":{},\"proto\":\"{}\",\"ok\":{ok},\"error\":{error}}}",
                js(&a.target),
                a.proto
            )
        })
        .collect();
    Response::json(
        200,
        format!(
            "{{\"attempts\":[{}],\"succeeded\":{succeeded}}}",
            items.join(",")
        ),
    )
}

/// Resolves `target` (`host:port`, IP literals need no lookup) to one address.
fn resolve_one(target: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = target.parse() {
        return Ok(addr);
    }
    target
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "no address".to_string())
}

fn try_tcp(target: &str) -> Result<(), String> {
    let addr = resolve_one(target)?;
    TcpStream::connect_timeout(&addr, EGRESS_TIMEOUT)
        .map(drop)
        .map_err(|e| e.to_string())
}

/// Sends a DNS query for `example.com` A to `server` and waits for a reply
/// with the same id.
fn try_udp_dns(server: &str) -> Result<(), String> {
    let addr = resolve_one(server)?;
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    socket.connect(addr).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(EGRESS_TIMEOUT))
        .map_err(|e| e.to_string())?;
    // Header: id 0x1234, recursion desired, one question.
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    // End of name, type A, class IN.
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    socket.send(&query).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 512];
    let n = socket.recv(&mut buf).map_err(|e| e.to_string())?;
    if n < 12 || buf[..2] != [0x12, 0x34] {
        return Err(format!("unexpected {n}-byte reply"));
    }
    Ok(())
}

fn try_lookup(target: &str) -> Result<(), String> {
    let mut addrs = target.to_socket_addrs().map_err(|e| e.to_string())?;
    match addrs.next() {
        Some(_) => Ok(()),
        None => Err("no address".into()),
    }
}

/// `/env?name=X`: whether X is set, with the length and SHA-256 of its value
/// but never the value itself, so secrets can be checked without leaking.
fn env(request: &Request) -> Response {
    let Some(name) = request.query("name").filter(|n| !n.is_empty()) else {
        return bad_request("name is required");
    };
    let value = if name.contains(['=', '\0']) {
        None
    } else {
        std::env::var_os(&name)
    };
    let (len, sha) = match &value {
        Some(v) => (v.len(), js(&sha256::hex(v.as_bytes()))),
        None => (0, "null".to_string()),
    };
    Response::json(
        200,
        format!(
            "{{\"name\":{},\"set\":{},\"len\":{len},\"sha256\":{sha}}}",
            js(&name),
            value.is_some()
        ),
    )
}

/// `/data`: increments the counter in `<data_dir>/count`.
fn data(data_dir: &Path) -> Response {
    match increment(data_dir) {
        Ok(count) => Response::json(200, format!("{{\"count\":{count}}}")),
        Err(e) => Response::json(
            500,
            format!(
                "{{\"error\":{}}}",
                js(&format!("{}: {e}", data_dir.display()))
            ),
        ),
    }
}

/// Reads, increments and atomically rewrites the counter file.
fn increment(data_dir: &Path) -> io::Result<u64> {
    let _guard = DATA_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = data_dir.join("count");
    let count = match fs::read_to_string(&path) {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "count is not a number"))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e),
    };
    let count = count.saturating_add(1);
    let tmp = data_dir.join(".count.tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(format!("{count}\n").as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    Ok(count)
}

/// `s` as a JSON string literal.
fn js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn js_opt(s: Option<&str>) -> String {
    s.map_or_else(|| "null".to_string(), js)
}

fn num(n: Option<u64>) -> String {
    n.map_or_else(|| "null".to_string(), |n| n.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn run(raw: &str, data_dir: &Path) -> (String, Option<i32>) {
        let mut out = Vec::new();
        let exit = serve(
            Cursor::new(raw.as_bytes().to_vec()),
            &mut out,
            "test",
            data_dir,
        );
        (String::from_utf8(out).unwrap(), exit)
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("foreign-echo-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn keep_alive_answers_every_request_on_the_connection() {
        let (out, exit) = run(
            "GET /healthz HTTP/1.1\r\n\r\nPOST /echo HTTP/1.1\r\nContent-Length: 2\r\n\r\nhiGET /nope HTTP/1.1\r\nConnection: close\r\n\r\nGET /healthz HTTP/1.1\r\n\r\n",
            Path::new("/nonexistent"),
        );
        assert_eq!(exit, None);
        assert_eq!(out.matches("HTTP/1.1 ").count(), 3, "{out}");
        assert!(out.starts_with("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"));
        assert!(out.contains("\"body\":\"hi\""));
        // The third request asked to close: it is the last one answered.
        assert!(out.ends_with("\"path\":\"/nope\"}"));
        assert_eq!(out.matches("connection: close").count(), 1);
    }

    #[test]
    fn malformed_request_gets_400_and_close() {
        let (out, _) = run(
            "GET /healthz HTTP/1.1\r\n\r\nBROKEN\r\n\r\nGET /healthz HTTP/1.1\r\n\r\n",
            Path::new("/nonexistent"),
        );
        assert_eq!(out.matches("HTTP/1.1 ").count(), 2);
        assert!(out.contains("HTTP/1.1 400 Bad Request\r\n"));
        assert!(out.contains("connection: close"));
    }

    #[test]
    fn echo_reports_the_request() {
        let (out, _) = run(
            "PUT /echo?x=1 HTTP/1.1\r\nX-A: 1\r\nx-a: 2\r\nContent-Length: 4\r\n\r\n\"\n\u{1}\u{fffd}",
            Path::new("/nonexistent"),
        );
        // The 4 bytes are `"`, `\n`, U+0001 and the first byte of U+FFFD.
        let body = out.split("\r\n\r\n").nth(1).unwrap();
        assert_eq!(
            body,
            "{\"method\":\"PUT\",\"path\":\"/echo\",\"query\":\"x=1\",\"headers\":{\"x-a\":\"1, 2\",\"content-length\":\"4\"},\"body\":\"\\\"\\n\\u0001\u{fffd}\"}"
        );
    }

    #[test]
    fn exit_answers_then_reports_the_status() {
        let (out, exit) = run(
            "POST /exit?code=7 HTTP/1.1\r\n\r\nGET /healthz HTTP/1.1\r\n\r\n",
            Path::new("/nonexistent"),
        );
        assert_eq!(exit, Some(7));
        assert_eq!(out.matches("HTTP/1.1 ").count(), 1);
        assert!(out.contains("connection: close") && out.ends_with("{\"exit\":7}"));
        let (out, exit) = run("POST /exit?code=300 HTTP/1.1\r\n\r\n", Path::new("/x"));
        assert_eq!(exit, None);
        assert!(out.starts_with("HTTP/1.1 400"));
        let (out, exit) = run("GET /exit HTTP/1.1\r\n\r\n", Path::new("/x"));
        assert_eq!(exit, None);
        assert!(out.starts_with("HTTP/1.1 405"));
    }

    #[test]
    fn env_never_shows_the_value() {
        // PATH is set in any test environment.
        let value = std::env::var_os("PATH").unwrap();
        let (out, _) = run("GET /env?name=PATH HTTP/1.1\r\n\r\n", Path::new("/x"));
        let expected = format!(
            "{{\"name\":\"PATH\",\"set\":true,\"len\":{},\"sha256\":\"{}\"}}",
            value.len(),
            sha256::hex(value.as_bytes())
        );
        assert!(out.ends_with(&expected), "{out}");
        let (out, _) = run(
            "GET /env?name=FOREIGN_ECHO_UNSET_VAR HTTP/1.1\r\n\r\n",
            Path::new("/x"),
        );
        assert!(out.ends_with("\"set\":false,\"len\":0,\"sha256\":null}"));
        let (out, _) = run("GET /env HTTP/1.1\r\n\r\n", Path::new("/x"));
        assert!(out.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn data_counts_and_reports_errors() {
        let dir = tmp_dir("data");
        let (out, _) = run("GET /data HTTP/1.1\r\n\r\nGET /data HTTP/1.1\r\n\r\n", &dir);
        assert!(out.contains("{\"count\":1}") && out.ends_with("{\"count\":2}"));
        assert_eq!(fs::read_to_string(dir.join("count")).unwrap(), "2\n");
        let (out, _) = run("GET /data HTTP/1.1\r\n\r\n", &dir.join("missing"));
        assert!(out.starts_with("HTTP/1.1 500"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unknown_paths_are_404_json() {
        let (out, _) = run("GET /what HTTP/1.1\r\n\r\n", Path::new("/x"));
        assert!(out.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(out.contains("application/json"));
    }

    #[test]
    fn interface_names_from_proc_net_dev() {
        let dev = "Inter-|   Receive\n face |bytes\n    lo: 1 2 3\n  eth0: 4 5 6\n";
        assert_eq!(interface_names(dev), ["lo", "eth0"]);
    }

    #[test]
    fn json_escaping() {
        assert_eq!(js("a\"b\\c\u{7}é"), "\"a\\\"b\\\\c\\u0007é\"");
    }
}
