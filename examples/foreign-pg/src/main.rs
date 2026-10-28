//! foreign-pg: Postgres behind a small HTTP/1.1 shim, a foreign actor for
//! Kronik's fork tests (docs/design/m14-foreign-forks.md §7). It starts the
//! image's `docker-entrypoint.sh postgres` (data in `$PGDATA`, under the
//! bind-mounted `/data`), waits until Postgres answers on 127.0.0.1, then
//! serves:
//!
//! ```text
//! GET  /healthz   200 "ok"
//! POST /sql       the body run by psql (-At, fields separated by |):
//!                 200 with its output, 400 with its error
//! GET  /egress    whether 1.1.1.1:443 can be reached from here
//! ```
//!
//! One thread per connection, keep-alive with `Content-Length` bodies.

// Shared with foreign-echo, which uses all of it.
#[allow(dead_code)]
mod http;

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use http::{ReadError, Request, Response};

const MAX_BODY: usize = 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long Postgres may take to initialize and start.
const START_TIMEOUT: Duration = Duration::from_secs(180);

fn log(msg: &str) {
    println!("foreign-pg: {msg}");
}

/// Runs `sql` with psql against the local server.
fn psql(sql: &str) -> Result<String, String> {
    let out = Command::new("psql")
        .args([
            "-h",
            "127.0.0.1",
            "-U",
            "postgres",
            "-X",
            "-q",
            "-At",
            "-F",
            "|",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("psql: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

fn main() {
    let listen: SocketAddr = std::env::args()
        .skip_while(|a| a != "--listen")
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8080)));
    // Postgres: the image's entrypoint initializes $PGDATA and starts it.
    let mut server = match Command::new("docker-entrypoint.sh")
        .arg("postgres")
        .stdin(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            log(&format!("cannot start postgres: {e}"));
            std::process::exit(1);
        }
    };
    let started = Instant::now();
    // The entrypoint's initialization server listens on a Unix socket
    // only; TCP on 127.0.0.1 answers once the real server runs.
    while psql("SELECT 1").is_err() {
        if let Ok(Some(status)) = server.try_wait() {
            log(&format!("postgres exited: {status}"));
            std::process::exit(1);
        }
        if started.elapsed() > START_TIMEOUT {
            log("postgres did not start");
            std::process::exit(1);
        }
        thread::sleep(Duration::from_millis(200));
    }
    log(&format!(
        "postgres ready after {} ms",
        started.elapsed().as_millis()
    ));
    let listener = match TcpListener::bind(listen) {
        Ok(l) => l,
        Err(e) => {
            log(&format!("cannot listen on {listen}: {e}"));
            std::process::exit(1);
        }
    };
    log(&format!("listening on {listen}"));
    thread::spawn(move || {
        let status = server.wait();
        log(&format!("postgres exited: {status:?}"));
        std::process::exit(1);
    });
    for stream in listener.incoming().flatten() {
        thread::spawn(move || handle_connection(stream));
    }
}

fn handle_connection(stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(IDLE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IDLE_TIMEOUT));
    let _ = stream.set_nodelay(true);
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    serve(reader, stream);
}

fn serve(read: impl Read, mut write: impl Write) {
    let mut reader = BufReader::new(read);
    loop {
        let request = match http::read_request(&mut reader, MAX_BODY) {
            Ok(Some(r)) => r,
            Ok(None) | Err(ReadError::Io(_)) => return,
            Err(ReadError::Malformed(msg)) => {
                let _ = http::write_response(&mut write, &Response::text(400, &msg), false, false);
                return;
            }
        };
        let response = route(&request);
        log(&format!(
            "{} {} {}",
            request.method, request.target, response.status
        ));
        let keep_alive = request.keep_alive;
        let written =
            http::write_response(&mut write, &response, keep_alive, request.method == "HEAD");
        if written.is_err() || !keep_alive {
            return;
        }
    }
}

fn route(request: &Request) -> Response {
    match (request.method.as_str(), request.path()) {
        ("GET" | "HEAD", "/healthz") => Response::text(200, "ok"),
        ("POST", "/sql") => {
            let sql = String::from_utf8_lossy(&request.body);
            match psql(&sql) {
                Ok(out) => Response::text(200, &out),
                Err(e) => Response::text(400, &e),
            }
        }
        ("GET", "/egress") => {
            let target = SocketAddr::from(([1, 1, 1, 1], 443));
            match TcpStream::connect_timeout(&target, Duration::from_secs(2)) {
                Ok(_) => Response::text(200, "reachable"),
                Err(e) => Response::text(200, &format!("unreachable: {e}")),
            }
        }
        _ => Response::text(404, "not found"),
    }
}
