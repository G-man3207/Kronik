//! The bridge into a sandbox (docs/design/m7-foreign.md §7, ADR 0003 §3):
//! one `runsc port-forward --stream` per connection for `gvisor`, a TCP
//! connection made inside the network namespace for `trusted`, and a pool
//! of kept-alive HTTP/1.1 connections per actor.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http1::SendRequest;
use kronik_core::env::{Env, HttpRequest, HttpResponse, NetError};
use kronik_effects::foreign::unavailable;

use crate::runtime::Runtime;

/// How long the runtime may take to connect a new bridge connection.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// Idle connections kept per actor.
const MAX_IDLE: usize = 8;

type Sender = SendRequest<Full<Bytes>>;

/// How new connections into one sandbox are made.
#[derive(Debug, Clone)]
pub(crate) enum Dialer {
    PortForward {
        runtime: Runtime,
        id: String,
        port: u16,
        /// Mode 0700; one socket per connection, removed once accepted.
        sock_dir: PathBuf,
        /// The actor's `output.log`, for the helper's own messages.
        log: PathBuf,
    },
    Netns {
        netns: PathBuf,
        port: u16,
    },
}

/// Kept-alive connections of one actor.
#[derive(Default)]
pub(crate) struct Pool {
    idle: Mutex<Vec<Sender>>,
    seq: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Pool {
    /// Drops every idle connection (the sandbox restarted or stopped).
    pub fn clear(&self) {
        lock(&self.idle).clear();
    }

    pub fn put(&self, s: Sender) {
        if s.is_closed() {
            return;
        }
        let mut idle = lock(&self.idle);
        if idle.len() < MAX_IDLE {
            idle.push(s);
        }
    }

    fn take(&self) -> Option<Sender> {
        let mut idle = lock(&self.idle);
        while let Some(s) = idle.pop() {
            if !s.is_closed() {
                return Some(s);
            }
        }
        None
    }

    #[cfg(test)]
    pub fn idle(&self) -> usize {
        lock(&self.idle).len()
    }

    fn next(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }
}

/// Opens one connection into the sandbox and starts its HTTP/1.1 client.
/// An error means nothing was sent.
pub(crate) async fn dial(env: &Env, pool: &Pool, d: &Dialer) -> Result<Sender, String> {
    match d {
        Dialer::PortForward {
            runtime,
            id,
            port,
            sock_dir,
            log,
        } => {
            let sock = sock_dir.join(format!("c{}.sock", pool.next()));
            let _ = std::fs::remove_file(&sock);
            let listener = tokio::net::UnixListener::bind(&sock)
                .map_err(|e| format!("binding {}: {e}", sock.display()))?;
            let result = port_forward(env, runtime, &listener, &sock, id, *port, log).await;
            let _ = std::fs::remove_file(&sock);
            let stream = result?;
            handshake(env, stream).await
        }
        Dialer::Netns { netns, port } => {
            let (netns, port) = (netns.clone(), *port);
            let std_stream = env
                .blocking("foreign-dial", move || {
                    crate::sys::connect_in_netns(&netns, port, DIAL_TIMEOUT)
                })
                .await
                .ok_or("the dial task was dropped")?
                .map_err(|e| format!("connecting to port {port}: {e}"))?;
            std_stream
                .set_nonblocking(true)
                .map_err(|e| e.to_string())?;
            let stream = tokio::net::TcpStream::from_std(std_stream).map_err(|e| e.to_string())?;
            handshake(env, stream).await
        }
    }
}

/// Runs `runsc port-forward --stream` against `listener` and returns the
/// connection once the helper has handed it to the sandbox: runsc connects
/// to the socket first and only then to the port inside, exiting 0 on
/// success and non-zero (closing the socket) when nothing listens there.
async fn port_forward(
    env: &Env,
    runtime: &Runtime,
    listener: &tokio::net::UnixListener,
    sock: &std::path::Path,
    id: &str,
    port: u16,
    log: &std::path::Path,
) -> Result<tokio::net::UnixStream, String> {
    let helper = env
        .procs
        .spawn(runtime.port_forward(sock, id, port, log))
        .await
        .map_err(|e| format!("starting runsc port-forward: {e}"))?;
    let accepted = env
        .timeout(DIAL_TIMEOUT, async {
            tokio::select! {
                biased;
                r = listener.accept() => Ok(r),
                status = helper.wait() => Err(status),
            }
        })
        .await;
    let stream = match accepted {
        Ok(Ok(Ok((stream, _)))) => stream,
        Ok(Ok(Err(e))) => {
            let _ = helper.kill().await;
            let _ = helper.wait().await;
            return Err(format!("accepting the port-forward connection: {e}"));
        }
        Ok(Err(status)) => {
            return Err(format!(
                "runsc port-forward exited with {} before connecting",
                describe(status)
            ));
        }
        Err(_) => {
            let _ = helper.kill().await;
            let _ = helper.wait().await;
            return Err(format!(
                "runsc port-forward did not connect within {} s",
                DIAL_TIMEOUT.as_secs()
            ));
        }
    };
    match env.timeout(DIAL_TIMEOUT, helper.wait()).await {
        Ok(Ok(Some(0))) => Ok(stream),
        Ok(status) => Err(format!(
            "nothing accepted the connection on port {port} (runsc port-forward exited with {})",
            describe(status)
        )),
        Err(_) => {
            let _ = helper.kill().await;
            let _ = helper.wait().await;
            Err("runsc port-forward did not finish handing over the connection".into())
        }
    }
}

fn describe(status: std::io::Result<Option<i32>>) -> String {
    match status {
        Ok(Some(c)) => format!("status {c}"),
        Ok(None) => "a signal".into(),
        Err(e) => format!("an error ({e})"),
    }
}

async fn handshake<T>(env: &Env, io: T) -> Result<Sender, String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
        .await
        .map_err(|e| format!("HTTP handshake: {e}"))?;
    env.spawn("foreign-conn", async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "foreign connection closed");
        }
    });
    Ok(sender)
}

/// The origin-form target (`/path?query`) of a `foreign://<name>/...` URL.
fn origin_form(url: &str) -> Result<String, String> {
    let uri: http::Uri = url
        .parse()
        .map_err(|e| format!("invalid URL {url:?}: {e}"))?;
    Ok(uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |pq| pq.as_str().to_owned()))
}

/// Headers Kronik sets itself or that belong to one connection.
fn hop_by_hop(name: &str) -> bool {
    name.eq_ignore_ascii_case("host") || kronik_core::http::hop_by_hop(name)
}

fn build(name: &str, req: &HttpRequest) -> Result<hyper::Request<Full<Bytes>>, String> {
    let mut b = hyper::Request::builder()
        .method(req.method.as_str())
        .uri(origin_form(&req.url)?)
        .header(http::header::HOST, name);
    for (n, v) in req.headers.iter().filter(|(n, _)| !hop_by_hop(n)) {
        b = b.header(n.as_str(), v.as_str());
    }
    b.body(Full::new(req.body.clone()))
        .map_err(|e| format!("invalid request: {e}"))
}

/// Sends one request: on an idle connection if one is left (a request the
/// connection never took is retried elsewhere), else on a new one. Errors
/// follow I17: `Connect` only when the request was certainly not sent.
pub(crate) async fn send(
    env: &Env,
    pool: &Pool,
    dialer: &Dialer,
    name: &str,
    req: HttpRequest,
) -> Result<HttpResponse, NetError> {
    let max = req.max_response_bytes;
    let mut request = build(name, &req).map_err(|e| unavailable(name, &e))?;
    loop {
        let Some(mut s) = pool.take() else { break };
        if s.ready().await.is_err() {
            continue;
        }
        match s.try_send_request(request).await {
            Ok(resp) => return finish(pool, s, resp, max).await,
            Err(mut e) => match e.take_message() {
                Some(back) => request = back,
                None => return Err(NetError::Io(e.into_error().to_string())),
            },
        }
    }
    let mut s = dial(env, pool, dialer)
        .await
        .map_err(|e| unavailable(name, &e))?;
    match s.try_send_request(request).await {
        Ok(resp) => finish(pool, s, resp, max).await,
        Err(mut e) => {
            let sent = e.take_message().is_none();
            let msg = e.into_error().to_string();
            Err(if sent {
                NetError::Io(msg)
            } else {
                unavailable(name, &msg)
            })
        }
    }
}

async fn finish(
    pool: &Pool,
    sender: Sender,
    resp: hyper::Response<hyper::body::Incoming>,
    max: u64,
) -> Result<HttpResponse, NetError> {
    let status = resp.status().as_u16();
    let close = resp
        .headers()
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("close"));
    let headers = resp
        .headers()
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let limit = usize::try_from(max).unwrap_or(usize::MAX);
    let body = Limited::new(resp.into_body(), limit)
        .collect()
        .await
        .map_err(|e| {
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                NetError::TooLarge
            } else {
                NetError::Io(e.to_string())
            }
        })?
        .to_bytes();
    if !close {
        pool.put(sender);
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
// Test harness: a std-thread HTTP server.
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn requests_target_the_path_with_the_actor_as_host() {
        assert_eq!(
            origin_form("foreign://echo/v1/x?a=1&b=2").unwrap(),
            "/v1/x?a=1&b=2"
        );
        assert_eq!(origin_form("foreign://echo").unwrap(), "/");
        let req = HttpRequest {
            method: "POST".into(),
            url: "foreign://payments.internal/v1/charges".into(),
            headers: vec![
                ("Host".into(), "evil".into()),
                ("content-type".into(), "application/json".into()),
                ("idempotency-key".into(), "k".into()),
                ("Connection".into(), "close".into()),
            ],
            body: Bytes::from_static(b"{}"),
            max_response_bytes: 10,
        };
        let r = build("payments.internal", &req).unwrap();
        assert_eq!(r.uri(), "/v1/charges");
        assert_eq!(r.headers()["host"], "payments.internal");
        assert_eq!(r.headers().get_all("host").iter().count(), 1);
        assert_eq!(r.headers()["idempotency-key"], "k");
        assert!(r.headers().get("connection").is_none());
    }

    /// A kept-alive HTTP/1.1 test server: answers `<request line> <body>`.
    fn test_server(accepts: std::sync::Arc<AtomicU64>) -> std::net::SocketAddr {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                accepts.fetch_add(1, Ordering::SeqCst);
                let mut conn = conn.unwrap();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(conn.try_clone().unwrap());
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let mut len = 0usize;
                        loop {
                            let mut h = String::new();
                            reader.read_line(&mut h).unwrap();
                            if h == "\r\n" {
                                break;
                            }
                            let lower = h.to_ascii_lowercase();
                            if let Some(v) = lower.strip_prefix("content-length:") {
                                len = v.trim().parse().unwrap();
                            }
                        }
                        let mut body = vec![0; len];
                        reader.read_exact(&mut body).unwrap();
                        let out = format!("{} {}", line.trim(), String::from_utf8_lossy(&body));
                        write!(
                            conn,
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{out}",
                            out.len()
                        )
                        .unwrap();
                    }
                });
            }
        });
        addr
    }

    fn request(url: &str, body: &[u8], max: u64) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            url: url.into(),
            headers: vec![],
            body: Bytes::copy_from_slice(body),
            max_response_bytes: max,
        }
    }

    /// The pool and the HTTP exchange over a plain TCP server (the real
    /// dialers are exercised by the integration tests).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pool_reuses_kept_alive_connections() {
        let accepts = std::sync::Arc::new(AtomicU64::new(0));
        let addr = test_server(accepts.clone());
        let env = Env::real(tokio::runtime::Handle::current());
        let pool = Pool::default();
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        pool.put(handshake(&env, stream).await.unwrap());
        // A dialer that cannot work: the idle connection must serve all.
        let dialer = Dialer::Netns {
            netns: "/nonexistent".into(),
            port: 1,
        };
        for i in 0..3 {
            let url = format!("foreign://echo/x?i={i}");
            let resp = send(&env, &pool, &dialer, "echo", request(&url, b"body", 1024))
                .await
                .unwrap();
            assert_eq!(resp.status, 200);
            assert_eq!(
                String::from_utf8_lossy(&resp.body),
                format!("POST /x?i={i} HTTP/1.1 body")
            );
        }
        assert_eq!(pool.idle(), 1);
        assert_eq!(accepts.load(Ordering::SeqCst), 1);
        let big = request("foreign://echo/", &[b'x'; 100], 10);
        let err = send(&env, &pool, &dialer, "echo", big).await.unwrap_err();
        assert_eq!(err, NetError::TooLarge);
        // No idle connection and a failing dialer: nothing was sent.
        pool.clear();
        let small = request("foreign://echo/", b"", 10);
        let err = send(&env, &pool, &dialer, "echo", small).await.unwrap_err();
        assert!(
            matches!(&err, NetError::Connect(m) if m.starts_with("FOREIGN_UNAVAILABLE: echo:")),
            "{err:?}"
        );
    }
}
