//! A minimal HTTP/1.1 client for the JSON API: on the daemon's Unix socket,
//! or over TCP (M10) to `https://host:port`, or plain `http://` to a
//! loopback address only. Each request uses its own connection
//! (`Connection: close`); hyper speaks HTTP/1.1 over the connected Unix, TCP
//! or TLS stream. Ordinary JSON responses are read to the end within a
//! timeout; SSE uses the same transport with incremental bounded decoding.

use std::error::Error as _;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;

/// Where the API is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Unix(PathBuf),
    Tcp { host: String, port: u16, tls: bool },
}

impl Endpoint {
    /// `https://host:port[/]`, or `http://` to a loopback host. Anything
    /// else (no port, a path, a query, user info, another scheme) is
    /// refused. Messages name only the scheme and the host, never user info.
    pub fn parse_url(url: &str) -> Result<Endpoint, String> {
        let shown = redacted(url);
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else if url
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
            || url
                .get(..7)
                .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
        {
            return Err(format!(
                "{shown}: write the scheme in lower case, https:// (or http:// to this machine)"
            ));
        } else {
            return Err(format!("{shown} is not an https:// URL"));
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
            return Err(format!(
                "{shown} must be only a scheme, a host and a port, such as https://kronik.example.com:7443"
            ));
        }
        let (host, port) = match rest.strip_prefix('[') {
            Some(v6) => {
                let (host, after) = v6
                    .split_once(']')
                    .ok_or_else(|| format!("{shown} has an unclosed [ in its host"))?;
                match after {
                    "" => (host, None),
                    _ => (
                        host,
                        Some(after.strip_prefix(':').ok_or_else(|| {
                            format!("{shown} has something other than :<port> after its [host]")
                        })?),
                    ),
                }
            }
            None => match rest.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (rest, None),
            },
        };
        if host.is_empty() {
            return Err(format!("{shown} has no host"));
        }
        if !tls && !is_loopback(host) {
            return Err(format!(
                "{shown} is plain HTTP to a host that is not this machine: the token would cross the network in the clear"
            ));
        }
        // No default port: 443 or 80 is usually the gateway, which would
        // record the token with the request.
        let Some(port) = port else {
            return Err(format!(
                "{shown} has no port: add the port of the daemon's server.api_listen, such as {shown}:7443"
            ));
        };
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("{shown} has an invalid port"))?;
        Ok(Endpoint::Tcp {
            host: host.to_ascii_lowercase(),
            port,
            tls,
        })
    }

    /// The endpoint as a user names it.
    pub fn shown(&self) -> String {
        match self {
            Endpoint::Unix(path) => path.display().to_string(),
            Endpoint::Tcp { host, port, tls } => {
                let scheme = if *tls { "https" } else { "http" };
                if host.contains(':') {
                    format!("{scheme}://[{host}]:{port}")
                } else {
                    format!("{scheme}://{host}:{port}")
                }
            }
        }
    }
}

/// A URL for messages: its scheme and host (and port), never user info, a
/// path or a query; nothing of a string without a scheme, which may be a
/// misplaced secret.
fn redacted(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "the URL".to_owned();
    };
    // After the last `@`: user info may itself hold `/`, `?` or `#`.
    let host = rest.rsplit('@').next().unwrap_or_default();
    let host = host.split(['/', '?', '#']).next().unwrap_or_default();
    format!("{scheme}://{host}")
}

/// `localhost`, or a loopback IP address.
fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The addresses to dial without asking a resolver: `localhost` is always
/// [::1] then 127.0.0.1 (RFC 6761), an IP address is itself; `None` for a
/// name to resolve.
fn fixed_addrs(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    if host.eq_ignore_ascii_case("localhost") {
        return Some(vec![
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ]);
    }
    host.parse::<IpAddr>()
        .ok()
        .map(|ip| vec![SocketAddr::from((ip, port))])
}

/// The longest a connection may take to be made.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Connects to the first address that answers within `timeout` (at most
/// [`CONNECT_TIMEOUT`]). Plain HTTP only ever dials loopback addresses.
/// Connects to the API socket at `path`.
///
/// As root, a socket in a directory that another user controls is not
/// connected to by path: a nonroot installation's `/run/kronik` belongs to
/// its service user, who could put a link to another of the host's sockets,
/// a FIFO or a listener of its own in place of the daemon's socket, and root
/// would connect with its own authority (and send its token). So root
/// reaches the directory from `/` without following a link that root did not
/// make and only through directories that root controls, opens the entry
/// without following a link, requires a socket that the directory's owner
/// made, connects to exactly that inode, and requires that owner at the
/// other end (`SO_PEERCRED`); anything else is refused, with the reason. The
/// daemon's own socket passes: its user owns the directory, made the socket
/// and serves it. A socket in a directory that only root controls, and every
/// connection of another user, is made by path as before.
pub(crate) fn connect_unix(path: &Path) -> io::Result<UnixStream> {
    if kronik_foreign::sys::is_root() {
        connect_unix_as_root(path)
    } else {
        UnixStream::connect(path)
    }
}

fn connect_unix_as_root(path: &Path) -> io::Result<UnixStream> {
    use kronik_foreign::sys;
    let refused = |why: String| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing, as root, to connect to the API socket {}: {why}",
                path.display()
            ),
        )
    };
    // A missing socket stays "not found": no daemon there is an answer.
    let refuse = |e: io::Error| {
        if e.kind() == io::ErrorKind::NotFound {
            e
        } else {
            refused(e.to_string())
        }
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| refused("it has no plain file name".into()))?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let dir = sys::open_socket_directory(parent).map_err(refuse)?;
    if dir.root_controlled {
        return UnixStream::connect(path);
    }
    let entry = sys::open_socket_entry_at(&dir.fd, name, dir.owner).map_err(refuse)?;
    let stream = UnixStream::connect(sys::fd_path(&entry))?;
    let peer = sys::peer_uid(&stream)?;
    if peer != dir.owner {
        return Err(refused(format!(
            "it is served by uid {peer}, not by uid {}, who owns its directory",
            dir.owner
        )));
    }
    Ok(stream)
}

fn connect(host: &str, port: u16, tls: bool, timeout: Duration) -> io::Result<TcpStream> {
    let timeout = timeout.min(CONNECT_TIMEOUT);
    let addrs = match fixed_addrs(host, port) {
        Some(addrs) => addrs,
        None => (host, port).to_socket_addrs()?.collect(),
    };
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address"));
    for addr in addrs {
        if !tls && !addr.ip().is_loopback() {
            last = io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{addr} is not a loopback address"),
            );
            continue;
        }
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// A response from the API.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why a request produced no response.
#[derive(Debug)]
pub enum Failure {
    /// The endpoint could not be connected to.
    Connect(io::Error),
    /// TLS could not be set up: no trusted roots, or the handshake failed
    /// (an untrusted or mismatched certificate). Retrying does not help.
    Tls(String),
    /// The connection broke while the request or the response was in
    /// flight, or closed before the response's Content-Length.
    Io(io::Error),
    /// The daemon sent nothing for as long as the request may take.
    Timeout,
    /// The reply is not an HTTP/1.1 response.
    Malformed(String),
}

/// A read or write that ran into the socket's timeout.
fn timed_out(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// The client TLS configuration with the system's root certificates
/// (`SSL_CERT_FILE` and `SSL_CERT_DIR` are honoured), loaded once per process.
static TLS: LazyLock<Result<Arc<rustls::ClientConfig>, String>> = LazyLock::new(|| {
    let found = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(found.certs);
    if added == 0 {
        return Err(
            "no trusted root certificates were found (set SSL_CERT_FILE to a CA bundle)".to_owned(),
        );
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map(|b| Arc::new(b.with_root_certificates(roots).with_no_client_auth()))
        .map_err(|e| e.to_string())
});

fn tls_config() -> Result<Arc<rustls::ClientConfig>, Failure> {
    TLS.clone().map_err(Failure::Tls)
}

/// A connected stream hyper speaks HTTP/1.1 over.
trait Transport: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T> Transport for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

/// Connects the endpoint and hands hyper the stream. The TCP connect is
/// bounded by `timeout`; the TLS handshake by `deadline`, and it completes
/// before any request is sent, so a certificate problem is reported as one
/// and not as a broken connection (ADR 0021).
async fn connect_transport(
    endpoint: &Endpoint,
    timeout: Duration,
    deadline: tokio::time::Instant,
) -> Result<Box<dyn Transport>, Failure> {
    match endpoint {
        Endpoint::Unix(path) => {
            let socket = connect_unix(path).map_err(Failure::Connect)?;
            // tokio registers the socket with its reactor: nonblocking only.
            socket.set_nonblocking(true).map_err(Failure::Io)?;
            Ok(Box::new(
                tokio::net::UnixStream::from_std(socket).map_err(Failure::Io)?,
            ))
        }
        Endpoint::Tcp { host, port, tls } => {
            let socket = connect(host, *port, *tls, timeout).map_err(Failure::Connect)?;
            socket.set_nonblocking(true).map_err(Failure::Io)?;
            let stream = tokio::net::TcpStream::from_std(socket).map_err(Failure::Io)?;
            if !tls {
                return Ok(Box::new(stream));
            }
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|e| Failure::Tls(format!("{host:?} is not a TLS server name: {e}")))?;
            let connector = tokio_rustls::TlsConnector::from(tls_config()?);
            let tls = tokio::time::timeout_at(deadline, connector.connect(name, stream))
                .await
                .map_err(|_| Failure::Timeout)?
                .map_err(tls_failure)?;
            Ok(Box::new(tls))
        }
    }
}

/// rustls reports its own errors (an untrusted or mismatched certificate, a
/// peer that does not speak TLS) as InvalidData; any other error is the
/// transport's.
fn tls_failure(e: io::Error) -> Failure {
    if e.kind() == io::ErrorKind::InvalidData {
        Failure::Tls(e.to_string())
    } else {
        Failure::Io(e)
    }
}

/// Why hyper produced no response: a reply that is not HTTP/1.1 is
/// Malformed; a connection that ended before the response is Io.
fn http_failure(e: hyper::Error) -> Failure {
    if e.is_parse() || e.is_parse_too_large() {
        return Failure::Malformed(format!("the daemon's response is not valid HTTP/1.1: {e}"));
    }
    if e.is_incomplete_message() || e.is_closed() || e.is_canceled() {
        return Failure::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "closed without a response",
        ));
    }
    if e.is_timeout() {
        return Failure::Timeout;
    }
    match e
        .source()
        .and_then(|cause| cause.downcast_ref::<io::Error>())
    {
        Some(cause) if timed_out(cause) => Failure::Timeout,
        Some(cause) => Failure::Io(io::Error::new(cause.kind(), cause.to_string())),
        None => Failure::Io(io::Error::other(e.to_string())),
    }
}

/// A body that stops early is a broken connection, not a reply (N4).
fn body_error(_broken: hyper::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the response ended before it was complete",
    )
}

/// The host of the `Host` field: the socket's name, or the URL's host and
/// port.
fn host_of(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Unix(_) => "kronik".to_owned(),
        Endpoint::Tcp { .. } => endpoint
            .shown()
            .split_once("://")
            .map_or_else(String::new, |(_, host)| host.to_owned()),
    }
}

/// Cursor text is opaque, but must remain one bounded HTTP field value.
fn event_cursor(cursor: Option<&str>) -> Result<Option<&str>, Failure> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    if cursor.is_empty()
        || cursor.len() > kronik_fleet::events::MAX_CURSOR_BYTES
        || !cursor
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(Failure::Malformed(
            "invalid event resume cursor header".into(),
        ));
    }
    Ok(Some(cursor))
}

/// One request over one connection: `Connection: close`, JSON or SSE. The
/// `target` is the already-encoded path and query; `bearer` is sent as
/// `Authorization: Bearer`; the cursor as Last-Event-ID, never interpolated
/// into the target.
fn build_request(
    method: &str,
    target: &str,
    accept: &str,
    body: &[u8],
    bearer: Option<&str>,
    cursor: Option<&str>,
    host: &str,
) -> Result<hyper::Request<Full<Bytes>>, Failure> {
    use hyper::header::{ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST};
    let invalid = |what: &str| Failure::Malformed(format!("invalid {what}"));
    let mut build = hyper::Request::builder()
        .method(
            hyper::Method::from_bytes(method.as_bytes()).map_err(|_| invalid("request method"))?,
        )
        .uri(target)
        .header(HOST, host)
        .header(ACCEPT, accept)
        .header(CONNECTION, "close")
        .header(CONTENT_LENGTH, body.len() as u64);
    if !body.is_empty() {
        build = build.header(CONTENT_TYPE, "application/json");
    }
    if let Some(token) = bearer {
        build = build.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(cursor) = cursor {
        build = build.header(
            hyper::header::HeaderName::from_static("last-event-id"),
            cursor,
        );
    }
    build
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|_| invalid("request target"))
}

/// Sends one request and reads the response. `target` is the path and
/// query, already encoded; `bearer` is sent as `Authorization: Bearer`.
/// `last_event_id` is an opaque bounded event cursor, sent as Last-Event-ID,
/// never interpolated into the request target.
/// `timeout` bounds the connect and every read and write: a daemon that
/// stays silent that long is a [`Failure::Timeout`].
// The remote-mode client runs on the operator's terminal, not the daemon:
// the runtime and its timeouts are the client's own transport concerns
// (ADR 0004 governs the daemon's Env, which a client does not have).
#[allow(clippy::disallowed_methods)]
pub fn request(
    endpoint: &Endpoint,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
    last_event_id: Option<&str>,
    timeout: Duration,
) -> Result<Response, Failure> {
    // A zero timeout still bounds every step.
    let timeout = timeout.max(Duration::from_millis(1));
    let body = body.unwrap_or_default();
    let request = build_request(
        method,
        target,
        "application/json",
        body,
        bearer,
        event_cursor(last_event_id)?,
        &host_of(endpoint),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            Failure::Io(io::Error::other(format!(
                "starting the client runtime failed: {e}"
            )))
        })?;
    runtime.block_on(async {
        let transport = connect_transport(
            endpoint,
            timeout,
            tokio::time::Instant::from_std(Instant::now() + timeout),
        )
        .await?;
        let (mut sender, connection) = hyper_handshake(transport).await?;
        let _driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = tokio::time::timeout(timeout, sender.send_request(request))
            .await
            .map_err(|_| Failure::Timeout)?
            .map_err(http_failure)?;
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut collected = Vec::new();
        loop {
            match tokio::time::timeout(timeout, body.frame()).await {
                Err(_) => return Err(Failure::Timeout),
                Ok(None) => break,
                Ok(Some(Err(e))) => return Err(Failure::Io(body_error(e))),
                Ok(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        collected.extend_from_slice(&data);
                    }
                }
            }
        }
        drop(sender);
        Ok(Response {
            status,
            body: collected,
        })
    })
}

/// The hyper HTTP/1.1 client handshake. The response head stays bounded, as
/// the client's own parser bounded it before.
async fn hyper_handshake(
    transport: Box<dyn Transport>,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        hyper::client::conn::http1::Connection<TokioIo<Box<dyn Transport>>, Full<Bytes>>,
    ),
    Failure,
> {
    hyper::client::conn::http1::Builder::new()
        .max_buf_size(65536)
        .handshake(TokioIo::new(transport))
        .await
        .map_err(|e| Failure::Io(io::Error::other(format!("the HTTP connection failed: {e}"))))
}

/// An incremental response: reading the body applies HTTP transfer framing.
pub(super) struct StreamResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Box<dyn Read + Send>,
}

/// Opens the same Unix/TLS API transport as ordinary requests, without buffering
/// an unbounded event stream. Cancellation interrupts idle waits. Resume
/// cursors use the standard Last-Event-ID header, not the URI.
/// CONNECT_TIMEOUT bounds TLS, the request and the response headers; only a
/// successful SSE body may remain idle indefinitely, still watching
/// cancellation.
// The remote-mode client runs on the operator's terminal, not the daemon:
// wall-clock deadlines and raw threads are the client's own transport
// concerns (ADR 0004 governs the daemon's Env, which a client does not have).
pub(super) fn stream(
    endpoint: &Endpoint,
    target: &str,
    bearer: Option<&str>,
    last_event_id: Option<&str>,
    cancelled: Arc<AtomicBool>,
) -> Result<StreamResponse, Failure> {
    stream_with_opening(
        endpoint,
        target,
        bearer,
        last_event_id,
        cancelled,
        CONNECT_TIMEOUT,
    )
}

/// The opening result a stream's pump thread reports.
type Opening = Result<(u16, Option<String>), Failure>;

fn stream_with_opening(
    endpoint: &Endpoint,
    target: &str,
    bearer: Option<&str>,
    last_event_id: Option<&str>,
    cancelled: Arc<AtomicBool>,
    opening: Duration,
) -> Result<StreamResponse, Failure> {
    // Targets are built from constant paths and encoded query values, never
    // raw input, and the cursor is a bounded field value: refusals happen
    // before a socket opens.
    if target.bytes().any(|b| b <= b' ' || b == 127)
        || bearer.is_some_and(|token| !token.bytes().all(|b| b.is_ascii_graphic()))
    {
        return Err(Failure::Malformed("invalid streaming request".into()));
    }
    let request = build_request(
        "GET",
        target,
        "text/event-stream",
        &[],
        bearer,
        event_cursor(last_event_id)?,
        &host_of(endpoint),
    )?;
    let (opened, receipt) = std::sync::mpsc::channel::<Opening>();
    let (blocks, body) = tokio::sync::mpsc::channel::<io::Result<Bytes>>(8);
    let endpoint = endpoint.clone();
    let stop = cancelled.clone();
    let worker = std::thread::Builder::new()
        .name("kronik-events".to_owned())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                let _ = opened.send(Err(Failure::Io(io::Error::other(
                    "starting the client runtime failed",
                ))));
                return;
            };
            runtime.block_on(pump(&endpoint, request, stop, opened, blocks, opening));
        })
        .map_err(|e| {
            Failure::Io(io::Error::other(format!(
                "starting the event stream reader failed: {e}"
            )))
        })?;
    // The pump thread runs until the body ends; the reader owns the stream.
    drop(worker);
    let (status, content_type) = receipt.recv().map_err(|_| {
        Failure::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the event stream reader stopped",
        ))
    })??;
    Ok(StreamResponse {
        status,
        content_type,
        body: Box::new(ChannelBody {
            blocks: body,
            cancelled,
            pending: Bytes::new(),
        }),
    })
}

/// Reads one response over the transport, reports the head to the waiting
/// caller, then forwards the body to [`ChannelBody`] until it ends, the
/// caller cancels, or the opening deadline (which only an API error body, a
/// non-SSE or failed response, still meets) elapses.
// The SSE reader's wall-clock deadline is the client's own transport
// concern, not ADR 0004's Env (this runs on the operator's terminal).
#[allow(clippy::disallowed_methods)]
async fn pump(
    endpoint: &Endpoint,
    request: hyper::Request<Full<Bytes>>,
    cancelled: Arc<AtomicBool>,
    opened: std::sync::mpsc::Sender<Opening>,
    blocks: tokio::sync::mpsc::Sender<io::Result<Bytes>>,
    opening: Duration,
) {
    let started = Instant::now();
    let (status, content_type, body) = match open_head(endpoint, request, &cancelled, opening).await
    {
        Ok(head) => head,
        Err(failure) => {
            let _ = opened.send(Err(failure));
            return;
        }
    };
    // API error bodies retain the opening deadline instead of hanging at
    // startup; a successful SSE body may idle indefinitely.
    let deadline = (!is_live_sse(status, content_type.as_deref())).then(|| started + opening);
    if opened.send(Ok((status, content_type))).is_err() {
        return;
    }
    forward(body, blocks, &cancelled, deadline).await;
}

/// A successful SSE response: the only body allowed to idle indefinitely.
fn is_live_sse(status: u16, content_type: Option<&str>) -> bool {
    (200..300).contains(&status)
        && content_type.is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}

/// Connects and reads one streamed response's head, watching cancellation.
// Wall-clock deadlines and the spawned connection driver are the client's
// own transport concerns, not ADR 0004's Env (ADR 0004 governs the daemon).
#[allow(clippy::disallowed_methods)]
async fn open_head(
    endpoint: &Endpoint,
    request: hyper::Request<Full<Bytes>>,
    cancelled: &AtomicBool,
    opening: Duration,
) -> Result<(u16, Option<String>, Incoming), Failure> {
    let deadline = tokio::time::Instant::from_std(Instant::now() + opening);
    let mut check = tokio::time::interval(Duration::from_millis(250));
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut connecting = std::pin::pin!(async {
        let transport = connect_transport(endpoint, CONNECT_TIMEOUT, deadline).await?;
        let (mut sender, connection) = hyper_handshake(transport).await?;
        let _driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = tokio::time::timeout_at(deadline, sender.send_request(request))
            .await
            .map_err(|_| Failure::Timeout)?
            .map_err(http_failure)?;
        // Fail closed where hyper is more permissive than the client's own
        // parser was: both framings at once (hyper would silently prefer
        // chunked), and any transfer coding but chunked, which the API never
        // sends.
        let framing = response.headers();
        if framing.contains_key(hyper::header::CONTENT_LENGTH)
            && framing.contains_key(hyper::header::TRANSFER_ENCODING)
        {
            return Err(Failure::Malformed(
                "ambiguous streaming response framing".into(),
            ));
        }
        if framing
            .get(hyper::header::TRANSFER_ENCODING)
            .is_some_and(|coding| {
                !coding
                    .to_str()
                    .is_ok_and(|coding| coding.eq_ignore_ascii_case("chunked"))
            })
        {
            return Err(Failure::Malformed(
                "unsupported streaming response transfer coding".into(),
            ));
        }
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        Ok((status, content_type, response.into_body()))
    });
    loop {
        tokio::select! {
            biased;
            _ = check.tick() => {
                if cancelled.load(Ordering::Relaxed) {
                    return Err(Failure::Io(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "event tail cancelled",
                    )));
                }
            }
            result = &mut connecting => return result,
        }
    }
}

/// Forwards the body one bounded block at a time, so a slow consumer applies
/// backpressure to the daemon. Cancellation ends the stream at once.
#[allow(clippy::disallowed_methods)]
async fn forward(
    mut body: Incoming,
    blocks: tokio::sync::mpsc::Sender<io::Result<Bytes>>,
    cancelled: &AtomicBool,
    deadline: Option<Instant>,
) {
    let mut check = tokio::time::interval(Duration::from_millis(250));
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pending = None;
    loop {
        tokio::select! {
            biased;
            _ = check.tick() => {
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
                if deadline.is_some_and(|at| Instant::now() >= at) {
                    let _ = blocks
                        .send(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "event stream opening deadline elapsed",
                        )))
                        .await;
                    return;
                }
            }
            permit = blocks.reserve(), if pending.is_some() => match permit {
                Ok(permit) => {
                    if let Some(block) = pending.take() {
                        permit.send(Ok(block));
                    }
                }
                // The reader went away: nothing more to do.
                Err(_) => return,
            },
            frame = body.frame(), if pending.is_none() => match frame {
                None => return,
                Some(Err(e)) => {
                    let _ = blocks.send(Err(body_error(e))).await;
                    return;
                }
                Some(Ok(frame)) => pending = frame.into_data().ok(),
            },
        }
    }
}

/// The body of a streamed response, read synchronously from the pump's
/// blocks. A closed channel is the end of the body, or, when the caller
/// cancelled, the end of the tail.
struct ChannelBody {
    blocks: tokio::sync::mpsc::Receiver<io::Result<Bytes>>,
    cancelled: Arc<AtomicBool>,
    pending: Bytes,
}

impl Read for ChannelBody {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() {
            match self.blocks.blocking_recv() {
                Some(Ok(block)) => self.pending = block,
                Some(Err(error)) => return Err(error),
                None => {
                    return if self.cancelled.load(Ordering::Relaxed) {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "event tail cancelled",
                        ))
                    } else {
                        // The body ended cleanly.
                        Ok(0)
                    };
                }
            }
        }
        let count = out.len().min(self.pending.len());
        out[..count].copy_from_slice(&self.pending[..count]);
        self.pending = self.pending.split_off(count);
        Ok(count)
    }
}

/// Reads at most `max` bytes, including LF, without an unbounded read_until.
/// Only the test fixtures that drive raw API sockets read requests with it.
#[cfg(test)]
pub(super) fn bounded_line(
    reader: &mut impl std::io::BufRead,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated stream line",
                ))
            };
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if count > max.saturating_sub(line.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream line exceeds its bound",
            ));
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if line.last() == Some(&b'\n') {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {

    // The remote-mode fixtures drive real sockets, threads and wall-clock
    // deadlines: the direct std/tokio calls are the harness, not daemon paths.
    #![allow(clippy::disallowed_methods)]

    /// F3: as root, the API socket in a directory that another user owns is
    /// reached only as that user's own socket, made and served by that user:
    /// a link, a FIFO, root's own socket and one handed to the user but served
    /// by root are refused, and nothing hangs. Needs root; elsewhere it says so,
    /// or fails under `KRONIK_FOREIGN_TESTS=require`.
    #[test]
    fn root_refuses_a_swapped_api_socket_and_reaches_its_owners() {
        use std::io::{BufRead as _, Read as _};
        use std::os::unix::fs::PermissionsExt as _;
        use std::os::unix::net::UnixListener;
        if !kronik_foreign::sys::is_root() {
            assert!(
                std::env::var("KRONIK_FOREIGN_TESTS").as_deref() != Ok("require"),
                "KRONIK_FOREIGN_TESTS=require, but the root client test needs root"
            );
            eprintln!("skipped: the root client test needs root");
            return;
        }
        let base = tempfile::Builder::new()
            .prefix("kronik-api-socket-")
            .tempdir_in("/var/tmp")
            .unwrap();
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        // The service user's runtime directory, as the nonroot unit makes it.
        let run = base.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::os::unix::fs::chown(&run, Some(65_534), Some(65_534)).unwrap();
        let socket = run.join("api.sock");
        // Root's own socket elsewhere, which a link would lead to.
        let elsewhere = base.path().join("root.sock");
        let _root_listener = UnixListener::bind(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &socket).unwrap();
        let why = connect_unix_as_root(&socket).unwrap_err().to_string();
        assert!(why.contains("refusing, as root"), "link: {why}");
        std::fs::remove_file(&socket).unwrap();
        // A FIFO: refused before anything could block on it.
        let made = std::process::Command::new("mkfifo")
            .arg(&socket)
            .status()
            .unwrap();
        assert!(made.success());
        let why = connect_unix_as_root(&socket).unwrap_err().to_string();
        assert!(why.contains("not a socket"), "fifo: {why}");
        std::fs::remove_file(&socket).unwrap();
        // Root's socket in the user's directory: not the user's.
        let listener = UnixListener::bind(&socket).unwrap();
        let why = connect_unix_as_root(&socket).unwrap_err().to_string();
        assert!(
            why.contains("belongs to user 0, not 65534"),
            "root's socket: {why}"
        );
        // Handed to the user, but served by root: the peer gives it away.
        std::os::unix::fs::lchown(&socket, Some(65_534), Some(65_534)).unwrap();
        let why = connect_unix_as_root(&socket).unwrap_err().to_string();
        assert!(
            why.contains("served by uid 0, not by uid 65534"),
            "root's listener: {why}"
        );
        drop(listener);
        std::fs::remove_file(&socket).unwrap();
        // The user's own socket, served by the user: reached.
        let mut server = std::process::Command::new("setpriv")
            .args([
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "python3",
                "-c",
            ])
            .arg(
                "import socket, sys\n\
                 s = socket.socket(socket.AF_UNIX)\n\
                 s.bind(sys.argv[1])\n\
                 s.listen(1)\n\
                 print('ready', flush=True)\n\
                 c, _ = s.accept()\n\
                 c.sendall(b'ok')\n\
                 c.close()\n",
            )
            .arg(&socket)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(server.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready");
        let mut stream = connect_unix_as_root(&socket).unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        assert_eq!(answer, "ok");
        assert!(server.wait().unwrap().success());
        // A missing socket stays "not found": no daemon is an answer, not a refusal.
        std::fs::remove_file(&socket).unwrap();
        assert_eq!(
            connect_unix_as_root(&socket).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    use super::*;
    use std::io::Write as _;
    use std::os::unix::net::UnixListener;

    /// Reads one request head, through its blank line, leaving any body
    /// unread.
    fn read_head(socket: &mut UnixStream) -> Vec<u8> {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut head = Vec::new();
        let mut chunk = [0u8; 512];
        while !head.ends_with(b"\r\n\r\n") {
            let read = socket.read(&mut chunk).unwrap();
            assert!(read > 0, "the client closed before sending its head");
            head.extend_from_slice(&chunk[..read]);
        }
        head
    }

    /// Serves one raw HTTP response on an API socket.
    fn serve(path: &std::path::Path, reply: Vec<u8>) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_head(&mut socket);
            socket.write_all(&reply).unwrap();
            socket.flush().unwrap();
        })
    }

    /// One `name: value` field of a raw head line, case-insensitively.
    fn field(line: &str, name: &str) -> Option<String> {
        let (field, value) = line.strip_suffix("\r\n")?.split_once(':')?;
        field
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    }

    #[test]
    fn connected_stream_bounds_opening_and_keeps_live_body_beyond_its_deadline() {
        // A silent peer: the opening deadline ends the attempt.
        let directory = tempfile::tempdir().unwrap();
        let silent_path = directory.path().join("api.sock");
        let listener = UnixListener::bind(&silent_path).unwrap();
        let silent_server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            // Hold the peer open until the client gives up and goes away.
            let mut sink = [0u8; 64];
            while socket.read(&mut sink).unwrap_or(0) > 0 {}
        });
        let started = Instant::now();
        let result = stream_with_opening(
            &Endpoint::Unix(silent_path),
            "/v1/events/stream",
            None,
            None,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(50),
        );
        assert!(
            matches!(result, Err(Failure::Timeout)) && started.elapsed() < Duration::from_secs(2),
            "silent peer: {:?} after {:?}",
            result.map(|_| ()).err(),
            started.elapsed()
        );
        silent_server.join().unwrap();

        // An API error body keeps the opening deadline instead of hanging.
        let directory = tempfile::tempdir().unwrap();
        let error_path = directory.path().join("api.sock");
        let listener = UnixListener::bind(&error_path).unwrap();
        let error_server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_head(&mut socket);
            socket
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1\r\n\r\n")
                .unwrap();
            // The promised body never arrives; the socket stays up.
            let mut sink = [0u8; 64];
            while socket.read(&mut sink).unwrap_or(0) > 0 {}
        });
        let mut response = stream_with_opening(
            &Endpoint::Unix(error_path),
            "/v1/events/stream",
            None,
            None,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(50),
        )
        .unwrap();
        assert_eq!(response.status, 403);
        let error = response.body.read(&mut [0; 8]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        error_server.join().unwrap();

        // A live SSE body survives past the opening deadline, then Ctrl-C ends it.
        let directory = tempfile::tempdir().unwrap();
        let live_path = directory.path().join("api.sock");
        let listener = UnixListener::bind(&live_path).unwrap();
        let live_server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_head(&mut socket);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
                .unwrap();
            std::thread::sleep(Duration::from_millis(150));
            socket.write_all(b": live\n\n").unwrap();
            let mut sink = [0u8; 64];
            while socket.read(&mut sink).unwrap_or(0) > 0 {}
        });
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut response = stream_with_opening(
            &Endpoint::Unix(live_path),
            "/v1/events/stream",
            None,
            None,
            cancelled.clone(),
            Duration::from_millis(50),
        )
        .unwrap();
        assert_eq!(response.status, 200);
        std::thread::sleep(Duration::from_millis(200));
        let mut heartbeat = [0; 8];
        response.body.read_exact(&mut heartbeat).unwrap();
        assert_eq!(&heartbeat, b": live\n\n");
        cancelled.store(true, Ordering::Relaxed);
        assert_eq!(
            response.body.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        live_server.join().unwrap();
    }

    #[test]
    fn ordinary_and_streaming_requests_resume_full_cursors_in_headers_not_uris() {
        let bytes = serde_json::to_vec(&super::super::events::full_event_cursor()).unwrap();
        let cursor = super::super::events::read_cursor("-", &mut bytes.as_slice()).unwrap();
        let encoded = serde_json::to_string(&cursor).unwrap();
        assert!(
            encoded.len() > 65_534,
            "the old Hyper URI limit must actually be crossed"
        );
        assert!(encoded.len() <= kronik_fleet::events::MAX_CURSOR_BYTES);
        for streaming in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("api.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            let server = std::thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(socket);
                // An oversized URI fails this existing public request-line bound;
                // the full typed cursor must instead arrive in Last-Event-ID.
                bounded_line(&mut reader, 8192).unwrap().unwrap();
                let mut cursor = None;
                loop {
                    let line =
                        bounded_line(&mut reader, kronik_fleet::events::MAX_CURSOR_BYTES + 1024)
                            .unwrap()
                            .unwrap();
                    if line == b"\r\n" {
                        break;
                    }
                    let line = String::from_utf8(line).unwrap();
                    if let Some(value) = field(&line, "last-event-id") {
                        assert!(cursor.is_none(), "one cursor field, not duplicates");
                        cursor = Some(value);
                    }
                }
                let observed =
                    serde_json::from_str::<kronik_fleet::events::ResumeCursor>(&cursor.unwrap())
                        .unwrap();
                reader.get_mut().write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 2\r\n\r\n{}"
                ).unwrap();
                observed
            });
            let endpoint = Endpoint::Unix(path);
            let target = if streaming {
                "/v1/events/stream"
            } else {
                "/v1/events?limit=1"
            };
            if streaming {
                let mut response = stream(
                    &endpoint,
                    target,
                    Some("bearer"),
                    Some(&encoded),
                    Arc::new(std::sync::atomic::AtomicBool::new(false)),
                )
                .unwrap();
                assert_eq!(response.status, 200);
                let mut body = Vec::new();
                response.body.read_to_end(&mut body).unwrap();
                assert_eq!(body, b"{}");
            } else {
                let response = request(
                    &endpoint,
                    "GET",
                    target,
                    None,
                    Some("bearer"),
                    Some(&encoded),
                    Duration::from_secs(5),
                )
                .unwrap();
                assert_eq!(response.status, 200);
                assert_eq!(response.body, b"{}");
            }
            let observed = server.join().unwrap();
            assert_eq!(observed, cursor);
        }
    }

    #[test]
    fn cursor_header_bounds_and_injection_fail_closed_without_echoing_input() {
        for cursor in [
            String::new(),
            "private\r\nAuthorization: secret".into(),
            "private\0secret".into(),
            "privateé".into(),
            "x".repeat(kronik_fleet::events::MAX_CURSOR_BYTES + 1),
        ] {
            let result = request(
                &Endpoint::Unix(PathBuf::from("/unused")),
                "GET",
                "/v1/events",
                None,
                None,
                Some(&cursor),
                Duration::from_secs(1),
            );
            let Err(Failure::Malformed(message)) = result else {
                panic!("expected header refusal");
            };
            assert!(!message.contains("private"));
            assert!(!message.contains("secret"));
            let result = stream(
                &Endpoint::Unix(PathBuf::from("/unused")),
                "/v1/events/stream",
                None,
                Some(&cursor),
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            );
            assert!(matches!(result, Err(Failure::Malformed(_))));
        }
    }

    #[test]
    fn requests_decode_content_length_chunked_and_closed_bodies() {
        for (raw, status, body) in [
            (
                &b"HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\n\
                    content-length: 2\r\n\r\n{}extra"[..],
                404u16,
                &b"{}"[..],
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    3\r\n{\"a\r\n4;ext=1\r\n\":1}\r\n0\r\nTrailer: x\r\n\r\n",
                200,
                &b"{\"a\":1}"[..],
            ),
            (b"HTTP/1.0 200 OK\r\n\r\nall of it", 200, &b"all of it"[..]),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("api.sock");
            let server = serve(&path, raw.to_vec());
            let response = request(
                &Endpoint::Unix(path),
                "GET",
                "/v1/events",
                None,
                None,
                None,
                Duration::from_secs(5),
            )
            .unwrap();
            server.join().unwrap();
            assert_eq!(response.status, status, "{}", String::from_utf8_lossy(raw));
            assert_eq!(response.body, body, "{}", String::from_utf8_lossy(raw));
        }
    }

    /// N4: a body cut short is a broken connection (retried by `wait`).
    #[test]
    fn a_request_body_cut_short_is_a_broken_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let server = serve(
            &path,
            b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nshort".to_vec(),
        );
        let r = request(
            &Endpoint::Unix(path),
            "GET",
            "/v1/events",
            None,
            None,
            None,
            Duration::from_secs(5),
        );
        server.join().unwrap();
        assert!(
            matches!(&r, Err(Failure::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{r:?}"
        );
    }

    #[test]
    fn requests_reject_malformed_responses() {
        for raw in [&b"SSH-2.0-OpenSSH\r\n\r\n"[..], b"HTTP/1.1 OK\r\n\r\n"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("api.sock");
            let server = serve(&path, raw.to_vec());
            let r = request(
                &Endpoint::Unix(path),
                "GET",
                "/v1/events",
                None,
                None,
                None,
                Duration::from_secs(5),
            );
            server.join().unwrap();
            assert!(
                matches!(r, Err(Failure::Malformed(_))),
                "{}: {r:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn streaming_decodes_chunks_content_length_and_connection_close_incrementally() {
        // Chunked, with a chunk extension and trailers, arriving in parts.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_head(&mut socket);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                      Transfer-Encoding: chunked\r\n\r\n3;ext=1\r\nid:",
                )
                .unwrap();
            socket.flush().unwrap();
            std::thread::sleep(Duration::from_millis(150));
            socket
                .write_all(b"\r\n4\r\n x\n\n\r\n0\r\nTrailer: ignored\r\n\r\n")
                .unwrap();
            std::thread::sleep(Duration::from_millis(500));
        });
        let mut response = stream(
            &Endpoint::Unix(path),
            "/v1/events/stream",
            None,
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type.as_deref(), Some("text/event-stream"));
        // The first chunk arrives before the stream is terminated.
        let mut first = [0u8; 3];
        response.body.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"id:");
        let mut rest = String::new();
        response.body.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, " x\n\n");
        server.join().unwrap();

        for (raw, body) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 7\r\n\r\nid: x\n\nignored"[..],
                "id: x\n\n",
            ),
            (
                b"HTTP/1.0 200 OK\r\nContent-Type: text/event-stream\r\n\r\nid: x\n\n",
                "id: x\n\n",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("api.sock");
            let server = serve(&path, raw.to_vec());
            let mut response = stream(
                &Endpoint::Unix(path),
                "/v1/events/stream",
                Some("bearer"),
                None,
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.content_type.as_deref(), Some("text/event-stream"));
            let mut received = String::new();
            response.body.read_to_string(&mut received).unwrap();
            assert_eq!(received, body);
            server.join().unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let server = serve(
            &path,
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        );
        let response = stream(
            &Endpoint::Unix(path),
            "/v1/events/stream",
            None,
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(response.status, 403);
        server.join().unwrap();
    }

    #[test]
    fn streaming_rejects_ambiguous_and_oversized_headers_and_truncated_bodies() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"HTTP/1.1 private\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nprivate malformed\r\n\r\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("api.sock");
            let server = serve(&path, raw.to_vec());
            let r = stream(
                &Endpoint::Unix(path),
                "/v1/events/stream",
                None,
                None,
                Arc::new(AtomicBool::new(false)),
            );
            server.join().unwrap();
            assert!(
                r.is_err(),
                "{}: {:?}",
                String::from_utf8_lossy(raw),
                r.map(|_| ()).err()
            );
        }
        // The response head stays bounded.
        let raw = format!("HTTP/1.1 200 OK\r\n{}\r\n", "X: value\r\n".repeat(10000));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let server = serve(&path, raw.into_bytes());
        let r = stream(
            &Endpoint::Unix(path),
            "/v1/events/stream",
            None,
            None,
            Arc::new(AtomicBool::new(false)),
        );
        server.join().unwrap();
        assert!(r.is_err());
        for raw in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nxx",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("api.sock");
            let server = serve(&path, raw.to_vec());
            let mut response = stream(
                &Endpoint::Unix(path),
                "/v1/events/stream",
                None,
                None,
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            server.join().unwrap();
            assert!(
                response.body.read_to_end(&mut Vec::new()).is_err(),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn stream_cancellation_and_request_injection_fail_without_echoing_input() {
        let (blocks, receiver) = tokio::sync::mpsc::channel(1);
        drop(blocks);
        let mut reader = ChannelBody {
            blocks: receiver,
            cancelled: Arc::new(AtomicBool::new(true)),
            pending: Bytes::new(),
        };
        assert_eq!(
            reader.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        for (target, token) in [
            ("/v1/events/stream\r\nprivate: secret", Some("bearer")),
            ("/v1/events/stream", Some("private\r\nsecret")),
        ] {
            let result = stream(
                &Endpoint::Unix(PathBuf::from("/unused")),
                target,
                token,
                None,
                Arc::new(AtomicBool::new(false)),
            );
            let Err(Failure::Malformed(message)) = result else {
                panic!("expected refusal");
            };
            assert!(!message.contains("private"));
            assert!(!message.contains("secret"));
        }
    }

    /// N4: a TLS error (here a peer that is not a TLS server) is `Tls`, not
    /// retried; a connection closed mid-handshake is `Io`, retried.
    #[test]
    fn handshake_tells_tls_errors_from_broken_connections() {
        use tokio::io::AsyncWriteExt as _;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from("kronik.example").unwrap();
        let r = runtime.block_on(async {
            let (client, mut peer) = tokio::io::duplex(4096);
            peer.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await
                .unwrap();
            connector
                .connect(name, client)
                .await
                .map(|_| ())
                .map_err(tls_failure)
        });
        assert!(matches!(r, Err(Failure::Tls(_))), "{r:?}");
        let name = rustls::pki_types::ServerName::try_from("kronik.example").unwrap();
        let r = runtime.block_on(async {
            let (client, mut peer) = tokio::io::duplex(4096);
            peer.shutdown().await.unwrap();
            connector
                .connect(name, client)
                .await
                .map(|_| ())
                .map_err(tls_failure)
        });
        assert!(
            matches!(&r, Err(Failure::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{r:?}"
        );
    }

    #[test]
    fn urls_are_https_or_plain_http_to_this_machine() {
        let tcp = |host: &str, port, tls| Endpoint::Tcp {
            host: host.into(),
            port,
            tls,
        };
        let ok = [
            (
                "https://Kronik.Example.com:7443/",
                tcp("kronik.example.com", 7443, true),
            ),
            ("https://10.0.0.5:7443", tcp("10.0.0.5", 7443, true)),
            ("https://[2001:db8::1]:7443", tcp("2001:db8::1", 7443, true)),
            ("http://localhost:7443", tcp("localhost", 7443, false)),
            ("http://127.0.0.1:7443", tcp("127.0.0.1", 7443, false)),
            ("http://[::1]:7443", tcp("::1", 7443, false)),
        ];
        for (url, want) in ok {
            assert_eq!(Endpoint::parse_url(url), Ok(want.clone()), "{url}");
        }
        assert_eq!(
            tcp("2001:db8::1", 7443, true).shown(),
            "https://[2001:db8::1]:7443"
        );
        for url in [
            "http://kronik.example.com:7443",
            "http://10.0.0.5",
            "ftp://localhost",
            "kronik.example.com",
            "https://host:7443/v1",
            "https://user@host",
            "https://host:0",
            "https://host:99999",
            "https://",
            "http://[::1]evil:1",
            "http://[::1]:7443x",
        ] {
            assert!(Endpoint::parse_url(url).is_err(), "{url}");
        }
    }

    /// L3: no default port, which would usually be the gateway's.
    #[test]
    fn a_url_without_a_port_is_refused_with_a_hint() {
        for (url, hint) in [
            (
                "https://kronik.example.com",
                "https://kronik.example.com:7443",
            ),
            (
                "https://kronik.example.com/",
                "https://kronik.example.com:7443",
            ),
            ("http://localhost", "http://localhost:7443"),
            ("https://[2001:db8::1]", "https://[2001:db8::1]:7443"),
        ] {
            let e = Endpoint::parse_url(url).unwrap_err();
            assert!(e.contains("has no port") && e.contains(hint), "{url}: {e}");
        }
    }

    /// L1: no message repeats user info, a path or a query.
    #[test]
    fn url_errors_name_only_the_scheme_and_host() {
        for url in [
            "https://ci:S3cr3tT0ken@kronik.example.com:7443",
            "https://ci:S3cr#et/T0ken@kronik.example.com",
            "http://ci:S3cr3tT0ken@kronik.example.com:7443",
            "https://kronik.example.com:7443/S3cr3tT0ken",
            "https://kronik.example.com:7443?t=S3cr3tT0ken",
            "ftp://ci:S3cr3tT0ken@kronik.example.com",
            "S3cr3tT0ken",
            "HTTPS://ci:S3cr3tT0ken@kronik.example.com",
        ] {
            let e = Endpoint::parse_url(url).unwrap_err();
            assert!(!e.contains("S3cr"), "{url}: {e}");
        }
        let e = Endpoint::parse_url("https://ci:pw@kronik.example.com:7443").unwrap_err();
        assert!(e.starts_with("https://kronik.example.com:7443 "), "{e}");
    }

    #[test]
    fn an_uppercase_scheme_is_named() {
        let e = Endpoint::parse_url("HTTPS://kronik.example.com:7443").unwrap_err();
        assert!(e.contains("lower case"), "{e}");
    }

    /// M2: `localhost` is never resolved, and plain HTTP dials only loopback.
    #[test]
    fn localhost_dials_only_loopback_addresses() {
        let addrs = fixed_addrs("localhost", 7443).unwrap();
        assert_eq!(
            addrs,
            [
                "[::1]:7443".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:7443".parse::<SocketAddr>().unwrap()
            ]
        );
        assert_eq!(fixed_addrs("LocalHost", 1).unwrap().len(), 2);
        assert_eq!(
            fixed_addrs("127.0.0.2", 1).unwrap(),
            ["127.0.0.2:1".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(fixed_addrs("kronik.example.com", 1), None);
        // A non-loopback address is never dialled over plain HTTP.
        let e = connect("192.0.2.10", 7443, false, Duration::from_millis(100)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
    }
}
