//! A minimal HTTP/1.1 client for the JSON API: on the daemon's Unix socket,
//! or over TCP (M10) to `https://host:port`, or plain `http://` to a
//! loopback address only. Each request uses its own connection
//! (`Connection: close`), and the response is read to the end, within a
//! timeout.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

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

/// Sends one request and reads the response. `target` is the path and
/// query, already encoded; `bearer` is sent as `Authorization: Bearer`.
/// `timeout` bounds the connect and every read and write: a daemon that
/// stays silent that long is a [`Failure::Timeout`].
pub fn request(
    endpoint: &Endpoint,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
    timeout: Duration,
) -> Result<Response, Failure> {
    // A zero timeout means none to the socket options.
    let timeout = timeout.max(Duration::from_millis(1));
    let body = body.unwrap_or_default();
    let host = match endpoint {
        Endpoint::Unix(_) => "kronik".to_owned(),
        Endpoint::Tcp { .. } => endpoint
            .shown()
            .split_once("://")
            .map_or_else(String::new, |(_, h)| h.to_owned()),
    };
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\n\
         Connection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    if let Some(token) = bearer {
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    match endpoint {
        Endpoint::Unix(path) => {
            let stream = UnixStream::connect(path).map_err(Failure::Connect)?;
            stream
                .set_read_timeout(Some(timeout))
                .and_then(|()| stream.set_write_timeout(Some(timeout)))
                .map_err(Failure::Io)?;
            exchange(stream, head.as_bytes(), body)
        }
        Endpoint::Tcp { host, port, tls } => {
            let stream = connect(host, *port, *tls, timeout).map_err(Failure::Connect)?;
            stream
                .set_read_timeout(Some(timeout))
                .and_then(|()| stream.set_write_timeout(Some(timeout)))
                .map_err(Failure::Io)?;
            if !tls {
                return exchange(stream, head.as_bytes(), body);
            }
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|e| Failure::Tls(format!("{host:?} is not a TLS server name: {e}")))?;
            let conn = rustls::ClientConnection::new(tls_config()?, name)
                .map_err(|e| Failure::Tls(e.to_string()))?;
            let mut tls = rustls::StreamOwned::new(conn, stream);
            handshake(&mut tls.conn, &mut tls.sock)?;
            exchange(tls, head.as_bytes(), body)
        }
    }
}

/// Completes the handshake first, so that a certificate problem is reported
/// as one and not as a broken connection. rustls reports its own errors as
/// InvalidData; any other is the transport's.
fn handshake(
    conn: &mut rustls::ClientConnection,
    sock: &mut (impl Read + Write),
) -> Result<(), Failure> {
    while conn.is_handshaking() {
        conn.complete_io(sock).map_err(|e| {
            if timed_out(&e) {
                Failure::Timeout
            } else if e.kind() == io::ErrorKind::InvalidData {
                Failure::Tls(e.to_string())
            } else {
                Failure::Io(e)
            }
        })?;
    }
    Ok(())
}

fn exchange(mut stream: impl Read + Write, head: &[u8], body: &[u8]) -> Result<Response, Failure> {
    let sent = stream
        .write_all(head)
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush());
    let mut raw = Vec::new();
    let received = stream.read_to_end(&mut raw);
    // The daemon may answer and close before it has read the whole request,
    // for example when the body is too large; its answer still counts. Over
    // TLS a peer may close without close_notify after a complete response.
    if !raw.is_empty()
        && let Ok(r) = parse(&raw)
    {
        return Ok(r);
    }
    match (sent, received) {
        (_, Ok(_)) if !raw.is_empty() => parse(&raw),
        (Err(e), _) | (Ok(()), Err(e)) if timed_out(&e) => Err(Failure::Timeout),
        (Err(e), _) | (Ok(()), Err(e)) => Err(Failure::Io(e)),
        // Nothing at all: the connection broke (a proxy or a reset), it is
        // not a reply.
        (Ok(()), Ok(_)) => Err(Failure::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "closed without a response",
        ))),
    }
}

/// Parses a complete HTTP/1.1 response: the status, and the body by
/// `Content-Length`, chunked transfer coding or the end of the stream.
fn parse(raw: &[u8]) -> Result<Response, Failure> {
    let malformed = |what: &str| Failure::Malformed(format!("the daemon's response {what}"));
    let end = find(raw, b"\r\n\r\n").ok_or_else(|| malformed("has no end of headers"))?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| malformed("has non-UTF-8 headers"))?;
    let mut lines = head.split("\r\n");
    let mut status_line = lines.next().unwrap_or_default().splitn(3, ' ');
    if !status_line
        .next()
        .is_some_and(|version| version.starts_with("HTTP/1."))
    {
        return Err(malformed("is not HTTP/1.x"));
    }
    let status: u16 = status_line
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| malformed("has no status code"))?;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| malformed("has an invalid Content-Length"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    let rest = &raw[end + 4..];
    let body = if chunked {
        dechunk(rest).ok_or_else(|| malformed("has a broken chunked body"))?
    } else if let Some(n) = length {
        // A clean close in mid-body is a broken connection, not a bad reply.
        rest.get(..n)
            .ok_or_else(|| {
                Failure::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the response ended before its Content-Length",
                ))
            })?
            .to_vec()
    } else {
        rest.to_vec()
    };
    Ok(Response { status, body })
}

/// Decodes a chunked body; trailers are ignored.
fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = find(rest, b"\r\n")?;
        let size = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size = size.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        body.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size..)?.strip_prefix(b"\r\n")?;
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Percent-encodes a path segment or query value: everything except
/// unreserved characters (RFC 3986).
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_bodies() {
        let raw = b"HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\n\
                    content-length: 2\r\n\r\n{}extra";
        assert_eq!(
            parse(raw).unwrap(),
            Response {
                status: 404,
                body: b"{}".to_vec()
            }
        );
    }

    #[test]
    fn parses_chunked_bodies_and_bodies_to_the_end() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    3\r\n{\"a\r\n4;ext=1\r\n\":1}\r\n0\r\nTrailer: x\r\n\r\n";
        assert_eq!(parse(raw).unwrap().body, b"{\"a\":1}");
        let raw = b"HTTP/1.0 200 OK\r\n\r\nall of it";
        assert_eq!(parse(raw).unwrap().body, b"all of it");
    }

    #[test]
    fn rejects_broken_responses() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nzz\r\n"[..],
            b"SSH-2.0-OpenSSH\r\n\r\n",
            b"HTTP/1.1 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",
        ] {
            assert!(
                matches!(parse(raw), Err(Failure::Malformed(_))),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    /// N4: a body cut short is a broken connection (retried by `wait`).
    #[test]
    fn a_body_cut_short_is_a_broken_connection() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nshort";
        let r = parse(raw);
        assert!(
            matches!(&r, Err(Failure::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{r:?}"
        );
    }

    /// A peer that answers `reply` (then EOF) and swallows what is sent.
    struct Peer(io::Cursor<&'static [u8]>);
    impl Read for Peer {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl Write for Peer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// N4: a TLS error (here a peer that is not a TLS server) is `Tls`, not
    /// retried; a connection closed mid-handshake is `Io`, retried.
    #[test]
    fn handshake_tells_tls_errors_from_broken_connections() {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let conn = || {
            rustls::ClientConnection::new(
                Arc::new(config.clone()),
                "kronik.example".try_into().unwrap(),
            )
            .unwrap()
        };
        let r = handshake(
            &mut conn(),
            &mut Peer(io::Cursor::new(b"HTTP/1.1 400 Bad Request\r\n\r\n")),
        );
        assert!(matches!(r, Err(Failure::Tls(_))), "{r:?}");
        let r = handshake(&mut conn(), &mut Peer(io::Cursor::new(b"")));
        assert!(
            matches!(&r, Err(Failure::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{r:?}"
        );
    }

    #[test]
    fn encodes_everything_but_unreserved_characters() {
        assert_eq!(encode("main:12"), "main%3A12");
        assert_eq!(encode("a b/c?d&e"), "a%20b%2Fc%3Fd%26e");
        assert_eq!(encode("ok-._~09AZ"), "ok-._~09AZ");
        assert_eq!(encode("ä"), "%C3%A4");
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
                "127.0.0.1:7443".parse().unwrap()
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
