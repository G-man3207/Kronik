//! A minimal HTTP/1.1 client for the JSON API on the daemon's Unix socket.
//! Each request uses its own connection (`Connection: close`), and the
//! response is read to the end.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// A response from the API.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why a request produced no response.
#[derive(Debug)]
pub enum Failure {
    /// The socket could not be connected to.
    Connect(io::Error),
    /// The connection broke while the request or the response was in flight.
    Io(io::Error),
    /// The reply is not an HTTP/1.1 response.
    Malformed(String),
}

/// Sends one request and reads the response. `target` is the path and
/// query, already encoded; `bearer` is sent as `Authorization: Bearer`.
pub fn request(
    socket: &Path,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
) -> Result<Response, Failure> {
    let mut stream = UnixStream::connect(socket).map_err(Failure::Connect)?;
    let body = body.unwrap_or_default();
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: kronik\r\nAccept: application/json\r\n\
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
    let sent = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush());
    let mut raw = Vec::new();
    let received = stream.read_to_end(&mut raw);
    // The daemon may answer and close before it has read the whole request,
    // for example when the body is too large; its answer still counts.
    match (sent, received) {
        (_, Ok(_)) if !raw.is_empty() => parse(&raw),
        (Err(e), _) | (Ok(()), Err(e)) => Err(Failure::Io(e)),
        (Ok(()), Ok(_)) => Err(Failure::Malformed(
            "the daemon closed the connection without a response".into(),
        )),
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
        rest.get(..n)
            .ok_or_else(|| malformed("ended before its Content-Length"))?
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
            &b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nshort"[..],
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nzz\r\n",
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

    #[test]
    fn encodes_everything_but_unreserved_characters() {
        assert_eq!(encode("main:12"), "main%3A12");
        assert_eq!(encode("a b/c?d&e"), "a%20b%2Fc%3Fd%26e");
        assert_eq!(encode("ok-._~09AZ"), "ok-._~09AZ");
        assert_eq!(encode("ä"), "%C3%A4");
    }
}
