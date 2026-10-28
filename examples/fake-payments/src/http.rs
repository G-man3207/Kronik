//! Just enough HTTP/1.1 for a small server: request heads, `Content-Length`
//! bodies and keep-alive. No chunked encoding (a request with
//! `Transfer-Encoding` is rejected), no pipelining tricks, no TLS.
//!
//! Every limit is checked before memory is allocated for it, so a hostile
//! client cannot make the server allocate more than [`MAX_HEAD`] plus the
//! caller's body limit per connection.

use std::io::{self, BufRead, Read, Write};

/// The largest request head (request line and headers) accepted.
pub const MAX_HEAD: usize = 64 * 1024;

/// The largest number of header lines accepted.
const MAX_HEADERS: usize = 100;

/// A parsed request. Header names are lowercased.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// The request target as sent, e.g. `/echo?x=1`. Always starts with `/`
    /// and contains only visible ASCII.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Whether the client wants the connection kept open after the answer.
    pub keep_alive: bool,
}

impl Request {
    /// The path part of the target, without the query string.
    pub fn path(&self) -> &str {
        self.target
            .split_once('?')
            .map_or(self.target.as_str(), |(path, _)| path)
    }

    /// The first value of the header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
}

/// An answer to send.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// A response with a JSON body.
    pub fn json(status: u16, body: String) -> Self {
        Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.into_bytes(),
        }
    }

    /// A response with a plain-text body.
    pub fn text(status: u16, body: &str) -> Self {
        Response {
            status,
            headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
            body: body.as_bytes().to_vec(),
        }
    }
}

/// Why a request could not be read.
#[derive(Debug)]
pub enum ReadError {
    /// The connection failed, timed out or ended in the middle of a request:
    /// there is nobody to answer.
    Io(io::Error),
    /// The bytes are not a request this module accepts: answer `400` and
    /// close, since the framing of what follows is unknown.
    Malformed(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "connection error: {e}"),
            ReadError::Malformed(m) => write!(f, "malformed request: {m}"),
        }
    }
}

fn malformed(msg: impl Into<String>) -> ReadError {
    ReadError::Malformed(msg.into())
}

/// Reads one line, at most `limit` bytes including the newline, and returns
/// it without the line ending. `Ok(None)` means EOF before the first byte.
fn read_line<R: BufRead>(r: &mut R, limit: usize) -> Result<Option<String>, ReadError> {
    if limit == 0 {
        return Err(malformed("request head too large"));
    }
    let mut line = Vec::new();
    let n = r
        .by_ref()
        .take(limit as u64)
        .read_until(b'\n', &mut line)
        .map_err(ReadError::Io)?;
    if n == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        if n >= limit {
            return Err(malformed("request head too large"));
        }
        return Err(ReadError::Io(io::ErrorKind::UnexpectedEof.into()));
    }
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line)
        .map(Some)
        .map_err(|_| malformed("request head is not UTF-8"))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Whether `s` is a non-empty HTTP token (method or header name).
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Whether the comma-separated header value `value` contains `token`.
fn has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// Reads one request. `Ok(None)` means the client closed the connection
/// cleanly between requests. Bodies longer than `max_body` are rejected.
pub fn read_request<R: BufRead>(r: &mut R, max_body: usize) -> Result<Option<Request>, ReadError> {
    let mut budget = MAX_HEAD;
    // RFC 9112 2.2: ignore empty lines before the request line.
    let start = loop {
        let Some(line) = read_line(r, budget)? else {
            return Ok(None);
        };
        budget = budget.saturating_sub(line.len() + 2);
        if !line.is_empty() {
            break line;
        }
        if budget == 0 {
            return Err(malformed("request head too large"));
        }
    };

    let parts: Vec<&str> = start.split(' ').collect();
    let [method, target, version] = parts[..] else {
        return Err(malformed(format!("bad request line {start:?}")));
    };
    if !is_token(method) {
        return Err(malformed(format!("bad method {method:?}")));
    }
    if !target.starts_with('/') || !target.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(malformed(format!("bad request target {target:?}")));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(malformed(format!("unsupported version {version:?}")));
    }

    let mut headers = Vec::new();
    loop {
        let line = read_line(r, budget)?.ok_or_else(|| {
            ReadError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF inside the request head",
            ))
        })?;
        budget = budget.saturating_sub(line.len() + 2);
        if line.is_empty() {
            break;
        }
        if headers.len() == MAX_HEADERS {
            return Err(malformed("too many headers"));
        }
        if line.starts_with([' ', '\t']) {
            return Err(malformed("obsolete header line folding"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| malformed(format!("bad header line {line:?}")))?;
        if !is_token(name) {
            return Err(malformed(format!("bad header name {name:?}")));
        }
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_string(),
        ));
    }

    if header(&headers, "transfer-encoding").is_some() {
        return Err(malformed("transfer-encoding is not supported"));
    }
    // Several Content-Length headers (or a list) must all agree.
    let mut length: Option<u64> = None;
    for (_, value) in headers.iter().filter(|(n, _)| n == "content-length") {
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() || !item.bytes().all(|b| b.is_ascii_digit()) {
                return Err(malformed(format!("bad content-length {value:?}")));
            }
            let n: u64 = item
                .parse()
                .map_err(|_| malformed(format!("bad content-length {value:?}")))?;
            if length.is_some_and(|l| l != n) {
                return Err(malformed("conflicting content-length headers"));
            }
            length = Some(n);
        }
    }
    let length = length.unwrap_or(0);
    if length > max_body as u64 {
        return Err(malformed(format!(
            "body of {length} bytes exceeds the limit of {max_body}"
        )));
    }
    let mut body = vec![0; length as usize];
    r.read_exact(&mut body).map_err(ReadError::Io)?;

    let connection = header(&headers, "connection").unwrap_or("");
    let keep_alive = if version == "HTTP/1.0" {
        has_token(connection, "keep-alive")
    } else {
        !has_token(connection, "close")
    };
    Ok(Some(Request {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        body,
        keep_alive,
    }))
}

/// The reason phrase for the status codes these servers use.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Writes `response` and flushes. With `keep_alive` false the response says
/// `connection: close`; with `head_only` (a `HEAD` request) the body is left
/// out but its length still announced.
pub fn write_response<W: Write>(
    w: &mut W,
    response: &Response,
    keep_alive: bool,
    head_only: bool,
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-length: {}\r\n",
        response.status,
        reason(response.status),
        response.body.len()
    );
    if !keep_alive {
        head.push_str("connection: close\r\n");
    }
    for (name, value) in &response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    // One write for head and body keeps small responses in one segment.
    let mut buf = head.into_bytes();
    if !head_only {
        buf.extend_from_slice(&response.body);
    }
    w.write_all(&buf)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(raw: &str) -> Result<Option<Request>, ReadError> {
        read_request(&mut Cursor::new(raw.as_bytes().to_vec()), 1024)
    }

    fn rejected(raw: &str) -> bool {
        matches!(parse(raw), Err(ReadError::Malformed(_)))
    }

    #[test]
    fn parses_a_request_with_a_body() {
        let r = parse(
            "POST /v1/x?a=1 HTTP/1.1\r\nHost: h\r\nX-Thing:  v \r\nContent-Length: 5\r\n\r\nhello",
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.path(), "/v1/x");
        assert_eq!(r.header("x-thing"), Some("v"));
        assert_eq!(r.header("missing"), None);
        assert_eq!(r.body, b"hello");
        assert!(r.keep_alive);
    }

    #[test]
    fn clean_eof_is_none() {
        assert!(parse("").unwrap().is_none());
    }

    #[test]
    fn truncated_requests_are_io_errors() {
        assert!(matches!(
            parse("GET / HTTP/1.1\r\nHost"),
            Err(ReadError::Io(_))
        ));
        assert!(matches!(
            parse("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"),
            Err(ReadError::Io(_))
        ));
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert!(rejected("GET\r\n\r\n"));
        assert!(rejected("GET / HTTP/1.1 extra\r\n\r\n"));
        assert!(rejected("GET nopath HTTP/1.1\r\n\r\n"));
        assert!(rejected("GET / HTTP/2.0\r\n\r\n"));
        assert!(rejected("G(T / HTTP/1.1\r\n\r\n"));
        assert!(rejected("GET / HTTP/1.1\r\nno colon\r\n\r\n"));
        assert!(rejected("GET / HTTP/1.1\r\nBad Name: v\r\n\r\n"));
        assert!(rejected("GET / HTTP/1.1\r\nA: b\r\n folded\r\n\r\n"));
        assert!(rejected("GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n"));
        assert!(rejected(
            "GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"
        ));
        assert!(rejected(
            "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        ));
        assert!(rejected("GET / HTTP/1.1\r\nContent-Length: 2000\r\n\r\n"));
        assert!(rejected("GET /\u{7f} HTTP/1.1\r\n\r\n"));
    }

    #[test]
    fn oversized_heads_are_rejected() {
        let raw = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert!(rejected(&raw));
        let many: String = (0..=MAX_HEADERS).map(|i| format!("H{i}: v\r\n")).collect();
        assert!(rejected(&format!("GET / HTTP/1.1\r\n{many}\r\n")));
    }

    #[test]
    fn keep_alive_rules() {
        let ka = |raw: &str| parse(raw).unwrap().unwrap().keep_alive;
        assert!(ka("GET / HTTP/1.1\r\n\r\n"));
        assert!(!ka("GET / HTTP/1.1\r\nConnection: Close\r\n\r\n"));
        assert!(!ka("GET / HTTP/1.1\r\nConnection: upgrade, close\r\n\r\n"));
        assert!(!ka("GET / HTTP/1.0\r\n\r\n"));
        assert!(ka("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"));
    }

    #[test]
    fn two_requests_on_one_stream_are_framed_by_content_length() {
        let raw = "POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\n\r\n\r\nGET /c HTTP/1.1\r\n\r\n";
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let a = read_request(&mut cursor, 1024).unwrap().unwrap();
        assert_eq!((a.target.as_str(), a.body.as_slice()), ("/a", &b"abc"[..]));
        let b = read_request(&mut cursor, 1024).unwrap().unwrap();
        assert_eq!((b.target.as_str(), b.body.len()), ("/b", 0));
        // An empty line before a request line is ignored.
        let c = read_request(&mut cursor, 1024).unwrap().unwrap();
        assert_eq!(c.target, "/c");
        assert!(read_request(&mut cursor, 1024).unwrap().is_none());
    }

    #[test]
    fn writes_responses() {
        let mut out = Vec::new();
        let r = Response::text(200, "ok");
        write_response(&mut out, &r, false, false).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\ncontent-type: text/plain; charset=utf-8\r\n\r\nok"
        );
        let mut out = Vec::new();
        write_response(&mut out, &r, true, true).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .ends_with("charset=utf-8\r\n\r\n")
        );
    }
}
