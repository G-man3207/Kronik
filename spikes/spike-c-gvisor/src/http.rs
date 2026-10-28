//! Just enough HTTP/1.1 for the echo server and the benchmark client:
//! request/response heads, `Content-Length` bodies and keep-alive. No chunked
//! encoding.

use std::io::{self, BufRead, Write};

const MAX_HEAD: usize = 64 * 1024;

pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

impl Request {
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    /// Returns the value of a query parameter, e.g. `code` in `/exit?code=3`.
    pub fn query(&self, key: &str) -> Option<&str> {
        let query = self.target.split_once('?')?.1;
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A start line and its headers, names lowercased.
type Head = (String, Vec<(String, String)>);

/// Reads the head (start line and headers). Returns `None` on a clean EOF
/// before the first byte.
fn read_head<R: BufRead>(r: &mut R) -> io::Result<Option<Head>> {
    let mut start = String::new();
    if r.read_line(&mut start)? == 0 {
        return Ok(None);
    }
    let mut total = start.len();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            return Err(invalid("EOF inside HTTP head"));
        }
        total += n;
        if total > MAX_HEAD {
            return Err(invalid("HTTP head too large"));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid(format!("bad header line {line:?}")))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok(Some((
        start.trim_end_matches(['\r', '\n']).to_string(),
        headers,
    )))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn read_body<R: BufRead>(r: &mut R, headers: &[(String, String)]) -> io::Result<Vec<u8>> {
    let len = match header(headers, "content-length") {
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| invalid("bad content-length"))?,
        None => 0,
    };
    let mut body = vec![0; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

pub fn read_request<R: BufRead>(r: &mut R) -> io::Result<Option<Request>> {
    let Some((start, headers)) = read_head(r)? else {
        return Ok(None);
    };
    let mut parts = start.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("");
    if method.is_empty() || !target.starts_with('/') || !version.starts_with("HTTP/1.") {
        return Err(invalid(format!("bad request line {start:?}")));
    }
    let body = read_body(r, &headers)?;
    let connection = header(&headers, "connection").unwrap_or("");
    let keep_alive = if version == "HTTP/1.0" {
        connection.eq_ignore_ascii_case("keep-alive")
    } else {
        !connection.eq_ignore_ascii_case("close")
    };
    Ok(Some(Request {
        method,
        target,
        headers,
        body,
        keep_alive,
    }))
}

pub fn read_response<R: BufRead>(r: &mut R) -> io::Result<Response> {
    let (start, headers) = read_head(r)?.ok_or_else(|| invalid("EOF before response"))?;
    let status = start
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| invalid(format!("bad status line {start:?}")))?;
    let body = read_body(r, &headers)?;
    Ok(Response {
        status,
        headers,
        body,
    })
}

pub fn write_response<W: Write>(
    w: &mut W,
    status: u16,
    headers: &[(&str, String)],
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\n",
        body.len()
    );
    if !keep_alive {
        head.push_str("connection: close\r\n");
    }
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    // One write for head and body keeps small responses in one segment.
    let mut buf = head.into_bytes();
    buf.extend_from_slice(body);
    w.write_all(&buf)?;
    w.flush()
}

pub fn write_request<W: Write>(
    w: &mut W,
    method: &str,
    target: &str,
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    let mut buf = format!(
        "{method} {target} HTTP/1.1\r\nhost: kronik-spike\r\ncontent-length: {}\r\n{}\r\n",
        body.len(),
        if keep_alive {
            ""
        } else {
            "connection: close\r\n"
        }
    )
    .into_bytes();
    buf.extend_from_slice(body);
    w.write_all(&buf)?;
    w.flush()
}
