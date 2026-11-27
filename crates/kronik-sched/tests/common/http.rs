//! A small HTTP/1.1 server for tests: it reads each request and leaves
//! the answer to a handler. The integration tests of kronik-sched include
//! it through `tests/common/mod.rs`, those of kronik-fork through a
//! `#[path]` attribute, so it names nothing of either crate.

#![allow(dead_code, clippy::unwrap_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

/// One request as the server read it.
pub struct Request {
    /// The request line and the header lines as received, each with its
    /// line ending, without the blank line that ends the head.
    pub head: String,
    pub method: String,
    pub path: String,
    /// The headers in the order received: names lowercased, values trimmed.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The value of the header `name` (lowercase); the first if repeated.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Reads one request: the head up to the blank line, then `content-length`
/// bytes of body. `None` at the end of the stream, on a read error, or
/// when the body is cut short.
pub fn read_request(r: &mut impl BufRead) -> Option<Request> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).ok()? == 0 {
            return None;
        }
        if line.trim_end().is_empty() {
            break;
        }
        head.push_str(&line);
    }
    let mut lines = head.lines();
    let mut request_line = lines.next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("").to_owned();
    let path = request_line.next().unwrap_or("").to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let len = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    r.read_exact(&mut body).ok()?;
    Some(Request {
        head,
        method,
        path,
        headers,
        body,
    })
}

/// Listens on `bind` (`"127.0.0.1:0"`, `"[::1]:0"`, ...) and returns the
/// bound address. Each connection runs on a thread of its own, which reads
/// its requests one after the other and passes each to `handler` with the
/// stream to answer on, until the stream ends.
pub fn serve_on(
    bind: &str,
    handler: impl Fn(Request, &mut TcpStream) + Send + Sync + 'static,
) -> String {
    let listener = TcpListener::bind(bind).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handler = Arc::new(handler);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let handler = handler.clone();
            std::thread::spawn(move || {
                let mut w = stream.try_clone().unwrap();
                let mut r = BufReader::new(stream);
                while let Some(request) = read_request(&mut r) {
                    handler(request, &mut w);
                }
            });
        }
    });
    addr
}

/// [`serve_on`] on `127.0.0.1:0`.
pub fn serve(handler: impl Fn(Request, &mut TcpStream) + Send + Sync + 'static) -> String {
    serve_on("127.0.0.1:0", handler)
}
