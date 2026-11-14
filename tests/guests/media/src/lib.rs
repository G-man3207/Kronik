//! Test guest (kind `media`, M25/M26): reads, writes and returns blobs,
//! written directly against the WIT world `actor`, which imports
//! `kronik:actor/blobs` (docs/design/m25-streaming-bodies.md §17).
//!
//! Every input is an operation named by the last path segment of an HTTP
//! request (`POST|GET /media/{key}/{op}`, options in the query string) or by
//! the name of an operator message. The request's body is the operation's
//! body: inline bytes or a blob. Answers are text.
//!
//! - `info`: `blob <hash> <size>` or `inline <size>` of the body.
//! - `sum` (`chunk=`, default 1 MiB): reads the whole body in chunks of
//!   `chunk` bytes and answers `<size> <fnv1a-64 hex>`.
//! - `ranges` (`at=<offset>:<len>,...`): reads each range and answers one
//!   `<offset>:<len>=<returned bytes> <fnv1a-64 hex>` per range.
//! - `echo`: answers with the body itself (a blob body is returned as one).
//! - `write` (`size=`, `chunk=`): writes `size` bytes of a fixed pattern in
//!   chunks of `chunk` bytes and answers with the blob.
//! - `fetch` (the body is a URL): GETs it and answers `status <s> <blob
//!   <hash> <size> | inline <size>>`; `fetch-sum` also reads the response
//!   body (`<size> <fnv1a-64 hex>`), `fetch-echo` answers with it.
//! - `fetch-write` (`size=`; the body is a URL): GETs it, then writes `size`
//!   bytes as `write` does and answers with the blob. Its turn has a
//!   `TurnBegin` before it writes.
//! - `write-post` (`size=`, `url=`): writes a blob as `write` does and
//!   POSTs it, in the same turn; answers the status or the fetch error.
//! - `post` (`url=`): POSTs the body (a blob stays a blob) and answers the
//!   status, or the fetch error.
//! - `remember`: stores the body's reference in state (`ref` = `<hash>
//!   <size>`), as bytes. `forged-get`, `forged-echo` and `forged-post`
//!   (`url=`) use that stored reference in a later turn: get answers the
//!   error, echo fails the turn, post answers the fetch error.
//! - `limits`: tries `get` of 0 and of 1 MiB + 1 bytes and `write` of 1 MiB
//!   + 1 bytes; answers the three errors. `quota` (`size=`) writes until the
//!   writer refuses and answers how many bytes it took and the error.
//! - `touch` (`count=`): reads the body's first MiB `count` times without
//!   looking at it, and answers the bytes read (the blob I/O budget).
//! - `many-writers` (`n=`, `size=`): opens `n` writers at once, writes
//!   `size` bytes into each and keeps them all open; answers `opened <n>`.
//! - `write-discard` (`size=`): writes a blob of `size` bytes as `write`
//!   does, finishes it, and answers `discarded` without it.
//! - `open-writer`: writes into a writer it never finishes.
//! - `fail-after-write` writes a blob, then fails the turn.

use std::fmt::Write as _;

wit_bindgen::generate!({
    world: "actor",
    path: "../../../wit/kronik-actor.wit",
});

use exports::kronik::actor::handler::Guest;
use kronik::actor::blobs::{self, BlobError, Writer};
use kronik::actor::http_client::{self, FetchError, Request, Response};
use kronik::actor::state;
use kronik::actor::types::{
    BlobRef, HandlerError, HttpBody, HttpResponse, Input, Manifest, Message, Output, Route,
};

struct Media;

const MIB: u64 = 1 << 20;

fn route(method: &str, pattern: &str) -> Route {
    Route {
        method: method.to_string(),
        pattern: pattern.to_string(),
    }
}

/// The value of `name` in a query string `a=1&b=2` (no decoding).
fn query_value<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
}

fn query_u64(query: &str, name: &str, default: u64) -> u64 {
    query_value(query, name)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// FNV-1a, 64 bits: a checksum the guest can compute without a crate.
struct Fnv(u64);

impl Fnv {
    fn new() -> Fnv {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
    fn update(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= u64::from(*b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    fn hex(&self) -> String {
        format!("{:016x}", self.0)
    }
}

/// Byte `i` of the `write` pattern.
fn pattern(i: u64) -> u8 {
    ((i.wrapping_mul(31) + 7) % 251) as u8
}

fn error_name(e: &BlobError) -> String {
    match e {
        BlobError::NotHeld => "not-held".into(),
        BlobError::QuotaExceeded => "quota-exceeded".into(),
        BlobError::Erased => "erased".into(),
        BlobError::Invalid(why) => format!("invalid({why})"),
    }
}

fn fetch_error(e: &FetchError) -> String {
    match e {
        FetchError::Denied(why) => format!("denied({why})"),
        FetchError::Network(why) => format!("network({why})"),
        FetchError::Timeout => "timeout".into(),
        FetchError::TooLarge => "too-large".into(),
        FetchError::OutcomeUnknown => "outcome-unknown".into(),
    }
}

fn failed(what: &str, e: &BlobError) -> HandlerError {
    HandlerError::Failed(format!("{what}: {}", error_name(e)))
}

fn describe_body(body: &HttpBody) -> String {
    match body {
        HttpBody::Inline(bytes) => format!("inline {}", bytes.len()),
        HttpBody::Blob(blob) => format!("blob {} {}", blob.hash, blob.size),
    }
}

/// Reads a whole body in chunks of `chunk` bytes: (size, checksum).
fn sum(body: &HttpBody, chunk: u64) -> Result<(u64, String), HandlerError> {
    let mut fnv = Fnv::new();
    match body {
        HttpBody::Inline(bytes) => {
            fnv.update(bytes);
            Ok((bytes.len() as u64, fnv.hex()))
        }
        HttpBody::Blob(blob) => {
            let chunk = chunk.clamp(1, MIB) as u32;
            let mut offset = 0;
            while offset < blob.size {
                let bytes = blobs::get(blob, offset, chunk).map_err(|e| failed("get", &e))?;
                if bytes.is_empty() {
                    return Err(HandlerError::Failed(format!("get at {offset} was empty")));
                }
                fnv.update(&bytes);
                offset += bytes.len() as u64;
            }
            Ok((offset, fnv.hex()))
        }
    }
}

fn text(body: String) -> Output {
    Output::Http(HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: HttpBody::Inline(body.into_bytes()),
    })
}

fn respond(body: HttpBody) -> Output {
    Output::Http(HttpResponse {
        status: 200,
        headers: Vec::new(),
        body,
    })
}

fn fetch(method: &str, url: &str, body: HttpBody) -> Result<Response, FetchError> {
    http_client::fetch(&Request {
        method: method.to_string(),
        url: url.to_string(),
        headers: Vec::new(),
        body,
    })
}

fn forged() -> Result<BlobRef, HandlerError> {
    let stored = state::get("ref").ok_or_else(|| HandlerError::Rejected("no ref".into()))?;
    let stored = String::from_utf8_lossy(&stored).into_owned();
    let (hash, size) = stored
        .split_once(' ')
        .ok_or_else(|| HandlerError::Failed("bad ref".into()))?;
    Ok(BlobRef {
        hash: hash.to_string(),
        size: size.parse().map_err(|_| HandlerError::Failed("bad size".into()))?,
    })
}

fn write_pattern(size: u64, chunk: u64) -> Result<BlobRef, BlobError> {
    let writer = Writer::new();
    let chunk = chunk.clamp(1, MIB);
    let mut written = 0;
    while written < size {
        let n = chunk.min(size - written);
        let bytes: Vec<u8> = (written..written + n).map(pattern).collect();
        writer.write(&bytes)?;
        written += n;
    }
    writer.finish()
}

fn run(op: &str, query: &str, body: HttpBody) -> Result<Output, HandlerError> {
    Ok(match op {
        "info" => text(describe_body(&body)),
        "sum" => {
            let (size, hex) = sum(&body, query_u64(query, "chunk", MIB))?;
            text(format!("{size} {hex}"))
        }
        "ranges" => {
            let HttpBody::Blob(blob) = &body else {
                return Err(HandlerError::Rejected("ranges needs a blob body".into()));
            };
            let mut out = String::new();
            for range in query_value(query, "at").unwrap_or("").split(',') {
                let Some((offset, len)) = range.split_once(':') else {
                    continue;
                };
                let (offset, len): (u64, u32) = match (offset.parse(), len.parse()) {
                    (Ok(o), Ok(l)) => (o, l),
                    _ => return Err(HandlerError::Rejected(format!("bad range {range}"))),
                };
                let bytes = blobs::get(blob, offset, len).map_err(|e| failed("get", &e))?;
                let mut fnv = Fnv::new();
                fnv.update(&bytes);
                let _ = writeln!(out, "{offset}:{len}={} {}", bytes.len(), fnv.hex());
            }
            text(out)
        }
        "echo" => respond(body),
        "write" => {
            let blob = write_pattern(query_u64(query, "size", 0), query_u64(query, "chunk", MIB))
                .map_err(|e| failed("write", &e))?;
            respond(HttpBody::Blob(blob))
        }
        "fetch" | "fetch-sum" | "fetch-echo" => {
            let url = match &body {
                HttpBody::Inline(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                HttpBody::Blob(_) => return Err(HandlerError::Rejected("a URL body".into())),
            };
            let response = match fetch("GET", &url, HttpBody::Inline(Vec::new())) {
                Ok(response) => response,
                Err(e) => return Ok(text(fetch_error(&e))),
            };
            match op {
                "fetch" => text(format!(
                    "status {} {}",
                    response.status,
                    describe_body(&response.body)
                )),
                "fetch-sum" => {
                    let (size, hex) = sum(&response.body, MIB)?;
                    text(format!("{} {size} {hex}", describe_body(&response.body)))
                }
                _ => respond(response.body),
            }
        }
        "fetch-write" => {
            let url = match &body {
                HttpBody::Inline(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                HttpBody::Blob(_) => return Err(HandlerError::Rejected("a URL body".into())),
            };
            if let Err(e) = fetch("GET", &url, HttpBody::Inline(Vec::new())) {
                return Ok(text(fetch_error(&e)));
            }
            let blob = write_pattern(query_u64(query, "size", 0), MIB)
                .map_err(|e| failed("write", &e))?;
            respond(HttpBody::Blob(blob))
        }
        "write-post" => {
            let url = query_value(query, "url").unwrap_or("").to_string();
            let blob = write_pattern(query_u64(query, "size", 0), MIB)
                .map_err(|e| failed("write", &e))?;
            match fetch("POST", &url, HttpBody::Blob(blob)) {
                Ok(response) => text(format!("status {}", response.status)),
                Err(e) => text(fetch_error(&e)),
            }
        }
        "post" => {
            let url = query_value(query, "url").unwrap_or("").to_string();
            match fetch("POST", &url, body) {
                Ok(response) => text(format!("status {}", response.status)),
                Err(e) => text(fetch_error(&e)),
            }
        }
        "remember" => {
            let HttpBody::Blob(blob) = &body else {
                return Err(HandlerError::Rejected("remember needs a blob body".into()));
            };
            state::set("ref", format!("{} {}", blob.hash, blob.size).as_bytes());
            text("remembered".into())
        }
        "forged-get" => {
            let blob = forged()?;
            text(match blobs::get(&blob, 0, 1) {
                Ok(bytes) => format!("read {}", bytes.len()),
                Err(e) => error_name(&e),
            })
        }
        "forged-echo" => respond(HttpBody::Blob(forged()?)),
        "forged-post" => {
            let url = query_value(query, "url").unwrap_or("").to_string();
            match fetch("POST", &url, HttpBody::Blob(forged()?)) {
                Ok(response) => text(format!("status {}", response.status)),
                Err(e) => text(fetch_error(&e)),
            }
        }
        "limits" => {
            let HttpBody::Blob(blob) = &body else {
                return Err(HandlerError::Rejected("limits needs a blob body".into()));
            };
            let empty = blobs::get(blob, 0, 0).map(|b| b.len());
            let large = blobs::get(blob, 0, (MIB + 1) as u32).map(|b| b.len());
            let writer = Writer::new();
            let big = writer.write(&vec![0u8; (MIB + 1) as usize]);
            let show = |r: Result<usize, BlobError>| match r {
                Ok(n) => format!("ok {n}"),
                Err(e) => error_name(&e),
            };
            text(format!(
                "{}\n{}\n{}",
                show(empty),
                show(large),
                show(big.map(|()| 0))
            ))
        }
        "quota" => {
            let writer = Writer::new();
            let size = query_u64(query, "size", MIB);
            let mut taken = 0u64;
            let error = loop {
                let n = size.min(MIB);
                match writer.write(&vec![1u8; n as usize]) {
                    Ok(()) => taken += n,
                    Err(e) => break error_name(&e),
                }
            };
            text(format!("{taken} {error}"))
        }
        "touch" => {
            let HttpBody::Blob(blob) = &body else {
                return Err(HandlerError::Rejected("touch needs a blob body".into()));
            };
            let mut read = 0u64;
            for _ in 0..query_u64(query, "count", 1) {
                read += blobs::get(blob, 0, MIB as u32)
                    .map_err(|e| failed("get", &e))?
                    .len() as u64;
            }
            text(format!("{read}"))
        }
        "many-writers" => {
            let n = query_u64(query, "n", 1);
            let size = query_u64(query, "size", 0);
            let chunk = vec![7u8; size as usize];
            let mut open = Vec::new();
            for _ in 0..n {
                let writer = Writer::new();
                if size > 0 {
                    writer.write(&chunk).map_err(|e| failed("write", &e))?;
                }
                open.push(writer);
            }
            text(format!("opened {}", open.len()))
        }
        "write-discard" => {
            write_pattern(query_u64(query, "size", 0), MIB).map_err(|e| failed("write", &e))?;
            text("discarded".into())
        }
        "open-writer" => {
            let writer = Writer::new();
            writer.write(b"never finished").map_err(|e| failed("write", &e))?;
            std::mem::forget(writer);
            text("left open".into())
        }
        "fail-after-write" => {
            write_pattern(1000, 1000).map_err(|e| failed("write", &e))?;
            return Err(HandlerError::Failed("failed after a write".into()));
        }
        other => return Err(HandlerError::Rejected(format!("unknown op {other}"))),
    })
}

impl Guest for Media {
    fn describe() -> Manifest {
        Manifest {
            kind: "media".to_string(),
            schema_version: 0,
            routes: vec![
                route("POST", "/media/{key}/{op}"),
                route("GET", "/media/{key}/{op}"),
            ],
            capabilities: vec!["http:*".to_string()],
        }
    }

    fn handle(input: Input) -> Result<Output, HandlerError> {
        match input {
            Input::Http(request) => {
                let op = request.path.rsplit('/').next().unwrap_or("").to_string();
                run(&op, &request.query, request.body)
            }
            Input::Message(incoming) => {
                let Message { name, body, .. } = incoming.msg;
                run(&name, "", HttpBody::Inline(body))
            }
            Input::Timer(_) | Input::Migrate(_) => Ok(Output::None),
        }
    }
}

export!(Media);
