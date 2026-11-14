//! A small S3 look-alike for the restore tests: it serves a directory as a
//! bucket (the listing and the GET of an object are all a restore uses),
//! checks the SigV4 signature of every request against the credentials it
//! issued, and can hold a request, or answer that the credentials ran out, at
//! the first download of a snapshot's files, which a restore that gave up root
//! makes first thing after the drop.
//!
//! It also plays the pod-identity credentials endpoint (`GET /credentials`
//! with the token of a file as `Authorization`), which is how a token file that
//! only root can read reaches a restore over plain HTTP.

#![allow(
    dead_code,
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

/// What the stub issues and accepts.
pub struct Settings {
    pub bucket: String,
    pub root: PathBuf,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// The session token that goes with the credentials (temporary ones).
    pub session_token: Option<String>,
    /// What the credentials endpoint requires as `Authorization`.
    pub endpoint_token: String,
    /// Serve requests that are not signed (a public bucket).
    pub anonymous: bool,
}

/// One request, as the stub saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub code: &'static str,
    /// Whether the request carried an `Authorization` header.
    pub signed: bool,
}

pub struct Stub {
    pub port: u16,
    state: Arc<State>,
}

struct State {
    settings: Settings,
    seen: Mutex<Vec<Seen>>,
    credential_requests: AtomicUsize,
    /// A file the stub writes when it holds, and the one that releases it.
    hold: Mutex<Option<(PathBuf, PathBuf)>>,
    /// Answer `ExpiredToken` from the first download of a snapshot's files on.
    expire_at_download: AtomicBool,
    expired: AtomicBool,
    held: AtomicBool,
}

impl Stub {
    pub fn start(settings: Settings) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(State {
            settings,
            seen: Mutex::new(Vec::new()),
            credential_requests: AtomicUsize::new(0),
            hold: Mutex::new(None),
            expire_at_download: AtomicBool::new(false),
            expired: AtomicBool::new(false),
            held: AtomicBool::new(false),
        });
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let state = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let _ = serve(&state, stream);
                });
            }
        });
        Stub { port, state }
    }

    pub fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Holds the first download of a snapshot's files: writes `marker`, then
    /// waits until `release` exists (at most half a minute).
    pub fn hold_first_download(&self, marker: &Path, release: &Path) {
        *self.state.hold.lock().unwrap() = Some((marker.to_owned(), release.to_owned()));
    }

    /// From the first download of a snapshot's files on, answer that the
    /// temporary credentials have run out.
    pub fn expire_at_first_download(&self) {
        self.state.expire_at_download.store(true, Ordering::SeqCst);
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().unwrap().clone()
    }

    pub fn credential_requests(&self) -> usize {
        self.state.credential_requests.load(Ordering::SeqCst)
    }
}

type Headers = Vec<(String, String)>;

fn serve(state: &State, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if raw.len() > 64 * 1024 {
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let headers: Headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));

    let (status, code, content_type, body) = route(state, &method, path, query, &headers);
    state.seen.lock().unwrap().push(Seen {
        method: method.clone(),
        path: target.clone(),
        status,
        code,
        signed: header(&headers, "authorization").is_some(),
    });
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nETag: \"stub\"\r\nLast-Modified: Sat, 07 Nov 2026 00:00:00 GMT\r\n\r\n",
        body.len()
    )
    .into_bytes();
    if method != "HEAD" {
        response.extend_from_slice(&body);
    }
    stream.write_all(&response)?;
    stream.flush()
}

type Reply = (u16, &'static str, &'static str, Vec<u8>);

fn error(status: u16, code: &'static str, message: &str) -> Reply {
    (
        status,
        code,
        "application/xml",
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{message}</Message></Error>")
            .into_bytes(),
    )
}

fn route(state: &State, method: &str, path: &str, query: &str, headers: &Headers) -> Reply {
    let settings = &state.settings;
    if path == "/credentials" {
        // The pod-identity endpoint: the token of the file, once.
        let token = header(headers, "authorization").unwrap_or_default();
        if token != settings.endpoint_token {
            return error(403, "AccessDenied", "the token is not the one of the pod");
        }
        state.credential_requests.fetch_add(1, Ordering::SeqCst);
        let session = settings
            .session_token
            .as_deref()
            .map(|t| format!(",\"Token\":\"{t}\""))
            .unwrap_or_default();
        let body = format!(
            "{{\"AccessKeyId\":\"{}\",\"SecretAccessKey\":\"{}\"{session},\"Expiration\":\"2099-01-01T00:00:00Z\"}}",
            settings.access_key, settings.secret_key
        );
        return (200, "ok", "application/json", body.into_bytes());
    }
    if path.starts_with("/latest/") {
        // The metadata of an instance: not here.
        return error(404, "NotFound", "no instance metadata");
    }
    if method != "GET" && method != "HEAD" {
        return error(400, "MethodNotAllowed", "only GET is served");
    }
    if !settings.anonymous
        && let Err(refusal) = verify(state, method, path, query, headers)
    {
        return refusal;
    }
    let bucket_path = format!("/{}", settings.bucket);
    let key = if path == bucket_path || path == format!("{bucket_path}/") {
        None
    } else if let Some(key) = path.strip_prefix(&format!("{bucket_path}/")) {
        Some(percent_decode(key))
    } else {
        return error(404, "NoSuchBucket", "no such bucket");
    };
    match key {
        None => list(settings, query),
        Some(key) => {
            if is_snapshot_download(&key)
                && let Some(refusal) = at_first_download(state)
            {
                return refusal;
            }
            get_object(settings, &key)
        }
    }
}

/// A file of a snapshot (not its manifest): the first thing a restore fetches
/// once it is running as the owner of the data directory.
fn is_snapshot_download(key: &str) -> bool {
    key.contains("/snapshots/") && key.ends_with(".zst")
}

fn at_first_download(state: &State) -> Option<Reply> {
    if !state.held.swap(true, Ordering::SeqCst) {
        let hold = state.hold.lock().unwrap().clone();
        if let Some((marker, release)) = hold {
            std::fs::write(&marker, b"held").unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !release.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if state.expire_at_download.load(Ordering::SeqCst) {
            state.expired.store(true, Ordering::SeqCst);
        }
    }
    state
        .expired
        .load(Ordering::SeqCst)
        .then(|| error(400, "ExpiredToken", "The provided token has expired."))
}

fn header<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The set that SigV4 leaves alone: letters, digits and `-._~`.
fn strict_encode(text: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (keep_slash && b == b'/')
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// HMAC-SHA256 (RFC 2104) on top of the hash that the tests already have.
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Checks the `Authorization` header the way S3 does: the access key is one
/// that was issued, the session token is the one that goes with it, and the
/// signature is the one of the canonical request.
fn verify(
    state: &State,
    method: &str,
    path: &str,
    query: &str,
    headers: &Headers,
) -> Result<(), Reply> {
    let settings = &state.settings;
    let Some(authorization) = header(headers, "authorization") else {
        return Err(error(403, "AccessDenied", "the request is not signed"));
    };
    let Some(rest) = authorization.strip_prefix("AWS4-HMAC-SHA256 ") else {
        return Err(error(403, "AccessDenied", "not SigV4"));
    };
    let fields: BTreeMap<&str, &str> = rest.split(", ").filter_map(|f| f.split_once('=')).collect();
    let (Some(credential), Some(signed), Some(signature)) = (
        fields.get("Credential"),
        fields.get("SignedHeaders"),
        fields.get("Signature"),
    ) else {
        return Err(error(403, "AccessDenied", "malformed Authorization"));
    };
    let mut scope = credential.splitn(2, '/');
    let key_id = scope.next().unwrap_or_default();
    let scope = scope.next().unwrap_or_default();
    if key_id != settings.access_key {
        return Err(error(
            403,
            "InvalidAccessKeyId",
            "the access key is not known",
        ));
    }
    if let Some(token) = &settings.session_token
        && header(headers, "x-amz-security-token") != Some(token.as_str())
    {
        return Err(error(
            403,
            "InvalidToken",
            "the session token is missing or wrong",
        ));
    }
    if state.expired.load(Ordering::SeqCst) {
        return Err(error(
            400,
            "ExpiredToken",
            "The provided token has expired.",
        ));
    }
    let canonical_headers: String = signed
        .split(';')
        .map(|name| format!("{name}:{}\n", header(headers, name).unwrap_or_default()))
        .collect();
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (
                strict_encode(&percent_decode(k), false),
                strict_encode(&percent_decode(v), false),
            )
        })
        .collect();
    pairs.sort_unstable();
    let canonical_query = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let payload = header(headers, "x-amz-content-sha256").unwrap_or("UNSIGNED-PAYLOAD");
    let canonical =
        format!("{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed}\n{payload}");
    let date = header(headers, "x-amz-date").unwrap_or_default();
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac(
        format!("AWS4{}", settings.secret_key).as_bytes(),
        scope.split('/').next().unwrap_or_default().as_bytes(),
    )
    .to_vec();
    for part in scope.split('/').skip(1) {
        key = hmac(&key, part.as_bytes()).to_vec();
    }
    let expected = hex(&hmac(&key, to_sign.as_bytes()));
    if &expected != signature {
        return Err(error(
            403,
            "SignatureDoesNotMatch",
            "the signature does not match",
        ));
    }
    Ok(())
}

fn safe_path(settings: &Settings, key: &str) -> Option<PathBuf> {
    if key.split('/').any(|part| part == ".." || part == ".") {
        return None;
    }
    Some(settings.root.join(key))
}

fn get_object(settings: &Settings, key: &str) -> Reply {
    let Some(path) = safe_path(settings, key) else {
        return error(400, "InvalidRequest", "bad key");
    };
    match std::fs::read(&path) {
        Ok(bytes) if path.is_file() => (200, "ok", "application/octet-stream", bytes),
        _ => error(404, "NoSuchKey", "the key does not exist"),
    }
}

fn list(settings: &Settings, query: &str) -> Reply {
    let mut prefix = String::new();
    let mut delimiter = false;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "prefix" => prefix = percent_decode(v),
            "delimiter" => delimiter = !v.is_empty(),
            _ => {}
        }
    }
    let Some(directory) = safe_path(settings, prefix.trim_end_matches('/')) else {
        return error(400, "InvalidRequest", "bad prefix");
    };
    let mut contents = String::new();
    let mut prefixes = String::new();
    if let Ok(entries) = std::fs::read_dir(&directory) {
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let key = format!("{prefix}{name}");
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                if delimiter {
                    prefixes.push_str(&format!(
                        "<CommonPrefixes><Prefix>{key}/</Prefix></CommonPrefixes>"
                    ));
                }
            } else {
                contents.push_str(&format!(
                    "<Contents><Key>{key}</Key><LastModified>2026-11-07T00:00:00.000Z</LastModified><ETag>&quot;stub&quot;</ETag><Size>{}</Size></Contents>",
                    meta.len()
                ));
            }
        }
    }
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>{}</Name><Prefix>{prefix}</Prefix><IsTruncated>false</IsTruncated>{contents}{prefixes}</ListBucketResult>",
        settings.bucket
    );
    (200, "ok", "application/xml", body.into_bytes())
}
