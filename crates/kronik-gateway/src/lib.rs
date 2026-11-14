//! The HTTP gateway: routes from the deployed manifests, root inputs,
//! ingress `Idempotency-Key` and the turn timeout. The service function
//! [`Gateway::handle`] uses only `Env` and the node, so the simulator calls
//! it directly; [`server`] binds it to hyper on TCP (no TLS in M1). With a
//! [`PreviewRouter`] (M11), the host `<id>.<preview_domain>`, or
//! `/__preview/<id>/...` when no preview domain is set, goes to preview
//! forks instead of main.
//!
//! Long-lived connections (M24, docs/design/m24-connections.md §5): a
//! WebSocket upgrade, or a GET that an `SSE` route answers, is classified
//! before any body is read ([`Gateway::classify`]), and
//! [`Gateway::open_connection`] admits its open, waits for the owner's open
//! turn and answers the handshake; the caller attaches the connection's
//! transport to the node's hub.

pub mod body;

pub use body::{BlobBody, RequestBody, ResponseBody};
#[cfg(feature = "server")]
pub mod connections;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod tls;

pub mod subject;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::BoxFuture;
use kronik_core::env::{BodySource, BytesSource};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, valid_key};
use kronik_privacy::sealer::is_erased;
use kronik_proto::log::v1 as pb;
use kronik_sched::{BodyPolicy, Ingress, IngressExtras, Node, RouteEntry, TurnResult};

/// The path prefix of preview requests: `/__preview/<id>/...`.
pub const PREVIEW_PREFIX: &str = "/__preview/";

/// Preview forks (M11, ADR 0025): `kronik serve` sets one on the gateway;
/// the simulator and the test host do not.
pub trait PreviewRouter: Send + Sync {
    /// The routes of preview `id`'s code; `PREVIEW_NOT_FOUND` for an
    /// unknown or expired id.
    fn routes(&self, id: &str) -> BoxFuture<'_, Result<Vec<RouteEntry>, ApiError>>;
    /// Runs `http` as a new root input of preview `id` and returns the
    /// finished turn. Runs to its end even when the caller stops waiting.
    fn send(
        self: Arc<Self>,
        id: String,
        actor: ActorRef,
        http: pb::HttpInput,
        subject: Option<String>,
        authority: kronik_core::authority::AuthLease,
    ) -> BoxFuture<'static, Result<TurnResult, ApiError>>;
    /// How the gateway reads a request body for `kind` in preview `id` (M25
    /// §6.4), as the node does for main's code: a body above the threshold
    /// of a kind whose preview code reads blobs is written to the preview
    /// fork's blob space. Inline by default.
    fn body_policy(&self, _id: &str, _kind: &str) -> BodyPolicy {
        BodyPolicy::Inline
    }
}

/// Gateway settings.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// After this, the client gets 504 and the turn still completes.
    pub timeout: Duration,
    /// Largest accepted request body.
    pub max_body: usize,
    /// Where root inputs get their default subject (`privacy.subject_from`).
    pub subject_from: Option<subject::SubjectFrom>,
    /// Ingress idempotency header (`gateway.idempotency_header`). Compared
    /// ASCII case-insensitively. Default `Idempotency-Key`.
    pub idempotency_header: String,
    /// Reverse proxies (`gateway.trusted_proxies`): their connections are
    /// exempt from the per-client connection cap.
    pub trusted_proxies: Vec<IpNet>,
    /// Requests for the host `<id>.<preview_domain>` go to preview `<id>`
    /// (`gateway.preview_domain`, M11).
    pub preview_domain: Option<String>,
    /// How long an upload that becomes a blob may send nothing (M25 §6.2):
    /// it has no whole-body timeout, so a slow large upload is not cut off
    /// while bytes keep arriving.
    pub body_idle_timeout: Duration,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        GatewayConfig {
            timeout: Duration::from_secs(30),
            max_body: 1 << 20,
            subject_from: None,
            idempotency_header: "Idempotency-Key".into(),
            preview_domain: None,
            trusted_proxies: Vec::new(),
            body_idle_timeout: Duration::from_secs(30),
        }
    }
}

/// How long a client may take to send a body held in memory.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// A request whose body could not be read (the client went away).
fn unreadable(e: std::io::Error) -> ApiError {
    ApiError::new(
        ErrorCode::BadRequest,
        format!("the request body could not be read: {e}"),
    )
}

/// The request's `Content-Length`, when it has a valid one.
fn content_length(req: &HttpRequest) -> Option<u64> {
    req.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
}

/// An address or a CIDR block, such as `192.0.2.7`, `10.0.0.0/8` or
/// `2001:db8::/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u32,
}

impl IpNet {
    pub fn parse(s: &str) -> Result<IpNet, String> {
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("{s:?} is not an IP address or a CIDR block"))?;
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => bits,
            Some(p) => p
                .parse::<u32>()
                .ok()
                .filter(|p| *p <= bits)
                .ok_or_else(|| format!("{s:?}: the prefix length must be 0 to {bits}"))?,
        };
        // `::ffff:a.b.c.d/n` (n >= 96) is the IPv4 block a.b.c.d/(n-96);
        // `contains` compares IPv4-mapped peers as IPv4.
        if let IpAddr::V6(v6) = addr
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            if prefix < 96 {
                return Err(format!(
                    "{s:?}: an IPv4-mapped block needs a prefix of 96 to 128; write it as IPv4"
                ));
            }
            return Ok(IpNet {
                addr: IpAddr::V4(v4),
                prefix: prefix - 96,
            });
        }
        Ok(IpNet { addr, prefix })
    }

    /// Whether `ip` is in the block; an IPv4 client may arrive IPv4-mapped.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// A request as the service function sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The connection's peer, when the request came over the network.
    pub peer: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The header that carries the turn id on every turn response.
pub const TURN_ID_HEADER: &str = "kronik-turn-id";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Lit(String),
    Param(String),
}

#[derive(Debug, Clone)]
struct Route {
    kind: String,
    method: String,
    pattern: String,
    segs: Vec<Seg>,
}

fn parse_pattern(pattern: &str) -> Vec<Seg> {
    pattern
        .split('/')
        .skip(1)
        .map(
            |s| match s.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(name) => Seg::Param(name.to_owned()),
                None => Seg::Lit(s.to_owned()),
            },
        )
        .collect()
}

pub struct Gateway {
    node: Arc<Node>,
    cfg: GatewayConfig,
    routes: Mutex<(Option<u64>, Vec<Route>)>,
    preview: Option<Arc<dyn PreviewRouter>>,
}

fn to_routes(entries: Vec<RouteEntry>) -> Vec<Route> {
    entries
        .into_iter()
        .map(
            |RouteEntry {
                 kind,
                 method,
                 pattern,
             }| Route {
                segs: parse_pattern(&pattern),
                kind,
                method,
                pattern,
            },
        )
        .collect()
}

/// The methods a request with `method` can match: a GET also matches `SSE`
/// routes, which cannot overlap a GET route's pattern (M24 §2.5), so the
/// most specific of either decides.
fn methods_for(method: &str) -> &'static [&'static str] {
    match method {
        "GET" => &["GET", "SSE"],
        "HEAD" => &["HEAD"],
        "POST" => &["POST"],
        "PUT" => &["PUT"],
        "PATCH" => &["PATCH"],
        "DELETE" => &["DELETE"],
        "OPTIONS" => &["OPTIONS"],
        _ => &[],
    }
}

/// The most specific route for `method` and `path`: fewest parameters,
/// literals first. A GET also matches `SSE` routes ([`methods_for`]).
fn find(routes: &[Route], method: &str, path: &str) -> Result<Matched, ApiError> {
    find_in(routes, methods_for(method), method, path)
}

fn find_in(
    routes: &[Route],
    methods: &[&str],
    method: &str,
    path: &str,
) -> Result<Matched, ApiError> {
    let segs: Vec<&str> = path.split('/').skip(1).collect();
    let mut best: Option<(Vec<bool>, &Route)> = None;
    for r in routes
        .iter()
        .filter(|r| methods.contains(&r.method.as_str()))
    {
        if r.segs.len() != segs.len() {
            continue;
        }
        let ok = r.segs.iter().zip(&segs).all(|(p, s)| match p {
            Seg::Lit(l) => l == s,
            Seg::Param(_) => !s.is_empty(),
        });
        if !ok {
            continue;
        }
        let shape: Vec<bool> = r.segs.iter().map(|p| matches!(p, Seg::Param(_))).collect();
        if best.as_ref().is_none_or(|(b, _)| shape < *b) {
            best = Some((shape, r));
        }
    }
    let Some((_, r)) = best else {
        return Err(ApiError::new(
            ErrorCode::RouteNotFound,
            format!("no route for {method} {path}"),
        ));
    };
    let mut params = Vec::new();
    for (p, s) in r.segs.iter().zip(&segs) {
        if let Seg::Param(name) = p {
            let v = percent_decode(s).ok_or_else(|| {
                ApiError::new(ErrorCode::BadRequest, format!("invalid path segment {s:?}"))
            })?;
            params.push((name.clone(), v));
        }
    }
    Ok(Matched {
        kind: r.kind.clone(),
        method: r.method.clone(),
        pattern: r.pattern.clone(),
        params,
    })
}

/// The preview a request is for and its path within the preview. Without
/// `domain`, the path `/__preview/<id>/rest` -> (`id`, `/rest`). With it,
/// only the host: any host under `<domain>` (any case, port and one
/// trailing dot ignored) -> (the labels before the domain, path), so a
/// mistyped id answers `PREVIEW_NOT_FOUND` instead of reaching main, and
/// the prefix stays main's (P-F1: proposal code never runs on main's origin
/// when previews have their own).
fn preview_target(req: &HttpRequest, domain: Option<&str>) -> Option<(String, String)> {
    let Some(domain) = domain else {
        let rest = req.path.strip_prefix(PREVIEW_PREFIX)?;
        let (id, path) = rest
            .find('/')
            .map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
        return Some((id.to_owned(), path.to_owned()));
    };
    let host = req
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("host"))?
        .1
        .to_ascii_lowercase();
    let host = host.rsplit_once(':').map_or(host.as_str(), |(h, _)| h);
    let host = host.strip_suffix('.').unwrap_or(host);
    let id = host.strip_suffix(domain)?.strip_suffix('.')?;
    (!id.is_empty()).then(|| (id.to_owned(), req.path.clone()))
}

/// The response headers a prefix preview keeps (N3): what a page needs to
/// render and cache. Anything else could act on main's origin (HSTS,
/// Clear-Site-Data, NEL/Report-To, Set-Cookie, a redirecting Location).
const PREFIX_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-language",
    "content-disposition",
    "cache-control",
    "expires",
    "etag",
    "last-modified",
    "vary",
    "retry-after",
    TURN_ID_HEADER,
];

/// A preview answering through the path prefix is on main's origin: it
/// keeps only [`PREFIX_HEADERS`], and its page runs sandboxed (an opaque
/// origin), so its scripts can neither read main's cookies nor call main
/// with them.
fn sandbox(headers: &mut Vec<(String, String)>) {
    headers.retain(|(n, _)| PREFIX_HEADERS.iter().any(|h| n.eq_ignore_ascii_case(h)));
    headers.push(("content-security-policy".into(), "sandbox".into()));
}

/// A route match: kind, the route's method, pattern and parameters in
/// order.
struct Matched {
    kind: String,
    method: String,
    pattern: String,
    params: Vec<(String, String)>,
}

/// What a request is (M24 §5.1), decided before any body is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Http,
    /// A WebSocket upgrade.
    WebSocket,
    /// A GET that an `SSE` route answers.
    Sse,
}

/// The values of every header named `name`, in order.
fn header_values<'a>(req: &'a HttpRequest, name: &'a str) -> impl Iterator<Item = &'a str> {
    req.headers
        .iter()
        .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Whether a header of `name` lists `token` (comma-separated, any case).
fn header_has_token(req: &HttpRequest, name: &str, token: &str) -> bool {
    header_values(req, name)
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// A WebSocket upgrade: a GET whose `Upgrade` lists `websocket` and whose
/// `Connection` lists `upgrade` (RFC 6455 §4.2.1).
pub fn is_websocket_upgrade(req: &HttpRequest) -> bool {
    req.method == "GET"
        && header_has_token(req, "upgrade", "websocket")
        && header_has_token(req, "connection", "upgrade")
}

/// The subprotocols a WebSocket client offered: its `Sec-WebSocket-Protocol`
/// headers in order, split at commas and trimmed, as the runtime derives
/// them from the recorded request.
fn offered_subprotocols(req: &HttpRequest) -> Vec<String> {
    header_values(req, "sec-websocket-protocol")
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// What [`Gateway::open_connection`] answers: the response for the client,
/// and the connection's id when its owner accepted it. The caller then
/// attaches the connection's transport to the hub, or abandons it
/// (`Hub::abandon`) when it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAnswer {
    pub response: HttpResponse,
    pub connection: Option<String>,
    pub protocol: Option<pb::ConnectionProtocol>,
}

/// Abandons a connection whose open is being answered unless disarmed
/// (`Hub::abandon` is harmless for one that is gone).
struct AbandonGuard {
    hub: Arc<kronik_sched::connections::Hub>,
    conn: Option<String>,
}

impl AbandonGuard {
    fn disarm(mut self) {
        self.conn = None;
    }
}

impl Drop for AbandonGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.hub.abandon(&conn);
        }
    }
}

/// How long a client waits before it reconnects after `CONNECTION_LIMIT`.
const CONNECTION_LIMIT_RETRY_SECS: &str = "5";

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn error(e: &ApiError) -> HttpResponse {
    // A failure inside Kronik may name files of the data directory: the log
    // gets the message, the client (anyone, at the gateway) a generic one.
    let generic;
    let e = if matches!(e.code, ErrorCode::Internal | ErrorCode::StorageCorrupt) {
        tracing::warn!(code = e.code.as_str(), message = %e.message, "gateway request failed");
        generic = ApiError::new(
            e.code,
            "the request failed inside Kronik; its log has the details",
        );
        &generic
    } else {
        e
    };
    HttpResponse {
        status: e.code.http_status(),
        headers: vec![("content-type".into(), "application/json".into())],
        body: e.to_json().to_string().into_bytes(),
    }
}

fn sealable_bytes(s: Option<&pb::Sealable>) -> Vec<u8> {
    match s.and_then(|s| s.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.clone(),
        _ => Vec::new(),
    }
}

/// Who a request is for and from ([`Gateway::identify`]).
struct Identity {
    actor: ActorRef,
    idempotency_key: String,
    subject: Option<String>,
}

/// How a root input's body was read (M25 §6.2).
enum InputBody {
    /// Held: the request's `body`.
    Inline,
    /// Spooled into a blob: its reference and the body's BLAKE3 digest.
    Blob { blob: pb::BlobRef, digest: [u8; 32] },
    /// Only hashed (a retry of a request running or answered): the body's
    /// BLAKE3 digest. Never recorded.
    Hashed { digest: [u8; 32] },
}

/// What the body phase read (M25 §6.2).
enum ReadBody {
    Inline(Vec<u8>),
    Spooled {
        blob: pb::BlobRef,
        digest: [u8; 32],
        lease: kronik_blob::Lease,
    },
    Hashed([u8; 32]),
}

/// A gateway answer whose body may stream (M25 §6.1).
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: ResponseBody,
}

impl From<HttpResponse> for Answer {
    fn from(r: HttpResponse) -> Answer {
        Answer {
            status: r.status,
            headers: r.headers,
            body: ResponseBody::Inline(r.body),
        }
    }
}

impl Answer {
    /// The answer with its body read whole, for tests and the simulator.
    /// A blob that cannot be read becomes BLOB_MISSING.
    pub async fn into_response(self) -> HttpResponse {
        let body = match self.body {
            ResponseBody::Inline(b) => b,
            ResponseBody::Blob(blob) => match blob.collect().await {
                Ok(b) => b,
                Err(e) => {
                    return error(&ApiError::new(
                        ErrorCode::BlobMissing,
                        format!("the response blob could not be read: {e}"),
                    ));
                }
            },
            ResponseBody::Events(_) => Vec::new(),
        };
        HttpResponse {
            status: self.status,
            headers: self.headers,
            body,
        }
    }
}

/// A request as a root input ([`Gateway::input`]).
struct Admitted {
    actor: ActorRef,
    http: pb::HttpInput,
    subject: Option<String>,
    /// The version-3 hash of a request with a key (M25 §6.3).
    legacy_hash: Option<Vec<u8>>,
}

/// What must match for a repeated `Idempotency-Key`: a version byte
/// ([`INGRESS_HASH_VERSION`], 4) and a hash of the request (method, path,
/// query, and the body as its BLAKE3 digest, so a body the gateway spooled
/// and one it held hash alike: M25 §6.3) and of who asks, so a saved
/// response is never replayed to another requester. Who asks is the
/// request's subject when it has one; without a subject, the value of its
/// `Authorization` header (none: anonymous). Never `Cookie`, and never
/// `Authorization` next to a subject: a load balancer's rotating sticky
/// cookie or a refreshed token must not turn a client's own retry into
/// IDEMPOTENCY_KEY_REUSED (v0.1 re-review R3). Keyed with a master-derived
/// key when the node has one (it sits next to sealed values and must not
/// confirm a guess of them); BLAKE3 with a domain string otherwise. Rows
/// saved with version 3 match [`legacy_request_hash`] during their TTL;
/// rows of older versions never match: such a key is used anew.
pub fn request_hash(
    req: &HttpRequest,
    subject: Option<&str>,
    sealer: &kronik_privacy::sealer::Sealer,
) -> Vec<u8> {
    request_hash_of_body(req, blake3::hash(&req.body).as_bytes(), subject, sealer)
}

/// [`request_hash`] of a request whose body was read as a stream:
/// `body_digest` is the BLAKE3 digest of the body, and `req.body` is not
/// read.
pub fn request_hash_of_body(
    req: &HttpRequest,
    body_digest: &[u8; 32],
    subject: Option<&str>,
    sealer: &kronik_privacy::sealer::Sealer,
) -> Vec<u8> {
    hash_request(
        INGRESS_HASH_VERSION,
        "kronik.ingress.v4",
        req,
        body_digest,
        subject,
        sealer,
    )
}

/// The version-3 hash of a request whose body the gateway holds (the body
/// itself where version 4 has its digest), which rows saved before version 4
/// hold. It is passed to the node, never recorded (M25 §6.3).
pub fn legacy_request_hash(
    req: &HttpRequest,
    subject: Option<&str>,
    sealer: &kronik_privacy::sealer::Sealer,
) -> Vec<u8> {
    hash_request(
        kronik_sched::LEGACY_INGRESS_HASH_VERSION,
        "kronik.ingress.v3",
        req,
        &req.body,
        subject,
        sealer,
    )
}

fn hash_request(
    version: u8,
    purpose: &str,
    req: &HttpRequest,
    body: &[u8],
    subject: Option<&str>,
    sealer: &kronik_privacy::sealer::Sealer,
) -> Vec<u8> {
    let requester = match subject {
        Some(s) => [b"subject\0".as_slice(), s.as_bytes()].concat(),
        None => {
            let mut h = blake3::Hasher::new();
            for (_, v) in req
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            {
                h.update(&(v.len() as u64).to_le_bytes());
                h.update(v.as_bytes());
            }
            [b"authorization\0".as_slice(), h.finalize().as_bytes()].concat()
        }
    };
    let parts: [&[u8]; 5] = [
        req.method.as_bytes(),
        req.path.as_bytes(),
        req.query.as_bytes(),
        body,
        &requester,
    ];
    let hash = sealer.keyed_hash(purpose, &parts).unwrap_or_else(|| {
        let mut h = blake3::Hasher::new();
        h.update(purpose.as_bytes());
        h.update(b"\0");
        for p in parts {
            h.update(&(p.len() as u64).to_le_bytes());
            h.update(p);
        }
        *h.finalize().as_bytes()
    });
    let mut out = Vec::with_capacity(33);
    out.push(version);
    out.extend_from_slice(&hash);
    out
}

pub use kronik_sched::INGRESS_HASH_VERSION;

fn reserved_admin_cookie(cookie: &str) -> bool {
    cookie.split_once('=').is_some_and(|(name, _)| {
        matches!(name.trim(), "__Host-kronik-session" | "__Host-kronik-login")
    })
}

fn strip_admin_cookies(headers: &mut Vec<(String, String)>) {
    headers.retain_mut(|(name, value)| {
        if !name.eq_ignore_ascii_case("cookie") || !value.split(';').any(reserved_admin_cookie) {
            return true;
        }
        // Cookies cross ports on the same hostname; never admit admin credentials to a guest.
        let mut kept = String::new();
        for cookie in value
            .split(';')
            .filter(|cookie| !reserved_admin_cookie(cookie))
        {
            if cookie.trim().is_empty() {
                continue;
            }
            if !kept.is_empty() {
                kept.push(';');
            }
            kept.push_str(cookie);
        }
        *value = kept;
        !value.is_empty()
    });
}

/// The actor's headers of an accepted open (M24), for the 101 or the
/// event stream's 200: without what belongs to the handshake, the stream or
/// Kronik, and without a header whose value is the tombstone of a subject
/// erased while the open turn ran (ADR 0123). The accept itself stands.
fn accept_headers(accept: &pb::ConnectionAccept) -> Vec<(String, String)> {
    accept
        .headers
        .iter()
        .filter(|h| {
            let name = h.name.to_ascii_lowercase();
            !kronik_core::http::hop_by_hop(&name)
                && name != TURN_ID_HEADER
                && !name.starts_with("sec-websocket-")
                && !matches!(name.as_str(), "content-type" | "cache-control")
                && !h.value.as_ref().is_some_and(is_erased)
        })
        .map(|h| {
            (
                h.name.clone(),
                String::from_utf8_lossy(&sealable_bytes(h.value.as_ref())).into_owned(),
            )
        })
        .filter(|(name, value)| {
            !name.eq_ignore_ascii_case("set-cookie") || !reserved_admin_cookie(value)
        })
        .collect()
}

/// The HTTP response for a finished turn.
pub fn turn_response(r: &TurnResult) -> HttpResponse {
    let id = (TURN_ID_HEADER.to_owned(), r.turn_id.to_string());
    if !r.committed() {
        let code = if r.outcome.error_code == ErrorCode::EffectOutcomeUnknown.as_str() {
            ErrorCode::EffectOutcomeUnknown
        } else {
            ErrorCode::TurnFailed
        };
        let mut resp = error(&ApiError::new(
            code,
            format!("turn {} failed: {}", r.turn_id, r.outcome.message),
        ));
        resp.headers.push(id);
        return resp;
    }
    match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            // A final response only. The length and the connection are
            // hyper's, and the turn id is Kronik's: an actor's would let it
            // spill into the next response on the connection, or spoof one.
            // The contract is 200 to 599: an informational status is no final
            // response, and 600 and above are no HTTP status a client or a
            // proxy in front of Kronik knows.
            let status = u16::try_from(h.status).unwrap_or(1000);
            if !(200..=599).contains(&status) {
                // The actor's mistake, so not INTERNAL, which hides the message.
                let why = if status < 200 {
                    "which is not a final response"
                } else {
                    "which is not an HTTP status"
                };
                let mut resp = error(&ApiError::new(
                    ErrorCode::TurnFailed,
                    format!(
                        "turn {} answered with status {}, {why}: an actor answers with 200 \
                         to 599",
                        r.turn_id, h.status
                    ),
                ));
                resp.headers.push(id);
                return resp;
            }
            // A turn that ran across its subject's erasure answers with the
            // erasure's tombstones, and a saved response of an erased
            // subject has nothing else to give (ADR 0123): the client learns
            // that the answer is gone, not a body with holes in it.
            let erased = h
                .headers
                .iter()
                .any(|hd| hd.value.as_ref().is_some_and(is_erased))
                || matches!(h.body.as_ref().and_then(|b| b.value.as_ref()),
                    Some(pb::body::Value::Inline(s)) if is_erased(s));
            if erased {
                let mut resp = error(&ApiError::new(
                    ErrorCode::SubjectErased,
                    format!(
                        "the response of turn {} held values of a data subject who was erased while it ran",
                        r.turn_id
                    ),
                ));
                resp.headers.push(id);
                return resp;
            }
            let mut headers: Vec<(String, String)> = h
                .headers
                .iter()
                .filter(|hd| {
                    !kronik_core::http::hop_by_hop(&hd.name)
                        && !hd.name.eq_ignore_ascii_case(TURN_ID_HEADER)
                })
                .map(|hd| {
                    (
                        hd.name.clone(),
                        String::from_utf8_lossy(&sealable_bytes(hd.value.as_ref())).into_owned(),
                    )
                })
                .collect();
            headers.retain(|(name, value)| {
                !name.eq_ignore_ascii_case("set-cookie") || !reserved_admin_cookie(value)
            });
            headers.push(id);
            let body = match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => sealable_bytes(Some(s)),
                _ => Vec::new(),
            };
            HttpResponse {
                status,
                headers,
                body,
            }
        }
        // Only an open turn accepts (M24), and the connection path answers
        // it; an HTTP turn never does.
        Some(pb::outcome::Output::Accept(_)) => {
            let mut resp = error(&ApiError::new(
                ErrorCode::TurnFailed,
                format!(
                    "turn {} answered with a connection accept, which is not an HTTP response",
                    r.turn_id
                ),
            ));
            resp.headers.push(id);
            resp
        }
        Some(pb::outcome::Output::Reply(m)) => HttpResponse {
            status: 200,
            headers: vec![
                (
                    "content-type".into(),
                    if m.content_type.is_empty() {
                        "application/octet-stream".into()
                    } else {
                        m.content_type.clone()
                    },
                ),
                id,
            ],
            body: sealable_bytes(m.body.as_ref()),
        },
        None => HttpResponse {
            status: 204,
            headers: vec![id],
            body: Vec::new(),
        },
    }
}

impl Gateway {
    pub fn new(node: Arc<Node>, cfg: GatewayConfig) -> Gateway {
        Gateway {
            node,
            cfg,
            routes: Mutex::new((None, Vec::new())),
            preview: None,
        }
    }

    /// Routes `<id>.<preview_domain>`, or `/__preview/<id>/...` without a
    /// preview domain, to `router` (M11).
    pub fn with_preview(mut self, router: Arc<dyn PreviewRouter>) -> Gateway {
        self.preview = Some(router);
        self
    }

    fn matched(&self, method: &str, path: &str) -> Result<Matched, ApiError> {
        let (epoch, entries) = self.node.routes();
        let mut cache = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        if cache.0 != Some(epoch) {
            cache.1 = to_routes(entries);
            cache.0 = Some(epoch);
        }
        find(&cache.1, method, path)
    }

    /// Serves one request: route, admit the root input, wait for the turn
    /// (at most the gateway timeout) and map its outcome to a response.
    /// Whether `peer` may set the request's subject: always without
    /// `trusted_proxies`, else only a trusted proxy.
    fn subject_trusted(&self, peer: Option<IpAddr>) -> bool {
        let trusted = &self.cfg.trusted_proxies;
        trusted.is_empty() || peer.is_some_and(|ip| trusted.iter().any(|n| n.contains(ip)))
    }

    /// Serves one request whose body is `req.body`, and reads the answer
    /// whole: the simulator and tests ([`Gateway::respond`] streams).
    pub async fn handle(&self, mut req: HttpRequest) -> HttpResponse {
        let body = RequestBody::Inline(std::mem::take(&mut req.body));
        self.respond(req, body).await.into_response().await
    }

    /// Serves one HTTP request whose body is `body` (`req.body` is not
    /// read): route it, read its body (M25 §6.2), admit the root input, wait
    /// for the turn (at most the gateway timeout) and answer, a blob body
    /// streamed from the store (§6.5).
    pub async fn respond(&self, req: HttpRequest, body: RequestBody) -> Answer {
        match self.serve(req, body).await {
            Ok(a) => a,
            Err(e) => error(&e).into(),
        }
    }

    async fn serve(&self, mut req: HttpRequest, body: RequestBody) -> Result<Answer, ApiError> {
        if let Some(router) = &self.preview
            && let Some((id, path)) = preview_target(&req, self.cfg.preview_domain.as_deref())
        {
            return self
                .serve_preview(router.clone(), id, path, req, body)
                .await;
        }
        if is_websocket_upgrade(&req) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "a WebSocket upgrade needs the gateway's connection path (open_connection)",
            ));
        }
        // The route before a byte of the body is read (M25 §6.1).
        let m = self.matched(&req.method, &req.path)?;
        if m.method == "SSE" {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "an SSE route needs the gateway's connection path (open_connection)",
            ));
        }
        strip_admin_cookies(&mut req.headers);
        let (input_body, upload, body_withheld) = match self.node.body_policy(&m.kind) {
            BodyPolicy::Inline => {
                req.body = self.read_inline(body).await?;
                (InputBody::Inline, None, false)
            }
            BodyPolicy::Blobs {
                threshold,
                upload_bytes,
            } => {
                let who = self.identify(&req, &m)?;
                let main = kronik_blob::Space::Main;
                match self
                    .read_for_blobs(&req, &who, body, threshold, upload_bytes, &main)
                    .await?
                {
                    ReadBody::Inline(bytes) => {
                        req.body = bytes;
                        (InputBody::Inline, None, false)
                    }
                    ReadBody::Spooled {
                        blob,
                        digest,
                        lease,
                    } => (InputBody::Blob { blob, digest }, Some(lease), false),
                    ReadBody::Hashed(digest) => (InputBody::Hashed { digest }, None, true),
                }
            }
        };
        let Admitted {
            actor,
            http,
            subject,
            legacy_hash,
        } = self.input(req, m, input_body)?;
        let extras = IngressExtras {
            legacy_hash,
            upload,
            body_withheld,
        };
        let main = kronik_blob::Space::Main;
        let (waiter, joined) = match self.node.ingress_with(actor, http, subject, extras)? {
            Ingress::Done(r) => return Ok(self.turn_answer(&r, &main).await),
            Ingress::Started(w) => (w, false),
            Ingress::Joined(w) => (w, true),
        };
        match self
            .node
            .env()
            .timeout(self.cfg.timeout, waiter.wait())
            .await
        {
            Ok(r) => Ok(self.turn_answer(&r?, &main).await),
            Err(_) if joined => Err(ApiError::new(
                ErrorCode::IdempotencyInFlight,
                "the original request with this Idempotency-Key is still running",
            )),
            Err(_) => Err(self.timed_out()),
        }
    }

    /// Reads a body into memory, up to `[gateway] max_body`, within
    /// [`BODY_TIMEOUT`].
    async fn read_inline(&self, body: RequestBody) -> Result<Vec<u8>, ApiError> {
        let max = self.cfg.max_body;
        let mut source = match body {
            RequestBody::Inline(b) if b.len() > max => {
                return Err(ApiError::new(
                    ErrorCode::PayloadTooLarge,
                    format!("the request body is {} bytes, the limit is {max}", b.len()),
                ));
            }
            RequestBody::Inline(b) => return Ok(b),
            RequestBody::Stream(source) => source,
        };
        let read = async {
            let mut out = Vec::new();
            while let Some(chunk) = source.next().await.map_err(unreadable)? {
                if out.len() + chunk.len() > max {
                    return Err(ApiError::new(
                        ErrorCode::PayloadTooLarge,
                        format!("the request body exceeds {max} bytes"),
                    ));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(out)
        };
        match self.node.env().timeout(BODY_TIMEOUT, read).await {
            Ok(read) => read,
            Err(_) => Err(ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "the request body did not arrive within {} s",
                    BODY_TIMEOUT.as_secs()
                ),
            )),
        }
    }

    /// The next chunk of an upload, which must come within
    /// `[gateway] body_idle_timeout`.
    async fn next_chunk(
        &self,
        source: &mut Box<dyn BodySource>,
    ) -> Result<Option<bytes::Bytes>, ApiError> {
        let idle = self.cfg.body_idle_timeout;
        match self.node.env().timeout(idle, source.next()).await {
            Ok(chunk) => chunk.map_err(unreadable),
            Err(_) => Err(ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "the request body stopped arriving: nothing for {} s",
                    idle.as_secs()
                ),
            )),
        }
    }

    /// The body phase of a kind whose code reads blobs (M25 §6.2): a body
    /// up to `threshold` bytes is held; a larger one is written to a blob
    /// as it arrives, up to `upload_bytes`, with no more than a frame of it
    /// in memory; the retry of a request running or answered is only
    /// hashed. Each chunk must arrive within `[gateway] body_idle_timeout`.
    /// The blob goes to `space`: main's, or a preview's (§6.4).
    async fn read_for_blobs(
        &self,
        req: &HttpRequest,
        who: &Identity,
        body: RequestBody,
        threshold: u64,
        upload_bytes: u64,
        space: &kronik_blob::Space,
    ) -> Result<ReadBody, ApiError> {
        let kind = who.actor.kind.as_str();
        let too_large = |size: String| {
            ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!("the request body is {size}, the limit of {kind} is {upload_bytes} bytes"),
            )
            .with_hint(format!(
                "kronik limits set {kind} --upload-size <size> --reason '...'"
            ))
        };
        if let Some(len) = content_length(req)
            && len > upload_bytes
        {
            return Err(too_large(format!("{len} bytes")));
        }
        let mut source: Box<dyn BodySource> = match body {
            RequestBody::Inline(b) => Box::new(BytesSource::new(bytes::Bytes::from(b))),
            RequestBody::Stream(source) => source,
        };
        // A retry of a request running or answered: only its hash matters.
        if self.node.ingress_peek(&who.actor, &who.idempotency_key)? {
            let mut hasher = blake3::Hasher::new();
            let mut size = 0u64;
            while let Some(chunk) = self.next_chunk(&mut source).await? {
                size += chunk.len() as u64;
                if size > upload_bytes {
                    return Err(too_large(format!("over {upload_bytes} bytes")));
                }
                hasher.update(&chunk);
            }
            return Ok(ReadBody::Hashed(*hasher.finalize().as_bytes()));
        }
        // Up to the threshold, held.
        let mut held = Vec::new();
        while held.len() as u64 <= threshold {
            match self.next_chunk(&mut source).await? {
                Some(chunk) => held.extend_from_slice(&chunk),
                None => return Ok(ReadBody::Inline(held)),
            }
        }
        // Larger: a blob, written as the body arrives. Only now is there
        // something to store, so only now do the log's and the blob
        // store's reserves count.
        self.node.check_running()?;
        if let Some(free) = self.node.blobs_below_reserve() {
            return Err(ApiError::new(
                ErrorCode::BlobStoreFull,
                format!("the blob store has {free} bytes free, below [blobs] disk_reserve"),
            ));
        }
        let store = self
            .node
            .blob_store()
            .ok_or_else(|| ApiError::new(ErrorCode::Internal, "the node has no blob store"))?
            .clone();
        let keys = match &who.subject {
            None => None,
            Some(subject) => {
                let entropy = self.node.env().entropy.clone();
                let fill = move |bytes: &mut [u8]| entropy.fill(bytes);
                Some(
                    self.node
                        .sealer()
                        .blob_keys(subject, &fill, self.node.env().clock.wall_ms())
                        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?,
                )
            }
        };
        // Renewed until the turn's result arrives, however long the upload
        // and the turn's wait take.
        let lease = store.leases().take("upload");
        lease.keep_alive(self.node.env());
        let stored = |e: kronik_blob::BlobError| match e {
            kronik_blob::BlobError::TooLarge { .. } => {
                too_large(format!("over {upload_bytes} bytes"))
            }
            kronik_blob::BlobError::StoreFull { .. } => {
                ApiError::new(ErrorCode::BlobStoreFull, e.to_string())
            }
            other => ApiError::new(
                ErrorCode::Internal,
                format!("storing the request body: {other}"),
            ),
        };
        let mut writer = store
            .writer(space.clone(), keys, upload_bytes, lease.clone())
            .await
            .map_err(stored)?;
        let mut digest = blake3::Hasher::new();
        digest.update(&held);
        writer.write(&held).await.map_err(stored)?;
        drop(held);
        while let Some(chunk) = self.next_chunk(&mut source).await? {
            digest.update(&chunk);
            writer.write(&chunk).await.map_err(stored)?;
        }
        let meta = writer.finish().await.map_err(stored)?;
        // Durable before the input that references it exists.
        store
            .ensure_durable(space, &[meta.id])
            .await
            .map_err(stored)?;
        kronik_metrics::add(
            "kronik_blob_written_bytes_total",
            &[("source", "upload")],
            meta.size,
        );
        Ok(ReadBody::Spooled {
            blob: meta.to_pb(),
            digest: *digest.finalize().as_bytes(),
            lease,
        })
    }

    /// The answer for a finished turn: [`turn_response`], with a blob body
    /// streamed from the store (M25 §6.5). An erased blob is 410
    /// SUBJECT_ERASED, a missing one 500 BLOB_MISSING, both with the turn
    /// id. A preview's blobs are in its fork's space (§6.4).
    async fn turn_answer(&self, r: &TurnResult, space: &kronik_blob::Space) -> Answer {
        let resp = turn_response(r);
        let blob = match &r.outcome.output {
            Some(pb::outcome::Output::Http(h)) if r.committed() => {
                match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                    Some(pb::body::Value::Blob(blob)) => Some(blob),
                    _ => None,
                }
            }
            _ => None,
        };
        let Some(blob) = blob.filter(|_| (200..=599).contains(&resp.status)) else {
            return resp.into();
        };
        match self.open_blob(blob, space).await {
            Ok(body) => Answer {
                status: resp.status,
                headers: resp.headers,
                body: ResponseBody::Blob(body),
            },
            Err(e) => {
                let mut resp = error(&e);
                resp.headers
                    .push((TURN_ID_HEADER.to_owned(), r.turn_id.to_string()));
                resp.into()
            }
        }
    }

    /// Opens a response blob in `space` (which also finds main's blobs)
    /// under a streaming lease.
    async fn open_blob(
        &self,
        blob: &pb::BlobRef,
        space: &kronik_blob::Space,
    ) -> Result<BlobBody, ApiError> {
        let missing = |why: String| ApiError::new(ErrorCode::BlobMissing, why);
        let store = self.node.blob_store().ok_or_else(|| {
            missing("the response is a blob and the node has no blob store".into())
        })?;
        let meta = kronik_blob::BlobMeta::from_pb(blob).map_err(|e| missing(e.to_string()))?;
        // Renewed while the answer streams, however slow the client.
        let lease = store.leases().take("stream");
        lease.add(meta.id);
        lease.keep_alive(self.node.env());
        let access = self.node.sealer().blob_key_access();
        let reader = store
            .reader(space, &meta, &access)
            .await
            .map_err(|e| match e {
                kronik_blob::BlobError::Erased => ApiError::new(
                    ErrorCode::SubjectErased,
                    "the response is a blob of a subject that was erased",
                ),
                other => missing(format!("the response blob {}: {other}", meta.id)),
            })?;
        Ok(BlobBody::new(reader, lease))
    }

    /// What a request is (M24 §5.1): a WebSocket upgrade, a GET that an
    /// `SSE` route of main answers (the most specific match of the GET and
    /// SSE routes), or HTTP. A preview's requests are HTTP here; its own
    /// path refuses connections.
    pub fn classify(&self, req: &HttpRequest) -> RequestKind {
        if self.preview.is_some()
            && preview_target(req, self.cfg.preview_domain.as_deref()).is_some()
        {
            return RequestKind::Http;
        }
        if is_websocket_upgrade(req) {
            return RequestKind::WebSocket;
        }
        match self.matched(&req.method, &req.path) {
            Ok(m) if m.method == "SSE" => RequestKind::Sse,
            _ => RequestKind::Http,
        }
    }

    /// The client address that `[connections] max_per_client` counts (M24
    /// §5.11, review M1): the peer, or, when the peer is a trusted proxy,
    /// the address it forwards: the rightmost `X-Forwarded-For` entry that
    /// is no trusted proxy itself. A trusted proxy that forwards none is
    /// exempt (`true`): its clients cannot be told apart.
    fn client_address(&self, req: &HttpRequest) -> (Option<IpAddr>, bool) {
        let trusted = |ip: IpAddr| self.cfg.trusted_proxies.iter().any(|n| n.contains(ip));
        let Some(peer) = req.peer else {
            return (None, false);
        };
        if !trusted(peer) {
            return (Some(peer), false);
        }
        let forwarded: Vec<&str> = header_values(req, "x-forwarded-for")
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .collect();
        for entry in forwarded.iter().rev() {
            // `[v6]:port`, `v4:port` and bare addresses.
            let host = entry
                .strip_prefix('[')
                .and_then(|r| r.split_once(']').map(|(h, _)| h))
                .unwrap_or_else(|| match entry.split_once(':') {
                    Some((h, port)) if !port.contains(':') => h,
                    _ => entry,
                });
            match host.parse::<IpAddr>() {
                Ok(ip) if trusted(ip) => continue,
                Ok(ip) => return (Some(ip), false),
                // A value that is no address names no client.
                Err(_) => break,
            }
        }
        (Some(peer), true)
    }

    /// Opens a long-lived connection (M24 §5.3 and §5.4, steps 1 to 5,
    /// without the socket): checks the handshake, matches the route, admits
    /// the open as a root input of the route's actor within the hub's caps,
    /// waits for the open turn (at most the gateway timeout; after it the
    /// hub closes an eventual accept as `abandoned`) and answers. An accept
    /// answers `101 Switching Protocols` (WebSocket) or the `200` event
    /// stream's headers (SSE) with the actor's headers and the turn id; a
    /// refusal or a failure answers like an HTTP turn.
    pub async fn open_connection(&self, req: HttpRequest) -> OpenAnswer {
        match self.open(req).await {
            Ok(answer) => answer,
            Err(e) => {
                let mut response = error(&e);
                if e.code == ErrorCode::ConnectionLimit {
                    response
                        .headers
                        .push(("retry-after".into(), CONNECTION_LIMIT_RETRY_SECS.into()));
                }
                OpenAnswer {
                    response,
                    connection: None,
                    protocol: None,
                }
            }
        }
    }

    async fn open(&self, req: HttpRequest) -> Result<OpenAnswer, ApiError> {
        if self.preview.is_some()
            && preview_target(&req, self.cfg.preview_domain.as_deref()).is_some()
        {
            return Err(ApiError::new(
                ErrorCode::NotImplemented,
                "previews do not take WebSocket or SSE connections",
            ));
        }
        let has_body = !req.body.is_empty()
            || header_values(&req, "content-length").any(|v| v.trim() != "0")
            || header_values(&req, "transfer-encoding").next().is_some();
        if has_body {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "a WebSocket upgrade or an SSE request has no body",
            ));
        }
        let websocket = is_websocket_upgrade(&req);
        let (protocol, m, key) = if websocket {
            if !header_values(&req, "sec-websocket-version").any(|v| v.trim() == "13") {
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    "a WebSocket upgrade needs Sec-WebSocket-Version: 13",
                ));
            }
            let key = header_values(&req, "sec-websocket-key")
                .next()
                .map(|k| k.trim().to_owned())
                .filter(|k| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD
                        .decode(k)
                        .is_ok_and(|b| b.len() == 16)
                })
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::BadRequest,
                        "a WebSocket upgrade needs a Sec-WebSocket-Key of 16 base64 bytes",
                    )
                })?;
            let m = {
                let (epoch, entries) = self.node.routes();
                let mut cache = self.routes.lock().unwrap_or_else(|e| e.into_inner());
                if cache.0 != Some(epoch) {
                    cache.1 = to_routes(entries);
                    cache.0 = Some(epoch);
                }
                find_in(&cache.1, &["WEBSOCKET"], "WEBSOCKET", &req.path)?
            };
            (pb::ConnectionProtocol::Websocket, m, Some(key))
        } else {
            let m = self.matched(&req.method, &req.path)?;
            if m.method != "SSE" {
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    format!(
                        "{} {} is not a WebSocket upgrade or an SSE request",
                        req.method, req.path
                    ),
                ));
            }
            (pb::ConnectionProtocol::Sse, m, None)
        };
        let offered = offered_subprotocols(&req);
        let (client, exempt) = self.client_address(&req);
        let Admitted {
            actor,
            http,
            subject,
            ..
        } = self.input(req, m, InputBody::Inline)?;
        let (conn, waiter) = self
            .node
            .connection_open(actor, http, protocol, subject, client, exempt)?;
        // Every way out of here but an accept handed to the caller
        // abandons the connection, including this future being dropped
        // because the client left while the open turn ran (review S3).
        let guard = AbandonGuard {
            hub: self.node.hub().clone(),
            conn: Some(conn.clone()),
        };
        let r = match self
            .node
            .env()
            .timeout(self.cfg.timeout, waiter.wait())
            .await
        {
            Ok(r) => r?,
            Err(_) => return Err(self.timed_out()),
        };
        let accept = match (&r.outcome.output, r.committed()) {
            (Some(pb::outcome::Output::Accept(a)), true) => a,
            _ => {
                return Ok(OpenAnswer {
                    response: turn_response(&r),
                    connection: None,
                    protocol: None,
                });
            }
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        let status = match key {
            Some(key) => {
                headers.push(("upgrade".into(), "websocket".into()));
                headers.push(("connection".into(), "Upgrade".into()));
                headers.push((
                    "sec-websocket-accept".into(),
                    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes()),
                ));
                // The value at the recorded position of the live request's
                // offered list (the record keeps no copy, §6.1).
                if let Some(p) = accept
                    .subprotocol_index
                    .and_then(|i| offered.get(usize::try_from(i).ok()?))
                {
                    headers.push(("sec-websocket-protocol".into(), p.clone()));
                }
                101
            }
            None => {
                headers.push(("content-type".into(), "text/event-stream".into()));
                headers.push(("cache-control".into(), "no-store".into()));
                headers.push(("x-accel-buffering".into(), "no".into()));
                200
            }
        };
        headers.extend(accept_headers(accept));
        headers.push((TURN_ID_HEADER.into(), r.turn_id.to_string()));
        // From here the caller attaches the connection's transport or
        // abandons it; the hub abandons it if neither happens in time.
        guard.disarm();
        Ok(OpenAnswer {
            response: HttpResponse {
                status,
                headers,
                body: Vec::new(),
            },
            connection: Some(conn),
            protocol: Some(protocol),
        })
    }

    /// The largest frame a connection's owner kind takes: its
    /// `message_bytes` under the current configuration.
    pub fn message_bytes_for_connection(&self, conn: &str) -> usize {
        let kind = self
            .node
            .store()
            .db()
            .connection(conn)
            .ok()
            .flatten()
            .map(|row| row.actor.kind);
        let limits = match kind {
            Some(kind) => self.node.config_now().limits(&kind),
            None => kronik_effects::KindLimits::default(),
        };
        usize::try_from(limits.message_bytes).unwrap_or(usize::MAX)
    }

    fn timed_out(&self) -> ApiError {
        ApiError::new(
            ErrorCode::GatewayTimeout,
            format!(
                "the turn did not finish within {} ms; it still completes",
                self.cfg.timeout.as_millis()
            ),
        )
    }

    /// A request for preview `id`, at `path` within it: matched against the
    /// preview's routes and run as a root input of the preview fork. No
    /// ingress deduplication: its key and hash are cleared, so the fork
    /// stores no `ingress_keys` row per request (N1).
    async fn serve_preview(
        &self,
        router: Arc<dyn PreviewRouter>,
        id: String,
        path: String,
        mut req: HttpRequest,
        body: RequestBody,
    ) -> Result<Answer, ApiError> {
        // New input, refused like main's on a fatal node or a full disk.
        self.node.check_running()?;
        // This public host request starts a new native operation. The factory
        // returns the stored NativeExecution lease, never a new token issuer.
        let authority = self.node.local_operator_authority()?;
        let routes = to_routes(router.routes(&id).await?);
        req.path = path;
        // M24 §5.12: previews take no WebSocket or SSE connections yet.
        let previews_take_none = || {
            ApiError::new(
                ErrorCode::NotImplemented,
                "previews do not take WebSocket or SSE connections",
            )
        };
        if is_websocket_upgrade(&req) {
            return Err(previews_take_none());
        }
        let m = find(&routes, &req.method, &req.path)?;
        if m.method == "SSE" {
            return Err(previews_take_none());
        }
        // A preview's uploads and blob answers are in its fork's space.
        let space = kronik_blob::Space::Fork(id.clone());
        let (input_body, upload) = match router.body_policy(&id, &m.kind) {
            BodyPolicy::Inline => {
                req.body = self.read_inline(body).await?;
                (InputBody::Inline, None)
            }
            BodyPolicy::Blobs {
                threshold,
                upload_bytes,
            } => {
                strip_admin_cookies(&mut req.headers);
                let mut who = self.identify(&req, &m)?;
                // Previews keep no idempotency keys: nothing to peek at, and
                // a body is never only hashed.
                who.idempotency_key.clear();
                match self
                    .read_for_blobs(&req, &who, body, threshold, upload_bytes, &space)
                    .await?
                {
                    ReadBody::Spooled {
                        blob,
                        digest,
                        lease,
                    } => (InputBody::Blob { blob, digest }, Some(lease)),
                    ReadBody::Inline(bytes) => {
                        req.body = bytes;
                        (InputBody::Inline, None)
                    }
                    ReadBody::Hashed(_) => {
                        return Err(ApiError::new(
                            ErrorCode::Internal,
                            "a preview request's body was only hashed",
                        ));
                    }
                }
            }
        };
        let Admitted {
            actor,
            mut http,
            subject,
            ..
        } = self.input(req, m, input_body)?;
        http.idempotency_key.clear();
        http.request_hash.clear();
        // On main's origin the browser sends main's credentials (N2): the
        // proposal's code must not see them. The subject is already read.
        if self.cfg.preview_domain.is_none() {
            http.headers.retain(|h| {
                !["cookie", "authorization", "proxy-authorization"]
                    .iter()
                    .any(|n| h.name.eq_ignore_ascii_case(n))
            });
        }
        let turn = router.send(id, actor, http, subject, authority);
        let mut answer = match self.node.env().timeout(self.cfg.timeout, turn).await {
            Ok(r) => self.turn_answer(&r?, &space).await,
            Err(_) => return Err(self.timed_out()),
        };
        // The upload's blob is the input's now; the turn's result is in.
        drop(upload);
        if self.cfg.preview_domain.is_none() {
            sandbox(&mut answer.headers);
        }
        Ok(answer)
    }

    /// Who a request is for and from (M25 §6.2: known before its body is
    /// read): its actor, its idempotency key and its subject.
    fn identify(&self, req: &HttpRequest, m: &Matched) -> Result<Identity, ApiError> {
        let key = m
            .params
            .iter()
            .find(|(n, _)| n == "key")
            .map_or("_", |(_, v)| v.as_str());
        if !valid_key(key) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("invalid actor key {key:?}"),
            ));
        }
        let actor = ActorRef {
            kind: m.kind.clone(),
            key: key.to_owned(),
        };
        let header = self.cfg.idempotency_header.as_str();
        let idempotency_key = req
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(header))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let subject = match &self.cfg.subject_from {
            None => None,
            Some(from) => {
                let subject = from.subject(&req.headers);
                // With trusted proxies configured, only they may say who the
                // subject is: a client reaching the gateway directly could
                // set the header (or the bearer token) to any subject.
                // Refused rather than dropped: without its subject the
                // request's data would be stored unsealed and could not be
                // erased.
                if !matches!(subject, Ok(None)) && !self.subject_trusted(req.peer) {
                    let peer = req
                        .peer
                        .map_or_else(|| "an unknown peer".to_owned(), |p| p.to_string());
                    return Err(ApiError::new(
                        ErrorCode::BadRequest,
                        format!(
                            "the request carries a subject ({}) but came from {peer}, which is not in [gateway] trusted_proxies",
                            from.source()
                        ),
                    )
                    .with_hint(
                        "The subject header is accepted only from [gateway] trusted_proxies: send the request through the proxy, or add the proxy's address (as it connects) to trusted_proxies.",
                    ));
                }
                subject.map_err(|e| ApiError::new(ErrorCode::BadRequest, e))?
            }
        };
        Ok(Identity {
            actor,
            idempotency_key,
            subject,
        })
    }

    /// The root input of a matched request: its actor, the HTTP input and
    /// its subject, with its body as the body phase read it.
    fn input(
        &self,
        mut req: HttpRequest,
        m: Matched,
        body: InputBody,
    ) -> Result<Admitted, ApiError> {
        strip_admin_cookies(&mut req.headers);
        let Identity {
            actor,
            idempotency_key,
            subject,
        } = self.identify(&req, &m)?;
        // With a key: the version-4 hash, recorded, and for a body the
        // gateway holds the version-3 one of rows saved before it (M25
        // §6.3), never recorded.
        let sealer = self.node.sealer();
        let (request_hash, legacy_hash) = match (&body, idempotency_key.is_empty()) {
            (_, true) => (Vec::new(), None),
            (InputBody::Inline, false) => (
                request_hash(&req, subject.as_deref(), sealer),
                Some(legacy_request_hash(&req, subject.as_deref(), sealer)),
            ),
            (InputBody::Blob { digest, .. } | InputBody::Hashed { digest }, false) => (
                request_hash_of_body(&req, digest, subject.as_deref(), sealer),
                None,
            ),
        };
        // The request is the subject's data: every value carries the tag
        // (I9). With a subject, path, query and parameter values go into
        // the sealable fields; the route pattern and the method are not
        // user data and stay plain.
        let tagged = |bytes: Vec<u8>| pb::Sealable {
            subject: subject.clone(),
            value: Some(pb::sealable::Value::Plain(bytes)),
        };
        let sealed = subject.is_some();
        let (path, sealed_path) = if sealed {
            (String::new(), Some(tagged(req.path.into_bytes())))
        } else {
            (req.path, None)
        };
        let (query, sealed_query) = if sealed {
            (String::new(), Some(tagged(req.query.into_bytes())))
        } else {
            (req.query, None)
        };
        let http = pb::HttpInput {
            method: req.method,
            path,
            query,
            params: m
                .params
                .into_iter()
                .map(|(name, value)| match sealed {
                    true => pb::Param {
                        name,
                        value: String::new(),
                        sealed_value: Some(tagged(value.into_bytes())),
                    },
                    false => pb::Param {
                        name,
                        value,
                        sealed_value: None,
                    },
                })
                .collect(),
            headers: req
                .headers
                .into_iter()
                .map(|(name, value)| pb::Header {
                    name,
                    value: Some(tagged(value.into_bytes())),
                })
                .collect(),
            // A spooled body is its blob, whose reference carries the
            // subject (I9); a hashed one is never recorded.
            body: Some(pb::Body {
                value: Some(match body {
                    InputBody::Blob { blob, .. } => pb::body::Value::Blob(blob),
                    InputBody::Inline | InputBody::Hashed { .. } => {
                        pb::body::Value::Inline(tagged(req.body))
                    }
                }),
            }),
            route: m.pattern,
            idempotency_key,
            request_hash,
            sealed_path,
            sealed_query,
        };
        Ok(Admitted {
            actor,
            http,
            subject,
            legacy_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use kronik_privacy::MasterKey;
    use kronik_privacy::keystore::Pseudonyms;
    use kronik_privacy::sealer::Sealer;

    use super::*;

    fn req(path: &str, host: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            path: path.into(),
            query: String::new(),
            headers: vec![("Host".into(), host.into())],
            body: Vec::new(),
            peer: None,
        }
    }

    /// P-F1, P-F6: the prefix only without a preview domain; with one, any
    /// host under it, in any case, with a port or a trailing dot.
    #[test]
    fn preview_targets_from_the_prefix_or_the_host() {
        let t = |path, host, domain| preview_target(&req(path, host), domain);
        let some = |id: &str, path: &str| Some((id.to_owned(), path.to_owned()));
        assert_eq!(t("/__preview/v-1/a/b", "x", None), some("v-1", "/a/b"));
        assert_eq!(t("/__preview/v-1", "x", None), some("v-1", "/"));
        assert_eq!(t("/__preview/v-1/", "x", None), some("v-1", "/"));
        assert_eq!(t("/a/b", "v-1.p.example", None), None);
        let d = Some("p.example");
        assert_eq!(t("/__preview/v-1/a", "app.example", d), None);
        assert_eq!(
            t("/__preview/v-1/a", "v-2.p.example", d),
            some("v-2", "/__preview/v-1/a")
        );
        assert_eq!(t("/a", "V-1.P.Example:8443", d), some("v-1", "/a"));
        assert_eq!(t("/a", "v-1.p.example.", d), some("v-1", "/a"));
        assert_eq!(t("/a", "v-1.p.example.:80", d), some("v-1", "/a"));
        assert_eq!(t("/a", "x.v-1.p.example", d), some("x.v-1", "/a"));
        assert_eq!(t("/a", "p.example", d), None);
        assert_eq!(t("/a", "v-1.xp.example", d), None);
    }

    /// P-F1: a response through the prefix drops Set-Cookie (any case) and
    /// carries the sandbox policy.
    #[test]
    fn a_prefix_response_sets_no_cookie_and_is_sandboxed() {
        let mut headers = vec![
            ("Set-Cookie".into(), "s=1".into()),
            ("set-cookie".into(), "t=2".into()),
            ("content-type".into(), "text/html".into()),
        ];
        sandbox(&mut headers);
        assert_eq!(
            headers,
            [
                ("content-type".to_owned(), "text/html".to_owned()),
                ("content-security-policy".to_owned(), "sandbox".to_owned()),
            ]
        );
    }

    /// The contract is 200 to 599 (#68): an actor's 1xx, 600 to 999 and
    /// anything that does not fit a status is `TURN_FAILED`; 200 and 599 pass.
    #[test]
    fn only_statuses_200_to_599_reach_the_client() {
        let answered = |status: u32| {
            turn_response(&TurnResult {
                turn_id: kronik_core::ids::TurnId {
                    branch: "main".into(),
                    lsn: 7,
                },
                outcome: pb::Outcome {
                    kind: pb::OutcomeKind::Committed as i32,
                    output: Some(pb::outcome::Output::Http(pb::HttpResponse {
                        status,
                        ..Default::default()
                    })),
                    ..Default::default()
                },
                scrubbed_with: None,
            })
        };
        for status in [200, 404, 599] {
            assert_eq!(answered(status).status, status as u16);
        }
        for status in [0, 101, 199, 600, 700, 999, 1000, 70_000] {
            let r = answered(status);
            let body = String::from_utf8(r.body).unwrap();
            assert_eq!(r.status, 500, "{status}: {body}");
            assert!(
                body.contains("\"TURN_FAILED\"") && body.contains(&format!("status {status},")),
                "{status}: {body}"
            );
            assert!(
                r.headers
                    .iter()
                    .any(|(n, v)| n == TURN_ID_HEADER && v == "main:7"),
                "{:?}",
                r.headers
            );
        }
    }

    /// ADR 0123: a turn that ran across its subject's erasure answers with
    /// the erasure's tombstones, and so does a saved response of an erased
    /// subject. The client gets `SUBJECT_ERASED` (410) and the turn id, never
    /// a body with holes in it; an open's tombstoned headers are left out
    /// and the accept stands.
    #[test]
    fn an_answer_that_holds_an_erased_subjects_values_is_subject_erased() {
        let tombstone = || {
            Some(pb::Sealable {
                subject: Some("user:1".into()),
                value: Some(pb::sealable::Value::Sealed(
                    kronik_privacy::sealer::erased_value(2),
                )),
            })
        };
        let plain = |b: &str| {
            Some(pb::Sealable {
                subject: Some("user:2".into()),
                value: Some(pb::sealable::Value::Plain(b.as_bytes().to_vec())),
            })
        };
        let answered = |headers: Vec<pb::Header>, body| {
            turn_response(&TurnResult {
                turn_id: kronik_core::ids::TurnId {
                    branch: "main".into(),
                    lsn: 9,
                },
                outcome: pb::Outcome {
                    kind: pb::OutcomeKind::Committed as i32,
                    output: Some(pb::outcome::Output::Http(pb::HttpResponse {
                        status: 200,
                        headers,
                        body: Some(pb::Body {
                            value: Some(pb::body::Value::Inline(body)),
                        }),
                    })),
                    ..Default::default()
                },
                scrubbed_with: None,
            })
        };
        let header = |value| pb::Header {
            name: "x-name".into(),
            value,
        };
        let erased_body = answered(vec![], tombstone().unwrap());
        let erased_header = answered(vec![header(tombstone())], plain("ok").unwrap());
        for r in [erased_body, erased_header] {
            let body = String::from_utf8(r.body).unwrap();
            assert_eq!(r.status, 410, "{body}");
            assert!(
                body.contains("\"SUBJECT_ERASED\"") && body.contains("turn main:9"),
                "{body}"
            );
            assert!(
                r.headers
                    .iter()
                    .any(|(n, v)| n == TURN_ID_HEADER && v == "main:9")
            );
        }
        let fine = answered(vec![header(plain("ada"))], plain("ok").unwrap());
        assert_eq!((fine.status, fine.body.as_slice()), (200, b"ok".as_slice()));

        let accept = pb::ConnectionAccept {
            headers: vec![
                pb::Header {
                    name: "x-room".into(),
                    value: plain("lobby"),
                },
                pb::Header {
                    name: "x-user".into(),
                    value: tombstone(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            accept_headers(&accept),
            [("x-room".to_owned(), "lobby".to_owned())]
        );
    }

    #[test]
    fn a_failure_inside_kronik_names_no_file() {
        let r = error(&ApiError::new(
            ErrorCode::Internal,
            "SQL open: invalid path /var/lib/kronik/branches/main/sql/ab/x.db",
        ));
        let body = String::from_utf8(r.body).unwrap();
        assert_eq!(r.status, 500);
        assert!(body.contains("\"INTERNAL\""), "{body}");
        assert!(!body.contains("/var/lib"), "{body}");
        // Other errors keep their message.
        let r = error(&ApiError::new(ErrorCode::RouteNotFound, "no route GET /x"));
        assert!(
            String::from_utf8(r.body)
                .unwrap()
                .contains("no route GET /x")
        );
    }

    /// H8, M6: the idempotency hash covers who asks (subject, credential
    /// headers) and is keyed with the master-derived key.
    /// M25 §6.3: version 4 hashes the body's BLAKE3 digest, so a body the
    /// gateway streamed and one it held hash alike; version 3 (the body
    /// itself) differs and carries its own version byte.
    #[test]
    fn version_4_hashes_held_and_streamed_bodies_alike() {
        let req = |body: &[u8]| HttpRequest {
            method: "POST".into(),
            path: "/media/a/upload".into(),
            query: "x=1".into(),
            headers: vec![("authorization".into(), "Bearer t".into())],
            peer: None,
            body: body.to_vec(),
        };
        let keyed = Sealer::plain()
            .with_pseudonyms(Pseudonyms::new(&MasterKey::from_bytes([1; 32]).unwrap()).unwrap());
        for sealer in [&keyed, &Sealer::plain()] {
            let body = vec![7u8; 100_000];
            let held = request_hash(&req(&body), None, sealer);
            let streamed =
                request_hash_of_body(&req(&[]), blake3::hash(&body).as_bytes(), None, sealer);
            assert_eq!(held, streamed);
            assert_eq!((held.len(), held[0]), (33, 4));
            let legacy = legacy_request_hash(&req(&body), None, sealer);
            assert_eq!((legacy.len(), legacy[0]), (33, 3));
            assert_ne!(legacy[1..], held[1..]);
            assert_ne!(held, request_hash(&req(b"other"), None, sealer));
        }
    }

    #[test]
    fn the_request_hash_covers_the_requester_and_is_keyed() {
        let req = |headers: &[(&str, &str)]| HttpRequest {
            method: "GET".into(),
            path: "/notes/n1".into(),
            query: String::new(),
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            peer: None,
            body: Vec::new(),
        };
        let keyed = Sealer::plain()
            .with_pseudonyms(Pseudonyms::new(&MasterKey::from_bytes([1; 32]).unwrap()).unwrap());
        let plain = Sealer::plain();
        let a = request_hash(&req(&[]), Some("user:1"), &keyed);
        assert_eq!((a.len(), a[0]), (33, INGRESS_HASH_VERSION));
        assert_eq!(a, request_hash(&req(&[]), Some("user:1"), &keyed));
        assert_ne!(a, request_hash(&req(&[]), Some("user:2"), &keyed));
        assert_ne!(a, request_hash(&req(&[]), None, &keyed));
        // With a subject, credential headers don't count (R3): a rotated
        // sticky cookie or a refreshed token is the same requester.
        for h in [
            ("Authorization", "Bearer refreshed"),
            ("cookie", "AWSALB=rotated"),
        ] {
            assert_eq!(a, request_hash(&req(&[h]), Some("user:1"), &keyed));
        }
        // Without one, Authorization tells requesters apart; Cookie never.
        let anon = request_hash(&req(&[]), None, &keyed);
        assert_ne!(
            anon,
            request_hash(&req(&[("Authorization", "Bearer x")]), None, &keyed)
        );
        assert_eq!(
            anon,
            request_hash(&req(&[("cookie", "session=1")]), None, &keyed)
        );
        // Unrelated headers don't change it; without the key it differs.
        assert_eq!(
            a,
            request_hash(&req(&[("accept", "*/*")]), Some("user:1"), &keyed)
        );
        assert_ne!(a, request_hash(&req(&[]), Some("user:1"), &plain));
    }

    #[test]
    fn trusted_proxies_are_addresses_or_blocks() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let one = IpNet::parse("127.0.0.1").unwrap();
        assert!(one.contains(ip("127.0.0.1")) && !one.contains(ip("127.0.0.2")));
        assert!(one.contains(ip("::ffff:127.0.0.1")));
        let block = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(block.contains(ip("10.200.3.4")) && !block.contains(ip("11.0.0.1")));
        let v6 = IpNet::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8::7")) && !v6.contains(ip("2001:db9::7")));
        assert!(IpNet::parse("0.0.0.0/0").unwrap().contains(ip("192.0.2.1")));
        // Written IPv4-mapped, they still match IPv4 peers (plain or mapped).
        let mapped = IpNet::parse("::ffff:10.0.0.1").unwrap();
        assert!(mapped.contains(ip("10.0.0.1")) && mapped.contains(ip("::ffff:10.0.0.1")));
        let mapped = IpNet::parse("::ffff:10.0.0.0/104").unwrap();
        assert!(mapped.contains(ip("10.9.9.9")) && !mapped.contains(ip("11.0.0.1")));
        assert!(IpNet::parse("::ffff:0.0.0.0/95").is_err());
        for bad in ["proxy", "10.0.0.0/33", "::1/129", "10.0.0.0/x"] {
            assert!(IpNet::parse(bad).is_err(), "{bad}");
        }
    }
}
