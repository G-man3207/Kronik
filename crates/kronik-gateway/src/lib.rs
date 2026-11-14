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
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, valid_key};
use kronik_proto::log::v1 as pb;
use kronik_sched::{Ingress, Node, RouteEntry, TurnResult};

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
        }
    }
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
fn sandboxed(mut resp: HttpResponse) -> HttpResponse {
    resp.headers
        .retain(|(n, _)| PREFIX_HEADERS.iter().any(|h| n.eq_ignore_ascii_case(h)));
    resp.headers
        .push(("content-security-policy".into(), "sandbox".into()));
    resp
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

/// What must match for a repeated `Idempotency-Key`: a version byte
/// ([`INGRESS_HASH_VERSION`]) and a hash of
/// the request (method, path, query, body) and of who asks, so a saved
/// response is never replayed to another requester. Who asks is the
/// request's subject when it has one; without a subject, the value of its
/// `Authorization` header (none: anonymous). Never `Cookie`, and never
/// `Authorization` next to a subject: a load balancer's rotating sticky
/// cookie or a refreshed token must not turn a client's own retry into
/// IDEMPOTENCY_KEY_REUSED (v0.1 re-review R3). Keyed with a master-derived
/// key when the node has one (it sits next to sealed values and must not
/// confirm a guess of them); BLAKE3 with a domain string otherwise. Rows
/// saved with an older version never match: such a key is used anew.
pub fn request_hash(
    req: &HttpRequest,
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
        &req.body,
        &requester,
    ];
    const PURPOSE: &str = "kronik.ingress.v3";
    let hash = sealer.keyed_hash(PURPOSE, &parts).unwrap_or_else(|| {
        let mut h = blake3::Hasher::new();
        h.update(PURPOSE.as_bytes());
        h.update(b"\0");
        for p in parts {
            h.update(&(p.len() as u64).to_le_bytes());
            h.update(p);
        }
        *h.finalize().as_bytes()
    });
    let mut out = Vec::with_capacity(33);
    out.push(INGRESS_HASH_VERSION);
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

    pub async fn handle(&self, req: HttpRequest) -> HttpResponse {
        match self.serve(req).await {
            Ok(r) => r,
            Err(e) => error(&e),
        }
    }

    async fn serve(&self, req: HttpRequest) -> Result<HttpResponse, ApiError> {
        if req.body.len() > self.cfg.max_body {
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!(
                    "the request body is {} bytes, the limit is {}",
                    req.body.len(),
                    self.cfg.max_body
                ),
            ));
        }
        if let Some(router) = &self.preview
            && let Some((id, path)) = preview_target(&req, self.cfg.preview_domain.as_deref())
        {
            return self.serve_preview(router.clone(), id, path, req).await;
        }
        if is_websocket_upgrade(&req) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "a WebSocket upgrade needs the gateway's connection path (open_connection)",
            ));
        }
        let m = self.matched(&req.method, &req.path)?;
        if m.method == "SSE" {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "an SSE route needs the gateway's connection path (open_connection)",
            ));
        }
        let (actor, http, subject) = self.input(req, m)?;
        let (waiter, joined) = match self.node.ingress(actor, http, subject)? {
            Ingress::Done(r) => return Ok(turn_response(&r)),
            Ingress::Started(w) => (w, false),
            Ingress::Joined(w) => (w, true),
        };
        match self
            .node
            .env()
            .timeout(self.cfg.timeout, waiter.wait())
            .await
        {
            Ok(r) => Ok(turn_response(&r?)),
            Err(_) if joined => Err(ApiError::new(
                ErrorCode::IdempotencyInFlight,
                "the original request with this Idempotency-Key is still running",
            )),
            Err(_) => Err(self.timed_out()),
        }
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
        let (actor, http, subject) = self.input(req, m)?;
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
        // The actor's headers, without what belongs to the handshake, the
        // stream or Kronik.
        headers.extend(
            accept
                .headers
                .iter()
                .filter(|h| {
                    let name = h.name.to_ascii_lowercase();
                    !kronik_core::http::hop_by_hop(&name)
                        && name != TURN_ID_HEADER
                        && !name.starts_with("sec-websocket-")
                        && !matches!(name.as_str(), "content-type" | "cache-control")
                })
                .map(|h| {
                    (
                        h.name.clone(),
                        String::from_utf8_lossy(&sealable_bytes(h.value.as_ref())).into_owned(),
                    )
                })
                .filter(|(name, value)| {
                    !name.eq_ignore_ascii_case("set-cookie") || !reserved_admin_cookie(value)
                }),
        );
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
    ) -> Result<HttpResponse, ApiError> {
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
        let (actor, mut http, subject) = self.input(req, m)?;
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
        let resp = match self.node.env().timeout(self.cfg.timeout, turn).await {
            Ok(r) => turn_response(&r?),
            Err(_) => return Err(self.timed_out()),
        };
        Ok(match self.cfg.preview_domain {
            None => sandboxed(resp),
            Some(_) => resp,
        })
    }

    /// The root input of a matched request: its actor, the HTTP input and
    /// its subject.
    fn input(
        &self,
        mut req: HttpRequest,
        m: Matched,
    ) -> Result<(ActorRef, pb::HttpInput, Option<String>), ApiError> {
        strip_admin_cookies(&mut req.headers);
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
            kind: m.kind,
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
        let request_hash = if idempotency_key.is_empty() {
            Vec::new()
        } else {
            request_hash(&req, subject.as_deref(), self.node.sealer())
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
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(tagged(req.body))),
            }),
            route: m.pattern,
            idempotency_key,
            request_hash,
            sealed_path,
            sealed_query,
        };
        Ok((actor, http, subject))
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
        let r = sandboxed(HttpResponse {
            status: 200,
            headers: vec![
                ("Set-Cookie".into(), "s=1".into()),
                ("set-cookie".into(), "t=2".into()),
                ("content-type".into(), "text/html".into()),
            ],
            body: Vec::new(),
        });
        assert_eq!(
            r.headers,
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
