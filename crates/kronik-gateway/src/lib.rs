//! The HTTP gateway: routes from the deployed manifests, root inputs,
//! ingress `Idempotency-Key` and the turn timeout. The service function
//! [`Gateway::handle`] uses only `Env` and the node, so the simulator calls
//! it directly; [`server`] binds it to hyper on TCP (no TLS in M1).

#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod tls;

pub mod subject;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, valid_key};
use kronik_proto::log::v1 as pb;
use kronik_sched::{Ingress, Node, RouteEntry, TurnResult};

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
}

impl Default for GatewayConfig {
    fn default() -> Self {
        GatewayConfig {
            timeout: Duration::from_secs(30),
            max_body: 1 << 20,
            subject_from: None,
            idempotency_header: "Idempotency-Key".into(),
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
}

/// A route match: kind, actor key, pattern and parameters in order.
struct Matched {
    kind: String,
    pattern: String,
    params: Vec<(String, String)>,
}

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
            let status = u16::try_from(h.status).unwrap_or(500);
            if status < 200 {
                // The actor's mistake, so not INTERNAL, which hides the message.
                let mut resp = error(&ApiError::new(
                    ErrorCode::TurnFailed,
                    format!(
                        "turn {} answered with status {status}, which is not a final \
                         response: an actor answers with 200 to 599",
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
        }
    }

    fn matched(&self, method: &str, path: &str) -> Result<Matched, ApiError> {
        let (epoch, entries) = self.node.routes();
        let mut cache = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        if cache.0 != Some(epoch) {
            cache.1 = entries
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
                .collect();
            cache.0 = Some(epoch);
        }
        let segs: Vec<&str> = path.split('/').skip(1).collect();
        // The most specific match wins: fewest parameters, literals first.
        let mut best: Option<(Vec<bool>, &Route)> = None;
        for r in cache.1.iter().filter(|r| r.method == method) {
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
            pattern: r.pattern.clone(),
            params,
        })
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
        let m = self.matched(&req.method, &req.path)?;
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
            Err(_) => Err(ApiError::new(
                ErrorCode::GatewayTimeout,
                format!(
                    "the turn did not finish within {} ms; it still completes",
                    self.cfg.timeout.as_millis()
                ),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use kronik_privacy::MasterKey;
    use kronik_privacy::keystore::Pseudonyms;
    use kronik_privacy::sealer::Sealer;

    use super::*;

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
        let keyed =
            Sealer::plain().with_pseudonyms(Pseudonyms::new(&MasterKey::from_bytes([1; 32])));
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
