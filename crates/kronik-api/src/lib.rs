//! The JSON API, versioned under `/v1`, served over the Unix socket
//! (docs/design/m1-core.md §4). [`Api::handle`] is the service function;
//! [`server`] binds it to hyper on a Unix socket. Every mutation requires a
//! `reason` and supports `dry_run` (I12); errors use the stable error JSON.

pub mod auth;
mod m3;
mod m6;
pub mod m7;
pub mod openapi;
mod preview;
pub mod privacy;
pub mod redact;
#[cfg(feature = "server")]
pub mod server;
pub mod tokens;
pub mod types;

use std::sync::Arc;

use base64::Engine as _;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, CodeHash, TurnId};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{Node, TurnResult};
use serde::Serialize;
use serde::de::DeserializeOwned;

use types::*;

/// A request as the service function sees it.
#[derive(Clone)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub body: Vec<u8>,
    /// The listener's identity of the connection: `unix:uid=<n>` on the
    /// local socket, `tcp:<peer>` over TCP. [`Api::handle`] replaces it with
    /// the authenticated caller's id before routing, so that audit records
    /// carry `token:<name>` for a token.
    pub token_id: String,
    /// The token from `Authorization: Bearer`, if any. It is never logged
    /// or recorded; `Debug` hides it.
    pub bearer: Option<String>,
}

impl std::fmt::Debug for ApiRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("body_len", &self.body.len())
            .field("token_id", &self.token_id)
            .field("bearer", &self.bearer.as_ref().map(|_| "[hidden]"))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse {
    pub status: u16,
    /// `application/json`, or `text/markdown` for Markdown diffs.
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

pub struct Api {
    node: Arc<Node>,
    http_listen: Option<String>,
    /// `[gateway] preview_domain` (M11).
    preview_domain: Option<String>,
    /// The gateway serves TLS: preview URLs are `https`.
    gateway_tls: bool,
    /// The gateway's public host (and port) for prefix preview URLs.
    preview_host: Option<String>,
    proposals: Option<Arc<kronik_fork::proposal::Proposals>>,
    watches: Option<Arc<kronik_fork::watch::Watches>>,
    auth: Arc<dyn auth::Authenticator>,
    tokens: Option<Arc<tokens::TokenStore>>,
    /// The foreign actors (M7), when this daemon runs them.
    foreign: Option<Arc<kronik_foreign::Foreign>>,
}

type Result<T, E = ApiError> = std::result::Result<T, E>;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, msg)
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, e.to_string())
}

fn json<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|e| bad(format!("invalid request body: {e}")))
}

fn ok<T: Serialize>(v: &T) -> Result<ApiResponse> {
    Ok(ApiResponse {
        status: 200,
        content_type: "application/json",
        body: serde_json::to_vec(v).map_err(internal)?,
    })
}

fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

struct Query(Vec<(String, String)>);

impl Query {
    fn parse(q: &str) -> Result<Query> {
        let mut out = Vec::new();
        for part in q.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            let k = decode(k).ok_or_else(|| bad(format!("invalid query {part:?}")))?;
            let v = decode(v).ok_or_else(|| bad(format!("invalid query {part:?}")))?;
            out.push((k, v));
        }
        Ok(Query(out))
    }

    fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    fn num(&self, k: &str) -> Result<Option<u64>> {
        self.get(k)
            .map(|v| v.parse().map_err(|_| bad(format!("{k} must be a number"))))
            .transpose()
    }

    fn limit(&self) -> Result<usize> {
        Ok(self.num("limit")?.unwrap_or(100).clamp(1, 1000) as usize)
    }
}

fn reason(r: &str) -> Result<()> {
    if r.trim().is_empty() {
        return Err(ApiError::new(
            ErrorCode::ReasonRequired,
            "every mutation needs a non-empty reason",
        ));
    }
    Ok(())
}

fn sealable_bytes(s: Option<&pb::Sealable>) -> Vec<u8> {
    match s.and_then(|s| s.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.clone(),
        _ => Vec::new(),
    }
}

fn outcome_kind(k: i32) -> &'static str {
    match pb::OutcomeKind::try_from(k) {
        Ok(pb::OutcomeKind::Committed) => "committed",
        Ok(pb::OutcomeKind::Rejected) => "rejected",
        Ok(pb::OutcomeKind::Failed) => "failed",
        Ok(pb::OutcomeKind::Trap) => "trap",
        Ok(pb::OutcomeKind::FuelExhausted) => "fuel_exhausted",
        Ok(pb::OutcomeKind::MemoryLimit) => "memory_limit",
        Ok(pb::OutcomeKind::EffectOutcomeUnknown) => "effect_outcome_unknown",
        _ => "unspecified",
    }
}

fn outcome(o: &pb::Outcome) -> Outcome {
    let opt = |s: &str| (!s.is_empty()).then(|| s.to_owned());
    Outcome {
        kind: outcome_kind(o.kind).into(),
        error_code: opt(&o.error_code),
        message: opt(&o.message),
    }
}

fn turn_response(r: Option<TurnResult>) -> TurnResponse {
    let Some(r) = r else {
        return TurnResponse {
            dry_run: true,
            turn_id: None,
            outcome: None,
            reply: None,
        };
    };
    let reply = match &r.outcome.output {
        Some(pb::outcome::Output::Reply(m)) => Some(Reply {
            name: m.name.clone(),
            content_type: m.content_type.clone(),
            body: Payload::from_bytes(&sealable_bytes(m.body.as_ref())),
        }),
        Some(pb::outcome::Output::Http(h)) => Some(Reply {
            name: format!("http {}", h.status),
            content_type: String::new(),
            body: Payload::from_bytes(&match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => sealable_bytes(Some(s)),
                _ => Vec::new(),
            }),
        }),
        None => None,
    };
    TurnResponse {
        dry_run: false,
        turn_id: Some(r.turn_id.to_string()),
        outcome: Some(outcome(&r.outcome)),
        reply,
    }
}

/// A one-line input summary. For HTTP: the method and the path, but the
/// route pattern instead of the path for a caller without `pii:read` when
/// the request has a sealed value (v0.1 re-review R4); a caller with
/// `pii:read` passes the input unsealed.
fn input_summary(i: Option<&pb::Input>, pii: bool) -> InputSummary {
    use pb::input::Kind;
    let (kind, summary) = match i.and_then(|i| i.kind.as_ref()) {
        Some(Kind::Http(h)) => {
            let path = h.path_text();
            let hidden = (!pii && input_has_sealed(i))
                || path.is_empty()
                || path == kronik_proto::http::SEALED;
            let line = if !hidden {
                path.as_str()
            } else if h.route.is_empty() {
                "(no route)"
            } else {
                h.route.as_str()
            };
            ("http", format!("{} {line}", h.method))
        }
        Some(Kind::Message(m)) => {
            let name = m.msg.as_ref().map_or("", |m| m.name.as_str());
            let from = match (&m.sender, pb::MessageSource::try_from(m.source)) {
                (Some(s), _) => format!("{}/{}", s.kind, s.key),
                (None, Ok(pb::MessageSource::Operator)) => "operator".into(),
                (None, Ok(pb::MessageSource::DeadLetterResend)) => {
                    format!("resend of {}", m.resend_of)
                }
                _ => "-".into(),
            };
            ("message", format!("{name} from {from}"))
        }
        Some(Kind::Timer(t)) => (
            "timer",
            format!(
                "timer {} {}",
                t.timer_id,
                t.msg.as_ref().map_or("", |m| m.name.as_str())
            ),
        ),
        Some(Kind::Migrate(m)) => (
            "migrate",
            format!(
                "migrate {} -> {}",
                m.from_schema_version, m.to_schema_version
            ),
        ),
        None => ("unknown", String::new()),
    };
    InputSummary {
        kind: kind.into(),
        summary,
    }
}

fn short_hash(b: &[u8]) -> String {
    CodeHash::from_slice(b).map_or_else(|| "-".into(), |h| h.short())
}

fn turn_summary(branch: &str, lsn: u64, t: &pb::TurnRecord, pii: bool) -> TurnSummary {
    TurnSummary {
        turn_id: TurnId {
            branch: branch.into(),
            lsn,
        }
        .to_string(),
        lsn,
        logical_time_ms: t.logical_time_ms,
        code_hash: short_hash(&t.code_hash),
        input: input_summary(t.input.as_ref(), pii),
        outcome: t.outcome.as_ref().map_or(
            Outcome {
                kind: "unspecified".into(),
                error_code: None,
                message: None,
            },
            outcome,
        ),
        writes: t
            .writes
            .iter()
            .map(|w| WriteSummary {
                op: if w.op == pb::StateOp::Set as i32 {
                    "set"
                } else {
                    "delete"
                }
                .into(),
                key: w.key.clone(),
                subject: w.value.as_ref().and_then(|v| v.subject.clone()),
                erased: false,
            })
            .collect(),
        messages: t
            .messages
            .iter()
            .map(|m| MessageSummary {
                to: m
                    .to
                    .as_ref()
                    .map_or_else(String::new, |a| format!("{}/{}", a.kind, a.key)),
                name: m.msg.as_ref().map_or_else(String::new, |m| m.name.clone()),
            })
            .collect(),
        sql_changes: t.sql_changes.len() as u64,
        fuel_used: t.fuel_used,
        // History names an HTTP effect's request; the turn JSON has its own schema.
        effects: effect_summaries(t)
            .into_iter()
            .zip(&t.effects)
            .map(|(s, e)| EffectSummary {
                request: request_line(e),
                ..s
            })
            .collect(),
    }
}

fn effect_status(s: i32) -> &'static str {
    match pb::EffectStatus::try_from(s) {
        Ok(pb::EffectStatus::Ok) => "ok",
        Ok(pb::EffectStatus::Denied) => "denied",
        Ok(pb::EffectStatus::Network) => "network",
        Ok(pb::EffectStatus::Timeout) => "timeout",
        Ok(pb::EffectStatus::TooLarge) => "too_large",
        Ok(pb::EffectStatus::OutcomeUnknown) => "outcome_unknown",
        Ok(pb::EffectStatus::NotFound) => "not_found",
        Ok(pb::EffectStatus::Rejected) => "rejected",
        Ok(pb::EffectStatus::Failed) => "failed",
        Ok(pb::EffectStatus::Reentrant) => "reentrant",
        _ => "unspecified",
    }
}

/// `METHOD host/path` of an HTTP effect's recorded request, without
/// credentials or the query; `None` for other effects, and for a request
/// sealed for a data subject (only a plain one can be read here).
fn request_line(e: &pb::EffectRecord) -> Option<String> {
    use prost::Message as _;
    if !matches!(e.kind.as_str(), "http.fetch" | "foreign.http") {
        return None;
    }
    let Some(pb::sealable::Value::Plain(bytes)) = e.request.as_ref()?.value.as_ref() else {
        return None;
    };
    let r = pb::HttpEffectRequest::decode(bytes.as_slice()).ok()?;
    let rest = r
        .url
        .split_once("://")
        .map_or(r.url.as_str(), |(_, rest)| rest);
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let rest = &rest[..end];
    let host = rest.find('/').unwrap_or(rest.len());
    let rest = rest[..host].rfind('@').map_or(rest, |at| &rest[at + 1..]);
    Some(format!("{} {rest}", r.method))
}

/// The effects of a turn; a denied effect carries the exact grant command.
fn effect_summaries(t: &pb::TurnRecord) -> Vec<EffectSummary> {
    let kind = t.actor.as_ref().map_or("<kind>", |a| a.kind.as_str());
    t.effects
        .iter()
        .map(|e| {
            let opt = |s: &str| (!s.is_empty()).then(|| s.to_owned());
            let hint = e
                .error
                .strip_prefix("CAPABILITY_NOT_GRANTED: ")
                .map(|cap| format!("kronik grant {kind} {cap} --reason '...'"));
            EffectSummary {
                ordinal: e.ordinal,
                kind: e.kind.clone(),
                target: e.target.clone(),
                status: effect_status(e.status).into(),
                delivery: opt(&e.delivery),
                error: opt(&e.error),
                hint,
                request: None,
            }
        })
        .collect()
}

fn payload_json(b: &[u8]) -> serde_json::Value {
    serde_json::to_value(Payload::from_bytes(b)).unwrap_or(serde_json::Value::Null)
}

fn sealable_json(s: Option<&pb::Sealable>) -> serde_json::Value {
    serde_json::json!({
        "subject": s.and_then(|s| s.subject.clone()),
        "value": payload_json(&sealable_bytes(s)),
    })
}

fn message_json(m: Option<&pb::Message>) -> serde_json::Value {
    match m {
        Some(m) => serde_json::json!({
            "name": m.name,
            "content_type": m.content_type,
            "body": sealable_json(m.body.as_ref()),
        }),
        None => serde_json::Value::Null,
    }
}

fn actor_json(a: Option<&pb::ActorRef>) -> serde_json::Value {
    a.map_or(serde_json::Value::Null, |a| {
        serde_json::Value::String(format!("{}/{}", a.kind, a.key))
    })
}

/// Without `pii:read`, the credentials of a turn's HTTP input and output
/// read `[redacted]`. The log keeps them as they came (security guide).
pub(crate) fn redact_credentials(t: &mut pb::TurnRecord, pii: bool) {
    if pii {
        return;
    }
    let redact = |headers: &mut Vec<pb::Header>| {
        for h in headers
            .iter_mut()
            .filter(|h| kronik_core::http::credential_header(&h.name))
        {
            if let Some(v) = h.value.as_mut() {
                v.value = Some(pb::sealable::Value::Plain(b"[redacted]".to_vec()));
            }
        }
    };
    if let Some(pb::input::Kind::Http(h)) = t.input.as_mut().and_then(|i| i.kind.as_mut()) {
        redact(&mut h.headers);
    }
    if let Some(pb::outcome::Output::Http(h)) = t.outcome.as_mut().and_then(|o| o.output.as_mut()) {
        redact(&mut h.headers);
    }
}

/// The full turn record as JSON.
fn turn_json(branch: &str, lsn: u64, t: &pb::TurnRecord) -> serde_json::Value {
    use pb::input::Kind;
    let input = match t.input.as_ref().and_then(|i| i.kind.as_ref()) {
        Some(Kind::Http(h)) => serde_json::json!({
            "type": "http", "method": h.method, "path": h.path_text(), "query": h.query_text(),
            "route": h.route,
            "params": h.param_values(),
            "headers": h.headers.iter().map(|hd| serde_json::json!({
                "name": hd.name, "value": sealable_json(hd.value.as_ref()),
            })).collect::<Vec<_>>(),
            "body": match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => sealable_json(Some(s)),
                _ => serde_json::Value::Null,
            },
            "idempotency_key": h.idempotency_key,
        }),
        Some(Kind::Message(m)) => serde_json::json!({
            "type": "message",
            "source": pb::MessageSource::try_from(m.source).map_or("unspecified", |s| s.as_str_name()),
            "sender": actor_json(m.sender.as_ref()),
            "message_id": m.message_id,
            "sent_logical_time_ms": m.sent_logical_time_ms,
            "resend_of": m.resend_of,
            "msg": message_json(m.msg.as_ref()),
            "reason": m.audit.as_ref().map(|a| a.reason.clone()),
            "token_id": m.audit.as_ref().map(|a| a.token_id.clone()),
        }),
        Some(Kind::Timer(tm)) => serde_json::json!({
            "type": "timer", "timer_id": tm.timer_id, "due_ms": tm.due_ms,
            "msg": message_json(tm.msg.as_ref()),
        }),
        Some(Kind::Migrate(m)) => serde_json::json!({
            "type": "migrate", "from": m.from_schema_version, "to": m.to_schema_version,
        }),
        None => serde_json::Value::Null,
    };
    let output = match t.outcome.as_ref().and_then(|o| o.output.as_ref()) {
        Some(pb::outcome::Output::Reply(m)) => {
            serde_json::json!({"reply": message_json(Some(m))})
        }
        Some(pb::outcome::Output::Http(h)) => serde_json::json!({"http": {
            "status": h.status,
            "headers": h.headers.iter().map(|hd| serde_json::json!({
                "name": hd.name, "value": sealable_json(hd.value.as_ref()),
            })).collect::<Vec<_>>(),
            "body": match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => sealable_json(Some(s)),
                _ => serde_json::Value::Null,
            },
        }}),
        None => serde_json::Value::Null,
    };
    let key = t.causal_key.as_ref();
    serde_json::json!({
        "turn_id": TurnId { branch: branch.into(), lsn }.to_string(),
        "lsn": lsn,
        "actor": actor_json(t.actor.as_ref()),
        "code_hash": short_hash(&t.code_hash),
        "engine_version": t.engine_version,
        "causal_id": key.map(kronik_core::causal::causal_id),
        "causal_key": key.map(|k| serde_json::json!({
            "root": k.root,
            "path": k.path.iter().map(|s| serde_json::json!({
                "actor": actor_json(s.actor.as_ref()), "ordinal": s.ordinal,
            })).collect::<Vec<_>>(),
        })),
        "logical_time_ms": t.logical_time_ms,
        "config_epoch": t.config_epoch,
        "input": input,
        "outcome": t.outcome.as_ref().map(outcome),
        "output": output,
        "writes": t.writes.iter().map(|w| serde_json::json!({
            "op": if w.op == pb::StateOp::Set as i32 { "set" } else { "delete" },
            "key": w.key,
            "value": w.value.as_ref().map(|v| sealable_json(Some(v))),
        })).collect::<Vec<_>>(),
        "messages": t.messages.iter().map(|m| serde_json::json!({
            "to": actor_json(m.to.as_ref()), "ordinal": m.ordinal, "message_id": m.message_id,
            "msg": message_json(m.msg.as_ref()),
        })).collect::<Vec<_>>(),
        "sql_schema": t.sql_schema.iter().map(|s| s.statement.clone()).collect::<Vec<_>>(),
        "sql_changes": t.sql_changes.iter().map(|c| serde_json::json!({
            "subject": c.changeset.as_ref().and_then(|s| s.subject.clone()),
            "bytes": sealable_bytes(c.changeset.as_ref()).len(),
        })).collect::<Vec<_>>(),
        "fuel_used": t.fuel_used,
        "memory_peak_bytes": t.memory_peak_bytes,
        "schema_version": t.schema_version,
        "effects": effect_summaries(t),
        "timers": t.timers.iter().map(|op| serde_json::json!({
            "op": if op.kind == pb::TimerOpKind::Schedule as i32 { "schedule" } else { "cancel" },
            "id": op.timer_id.to_string(),
            "due_ms": op.due_ms,
            "name": op.msg.as_ref().map(|m| m.name.clone()),
        })).collect::<Vec<_>>(),
        "compensations": t.compensations.iter().map(|m| serde_json::json!({
            "to": actor_json(m.to.as_ref()), "message_id": m.message_id,
            "msg": message_json(m.msg.as_ref()),
        })).collect::<Vec<_>>(),
    })
}

impl Api {
    pub fn new(node: Arc<Node>) -> Api {
        Api {
            node,
            http_listen: None,
            preview_domain: None,
            gateway_tls: false,
            preview_host: None,
            proposals: None,
            watches: None,
            auth: Arc::new(auth::LocalAuthenticator),
            tokens: None,
            foreign: None,
        }
    }

    /// Serves `/v1/foreign` (M7) from `foreign`.
    pub fn with_foreign(mut self, foreign: Arc<kronik_foreign::Foreign>) -> Api {
        self.foreign = Some(foreign);
        self
    }

    /// Serves `/v1/tokens` from `store` and authenticates bearer tokens
    /// with it ([`tokens::TokenAuthenticator`]).
    pub fn with_tokens(mut self, store: Arc<tokens::TokenStore>) -> Api {
        self.auth = Arc::new(tokens::TokenAuthenticator::new(store.clone()));
        self.tokens = Some(store);
        self
    }

    /// Resolves callers with `auth` (M5 tokens) instead of the local
    /// socket's all-scopes caller.
    pub fn with_authenticator(mut self, auth: Arc<dyn auth::Authenticator>) -> Api {
        self.auth = auth;
        self
    }

    /// The caller of a request.
    pub fn caller(&self, req: &ApiRequest) -> Result<auth::Caller> {
        self.auth.caller(req)
    }

    /// Serves the M3 endpoints (forks, proposals, policy) from `proposals`.
    pub fn with_proposals(mut self, proposals: Arc<kronik_fork::proposal::Proposals>) -> Api {
        self.proposals = Some(proposals);
        self
    }

    /// Serves `kronik watch` (M11) from `watches`.
    pub fn with_watches(mut self, watches: Arc<kronik_fork::watch::Watches>) -> Api {
        self.watches = Some(watches);
        self
    }

    /// Reports the gateway's address in `/v1/health`.
    pub fn with_http_listen(mut self, addr: String) -> Api {
        self.http_listen = Some(addr);
        self
    }

    /// How preview URLs look (M11): `<scheme>://<id>.<domain>/` with
    /// `[gateway] preview_domain`, else `<scheme>://<host>/__preview/<id>/`;
    /// `https` when the gateway serves TLS. `host` is the gateway's public
    /// name and port, never an unspecified bind address (P-F5).
    pub fn with_preview_urls(mut self, domain: Option<String>, tls: bool, host: String) -> Api {
        self.preview_domain = domain;
        self.gateway_tls = tls;
        self.preview_host = Some(host);
        self
    }

    /// Like `ok`, with every live secret value replaced by
    /// `[secret:<name>]` (revealed values a guest stored or logged), in
    /// every string and in every byte payload: a `base64` field is decoded,
    /// scrubbed, encoded again, and its `text` twin follows (I8).
    fn ok_scrubbed<T: Serialize>(&self, v: &T) -> Result<ApiResponse> {
        let secrets = self.node.secret_values();
        if secrets.is_empty() {
            return Ok(ApiResponse {
                status: 200,
                content_type: "application/json",
                body: serde_json::to_vec(v).map_err(internal)?,
            });
        }
        let mut value = serde_json::to_value(v).map_err(internal)?;
        scrub_json(&mut value, &secrets);
        Ok(ApiResponse {
            status: 200,
            content_type: "application/json",
            body: serde_json::to_vec(&value).map_err(internal)?,
        })
    }

    fn audit(&self, req: &ApiRequest, reason: String) -> pb::Audit {
        pb::Audit {
            token_id: req.token_id.clone(),
            reason,
            wall_time_ms: self.node.env().clock.wall_ms(),
        }
    }

    /// Serves one request; errors become the stable error JSON. The caller
    /// is resolved first, and handlers see its id in `req.token_id`, never
    /// the bearer token.
    pub async fn handle(&self, mut req: ApiRequest) -> ApiResponse {
        let result = match self.caller(&req) {
            Ok(caller) => {
                req.token_id = caller.token_id.clone();
                req.bearer = None;
                self.route(&req, &caller).await
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(r) => r,
            Err(e) => ApiResponse {
                status: e.code.http_status(),
                content_type: "application/json",
                body: e.to_json().to_string().into_bytes(),
            },
        }
    }

    async fn route(&self, req: &ApiRequest, caller: &auth::Caller) -> Result<ApiResponse> {
        let segs: Vec<String> = req
            .path
            .split('/')
            .skip(1)
            .map(|s| decode(s).ok_or_else(|| bad(format!("invalid path segment {s:?}"))))
            .collect::<Result<_>>()?;
        let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
        caller.require(auth::required_scope(&req.method, &segs))?;
        let q = Query::parse(&req.query)?;
        match (req.method.as_str(), segs.as_slice()) {
            ("GET", ["v1", "health"]) => self.health(),
            ("GET", ["v1", "openapi.json"]) => self.openapi(),
            ("POST", ["v1", "deployments"]) => self.deploy(req).await,
            ("GET", ["v1", "deployments"]) => self.deployments(),
            ("POST", ["v1", "actors", kind, key, "messages"]) => self.send(req, kind, key).await,
            ("GET", ["v1", "actors"]) => self.actors(&q),
            ("GET", ["v1", "actors", kind, key]) => {
                self.inspect(kind, key, caller.has(auth::Scope::PiiRead))
            }
            ("GET", ["v1", "actors", kind, key, "history"]) => {
                self.history(kind, key, &q, caller.has(auth::Scope::PiiRead))
                    .await
            }
            ("GET", ["v1", "turns", id]) => self.turn(id, caller).await,
            ("GET", ["v1", "dead-letters"]) => {
                self.dead_letters(&q, caller.has(auth::Scope::PiiRead))
            }
            ("POST", ["v1", "dead-letters", id, "resend"]) => self.resend(req, id).await,
            ("POST", ["v1", "grants"]) => self.grant(req).await,
            ("POST", ["v1", "grants", "revoke"]) => self.revoke(req).await,
            ("GET", ["v1", "grants"]) => self.grants(&q),
            ("POST", ["v1", "limits"]) => self.set_limits(req).await,
            ("GET", ["v1", "limits"]) => self.limits(&q),
            ("PUT", ["v1", "secrets", name]) => self.secret_set(req, name),
            ("GET", ["v1", "secrets"]) => self.secrets(),
            ("DELETE", ["v1", "secrets", name]) => self.secret_delete(req, name),
            ("GET", ["v1", "orphans"]) => self.orphans(&q),
            ("GET", ["v1", "actors", kind, key, "timers"]) => self.timers(kind, key),
            ("POST", ["v1", "tokens"]) => self.token_create(req),
            ("GET", ["v1", "tokens"]) => self.tokens(),
            ("POST", ["v1", "tokens", name, "revoke"]) => self.token_revoke(req, name),
            _ => match self.route_m3(req, segs.as_slice(), &q, caller).await {
                Some(r) => r,
                None => match self.route_m7(req, segs.as_slice(), &q).await {
                    Some(r) => r,
                    None => match self.route_privacy(req, segs.as_slice()).await {
                        Some(r) => r,
                        None => match self.route_m6(req, segs.as_slice()).await {
                            Some(r) => r,
                            None => match self.route_preview(req, segs.as_slice(), caller).await {
                                Some(r) => r,
                                None => Err(ApiError::new(
                                    ErrorCode::NotImplemented,
                                    format!("no endpoint {} {}", req.method, req.path),
                                )),
                            },
                        },
                    },
                },
            },
        }
    }

    /// `GET /v1/openapi.json`: the document, generated once.
    fn openapi(&self) -> Result<ApiResponse> {
        static DOCUMENT: std::sync::LazyLock<Vec<u8>> =
            std::sync::LazyLock::new(openapi::document_bytes);
        Ok(ApiResponse {
            status: 200,
            content_type: "application/json",
            body: DOCUMENT.clone(),
        })
    }

    fn health(&self) -> Result<ApiResponse> {
        if let Some(f) = self.node.fatal() {
            return Err(ApiError::new(ErrorCode::Unavailable, f));
        }
        ok(&HealthResponse {
            status: "ok".into(),
            version: kronik_runtime::KRONIK_VERSION.into(),
            engine: kronik_runtime::ENGINE_VERSION.into(),
            applied_lsn: self.node.applied_lsn(),
            branch: self.node.branch().into(),
            http_listen: self.http_listen.clone(),
            disk_free_bytes: self.node.disk_free(),
            low_disk: self.node.disk_below_reserve().is_some(),
        })
    }

    async fn deploy(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: DeployRequest = json(&req.body)?;
        reason(&r.reason)?;
        let wasm = base64::engine::general_purpose::STANDARD
            .decode(r.wasm_base64.trim())
            .map_err(|e| bad(format!("wasm_base64 is not valid base64: {e}")))?;
        let d = self
            .node
            .deploy(&wasm, self.audit(req, r.reason), r.dry_run)
            .await?;
        ok(&DeployResponse {
            dry_run: d.dry_run,
            unchanged: d.unchanged,
            deployment: Deployment {
                epoch: d.epoch,
                lsn: d.lsn,
                kind: d.manifest.kind.clone(),
                code_hash: d.code_hash.short(),
                schema_version: d.manifest.schema_version,
                routes: d
                    .manifest
                    .routes
                    .iter()
                    .map(|r| Route {
                        method: r.method.clone(),
                        pattern: r.pattern.clone(),
                    })
                    .collect(),
                capabilities: d.manifest.capabilities.clone(),
            },
            warnings: d.warnings,
        })
    }

    fn deployments(&self) -> Result<ApiResponse> {
        let rows = self.node.store().db().deployments().map_err(internal)?;
        ok(&DeploymentsResponse {
            deployments: rows
                .into_iter()
                .map(|(lsn, d)| DeploymentEntry {
                    epoch: d.epoch,
                    lsn,
                    cause: pb::DeploymentCause::try_from(d.cause)
                        .map_or("unspecified", |c| c.as_str_name())
                        .trim_start_matches("DEPLOYMENT_CAUSE_")
                        .to_ascii_lowercase(),
                    kinds: d
                        .kinds
                        .iter()
                        .map(|k| DeploymentKind {
                            kind: k.kind.clone(),
                            code_hash: short_hash(&k.code_hash),
                            schema_version: k.schema_version,
                        })
                        .collect(),
                    reason: d
                        .audit
                        .as_ref()
                        .map(|a| a.reason.clone())
                        .unwrap_or_default(),
                    token_id: d.audit.map(|a| a.token_id).unwrap_or_default(),
                })
                .collect(),
        })
    }

    fn actor_ref(kind: &str, key: &str) -> Result<ActorRef> {
        ActorRef::new(kind, key).map_err(|e| bad(e.to_string()))
    }

    async fn send(&self, req: &ApiRequest, kind: &str, key: &str) -> Result<ApiResponse> {
        let actor = Self::actor_ref(kind, key)?;
        let r: SendRequest = json(&req.body)?;
        reason(&r.reason)?;
        if r.name.is_empty() {
            return Err(bad("the message needs a name"));
        }
        let body = r.body.to_bytes().map_err(bad)?;
        let msg = pb::Message {
            name: r.name,
            content_type: if r.content_type.is_empty() {
                "application/octet-stream".into()
            } else {
                r.content_type
            },
            body: Some(pb::Sealable {
                subject: r.subject,
                value: Some(pb::sealable::Value::Plain(body)),
            }),
            blobs: Vec::new(),
        };
        let t = self
            .node
            .send(actor, msg, self.audit(req, r.reason), r.dry_run)
            .await?;
        ok(&turn_response(t))
    }

    fn actor_view(&self, a: &kronik_store::db::ActorRow) -> Actor {
        Actor {
            kind: a.kind.clone(),
            key: a.key.clone(),
            schema_version: a.schema_version,
            turns: a.turns,
            last_turn_id: TurnId {
                branch: self.node.branch().into(),
                lsn: a.last_lsn,
            }
            .to_string(),
            sql: a.sql,
        }
    }

    fn actors(&self, q: &Query) -> Result<ApiResponse> {
        let limit = q.limit()?;
        let after = q
            .get("after")
            .map(|a| {
                a.split_once('/')
                    .ok_or_else(|| bad("after must be kind/key"))
            })
            .transpose()?;
        let rows = self
            .node
            .store()
            .db()
            .actors(q.get("kind"), after, limit)
            .map_err(internal)?;
        let next = (rows.len() == limit)
            .then(|| rows.last().map(|a| format!("{}/{}", a.kind, a.key)))
            .flatten();
        ok(&ActorsResponse {
            actors: rows.iter().map(|a| self.actor_view(a)).collect(),
            next,
        })
    }

    fn not_found(kind: &str, key: &str) -> ApiError {
        ApiError::new(
            ErrorCode::ActorNotFound,
            format!("actor {kind}/{key} has no turns"),
        )
    }

    /// `pii`: the caller has `pii:read`, so sealed values are shown
    /// (docs/design/m8-privacy.md §5).
    fn inspect(&self, kind: &str, key: &str, pii: bool) -> Result<ApiResponse> {
        let actor = Self::actor_ref(kind, key)?;
        let (row, kv) = {
            let db = self.node.store().db();
            let row = db
                .actor(&actor.kind, &actor.key)
                .map_err(internal)?
                .ok_or_else(|| Self::not_found(kind, key))?;
            (row, db.kv_list(&actor.kind, &actor.key).map_err(internal)?)
        };
        let sql = if row.sql {
            let db = self
                .node
                .store()
                .sql
                .get(&actor.to_string())
                .map_err(internal)?;
            let rows = db
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .table_rows()
                .map_err(internal)?;
            Some(SqlSummary {
                tables: rows
                    .into_iter()
                    .map(|(name, rows)| SqlTable { name, rows })
                    .collect(),
            })
        } else {
            None
        };
        self.ok_scrubbed(&InspectResponse {
            actor: self.actor_view(&row),
            state: kv
                .into_iter()
                .map(|r| {
                    let shown = match r.sealable() {
                        Ok(v) => redact::render_sealable(&v, self.node.sealer(), pii).into_bytes(),
                        Err(_) => b"[unreadable]".to_vec(),
                    };
                    StateEntry {
                        key: r.k,
                        value: Payload::from_bytes(&shown),
                        // M3: no subject ids for callers without pii:read.
                        subject: r.subject.filter(|_| pii),
                        lsn: r.lsn,
                    }
                })
                .collect(),
            sql,
        })
    }

    async fn history(&self, kind: &str, key: &str, q: &Query, pii: bool) -> Result<ApiResponse> {
        let actor = Self::actor_ref(kind, key)?;
        let limit = q.limit()?;
        let refs = {
            let db = self.node.store().db();
            if db
                .actor(&actor.kind, &actor.key)
                .map_err(internal)?
                .is_none()
            {
                return Err(Self::not_found(kind, key));
            }
            db.history(&actor.kind, &actor.key, q.num("before")?, limit)
                .map_err(internal)?
        };
        let mut turns = Vec::with_capacity(refs.len());
        for r in &refs {
            let c = self
                .node
                .reader()
                .read_at(r.pos)
                .await
                .map_err(|e| ApiError::new(ErrorCode::StorageCorrupt, e.to_string()))?;
            if let Record::TurnRecord(t) = &c.record {
                // With pii:read the summary shows the path: unsealed first.
                let mut s = if pii && input_has_sealed(t.input.as_ref()) {
                    let mut u = t.clone();
                    if let Some(i) = u.input.as_mut() {
                        redact::redact_input(i, self.node.sealer(), true);
                    }
                    turn_summary(self.node.branch(), c.lsn, &u, pii)
                } else {
                    turn_summary(self.node.branch(), c.lsn, t, pii)
                };
                if !pii {
                    s.writes.iter_mut().for_each(|w| w.subject = None);
                }
                for (w, r) in s.writes.iter_mut().zip(&t.writes) {
                    w.erased = r
                        .value
                        .as_ref()
                        .is_some_and(|v| redact::is_erased(v, self.node.sealer()));
                }
                turns.push(s);
            }
        }
        let next = (refs.len() == limit)
            .then(|| refs.last().map(|r| r.lsn))
            .flatten();
        self.ok_scrubbed(&HistoryResponse { turns, next })
    }

    fn grant_view(g: &kronik_effects::Grant, lsn: u64) -> GrantView {
        GrantView {
            kind: g.kind.clone(),
            capability: g.capability.clone(),
            delivery: g.delivery.map(|d| d.as_str().to_owned()),
            rate: g.rate.map(|r| r.render()),
            epoch: g.epoch,
            lsn,
            reason: g.reason.clone(),
        }
    }

    async fn grant(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: GrantRequest = json(&req.body)?;
        reason(&r.reason)?;
        let delivery = r
            .delivery
            .as_deref()
            .map(|d| {
                kronik_effects::Delivery::parse(d).ok_or_else(|| {
                    bad(format!(
                        "delivery must be replay-safe, idempotency-keyed or unsafe, got {d:?}"
                    ))
                })
            })
            .transpose()?;
        let rate = r
            .rate
            .as_deref()
            .map(|v| {
                kronik_effects::Rate::parse(v).ok_or_else(|| {
                    bad(format!("rate must look like 2/s, 10/m or 100/h, got {v:?}"))
                })
            })
            .transpose()?;
        let (epoch, lsn) = self
            .node
            .grant(
                &r.kind,
                &r.capability,
                delivery,
                rate,
                self.audit(req, r.reason.clone()),
                r.dry_run,
            )
            .await?;
        let capability = kronik_effects::Capability::parse(&r.capability)
            .map_or(r.capability.clone(), |c| c.render());
        ok(&GrantResponse {
            dry_run: r.dry_run,
            grant: GrantView {
                kind: r.kind,
                capability,
                delivery: delivery.map(|d| d.as_str().to_owned()),
                rate: rate.map(|x| x.render()),
                epoch,
                lsn,
                reason: r.reason,
            },
        })
    }

    async fn revoke(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: RevokeRequest = json(&req.body)?;
        reason(&r.reason)?;
        let (epoch, lsn) = self
            .node
            .revoke(&r.kind, &r.capability, self.audit(req, r.reason), r.dry_run)
            .await?;
        ok(&RevokeResponse {
            dry_run: r.dry_run,
            revoked: Revoked {
                kind: r.kind,
                capability: kronik_effects::Capability::parse(&r.capability)
                    .map_or(r.capability.clone(), |c| c.render()),
                epoch,
                lsn,
            },
        })
    }

    fn grants(&self, q: &Query) -> Result<ApiResponse> {
        let config = self.node.config_now();
        let lsns = self.config_lsns();
        ok(&GrantsResponse {
            grants: config
                .grants()
                .filter(|g| q.get("kind").is_none_or(|k| k == g.kind))
                .map(|g| Self::grant_view(g, lsns.get(&g.epoch).copied().unwrap_or(0)))
                .collect(),
        })
    }

    /// epoch -> lsn of the configuration records.
    fn config_lsns(&self) -> std::collections::BTreeMap<u64, u64> {
        let mut out = std::collections::BTreeMap::new();
        let db = self.node.store().db();
        if let Ok(rows) = db.config_record_lsns() {
            out.extend(rows);
        }
        out
    }

    fn limits_view(kind: &str, l: &kronik_effects::KindLimits) -> LimitsView {
        LimitsView {
            kind: kind.to_owned(),
            fuel: l.fuel,
            memory_bytes: l.memory_bytes,
            message_bytes: l.message_bytes,
            state_value_bytes: l.state_value_bytes,
            sql_bytes_per_actor: l.sql_bytes_per_actor,
            effect_timeout_ms: l.effect_timeout.as_millis() as u64,
            effect_response_bytes: l.effect_response_bytes,
            epoch: None,
            lsn: None,
        }
    }

    async fn set_limits(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: LimitsRequest = json(&req.body)?;
        reason(&r.reason)?;
        let limits = pb::Limits {
            epoch: 0,
            kind: r.kind.clone(),
            fuel: r.fuel,
            memory_bytes: r.memory_bytes,
            message_bytes: r.message_bytes,
            state_value_bytes: r.state_value_bytes,
            sql_bytes_per_actor: r.sql_bytes_per_actor,
            effect_timeout_ms: r.effect_timeout_ms,
            effect_response_bytes: r.effect_response_bytes,
            audit: None,
        };
        let (epoch, lsn, effective) = self
            .node
            .set_limits(limits, self.audit(req, r.reason), r.dry_run)
            .await?;
        let mut view = Self::limits_view(&r.kind, &effective);
        view.epoch = Some(epoch);
        view.lsn = Some(lsn);
        ok(&LimitsResponse {
            dry_run: r.dry_run,
            limits: view,
        })
    }

    fn limits(&self, q: &Query) -> Result<ApiResponse> {
        let config = self.node.config_now();
        let kinds: Vec<String> = match q.get("kind") {
            Some(k) => vec![k.to_owned()],
            None => self
                .node
                .store()
                .db()
                .kinds()
                .map_err(internal)?
                .into_iter()
                .map(|k| k.version.kind)
                .collect(),
        };
        ok(&LimitsListResponse {
            limits: kinds
                .iter()
                .map(|k| Self::limits_view(k, &config.limits(k)))
                .collect(),
        })
    }

    fn secret_view(m: &kronik_privacy::SecretMeta) -> SecretView {
        SecretView {
            name: m.name.clone(),
            version: m.version,
            version_hash: m.version_hash.iter().map(|b| format!("{b:02x}")).collect(),
            created_wall_ms: m.created_wall_ms,
        }
    }

    fn secret_set(&self, req: &ApiRequest, name: &str) -> Result<ApiResponse> {
        let r: SecretSetRequest = json(&req.body)?;
        reason(&r.reason)?;
        let value = r.value.to_bytes().map_err(bad)?;
        if value.is_empty() {
            return Err(bad("the secret value is empty"));
        }
        let meta = self
            .node
            .secret_set(name, &value, &self.audit(req, r.reason), r.dry_run)?;
        ok(&SecretResponse {
            dry_run: r.dry_run,
            secret: meta.as_ref().map(Self::secret_view),
        })
    }

    fn secrets(&self) -> Result<ApiResponse> {
        ok(&SecretsResponse {
            secrets: self
                .node
                .secret_list()?
                .iter()
                .map(Self::secret_view)
                .collect(),
        })
    }

    fn secret_delete(&self, req: &ApiRequest, name: &str) -> Result<ApiResponse> {
        let r: SecretDeleteRequest = json(&req.body)?;
        reason(&r.reason)?;
        let versions = self.node.secret_delete(name, r.dry_run)?;
        ok(&SecretDeleteResponse {
            dry_run: r.dry_run,
            deleted: SecretDeleted {
                name: name.to_owned(),
                versions,
            },
        })
    }

    fn token_store(&self) -> Result<&Arc<tokens::TokenStore>> {
        self.tokens
            .as_ref()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "this daemon has no token store"))
    }

    fn token_view(m: &tokens::TokenMeta) -> TokenView {
        TokenView {
            name: m.name.clone(),
            token_id: m.token_id(),
            scopes: m.scopes.iter().map(|s| s.as_str().to_owned()).collect(),
            created_wall_ms: m.created_wall_ms,
            created_by: m.created_by.clone(),
            reason: m.reason.clone(),
            revoked: m.revoked.is_some(),
            revoked_wall_ms: m.revoked.as_ref().map(|r| r.wall_ms),
            revoked_by: m.revoked.as_ref().map(|r| r.by.clone()),
            revoke_reason: m.revoked.as_ref().map(|r| r.reason.clone()),
        }
    }

    /// `kronik token create`: the token is in the answer once, and only its
    /// hash is stored.
    fn token_create(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: TokenCreateRequest = json(&req.body)?;
        reason(&r.reason)?;
        let scopes = match &r.scopes {
            Some(list) => tokens::parse_scopes(list)?,
            None => tokens::DEFAULT_SCOPES.into_iter().collect(),
        };
        let change = tokens::Change {
            wall_ms: self.node.env().clock.wall_ms(),
            by: &req.token_id,
            reason: &r.reason,
        };
        let (meta, secret) = self.token_store()?.create(
            &r.name,
            scopes,
            self.node.env().random_bytes::<32>(),
            &change,
            r.dry_run,
        )?;
        ok(&TokenCreateResponse {
            dry_run: r.dry_run,
            token: Self::token_view(&meta),
            secret,
        })
    }

    fn tokens(&self) -> Result<ApiResponse> {
        ok(&TokensResponse {
            tokens: self
                .token_store()?
                .list()?
                .iter()
                .map(Self::token_view)
                .collect(),
        })
    }

    fn token_revoke(&self, req: &ApiRequest, name: &str) -> Result<ApiResponse> {
        let r: TokenRevokeRequest = json(&req.body)?;
        reason(&r.reason)?;
        let change = tokens::Change {
            wall_ms: self.node.env().clock.wall_ms(),
            by: &req.token_id,
            reason: &r.reason,
        };
        let meta = self.token_store()?.revoke(name, &change, r.dry_run)?;
        ok(&TokenRevokeResponse {
            dry_run: r.dry_run,
            token: Self::token_view(&meta),
        })
    }

    fn orphans(&self, q: &Query) -> Result<ApiResponse> {
        let all = matches!(q.get("all"), Some("true" | "1"));
        let branch = self.node.branch().to_owned();
        let id = |lsn| {
            TurnId {
                branch: branch.clone(),
                lsn,
            }
            .to_string()
        };
        let db = self.node.store().db();
        let rows = db.orphans(all).map_err(internal)?;
        let mut orphans = Vec::with_capacity(rows.len());
        for o in rows {
            let compensation = match &o.compensation_id {
                Some(m) => {
                    let state = if o.resolved_lsn.is_some() {
                        "done"
                    } else if db.delivery(m).map_err(internal)?.is_some() {
                        "dead_letter"
                    } else {
                        "pending"
                    };
                    Some(Compensation {
                        message_id: m.clone(),
                        state: state.into(),
                    })
                }
                None => None,
            };
            orphans.push(Orphan {
                actor: o.callee.to_string(),
                // A sealed reply hides the callee's turn id in the record; the
                // callee's delivery gives it without reading user data.
                turn_id: if o.callee_turn.is_empty() {
                    db.call_outcome(&o.call_message_id)
                        .ok()
                        .flatten()
                        .map(|(lsn, _)| id(lsn))
                        .unwrap_or_default()
                } else {
                    o.callee_turn.clone()
                },
                caller: o.caller.to_string(),
                caller_turn_id: id(o.caller_lsn),
                call_message_id: o.call_message_id.clone(),
                compensation,
                resolved_turn_id: o.resolved_lsn.map(id),
            });
        }
        ok(&OrphansResponse { orphans })
    }

    fn timers(&self, kind: &str, key: &str) -> Result<ApiResponse> {
        let actor = Self::actor_ref(kind, key)?;
        let rows = self
            .node
            .store()
            .db()
            .timers(Some((&actor.kind, &actor.key)))
            .map_err(internal)?;
        ok(&TimersResponse {
            timers: rows
                .into_iter()
                .map(|t| Timer {
                    id: t.timer_id.to_string(),
                    due_ms: t.due_ms,
                    name: t.msg.name,
                })
                .collect(),
        })
    }

    fn turn_id(&self, id: &str) -> Result<u64> {
        let t = TurnId::parse(id)
            .ok_or_else(|| bad(format!("{id:?} is not a turn id (<branch>:<lsn>)")))?;
        if t.branch != self.node.branch() {
            return Err(ApiError::new(
                ErrorCode::TurnNotFound,
                format!("branch {:?} is not served here", t.branch),
            ));
        }
        Ok(t.lsn)
    }

    /// `TURN_NOT_FOUND` for a missing main-branch turn. A LSN below the
    /// log's first LSN was deleted by retention.
    async fn missing_turn(&self, id: &str, lsn: u64) -> ApiError {
        let first = match self.node.reader().starts().await {
            Ok(starts) => starts.first().copied().unwrap_or(1),
            Err(e) => return internal(e),
        };
        if lsn < first {
            ApiError::new(
                ErrorCode::TurnNotFound,
                format!("turn {id} is outside retention (log_first_lsn {first})"),
            )
        } else {
            ApiError::new(ErrorCode::TurnNotFound, format!("no turn {id}"))
        }
    }

    async fn turn(&self, id: &str, caller: &auth::Caller) -> Result<ApiResponse> {
        let pii = caller.has(auth::Scope::PiiRead);
        // A fork's turn: from the fork's log, or a persisted isolated tree.
        if let Some(r) = self.fork_turn_json(id, caller).await? {
            return Ok(r);
        }
        let lsn = self.turn_id(id)?;
        let c = match self.node.read_record(lsn).await? {
            Some(c) => c,
            None => return Err(self.missing_turn(id, lsn).await),
        };
        match &c.record {
            Record::TurnRecord(t) => {
                let hide = !pii && input_has_sealed(t.input.as_ref());
                let mut t = t.clone();
                redact::redact_turn(&mut t, self.node.sealer(), pii);
                redact_credentials(&mut t, pii);
                let mut v = turn_json(self.node.branch(), c.lsn, &t);
                if hide {
                    hide_http_identity(&mut v);
                }
                self.ok_scrubbed(&v)
            }
            _ => Err(ApiError::new(
                ErrorCode::TurnNotFound,
                format!("{id} is not a turn"),
            )),
        }
    }

    fn dead_letters(&self, q: &Query, pii: bool) -> Result<ApiResponse> {
        let after = match q.get("after") {
            Some(a) => self.turn_id(a)?,
            None => 0,
        };
        let rows = self
            .node
            .store()
            .db()
            .dead_letters(after, q.limit()?)
            .map_err(internal)?;
        let branch = self.node.branch();
        let id = |lsn| {
            TurnId {
                branch: branch.into(),
                lsn,
            }
            .to_string()
        };
        self.ok_scrubbed(&DeadLettersResponse {
            dead_letters: rows
                .iter()
                .map(|d| DeadLetter {
                    id: id(d.lsn),
                    actor: d.actor.to_string(),
                    input: input_summary(
                        Some(&if pii {
                            let mut i = d.input.clone();
                            redact::redact_input(&mut i, self.node.sealer(), true);
                            i
                        } else {
                            d.input.clone()
                        }),
                        pii,
                    ),
                    error_code: d.error_code.clone(),
                    message: d.message.clone(),
                    resent_as: d.resent_as.map(id),
                })
                .collect(),
        })
    }

    async fn resend(&self, req: &ApiRequest, id: &str) -> Result<ApiResponse> {
        let lsn = self.turn_id(id)?;
        let r: ResendRequest = json(&req.body)?;
        reason(&r.reason)?;
        let t = self
            .node
            .resend(lsn, self.audit(req, r.reason), r.dry_run)
            .await?;
        ok(&turn_response(t))
    }
}

/// Replaces secret values in every string of `v`; a payload's `base64` is
/// scrubbed as bytes and its `text` recomputed from them.
fn scrub_json(v: &mut serde_json::Value, secrets: &[(String, Vec<u8>)]) {
    use kronik_effects::http::{scrub, scrub_str};
    match v {
        serde_json::Value::String(s) => *s = scrub_str(s, secrets),
        serde_json::Value::Array(items) => {
            for i in items {
                scrub_json(i, secrets);
            }
        }
        serde_json::Value::Object(map) => {
            let bytes = map
                .get("base64")
                .and_then(serde_json::Value::as_str)
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
            if let Some(bytes) = bytes {
                let clean = scrub(&bytes, secrets);
                if map.contains_key("text") {
                    map.insert(
                        "text".into(),
                        std::str::from_utf8(&clean)
                            .map_or(serde_json::Value::Null, |t| t.to_owned().into()),
                    );
                }
                map.insert(
                    "base64".into(),
                    base64::engine::general_purpose::STANDARD
                        .encode(&clean)
                        .into(),
                );
            }
            for (k, item) in map.iter_mut() {
                if k != "base64" {
                    scrub_json(item, secrets);
                }
            }
        }
        _ => {}
    }
}

/// Whether an input holds a sealed value (privacy mode `on` with a subject).
pub(crate) fn input_has_sealed(input: Option<&pb::Input>) -> bool {
    let mut copy = input.cloned();
    let mut sealed = false;
    kronik_proto::sealables::input_mut(copy.as_mut(), &mut |s| {
        sealed |= matches!(s.value, Some(pb::sealable::Value::Sealed(_)));
    });
    sealed
}

/// Replaces a turn's HTTP path, query and parameter values with the
/// `[sealed]` placeholder, so summaries fall back to the route pattern:
/// for a caller without `pii:read` and a sealed request, before redaction
/// (which drops the seals) and for records from before the path was a
/// sealable field (v0.1 re-review R4).
pub(crate) fn hide_request_line(t: &mut pb::TurnRecord) {
    let Some(pb::input::Kind::Http(h)) = t.input.as_mut().and_then(|i| i.kind.as_mut()) else {
        return;
    };
    let sealed = || {
        Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(
                kronik_proto::http::SEALED.as_bytes().to_vec(),
            )),
        })
    };
    h.path.clear();
    h.query.clear();
    h.sealed_path = sealed();
    h.sealed_query = sealed();
    for p in &mut h.params {
        p.value.clear();
        p.sealed_value = sealed();
    }
}

/// For a caller without `pii:read`, a sealed HTTP request's path, query,
/// parameter values and `Idempotency-Key` are the subject's data, also in
/// records written before path and query were sealable fields (H10, H8).
pub(crate) fn hide_http_identity(turn: &mut serde_json::Value) {
    let Some(input) = turn.get_mut("input").filter(|i| i["type"] == "http") else {
        return;
    };
    let sealed = serde_json::Value::String(kronik_proto::http::SEALED.to_owned());
    for field in ["path", "query"] {
        input[field] = sealed.clone();
    }
    if input["idempotency_key"]
        .as_str()
        .is_some_and(|k| !k.is_empty())
    {
        input["idempotency_key"] = sealed.clone();
    }
    if let Some(params) = input["params"].as_array_mut() {
        for p in params {
            if let Some(pair) = p.as_array_mut()
                && pair.len() == 2
            {
                pair[1] = sealed.clone();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::*;

    #[test]
    fn request_lines_show_method_host_and_path_only() {
        let effect = |kind: &str, url: &str| pb::EffectRecord {
            kind: kind.into(),
            request: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(
                    pb::HttpEffectRequest {
                        method: "POST".into(),
                        url: url.into(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                )),
            }),
            ..Default::default()
        };
        let line = |kind, url| request_line(&effect(kind, url));
        assert_eq!(
            line(
                "http.fetch",
                "https://user:pw@api.example.com/v1/a@b?token=x#f"
            )
            .as_deref(),
            Some("POST api.example.com/v1/a@b")
        );
        assert_eq!(
            line("foreign.http", "http://127.0.0.1:8080").as_deref(),
            Some("POST 127.0.0.1:8080")
        );
        assert_eq!(line("actor.call", "http://127.0.0.1/"), None);
    }

    #[test]
    fn credentials_read_redacted_without_pii_read() {
        let header = |name: &str| pb::Header {
            name: name.into(),
            value: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(b"s3cret".to_vec())),
            }),
        };
        let names = [
            "Authorization",
            "Cookie",
            "X-Api-Key",
            "x-auth-token",
            "accept",
        ];
        let turn = pb::TurnRecord {
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Http(pb::HttpInput {
                    headers: names.iter().map(|n| header(n)).collect(),
                    ..Default::default()
                })),
            }),
            outcome: Some(pb::Outcome {
                output: Some(pb::outcome::Output::Http(pb::HttpResponse {
                    headers: vec![header("Set-Cookie"), header("content-type")],
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        let shown = |pii| {
            let mut t = turn.clone();
            redact_credentials(&mut t, pii);
            turn_json("main", 1, &t).to_string()
        };
        let without = shown(false);
        assert_eq!(without.matches("[redacted]").count(), 5, "{without}");
        assert_eq!(
            without.matches("s3cret").count(),
            2,
            "accept, content-type: {without}"
        );
        assert_eq!(shown(true).matches("s3cret").count(), 7);
    }
}
