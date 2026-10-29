//! The per-turn effect gate (docs/design/m2-effects.md §3-§5): capability
//! checks at the turn's epoch, `TurnBegin` before the first external effect,
//! call or secret use, `EffectResult` fsynced before the guest sees a
//! result, replay of recorded results in re-runs, and re-execution by
//! delivery class.

use std::sync::{Arc, Mutex};

use kronik_core::causal;
use kronik_core::env::{BoxFuture, HttpRequest, NetError};
use kronik_core::ids::{ActorRef, TurnId};
use kronik_effects::http::{fingerprint, parse_url, scrub};
use kronik_effects::simulator::{EffectRequest, RecordedMatch, ReplayContext};
use kronik_effects::{Config, Delivery, KindLimits};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CallOutcome, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchHeader, FetchOutcome,
    FetchRequest, FetchResponse, GateError,
};
use prost::Message as _;

use crate::node::Node;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A recorded value of `subject` (the guest's default subject at the
/// effect); sealed when the record is appended in privacy mode.
fn tagged(subject: &Option<String>, bytes: Vec<u8>) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: subject.clone(),
        value: Some(pb::sealable::Value::Plain(bytes)),
    })
}

fn plain(bytes: Vec<u8>) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(bytes)),
    })
}

fn sealable_bytes(s: Option<&pb::Sealable>) -> Vec<u8> {
    match s.and_then(|s| s.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.clone(),
        _ => Vec::new(),
    }
}

fn not_granted(cap: &str) -> String {
    format!("CAPABILITY_NOT_GRANTED: {cap}")
}

/// What the turn needs to know to record its effects.
pub(crate) struct TurnSpec {
    pub actor: ActorRef,
    pub execution_id: String,
    pub causal_key: pb::CausalKey,
    pub time: u64,
    /// The turn's start on the monotonic clock: effects record their
    /// `offset_us` from it (m28-otel §3.3).
    pub started: std::time::Duration,
    pub config: Arc<Config>,
    pub limits: KindLimits,
    pub call_chain: Vec<ActorRef>,
    /// The `TurnBegin` written before the first external effect.
    pub begin: pb::TurnBegin,
    /// Recorded results of an earlier execution (re-runs only).
    pub recorded: Option<Vec<pb::EffectRecord>>,
}

#[derive(Default)]
pub(crate) struct FxState {
    begun: bool,
    /// Every effect of the turn, denied ones included.
    pub records: Vec<pb::EffectRecord>,
    /// Compensations of successful calls, delivered if the turn fails.
    pub compensations: Vec<pb::OutboundMessage>,
    /// A guest received `outcome-unknown`.
    pub outcome_unknown: bool,
    /// Revealed or used secret values, scrubbed from guest logs.
    pub secrets: Vec<(String, Vec<u8>)>,
}

pub(crate) struct TurnFx {
    node: Arc<Node>,
    spec: TurnSpec,
    pub state: Mutex<FxState>,
}

/// The `EffectGate` handed to the runtime.
pub(crate) struct Gate(pub Arc<TurnFx>);

impl TurnFx {
    pub fn new(node: Arc<Node>, spec: TurnSpec) -> Arc<TurnFx> {
        let begun = spec.recorded.is_some();
        Arc::new(TurnFx {
            node,
            spec,
            state: Mutex::new(FxState {
                begun,
                ..FxState::default()
            }),
        })
    }

    fn kind(&self) -> &str {
        &self.spec.actor.kind
    }

    fn rerun(&self) -> bool {
        self.spec.recorded.is_some()
    }

    fn recorded(&self, req: &EffectRequest) -> Result<Option<pb::EffectRecord>, GateError> {
        let Some(recorded) = &self.spec.recorded else {
            return Ok(None);
        };
        let m = RecordedMatch {
            grounding: pb::Grounding::Live,
        };
        match m.lookup(req, &ReplayContext { recorded }) {
            Ok(r) => Ok(r.map(|r| r.record)),
            Err(d) => Err(GateError::Diverged(format!(
                "effect {} ({}) differs from the recorded request",
                d.ordinal, req.kind
            ))),
        }
    }

    /// [`Self::recorded`] for an effect whose fingerprint is keyed for its
    /// subject (`Sealer::effect_fingerprint`): a record written before
    /// keyed fingerprints, with the plain fingerprint `plain`, matches too.
    fn recorded_keyed(
        &self,
        req: &EffectRequest,
        plain: &[u8],
    ) -> Result<Option<pb::EffectRecord>, GateError> {
        match self.recorded(req) {
            Err(_)
                if self
                    .recorded_raw(req.ordinal)
                    .is_some_and(|r| r.kind == req.kind && r.fingerprint == plain) =>
            {
                Ok(self.recorded_raw(req.ordinal).cloned().map(|mut r| {
                    r.grounding = pb::Grounding::Live as i32;
                    r
                }))
            }
            other => other,
        }
    }

    fn recorded_raw(&self, ordinal: u32) -> Option<&pb::EffectRecord> {
        self.spec
            .recorded
            .as_ref()
            .and_then(|r| r.iter().find(|e| e.ordinal == ordinal))
    }

    /// Appends and fsyncs the `TurnBegin` once (I14).
    async fn begin(&self) -> Result<(), GateError> {
        if lock(&self.state).begun {
            return Ok(());
        }
        self.node
            .append(Record::TurnBegin(self.spec.begin.clone()))
            .await
            .map_err(|e| GateError::Host(e.to_string()))?;
        lock(&self.state).begun = true;
        Ok(())
    }

    /// Microseconds since the turn started.
    fn since_start(&self) -> u64 {
        self.node
            .env
            .clock
            .monotonic()
            .saturating_sub(self.spec.started)
            .as_micros() as u64
    }

    /// Appends and fsyncs the result before the guest sees it, without the
    /// values of the secrets the turn used or revealed so far (I8).
    async fn record(&self, mut rec: pb::EffectRecord) -> Result<(), GateError> {
        // From the effect's start (`base`) unless the effect timed itself.
        if rec.duration_us == 0 {
            rec.duration_us = self.since_start().saturating_sub(rec.offset_us);
        }
        let secrets = lock(&self.state).secrets.clone();
        crate::scrub::effect(&mut rec, &secrets);
        let status = pb::EffectStatus::try_from(rec.status)
            .map(|s| kronik_metrics::enum_label(s.as_str_name(), "EFFECT_STATUS_"))
            .unwrap_or_default();
        kronik_metrics::inc(
            "kronik_effects_total",
            &[("kind", &rec.kind), ("status", &status)],
        );
        self.node
            .append(Record::EffectResult(pb::EffectResult {
                execution_id: self.spec.execution_id.clone(),
                effect: Some(rec.clone()),
            }))
            .await
            .map_err(|e| GateError::Host(e.to_string()))?;
        lock(&self.state).records.push(rec);
        Ok(())
    }

    /// A deterministic result that needs no fsync (denied by configuration).
    fn note(&self, rec: pb::EffectRecord) {
        lock(&self.state).records.push(rec);
    }

    fn base(&self, ordinal: u32, kind: &str, target: String, fp: Vec<u8>) -> pb::EffectRecord {
        pb::EffectRecord {
            ordinal,
            kind: kind.into(),
            target,
            fingerprint: fp,
            grounding: pb::Grounding::Live as i32,
            offset_us: self.since_start(),
            ..Default::default()
        }
    }

    fn denied(&self, ordinal: u32, kind: &str, target: String, error: String) -> pb::EffectRecord {
        let mut r = self.base(ordinal, kind, target, Vec::new());
        r.status = pb::EffectStatus::Denied as i32;
        r.error = error;
        r
    }

    fn secret_value(
        &self,
        name: &str,
        version: Option<u32>,
    ) -> Result<Option<kronik_privacy::SecretValue>, GateError> {
        let Some(store) = &self.node.secrets else {
            return Ok(None);
        };
        let v = match version {
            Some(v) => store.version(name, v),
            None => store.current(name),
        };
        v.map_err(|e| GateError::Host(e.to_string()))
    }

    async fn fetch(&self, ordinal: u32, req: FetchRequest) -> Result<FetchOutcome, GateError> {
        let subject = req.subject.clone();
        let target = match parse_url(&req.url) {
            Ok(t) => t,
            Err(e) => {
                self.note(self.denied(ordinal, "http.fetch", String::new(), e.clone()));
                return Ok(FetchOutcome::Denied(e));
            }
        };
        // foreign:// reaches a foreign actor (docs/design/m7-foreign.md §8):
        // the same pipeline as http.fetch with its own kind, capability and
        // transport.
        let foreign = target.scheme == "foreign";
        let kind = if foreign {
            "foreign.http"
        } else {
            "http.fetch"
        };
        let cap_target = if foreign {
            format!("foreign:{}", target.host)
        } else {
            format!("http:{}", target.host)
        };
        let grant = if foreign {
            self.spec.config.grant(self.kind(), &cap_target).cloned()
        } else {
            self.spec
                .config
                .http_grant(self.kind(), &target.host)
                .cloned()
        };
        let Some(grant) = grant else {
            let e = not_granted(&cap_target);
            self.note(self.denied(ordinal, kind, cap_target, e.clone()));
            return Ok(FetchOutcome::Denied(e));
        };
        if foreign && self.spec.config.foreign(&target.host).is_none() {
            let e = format!("FOREIGN_NOT_FOUND: no foreign actor {}", target.host);
            self.note(self.denied(ordinal, kind, cap_target, e.clone()));
            return Ok(FetchOutcome::Denied(e));
        }
        // Secret headers: the capability, then the recorded version on a
        // re-run with a result, else the current version.
        let recorded_req: Option<pb::HttpEffectRequest> =
            self.recorded_raw(ordinal).and_then(|r| {
                pb::HttpEffectRequest::decode(sealable_bytes(r.request.as_ref()).as_slice()).ok()
            });
        let mut headers = Vec::new();
        let mut wire_secrets: Vec<(String, String, Vec<u8>)> = Vec::new();
        for (name, value) in &req.headers {
            if name.eq_ignore_ascii_case("idempotency-key") {
                continue;
            }
            let value = match value {
                FetchHeader::Text(t) => pb::http_effect_header::Value::Text(t.clone()),
                FetchHeader::Secret {
                    name: secret,
                    template,
                } => {
                    let cap = format!("secret:{secret}");
                    if self.spec.config.grant(self.kind(), &cap).is_none() {
                        let e = not_granted(&cap);
                        self.note(self.denied(ordinal, kind, cap, e.clone()));
                        return Ok(FetchOutcome::Denied(e));
                    }
                    let recorded_ref = recorded_req.as_ref().and_then(|r| {
                        r.headers.iter().find_map(|h| match &h.value {
                            Some(pb::http_effect_header::Value::Secret(s))
                                if h.name == *name && s.name == *secret =>
                            {
                                Some(s.clone())
                            }
                            _ => None,
                        })
                    });
                    let sref = match recorded_ref {
                        Some(r) => r,
                        None => {
                            let Some(v) = self.secret_value(secret, None)? else {
                                let e = format!("SECRET_NOT_FOUND: {secret}");
                                self.note(self.denied(ordinal, kind, cap, e.clone()));
                                return Ok(FetchOutcome::Denied(e));
                            };
                            wire_secrets.push((secret.clone(), template.clone(), v.value));
                            pb::SecretRef {
                                name: secret.clone(),
                                template: template.clone(),
                                version: v.meta.version,
                                version_hash: v.meta.version_hash,
                            }
                        }
                    };
                    pb::http_effect_header::Value::Secret(sref)
                }
            };
            headers.push(pb::HttpEffectHeader {
                name: name.clone(),
                value: Some(value),
            });
        }
        let request = pb::HttpEffectRequest {
            method: req.method.clone(),
            url: req.url.clone(),
            headers,
            body: req.body.clone(),
        };
        // Recorded and fingerprinted without the values of secrets revealed
        // so far (I8), so a fork's placeholder (`[secret:<name>]`) matches
        // the recording exactly; `request` itself goes on the wire.
        let mut recorded = request.clone();
        crate::scrub::http_request(&mut recorded, &lock(&self.state).secrets.clone());
        let plain_fp = fingerprint(&recorded).map_err(GateError::Host)?;
        let fp = self
            .node
            .sealer()
            .effect_fingerprint(subject.as_deref(), plain_fp.clone());
        let ereq = EffectRequest {
            ordinal,
            kind: kind.into(),
            target: cap_target.clone(),
            fingerprint: fp.clone(),
            http: None,
        };
        if let Some(rec) = self.recorded_keyed(&ereq, &plain_fp)? {
            lock(&self.state).records.push(rec.clone());
            return Ok(outcome_of_fetch(&rec));
        }
        let delivery = grant
            .delivery
            .unwrap_or_else(|| Delivery::default_for(&req.method));
        let idem = causal::idempotency_key(&self.spec.causal_key, ordinal);
        let mut rec = self.base(ordinal, kind, cap_target, fp);
        rec.request = tagged(&subject, recorded.encode_to_vec());
        rec.idempotency_key = idem.clone();
        rec.delivery = delivery.as_str().into();
        if self.rerun() && delivery == Delivery::Unsafe {
            // I17: an unsafe effect without a recorded result is not
            // performed again.
            rec.status = pb::EffectStatus::OutcomeUnknown as i32;
            rec.error = "outcome unknown: the daemon stopped before the result was recorded".into();
            self.record(rec).await?;
            lock(&self.state).outcome_unknown = true;
            return Ok(FetchOutcome::OutcomeUnknown);
        }
        self.begin().await?;
        if let Some(rate) = grant.rate {
            let key = format!("{}|{}|{}", grant.kind, grant.capability, target.host);
            self.node.rates.acquire(&self.node.env, &key, rate).await;
        }
        // The values of secrets taken from the recording are needed on the
        // wire again (replay-safe or idempotency-keyed re-execution).
        for h in &request.headers {
            if let Some(pb::http_effect_header::Value::Secret(s)) = &h.value
                && !wire_secrets.iter().any(|(n, _, _)| *n == s.name)
            {
                let Some(v) = self.secret_value(&s.name, Some(s.version))? else {
                    let e = format!("SECRET_NOT_FOUND: {}", s.name);
                    rec.status = pb::EffectStatus::Denied as i32;
                    rec.error = e.clone();
                    self.record(rec).await?;
                    return Ok(FetchOutcome::Denied(e));
                };
                wire_secrets.push((s.name.clone(), s.template.clone(), v.value));
            }
        }
        let mut wire_headers: Vec<(String, String)> = Vec::new();
        for h in &request.headers {
            match &h.value {
                Some(pb::http_effect_header::Value::Text(t)) => {
                    wire_headers.push((h.name.clone(), t.clone()))
                }
                Some(pb::http_effect_header::Value::Secret(s)) => {
                    if let Some((_, tpl, v)) = wire_secrets.iter().find(|(n, _, _)| *n == s.name) {
                        let value = String::from_utf8_lossy(v);
                        let rendered = if tpl.contains("{}") {
                            tpl.replace("{}", &value)
                        } else {
                            value.into_owned()
                        };
                        wire_headers.push((h.name.clone(), rendered));
                    }
                }
                None => {}
            }
        }
        wire_headers.push(("idempotency-key".into(), idem));
        let secrets: Vec<(String, Vec<u8>)> = wire_secrets
            .iter()
            .map(|(n, _, v)| (n.clone(), v.clone()))
            .collect();
        lock(&self.state).secrets.extend(secrets.iter().cloned());
        let started = self.node.env.clock.monotonic();
        rec.offset_us = started.saturating_sub(self.spec.started).as_micros() as u64;
        let wire = HttpRequest {
            method: req.method,
            url: req.url,
            headers: wire_headers,
            body: bytes::Bytes::from(req.body),
            max_response_bytes: self.spec.limits.effect_response_bytes,
        };
        let call: BoxFuture<'static, Result<kronik_core::env::HttpResponse, NetError>> =
            match (foreign, &self.node.foreign) {
                (false, _) => self.node.env.net.http(wire),
                (true, Some(host)) => host.http(&target.host, wire),
                (true, None) => {
                    let e = kronik_effects::foreign::unavailable(
                        &target.host,
                        "foreign actors are not available in this process",
                    );
                    Box::pin(std::future::ready(Err(e)))
                }
            };
        let res = self
            .node
            .env
            .timeout(self.spec.limits.effect_timeout, call)
            .await;
        rec.duration_us = self
            .node
            .env
            .clock
            .monotonic()
            .saturating_sub(started)
            .as_micros() as u64;
        // The guest sees the answer as a re-run will (from the scrubbed
        // recording): without the values of every secret known so far,
        // inserted or revealed (I8, I1).
        let secrets = lock(&self.state).secrets.clone();
        let outcome = match res {
            Err(_) => {
                rec.status = pb::EffectStatus::Timeout as i32;
                rec.error = format!(
                    "no response within {} ms",
                    self.spec.limits.effect_timeout.as_millis()
                );
                FetchOutcome::Timeout
            }
            Ok(Err(NetError::TooLarge)) => {
                rec.status = pb::EffectStatus::TooLarge as i32;
                rec.error = format!(
                    "the response exceeds {} bytes",
                    self.spec.limits.effect_response_bytes
                );
                FetchOutcome::TooLarge
            }
            Ok(Err(NetError::Connect(e) | NetError::Io(e))) => {
                let e = kronik_effects::http::scrub_str(&e, &secrets);
                rec.status = pb::EffectStatus::Network as i32;
                rec.error = e.clone();
                FetchOutcome::Network(e)
            }
            Ok(Ok(resp)) => {
                let response = FetchResponse {
                    status: resp.status,
                    headers: resp
                        .headers
                        .iter()
                        .map(|(n, v)| (n.clone(), kronik_effects::http::scrub_str(v, &secrets)))
                        .collect(),
                    body: scrub(&resp.body, &secrets),
                };
                rec.status = pb::EffectStatus::Ok as i32;
                rec.response = tagged(
                    &subject,
                    pb::HttpEffectResponse {
                        status: u32::from(response.status),
                        headers: response
                            .headers
                            .iter()
                            .map(|(name, value)| pb::HeaderPair {
                                name: name.clone(),
                                value: value.clone(),
                            })
                            .collect(),
                        body: response.body.clone(),
                    }
                    .encode_to_vec(),
                );
                FetchOutcome::Ok(response)
            }
        };
        self.record(rec).await?;
        Ok(outcome)
    }

    async fn call(
        &self,
        ordinal: u32,
        to: ActorRef,
        msg: pb::Message,
        compensate: Option<pb::Message>,
    ) -> Result<CallOutcome, GateError> {
        let kind = "actor.call";
        let message_id = causal::message_id(&self.spec.causal_key, ordinal);
        let request = pb::CallEffectRequest {
            to: Some(to.to_pb()),
            msg: Some(msg.clone()),
            compensate: compensate.clone(),
            message_id: message_id.clone(),
        };
        // Recorded and fingerprinted without revealed secret values (I8),
        // as for fetch; `msg` itself is what the callee gets.
        let mut recorded = request;
        let known = lock(&self.state).secrets.clone();
        crate::scrub::message(&mut recorded.msg, &known);
        crate::scrub::message(&mut recorded.compensate, &known);
        let encoded = recorded.encode_to_vec();
        // The request holds the message: it is the message's subject's data.
        let msg_subject = msg.body.as_ref().and_then(|b| b.subject.clone());
        let plain_fp = blake3::hash(&encoded).as_bytes().to_vec();
        let fp = self
            .node
            .sealer()
            .effect_fingerprint(msg_subject.as_deref(), plain_fp.clone());
        let target = format!("actor:{to}");
        let ereq = EffectRequest {
            ordinal,
            kind: kind.into(),
            target: target.clone(),
            fingerprint: fp.clone(),
            http: None,
        };
        let mut rec = self.base(ordinal, kind, target, fp);
        rec.request = tagged(&msg_subject, encoded);
        let outcome = if let Some(r) = self.recorded_keyed(&ereq, &plain_fp)? {
            lock(&self.state).records.push(r.clone());
            rec = r;
            outcome_of_call(&rec)
        } else {
            self.begin().await?;
            let (mut outcome, turn_id) = self.perform_call(ordinal, &to, msg, &message_id).await;
            if self.node.hold_after_call() {
                std::future::pending::<()>().await;
            }
            // As for fetch: the reply as a re-run will see it (I8, I1).
            let secrets = lock(&self.state).secrets.clone();
            match &mut outcome {
                CallOutcome::Ok(reply) => crate::scrub::message(reply, &secrets),
                CallOutcome::Rejected(m) | CallOutcome::Failed(m) => {
                    *m = kronik_effects::http::scrub_str(m, &secrets);
                }
                _ => {}
            }
            match &outcome {
                CallOutcome::Ok(reply) => {
                    rec.status = pb::EffectStatus::Ok as i32;
                    let reply_subject = reply
                        .as_ref()
                        .and_then(|m| m.body.as_ref())
                        .and_then(|b| b.subject.clone());
                    rec.response = tagged(
                        &reply_subject,
                        pb::CallEffectResponse {
                            reply: reply.clone(),
                            turn_id: turn_id.unwrap_or_default(),
                        }
                        .encode_to_vec(),
                    );
                }
                CallOutcome::NotFound => {
                    rec.status = pb::EffectStatus::NotFound as i32;
                    rec.error = format!("no deployed kind {:?}", to.kind);
                }
                CallOutcome::Rejected(m) => {
                    rec.status = pb::EffectStatus::Rejected as i32;
                    rec.error = m.clone();
                }
                CallOutcome::Failed(m) => {
                    rec.status = pb::EffectStatus::Failed as i32;
                    rec.error = m.clone();
                }
                CallOutcome::Reentrant => {
                    rec.status = pb::EffectStatus::Reentrant as i32;
                    rec.error = format!("{to} is already waiting in a call on this chain");
                }
                CallOutcome::Timeout => {
                    rec.status = pb::EffectStatus::Timeout as i32;
                    rec.error = format!(
                        "no answer within {} ms",
                        self.spec.limits.effect_timeout.as_millis()
                    );
                }
            }
            self.record(rec.clone()).await?;
            outcome
        };
        if let (CallOutcome::Ok(_), Some(c)) = (&outcome, compensate) {
            let key = causal::compensation(&self.spec.causal_key, &self.spec.actor, ordinal, &to);
            lock(&self.state).compensations.push(pb::OutboundMessage {
                to: Some(to.to_pb()),
                msg: Some(c),
                ordinal,
                message_id: causal::causal_id(&key),
            });
        }
        Ok(outcome)
    }

    /// Runs the callee's turn (or returns its saved outcome).
    async fn perform_call(
        &self,
        ordinal: u32,
        to: &ActorRef,
        msg: pb::Message,
        message_id: &str,
    ) -> (CallOutcome, Option<String>) {
        if *to == self.spec.actor || self.spec.call_chain.contains(to) {
            return (CallOutcome::Reentrant, None);
        }
        if !self.node.kind_exists(&to.kind) {
            return (CallOutcome::NotFound, None);
        }
        let branch = self.node.branch().to_owned();
        let saved = self.node.store().db().call_outcome(message_id);
        if let Ok(Some((lsn, mut outcome))) = saved {
            self.node.unseal_outcome(&mut outcome);
            return (
                map_call_outcome(&outcome),
                Some(TurnId { branch, lsn }.to_string()),
            );
        }
        let mut chain = self.spec.call_chain.clone();
        chain.push(self.spec.actor.clone());
        let input = pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::Call as i32,
                sender: Some(self.spec.actor.to_pb()),
                msg: Some(msg),
                message_id: message_id.to_owned(),
                sent_logical_time_ms: self.spec.time,
                call_chain: chain.iter().map(ActorRef::to_pb).collect(),
                ..Default::default()
            })),
        };
        let key = causal::child(&self.spec.causal_key, &self.spec.actor, ordinal);
        let rx = self
            .node
            .enqueue_call(to.clone(), input, key, self.spec.time);
        match self
            .node
            .env
            .timeout(self.spec.limits.effect_timeout, rx)
            .await
        {
            Err(_) => (CallOutcome::Timeout, None),
            Ok(Err(_)) => (CallOutcome::Failed("the callee was abandoned".into()), None),
            Ok(Ok(Err(e))) => (CallOutcome::Failed(e.to_string()), None),
            Ok(Ok(Ok(r))) => (map_call_outcome(&r.outcome), Some(r.turn_id.to_string())),
        }
    }

    async fn crypto(
        &self,
        ordinal: u32,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> Result<CryptoOutcome, GateError> {
        let (kind, alg) = match algorithm {
            CryptoAlgorithm::HmacSha256 => ("crypto.hmac-sha256", "hmac-sha256"),
            CryptoAlgorithm::SignEd25519 => ("crypto.sign-ed25519", "sign-ed25519"),
        };
        let cap = format!("secret:{secret}");
        if self.spec.config.grant(self.kind(), &cap).is_none() {
            let e = not_granted(&cap);
            self.note(self.denied(ordinal, kind, cap, e.clone()));
            return Ok(CryptoOutcome::Denied(e));
        }
        let data_hash = blake3::hash(&data).as_bytes().to_vec();
        let mut h = blake3::Hasher::new();
        h.update(alg.as_bytes());
        h.update(b"\0");
        h.update(secret.as_bytes());
        h.update(b"\0");
        h.update(&data_hash);
        let fp = h.finalize().as_bytes().to_vec();
        let ereq = EffectRequest {
            ordinal,
            kind: kind.into(),
            target: cap.clone(),
            fingerprint: fp.clone(),
            http: None,
        };
        if let Some(rec) = self.recorded(&ereq)? {
            lock(&self.state).records.push(rec.clone());
            return Ok(if rec.status == pb::EffectStatus::Ok as i32 {
                CryptoOutcome::Ok(sealable_bytes(rec.response.as_ref()))
            } else if rec.status == pb::EffectStatus::Denied as i32 {
                CryptoOutcome::Denied(rec.error)
            } else {
                CryptoOutcome::Unsupported(rec.error)
            });
        }
        self.begin().await?;
        let mut rec = self.base(ordinal, kind, cap, fp);
        let outcome = match self.secret_value(&secret, None)? {
            None => {
                rec.status = pb::EffectStatus::Denied as i32;
                rec.error = format!("SECRET_NOT_FOUND: {secret}");
                CryptoOutcome::Denied(rec.error.clone())
            }
            Some(v) => {
                rec.request = plain(
                    pb::CryptoEffectRequest {
                        algorithm: alg.into(),
                        secret: Some(pb::SecretRef {
                            name: secret.clone(),
                            template: String::new(),
                            version: v.meta.version,
                            version_hash: v.meta.version_hash.clone(),
                        }),
                        data_hash,
                    }
                    .encode_to_vec(),
                );
                lock(&self.state)
                    .secrets
                    .push((secret.clone(), v.value.clone()));
                let result = match algorithm {
                    CryptoAlgorithm::HmacSha256 => {
                        Ok(kronik_effects::crypto::hmac_sha256(&v.value, &data))
                    }
                    CryptoAlgorithm::SignEd25519 => {
                        kronik_effects::crypto::sign_ed25519(&v.value, &data)
                    }
                };
                match result {
                    Ok(out) => {
                        rec.status = pb::EffectStatus::Ok as i32;
                        rec.response = plain(out.clone());
                        CryptoOutcome::Ok(out)
                    }
                    Err(e) => {
                        rec.status = pb::EffectStatus::Failed as i32;
                        rec.error = e.clone();
                        CryptoOutcome::Unsupported(e)
                    }
                }
            }
        };
        self.record(rec).await?;
        Ok(outcome)
    }

    async fn reveal(
        &self,
        ordinal: u32,
        name: String,
    ) -> Result<Result<String, String>, GateError> {
        let kind = "secret.reveal";
        let cap = format!("secret-reveal:{name}");
        if self.spec.config.grant(self.kind(), &cap).is_none() {
            let e = not_granted(&cap);
            self.note(self.denied(ordinal, kind, cap, e.clone()));
            return Ok(Err(e));
        }
        let fp = blake3::hash(format!("reveal\0{name}").as_bytes())
            .as_bytes()
            .to_vec();
        let ereq = EffectRequest {
            ordinal,
            kind: kind.into(),
            target: cap.clone(),
            fingerprint: fp.clone(),
            http: None,
        };
        if let Some(rec) = self.recorded(&ereq)? {
            lock(&self.state).records.push(rec.clone());
            if rec.status != pb::EffectStatus::Ok as i32 {
                return Ok(Err(rec.error));
            }
            let req =
                pb::RevealEffectRequest::decode(sealable_bytes(rec.request.as_ref()).as_slice())
                    .map_err(|e| GateError::Host(e.to_string()))?;
            let version = req.secret.map_or(0, |s| s.version);
            return Ok(match self.secret_value(&name, Some(version))? {
                Some(v) => {
                    lock(&self.state).secrets.push((name, v.value.clone()));
                    Ok(String::from_utf8_lossy(&v.value).into_owned())
                }
                None => Err(format!("SECRET_NOT_FOUND: {name} version {version}")),
            });
        }
        self.begin().await?;
        let mut rec = self.base(ordinal, kind, cap, fp);
        let out = match self.secret_value(&name, None)? {
            None => {
                rec.status = pb::EffectStatus::Denied as i32;
                rec.error = format!("SECRET_NOT_FOUND: {name}");
                Err(rec.error.clone())
            }
            Some(v) => {
                rec.status = pb::EffectStatus::Ok as i32;
                rec.request = plain(
                    pb::RevealEffectRequest {
                        secret: Some(pb::SecretRef {
                            name: name.clone(),
                            template: String::new(),
                            version: v.meta.version,
                            version_hash: v.meta.version_hash.clone(),
                        }),
                    }
                    .encode_to_vec(),
                );
                lock(&self.state).secrets.push((name, v.value.clone()));
                Ok(String::from_utf8_lossy(&v.value).into_owned())
            }
        };
        self.record(rec).await?;
        Ok(out)
    }
}

/// The guest-visible result of a recorded fetch.
pub fn outcome_of_fetch(rec: &pb::EffectRecord) -> FetchOutcome {
    match pb::EffectStatus::try_from(rec.status).unwrap_or(pb::EffectStatus::Unspecified) {
        pb::EffectStatus::Ok => {
            let r =
                pb::HttpEffectResponse::decode(sealable_bytes(rec.response.as_ref()).as_slice())
                    .unwrap_or_default();
            FetchOutcome::Ok(FetchResponse {
                status: u16::try_from(r.status).unwrap_or(500),
                headers: r.headers.into_iter().map(|h| (h.name, h.value)).collect(),
                body: r.body,
            })
        }
        pb::EffectStatus::Timeout => FetchOutcome::Timeout,
        pb::EffectStatus::TooLarge => FetchOutcome::TooLarge,
        pb::EffectStatus::OutcomeUnknown => FetchOutcome::OutcomeUnknown,
        pb::EffectStatus::Network => FetchOutcome::Network(rec.error.clone()),
        _ => FetchOutcome::Denied(rec.error.clone()),
    }
}

/// The guest-visible result of a recorded call.
pub fn outcome_of_call(rec: &pb::EffectRecord) -> CallOutcome {
    match pb::EffectStatus::try_from(rec.status).unwrap_or(pb::EffectStatus::Unspecified) {
        pb::EffectStatus::Ok => CallOutcome::Ok(
            pb::CallEffectResponse::decode(sealable_bytes(rec.response.as_ref()).as_slice())
                .ok()
                .and_then(|r| r.reply),
        ),
        pb::EffectStatus::NotFound => CallOutcome::NotFound,
        pb::EffectStatus::Rejected => CallOutcome::Rejected(rec.error.clone()),
        pb::EffectStatus::Reentrant => CallOutcome::Reentrant,
        pb::EffectStatus::Timeout => CallOutcome::Timeout,
        _ => CallOutcome::Failed(rec.error.clone()),
    }
}

/// The callee's turn outcome as the caller sees it.
pub fn map_call_outcome(o: &pb::Outcome) -> CallOutcome {
    match pb::OutcomeKind::try_from(o.kind).unwrap_or(pb::OutcomeKind::Unspecified) {
        pb::OutcomeKind::Committed => CallOutcome::Ok(match &o.output {
            Some(pb::outcome::Output::Reply(m)) => Some(m.clone()),
            Some(pb::outcome::Output::Http(h)) => Some(pb::Message {
                name: format!("http {}", h.status),
                content_type: String::new(),
                body: match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                    Some(pb::body::Value::Inline(s)) => Some(s.clone()),
                    _ => None,
                },
                blobs: Vec::new(),
            }),
            None => None,
        }),
        pb::OutcomeKind::Rejected => CallOutcome::Rejected(o.message.clone()),
        _ if o.error_code == kronik_core::error::ErrorCode::ActorNotFound.as_str() => {
            CallOutcome::NotFound
        }
        _ => CallOutcome::Failed(o.message.clone()),
    }
}

impl EffectGate for Gate {
    fn fetch(
        &self,
        ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        let fx = self.0.clone();
        Box::pin(async move { fx.fetch(ordinal, req).await })
    }

    fn call(
        &self,
        ordinal: u32,
        to: ActorRef,
        msg: pb::Message,
        compensate: Option<pb::Message>,
    ) -> BoxFuture<'static, Result<CallOutcome, GateError>> {
        let fx = self.0.clone();
        Box::pin(async move { fx.call(ordinal, to, msg, compensate).await })
    }

    fn crypto(
        &self,
        ordinal: u32,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> BoxFuture<'static, Result<CryptoOutcome, GateError>> {
        let fx = self.0.clone();
        Box::pin(async move { fx.crypto(ordinal, algorithm, secret, data).await })
    }

    fn reveal(
        &self,
        ordinal: u32,
        name: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>> {
        let fx = self.0.clone();
        Box::pin(async move { fx.reveal(ordinal, name).await })
    }
}
