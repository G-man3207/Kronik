//! The host side of the `kronik:actor` world and the deterministic WASI
//! subset (ADR 0001).
//!
//! Everything a turn can observe is a function of the turn's recorded inputs:
//! actor, causal key, logical time, seed, input, the actor's state at turn
//! start, and the configuration epoch. Writes, messages and SQL changes are
//! buffered and only leave the turn through [`crate::turn::TurnOutput`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chacha20::ChaCha20Rng;
use chacha20::rand_core::{Rng, SeedableRng};
use kronik_core::causal;
use kronik_core::env::BoxFuture;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use wasmtime::component::{HasData, Resource, ResourceTable};
use wasmtime::{ResourceLimiter, bail};
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};
use wasmtime_wasi::p2::bindings::clocks::{monotonic_clock, wall_clock};
use wasmtime_wasi::p2::bindings::random::{insecure, insecure_seed, random};
use wasmtime_wasi::p2::{DynPollable, OutputStream, Pollable, StreamResult};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

pub mod bindings {
    wasmtime::component::bindgen!({
        world: "actor",
        path: "../../wit/kronik-actor.wit",
        imports: { default: async | trappable },
        exports: { default: async },
    });
}

use bindings::kronik::actor::{
    context, crypto, http_client, log, messaging, privacy, secrets, sql, state, timers, types,
};

pub use sql::{Rows as SqlRows, SqlError, SqlValue};

/// Maximum bytes per random request; larger requests trap.
const MAX_RANDOM_BYTES: u64 = 1 << 20;

/// ChaCha20 stream ids under the turn seed (ADR 0001). Stream 4 is SQL
/// `random()` (ADR 0005), drawn by the SQL host.
const STREAM_CONTEXT: u64 = 0;
const STREAM_WASI_RANDOM: u64 = 1;
const STREAM_WASI_INSECURE: u64 = 2;
const STREAM_WASI_INSECURE_SEED: u64 = 3;

/// Per-kind limits that apply to one turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnLimits {
    pub fuel: u64,
    pub memory_bytes: usize,
    pub message_bytes: usize,
    pub state_value_bytes: usize,
}

impl Default for TurnLimits {
    fn default() -> Self {
        TurnLimits {
            fuel: crate::engine::DEFAULT_FUEL,
            memory_bytes: crate::engine::DEFAULT_MEMORY_BYTES,
            message_bytes: 1 << 20,
            state_value_bytes: 1 << 20,
        }
    }
}

/// The actor's committed key-value state at turn start. An `Err` is a host
/// failure: the turn is abandoned without a record.
pub trait StateView: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    fn keys(&self, prefix: &str) -> Result<Vec<String>, String>;
    /// Whether the actor has a committed, pending timer with this id.
    fn timer_pending(&self, id: u64) -> Result<bool, String>;
}

/// A header of an outgoing HTTP effect: text, or a secret filled in by the
/// host at the effect boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchHeader {
    Text(String),
    Secret { name: String, template: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, FetchHeader)>,
    pub body: Vec<u8>,
    /// The guest's default subject at the call: the request and its
    /// response are that subject's data (docs/design/m8-privacy.md §4).
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// `http-client.fetch` results (`fetch-error` in the WIT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    Ok(FetchResponse),
    Denied(String),
    Network(String),
    Timeout,
    TooLarge,
    OutcomeUnknown,
}

/// `messaging.call` results (`call-error` in the WIT).
#[derive(Debug, Clone, PartialEq)]
pub enum CallOutcome {
    Ok(Option<pb::Message>),
    NotFound,
    Rejected(String),
    Failed(String),
    Reentrant,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    HmacSha256,
    SignEd25519,
}

/// `crypto.*` results (`crypto-error` in the WIT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoOutcome {
    Ok(Vec<u8>),
    Denied(String),
    Unsupported(String),
}

/// Why the gate could not produce a guest-visible result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    /// A host failure: the turn is abandoned without a record.
    Host(String),
    /// A re-run's request differs from the recorded one: the turn traps
    /// with `REPLAY_DIVERGED`.
    Diverged(String),
}

/// The effect boundary of one turn (docs/design/m2-effects.md §3): the
/// scheduler implements capability checks, `TurnBegin`, recording, replay of
/// recorded results and execution. `ordinal` is the turn's operation ordinal.
pub trait EffectGate: Send + Sync {
    fn fetch(
        &self,
        ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>>;
    fn call(
        &self,
        ordinal: u32,
        to: ActorRef,
        msg: pb::Message,
        compensate: Option<pb::Message>,
    ) -> BoxFuture<'static, Result<CallOutcome, GateError>>;
    fn crypto(
        &self,
        ordinal: u32,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> BoxFuture<'static, Result<CryptoOutcome, GateError>>;
    fn reveal(
        &self,
        ordinal: u32,
        name: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>>;
}

/// The u64 id of the timer scheduled by the turn `key` with `ordinal`.
pub fn timer_id(key: &pb::CausalKey, ordinal: u32) -> u64 {
    let mut bytes = causal::encode(key);
    bytes.extend_from_slice(b"timer");
    bytes.extend_from_slice(&ordinal.to_le_bytes());
    let h = blake3::hash(&bytes);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

/// Why a SQL call did not produce a guest-visible result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlHostError {
    /// The turn's SQL work budget ran out: the turn fails with
    /// `FUEL_EXHAUSTED`.
    FuelExhausted,
    /// A host failure: the turn is abandoned without a record.
    Host(String),
}

/// The actor's SQL database for one turn. `subject` is the turn's default
/// subject at the time of the call (for `kronik_subject()` and tables without
/// `_subject`).
pub trait SqlHost: Send {
    fn query(
        &mut self,
        statement: &str,
        params: Vec<SqlValue>,
        subject: Option<&str>,
    ) -> Result<Result<SqlRows, SqlError>, SqlHostError>;
    fn execute(
        &mut self,
        statement: &str,
        params: Vec<SqlValue>,
        subject: Option<&str>,
    ) -> Result<Result<u64, SqlError>, SqlHostError>;
}

/// A guest log event (`log.emit` or a write to stdout/stderr).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    pub level: &'static str,
    pub message: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Clone, Default)]
pub(crate) struct Logs(Arc<Mutex<Vec<LogEvent>>>);

impl Logs {
    fn push(&self, e: LogEvent) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(e);
    }
    pub(crate) fn take(&self) -> Vec<LogEvent> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// Caps the total linear memory of all memories in the instance. A refused
/// growth makes `memory.grow` return -1; the flag lets the host classify a
/// following trap as a memory-limit failure.
pub(crate) struct MemoryLimiter {
    max_bytes: usize,
    total_bytes: usize,
    pub(crate) peak_bytes: usize,
    pub(crate) hit: bool,
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let next = self.total_bytes - current.min(self.total_bytes) + desired;
        if next > self.max_bytes {
            self.hit = true;
            return Ok(false);
        }
        self.total_bytes = next;
        self.peak_bytes = self.peak_bytes.max(next);
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 1_000_000)
    }
}

/// A buffered state write: `None` deletes.
pub(crate) type Write = Option<(Vec<u8>, Option<String>)>;

/// Per-turn store data, built fresh for every turn with a fresh instance.
pub struct TurnHost {
    wasi: WasiCtx,
    table: ResourceTable,
    pub(crate) limiter: MemoryLimiter,
    pub(crate) logs: Logs,
    describe_only: bool,
    actor: ActorRef,
    causal_key: pb::CausalKey,
    causal_id: String,
    now_ms: u64,
    rng_context: ChaCha20Rng,
    rng_wasi: ChaCha20Rng,
    rng_insecure: ChaCha20Rng,
    insecure_seed: (u64, u64),
    limits: TurnLimits,
    state: Option<Arc<dyn StateView>>,
    pub(crate) sql: Option<Box<dyn SqlHost>>,
    pub(crate) subject: Option<String>,
    pub(crate) writes: BTreeMap<String, Write>,
    pub(crate) messages: Vec<pb::OutboundMessage>,
    pub(crate) timers: Vec<pb::TimerOp>,
    gate: Option<Arc<dyn EffectGate>>,
    next_ordinal: u32,
    /// A host failure (not guest-visible); the turn is abandoned.
    pub(crate) fatal: Option<String>,
}

fn stream(seed: [u8; 32], id: u64) -> ChaCha20Rng {
    let mut rng = ChaCha20Rng::from_seed(seed);
    rng.set_stream(id);
    rng
}

pub(crate) struct HostInit {
    pub actor: ActorRef,
    pub causal_key: pb::CausalKey,
    pub now_ms: u64,
    pub seed: [u8; 32],
    pub limits: TurnLimits,
    pub subject: Option<String>,
    pub state: Option<Arc<dyn StateView>>,
    pub sql: Option<Box<dyn SqlHost>>,
    pub gate: Option<Arc<dyn EffectGate>>,
    pub describe_only: bool,
}

impl TurnHost {
    pub(crate) fn new(init: HostInit) -> TurnHost {
        let logs = Logs::default();
        // Empty environment, no args, no preopens, no network, empty stdin;
        // stdout/stderr become log events.
        let wasi = WasiCtxBuilder::new()
            .stdout(LogStdout {
                logs: logs.clone(),
                level: "info",
            })
            .stderr(LogStdout {
                logs: logs.clone(),
                level: "warn",
            })
            .build();
        let mut seed_rng = stream(init.seed, STREAM_WASI_INSECURE_SEED);
        let insecure_seed = (seed_rng.next_u64(), seed_rng.next_u64());
        TurnHost {
            wasi,
            table: ResourceTable::new(),
            limiter: MemoryLimiter {
                max_bytes: init.limits.memory_bytes,
                total_bytes: 0,
                peak_bytes: 0,
                hit: false,
            },
            logs,
            describe_only: init.describe_only,
            causal_id: causal::causal_id(&init.causal_key),
            actor: init.actor,
            causal_key: init.causal_key,
            now_ms: init.now_ms,
            rng_context: stream(init.seed, STREAM_CONTEXT),
            rng_wasi: stream(init.seed, STREAM_WASI_RANDOM),
            rng_insecure: stream(init.seed, STREAM_WASI_INSECURE),
            insecure_seed,
            limits: init.limits,
            state: init.state,
            sql: init.sql,
            subject: init.subject,
            writes: BTreeMap::new(),
            messages: Vec::new(),
            timers: Vec::new(),
            gate: init.gate,
            next_ordinal: 0,
            fatal: None,
        }
    }

    fn deny_in_describe(&self, what: &str) -> wasmtime::Result<()> {
        if self.describe_only {
            bail!("describe must not use {what}: it runs without state and without effects");
        }
        Ok(())
    }

    /// Records a host failure and traps the guest.
    fn host_failure(&mut self, msg: String) -> wasmtime::Error {
        let e = wasmtime::format_err!("host failure: {msg}");
        self.fatal = Some(msg);
        e
    }

    fn sql_failure(&mut self, e: SqlHostError) -> wasmtime::Error {
        match e {
            SqlHostError::FuelExhausted => wasmtime::Error::from(wasmtime::Trap::OutOfFuel),
            SqlHostError::Host(msg) => self.host_failure(msg),
        }
    }

    fn state_view(&self) -> wasmtime::Result<&Arc<dyn StateView>> {
        match &self.state {
            Some(s) => Ok(s),
            None => bail!("state is not available in this turn"),
        }
    }

    fn set_value(
        &mut self,
        subject: Option<String>,
        key: String,
        value: Vec<u8>,
    ) -> wasmtime::Result<()> {
        self.deny_in_describe("state")?;
        if value.len() > self.limits.state_value_bytes {
            bail!(
                "state value for {key:?} is {} bytes, the limit is {}",
                value.len(),
                self.limits.state_value_bytes
            );
        }
        self.writes.insert(key, Some((value, subject)));
        Ok(())
    }

    fn ordinal(&mut self) -> u32 {
        let o = self.next_ordinal;
        self.next_ordinal += 1;
        o
    }

    fn gate(&self, what: &str) -> wasmtime::Result<Arc<dyn EffectGate>> {
        match &self.gate {
            Some(g) => Ok(g.clone()),
            None => bail!("NOT_IMPLEMENTED: {what} is not available in this turn"),
        }
    }

    fn gate_failure(&mut self, e: GateError) -> wasmtime::Error {
        match e {
            GateError::Host(msg) => self.host_failure(msg),
            GateError::Diverged(msg) => wasmtime::format_err!("REPLAY_DIVERGED: {msg}"),
        }
    }

    fn check_message(&self, msg: &types::Message) -> wasmtime::Result<()> {
        if msg.body.len() > self.limits.message_bytes {
            bail!(
                "message {:?} is {} bytes, the limit is {}",
                msg.name,
                msg.body.len(),
                self.limits.message_bytes
            );
        }
        if !msg.blobs.is_empty() {
            bail!("NOT_IMPLEMENTED: blobs in messages arrive in a later version");
        }
        Ok(())
    }
}

impl WasiView for TurnHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl types::Host for TurnHost {}

impl state::Host for TurnHost {
    async fn get(&mut self, key: String) -> wasmtime::Result<Option<Vec<u8>>> {
        self.deny_in_describe("state")?;
        if let Some(w) = self.writes.get(&key) {
            return Ok(w.as_ref().map(|(v, _)| v.clone()));
        }
        let res = self.state_view()?.get(&key);
        res.map_err(|e| self.host_failure(e))
    }

    async fn set(&mut self, key: String, value: Vec<u8>) -> wasmtime::Result<()> {
        let subject = self.subject.clone();
        self.set_value(subject, key, value)
    }

    async fn set_for(
        &mut self,
        subject: Option<String>,
        key: String,
        value: Vec<u8>,
    ) -> wasmtime::Result<()> {
        self.set_value(subject, key, value)
    }

    async fn delete(&mut self, key: String) -> wasmtime::Result<()> {
        self.deny_in_describe("state")?;
        self.writes.insert(key, None);
        Ok(())
    }

    async fn keys(&mut self, prefix: String) -> wasmtime::Result<Vec<String>> {
        self.deny_in_describe("state")?;
        let base = self.state_view()?.keys(&prefix);
        let base = base.map_err(|e| self.host_failure(e))?;
        let mut merged: BTreeMap<String, bool> = base.into_iter().map(|k| (k, true)).collect();
        for (k, v) in self.writes.range(prefix.clone()..) {
            if !k.starts_with(&prefix) {
                break;
            }
            merged.insert(k.clone(), v.is_some());
        }
        Ok(merged
            .into_iter()
            .filter_map(|(k, live)| live.then_some(k))
            .collect())
    }
}

impl sql::Host for TurnHost {
    async fn query(
        &mut self,
        statement: String,
        params: Vec<SqlValue>,
    ) -> wasmtime::Result<Result<SqlRows, SqlError>> {
        self.deny_in_describe("sql")?;
        let subject = self.subject.clone();
        let Some(sql) = self.sql.as_mut() else {
            bail!("sql is not available in this turn");
        };
        let res = sql.query(&statement, params, subject.as_deref());
        res.map_err(|e| self.sql_failure(e))
    }

    async fn execute(
        &mut self,
        statement: String,
        params: Vec<SqlValue>,
    ) -> wasmtime::Result<Result<u64, SqlError>> {
        self.deny_in_describe("sql")?;
        let subject = self.subject.clone();
        let Some(sql) = self.sql.as_mut() else {
            bail!("sql is not available in this turn");
        };
        let res = sql.execute(&statement, params, subject.as_deref());
        res.map_err(|e| self.sql_failure(e))
    }
}

impl context::Host for TurnHost {
    async fn self_ref(&mut self) -> wasmtime::Result<types::ActorRef> {
        Ok(types::ActorRef {
            kind: self.actor.kind.clone(),
            key: self.actor.key.clone(),
        })
    }

    async fn causal_id(&mut self) -> wasmtime::Result<String> {
        Ok(self.causal_id.clone())
    }

    async fn now_ms(&mut self) -> wasmtime::Result<u64> {
        Ok(self.now_ms)
    }

    async fn random_bytes(&mut self, len: u32) -> wasmtime::Result<Vec<u8>> {
        random_vec(&mut self.rng_context, u64::from(len))
    }
}

/// Converts a guest message to the log form, tagging the body with `subject`.
pub(crate) fn message_to_pb(m: types::Message, subject: Option<String>) -> pb::Message {
    pb::Message {
        name: m.name,
        content_type: m.content_type,
        body: Some(pb::Sealable {
            subject,
            value: Some(pb::sealable::Value::Plain(m.body)),
        }),
        blobs: m
            .blobs
            .into_iter()
            .map(|b| pb::BlobRef {
                hash: b.hash,
                size: b.size,
            })
            .collect(),
    }
}

impl messaging::Host for TurnHost {
    async fn send(&mut self, to: types::ActorRef, msg: types::Message) -> wasmtime::Result<()> {
        self.deny_in_describe("messaging")?;
        let to = match ActorRef::new(to.kind, to.key) {
            Ok(a) => a,
            Err(e) => bail!("messaging.send: {e}"),
        };
        self.check_message(&msg)?;
        let ordinal = self.ordinal();
        self.messages.push(pb::OutboundMessage {
            to: Some(to.to_pb()),
            msg: Some(message_to_pb(msg, self.subject.clone())),
            ordinal,
            message_id: causal::message_id(&self.causal_key, ordinal),
        });
        Ok(())
    }

    async fn call(
        &mut self,
        to: types::ActorRef,
        msg: types::Message,
        compensate: Option<types::Message>,
    ) -> wasmtime::Result<Result<Option<types::Message>, messaging::CallError>> {
        self.deny_in_describe("messaging")?;
        let to = match ActorRef::new(to.kind, to.key) {
            Ok(a) => a,
            Err(e) => bail!("messaging.call: {e}"),
        };
        self.check_message(&msg)?;
        if let Some(c) = &compensate {
            self.check_message(c)?;
        }
        let gate = self.gate("messaging.call")?;
        let ordinal = self.ordinal();
        let subject = self.subject.clone();
        let msg = message_to_pb(msg, subject.clone());
        let compensate = compensate.map(|c| message_to_pb(c, subject));
        let res = gate.call(ordinal, to, msg, compensate).await;
        let out = res.map_err(|e| self.gate_failure(e))?;
        Ok(match out {
            CallOutcome::Ok(reply) => Ok(reply.map(|m| types::Message {
                name: m.name,
                content_type: m.content_type,
                body: match m.body.and_then(|b| b.value) {
                    Some(pb::sealable::Value::Plain(b)) => b,
                    _ => Vec::new(),
                },
                blobs: Vec::new(),
            })),
            CallOutcome::NotFound => Err(messaging::CallError::NotFound),
            CallOutcome::Rejected(m) => Err(messaging::CallError::Rejected(m)),
            CallOutcome::Failed(m) => Err(messaging::CallError::Failed(m)),
            CallOutcome::Reentrant => Err(messaging::CallError::Reentrant),
            CallOutcome::Timeout => Err(messaging::CallError::Timeout),
        })
    }
}

impl timers::Host for TurnHost {
    async fn schedule(&mut self, delay_ms: u64, msg: types::Message) -> wasmtime::Result<u64> {
        self.deny_in_describe("timers")?;
        self.check_message(&msg)?;
        let ordinal = self.ordinal();
        let id = timer_id(&self.causal_key, ordinal);
        self.timers.push(pb::TimerOp {
            kind: pb::TimerOpKind::Schedule as i32,
            timer_id: id,
            due_ms: self.now_ms.saturating_add(delay_ms),
            msg: Some(message_to_pb(msg, self.subject.clone())),
            ordinal,
        });
        Ok(id)
    }

    async fn cancel(&mut self, id: u64) -> wasmtime::Result<bool> {
        self.deny_in_describe("timers")?;
        // The last operation on this id in the turn decides; otherwise the
        // committed state.
        let pending = match self.timers.iter().rev().find(|t| t.timer_id == id) {
            Some(t) => t.kind == pb::TimerOpKind::Schedule as i32,
            None => {
                let res = self.state_view()?.timer_pending(id);
                res.map_err(|e| self.host_failure(e))?
            }
        };
        if pending {
            self.timers.push(pb::TimerOp {
                kind: pb::TimerOpKind::Cancel as i32,
                timer_id: id,
                due_ms: 0,
                msg: None,
                ordinal: 0,
            });
        }
        Ok(pending)
    }
}

impl http_client::Host for TurnHost {
    async fn fetch(
        &mut self,
        req: http_client::Request,
    ) -> wasmtime::Result<Result<http_client::Response, http_client::FetchError>> {
        self.deny_in_describe("http-client")?;
        let body = match req.body {
            types::HttpBody::Inline(b) => b,
            types::HttpBody::Blob(_) => {
                bail!("NOT_IMPLEMENTED: blob bodies arrive in a later version")
            }
        };
        if body.len() > self.limits.message_bytes {
            bail!(
                "request body is {} bytes, the limit is {}",
                body.len(),
                self.limits.message_bytes
            );
        }
        let headers = req
            .headers
            .into_iter()
            .map(|h| {
                let v = match h.value {
                    http_client::HeaderValue::Text(t) => FetchHeader::Text(t),
                    http_client::HeaderValue::Secret(s) => FetchHeader::Secret {
                        name: s.name,
                        template: s.template,
                    },
                };
                (h.name, v)
            })
            .collect();
        let gate = self.gate("http-client.fetch")?;
        let ordinal = self.ordinal();
        let res = gate
            .fetch(
                ordinal,
                FetchRequest {
                    method: req.method,
                    url: req.url,
                    headers,
                    body,
                    subject: self.subject.clone(),
                },
            )
            .await;
        Ok(match res.map_err(|e| self.gate_failure(e))? {
            FetchOutcome::Ok(r) => Ok(http_client::Response {
                status: r.status,
                headers: r.headers,
                body: types::HttpBody::Inline(r.body),
            }),
            FetchOutcome::Denied(m) => Err(http_client::FetchError::Denied(m)),
            FetchOutcome::Network(m) => Err(http_client::FetchError::Network(m)),
            FetchOutcome::Timeout => Err(http_client::FetchError::Timeout),
            FetchOutcome::TooLarge => Err(http_client::FetchError::TooLarge),
            FetchOutcome::OutcomeUnknown => Err(http_client::FetchError::OutcomeUnknown),
        })
    }
}

impl TurnHost {
    async fn crypto(
        &mut self,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, crypto::CryptoError>> {
        self.deny_in_describe("crypto")?;
        let gate = self.gate("crypto")?;
        let ordinal = self.ordinal();
        let res = gate.crypto(ordinal, algorithm, secret, data).await;
        Ok(match res.map_err(|e| self.gate_failure(e))? {
            CryptoOutcome::Ok(v) => Ok(v),
            CryptoOutcome::Denied(m) => Err(crypto::CryptoError::Denied(m)),
            CryptoOutcome::Unsupported(m) => Err(crypto::CryptoError::Unsupported(m)),
        })
    }
}

impl crypto::Host for TurnHost {
    async fn hmac_sha256(
        &mut self,
        secret: String,
        data: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, crypto::CryptoError>> {
        self.crypto(CryptoAlgorithm::HmacSha256, secret, data).await
    }

    async fn sign_ed25519(
        &mut self,
        secret: String,
        data: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, crypto::CryptoError>> {
        self.crypto(CryptoAlgorithm::SignEd25519, secret, data)
            .await
    }
}

impl secrets::Host for TurnHost {
    async fn reveal(&mut self, name: String) -> wasmtime::Result<Result<String, String>> {
        self.deny_in_describe("secrets")?;
        let gate = self.gate("secrets.reveal")?;
        let ordinal = self.ordinal();
        let res = gate.reveal(ordinal, name).await;
        res.map_err(|e| self.gate_failure(e))
    }
}

impl log::Host for TurnHost {
    async fn emit(
        &mut self,
        lvl: log::Level,
        message: String,
        fields: Vec<(String, String)>,
    ) -> wasmtime::Result<()> {
        let level = match lvl {
            log::Level::Trace => "trace",
            log::Level::Debug => "debug",
            log::Level::Info => "info",
            log::Level::Warn => "warn",
            log::Level::Error => "error",
        };
        self.logs.push(LogEvent {
            level,
            message,
            fields,
        });
        Ok(())
    }
}

impl privacy::Host for TurnHost {
    async fn set_subject(&mut self, subject: Option<String>) -> wasmtime::Result<()> {
        self.deny_in_describe("privacy")?;
        self.subject = subject;
        Ok(())
    }

    async fn current_subject(&mut self) -> wasmtime::Result<Option<String>> {
        Ok(self.subject.clone())
    }
}

// Deterministic WASI: clocks and random are implemented here; cli and io come
// from wasmtime-wasi with an empty environment and stdio as log events.

/// `HasData` projection for the WASI clock/random `add_to_linker` functions.
pub(crate) struct DetWasi;

impl HasData for DetWasi {
    type Data<'a> = &'a mut TurnHost;
}

/// `HasData` projection for `wasi:io` (resource table only).
pub(crate) struct HasIo;

impl HasData for HasIo {
    type Data<'a> = &'a mut ResourceTable;
}

/// Always ready: logical time is constant within a turn, so a guest sleep
/// resolves immediately instead of waiting on the host clock.
struct ReadyNow;

#[wasmtime_wasi::async_trait]
impl Pollable for ReadyNow {
    async fn ready(&mut self) {}
}

fn ready_pollable(table: &mut ResourceTable) -> wasmtime::Result<Resource<DynPollable>> {
    let r = table.push(ReadyNow)?;
    wasmtime_wasi::p2::subscribe(table, r)
}

impl wall_clock::Host for &mut TurnHost {
    fn now(&mut self) -> wasmtime::Result<wall_clock::Datetime> {
        Ok(wall_clock::Datetime {
            seconds: self.now_ms / 1000,
            nanoseconds: ((self.now_ms % 1000) * 1_000_000) as u32,
        })
    }

    fn resolution(&mut self) -> wasmtime::Result<wall_clock::Datetime> {
        Ok(wall_clock::Datetime {
            seconds: 0,
            nanoseconds: 1_000_000,
        })
    }
}

impl monotonic_clock::Host for &mut TurnHost {
    fn now(&mut self) -> wasmtime::Result<monotonic_clock::Instant> {
        Ok(self.now_ms.saturating_mul(1_000_000))
    }

    fn resolution(&mut self) -> wasmtime::Result<monotonic_clock::Duration> {
        Ok(1_000_000)
    }

    fn subscribe_instant(
        &mut self,
        _when: monotonic_clock::Instant,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        ready_pollable(&mut self.table)
    }

    fn subscribe_duration(
        &mut self,
        _duration: monotonic_clock::Duration,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        ready_pollable(&mut self.table)
    }
}

fn random_vec(rng: &mut ChaCha20Rng, len: u64) -> wasmtime::Result<Vec<u8>> {
    if len > MAX_RANDOM_BYTES {
        bail!("random request of {len} bytes exceeds the {MAX_RANDOM_BYTES} byte limit");
    }
    let mut buf = vec![0u8; len as usize];
    rng.fill_bytes(&mut buf);
    Ok(buf)
}

impl random::Host for &mut TurnHost {
    fn get_random_bytes(&mut self, len: u64) -> wasmtime::Result<Vec<u8>> {
        random_vec(&mut self.rng_wasi, len)
    }

    fn get_random_u64(&mut self) -> wasmtime::Result<u64> {
        Ok(self.rng_wasi.next_u64())
    }
}

impl insecure::Host for &mut TurnHost {
    fn get_insecure_random_bytes(&mut self, len: u64) -> wasmtime::Result<Vec<u8>> {
        random_vec(&mut self.rng_insecure, len)
    }

    fn get_insecure_random_u64(&mut self) -> wasmtime::Result<u64> {
        Ok(self.rng_insecure.next_u64())
    }
}

impl insecure_seed::Host for &mut TurnHost {
    fn insecure_seed(&mut self) -> wasmtime::Result<(u64, u64)> {
        Ok(self.insecure_seed)
    }
}

/// stdout/stderr: every write becomes a log event.
struct LogStdout {
    logs: Logs,
    level: &'static str,
}

impl IsTerminal for LogStdout {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for LogStdout {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(LogOutput {
            logs: self.logs.clone(),
            level: self.level,
        })
    }

    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        // Only used by WASIp3 bindings, which are never linked.
        Box::new(tokio::io::sink())
    }
}

struct LogOutput {
    logs: Logs,
    level: &'static str,
}

#[wasmtime_wasi::async_trait]
impl Pollable for LogOutput {
    async fn ready(&mut self) {}
}

impl OutputStream for LogOutput {
    fn write(&mut self, bytes: bytes::Bytes) -> StreamResult<()> {
        self.logs.push(LogEvent {
            level: self.level,
            message: String::from_utf8_lossy(&bytes).into_owned(),
            fields: Vec::new(),
        });
        Ok(())
    }

    fn flush(&mut self) -> StreamResult<()> {
        Ok(())
    }

    fn check_write(&mut self) -> StreamResult<usize> {
        Ok(64 * 1024)
    }
}

/// The linker with exactly the allowlisted interfaces. No filesystem, sockets
/// or http are linked, so even a component that bypassed the deploy check
/// could not instantiate.
pub(crate) fn build_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<TurnHost>> {
    use wasmtime::component::HasSelf;
    use wasmtime_wasi::cli::{WasiCli, WasiCliView};
    use wasmtime_wasi::p2::bindings::cli;

    let mut l = wasmtime::component::Linker::<TurnHost>::new(engine);
    bindings::Actor::add_to_linker::<TurnHost, HasSelf<TurnHost>>(&mut l, |s| s)?;
    wasmtime_wasi_io::bindings::wasi::io::error::add_to_linker::<TurnHost, HasIo>(&mut l, |s| {
        &mut s.table
    })?;
    wasmtime_wasi_io::bindings::wasi::io::poll::add_to_linker::<TurnHost, HasIo>(&mut l, |s| {
        &mut s.table
    })?;
    wasmtime_wasi_io::bindings::wasi::io::streams::add_to_linker::<TurnHost, HasIo>(&mut l, |s| {
        &mut s.table
    })?;
    wall_clock::add_to_linker::<TurnHost, DetWasi>(&mut l, |s| s)?;
    monotonic_clock::add_to_linker::<TurnHost, DetWasi>(&mut l, |s| s)?;
    random::add_to_linker::<TurnHost, DetWasi>(&mut l, |s| s)?;
    insecure::add_to_linker::<TurnHost, DetWasi>(&mut l, |s| s)?;
    insecure_seed::add_to_linker::<TurnHost, DetWasi>(&mut l, |s| s)?;
    cli::exit::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    cli::environment::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    cli::stdin::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    cli::stdout::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    cli::stderr::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    cli::terminal_input::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    cli::terminal_output::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    cli::terminal_stdin::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    cli::terminal_stdout::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    cli::terminal_stderr::add_to_linker::<TurnHost, WasiCli>(&mut l, TurnHost::cli)?;
    Ok(l)
}
