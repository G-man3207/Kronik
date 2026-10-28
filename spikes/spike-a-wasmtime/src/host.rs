//! Host side of the `kronik:actor` world plus the deterministic WASI subset.
//!
//! Every host call is appended to an ordered trace. Two turns with the same
//! code, engine version, input, seed, logical time and starting state must
//! produce byte-identical traces (I1).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chacha20::ChaCha20Rng;
use chacha20::rand_core::{Rng, SeedableRng};
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

/// Maximum size of a state value or message body (brief: 1 MiB).
pub const MAX_VALUE_BYTES: usize = 1 << 20;
/// Maximum nesting of `messaging.call` in the harness (cycle detection proper is M2).
pub const MAX_CALL_DEPTH: u32 = 4;
/// Maximum bytes per random request; larger requests trap.
pub const MAX_RANDOM_BYTES: u64 = 1 << 20;

/// ChaCha20 stream ids: one seed, domain-separated streams per source, so
/// that e.g. a language runtime seeding its hash maps from `wasi:random` does
/// not shift the bytes the actor gets from `context.random-bytes`.
const STREAM_CONTEXT: u64 = 0;
const STREAM_WASI_RANDOM: u64 = 1;
const STREAM_WASI_INSECURE: u64 = 2;
const STREAM_WASI_INSECURE_SEED: u64 = 3;

/// Ordered host-call trace, shared with the WASI stdout/stderr streams.
#[derive(Clone, Default)]
pub struct Trace(Arc<Mutex<Vec<String>>>);

impl Trace {
    pub fn push(&self, line: String) {
        if let Ok(mut v) = self.0.lock() {
            v.push(line);
        }
    }
    pub fn take(&self) -> Vec<String> {
        self.0
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    }
}

/// Short, deterministic rendering of byte payloads in the trace.
pub fn fmt_bytes(b: &[u8]) -> String {
    if b.len() <= 32 {
        match std::str::from_utf8(b) {
            Ok(s) if s.chars().all(|c| !c.is_control()) => format!("{s:?}"),
            _ => format!("0x{}", hex(b)),
        }
    } else {
        format!("<{} bytes b3:{}>", b.len(), &blake3::hash(b).to_hex()[..12])
    }
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

/// Memory limiter: the total linear memory of all memories in the instance is
/// capped. A refused growth makes `memory.grow` return -1 (spec behaviour, the
/// guest may recover deterministically); the flag lets the host classify a
/// subsequent trap as a memory-limit failure.
pub struct MemoryLimiter {
    pub max_bytes: usize,
    pub total_bytes: usize,
    pub peak_bytes: usize,
    pub hit: bool,
}

impl MemoryLimiter {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            total_bytes: 0,
            peak_bytes: 0,
            hit: false,
        }
    }
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

/// Inputs that fully determine a turn, besides code and engine version.
#[derive(Clone)]
pub struct TurnSpec {
    pub kind: String,
    pub key: String,
    pub causal_id: String,
    pub logical_time_ms: u64,
    pub seed: [u8; 32],
    pub state: BTreeMap<String, Vec<u8>>,
    pub fuel: u64,
    pub memory_bytes: usize,
}

/// Per-turn store data. A new one is built for every turn, together with a
/// fresh instance.
pub struct TurnCtx {
    wasi: WasiCtx,
    table: ResourceTable,
    pub limiter: MemoryLimiter,
    pub trace: Trace,
    /// `describe` runs without state and without effects.
    describe_only: bool,
    kind: String,
    key: String,
    causal_id: String,
    now_ms: u64,
    rng_context: ChaCha20Rng,
    rng_wasi: ChaCha20Rng,
    rng_insecure: ChaCha20Rng,
    insecure_seed: (u64, u64),
    state_base: BTreeMap<String, Vec<u8>>,
    /// Buffered writes: `None` is a delete. Committed only if the turn commits.
    pub writes: BTreeMap<String, Option<Vec<u8>>>,
    next_timer_id: u64,
    /// Used by `messaging.call` to run the callee's turn before returning.
    runner: Option<Arc<crate::turn::Runner>>,
    depth: u32,
    call_ordinal: u32,
    seed: [u8; 32],
    fuel: u64,
    memory_bytes: usize,
}

fn stream(seed: [u8; 32], id: u64) -> ChaCha20Rng {
    let mut rng = ChaCha20Rng::from_seed(seed);
    rng.set_stream(id);
    rng
}

impl TurnCtx {
    pub fn new(
        spec: &TurnSpec,
        describe_only: bool,
        runner: Option<Arc<crate::turn::Runner>>,
        depth: u32,
    ) -> Self {
        let trace = Trace::default();
        // Empty environment, no args, no preopens, no network; stdin empty;
        // stdout/stderr are captured into the trace as log events.
        let wasi = WasiCtxBuilder::new()
            .stdout(TraceStdout {
                trace: trace.clone(),
                name: "stdout",
            })
            .stderr(TraceStdout {
                trace: trace.clone(),
                name: "stderr",
            })
            .build();
        let mut seed_rng = stream(spec.seed, STREAM_WASI_INSECURE_SEED);
        let insecure_seed = (seed_rng.next_u64(), seed_rng.next_u64());
        Self {
            wasi,
            table: ResourceTable::new(),
            limiter: MemoryLimiter::new(spec.memory_bytes),
            trace,
            describe_only,
            kind: spec.kind.clone(),
            key: spec.key.clone(),
            causal_id: spec.causal_id.clone(),
            now_ms: spec.logical_time_ms,
            rng_context: stream(spec.seed, STREAM_CONTEXT),
            rng_wasi: stream(spec.seed, STREAM_WASI_RANDOM),
            rng_insecure: stream(spec.seed, STREAM_WASI_INSECURE),
            insecure_seed,
            state_base: if describe_only {
                BTreeMap::new()
            } else {
                spec.state.clone()
            },
            writes: BTreeMap::new(),
            next_timer_id: 1,
            runner,
            depth,
            call_ordinal: 0,
            seed: spec.seed,
            fuel: spec.fuel,
            memory_bytes: spec.memory_bytes,
        }
    }

    fn deny_in_describe(&self, what: &str) -> wasmtime::Result<()> {
        if self.describe_only {
            bail!("describe must not use {what}: it runs without state and without effects");
        }
        Ok(())
    }

    fn read(&self, key: &str) -> Option<Vec<u8>> {
        match self.writes.get(key) {
            Some(v) => v.clone(),
            None => self.state_base.get(key).cloned(),
        }
    }

    fn t(&self, line: String) {
        self.trace.push(line);
    }
}

impl WasiView for TurnCtx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

// ---------------------------------------------------------------------------
// kronik:actor imports
// ---------------------------------------------------------------------------

impl types::Host for TurnCtx {}

impl state::Host for TurnCtx {
    async fn get(&mut self, key: String) -> wasmtime::Result<Option<Vec<u8>>> {
        self.deny_in_describe("state")?;
        let v = self.read(&key);
        self.t(format!(
            "state.get({key:?}) -> {}",
            v.as_deref().map_or("none".into(), fmt_bytes)
        ));
        Ok(v)
    }

    async fn set(&mut self, key: String, value: Vec<u8>) -> wasmtime::Result<()> {
        self.deny_in_describe("state")?;
        if value.len() > MAX_VALUE_BYTES {
            bail!(
                "state value for {key:?} is {} bytes, limit is {MAX_VALUE_BYTES}",
                value.len()
            );
        }
        self.t(format!("state.set({key:?}, {})", fmt_bytes(&value)));
        self.writes.insert(key, Some(value));
        Ok(())
    }

    async fn delete(&mut self, key: String) -> wasmtime::Result<()> {
        self.deny_in_describe("state")?;
        self.t(format!("state.delete({key:?})"));
        self.writes.insert(key, None);
        Ok(())
    }

    async fn keys(&mut self, prefix: String) -> wasmtime::Result<Vec<String>> {
        self.deny_in_describe("state")?;
        let mut merged: BTreeMap<&String, bool> = BTreeMap::new();
        for k in self.state_base.keys().filter(|k| k.starts_with(&prefix)) {
            merged.insert(k, true);
        }
        for (k, v) in self.writes.iter().filter(|(k, _)| k.starts_with(&prefix)) {
            merged.insert(k, v.is_some());
        }
        let keys: Vec<String> = merged
            .into_iter()
            .filter(|(_, live)| *live)
            .map(|(k, _)| k.clone())
            .collect();
        self.t(format!("state.keys({prefix:?}) -> {keys:?}"));
        Ok(keys)
    }
}

impl sql::Host for TurnCtx {
    async fn query(
        &mut self,
        statement: String,
        _params: Vec<sql::SqlValue>,
    ) -> wasmtime::Result<Result<sql::Rows, sql::SqlError>> {
        self.deny_in_describe("sql")?;
        self.t(format!("sql.query({statement:?}) -> denied"));
        Ok(Err(sql::SqlError::Denied(
            "sql state is not available in spike A".into(),
        )))
    }

    async fn execute(
        &mut self,
        statement: String,
        _params: Vec<sql::SqlValue>,
    ) -> wasmtime::Result<Result<u64, sql::SqlError>> {
        self.deny_in_describe("sql")?;
        self.t(format!("sql.execute({statement:?}) -> denied"));
        Ok(Err(sql::SqlError::Denied(
            "sql state is not available in spike A".into(),
        )))
    }
}

impl context::Host for TurnCtx {
    async fn self_ref(&mut self) -> wasmtime::Result<types::ActorRef> {
        self.t(format!("context.self-ref() -> {}/{}", self.kind, self.key));
        Ok(types::ActorRef {
            kind: self.kind.clone(),
            key: self.key.clone(),
        })
    }

    async fn causal_id(&mut self) -> wasmtime::Result<String> {
        self.t(format!("context.causal-id() -> {:?}", self.causal_id));
        Ok(self.causal_id.clone())
    }

    async fn now_ms(&mut self) -> wasmtime::Result<u64> {
        self.t(format!("context.now-ms() -> {}", self.now_ms));
        Ok(self.now_ms)
    }

    async fn random_bytes(&mut self, len: u32) -> wasmtime::Result<Vec<u8>> {
        if u64::from(len) > MAX_RANDOM_BYTES {
            bail!("random-bytes({len}) exceeds the {MAX_RANDOM_BYTES} byte limit");
        }
        let mut buf = vec![0u8; len as usize];
        self.rng_context.fill_bytes(&mut buf);
        self.t(format!(
            "context.random-bytes({len}) -> {}",
            fmt_bytes(&buf)
        ));
        Ok(buf)
    }
}

impl messaging::Host for TurnCtx {
    async fn send(&mut self, to: types::ActorRef, msg: types::Message) -> wasmtime::Result<()> {
        self.deny_in_describe("messaging")?;
        if msg.body.len() > MAX_VALUE_BYTES {
            bail!(
                "message body is {} bytes, limit is {MAX_VALUE_BYTES}",
                msg.body.len()
            );
        }
        self.t(format!(
            "messaging.send({}/{}, {:?}, {}) buffered",
            to.kind,
            to.key,
            msg.name,
            fmt_bytes(&msg.body)
        ));
        Ok(())
    }

    async fn call(
        &mut self,
        to: types::ActorRef,
        msg: types::Message,
        _compensate: Option<types::Message>,
    ) -> wasmtime::Result<Result<Option<types::Message>, messaging::CallError>> {
        self.deny_in_describe("messaging")?;
        let ordinal = self.call_ordinal;
        self.call_ordinal += 1;
        let target = format!("{}/{}", to.kind, to.key);
        // The harness hosts a single actor kind: calls to other kinds are not-found.
        let Some(runner) = self.runner.clone().filter(|_| to.kind == self.kind) else {
            self.t(format!(
                "messaging.call({target}, {:?}) -> not-found",
                msg.name
            ));
            return Ok(Err(messaging::CallError::NotFound));
        };
        if to.key == self.key || self.depth >= MAX_CALL_DEPTH {
            self.t(format!(
                "messaging.call({target}, {:?}) -> reentrant",
                msg.name
            ));
            return Ok(Err(messaging::CallError::Reentrant));
        }
        // The callee runs and finishes its own turn, on its own fresh instance,
        // before `call` returns. Its seed and causal id are derived from the
        // caller's, so the whole call tree is deterministic.
        let mut h = blake3::Hasher::new();
        h.update(b"kronik-spike-a/call-seed");
        h.update(&self.seed);
        h.update(&ordinal.to_le_bytes());
        let spec = TurnSpec {
            kind: to.kind.clone(),
            key: to.key.clone(),
            causal_id: format!("{}/{target}#{ordinal}", self.causal_id),
            logical_time_ms: self.now_ms,
            seed: *h.finalize().as_bytes(),
            state: BTreeMap::new(),
            fuel: self.fuel,
            memory_bytes: self.memory_bytes,
        };
        let name = msg.name.clone();
        let input = types::Input::Message(types::Incoming {
            sender: Some(types::ActorRef {
                kind: self.kind.clone(),
                key: self.key.clone(),
            }),
            msg,
        });
        let result = Box::pin(runner.handle_at_depth(&spec, &input, self.depth + 1)).await?;
        self.t(format!(
            "messaging.call({target}, {name:?}) begin, callee turn {}",
            spec.causal_id
        ));
        for line in &result.trace {
            self.t(format!("  | {line}"));
        }
        let reply = match (&result.output, &result.outcome) {
            (Some(types::Output::Reply(m)), _) => Ok(Some(m.clone())),
            (Some(_), _) => Ok(None),
            (None, crate::turn::Outcome::HandlerError(m)) if m.starts_with("rejected") => {
                Err(messaging::CallError::Rejected(m.clone()))
            }
            (None, other) => Err(messaging::CallError::Failed(other.code().to_string())),
        };
        self.t(format!(
            "messaging.call({target}, {name:?}) -> {}",
            match &reply {
                Ok(Some(m)) => format!("reply {:?} {}", m.name, fmt_bytes(&m.body)),
                Ok(None) => "none".to_string(),
                Err(e) => format!("{e:?}"),
            }
        ));
        Ok(reply)
    }
}

impl timers::Host for TurnCtx {
    async fn schedule(&mut self, delay_ms: u64, msg: types::Message) -> wasmtime::Result<u64> {
        self.deny_in_describe("timers")?;
        let id = self.next_timer_id;
        self.next_timer_id += 1;
        self.t(format!(
            "timers.schedule({delay_ms}, {:?}) -> {id} buffered",
            msg.name
        ));
        Ok(id)
    }

    async fn cancel(&mut self, id: u64) -> wasmtime::Result<bool> {
        self.deny_in_describe("timers")?;
        self.t(format!("timers.cancel({id}) -> false"));
        Ok(false)
    }
}

impl http_client::Host for TurnCtx {
    async fn fetch(
        &mut self,
        req: http_client::Request,
    ) -> wasmtime::Result<Result<http_client::Response, http_client::FetchError>> {
        self.deny_in_describe("http-client")?;
        let host = req
            .url
            .split_once("://")
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(""))
            .unwrap_or("")
            .to_string();
        self.t(format!(
            "http-client.fetch({} {}) -> denied",
            req.method, req.url
        ));
        Ok(Err(http_client::FetchError::Denied(format!(
            "CAPABILITY_NOT_GRANTED: http:{host}"
        ))))
    }
}

impl crypto::Host for TurnCtx {
    async fn hmac_sha256(
        &mut self,
        secret: String,
        data: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, crypto::CryptoError>> {
        self.deny_in_describe("crypto")?;
        self.t(format!(
            "crypto.hmac-sha256({secret:?}, {}) -> denied",
            fmt_bytes(&data)
        ));
        Ok(Err(crypto::CryptoError::Denied(format!(
            "CAPABILITY_NOT_GRANTED: secret:{secret}"
        ))))
    }

    async fn sign_ed25519(
        &mut self,
        secret: String,
        data: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, crypto::CryptoError>> {
        self.deny_in_describe("crypto")?;
        self.t(format!(
            "crypto.sign-ed25519({secret:?}, {}) -> denied",
            fmt_bytes(&data)
        ));
        Ok(Err(crypto::CryptoError::Denied(format!(
            "CAPABILITY_NOT_GRANTED: secret:{secret}"
        ))))
    }
}

impl secrets::Host for TurnCtx {
    async fn reveal(&mut self, name: String) -> wasmtime::Result<Result<String, String>> {
        self.deny_in_describe("secrets")?;
        self.t(format!("secrets.reveal({name:?}) -> denied"));
        Ok(Err(format!("CAPABILITY_NOT_GRANTED: secret-reveal:{name}")))
    }
}

impl log::Host for TurnCtx {
    async fn emit(
        &mut self,
        lvl: log::Level,
        message: String,
        fields: Vec<(String, String)>,
    ) -> wasmtime::Result<()> {
        self.t(format!("log.emit({lvl:?}, {message:?}, {fields:?})"));
        Ok(())
    }
}

impl privacy::Host for TurnCtx {
    async fn set_subject(&mut self, subject: Option<String>) -> wasmtime::Result<()> {
        self.t(format!("privacy.set-subject({subject:?})"));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deterministic WASI: clocks and random are implemented here (not by
// wasmtime-wasi's real-clock/OS-entropy defaults); cli and io come from
// wasmtime-wasi configured with an empty environment and traced stdio.
// ---------------------------------------------------------------------------

/// `HasData` projection used to plug `TurnCtx` into the generated WASI
/// clock/random `add_to_linker` functions.
pub struct DetWasi;

impl HasData for DetWasi {
    type Data<'a> = &'a mut TurnCtx;
}

/// `HasData` projection for `wasi:io` (resource table only).
pub struct HasIo;

impl HasData for HasIo {
    type Data<'a> = &'a mut ResourceTable;
}

/// A pollable that is always ready. Logical time is constant within a turn,
/// so a guest sleep/timeout resolves immediately instead of blocking on the
/// host's real clock.
struct ReadyNow;

#[wasmtime_wasi::async_trait]
impl Pollable for ReadyNow {
    async fn ready(&mut self) {}
}

fn ready_pollable(table: &mut ResourceTable) -> wasmtime::Result<Resource<DynPollable>> {
    let r = table.push(ReadyNow)?;
    wasmtime_wasi::p2::subscribe(table, r)
}

impl wall_clock::Host for &mut TurnCtx {
    fn now(&mut self) -> wasmtime::Result<wall_clock::Datetime> {
        self.t(format!("wasi:clocks/wall-clock.now() -> {}ms", self.now_ms));
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

impl monotonic_clock::Host for &mut TurnCtx {
    fn now(&mut self) -> wasmtime::Result<monotonic_clock::Instant> {
        let ns = self.now_ms.saturating_mul(1_000_000);
        self.t(format!("wasi:clocks/monotonic-clock.now() -> {ns}ns"));
        Ok(ns)
    }

    fn resolution(&mut self) -> wasmtime::Result<monotonic_clock::Duration> {
        Ok(1_000_000)
    }

    fn subscribe_instant(
        &mut self,
        when: monotonic_clock::Instant,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        self.t(format!(
            "wasi:clocks/monotonic-clock.subscribe-instant({when}) -> ready"
        ));
        ready_pollable(&mut self.table)
    }

    fn subscribe_duration(
        &mut self,
        duration: monotonic_clock::Duration,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        self.t(format!(
            "wasi:clocks/monotonic-clock.subscribe-duration({duration}) -> ready"
        ));
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

impl random::Host for &mut TurnCtx {
    fn get_random_bytes(&mut self, len: u64) -> wasmtime::Result<Vec<u8>> {
        let buf = random_vec(&mut self.rng_wasi, len)?;
        self.t(format!(
            "wasi:random/random.get-random-bytes({len}) -> {}",
            fmt_bytes(&buf)
        ));
        Ok(buf)
    }

    fn get_random_u64(&mut self) -> wasmtime::Result<u64> {
        let v = self.rng_wasi.next_u64();
        self.t(format!("wasi:random/random.get-random-u64() -> {v}"));
        Ok(v)
    }
}

impl insecure::Host for &mut TurnCtx {
    fn get_insecure_random_bytes(&mut self, len: u64) -> wasmtime::Result<Vec<u8>> {
        let buf = random_vec(&mut self.rng_insecure, len)?;
        self.t(format!(
            "wasi:random/insecure.get-insecure-random-bytes({len}) -> {}",
            fmt_bytes(&buf)
        ));
        Ok(buf)
    }

    fn get_insecure_random_u64(&mut self) -> wasmtime::Result<u64> {
        let v = self.rng_insecure.next_u64();
        self.t(format!(
            "wasi:random/insecure.get-insecure-random-u64() -> {v}"
        ));
        Ok(v)
    }
}

impl insecure_seed::Host for &mut TurnCtx {
    fn insecure_seed(&mut self) -> wasmtime::Result<(u64, u64)> {
        let s = self.insecure_seed;
        self.t(format!(
            "wasi:random/insecure-seed.insecure-seed() -> ({}, {})",
            s.0, s.1
        ));
        Ok(s)
    }
}

/// stdout/stderr sink that turns every write into a trace (log) event.
struct TraceStdout {
    trace: Trace,
    name: &'static str,
}

impl IsTerminal for TraceStdout {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for TraceStdout {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(TraceOutput {
            trace: self.trace.clone(),
            name: self.name,
        })
    }

    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        // Only used by WASIp3 bindings, which are not linked.
        Box::new(tokio::io::sink())
    }
}

struct TraceOutput {
    trace: Trace,
    name: &'static str,
}

#[wasmtime_wasi::async_trait]
impl Pollable for TraceOutput {
    async fn ready(&mut self) {}
}

impl OutputStream for TraceOutput {
    fn write(&mut self, bytes: bytes::Bytes) -> StreamResult<()> {
        self.trace.push(format!(
            "wasi:cli/{}.write({:?})",
            self.name,
            String::from_utf8_lossy(&bytes)
        ));
        Ok(())
    }

    fn flush(&mut self) -> StreamResult<()> {
        Ok(())
    }

    fn check_write(&mut self) -> StreamResult<usize> {
        Ok(64 * 1024)
    }
}

/// Builds the linker with exactly the allowlisted interfaces: all of
/// `kronik:actor`, deterministic `wasi:clocks` and `wasi:random`, `wasi:cli`
/// and `wasi:io`. No filesystem, sockets or http are ever linked, so even a
/// component that bypassed the deploy check could not instantiate.
pub fn build_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<TurnCtx>> {
    use wasmtime::component::HasSelf;
    use wasmtime_wasi::cli::{WasiCli, WasiCliView};
    use wasmtime_wasi::p2::bindings::cli;

    let mut l = wasmtime::component::Linker::<TurnCtx>::new(engine);
    bindings::Actor::add_to_linker::<TurnCtx, HasSelf<TurnCtx>>(&mut l, |s| s)?;

    wasmtime_wasi_io::bindings::wasi::io::error::add_to_linker::<TurnCtx, HasIo>(&mut l, |s| {
        &mut s.table
    })?;
    wasmtime_wasi_io::bindings::wasi::io::poll::add_to_linker::<TurnCtx, HasIo>(&mut l, |s| {
        &mut s.table
    })?;
    wasmtime_wasi_io::bindings::wasi::io::streams::add_to_linker::<TurnCtx, HasIo>(&mut l, |s| {
        &mut s.table
    })?;

    wall_clock::add_to_linker::<TurnCtx, DetWasi>(&mut l, |s| s)?;
    monotonic_clock::add_to_linker::<TurnCtx, DetWasi>(&mut l, |s| s)?;
    random::add_to_linker::<TurnCtx, DetWasi>(&mut l, |s| s)?;
    insecure::add_to_linker::<TurnCtx, DetWasi>(&mut l, |s| s)?;
    insecure_seed::add_to_linker::<TurnCtx, DetWasi>(&mut l, |s| s)?;

    cli::exit::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    cli::environment::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    cli::stdin::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    cli::stdout::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    cli::stderr::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    cli::terminal_input::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    cli::terminal_output::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    cli::terminal_stdin::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    cli::terminal_stdout::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    cli::terminal_stderr::add_to_linker::<TurnCtx, WasiCli>(&mut l, TurnCtx::cli)?;
    Ok(l)
}
