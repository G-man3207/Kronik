//! Turn execution on a fresh Wasm instance, following ADR 0001: async host
//! functions, fuel with cooperative yields, deterministic WASI. Trimmed to
//! what the spike's guest uses; unused `kronik:actor` imports trap.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use chacha20::ChaCha20Rng;
use chacha20::rand_core::{Rng, SeedableRng};
use wasmtime::component::{Component, HasData, HasSelf, Resource, ResourceTable};
use wasmtime::{
    Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Store, Trap, bail,
};
use wasmtime_wasi::cli::{IsTerminal, StdoutStream, WasiCli, WasiCliView};
use wasmtime_wasi::p2::bindings::clocks::{monotonic_clock, wall_clock};
use wasmtime_wasi::p2::bindings::random::{insecure, insecure_seed, random};
use wasmtime_wasi::p2::{DynPollable, OutputStream, Pollable, StreamResult};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::daemon::log::{EffectOutcome, Outcome};
use crate::env::{BoxFuture, HttpRequest};

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

pub const FUEL_PER_TURN: u64 = 50_000_000;
/// Small in the spike so that turns interleave at many yield points.
pub const FUEL_YIELD_INTERVAL: u64 = 20_000;

/// Reads of committed state for the turn's actor.
pub trait StateRead: Send + Sync + 'static {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn keys(&self, prefix: &str) -> Vec<String>;
}

/// The effect boundary as seen from the host functions. The daemon
/// implements it (TurnBegin before the first effect, recording, replay of
/// recorded results); the replay checker serves recorded results only.
pub trait EffectGate: Send + Sync + 'static {
    /// `Err` aborts the turn (e.g. the log failed); it is not guest-visible.
    fn fetch(
        &self,
        ordinal: u32,
        req: HttpRequest,
    ) -> BoxFuture<'static, Result<EffectOutcome, String>>;
}

pub struct TurnSpec {
    pub kind: String,
    pub key: String,
    pub causal_key: String,
    pub time_ms: u64,
    pub seed: [u8; 32],
    pub input: Vec<u8>,
}

pub struct TurnOutput {
    pub outcome: Outcome,
    pub writes: Vec<(String, Option<Vec<u8>>)>,
    pub effects: Vec<(u32, EffectOutcome)>,
    pub fuel: u64,
}

/// Engine and pre-linked component, built once per process and shared by all
/// simulated nodes and threads.
pub struct Code {
    engine: Engine,
    pre: bindings::ActorPre<TurnHost>,
}

static CODE: LazyLock<Arc<Code>> = LazyLock::new(|| {
    Arc::new(Code::load().unwrap_or_else(|e| panic!("cannot load guest component: {e:?}")))
});

pub fn code() -> Arc<Code> {
    CODE.clone()
}

pub const GUEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/guest/target/wasm32-wasip2/release/spike_d_guest.wasm"
);

impl Code {
    fn load() -> wasmtime::Result<Self> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        cfg.epoch_interruption(false);
        cfg.cranelift_nan_canonicalization(true);
        cfg.relaxed_simd_deterministic(true);
        cfg.wasm_shared_everything_threads(false);
        let mut pool = PoolingAllocationConfig::new();
        pool.total_component_instances(1024);
        pool.total_core_instances(4096);
        pool.total_memories(1024);
        pool.total_tables(4096);
        pool.total_stacks(1024);
        pool.max_memory_size(64 << 20);
        cfg.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
        let engine = Engine::new(&cfg)?;
        let bytes = std::fs::read(GUEST)
            .map_err(|e| wasmtime::format_err!("{GUEST}: {e} (run guest build first)"))?;
        let component = Component::new(&engine, &bytes)?;
        let linker = build_linker(&engine)?;
        let pre = bindings::ActorPre::new(linker.instantiate_pre(&component)?)?;
        Ok(Self { engine, pre })
    }

    /// Runs one turn on a fresh instance.
    pub async fn run(
        &self,
        spec: &TurnSpec,
        state: Arc<dyn StateRead>,
        gate: Arc<dyn EffectGate>,
    ) -> Result<TurnOutput, String> {
        let host = TurnHost::new(spec, state, gate);
        let mut store = Store::new(&self.engine, host);
        store.set_fuel(FUEL_PER_TURN).map_err(|e| e.to_string())?;
        store
            .fuel_async_yield_interval(Some(FUEL_YIELD_INTERVAL))
            .map_err(|e| e.to_string())?;
        let input = types::Input::Http(types::HttpRequest {
            method: "POST".into(),
            path: format!("/{}/{}/increment", spec.kind, spec.key),
            query: String::new(),
            params: vec![("key".into(), spec.key.clone())],
            headers: Vec::new(),
            body: types::HttpBody::Inline(spec.input.clone()),
        });
        let result = match self.pre.instantiate_async(&mut store).await {
            Ok(actor) => {
                actor
                    .kronik_actor_handler()
                    .call_handle(&mut store, &input)
                    .await
            }
            Err(e) => Err(e),
        };
        let fuel = FUEL_PER_TURN - store.get_fuel().unwrap_or(0);
        let host = store.into_data();
        if let Some(fatal) = host.fatal {
            return Err(fatal);
        }
        let outcome = match result {
            Ok(Ok(types::Output::Http(r))) => Outcome::Ok {
                status: r.status,
                body: match r.body {
                    types::HttpBody::Inline(b) => b,
                    types::HttpBody::Blob(_) => Vec::new(),
                },
            },
            Ok(Ok(_)) => Outcome::Ok {
                status: 204,
                body: Vec::new(),
            },
            Ok(Err(types::HandlerError::Rejected(m))) => Outcome::Failed {
                code: "TURN_FAILED".into(),
                message: format!("rejected: {m}"),
            },
            Ok(Err(types::HandlerError::Failed(m))) => {
                let code = if host.outcome_unknown_seen && m.contains("OutcomeUnknown") {
                    "EFFECT_OUTCOME_UNKNOWN"
                } else {
                    "TURN_FAILED"
                };
                Outcome::Failed {
                    code: code.into(),
                    message: m,
                }
            }
            Err(e) => match e.downcast_ref::<Trap>() {
                Some(Trap::OutOfFuel) => Outcome::Failed {
                    code: "FUEL_EXHAUSTED".into(),
                    message: String::new(),
                },
                Some(t) => Outcome::Failed {
                    code: "TURN_FAILED".into(),
                    message: t.to_string(),
                },
                None => Outcome::Failed {
                    code: "TURN_FAILED".into(),
                    message: e.root_cause().to_string(),
                },
            },
        };
        let committed = matches!(outcome, Outcome::Ok { .. });
        Ok(TurnOutput {
            outcome,
            writes: if committed {
                host.writes.into_iter().collect()
            } else {
                Vec::new()
            },
            effects: host.effects,
            fuel,
        })
    }
}

pub struct TurnHost {
    wasi: WasiCtx,
    table: ResourceTable,
    kind: String,
    key: String,
    causal_key: String,
    time_ms: u64,
    rng_context: ChaCha20Rng,
    rng_wasi: ChaCha20Rng,
    rng_insecure: ChaCha20Rng,
    insecure_seed: (u64, u64),
    state: Arc<dyn StateRead>,
    gate: Arc<dyn EffectGate>,
    writes: BTreeMap<String, Option<Vec<u8>>>,
    effects: Vec<(u32, EffectOutcome)>,
    next_ordinal: u32,
    outcome_unknown_seen: bool,
    fatal: Option<String>,
}

fn stream(seed: [u8; 32], id: u64) -> ChaCha20Rng {
    let mut r = ChaCha20Rng::from_seed(seed);
    r.set_stream(id);
    r
}

impl TurnHost {
    fn new(spec: &TurnSpec, state: Arc<dyn StateRead>, gate: Arc<dyn EffectGate>) -> Self {
        let wasi = WasiCtxBuilder::new()
            .stdout(Discard)
            .stderr(Discard)
            .build();
        let mut s = stream(spec.seed, 3);
        let insecure_seed = (s.next_u64(), s.next_u64());
        Self {
            wasi,
            table: ResourceTable::new(),
            kind: spec.kind.clone(),
            key: spec.key.clone(),
            causal_key: spec.causal_key.clone(),
            time_ms: spec.time_ms,
            rng_context: stream(spec.seed, 0),
            rng_wasi: stream(spec.seed, 1),
            rng_insecure: stream(spec.seed, 2),
            insecure_seed,
            state,
            gate,
            writes: BTreeMap::new(),
            effects: Vec::new(),
            next_ordinal: 0,
            outcome_unknown_seen: false,
            fatal: None,
        }
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
        Ok(match self.writes.get(&key) {
            Some(v) => v.clone(),
            None => self.state.get(&key),
        })
    }
    async fn set(&mut self, key: String, value: Vec<u8>) -> wasmtime::Result<()> {
        self.writes.insert(key, Some(value));
        Ok(())
    }
    async fn delete(&mut self, key: String) -> wasmtime::Result<()> {
        self.writes.insert(key, None);
        Ok(())
    }
    async fn keys(&mut self, prefix: String) -> wasmtime::Result<Vec<String>> {
        let mut set: BTreeMap<String, bool> = self
            .state
            .keys(&prefix)
            .into_iter()
            .map(|k| (k, true))
            .collect();
        for (k, v) in self.writes.iter().filter(|(k, _)| k.starts_with(&prefix)) {
            set.insert(k.clone(), v.is_some());
        }
        Ok(set
            .into_iter()
            .filter(|(_, live)| *live)
            .map(|(k, _)| k)
            .collect())
    }
}

impl context::Host for TurnHost {
    async fn self_ref(&mut self) -> wasmtime::Result<types::ActorRef> {
        Ok(types::ActorRef {
            kind: self.kind.clone(),
            key: self.key.clone(),
        })
    }
    async fn causal_id(&mut self) -> wasmtime::Result<String> {
        Ok(blake3::hash(self.causal_key.as_bytes()).to_hex()[..16].to_string())
    }
    async fn now_ms(&mut self) -> wasmtime::Result<u64> {
        Ok(self.time_ms)
    }
    async fn random_bytes(&mut self, len: u32) -> wasmtime::Result<Vec<u8>> {
        if len > 1 << 20 {
            bail!("random-bytes limit");
        }
        let mut b = vec![0u8; len as usize];
        self.rng_context.fill_bytes(&mut b);
        Ok(b)
    }
}

impl http_client::Host for TurnHost {
    async fn fetch(
        &mut self,
        req: http_client::Request,
    ) -> wasmtime::Result<Result<http_client::Response, http_client::FetchError>> {
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        let mut headers = Vec::new();
        for h in req.headers {
            match h.value {
                http_client::HeaderValue::Text(v) => headers.push((h.name, v)),
                http_client::HeaderValue::Secret(_) => {
                    return Ok(Err(http_client::FetchError::Denied(
                        "secrets are not supported in spike D".into(),
                    )));
                }
            }
        }
        let body = match req.body {
            types::HttpBody::Inline(b) => Bytes::from(b),
            types::HttpBody::Blob(_) => Bytes::new(),
        };
        let request = HttpRequest {
            method: req.method,
            url: req.url,
            headers,
            body,
        };
        let outcome = match self.gate.fetch(ordinal, request).await {
            Ok(o) => o,
            Err(fatal) => {
                self.fatal = Some(fatal.clone());
                bail!("effect layer failed: {fatal}");
            }
        };
        self.effects.push((ordinal, outcome.clone()));
        Ok(match outcome {
            EffectOutcome::Response { status, body } => Ok(http_client::Response {
                status,
                headers: Vec::new(),
                body: types::HttpBody::Inline(body),
            }),
            EffectOutcome::NotSent(m) => Err(http_client::FetchError::Network(m)),
            EffectOutcome::Unknown(_) => {
                self.outcome_unknown_seen = true;
                Err(http_client::FetchError::OutcomeUnknown)
            }
        })
    }
}

macro_rules! unsupported {
    () => {
        bail!("not supported in spike D")
    };
}

impl sql::Host for TurnHost {
    async fn query(
        &mut self,
        _: String,
        _: Vec<sql::SqlValue>,
    ) -> wasmtime::Result<Result<sql::Rows, sql::SqlError>> {
        unsupported!()
    }
    async fn execute(
        &mut self,
        _: String,
        _: Vec<sql::SqlValue>,
    ) -> wasmtime::Result<Result<u64, sql::SqlError>> {
        unsupported!()
    }
}
impl messaging::Host for TurnHost {
    async fn send(&mut self, _: types::ActorRef, _: types::Message) -> wasmtime::Result<()> {
        unsupported!()
    }
    async fn call(
        &mut self,
        _: types::ActorRef,
        _: types::Message,
        _: Option<types::Message>,
    ) -> wasmtime::Result<Result<Option<types::Message>, messaging::CallError>> {
        unsupported!()
    }
}
impl timers::Host for TurnHost {
    async fn schedule(&mut self, _: u64, _: types::Message) -> wasmtime::Result<u64> {
        unsupported!()
    }
    async fn cancel(&mut self, _: u64) -> wasmtime::Result<bool> {
        unsupported!()
    }
}
impl crypto::Host for TurnHost {
    async fn hmac_sha256(
        &mut self,
        _: String,
        _: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, crypto::CryptoError>> {
        unsupported!()
    }
    async fn sign_ed25519(
        &mut self,
        _: String,
        _: Vec<u8>,
    ) -> wasmtime::Result<Result<Vec<u8>, crypto::CryptoError>> {
        unsupported!()
    }
}
impl secrets::Host for TurnHost {
    async fn reveal(&mut self, _: String) -> wasmtime::Result<Result<String, String>> {
        unsupported!()
    }
}
impl log::Host for TurnHost {
    async fn emit(
        &mut self,
        _: log::Level,
        _: String,
        _: Vec<(String, String)>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}
impl privacy::Host for TurnHost {
    async fn set_subject(&mut self, _: Option<String>) -> wasmtime::Result<()> {
        Ok(())
    }
}

// Deterministic WASI (ADR 0001 section 7).

struct DetWasi;
impl HasData for DetWasi {
    type Data<'a> = &'a mut TurnHost;
}
struct HasIo;
impl HasData for HasIo {
    type Data<'a> = &'a mut ResourceTable;
}

struct ReadyNow;
#[wasmtime_wasi::async_trait]
impl Pollable for ReadyNow {
    async fn ready(&mut self) {}
}

impl wall_clock::Host for &mut TurnHost {
    fn now(&mut self) -> wasmtime::Result<wall_clock::Datetime> {
        Ok(wall_clock::Datetime {
            seconds: self.time_ms / 1000,
            nanoseconds: ((self.time_ms % 1000) * 1_000_000) as u32,
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
    fn now(&mut self) -> wasmtime::Result<u64> {
        Ok(self.time_ms.saturating_mul(1_000_000))
    }
    fn resolution(&mut self) -> wasmtime::Result<u64> {
        Ok(1_000_000)
    }
    fn subscribe_instant(&mut self, _: u64) -> wasmtime::Result<Resource<DynPollable>> {
        let r = self.table.push(ReadyNow)?;
        wasmtime_wasi::p2::subscribe(&mut self.table, r)
    }
    fn subscribe_duration(&mut self, _: u64) -> wasmtime::Result<Resource<DynPollable>> {
        let r = self.table.push(ReadyNow)?;
        wasmtime_wasi::p2::subscribe(&mut self.table, r)
    }
}
impl random::Host for &mut TurnHost {
    fn get_random_bytes(&mut self, len: u64) -> wasmtime::Result<Vec<u8>> {
        if len > 1 << 20 {
            bail!("random limit");
        }
        let mut b = vec![0u8; len as usize];
        self.rng_wasi.fill_bytes(&mut b);
        Ok(b)
    }
    fn get_random_u64(&mut self) -> wasmtime::Result<u64> {
        Ok(self.rng_wasi.next_u64())
    }
}
impl insecure::Host for &mut TurnHost {
    fn get_insecure_random_bytes(&mut self, len: u64) -> wasmtime::Result<Vec<u8>> {
        if len > 1 << 20 {
            bail!("random limit");
        }
        let mut b = vec![0u8; len as usize];
        self.rng_insecure.fill_bytes(&mut b);
        Ok(b)
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

/// Guest stdout/stderr are dropped in the spike (spike A captures them).
struct Discard;
impl IsTerminal for Discard {
    fn is_terminal(&self) -> bool {
        false
    }
}
impl StdoutStream for Discard {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(Discard)
    }
    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        Box::new(tokio::io::sink())
    }
}
#[wasmtime_wasi::async_trait]
impl Pollable for Discard {
    async fn ready(&mut self) {}
}
impl OutputStream for Discard {
    fn write(&mut self, _: bytes::Bytes) -> StreamResult<()> {
        Ok(())
    }
    fn flush(&mut self) -> StreamResult<()> {
        Ok(())
    }
    fn check_write(&mut self) -> StreamResult<usize> {
        Ok(64 * 1024)
    }
}

fn build_linker(engine: &Engine) -> wasmtime::Result<wasmtime::component::Linker<TurnHost>> {
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
