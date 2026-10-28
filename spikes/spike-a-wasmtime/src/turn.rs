//! Turn execution: one fresh instance per call, created from an `InstancePre`.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use wasmtime::component::Component;
use wasmtime::{Engine, Store, Trap};

use crate::engine::FUEL_YIELD_INTERVAL;
use crate::host::bindings::ActorPre;
use crate::host::bindings::kronik::actor::types::{HandlerError, Input, Manifest, Output};
use crate::host::{TurnCtx, TurnSpec, build_linker, fmt_bytes};

/// Turn outcome classification; the codes match the brief's error catalogue
/// where one exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `handle` returned `ok(output)`: buffered writes would be committed.
    Committed(String),
    /// `handle` returned `err(handler-error)`.
    HandlerError(String),
    /// Fuel ran out: `FUEL_EXHAUSTED`.
    FuelExhausted,
    /// A memory growth beyond the instance limit was refused and the guest
    /// then trapped (Rust aborts on allocation failure).
    MemoryLimit(String),
    /// Any other trap, including host-raised traps (limits, describe rules).
    Trap(String),
}

impl Outcome {
    pub fn code(&self) -> &'static str {
        match self {
            Outcome::Committed(_) => "OK",
            Outcome::HandlerError(_) => "TURN_FAILED",
            Outcome::FuelExhausted => "FUEL_EXHAUSTED",
            Outcome::MemoryLimit(_) => "TURN_FAILED",
            Outcome::Trap(_) => "TURN_FAILED",
        }
    }
}

pub struct TurnResult {
    pub outcome: Outcome,
    /// Ordered host-call trace, including WASI clock/random/stdio calls.
    pub trace: Vec<String>,
    /// Buffered state writes (applied only when the turn commits).
    pub writes: BTreeMap<String, Option<Vec<u8>>>,
    pub fuel_used: u64,
    pub peak_memory_bytes: usize,
    /// Wall-clock time spent instantiating and running; never part of the
    /// canonical outcome.
    pub instantiate_time: Duration,
    pub call_time: Duration,
    /// The raw output when the turn committed (used to answer `call`).
    pub output: Option<Output>,
}

impl TurnResult {
    /// Canonical byte representation of everything that I1 requires to be
    /// identical: outcome, output, ordered host calls, state writes, fuel.
    pub fn canonical(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "outcome {} {:?}\n",
            self.outcome.code(),
            self.outcome
        ));
        for line in &self.trace {
            s.push_str("call ");
            s.push_str(line);
            s.push('\n');
        }
        for (k, v) in &self.writes {
            match v {
                Some(v) => s.push_str(&format!("write {k:?} = {}\n", fmt_bytes(v))),
                None => s.push_str(&format!("delete {k:?}\n")),
            }
        }
        s.push_str(&format!("fuel {}\n", self.fuel_used));
        s
    }

    pub fn digest(&self) -> String {
        format!("b3:{}", blake3::hash(self.canonical().as_bytes()).to_hex())
    }
}

pub struct Runner {
    engine: Engine,
    pre: ActorPre<TurnCtx>,
    /// Handed to each turn's store so `messaging.call` can run a nested turn.
    me: Weak<Runner>,
}

impl Runner {
    /// Links the component once; every turn then instantiates from the
    /// pre-resolved `InstancePre` (no import resolution per turn).
    pub fn new(engine: &Engine, component: &Component) -> wasmtime::Result<Arc<Self>> {
        let linker = build_linker(engine)?;
        let instance_pre = linker.instantiate_pre(component)?;
        let pre = ActorPre::new(instance_pre)?;
        Ok(Arc::new_cyclic(|me| Self {
            engine: engine.clone(),
            pre,
            me: me.clone(),
        }))
    }

    fn store(
        &self,
        spec: &TurnSpec,
        describe_only: bool,
        depth: u32,
    ) -> wasmtime::Result<Store<TurnCtx>> {
        let ctx = TurnCtx::new(spec, describe_only, self.me.upgrade(), depth);
        let mut store = Store::new(&self.engine, ctx);
        store.limiter(|ctx| &mut ctx.limiter);
        store.set_fuel(spec.fuel)?;
        store.fuel_async_yield_interval(Some(FUEL_YIELD_INTERVAL))?;
        Ok(store)
    }

    /// Runs `describe` in an isolated turn without state and without effects.
    pub async fn describe(&self, spec: &TurnSpec) -> wasmtime::Result<(Manifest, Vec<String>)> {
        let mut store = self.store(spec, true, 0)?;
        let actor = self.pre.instantiate_async(&mut store).await?;
        let manifest = actor
            .kronik_actor_handler()
            .call_describe(&mut store)
            .await?;
        let trace = store.data().trace.take();
        Ok((manifest, trace))
    }

    /// Runs one turn on a brand-new instance. Errors are only returned for
    /// host-level failures (e.g. pool exhaustion); guest failures are
    /// classified into `Outcome`.
    pub async fn handle(&self, spec: &TurnSpec, input: &Input) -> wasmtime::Result<TurnResult> {
        self.handle_at_depth(spec, input, 0).await
    }

    pub async fn handle_at_depth(
        &self,
        spec: &TurnSpec,
        input: &Input,
        depth: u32,
    ) -> wasmtime::Result<TurnResult> {
        let mut store = self.store(spec, false, depth)?;
        let t0 = Instant::now();
        let result = match self.pre.instantiate_async(&mut store).await {
            Ok(actor) => {
                let t1 = Instant::now();
                let r = actor
                    .kronik_actor_handler()
                    .call_handle(&mut store, input)
                    .await;
                (t1 - t0, t1.elapsed(), r)
            }
            Err(e) => (t0.elapsed(), Duration::ZERO, Err(e)),
        };
        let (instantiate_time, call_time, r) = result;
        let fuel_left = store.get_fuel()?;
        let ctx = store.data();
        let (outcome, output) = match r {
            Ok(Ok(output)) => (Outcome::Committed(render_output(&output)), Some(output)),
            Ok(Err(e)) => (
                Outcome::HandlerError(match e {
                    HandlerError::Rejected(m) => format!("rejected: {m}"),
                    HandlerError::Failed(m) => format!("failed: {m}"),
                }),
                None,
            ),
            Err(e) => (classify_error(&e, ctx.limiter.hit), None),
        };
        let committed = matches!(outcome, Outcome::Committed(_));
        Ok(TurnResult {
            outcome,
            trace: ctx.trace.take(),
            writes: if committed {
                ctx.writes.clone()
            } else {
                BTreeMap::new()
            },
            fuel_used: spec.fuel - fuel_left,
            peak_memory_bytes: ctx.limiter.peak_bytes,
            instantiate_time,
            call_time,
            output,
        })
    }
}

/// Maps a guest failure to a deterministic description: trap codes and
/// host-raised messages only, never backtraces or addresses.
fn classify_error(e: &wasmtime::Error, memory_limit_hit: bool) -> Outcome {
    if let Some(trap) = e.downcast_ref::<Trap>() {
        if *trap == Trap::OutOfFuel {
            return Outcome::FuelExhausted;
        }
        if memory_limit_hit {
            return Outcome::MemoryLimit(format!("memory limit reached, then trap: {trap}"));
        }
        return Outcome::Trap(trap.to_string());
    }
    if let Some(exit) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
        return Outcome::Trap(format!("guest called wasi:cli/exit with status {}", exit.0));
    }
    let msg = e.root_cause().to_string();
    if memory_limit_hit {
        return Outcome::MemoryLimit(format!("memory limit reached, then: {msg}"));
    }
    Outcome::Trap(msg)
}

pub fn render_output(output: &Output) -> String {
    use crate::host::bindings::kronik::actor::types::HttpBody;
    let body = |b: &HttpBody| match b {
        HttpBody::Inline(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        HttpBody::Blob(r) => format!("<blob {} {}>", r.hash, r.size),
    };
    match output {
        Output::None => "none".to_string(),
        Output::Reply(m) => format!(
            "reply name={:?} content-type={:?}\n{}",
            m.name,
            m.content_type,
            String::from_utf8_lossy(&m.body)
        ),
        Output::Http(r) => format!(
            "http status={} headers={:?}\n{}",
            r.status,
            r.headers
                .iter()
                .map(|h| (&h.name, &h.value))
                .collect::<Vec<_>>(),
            body(&r.body)
        ),
    }
}
