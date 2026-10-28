//! Turn execution: one fresh instance per turn from a pre-linked component.

use std::sync::Arc;

use kronik_core::ids::{ActorRef, CodeHash};
use kronik_proto::log::v1 as pb;
use wasmtime::component::Component;
use wasmtime::{Engine, Store, Trap};

use crate::engine::FUEL_YIELD_INTERVAL;
use crate::host::bindings::ActorPre;
use crate::host::bindings::kronik::actor::types;
use crate::host::{
    EffectGate, HostInit, LogEvent, SqlHost, StateView, TurnHost, TurnLimits, build_linker,
    message_to_pb,
};

/// Everything that determines a turn besides code, engine version and the
/// actor's state at turn start.
pub struct TurnRequest {
    pub actor: ActorRef,
    pub causal_key: pb::CausalKey,
    pub logical_time_ms: u64,
    pub seed: [u8; 32],
    pub input: pb::Input,
    pub limits: TurnLimits,
    /// The default subject at turn start (the sender's or the request's).
    pub subject: Option<String>,
}

/// What a finished turn produced. Failed turns carry no writes or messages.
pub struct TurnOutput {
    pub outcome: pb::Outcome,
    pub writes: Vec<pb::StateWrite>,
    pub messages: Vec<pb::OutboundMessage>,
    pub timers: Vec<pb::TimerOp>,
    pub fuel_used: u64,
    pub memory_peak_bytes: u64,
    pub logs: Vec<LogEvent>,
    /// The SQL host handed in, returned so the caller can end its turn.
    pub sql: Option<Box<dyn SqlHost>>,
}

impl TurnOutput {
    pub fn committed(&self) -> bool {
        self.outcome.kind == pb::OutcomeKind::Committed as i32
    }
}

/// A host-side failure: the turn did not run to a recordable outcome (pool
/// exhaustion, a state read error). Nothing is recorded for it.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("host failure during turn: {0}")]
    Host(String),
    #[error("invalid input: {0}")]
    Input(String),
}

/// A component linked once; every turn instantiates from it.
pub struct Program {
    engine: Engine,
    pre: ActorPre<TurnHost>,
    hash: CodeHash,
}

impl Program {
    pub(crate) fn new(
        engine: &Engine,
        component: &Component,
        hash: CodeHash,
    ) -> wasmtime::Result<Program> {
        let linker = build_linker(engine)?;
        let pre = ActorPre::new(linker.instantiate_pre(component)?)?;
        Ok(Program {
            engine: engine.clone(),
            pre,
            hash,
        })
    }

    pub fn hash(&self) -> CodeHash {
        self.hash
    }

    fn store(&self, host: TurnHost, fuel: u64) -> Result<Store<TurnHost>, RunError> {
        let mut store = Store::new(&self.engine, host);
        store.limiter(|h| &mut h.limiter);
        store
            .set_fuel(fuel)
            .and_then(|()| store.fuel_async_yield_interval(Some(FUEL_YIELD_INTERVAL)))
            .map_err(|e| RunError::Host(format!("{e:#}")))?;
        Ok(store)
    }

    /// Runs `describe` in an isolated turn without state and effects.
    pub async fn describe(&self, limits: TurnLimits) -> Result<pb::Manifest, String> {
        let host = TurnHost::new(HostInit {
            actor: ActorRef {
                kind: "describe".into(),
                key: "describe".into(),
            },
            causal_key: kronik_core::causal::root("describe".into()),
            now_ms: 0,
            seed: [0; 32],
            limits,
            subject: None,
            state: None,
            sql: None,
            gate: None,
            describe_only: true,
        });
        let mut store = self.store(host, limits.fuel).map_err(|e| e.to_string())?;
        let actor = self
            .pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| format!("{e:#}"))?;
        let m = actor
            .kronik_actor_handler()
            .call_describe(&mut store)
            .await
            .map_err(|e| describe_error(&e))?;
        Ok(pb::Manifest {
            kind: m.kind,
            schema_version: m.schema_version,
            routes: m
                .routes
                .into_iter()
                .map(|r| pb::Route {
                    method: r.method,
                    pattern: r.pattern,
                })
                .collect(),
            capabilities: m.capabilities,
        })
    }

    /// Runs one turn on a fresh instance. Guest failures become a failed
    /// outcome; only host failures are errors.
    pub async fn run(
        &self,
        req: TurnRequest,
        state: Arc<dyn StateView>,
        sql: Option<Box<dyn SqlHost>>,
        gate: Option<Arc<dyn EffectGate>>,
    ) -> Result<TurnOutput, RunError> {
        let input = input_to_wit(&req.input)?;
        let fuel = req.limits.fuel;
        let message_bytes = req.limits.message_bytes;
        let host = TurnHost::new(HostInit {
            actor: req.actor,
            causal_key: req.causal_key,
            now_ms: req.logical_time_ms,
            seed: req.seed,
            limits: req.limits,
            subject: req.subject,
            state: Some(state),
            sql,
            gate,
            describe_only: false,
        });
        let mut store = self.store(host, fuel)?;
        let result = match self.pre.instantiate_async(&mut store).await {
            Ok(actor) => {
                actor
                    .kronik_actor_handler()
                    .call_handle(&mut store, &input)
                    .await
            }
            Err(e) => Err(e),
        };
        let fuel_used = fuel - store.get_fuel().unwrap_or(0);
        let mut host = store.into_data();
        if let Some(fatal) = host.fatal.take() {
            return Err(RunError::Host(fatal));
        }
        let subject = host.subject.clone();
        let mut outcome = match result {
            Ok(Ok(output)) => committed(output, subject, message_bytes),
            Ok(Err(types::HandlerError::Rejected(m))) => {
                failed(pb::OutcomeKind::Rejected, "TURN_FAILED", m)
            }
            Ok(Err(types::HandlerError::Failed(m))) => {
                failed(pb::OutcomeKind::Failed, "TURN_FAILED", m)
            }
            Err(e) => classify_error(&e, host.limiter.hit),
        };
        if outcome.kind == pb::OutcomeKind::Committed as i32 && host.limiter.hit {
            // A refused growth the guest recovered from is not a failure.
            outcome.message.clear();
        }
        let ok = outcome.kind == pb::OutcomeKind::Committed as i32;
        let writes = if ok {
            std::mem::take(&mut host.writes)
                .into_iter()
                .map(|(key, w)| match w {
                    Some((value, subject)) => pb::StateWrite {
                        op: pb::StateOp::Set as i32,
                        key,
                        value: Some(pb::Sealable {
                            subject,
                            value: Some(pb::sealable::Value::Plain(value)),
                        }),
                    },
                    None => pb::StateWrite {
                        op: pb::StateOp::Delete as i32,
                        key,
                        value: None,
                    },
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(TurnOutput {
            outcome,
            writes,
            messages: if ok {
                std::mem::take(&mut host.messages)
            } else {
                Vec::new()
            },
            timers: if ok {
                std::mem::take(&mut host.timers)
            } else {
                Vec::new()
            },
            fuel_used,
            memory_peak_bytes: host.limiter.peak_bytes as u64,
            logs: host.logs.take(),
            sql: host.sql.take(),
        })
    }
}

fn failed(kind: pb::OutcomeKind, code: &str, message: String) -> pb::Outcome {
    pb::Outcome {
        kind: kind as i32,
        error_code: code.into(),
        message,
        output: None,
    }
}

fn committed(output: types::Output, subject: Option<String>, limit: usize) -> pb::Outcome {
    let output = match output {
        types::Output::None => None,
        types::Output::Reply(m) => {
            if m.body.len() > limit {
                return failed(
                    pb::OutcomeKind::Trap,
                    "TURN_FAILED",
                    format!("reply is {} bytes, the limit is {limit}", m.body.len()),
                );
            }
            Some(pb::outcome::Output::Reply(message_to_pb(m, subject)))
        }
        types::Output::Http(r) => {
            let body = match r.body {
                types::HttpBody::Inline(b) => {
                    if b.len() > limit {
                        return failed(
                            pb::OutcomeKind::Trap,
                            "TURN_FAILED",
                            format!("response body is {} bytes, the limit is {limit}", b.len()),
                        );
                    }
                    pb::body::Value::Inline(plain(subject.clone(), b))
                }
                types::HttpBody::Blob(_) => {
                    return failed(
                        pb::OutcomeKind::Trap,
                        "TURN_FAILED",
                        "NOT_IMPLEMENTED: blob bodies arrive in a later version".into(),
                    );
                }
            };
            Some(pb::outcome::Output::Http(pb::HttpResponse {
                status: u32::from(r.status),
                headers: r
                    .headers
                    .into_iter()
                    .map(|h| pb::Header {
                        name: h.name,
                        value: Some(plain(subject.clone(), h.value.into_bytes())),
                    })
                    .collect(),
                body: Some(pb::Body { value: Some(body) }),
            }))
        }
    };
    pb::Outcome {
        kind: pb::OutcomeKind::Committed as i32,
        error_code: String::new(),
        message: String::new(),
        output,
    }
}

fn plain(subject: Option<String>, bytes: Vec<u8>) -> pb::Sealable {
    pb::Sealable {
        subject,
        value: Some(pb::sealable::Value::Plain(bytes)),
    }
}

/// Maps a guest failure to a deterministic description: trap codes and
/// host-raised messages only, never backtraces or addresses.
fn classify_error(e: &wasmtime::Error, memory_limit_hit: bool) -> pb::Outcome {
    if let Some(trap) = e.downcast_ref::<Trap>() {
        if *trap == Trap::OutOfFuel {
            return failed(
                pb::OutcomeKind::FuelExhausted,
                "FUEL_EXHAUSTED",
                "the turn ran out of fuel".into(),
            );
        }
        if memory_limit_hit {
            return failed(
                pb::OutcomeKind::MemoryLimit,
                "TURN_FAILED",
                format!("memory limit reached, then trap: {trap}"),
            );
        }
        return failed(pb::OutcomeKind::Trap, "TURN_FAILED", trap.to_string());
    }
    if let Some(exit) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
        return failed(
            pb::OutcomeKind::Trap,
            "TURN_FAILED",
            format!("guest called wasi:cli/exit with status {}", exit.0),
        );
    }
    let msg = e.root_cause().to_string();
    if memory_limit_hit {
        return failed(
            pb::OutcomeKind::MemoryLimit,
            "TURN_FAILED",
            format!("memory limit reached, then: {msg}"),
        );
    }
    let code = if msg.starts_with("NOT_IMPLEMENTED") {
        "NOT_IMPLEMENTED"
    } else if msg.starts_with("REPLAY_DIVERGED") {
        "REPLAY_DIVERGED"
    } else {
        "TURN_FAILED"
    };
    failed(pb::OutcomeKind::Trap, code, msg)
}

fn describe_error(e: &wasmtime::Error) -> String {
    match e.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => "describe ran out of fuel".into(),
        Some(t) => format!("describe trapped: {t}"),
        None => format!("describe failed: {}", e.root_cause()),
    }
}

fn sealed_bytes(s: Option<&pb::Sealable>) -> Result<Vec<u8>, RunError> {
    match s.and_then(|s| s.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => Ok(b.clone()),
        Some(pb::sealable::Value::Sealed(_)) => Err(RunError::Input(
            "sealed values need privacy mode, which arrives in a later version".into(),
        )),
        None => Ok(Vec::new()),
    }
}

fn message_to_wit(m: Option<&pb::Message>) -> Result<types::Message, RunError> {
    let m = m.ok_or_else(|| RunError::Input("message missing".into()))?;
    Ok(types::Message {
        name: m.name.clone(),
        content_type: m.content_type.clone(),
        body: sealed_bytes(m.body.as_ref())?,
        blobs: m
            .blobs
            .iter()
            .map(|b| types::BlobRef {
                hash: b.hash.clone(),
                size: b.size,
            })
            .collect(),
    })
}

fn body_to_wit(b: Option<&pb::Body>) -> Result<types::HttpBody, RunError> {
    Ok(match b.and_then(|b| b.value.as_ref()) {
        Some(pb::body::Value::Inline(s)) => types::HttpBody::Inline(sealed_bytes(Some(s))?),
        Some(pb::body::Value::Blob(r)) => types::HttpBody::Blob(types::BlobRef {
            hash: r.hash.clone(),
            size: r.size,
        }),
        None => types::HttpBody::Inline(Vec::new()),
    })
}

fn input_to_wit(input: &pb::Input) -> Result<types::Input, RunError> {
    use pb::input::Kind;
    Ok(match &input.kind {
        Some(Kind::Http(h)) => types::Input::Http(types::HttpRequest {
            method: h.method.clone(),
            // Plain or the sealable copies of a subject's request (unsealed
            // for the guest before the turn).
            path: h.path_text(),
            query: h.query_text(),
            params: h.param_values(),
            headers: h
                .headers
                .iter()
                .map(|hd| {
                    Ok(types::Header {
                        name: hd.name.clone(),
                        value: String::from_utf8_lossy(&sealed_bytes(hd.value.as_ref())?)
                            .into_owned(),
                    })
                })
                .collect::<Result<_, RunError>>()?,
            body: body_to_wit(h.body.as_ref())?,
        }),
        Some(Kind::Message(m)) => types::Input::Message(types::Incoming {
            sender: m.sender.as_ref().map(|s| types::ActorRef {
                kind: s.kind.clone(),
                key: s.key.clone(),
            }),
            msg: message_to_wit(m.msg.as_ref())?,
        }),
        Some(Kind::Timer(t)) => types::Input::Timer(types::TimerFired {
            id: t.timer_id,
            msg: message_to_wit(t.msg.as_ref())?,
        }),
        Some(Kind::Migrate(m)) => types::Input::Migrate(m.from_schema_version),
        None => return Err(RunError::Input("input has no case".into())),
    })
}
