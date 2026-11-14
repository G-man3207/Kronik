//! Turn execution: one fresh instance per turn from a pre-linked component.

use std::sync::Arc;

use kronik_core::error::ErrorCode;
use kronik_core::ids::{ActorRef, CodeHash};
use kronik_proto::log::v1 as pb;
use wasmtime::component::Component;
use wasmtime::{Engine, Store, Trap};

use crate::engine::FUEL_YIELD_INTERVAL;
use crate::host::bindings::ActorPre;
use crate::host::bindings::kronik::actor::types;
use crate::host::blobs::{BlobHost, TurnBlobs, not_held};
use crate::host::connection_bindings::ActorConnectionsPre;
use crate::host::connection_bindings::kronik::actor::connections as conn_wit;
use crate::host::{
    CONNECTION_HANDLER_EXPORT, EffectGate, HostInit, LogEvent, SqlHost, StateView, TurnHost,
    TurnLimits, build_linker, message_to_pb,
};

/// The import name prefix of the `blobs` interface: a component that
/// imports it reads blob bodies (ADR 0119 §1).
const BLOBS_IMPORT: &str = "kronik:actor/blobs@";

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
    /// The buffered connection operations, with their outgoing seqs (M24).
    pub connection_ops: Vec<pb::ConnectionOp>,
    /// The net hold changes of a committed turn (M26 §3), sorted by
    /// identity; empty for a failed one.
    pub blob_refs: Vec<pb::BlobRefOp>,
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
    #[error("{0}: an immutable recorded prerequisite is no longer available")]
    Prerequisite(ErrorCode),
    #[error("invalid input: {0}")]
    Input(String),
    /// The blob store is below its disk reserve or full (ADR 0117 §9): the
    /// turn attempt is abandoned without a record and runs again later.
    #[error("BLOB_STORE_FULL: {0}")]
    BlobStoreFull(String),
    /// A committed blob reference's bytes are not in the blob store
    /// (`BLOB_MISSING`); never expected, as a record follows its blobs.
    #[error("BLOB_MISSING: {0}")]
    BlobMissing(String),
    /// The blob store's disk failed: its durability is unknown, so the
    /// node stops as for a failure of its log (the restart runs the turn
    /// again).
    #[error("the blob store failed: {0}")]
    BlobIo(String),
    /// A sealed value reached the turn unopened: its subject's key is not
    /// in this node's privacy keystore (`KEYSTORE_INCOMPLETE`).
    #[error(
        "KEYSTORE_INCOMPLETE: a sealed value of subject {0} cannot be opened: its key is not \
         in this node's privacy keystore"
    )]
    KeyMissing(String),
}

/// A component linked once; every turn instantiates from it.
pub struct Program {
    engine: Engine,
    pre: ActorPre<TurnHost>,
    /// The same component through the world `actor-connections`, when it
    /// exports `connection-handler` (M24, ADR 0113): the export is optional.
    connections: Option<ActorConnectionsPre<TurnHost>>,
    /// Whether the component imports `kronik:actor/blobs` (M25).
    reads_blobs: bool,
    hash: CodeHash,
}

impl Program {
    pub(crate) fn new(
        engine: &Engine,
        component: &Component,
        hash: CodeHash,
    ) -> wasmtime::Result<Program> {
        let linker = build_linker(engine)?;
        let instance = linker.instantiate_pre(component)?;
        // Looked up semver-compatibly: a later 0.1.x export is found too. A
        // component that has the export with other types is invalid.
        let connections = match component.get_export_index(None, CONNECTION_HANDLER_EXPORT) {
            Some(_) => Some(ActorConnectionsPre::new(instance.clone())?),
            None => None,
        };
        let pre = ActorPre::new(instance)?;
        let reads_blobs = component
            .component_type()
            .imports(engine)
            .any(|(name, _)| name.starts_with(BLOBS_IMPORT));
        Ok(Program {
            engine: engine.clone(),
            pre,
            connections,
            reads_blobs,
            hash,
        })
    }

    pub fn hash(&self) -> CodeHash {
        self.hash
    }

    /// Whether the component exports `kronik:actor/connection-handler`, so
    /// it can take connection inputs (M24). A kind with WebSocket or SSE
    /// routes needs it.
    pub fn handles_connections(&self) -> bool {
        self.connections.is_some()
    }

    /// Whether the component imports `kronik:actor/blobs`, so it may get
    /// HTTP bodies and effect responses as blobs (M25, ADR 0119 §1). A
    /// component that does not keeps inline bodies and their limits.
    pub fn reads_blobs(&self) -> bool {
        self.reads_blobs
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
            blobs: None,
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
    /// outcome; only host failures are errors. A connection input (M24)
    /// calls the component's `connection-handler`, every other input
    /// `handle`.
    pub async fn run(
        &self,
        req: TurnRequest,
        state: Arc<dyn StateView>,
        sql: Option<Box<dyn SqlHost>>,
        gate: Option<Arc<dyn EffectGate>>,
    ) -> Result<TurnOutput, RunError> {
        self.run_with_blobs(req, state, sql, gate, None).await
    }

    /// [`Program::run`] with blob storage (M25): the turn may read the blobs
    /// its input references and create blobs through `blobs`. Without it,
    /// every blob function traps with `NOT_IMPLEMENTED`.
    pub async fn run_with_blobs(
        &self,
        req: TurnRequest,
        state: Arc<dyn StateView>,
        sql: Option<Box<dyn SqlHost>>,
        gate: Option<Arc<dyn EffectGate>>,
        blobs: Option<Arc<dyn BlobHost>>,
    ) -> Result<TurnOutput, RunError> {
        let call = match &req.input.kind {
            Some(pb::input::Kind::Connection(c)) => Call::Connection(connection_to_wit(c)?),
            _ => Call::Handle(input_to_wit(&req.input)?),
        };
        let fuel = req.limits.fuel;
        let message_bytes = req.limits.message_bytes;
        let with_blobs = blobs.is_some();
        let mut host = TurnHost::new(HostInit {
            actor: req.actor,
            causal_key: req.causal_key,
            now_ms: req.logical_time_ms,
            seed: req.seed,
            limits: req.limits,
            subject: req.subject,
            state: Some(state),
            sql,
            gate,
            blobs,
            describe_only: false,
        });
        // The connection an open input names is held, and opens when the
        // turn commits.
        let offered = match &call {
            Call::Connection(ConnCall::Open(o)) => {
                host.conns.opening = Some((o.connection.clone(), protocol_to_pb(o.protocol)));
                Some((o.subprotocols.clone(), o.protocol))
            }
            _ => None,
        };
        if with_blobs && self.reads_blobs {
            // A wasi:http request body above the kind's threshold becomes a
            // blob, as the gate makes a response above it one (M25 §7.6).
            host.spool_request_bodies_above(req.limits.blob_threshold);
        }
        if with_blobs {
            // The input's references are the turn's to read (ADR 0119 §2).
            let mut refs = Vec::new();
            kronik_proto::blobs::input(Some(&req.input), &mut refs);
            for blob in refs {
                host.blob_state.admit(blob.clone());
            }
        }
        let mut store = self.store(host, fuel)?;
        let result = match call {
            Call::Handle(input) => match self.pre.instantiate_async(&mut store).await {
                Ok(actor) => actor
                    .kronik_actor_handler()
                    .call_handle(&mut store, &input)
                    .await
                    .map(|r| r.map(Answer::Output)),
                Err(e) => Err(e),
            },
            Call::Connection(call) => match &self.connections {
                // Recorded as a failed turn, without running (M24 §2.3).
                None => Ok(Err(types::HandlerError::Failed(
                    "the kind's code does not handle connections: it does not export \
                     kronik:actor/connection-handler"
                        .into(),
                ))),
                Some(pre) => match pre.instantiate_async(&mut store).await {
                    Ok(actor) => {
                        let handler = actor.kronik_actor_connection_handler();
                        match call {
                            ConnCall::Open(o) => handler
                                .call_open(&mut store, &o)
                                .await
                                .map(|r| r.map(Answer::Open)),
                            ConnCall::Frame(f) => handler
                                .call_frame(&mut store, &f)
                                .await
                                .map(|r| r.map(|()| Answer::Output(types::Output::None))),
                            ConnCall::Close(c) => handler
                                .call_close(&mut store, &c)
                                .await
                                .map(|r| r.map(|()| Answer::Output(types::Output::None))),
                        }
                    }
                    Err(e) => Err(e),
                },
            },
        };
        let fuel_used = fuel - store.get_fuel().unwrap_or(0);
        let mut host = store.into_data();
        // Writers still open when the turn ends are discarded.
        let open = host.blob_state.take_open();
        if let Some(blobs) = &host.blobs {
            for writer in open {
                blobs.discard(writer);
            }
        }
        // A blob the actor held when the turn started is in `T` too: the
        // answer may use it (M26 §2). A lookup that fails is the turn's
        // failure below.
        if with_blobs {
            for blob in answer_refs(&result) {
                let _ = host.complete_ref(&blob);
            }
        }
        if let Some(fatal) = host.fatal.take() {
            return Err(fatal);
        }
        host.warn_unsent();
        let subject = host.subject.clone();
        let refs = with_blobs.then_some(&host.blob_state);
        let mut outcome = match result {
            Ok(Ok(Answer::Output(output))) => committed(output, subject, message_bytes, refs),
            Ok(Ok(Answer::Open(reply))) => {
                let (offered, protocol) = offered.unwrap_or((Vec::new(), conn_wit::Protocol::Sse));
                open_outcome(reply, &offered, protocol, subject, message_bytes, refs)
            }
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
            blob_refs: if ok {
                host.blob_state.ops()
            } else {
                Vec::new()
            },
            // A failed turn records no operation and sends nothing (§4.3).
            connection_ops: if ok {
                host.conns.take_ops()
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

/// What a turn calls: `handle`, or a `connection-handler` function (M24).
enum Call {
    Handle(types::Input),
    Connection(ConnCall),
}

enum ConnCall {
    Open(conn_wit::OpenRequest),
    Frame(conn_wit::IncomingFrame),
    Close(conn_wit::Closed),
}

/// What the guest answered.
enum Answer {
    Output(types::Output),
    Open(conn_wit::OpenReply),
}

/// Whether `subject` can be a subject: 1 to 256 bytes of printable ASCII
/// without spaces, such as `user:123` (the keystore's rule, m8-privacy §1).
fn valid_subject(subject: &str) -> bool {
    !subject.is_empty() && subject.len() <= 256 && subject.bytes().all(|b| b.is_ascii_graphic())
}

/// The outcome of an open turn that answered (M24 §4.2). An accept is
/// checked before the turn is recorded: its subprotocol is one the client
/// offered (none for SSE), its headers are valid and its subject is one. A
/// refusal is an HTTP response with a final status.
fn open_outcome(
    reply: conn_wit::OpenReply,
    offered: &[String],
    protocol: conn_wit::Protocol,
    subject: Option<String>,
    limit: usize,
    refs: Option<&TurnBlobs>,
) -> pb::Outcome {
    let bad = |m: String| failed(pb::OutcomeKind::Trap, "TURN_FAILED", m);
    match reply {
        conn_wit::OpenReply::Refuse(response) => {
            if !(200..=599).contains(&response.status) {
                return bad(format!(
                    "the open's refusal has status {}; refuse with a status from 200 to 599",
                    response.status
                ));
            }
            // A refusal's body may be a blob: the turn must hold it, as for
            // any response (M25 §5.4).
            committed(types::Output::Http(response), subject, limit, refs)
        }
        conn_wit::OpenReply::Accept(accept) => {
            // Recorded as its first position among the offered values, never
            // as the value: clients put bearer tokens there (§6.1, §8).
            let mut subprotocol_index = None;
            if let Some(p) = &accept.subprotocol {
                if protocol == conn_wit::Protocol::Sse {
                    return bad("the open's accept selects a subprotocol, but SSE has none".into());
                }
                match offered.iter().position(|o| o == p) {
                    Some(i) => subprotocol_index = u32::try_from(i).ok(),
                    None => {
                        return bad(
                            "the open's accept selects a subprotocol the client did not offer"
                                .into(),
                        );
                    }
                }
            }
            // A handshake's headers are bounded like a request head (review
            // L5): at most 64, of 16 KiB together.
            let header_bytes: usize = accept
                .headers
                .iter()
                .map(|h| h.name.len() + h.value.len())
                .sum();
            if accept.headers.len() > MAX_ACCEPT_HEADERS || header_bytes > MAX_ACCEPT_HEADER_BYTES {
                return bad(format!(
                    "the open's accept has {} headers of {header_bytes} bytes; the limit is \
                     {MAX_ACCEPT_HEADERS} headers of {MAX_ACCEPT_HEADER_BYTES} bytes",
                    accept.headers.len()
                ));
            }
            for h in &accept.headers {
                if http::HeaderName::from_bytes(h.name.as_bytes()).is_err()
                    || http::HeaderValue::from_str(&h.value).is_err()
                {
                    return bad(format!(
                        "the open's accept has an invalid header {:?}",
                        h.name
                    ));
                }
            }
            if let Some(s) = &accept.subject
                && !valid_subject(s)
            {
                return bad(format!(
                    "the open's accept sets the subject {s:?}, which is not one: 1 to 256 \
                     printable ASCII characters without spaces, such as user:123"
                ));
            }
            pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                error_code: String::new(),
                message: String::new(),
                output: Some(pb::outcome::Output::Accept(pb::ConnectionAccept {
                    subprotocol_index,
                    headers: accept
                        .headers
                        .into_iter()
                        .map(|h| pb::Header {
                            name: h.name,
                            value: Some(plain(subject.clone(), h.value.into_bytes())),
                        })
                        .collect(),
                    subject: accept.subject,
                })),
            }
        }
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

/// The outcome of a turn that returned `output`. A blob body must be one of
/// the turn's references (`refs`; None: blobs are off).
fn committed(
    output: types::Output,
    subject: Option<String>,
    limit: usize,
    refs: Option<&TurnBlobs>,
) -> pb::Outcome {
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
            if m.blobs.len() > crate::host::blobs::MAX_MESSAGE_BLOBS {
                return failed(
                    pb::OutcomeKind::Trap,
                    "TURN_FAILED",
                    format!(
                        "the reply carries {} blobs, the limit is {}",
                        m.blobs.len(),
                        crate::host::blobs::MAX_MESSAGE_BLOBS
                    ),
                );
            }
            let mut blobs = Vec::with_capacity(m.blobs.len());
            for blob in &m.blobs {
                match refs.map(|refs| refs.complete(blob)) {
                    None => {
                        return failed(
                            pb::OutcomeKind::Trap,
                            "NOT_IMPLEMENTED",
                            "NOT_IMPLEMENTED: blobs in messages are not available in this turn"
                                .into(),
                        );
                    }
                    Some(None) => {
                        return failed(
                            pb::OutcomeKind::Trap,
                            ErrorCode::BlobNotHeld.as_str(),
                            not_held(blob),
                        );
                    }
                    Some(Some(full)) => blobs.push(full),
                }
            }
            Some(pb::outcome::Output::Reply(message_to_pb(m, subject, blobs)))
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
                types::HttpBody::Blob(blob) => match refs.map(|refs| refs.complete(&blob)) {
                    None => {
                        return failed(
                            pb::OutcomeKind::Trap,
                            "NOT_IMPLEMENTED",
                            "NOT_IMPLEMENTED: blob bodies are not available in this turn".into(),
                        );
                    }
                    Some(None) => {
                        return failed(
                            pb::OutcomeKind::Trap,
                            ErrorCode::BlobNotHeld.as_str(),
                            not_held(&blob),
                        );
                    }
                    Some(Some(full)) => pb::body::Value::Blob(full),
                },
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

/// The guest references an answer names: a reply's blobs, or an HTTP
/// response body (also an open's refusal).
fn answer_refs(
    result: &wasmtime::Result<Result<Answer, types::HandlerError>>,
) -> Vec<crate::host::bindings::kronik::actor::types::BlobRef> {
    let http = |r: &types::HttpResponse| match &r.body {
        types::HttpBody::Blob(blob) => vec![blob.clone()],
        types::HttpBody::Inline(_) => Vec::new(),
    };
    match result {
        Ok(Ok(Answer::Output(types::Output::Reply(m)))) => m.blobs.clone(),
        Ok(Ok(Answer::Output(types::Output::Http(r)))) => http(r),
        Ok(Ok(Answer::Open(conn_wit::OpenReply::Refuse(r)))) => http(r),
        _ => Vec::new(),
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
    if e.downcast_ref::<crate::host::HostRedactionFailure>()
        .is_some()
    {
        // The ordinary finalizer below retains real meters and discards all
        // buffered writes/messages/timers. The durable effect stays in FxState.
        return failed(
            pb::OutcomeKind::Trap,
            "HOST_REDACTION_FAILURE",
            String::new(),
        );
    }
    if let Some(too_large) = e.downcast_ref::<crate::host::TurnTooLarge>() {
        // The gate refused an effect before it happened: the record has no
        // room for it. Writes, messages and timers are discarded below.
        return failed(
            pb::OutcomeKind::Trap,
            ErrorCode::TurnTooLarge.as_str(),
            too_large.0.clone(),
        );
    }
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
    } else if msg.starts_with("BLOB_NOT_HELD") {
        ErrorCode::BlobNotHeld.as_str()
    } else if msg.starts_with("BLOB_QUOTA_EXCEEDED") {
        ErrorCode::BlobQuotaExceeded.as_str()
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
        // The caller opens sealed values first; one still sealed here has no
        // key in this node's keystore.
        Some(pb::sealable::Value::Sealed(_)) => Err(RunError::KeyMissing(
            s.and_then(|s| s.subject.clone())
                .unwrap_or_else(|| "?".into()),
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

fn http_to_wit(h: &pb::HttpInput) -> Result<types::HttpRequest, RunError> {
    Ok(types::HttpRequest {
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
                    value: String::from_utf8_lossy(&sealed_bytes(hd.value.as_ref())?).into_owned(),
                })
            })
            .collect::<Result<_, RunError>>()?,
        body: body_to_wit(h.body.as_ref())?,
    })
}

fn protocol_to_pb(p: conn_wit::Protocol) -> pb::ConnectionProtocol {
    match p {
        conn_wit::Protocol::Websocket => pb::ConnectionProtocol::Websocket,
        conn_wit::Protocol::Sse => pb::ConnectionProtocol::Sse,
    }
}

fn frame_to_wit(f: Option<&pb::Frame>) -> Result<conn_wit::Frame, RunError> {
    let f =
        f.ok_or_else(|| RunError::Input("a connection frame input without its frame".into()))?;
    let data = sealed_bytes(f.data.as_ref())?;
    Ok(match pb::frame::Kind::try_from(f.kind) {
        Ok(pb::frame::Kind::Text) => {
            conn_wit::Frame::Text(String::from_utf8_lossy(&data).into_owned())
        }
        Ok(pb::frame::Kind::Binary) => conn_wit::Frame::Binary(data),
        Ok(pb::frame::Kind::Event) => conn_wit::Frame::Event(conn_wit::SseEvent {
            event: f.event.clone(),
            id: f.id.clone(),
            data: String::from_utf8_lossy(&data).into_owned(),
        }),
        _ => return Err(RunError::Input("a frame without a kind".into())),
    })
}

/// The most headers an open's accept may set, and their bytes together.
pub const MAX_ACCEPT_HEADERS: usize = 64;
pub const MAX_ACCEPT_HEADER_BYTES: usize = 16 << 10;

/// The subprotocols a WebSocket client offered: its `Sec-WebSocket-Protocol`
/// headers in order, each split at commas and trimmed (RFC 6455 §4.1). They
/// come from the recorded request, whose headers are sealable, because
/// browsers put bearer tokens there (M24 §8); the log keeps no other copy.
fn offered_subprotocols(headers: &[types::Header]) -> Vec<String> {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("sec-websocket-protocol"))
        .flat_map(|h| h.value.split(','))
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The `connection-handler` call of a connection input (M24): the open's
/// request, an incoming frame, or the close; a host close's reason is its
/// cause, such as `restart`.
fn connection_to_wit(c: &pb::ConnectionInput) -> Result<ConnCall, RunError> {
    use pb::connection_input::Event;
    let protocol = match pb::ConnectionProtocol::try_from(c.protocol) {
        Ok(pb::ConnectionProtocol::Websocket) => conn_wit::Protocol::Websocket,
        Ok(pb::ConnectionProtocol::Sse) => conn_wit::Protocol::Sse,
        _ => {
            return Err(RunError::Input(
                "a connection input without a protocol".into(),
            ));
        }
    };
    Ok(match &c.event {
        Some(Event::Open(o)) => {
            let request =
                http_to_wit(o.request.as_ref().ok_or_else(|| {
                    RunError::Input("a connection open without its request".into())
                })?)?;
            let subprotocols = offered_subprotocols(&request.headers);
            ConnCall::Open(conn_wit::OpenRequest {
                connection: c.connection.clone(),
                protocol,
                request,
                subprotocols,
            })
        }
        Some(Event::Frame(f)) => ConnCall::Frame(conn_wit::IncomingFrame {
            connection: c.connection.clone(),
            seq: f.seq,
            frame: frame_to_wit(f.frame.as_ref())?,
        }),
        Some(Event::Close(close)) => {
            let initiator = match pb::CloseCause::try_from(close.cause) {
                Ok(pb::CloseCause::Client) => conn_wit::CloseInitiator::Client,
                Ok(pb::CloseCause::Actor) => conn_wit::CloseInitiator::Actor,
                _ => conn_wit::CloseInitiator::Host,
            };
            let reason = match initiator {
                conn_wit::CloseInitiator::Host => {
                    kronik_proto::connection::cause_name(close.cause).to_owned()
                }
                _ => String::from_utf8_lossy(&sealed_bytes(close.reason.as_ref())?).into_owned(),
            };
            ConnCall::Close(conn_wit::Closed {
                connection: c.connection.clone(),
                info: conn_wit::CloseInfo {
                    initiator,
                    code: u16::try_from(close.code).unwrap_or(u16::MAX),
                    reason,
                },
            })
        }
        None => {
            return Err(RunError::Input(
                "a connection input without an event".into(),
            ));
        }
    })
}

fn input_to_wit(input: &pb::Input) -> Result<types::Input, RunError> {
    use pb::input::Kind;
    Ok(match &input.kind {
        Some(Kind::Http(h)) => types::Input::Http(http_to_wit(h)?),
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
        // M24: `connection-handler` takes these, not `handle`.
        Some(Kind::Connection(_)) => {
            return Err(RunError::Input(
                "a connection input is not an input of handle".into(),
            ));
        }
        None => return Err(RunError::Input("input has no case".into())),
    })
}
