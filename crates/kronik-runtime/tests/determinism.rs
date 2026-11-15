//! The determinism test (brief: "the same input twice on fresh instances
//! gives a byte-identical outcome", every commit): each input runs twice on
//! fresh instances with the same seed, logical time, causal key and state,
//! and the encoded outcome, writes, messages, fuel and logs must be equal.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kronik_core::env::BoxFuture;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CallOutcome, CodeStore, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchOutcome, FetchRequest,
    GateError, PoolSize, Program, StateView, TurnLimits, TurnRequest, build_engine,
};
use prost::Message as _;

const COUNTER: &[u8] = include_bytes!("../../../tests/guests/counter.wasm");

struct Map(BTreeMap<String, Vec<u8>>);

impl StateView for Map {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.get(key).cloned())
    }
    fn keys(&self, prefix: &str) -> Result<Vec<String>, String> {
        Ok(self
            .0
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    fn timer_pending(&self, _id: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn connection(&self, _: &str) -> Result<Option<kronik_runtime::ConnectionView>, String> {
        Ok(None)
    }
}

fn message(name: &str, body: &[u8]) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Operator as i32,
            msg: Some(pb::Message {
                name: name.into(),
                content_type: "text/plain".into(),
                body: Some(pb::Sealable {
                    subject: Some("user:7".into()),
                    value: Some(pb::sealable::Value::Plain(body.to_vec())),
                }),
                blobs: vec![],
                retained_compensation_source: None,
            }),
            message_id: "m".into(),
            ..Default::default()
        })),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_input_twice_gives_byte_identical_outcomes() {
    let engine = build_engine(PoolSize { concurrency: 4 }).unwrap();
    let code = CodeStore::new(engine, None).unwrap();
    let (_, program) = code.add(COUNTER).unwrap();
    let state = Arc::new(Map(BTreeMap::from([("n".to_string(), b"41".to_vec())])));
    let limits = TurnLimits {
        fuel: 5_000_000,
        ..TurnLimits::default()
    };
    let inputs = [
        message("increment", b""),
        message("probe", b""),
        message("forward", b"other"),
        message("subject", b""),
        message("spin", b"10000"),
        message("spin", b"x"),
        message("fail", b""),
        message("trap", b""),
        message("big", b"2000000"),
    ];
    for (i, input) in inputs.iter().enumerate() {
        let run = || async {
            let out = program
                .run(
                    TurnRequest {
                        actor: ActorRef::parse("counter/a").unwrap(),
                        causal_key: kronik_core::causal::root(format!("root{i}")),
                        logical_time_ms: 1_761_300_000_000 + i as u64,
                        seed: [i as u8; 32],
                        input: input.clone(),
                        limits,
                        subject: Some("user:7".into()),
                    },
                    state.clone(),
                    None,
                    None,
                )
                .await
                .unwrap();
            let record = pb::TurnRecord {
                outcome: Some(out.outcome),
                writes: out.writes,
                messages: out.messages,
                fuel_used: out.fuel_used,
                memory_peak_bytes: out.memory_peak_bytes,
                ..Default::default()
            };
            (record.encode_to_vec(), format!("{:?}", out.logs), record)
        };
        let (a, la, rec) = run().await;
        let (b, lb, _) = run().await;
        assert_eq!(a, b, "input {i} differs between runs: {rec:?}");
        assert_eq!(la, lb, "input {i} logs differ");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outcomes_classify_failures() {
    let engine = build_engine(PoolSize { concurrency: 2 }).unwrap();
    let code = CodeStore::new(engine, None).unwrap();
    let (_, program) = code.add(COUNTER).unwrap();
    let state = Arc::new(Map(BTreeMap::new()));
    let limits = TurnLimits {
        fuel: 5_000_000,
        ..TurnLimits::default()
    };
    let run = |input: pb::Input| {
        let state = state.clone();
        let program = program.clone();
        async move {
            program
                .run(
                    TurnRequest {
                        actor: ActorRef::parse("counter/a").unwrap(),
                        causal_key: kronik_core::causal::root("r".into()),
                        logical_time_ms: 1,
                        seed: [0; 32],
                        input,
                        limits,
                        subject: None,
                    },
                    state,
                    None,
                    None,
                )
                .await
                .unwrap()
        }
    };
    let k = |o: &kronik_runtime::TurnOutput| pb::OutcomeKind::try_from(o.outcome.kind).unwrap();
    assert_eq!(
        k(&run(message("spin", b"x")).await),
        pb::OutcomeKind::FuelExhausted
    );
    assert_eq!(k(&run(message("trap", b"")).await), pb::OutcomeKind::Trap);
    assert_eq!(k(&run(message("fail", b"")).await), pb::OutcomeKind::Failed);
    assert_eq!(
        k(&run(message("reject", b"")).await),
        pb::OutcomeKind::Rejected
    );
    let big = run(message("big", b"2000000")).await;
    assert_eq!(k(&big), pb::OutcomeKind::Trap);
    assert!(big.outcome.message.contains("limit"), "{:?}", big.outcome);
    // set-for tags the write with its own subject; set uses the default.
    let s = run(message("subject", b"")).await;
    let subjects: Vec<_> = s
        .writes
        .iter()
        .map(|w| (w.key.clone(), w.value.as_ref().unwrap().subject.clone()))
        .collect();
    assert_eq!(
        subjects,
        [
            ("s".to_string(), Some("user:1".to_string())),
            ("t".to_string(), Some("user:2".to_string()))
        ]
    );
}

/// Runs the callee of a call on the same program inside the caller's
/// `call`, as a replay does, and keeps whether the pool had room for it
/// and its outcome.
struct Nested {
    program: Arc<Program>,
    state: Arc<Map>,
    callee: Arc<Mutex<Option<(bool, pb::Outcome)>>>,
}

impl EffectGate for Nested {
    fn fetch(
        &self,
        _ordinal: u32,
        _req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        Box::pin(async { Ok(FetchOutcome::Network("no network here".into())) })
    }
    fn call(
        &self,
        _ordinal: u32,
        to: ActorRef,
        msg: pb::Message,
        _compensate: Option<pb::Message>,
    ) -> BoxFuture<'static, Result<CallOutcome, GateError>> {
        let (program, state, callee) = (
            self.program.clone(),
            self.state.clone(),
            self.callee.clone(),
        );
        Box::pin(async move {
            let out = program
                .run(
                    TurnRequest {
                        actor: to,
                        causal_key: kronik_core::causal::root("callee".into()),
                        logical_time_ms: 1,
                        seed: [0; 32],
                        input: message(&msg.name, b""),
                        limits: TurnLimits::default(),
                        subject: None,
                    },
                    state,
                    None,
                    None,
                )
                .await
                .map_err(|e| GateError::Host(e.to_string()))?;
            *callee.lock().unwrap() = Some((out.pool_exhausted, out.outcome));
            Ok(CallOutcome::Failed("the callee did not commit".into()))
        })
    }
    fn crypto(
        &self,
        _ordinal: u32,
        _algorithm: CryptoAlgorithm,
        _secret: String,
        _data: Vec<u8>,
    ) -> BoxFuture<'static, Result<CryptoOutcome, GateError>> {
        Box::pin(async { Ok(CryptoOutcome::Unsupported("none".into())) })
    }
    fn reveal(
        &self,
        _ordinal: u32,
        _name: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>> {
        Box::pin(async { Ok(Err("none".into())) })
    }
}

/// A turn the instance pool has no room for did not run: its outcome is
/// the `TURN_FAILED` a daemon records, marked `pool_exhausted` so that a
/// replay does not take it for the code's failure. With one instance, the
/// callee of a call that runs while its caller waits has none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_turn_without_room_in_the_pool_is_marked_as_not_run() {
    let engine = build_engine(PoolSize { concurrency: 1 }).unwrap();
    let code = CodeStore::new(engine, None).unwrap();
    let (_, program) = code.add(COUNTER).unwrap();
    let state = Arc::new(Map(BTreeMap::new()));
    let callee = Arc::new(Mutex::new(None));
    let gate = Arc::new(Nested {
        program: program.clone(),
        state: state.clone(),
        callee: callee.clone(),
    });
    let run = |input: pb::Input, gate: Option<Arc<dyn EffectGate>>| {
        let (program, state) = (program.clone(), state.clone());
        async move {
            program
                .run(
                    TurnRequest {
                        actor: ActorRef::parse("counter/a").unwrap(),
                        causal_key: kronik_core::causal::root("caller".into()),
                        logical_time_ms: 1,
                        seed: [0; 32],
                        input,
                        limits: TurnLimits::default(),
                        subject: None,
                    },
                    state,
                    None,
                    gate,
                )
                .await
                .unwrap()
        }
    };
    let gate: Arc<dyn EffectGate> = gate;
    let caller = run(message("call", b"counter/b increment"), Some(gate)).await;
    let (exhausted, outcome) = callee.lock().unwrap().take().expect("the call ran");
    assert!(exhausted, "{outcome:?}");
    assert_eq!(outcome.error_code, "TURN_FAILED");
    assert!(
        outcome
            .message
            .contains("maximum concurrent limit of 1 for"),
        "{outcome:?}"
    );
    // The caller ran, and so does a guest that fails on its own.
    assert!(
        caller.committed() && !caller.pool_exhausted,
        "{:?}",
        caller.outcome
    );
    let failed = run(message("fail", b""), None).await;
    assert!(
        !failed.committed() && !failed.pool_exhausted,
        "{:?}",
        failed.outcome
    );
}
