//! The determinism test (brief: "the same input twice on fresh instances
//! gives a byte-identical outcome", every commit): each input runs twice on
//! fresh instances with the same seed, logical time, causal key and state,
//! and the encoded outcome, writes, messages, fuel and logs must be equal.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{CodeStore, PoolSize, StateView, TurnLimits, TurnRequest, build_engine};
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
