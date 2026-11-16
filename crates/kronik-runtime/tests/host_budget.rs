//! A turn's host-side buffers are bounded per turn (issue #121): guest logs,
//! stdout/stderr, state writes, messages and timers share the kind's memory
//! limit, and passing it traps the turn with `TURN_TOO_LARGE` instead of
//! growing the daemon's RSS.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CodeStore, PoolSize, Program, StateView, TurnLimits, TurnOutput, TurnRequest, build_engine,
};

const COUNTER_BUDGET: &[u8] = include_bytes!("../../../tests/guests/counter-budget.wasm");

struct Empty;

impl StateView for Empty {
    fn get(&self, _: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    fn keys(&self, _: &str) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    fn timer_pending(&self, _: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn connection(&self, _: &str) -> Result<Option<kronik_runtime::ConnectionView>, String> {
        Ok(None)
    }
}

fn program() -> Arc<Program> {
    let code = CodeStore::new(build_engine(PoolSize { concurrency: 2 }).unwrap(), None).unwrap();
    code.add(COUNTER_BUDGET).unwrap().1
}

/// A message whose body is `<mode> <count> 8`, for the guest's `budget`
/// operation.
async fn run(program: &Program, mode: &str, count: usize, host_bytes: usize) -> TurnOutput {
    run_body(program, &format!("{mode} {count} 8"), host_bytes).await
}

async fn run_body(program: &Program, body: &str, host_bytes: usize) -> TurnOutput {
    let limits = TurnLimits {
        host_bytes,
        ..TurnLimits::default()
    };
    let input = pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Operator as i32,
            msg: Some(pb::Message {
                name: "budget".into(),
                content_type: "text/plain".into(),
                body: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
                }),
                blobs: vec![],
                retained_compensation_source: None,
            }),
            message_id: "m".into(),
            ..Default::default()
        })),
    };
    program
        .run(
            TurnRequest {
                actor: ActorRef::parse("counter/a").unwrap(),
                causal_key: kronik_core::causal::root("r".into()),
                logical_time_ms: 1_761_300_000_000,
                seed: [7; 32],
                input,
                limits,
                subject: None,
            },
            Arc::new(Empty),
            None,
            None,
        )
        .await
        .unwrap()
}

/// Each host accumulator is charged as it is written, so a loop that passes
/// the budget traps with TURN_TOO_LARGE and commits none of its outputs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_host_accumulator_stops_at_the_budget() {
    let program = program();
    for mode in ["log", "stdout", "state", "send", "timer"] {
        let out = run(&program, mode, 4, 400).await;
        assert_eq!(
            out.outcome.error_code, "TURN_TOO_LARGE",
            "{mode}: {:?}",
            out.outcome
        );
        assert_eq!(
            out.outcome.kind,
            pb::OutcomeKind::Trap as i32,
            "{mode}: {:?}",
            out.outcome
        );
        assert!(
            out.outcome.message.contains("host budget"),
            "{mode}: {}",
            out.outcome.message
        );
        assert!(out.writes.is_empty(), "{mode}: {:?}", out.writes);
        assert!(out.messages.is_empty(), "{mode}: {:?}", out.messages);
        assert!(out.timers.is_empty(), "{mode}: {:?}", out.timers);
        assert!(
            out.connection_ops.is_empty(),
            "{mode}: {:?}",
            out.connection_ops
        );
        if mode == "log" || mode == "stdout" {
            // The entries that fit stay readable; the trap stopped the rest.
            assert!(out.logs.len() < 4, "{mode}: {:?}", out.logs);
        } else {
            assert!(out.logs.is_empty(), "{mode}: {:?}", out.logs);
        }
    }
}

/// The default 64 MiB budget stops a loop of large log messages, rather than
/// letting one turn hold many times the documented memory limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_default_budget_stops_large_log_messages() {
    let program = program();
    let out = run_body(&program, "log 4 20000000", 64 << 20).await;
    assert_eq!(
        out.outcome.error_code, "TURN_TOO_LARGE",
        "{:?}",
        out.outcome
    );
    assert!(!out.logs.is_empty(), "{:?}", out.logs);
    let held: usize = out.logs.iter().map(|e| e.message.len()).sum();
    assert!(held <= 64 << 20, "{held} bytes of logs held");
}

/// Below the budget the same turn commits all its buffered output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_host_accumulator_commits_below_the_budget() {
    let program = program();
    for mode in ["log", "stdout", "state", "send", "timer"] {
        let out = run(&program, mode, 4, 1 << 20).await;
        assert_eq!(out.outcome.error_code, "", "{mode}: {:?}", out.outcome);
        assert_eq!(
            out.outcome.kind,
            pb::OutcomeKind::Committed as i32,
            "{mode}: {:?}",
            out.outcome
        );
        match mode {
            "log" | "stdout" => assert!(out.logs.len() >= 4, "{mode}: {:?}", out.logs),
            "state" => assert_eq!(out.writes.len(), 4, "{mode}: {:?}", out.writes),
            "send" => assert_eq!(out.messages.len(), 4, "{mode}: {:?}", out.messages),
            "timer" => assert_eq!(out.timers.len(), 4, "{mode}: {:?}", out.timers),
            _ => unreachable!(),
        }
    }
}
