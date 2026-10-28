//! The determinism test for SDK components built elsewhere (M15: the
//! Python and Go examples, `scripts/ci.sh sdks`; review M15 round 3). Every
//! component in `KRONIK_DETERMINISM_COMPONENTS` (absolute paths separated
//! by `:`) runs a sequence of inputs twice, each time in a fresh world: its
//! migration, a `configure` message, every route with real ids (POST and PUT
//! first, then GET, then DELETE), two more messages, and the timers its
//! turns scheduled. Each turn gets the scheduler's real SQL host (the actor
//! database, opened per turn) and a stub effect gate; committed turns are
//! applied to the world's store as the scheduler applies them. Every turn's
//! outcome, writes, messages, timers, SQL changes, fuel and logs, and the
//! effects it asked for, must be byte-identical between the two runs. The
//! sequence must also get somewhere: turns commit, GETs by a created id
//! answer 200, and an effect that fails is retried by a timer. Without the
//! variable there is nothing to check.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use kronik_core::env::BoxFuture;
use kronik_core::ids::ActorRef;
use kronik_log::{Committed, Position};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CallOutcome, CodeStore, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchOutcome, FetchRequest,
    FetchResponse, GateError, PoolSize, Program, TurnLimits, TurnRequest, build_engine,
};
use kronik_sched::host::{KvView, SqlHandle, SqlTurn};
use kronik_store::Store;
use kronik_store::sql::TurnOpts;
use prost::Message as _;

/// Answers effects without a network and records what they asked: the
/// first fetch fails with 503 (a relay retries it by timer), later ones get
/// 200.
#[derive(Default)]
struct StubGate {
    calls: Mutex<Vec<String>>,
}

impl EffectGate for StubGate {
    fn fetch(
        &self,
        ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        let mut calls = self.calls.lock().unwrap();
        let first = !calls.iter().any(|c| c.starts_with("fetch"));
        calls.push(format!("fetch #{ordinal} {req:?}"));
        Box::pin(async move {
            Ok(FetchOutcome::Ok(FetchResponse {
                status: if first { 503 } else { 200 },
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"ok":true}"#.to_vec(),
            }))
        })
    }
    fn call(
        &self,
        ordinal: u32,
        to: ActorRef,
        msg: pb::Message,
        _: Option<pb::Message>,
    ) -> BoxFuture<'static, Result<CallOutcome, GateError>> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("call #{ordinal} {to} {msg:?}"));
        Box::pin(async { Ok(CallOutcome::Ok(None)) })
    }
    fn crypto(
        &self,
        ordinal: u32,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> BoxFuture<'static, Result<CryptoOutcome, GateError>> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("crypto #{ordinal} {algorithm:?} {secret} {data:?}"));
        let mut key = secret.into_bytes();
        key.extend_from_slice(&data);
        let mac = blake3::hash(&key).as_bytes().to_vec();
        Box::pin(async move { Ok(CryptoOutcome::Ok(mac)) })
    }
    fn reveal(
        &self,
        ordinal: u32,
        name: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("reveal #{ordinal} {name}"));
        Box::pin(async { Ok(Err("CAPABILITY_NOT_GRANTED".into())) })
    }
}

/// What one turn produced, encoded for the comparison.
struct Turn {
    bytes: Vec<u8>,
    logs: String,
    calls: Vec<String>,
    record: pb::TurnRecord,
}

/// A fresh store the committed turns are applied to, and a stub gate.
struct World {
    store: Arc<Store>,
    lsn: u64,
    gate: Arc<StubGate>,
}

impl World {
    fn new() -> World {
        World {
            store: Store::memory().unwrap(),
            lsn: 0,
            gate: Arc::new(StubGate::default()),
        }
    }

    async fn turn(
        &mut self,
        program: &Program,
        actor: &ActorRef,
        i: usize,
        input: &pb::Input,
    ) -> Turn {
        let migrate = matches!(input.kind, Some(pb::input::Kind::Migrate(_)));
        let time = 1_761_300_000_000 + i as u64 * 1000;
        let seed = [i as u8; 32];
        let limits = TurnLimits::default();
        let sql = Arc::new(Mutex::new(SqlTurn::new(
            self.store.clone(),
            actor,
            TurnOpts {
                seed,
                time_ms: time as i64,
                default_subject: None,
                migrate,
                sql_budget: limits.fuel,
                max_bytes: 0,
            },
        )));
        let state = Arc::new(KvView {
            store: self.store.clone(),
            actor: actor.clone(),
            sealer: Arc::new(kronik_privacy::sealer::Sealer::plain()),
        });
        let before = self.gate.calls.lock().unwrap().len();
        let key = kronik_core::causal::root(format!("root{i}"));
        let mut out = program
            .run(
                TurnRequest {
                    actor: actor.clone(),
                    causal_key: key.clone(),
                    logical_time_ms: time,
                    seed,
                    input: input.clone(),
                    limits,
                    subject: None,
                },
                state,
                Some(Box::new(SqlHandle(sql.clone()))),
                Some(self.gate.clone()),
            )
            .await
            .unwrap();
        drop(out.sql.take());
        let committed = out.committed();
        let mut record = pb::TurnRecord {
            actor: Some(actor.to_pb()),
            causal_key: Some(key),
            logical_time_ms: time,
            random_seed: seed.to_vec(),
            input: Some(input.clone()),
            outcome: Some(out.outcome),
            writes: out.writes,
            messages: out.messages,
            timers: out.timers,
            fuel_used: out.fuel_used,
            memory_peak_bytes: out.memory_peak_bytes,
            ..Default::default()
        };
        if let Some(t) = sql.lock().unwrap().end(committed, &[]).unwrap() {
            record.sql_schema = t
                .ddl
                .into_iter()
                .map(|statement| pb::SqlSchemaChange { statement })
                .collect();
            record.sql_changes = t
                .changesets
                .into_iter()
                .map(|(subject, cs)| pb::SqlChangeset {
                    changeset: Some(pb::Sealable {
                        subject,
                        value: Some(pb::sealable::Value::Plain(cs)),
                    }),
                })
                .collect();
        }
        if committed {
            self.lsn += 1;
            self.store
                .apply(&[Committed {
                    lsn: self.lsn,
                    pos: Position {
                        segment: 0,
                        offset: 0,
                    },
                    record: Record::TurnRecord(record.clone()),
                }])
                .unwrap();
        }
        let calls = self.gate.calls.lock().unwrap()[before..].to_vec();
        Turn {
            bytes: record.encode_to_vec(),
            logs: format!("{:?}", out.logs),
            calls,
            record,
        }
    }
}

fn sealable(b: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(b.to_vec())),
    })
}

fn message(name: &str, body: &[u8]) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Operator as i32,
            msg: Some(pb::Message {
                name: name.into(),
                content_type: "application/json".into(),
                body: sealable(body),
                blobs: vec![],
            }),
            message_id: format!("m-{name}"),
            ..Default::default()
        })),
    }
}

/// An HTTP input for `pattern`, as the gateway builds it: `{key}` is
/// `alice`, `{id}` the newest id a response gave (else `1`).
fn http(method: &str, pattern: &str, id: &str, body: &[u8]) -> pb::Input {
    let mut params = Vec::new();
    let path: Vec<String> = pattern
        .split('/')
        .map(
            |seg| match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(name) => {
                    let value = if name == "key" { "alice" } else { id };
                    params.push(pb::Param {
                        name: name.into(),
                        value: value.into(),
                        sealed_value: None,
                    });
                    value.to_string()
                }
                None => seg.to_string(),
            },
        )
        .collect();
    pb::Input {
        kind: Some(pb::input::Kind::Http(pb::HttpInput {
            method: method.into(),
            path: path.join("/"),
            params,
            route: pattern.into(),
            headers: vec![pb::Header {
                name: "content-type".into(),
                value: sealable(b"application/json"),
            }],
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(body.to_vec())),
                })),
            }),
            ..Default::default()
        })),
    }
}

/// The HTTP status and JSON body of a turn's response.
fn response(record: &pb::TurnRecord) -> Option<(u32, serde_json::Value)> {
    match record.outcome.as_ref()?.output.as_ref()? {
        pb::outcome::Output::Http(h) => {
            let body = match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => {
                        serde_json::from_slice(b).unwrap_or_default()
                    }
                    _ => serde_json::Value::Null,
                },
                _ => serde_json::Value::Null,
            };
            Some((h.status, body))
        }
        _ => None,
    }
}

fn committed(r: &pb::TurnRecord) -> bool {
    r.outcome
        .as_ref()
        .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_components_give_byte_identical_outcomes() {
    let Some(paths) = std::env::var_os("KRONIK_DETERMINISM_COMPONENTS") else {
        eprintln!("KRONIK_DETERMINISM_COMPONENTS is not set: no SDK components to check");
        return;
    };
    let engine = build_engine(PoolSize { concurrency: 2 }).unwrap();
    let code = CodeStore::new(engine, None).unwrap();
    const BODY: &[u8] = br#"{"title":"t","body":"b","event":"paid","amount":42}"#;
    // A trailing `:` (as `printf '%s:'` writes the list) is no component.
    for path in std::env::split_paths(&paths).filter(|p| !p.as_os_str().is_empty()) {
        let name = path.display().to_string();
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        let (_, program) = code.add(&bytes).unwrap();
        let manifest = program.describe(TurnLimits::default()).await.unwrap();
        let actor = ActorRef::parse(&format!("{}/alice", manifest.kind)).unwrap();

        // The first run picks the inputs (ids from responses, timers from
        // turns); the second runs the same inputs in a fresh world.
        let mut world = World::new();
        let mut inputs = Vec::new();
        let mut first = Vec::new();
        let mut id = "1".to_string();
        let mut by_id_ok = 0;
        let mut planned: Vec<pb::Input> = vec![
            pb::Input {
                kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
                    from_schema_version: 0,
                    to_schema_version: manifest.schema_version,
                })),
            },
            message(
                "configure",
                br#"{"target":"https://webhooks.example.com/relay"}"#,
            ),
        ];
        let mut routes = manifest.routes.clone();
        routes.sort_by_key(|r| match r.method.as_str() {
            "POST" | "PUT" => 0,
            "GET" => 1,
            _ => 2,
        });
        let mut i = 0;
        let mut pending_routes = routes.into_iter();
        let mut tail = vec![message("increment", b""), message("no-such-message", b"{}")];
        loop {
            let input = if !planned.is_empty() {
                planned.remove(0)
            } else if let Some(r) = pending_routes.next() {
                http(&r.method, &r.pattern, &id, BODY)
            } else if !tail.is_empty() {
                tail.remove(0)
            } else {
                break;
            };
            let t = world.turn(&program, &actor, i, &input).await;
            if let Some((status, body)) = response(&t.record) {
                if let Some(new) = body["id"]
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| body["id"].as_i64().map(|n| n.to_string()))
                {
                    id = new;
                }
                if status == 200 && t.record.input.as_ref().is_some_and(|i| matches!(&i.kind, Some(pb::input::Kind::Http(h)) if h.method == "GET" && h.route.contains("{id}"))) {
                    by_id_ok += 1;
                }
            }
            if committed(&t.record) {
                for op in &t.record.timers {
                    if op.kind == pb::TimerOpKind::Schedule as i32 {
                        tail.push(pb::Input {
                            kind: Some(pb::input::Kind::Timer(pb::TimerInput {
                                timer_id: op.timer_id,
                                msg: op.msg.clone(),
                                due_ms: op.due_ms,
                                scheduled_by: String::new(),
                            })),
                        });
                    }
                }
            }
            inputs.push(input);
            first.push(t);
            i += 1;
        }

        let mut again = World::new();
        for (i, input) in inputs.iter().enumerate() {
            let b = again.turn(&program, &actor, i, input).await;
            let a = &first[i];
            assert_eq!(
                a.bytes, b.bytes,
                "{name}: input {i} differs between runs: {:?}",
                a.record
            );
            assert_eq!(a.logs, b.logs, "{name}: input {i} logs differ");
            assert_eq!(a.calls, b.calls, "{name}: input {i} effects differ");
        }

        // It got somewhere.
        let commits = first.iter().filter(|t| committed(&t.record)).count();
        let fetches = first
            .iter()
            .flat_map(|t| &t.calls)
            .filter(|c| c.starts_with("fetch"))
            .count();
        let timers = first
            .iter()
            .filter(|t| {
                matches!(
                    t.record.input.as_ref().and_then(|i| i.kind.as_ref()),
                    Some(pb::input::Kind::Timer(_))
                )
            })
            .filter(|t| committed(&t.record))
            .count();
        let fuel: Vec<String> = first
            .iter()
            .map(|t| format!("{:.2}M", t.record.fuel_used as f64 / 1e6))
            .collect();
        eprintln!(
            "{name}: {} inputs identical twice: {commits} committed, {by_id_ok} GETs by id answered 200, {fetches} fetches, {timers} timers; fuel {}",
            inputs.len(),
            fuel.join(" ")
        );
        assert!(commits >= 3, "{name}: only {commits} turns committed");
        if manifest.routes.iter().any(|r| r.pattern.contains("{id}")) {
            assert!(by_id_ok > 0, "{name}: no GET by a created id answered 200");
        }
        if fetches > 0 {
            assert!(
                fetches >= 2 && timers > 0,
                "{name}: the failed fetch was not retried by a committed timer"
            );
        }
    }
}
