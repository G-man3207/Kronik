//! The mini daemon: written only against [`Env`], `tokio::sync` and
//! `futures`, so the same code runs on tokio in production and on the
//! deterministic simulator.
//!
//! Request path: ingress idempotency check, per-actor serialization, logical
//! time (I15), a fresh Wasm instance, `TurnBegin` fsynced before the first
//! external effect (I14), `EffectResult` fsynced before the guest sees it,
//! `TurnRecord` fsynced, applied in LSN order by a single applier, then the
//! response. Recovery re-applies the log tail and re-runs every `TurnBegin`
//! without a `TurnRecord` with its recorded inputs and effect results.

pub mod log;
pub mod replay;
pub mod state;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, mpsc, oneshot};

use crate::env::{BoxFuture, Env, HttpRequest, NetError};
use crate::wasm::{Code, EffectGate, StateRead, TurnSpec};
use log::{EffectOutcome, EffectResult, Log, Outcome, Record, TurnBegin, TurnRecord};
use state::StateDb;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryClass {
    IdempotencyKeyed,
    Unsafe,
}

#[derive(Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub delivery: DeliveryClass,
    pub effect_timeout: Duration,
    /// Deliberate bugs, to prove the simulator's invariants catch them.
    pub mutation: Option<Mutation>,
}

/// Spike-only fault seeding ("mutation testing" of the DST harness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// Send the effect without waiting for the durable `TurnBegin` (I14).
    EffectBeforeTurnBegin,
    /// The log writer acknowledges appends before `fdatasync`.
    AckBeforeFsync,
    /// Recovery does not truncate a torn tail and appends after it.
    NoTruncateTail,
    /// The segment's directory entry is never fsynced.
    NoDirSync,
    /// Logical time is the wall clock only (I15).
    WallClockTime,
    /// Recovery skips re-running `TurnBegin`s without a `TurnRecord`.
    NoRerun,
    /// Recovery re-runs pending turns in `HashMap` (RandomState) order.
    HashMapRerunOrder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub actor_key: String,
    pub ingress_key: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Observations for tests and metrics. Production: tracing; simulation:
/// event trace plus invariant checks.
#[derive(Debug, Clone)]
pub enum Event {
    TimeAssigned {
        actor: String,
        time_ms: u64,
    },
    Committed {
        lsn: u64,
        actor: String,
        ingress_key: String,
        ok: bool,
    },
    Recovered {
        applied_from: u64,
        applied: u64,
        reruns: usize,
        truncated: u64,
        valid_after_tear: u32,
        hwm: u64,
    },
    Fatal(String),
    Violation(String),
}

pub trait Probe: Send + Sync + 'static {
    fn event(&self, e: Event);
}

pub fn idempotency_key(causal_key: &str, ordinal: u32) -> String {
    let mut h = blake3::Hasher::new();
    h.update(causal_key.as_bytes());
    h.update(&ordinal.to_le_bytes());
    h.finalize().to_hex().to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub struct Daemon {
    env: Env,
    cfg: Config,
    log: Log,
    state: Arc<Mutex<StateDb>>,
    applied: Arc<AppliedLsn>,
    hwm: Mutex<u64>,
    actors: Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>,
    inflight: Mutex<InFlight>,
    code: Arc<Code>,
    probe: Arc<dyn Probe>,
}

/// Ingress keys whose turn is running, with the requests waiting for it.
type InFlight = BTreeMap<(String, String), Vec<oneshot::Sender<Response>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Daemon {
    /// Recovery, then ready to serve. `db` is the (possibly stale) `state.db`.
    pub async fn start(
        env: Env,
        cfg: Config,
        code: Arc<Code>,
        probe: Arc<dyn Probe>,
        db: StateDb,
    ) -> Result<Arc<Daemon>, String> {
        let (committed_tx, mut committed_rx) = mpsc::unbounded_channel::<(u64, Record)>();
        let (fatal_tx, fatal_rx) = oneshot::channel::<String>();
        let (log, opened) = Log::open(
            &env,
            cfg.data_dir.join("log"),
            committed_tx,
            fatal_tx,
            cfg.mutation,
        )
        .await
        .map_err(|e| e.to_string())?;
        let mut db = db;
        let applied_from = db.applied_lsn().map_err(|e| e.to_string())?;
        let last_lsn = opened.scan.records.last().map(|(l, _)| *l).unwrap_or(0);
        if applied_from > last_lsn {
            return Err(format!(
                "STORAGE_CORRUPT: state.db applied_lsn {applied_from} is past the log end {last_lsn}"
            ));
        }
        let mut applied = 0;
        let mut hwm = db.time_hwm().map_err(|e| e.to_string())?;
        let mut results: BTreeMap<String, BTreeMap<u32, EffectOutcome>> = BTreeMap::new();
        let mut finished: BTreeSet<String> = BTreeSet::new();
        for (lsn, rec) in &opened.scan.records {
            if *lsn > applied_from
                && db
                    .apply(*lsn, rec)
                    .map_err(|e| format!("apply {lsn}: {e}"))?
            {
                applied += 1;
            }
            match rec {
                Record::TurnBegin(b) => hwm = hwm.max(b.time_ms),
                Record::EffectResult(r) => {
                    results
                        .entry(r.exec_id.clone())
                        .or_default()
                        .insert(r.ordinal, r.outcome.clone());
                }
                Record::TurnRecord(t) => {
                    hwm = hwm.max(t.begin.time_ms);
                    finished.insert(t.begin.exec_id.clone());
                }
            }
        }
        // Re-run in log order of their TurnBegin.
        let pending: Vec<TurnBegin> = opened
            .scan
            .records
            .iter()
            .filter_map(|(_, r)| match r {
                Record::TurnBegin(b) if !finished.contains(&b.exec_id) => Some(b.clone()),
                _ => None,
            })
            .collect();
        let pending: Vec<TurnBegin> = match cfg.mutation {
            Some(Mutation::NoRerun) => Vec::new(),
            Some(Mutation::HashMapRerunOrder) => {
                let m: std::collections::HashMap<String, TurnBegin> = pending
                    .into_iter()
                    .map(|b| (b.exec_id.clone(), b))
                    .collect();
                m.into_values().collect()
            }
            _ => pending,
        };

        let start_lsn = db.applied_lsn().map_err(|e| e.to_string())?;
        let applied_lsn = Arc::new(AppliedLsn {
            lsn: AtomicU64::new(start_lsn),
            notify: Notify::new(),
        });
        let state = Arc::new(Mutex::new(db));
        let daemon = Arc::new(Daemon {
            env: env.clone(),
            cfg,
            log,
            state: state.clone(),
            applied: applied_lsn.clone(),
            hwm: Mutex::new(hwm),
            actors: Mutex::new(BTreeMap::new()),
            inflight: Mutex::new(BTreeMap::new()),
            code,
            probe: probe.clone(),
        });

        // The single applier: committed records arrive in LSN order.
        let p = probe.clone();
        env.spawn("applier", async move {
            while let Some((lsn, rec)) = committed_rx.recv().await {
                let r = lock(&state).apply(lsn, &rec);
                match r {
                    Ok(_) => applied_lsn.advance(lsn),
                    Err(e) => {
                        p.event(Event::Violation(format!("apply of lsn {lsn} failed: {e}")));
                        return;
                    }
                }
            }
        });
        let p = probe.clone();
        env.spawn("fatal-watch", async move {
            if let Ok(msg) = fatal_rx.await {
                p.event(Event::Fatal(msg));
            }
        });

        let reruns = pending.len();
        for begin in pending {
            // The client's retry with the same idempotency key finds the
            // saved response once the re-run has committed.
            let recorded = results.remove(&begin.exec_id).unwrap_or_default();
            let actor_lock = daemon.actor_lock(&begin.actor);
            let _g = actor_lock.lock().await;
            daemon.execute(begin, recorded, true).await?;
        }
        probe.event(Event::Recovered {
            applied_from,
            applied,
            reruns,
            truncated: opened.truncated_bytes,
            valid_after_tear: opened.scan.valid_after_tear,
            hwm,
        });
        Ok(daemon)
    }

    fn actor_lock(&self, actor: &str) -> Arc<tokio::sync::Mutex<()>> {
        lock(&self.actors)
            .entry(actor.to_string())
            .or_default()
            .clone()
    }

    /// I15: max(host wall clock, high-water mark + 1). A message/timer parent
    /// time would be a third operand.
    fn assign_time(&self) -> u64 {
        let mut hwm = lock(&self.hwm);
        let t = if self.cfg.mutation == Some(Mutation::WallClockTime) {
            self.env.clock.wall_ms()
        } else {
            self.env.clock.wall_ms().max(*hwm + 1)
        };
        *hwm = t;
        t
    }

    /// The gateway's service function: what hyper calls in production and
    /// what the simulator calls directly.
    pub async fn handle(self: &Arc<Self>, req: Request) -> Response {
        let actor = format!("counter/{}", req.actor_key);
        let k = (actor.clone(), req.ingress_key.clone());
        // Check the saved response and the in-flight table atomically: a
        // turn removes itself from `inflight` only after it was applied.
        let wait = {
            let mut inflight = lock(&self.inflight);
            match lock(&self.state).saved_response(&actor, &req.ingress_key) {
                Ok(Some(saved)) => {
                    return Response {
                        status: saved.status,
                        body: saved.body,
                    };
                }
                Ok(None) => {}
                Err(e) => {
                    return Response {
                        status: 500,
                        body: format!("STORAGE: {e}").into_bytes(),
                    };
                }
            }
            match inflight.get_mut(&k) {
                Some(waiters) => {
                    let (tx, rx) = oneshot::channel();
                    waiters.push(tx);
                    Some(rx)
                }
                None => {
                    inflight.insert(k.clone(), Vec::new());
                    None
                }
            }
        };
        if let Some(rx) = wait {
            return rx.await.unwrap_or(Response {
                status: 503,
                body: b"IDEMPOTENCY_IN_FLIGHT".to_vec(),
            });
        }

        let resp = {
            let actor_lock = self.actor_lock(&actor);
            let _g = actor_lock.lock().await;
            let exec_id = hex(&self.env.random_bytes::<16>());
            let seed = self.env.random_bytes::<32>();
            let time_ms = self.assign_time();
            self.probe.event(Event::TimeAssigned {
                actor: actor.clone(),
                time_ms,
            });
            let begin = TurnBegin {
                exec_id,
                actor: actor.clone(),
                causal_key: format!("{actor}#{}", req.ingress_key),
                ingress_key: req.ingress_key.clone(),
                time_ms,
                seed,
                input: req.body,
            };
            match self.execute(begin, BTreeMap::new(), false).await {
                Ok(r) => r,
                Err(e) => Response {
                    status: 503,
                    body: format!("unavailable: {e}").into_bytes(),
                },
            }
        };
        let waiters = lock(&self.inflight).remove(&k).unwrap_or_default();
        for w in waiters {
            let _ = w.send(resp.clone());
        }
        resp
    }

    /// Runs one turn (new or re-run) to a durable, applied `TurnRecord`.
    /// The caller holds the actor lock.
    async fn execute(
        self: &Arc<Self>,
        begin: TurnBegin,
        recorded: BTreeMap<u32, EffectOutcome>,
        begun: bool,
    ) -> Result<Response, String> {
        let (kind, key) = begin.actor.split_once('/').unwrap_or(("counter", ""));
        let spec = TurnSpec {
            kind: kind.to_string(),
            key: key.to_string(),
            causal_key: begin.causal_key.clone(),
            time_ms: begin.time_ms,
            seed: begin.seed,
            input: begin.input.clone(),
        };
        let gate = Arc::new(LiveGate {
            daemon: self.clone(),
            begin: begin.clone(),
            begun: AtomicBool::new(begun),
            recorded,
            recovering: begun,
        });
        let reads = Arc::new(ActorState {
            state: self.state.clone(),
            actor: begin.actor.clone(),
        });
        let out = self.code.run(&spec, reads, gate).await?;
        let rec = TurnRecord {
            begin,
            effects: out.effects,
            writes: out.writes,
            outcome: out.outcome,
            fuel: out.fuel,
        };
        let resp = match &rec.outcome {
            Outcome::Ok { status, body } => Response {
                status: *status,
                body: body.clone(),
            },
            Outcome::Failed { code, .. } => Response {
                status: 500,
                body: code.as_bytes().to_vec(),
            },
        };
        let (actor, ingress, ok) = (
            rec.begin.actor.clone(),
            rec.begin.ingress_key.clone(),
            matches!(rec.outcome, Outcome::Ok { .. }),
        );
        let lsn = self.log.append(Record::TurnRecord(rec)).await?;
        self.applied.wait_for(lsn).await;
        self.probe.event(Event::Committed {
            lsn,
            actor,
            ingress_key: ingress,
            ok,
        });
        Ok(resp)
    }
    /// Canonical dump of the materialized state.
    pub fn dump(&self) -> BTreeMap<String, String> {
        lock(&self.state).dump().unwrap_or_default()
    }
}

/// "Applied through LSN", with waiters.
///
/// Not `tokio::sync::watch`: its receivers register on one of eight
/// `Notify` shards picked by tokio's thread-local RNG (seeded from the OS),
/// so wake order is nondeterministic. `Notify::notify_waiters` wakes in a
/// fixed order.
struct AppliedLsn {
    lsn: AtomicU64,
    notify: Notify,
}

impl AppliedLsn {
    fn advance(&self, lsn: u64) {
        self.lsn.store(lsn, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn wait_for(&self, lsn: u64) {
        loop {
            // Register before checking, so an advance in between is not lost.
            let notified = self.notify.notified();
            if self.lsn.load(Ordering::SeqCst) >= lsn {
                return;
            }
            notified.await;
        }
    }
}

struct ActorState {
    state: Arc<Mutex<StateDb>>,
    actor: String,
}

impl StateRead for ActorState {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        lock(&self.state).get(&self.actor, key).ok().flatten()
    }
    fn keys(&self, prefix: &str) -> Vec<String> {
        lock(&self.state)
            .keys(&self.actor, prefix)
            .unwrap_or_default()
    }
}

struct LiveGate {
    daemon: Arc<Daemon>,
    begin: TurnBegin,
    begun: AtomicBool,
    recorded: BTreeMap<u32, EffectOutcome>,
    recovering: bool,
}

impl EffectGate for LiveGate {
    fn fetch(
        &self,
        ordinal: u32,
        mut req: HttpRequest,
    ) -> BoxFuture<'static, Result<EffectOutcome, String>> {
        if let Some(o) = self.recorded.get(&ordinal) {
            let o = o.clone();
            return Box::pin(async move { Ok(o) });
        }
        let d = self.daemon.clone();
        let begin = self.begin.clone();
        let need_begin = !self.begun.swap(true, Ordering::SeqCst);
        let recovering = self.recovering;
        Box::pin(async move {
            if need_begin {
                if d.cfg.mutation == Some(Mutation::EffectBeforeTurnBegin) {
                    let d2 = d.clone();
                    let b = begin.clone();
                    d.env.spawn("turn-begin", async move {
                        d2.log.append(Record::TurnBegin(b)).await
                    });
                } else {
                    // I14: durable before the first external effect.
                    d.log.append(Record::TurnBegin(begin.clone())).await?;
                }
            }
            let outcome = if recovering && d.cfg.delivery == DeliveryClass::Unsafe {
                // I17: an unsafe effect without a recorded result is never redone.
                EffectOutcome::Unknown("not retried after crash: unsafe target".into())
            } else {
                req.headers.push((
                    "idempotency-key".into(),
                    idempotency_key(&begin.causal_key, ordinal),
                ));
                match d
                    .env
                    .timeout(d.cfg.effect_timeout, d.env.net.http(req))
                    .await
                {
                    Ok(Ok(r)) => EffectOutcome::Response {
                        status: r.status,
                        body: r.body.to_vec(),
                    },
                    Ok(Err(NetError::Connect(m))) => EffectOutcome::NotSent(m),
                    Ok(Err(NetError::Io(m))) => EffectOutcome::Unknown(m),
                    Err(_) => EffectOutcome::Unknown("timeout".into()),
                }
            };
            d.log
                .append(Record::EffectResult(EffectResult {
                    exec_id: begin.exec_id.clone(),
                    ordinal,
                    outcome: outcome.clone(),
                }))
                .await?;
            Ok(outcome)
        })
    }
}
