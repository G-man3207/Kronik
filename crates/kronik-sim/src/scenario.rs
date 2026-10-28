//! The M1 counter workload: HTTP clients increment counter actors through
//! the real gateway, node, log, store and Wasm runtime, some requests also
//! send a message to another counter, while the node crashes at random
//! points (unsynced writes lost or torn, `state.db` and the SQL pool kept or
//! lost), fsyncs fail, and the wall clock jumps backwards.
//!
//! With `effects` set, the clients ask counters to charge a simulated
//! external service (`service.rs`) through `http.fetch`, under an
//! idempotency-keyed or unsafe grant with an optional rate, and the service
//! fails connections or loses responses.
//!
//! Invariants: every request commits exactly once under its
//! `Idempotency-Key` and every retry gets the same response; every message
//! is delivered exactly once; final counters match the workload; logical
//! time never decreases per actor and a receiver never runs before its
//! message; the materialized state equals a rebuild from the log; the run is
//! a deterministic function of the seed.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use kronik_core::env::{BoxFuture, Clock, Env};
use kronik_core::ids::{ActorRef, Lsn};
use kronik_gateway::{Gateway, GatewayConfig, HttpRequest, HttpResponse};
use kronik_log::{LogConfig, LogError};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{CodeStore, PoolSize, build_engine};
use kronik_sched::{Node, NodeConfig, NodeParts, StartError};
use kronik_store::Store;
use kronik_store::sql::{Limits, MemOpener, SqlPool};
use tokio::sync::{mpsc, oneshot};

use crate::exec::{Executor, Handle, NodeId, RunEnd, SUPERVISOR};
use crate::fs::{CrashModel, Disk, DiskFaults, SimFs};
use crate::service::{ServiceFaults, SimService};
use crate::{SimClock, SimEntropy, SimNoNet, SimProcs, SimRng, SimSpawner, Trace};
use kronik_effects::{Delivery, Rate};

/// The counter guest (tests/guests/counter.wasm).
pub const COUNTER: &[u8] = include_bytes!("../../../tests/guests/counter.wasm");
/// webhook-relay-rs (examples/webhook-relay-rs, copied from
/// examples/dist by scripts/build-test-guests.sh).
const WEBHOOK_RELAY_RS: &[u8] = include_bytes!("../../../tests/guests/webhook-relay.wasm");

/// The relay the webhook workload deploys: webhook-relay-rs, or the
/// component at `$KRONIK_DST_RELAY` (e.g. webhook-relay-ts, same behavior).
pub fn webhook_relay() -> Result<&'static [u8], String> {
    static RELAY: OnceLock<Result<Vec<u8>, String>> = OnceLock::new();
    match RELAY.get_or_init(|| match std::env::var_os("KRONIK_DST_RELAY") {
        Some(p) => std::fs::read(&p).map_err(|e| format!("KRONIK_DST_RELAY {p:?}: {e}")),
        None => Ok(WEBHOOK_RELAY_RS.to_vec()),
    }) {
        Ok(b) => Ok(b.as_slice()),
        Err(e) => Err(e.clone()),
    }
}
/// The signing key the webhook workload stores as `relay-signing-key`.
const SIGNING_KEY: &[u8] = b"dst-signing-key";

/// One run's knobs, derived from the seed.
#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    pub clients: usize,
    pub requests_per_client: usize,
    pub actors: usize,
    /// Share of requests that also send `increment` to another counter.
    pub forward_p: f64,
    pub crash_mean: Duration,
    pub max_crashes: u32,
    pub crash_model: CrashModel,
    pub fsync_error: f64,
    /// Chance per fault tick that the wall clock jumps backwards.
    pub clock_jump_p: f64,
    /// Chance that `state.db` and the actor databases survive a crash.
    pub keep_store_p: f64,
    pub segment_max_bytes: u64,
    /// Deliberate bug (mutation testing of the harness): the log writer
    /// acknowledges before fsync.
    pub mutation_ack_before_fsync: bool,
    /// The effects workload instead of the counter workload.
    pub effects: Option<EffectsConfig>,
    /// A long run: the clients keep sending until the executor has taken
    /// this many steps (polls), crashes keep coming throughout, and the
    /// drain and the step budget grow to match.
    pub long: Option<u64>,
    /// `NodeConfig::bulk_replay_min` and `startup_apply_batch`: tiny in
    /// the `rebuild` workload, so restarts replay in many bulk batches.
    pub bulk_replay_min: u64,
    pub startup_apply_batch: usize,
    /// After every start, the recovered derived state (state hash, open
    /// turns and their recorded effects) must equal a plain rebuild from
    /// the log up to the same LSN, as scripts/chaos.py checks.
    pub check_recovery: bool,
}

/// The effects workload's knobs.
#[derive(Debug, Clone, Copy)]
pub struct EffectsConfig {
    pub delivery: Delivery,
    pub rate: Option<Rate>,
    pub faults: ServiceFaults,
    /// Clients post webhooks to webhook-relay-rs instead of asking the test
    /// counter to charge.
    pub webhook: bool,
}

impl ScenarioConfig {
    pub fn for_seed(seed: u64) -> ScenarioConfig {
        let r = SimRng::new(seed, b"config");
        ScenarioConfig {
            clients: 2 + r.below(3) as usize,
            requests_per_client: 10 + r.below(30) as usize,
            actors: 2 + r.below(4) as usize,
            forward_p: [0.0, 0.3, 0.6][r.below(3) as usize],
            crash_mean: Duration::from_millis(5 + r.below(80)),
            max_crashes: r.below(10) as u32,
            crash_model: if r.chance(0.5) {
                CrashModel::PrefixTorn
            } else {
                CrashModel::Reorder
            },
            fsync_error: if r.chance(0.3) { 0.01 } else { 0.0 },
            clock_jump_p: 0.2,
            keep_store_p: [0.0, 0.5, 1.0][r.below(3) as usize],
            segment_max_bytes: [2 << 10, 64 << 10, 64 << 20][r.below(3) as usize],
            mutation_ack_before_fsync: false,
            effects: None,
            long: None,
            bulk_replay_min: kronik_sched::NodeConfig::default().bulk_replay_min,
            startup_apply_batch: kronik_sched::NodeConfig::default().startup_apply_batch,
            check_recovery: false,
        }
    }

    /// The counter workload for `seed` as a long run of at least `steps`
    /// executor steps: four clients send until then, and a crash comes about
    /// every 0.3 to 1 s of virtual time, with no limit on their number.
    /// Segments are at least 64 KiB, so recovery does not reread thousands
    /// of tiny files.
    pub fn long(seed: u64, steps: u64) -> ScenarioConfig {
        let r = SimRng::new(seed, b"long-config");
        let base = ScenarioConfig::for_seed(seed);
        ScenarioConfig {
            clients: 4,
            requests_per_client: usize::MAX,
            crash_mean: Duration::from_millis(300 + r.below(700)),
            max_crashes: u32::MAX,
            segment_max_bytes: base.segment_max_bytes.max(64 << 10),
            long: Some(steps),
            ..base
        }
    }

    /// The effects workload for `seed`.
    pub fn effects_for_seed(seed: u64) -> ScenarioConfig {
        let r = SimRng::new(seed, b"effects-config");
        let mut cfg = ScenarioConfig::for_seed(seed);
        cfg.forward_p = 0.0;
        cfg.requests_per_client = 4 + r.below(10) as usize;
        cfg.effects = Some(EffectsConfig {
            delivery: if r.chance(0.5) {
                Delivery::IdempotencyKeyed
            } else {
                Delivery::Unsafe
            },
            rate: r.chance(0.3).then_some(Rate {
                count: 5,
                per: Duration::from_secs(1),
            }),
            faults: ServiceFaults {
                connect_fail: [0.0, 0.05][r.below(2) as usize],
                lose_response: [0.0, 0.05][r.below(2) as usize],
            },
            webhook: false,
        });
        cfg
    }

    /// The webhook workload for `seed`: the effects workload's knobs with
    /// webhook-relay-rs as the actor (HMAC signature, retries on timers).
    pub fn webhook_for_seed(seed: u64) -> ScenarioConfig {
        let mut cfg = ScenarioConfig::effects_for_seed(seed);
        if let Some(fx) = cfg.effects.as_mut() {
            fx.webhook = true;
        }
        cfg
    }

    /// The bulk-replay workload for `seed` (`--scenario rebuild`): the
    /// effects workload, whose turns have a `TurnBegin`, with tiny startup
    /// replay thresholds and segments, so every restart (with `state.db`
    /// lost or kept) replays in bulk batches that cut turns between their
    /// begin and their record, across batches and segments. Every start's
    /// recovered state is checked against a rebuild from the log.
    pub fn rebuild_for_seed(seed: u64) -> ScenarioConfig {
        let r = SimRng::new(seed, b"rebuild-config");
        let mut cfg = ScenarioConfig::effects_for_seed(seed);
        cfg.bulk_replay_min = 1 + r.below(32);
        cfg.startup_apply_batch = 2 + r.below(30) as usize;
        cfg.segment_max_bytes = [512, 1 << 10, 2 << 10, 4 << 10][r.below(4) as usize];
        cfg.keep_store_p = [0.0, 0.5][r.below(2) as usize];
        cfg.max_crashes = cfg.max_crashes.max(2);
        cfg.check_recovery = true;
        cfg
    }
}

/// The result of one run.
#[derive(Debug, Clone)]
pub struct Report {
    pub seed: u64,
    pub violations: Vec<String>,
    pub trace_hash: String,
    pub events: u64,
    pub crashes: u32,
    pub requests: usize,
    pub turns: u64,
    pub end: RunEnd,
    pub polls: u64,
    pub virtual_time: Duration,
    pub wall: Duration,
    pub recent: Vec<String>,
    /// Workload-specific summary (the effects workload's service counts).
    pub notes: String,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn line(&self) -> String {
        format!(
            "seed {:>5} {} trace={} requests={} turns={} crashes={} events={} polls={} \
             virtual={:.1}s wall={:.0}ms",
            self.seed,
            if self.ok() { "ok  " } else { "FAIL" },
            self.trace_hash,
            self.requests,
            self.turns,
            self.crashes,
            self.events,
            self.polls,
            self.virtual_time.as_secs_f64(),
            self.wall.as_secs_f64() * 1000.0
        ) + &self.notes
    }
}

/// Engine and compiled guest, shared by every run in the process (the code
/// directory survives crashes anyway).
fn code() -> Result<Arc<CodeStore>, String> {
    static CODE: OnceLock<Result<Arc<CodeStore>, String>> = OnceLock::new();
    CODE.get_or_init(|| {
        let engine = build_engine(PoolSize { concurrency: 16 }).map_err(|e| e.to_string())?;
        let code = CodeStore::new(engine, None).map_err(|e| e.to_string())?;
        code.add(COUNTER).map_err(|e| e.to_string())?;
        code.add(webhook_relay()?).map_err(|e| e.to_string())?;
        Ok(Arc::new(code))
    })
    .clone()
}

type Conn = mpsc::UnboundedSender<(HttpRequest, oneshot::Sender<HttpResponse>)>;

#[derive(Default)]
struct State {
    trace: Trace,
    violations: Vec<String>,
    node_id: NodeId,
    node: Option<Arc<Node>>,
    store: Option<Arc<Store>>,
    conn: Option<Conn>,
    crashes: u32,
    clients_done: usize,
    responses: BTreeMap<String, Vec<u8>>,
    expected: BTreeMap<String, u64>,
    requests: usize,
    turns: u64,
    finished: bool,
    notes: String,
}

struct World {
    seed: u64,
    cfg: ScenarioConfig,
    exec: Handle,
    clock: Arc<dyn Clock>,
    faults: SimRng,
    work: SimRng,
    entropy: SimRng,
    disk: Arc<Mutex<Disk>>,
    wall_offset: Arc<AtomicI64>,
    code: Arc<CodeStore>,
    fatal_tx: mpsc::UnboundedSender<NodeId>,
    service: Option<Arc<SimService>>,
    /// The secret store (on "disk": it survives crashes).
    secrets: Option<Arc<kronik_privacy::SecretStore>>,
    state: Mutex<State>,
}

fn log_dir() -> PathBuf {
    PathBuf::from("/data/branches/main/log")
}

impl World {
    fn st(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn event(&self, line: impl Into<String>) {
        let now = self.exec.now();
        self.st().trace.push(now, line.into());
    }

    fn violation(&self, v: impl Into<String>) {
        let v = v.into();
        self.event(format!("VIOLATION {v}"));
        self.st().violations.push(v);
    }

    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        self.clock.sleep(d)
    }

    fn env(&self, node: NodeId) -> Env {
        Env {
            clock: self.clock.clone(),
            spawner: Arc::new(SimSpawner {
                exec: self.exec.clone(),
                node,
            }),
            entropy: Arc::new(SimEntropy(self.entropy.clone())),
            fs: Arc::new(SimFs::new(
                self.disk.clone(),
                self.clock.clone(),
                self.faults.clone(),
                DiskFaults {
                    crash_model: self.cfg.crash_model,
                    fsync_error: self.cfg.fsync_error,
                },
            )),
            net: match &self.service {
                Some(s) => s.net(node),
                None => Arc::new(SimNoNet),
            },
            procs: Arc::new(SimProcs {
                clock: self.clock.clone(),
            }),
        }
    }

    fn new_store() -> Result<Arc<Store>, String> {
        let conn = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
        let pool = SqlPool::new(Arc::new(MemOpener), Limits::default(), usize::MAX);
        Store::open(conn, pool).map_err(|e| e.to_string())
    }

    fn log_config(&self) -> LogConfig {
        let mut cfg = LogConfig::new(log_dir(), "main");
        cfg.segment_max_bytes = self.cfg.segment_max_bytes;
        cfg.mutation_ack_before_fsync = self.cfg.mutation_ack_before_fsync;
        cfg
    }

    /// Starts a new node process on the current disk.
    fn start_node(self: &Arc<Self>) {
        let store = {
            let mut st = self.st();
            st.node_id += 1;
            st.store.take()
        };
        let store = match store {
            Some(s) => s,
            None => match Self::new_store() {
                Ok(s) => s,
                Err(e) => return self.violation(format!("in-memory store: {e}")),
            },
        };
        let node_id = self.st().node_id;
        self.st().store = Some(store.clone());
        let env = self.env(node_id);
        self.event(format!("start node {node_id}"));
        let me = self.clone();
        self.exec.spawn(
            node_id,
            "node-main",
            Box::pin(async move { me.node_main(env, node_id, store).await }),
        );
    }

    async fn node_main(self: Arc<Self>, env: Env, node_id: NodeId, store: Arc<Store>) {
        let parts = NodeParts {
            env: env.clone(),
            config: NodeConfig {
                concurrency: 4,
                apply_batch: 64,
                bulk_replay_min: self.cfg.bulk_replay_min,
                startup_apply_batch: self.cfg.startup_apply_batch,
                ..NodeConfig::default()
            },
            log: self.log_config(),
            store,
            code: self.code.clone(),
            secrets: self.secrets.clone(),
            sealer: None,
        };
        let node = match Node::start(parts).await {
            Ok(n) => n,
            Err(StartError::Log(LogError::Io(e))) => {
                // An injected fsync failure during recovery: restart.
                self.event(format!("node {node_id} start I/O error: {e}"));
                let _ = self.fatal_tx.send(node_id);
                return;
            }
            Err(e) => return self.violation(format!("node {node_id} failed to start: {e}")),
        };
        self.event(format!(
            "node {node_id} recovered at lsn {}",
            node.applied_lsn()
        ));
        if self.cfg.check_recovery {
            // Taken before anything awaits: no re-run and no new input has
            // been applied yet.
            let applied = node.applied_lsn();
            match derived_state(node.store()) {
                Ok(recovered) => {
                    self.check_recovered(node_id, applied, recovered, &node)
                        .await
                }
                Err(e) => return self.violation(format!("node {node_id}: recovered state: {e}")),
            }
        }
        if !node.kind_exists("counter") {
            let audit = pb::Audit {
                token_id: "sim".into(),
                reason: "dst".into(),
                wall_time_ms: 0,
            };
            if let Err(e) = node.deploy(COUNTER, audit, false).await {
                self.event(format!("deploy failed: {}", e.code));
                let _ = self.fatal_tx.send(node_id);
                return;
            }
            self.event("deployed counter");
        }
        if let Some(fx) = self.cfg.effects
            && node
                .config_now()
                .http_grant("counter", "payments")
                .is_none()
        {
            let audit = pb::Audit {
                token_id: "sim".into(),
                reason: "dst".into(),
                wall_time_ms: 0,
            };
            if let Err(e) = node
                .grant(
                    "counter",
                    "http:payments",
                    Some(fx.delivery),
                    fx.rate,
                    audit,
                    false,
                )
                .await
            {
                self.event(format!("grant failed: {}", e.code));
                let _ = self.fatal_tx.send(node_id);
                return;
            }
            self.event("granted http:payments");
        }
        if self.cfg.effects.is_some_and(|fx| fx.webhook)
            && let Err(e) = self.setup_webhook(&node).await
        {
            self.event(format!("webhook setup failed: {e}"));
            let _ = self.fatal_tx.send(node_id);
            return;
        }
        let gateway = Arc::new(Gateway::new(node.clone(), GatewayConfig::default()));
        let (tx, mut rx) =
            mpsc::unbounded_channel::<(HttpRequest, oneshot::Sender<HttpResponse>)>();
        {
            let mut st = self.st();
            st.node = Some(node.clone());
            st.conn = Some(tx);
        }
        let fatal = self.fatal_tx.clone();
        let watched = node.clone();
        env.spawn("fatal-watch", async move {
            watched.wait_fatal().await;
            let _ = fatal.send(node_id);
        });
        // The "TCP listener": each request is served by a task of this
        // node, so a crash drops it and the client sees a broken connection.
        while let Some((req, reply)) = rx.recv().await {
            let gw = gateway.clone();
            env.spawn("http", async move {
                let _ = reply.send(gw.handle(req).await);
            });
        }
    }

    /// Deploys webhook-relay-rs, grants it the service and its signing key,
    /// stores the key, and points each actor at the service (each step only
    /// once: they are history after a restart).
    async fn setup_webhook(&self, node: &Node) -> Result<(), String> {
        let Some(fx) = self.cfg.effects else {
            return Ok(());
        };
        let audit = || pb::Audit {
            token_id: "sim".into(),
            reason: "dst".into(),
            wall_time_ms: 0,
        };
        let kind = "webhook-relay";
        if !node.kind_exists(kind) {
            node.deploy(webhook_relay()?, audit(), false)
                .await
                .map_err(|e| format!("deploy: {}", e.code))?;
            self.event("deployed webhook-relay");
        }
        let config = node.config_now();
        if config.http_grant(kind, "payments").is_none() {
            node.grant(
                kind,
                "http:payments",
                Some(fx.delivery),
                fx.rate,
                audit(),
                false,
            )
            .await
            .map_err(|e| format!("grant: {}", e.code))?;
        }
        if config.grant(kind, "secret:relay-signing-key").is_none() {
            node.grant(kind, "secret:relay-signing-key", None, None, audit(), false)
                .await
                .map_err(|e| format!("grant: {}", e.code))?;
        }
        let have_key = node
            .secret_list()
            .map_err(|e| format!("secrets: {}", e.code))?
            .iter()
            .any(|m| m.name == "relay-signing-key");
        if !have_key {
            node.secret_set("relay-signing-key", SIGNING_KEY, &audit(), false)
                .map_err(|e| format!("secret: {}", e.code))?;
        }
        for a in 0..self.cfg.actors {
            let key = format!("k{a}");
            let configured = node
                .store()
                .db()
                .kv_get(kind, &key, "config")
                .map_err(|e| e.to_string())?
                .is_some();
            if configured {
                continue;
            }
            let actor = ActorRef::parse(&format!("{kind}/{key}")).map_err(|e| e.to_string())?;
            let msg = pb::Message {
                name: "configure".into(),
                content_type: "application/json".into(),
                body: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(
                        br#"{"target":"http://payments/relay"}"#.to_vec(),
                    )),
                }),
                blobs: vec![],
            };
            let r = node
                .send(actor, msg, audit(), false)
                .await
                .map_err(|e| format!("configure: {}", e.code))?;
            if !r.is_some_and(|r| r.committed()) {
                return Err(format!("configure {key} did not commit"));
            }
        }
        Ok(())
    }

    fn crash(self: &Arc<Self>) {
        let (node_id, store) = {
            let mut st = self.st();
            st.crashes += 1;
            st.conn = None;
            if let Some(n) = st.node.take() {
                st.turns += n.probe.turns_run.load(std::sync::atomic::Ordering::Relaxed);
            }
            (st.node_id, st.store.take())
        };
        let killed = self.exec.kill_node(node_id);
        self.disk
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .crash(self.cfg.crash_model, &self.faults);
        let keep = self.faults.chance(self.cfg.keep_store_p);
        if keep && let Some(s) = store {
            s.sql.abort_turns();
            self.st().store = Some(s);
        }
        self.event(format!(
            "crash node {node_id} ({killed} tasks), store {}",
            if keep { "kept" } else { "lost" }
        ));
    }

    async fn client(self: Arc<Self>, client: usize) {
        for r in 0..self.cfg.requests_per_client {
            if self
                .cfg
                .long
                .is_some_and(|steps| self.exec.polls() >= steps)
            {
                break;
            }
            let actor = format!("k{}", self.work.below(self.cfg.actors as u64));
            let forward = self.work.chance(self.cfg.forward_p);
            let target = format!("k{}", self.work.below(self.cfg.actors as u64));
            let idem = format!("c{client}-r{r}");
            {
                let mut st = self.st();
                st.requests += 1;
                if self.cfg.effects.is_none() {
                    *st.expected.entry(actor.clone()).or_default() += 1;
                    if forward {
                        *st.expected.entry(target.clone()).or_default() += 1;
                    }
                }
            }
            let webhook = self.cfg.effects.is_some_and(|fx| fx.webhook);
            let (op, body) = if webhook {
                ("hook", format!("{{\"n\":\"{idem}\"}}").into_bytes())
            } else if self.cfg.effects.is_some() {
                // A charge per request; the guest handles fetch errors, so
                // every turn commits (outcome-unknown included).
                (
                    "fetch-ok",
                    format!("POST http://payments/charge\n\n{idem} amount=10").into_bytes(),
                )
            } else if forward {
                ("forward", target.into_bytes())
            } else {
                ("increment", Vec::new())
            };
            let req = HttpRequest {
                method: "POST".into(),
                path: if webhook {
                    format!("/hooks/{actor}")
                } else {
                    format!("/counter/{actor}/{op}")
                },
                query: String::new(),
                headers: vec![("Idempotency-Key".into(), idem.clone())],
                body,
                peer: None,
            };
            let mut attempt = 0u32;
            loop {
                attempt += 1;
                if attempt > 2_000 {
                    self.violation(format!("{idem} never succeeded"));
                    return;
                }
                let conn = self.st().conn.clone();
                let Some(conn) = conn else {
                    self.sleep(Duration::from_millis(10)).await;
                    continue;
                };
                let (tx, rx) = oneshot::channel();
                if conn.send((req.clone(), tx)).is_err() {
                    self.sleep(Duration::from_millis(10)).await;
                    continue;
                }
                let resp = self.clock_timeout(Duration::from_secs(60), rx).await;
                match resp {
                    // webhook-relay answers its hook record, with 502 when
                    // the target has not taken it (yet); the turn committed.
                    Some(Ok(resp))
                        if resp.status == 200
                            || (webhook
                                && resp.status == 502
                                && resp.body.starts_with(b"{\"id\"")) =>
                    {
                        self.event(format!(
                            "{idem} {op} {actor} -> 200 {} (attempt {attempt})",
                            String::from_utf8_lossy(&resp.body)
                        ));
                        let mut st = self.st();
                        match st.responses.get(&idem) {
                            Some(prev) if *prev != resp.body => {
                                let v = format!(
                                    "{idem}: retry got {:?}, first response was {:?}",
                                    String::from_utf8_lossy(&resp.body),
                                    String::from_utf8_lossy(prev)
                                );
                                drop(st);
                                self.violation(v);
                            }
                            _ => {
                                st.responses.insert(idem.clone(), resp.body);
                            }
                        }
                        break;
                    }
                    Some(Ok(resp)) => {
                        let body = String::from_utf8_lossy(&resp.body).into_owned();
                        self.event(format!("{idem} -> {} {body}", resp.status));
                        if body.contains("TURN_FAILED") || body.contains("IDEMPOTENCY_KEY_REUSED") {
                            self.violation(format!("{idem}: {} {body}", resp.status));
                            return;
                        }
                    }
                    Some(Err(_)) => self.event(format!("{idem} -> connection lost")),
                    None => self.event(format!("{idem} -> client timeout")),
                }
                let backoff = self
                    .work
                    .duration(Duration::from_millis(5), Duration::from_millis(60));
                self.sleep(backoff).await;
            }
        }
        self.st().clients_done += 1;
    }

    async fn clock_timeout<T>(
        &self,
        d: Duration,
        rx: oneshot::Receiver<T>,
    ) -> Option<Result<T, oneshot::error::RecvError>> {
        let sleep = self.sleep(d);
        tokio::select! {
            biased;
            r = rx => Some(r),
            () = sleep => None,
        }
    }

    async fn supervisor(self: Arc<Self>, mut fatal_rx: mpsc::UnboundedReceiver<NodeId>) {
        self.start_node();
        loop {
            if self.st().clients_done == self.cfg.clients {
                break;
            }
            let crash_in = Duration::from_micros(
                1 + self
                    .faults
                    .below(2 * self.cfg.crash_mean.as_micros() as u64),
            );
            let sleep = self.sleep(crash_in);
            let fatal = tokio::select! {
                biased;
                id = fatal_rx.recv() => id,
                () = sleep => None,
            };
            if self.faults.chance(self.cfg.clock_jump_p) {
                let back = self.faults.below(10_000) as i64;
                self.wall_offset
                    .fetch_sub(back, std::sync::atomic::Ordering::Relaxed);
                self.event(format!("wall clock jumps back {back} ms"));
            }
            let current = self.st().node_id;
            let crash = match fatal {
                Some(id) if id == current => true,
                Some(_) => false,
                None => self.st().crashes < self.cfg.max_crashes,
            };
            if crash && self.st().clients_done < self.cfg.clients {
                self.crash();
                let d = self
                    .faults
                    .duration(Duration::from_millis(1), Duration::from_millis(100));
                self.sleep(d).await;
                self.start_node();
            } else if fatal == Some(current) {
                // A fatal failure after the workload: restart to check.
                self.crash();
                self.start_node();
            }
        }
        self.finish(&mut fatal_rx).await;
        self.st().finished = true;
    }

    /// Waits for the mailbox to drain, then checks the end-state invariants.
    async fn finish(self: &Arc<Self>, fatal_rx: &mut mpsc::UnboundedReceiver<NodeId>) {
        // Timers are due in logical time, which holds still while the wall
        // clock is behind its high-water mark (ADR 0006). The workload's
        // backward jumps can add up to many minutes, so the clock is
        // corrected before waiting for the webhook retries.
        if self.cfg.effects.is_some_and(|fx| fx.webhook) {
            let off = self
                .wall_offset
                .swap(0, std::sync::atomic::Ordering::Relaxed);
            if off < 0 {
                self.event(format!("wall clock corrected forward {} ms", -off));
            }
        }
        let mut node = None;
        // 100 s of virtual time, or 10 000 s after a long run.
        let rounds = if self.cfg.long.is_some() {
            1_000_000
        } else {
            10_000
        };
        for _ in 0..rounds {
            if let Ok(id) = fatal_rx.try_recv() {
                self.event(format!("fatal on node {id} during drain"));
                // Turns keep writing during the drain (forwarded increments,
                // webhook retries); a node that stopped on an I/O error
                // restarts as during the workload.
                if id == self.st().node_id {
                    self.crash();
                    self.start_node();
                }
            }
            let n = self.st().node.clone();
            let webhook = self.cfg.effects.is_some_and(|fx| fx.webhook);
            if let Some(n) = n
                && n.fatal().is_none()
                && n.store()
                    .db()
                    .mailbox()
                    .map(|m| m.is_empty())
                    .unwrap_or(false)
                // Webhook retries wait on timers.
                && (!webhook || n.store().db().timers(None).is_ok_and(|t| t.is_empty()))
            {
                node = Some(n);
                break;
            }
            self.sleep(Duration::from_millis(10)).await;
        }
        let Some(node) = node else {
            let detail = self.st().node.clone().map(|n| {
                let db = n.store().db();
                format!(
                    " (mailbox {:?}, timers {:?}, fatal {:?})",
                    db.mailbox().map(|m| m.len()),
                    db.timers(None)
                        .map(|t| t.iter().map(|t| t.due_ms).collect::<Vec<_>>()),
                    n.fatal()
                )
            });
            return self.violation(format!(
                "the node never drained its mailbox{}",
                detail.unwrap_or_default()
            ));
        };
        // Let the last applies land.
        self.sleep(Duration::from_millis(50)).await;
        self.check_counters(&node);
        self.check_log(&node).await;
        self.check_effects(&node).await;
        let turns = node
            .probe
            .turns_run
            .load(std::sync::atomic::Ordering::Relaxed);
        self.st().turns += turns;
    }

    fn check_counters(&self, node: &Node) {
        let expected = self.st().expected.clone();
        let db = node.store().db();
        for (key, want) in &expected {
            let got = db
                .kv_get("counter", key, "n")
                .ok()
                .flatten()
                .and_then(|v| String::from_utf8(v).ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let line = format!("final counter/{key} = {got} (expected {want})");
            if got != *want {
                drop(db);
                return self.violation(line);
            }
        }
        match db.dead_letters(0, 10) {
            Ok(d) if d.is_empty() => {}
            Ok(d) => {
                let v = format!(
                    "unexpected dead letters: {:?}",
                    d.iter().map(|x| &x.message).collect::<Vec<_>>()
                );
                drop(db);
                self.violation(v);
            }
            Err(e) => {
                drop(db);
                self.violation(format!("dead letters: {e}"));
            }
        }
    }

    /// The effect invariants against what the simulated service saw.
    async fn check_effects(&self, node: &Node) {
        let (Some(fx), Some(svc)) = (self.cfg.effects, &self.service) else {
            return;
        };
        let mut records = Vec::new();
        if let Err(e) = node
            .reader()
            .read(1, node.applied_lsn(), |c| {
                records.push(c.record);
                Ok(())
            })
            .await
        {
            return self.violation(format!("reading the log: {e}"));
        }
        // Keys of every TurnBegin that survived: the test counter's fetch is
        // its first operation; webhook-relay signs first (ordinal 0) and may
        // schedule before fetching, so take the first few ordinals.
        let mut begun = std::collections::BTreeSet::new();
        let mut ok_keys = std::collections::BTreeSet::new();
        let mut unknown = 0;
        for r in &records {
            match r {
                Record::TurnBegin(b) => {
                    if let Some(k) = &b.causal_key {
                        for ordinal in 0..8 {
                            begun.insert(kronik_core::causal::idempotency_key(k, ordinal));
                        }
                    }
                }
                Record::TurnRecord(t) => {
                    for e in &t.effects {
                        if e.status == pb::EffectStatus::Ok as i32 && e.kind == "http.fetch" {
                            ok_keys.insert(e.idempotency_key.clone());
                        }
                        if e.status == pb::EffectStatus::OutcomeUnknown as i32 {
                            unknown += 1;
                        }
                    }
                }
                _ => {}
            }
        }
        let received = svc.received();
        let mut by_key: BTreeMap<String, Vec<&crate::service::Received>> = BTreeMap::new();
        for r in &received {
            by_key.entry(r.key.clone()).or_default().push(r);
        }
        for (key, reqs) in &by_key {
            // I14: the service never saw a request whose TurnBegin could be
            // lost.
            if !begun.contains(key) {
                self.violation(format!("service saw key {key} without a durable TurnBegin"));
            }
            if reqs.iter().any(|r| r.body != reqs[0].body) {
                self.violation(format!("retries for key {key} differ"));
            }
            if fx.delivery == Delivery::Unsafe && reqs.len() > 1 {
                self.violation(format!("unsafe effect {key} was sent {} times", reqs.len()));
            }
        }
        for k in &ok_keys {
            if !by_key.contains_key(k) {
                self.violation(format!("recorded OK result for {k} the service never saw"));
            }
        }
        if fx.delivery == Delivery::IdempotencyKeyed && unknown > 0 {
            self.violation(format!(
                "{unknown} outcome-unknown results under idempotency-keyed"
            ));
        }
        if fx.webhook {
            self.check_webhooks(node, &received);
        }
        if let Some(rate) = fx.rate {
            // The limiter bounds send times, across restarts (windows start
            // full at process start; docs/design/m2-effects.md §6). Network
            // delay can bunch arrivals at the target.
            let sent = svc.sent();
            for (i, s) in sent.iter().enumerate() {
                let n = sent[i..]
                    .iter()
                    .take_while(|u| u.at.saturating_sub(s.at) < rate.per)
                    .count();
                if n > rate.count as usize {
                    self.violation(format!(
                        "{n} calls sent within {:?} (rate {})",
                        rate.per,
                        rate.render()
                    ));
                    break;
                }
            }
        }
        self.event(format!(
            "service: {} requests, {} keys, {} charges, {unknown} outcome-unknown",
            received.len(),
            by_key.len(),
            svc.charges()
        ));
        self.st().notes = format!(
            " {} sent={} received={} charges={} unknown={unknown}{}",
            fx.delivery.as_str(),
            svc.sent().len(),
            received.len(),
            svc.charges(),
            fx.rate
                .map_or(String::new(), |r| format!(" rate={}", r.render()))
        );
    }

    /// webhook-relay-rs: every delivery attempt of a webhook carries the same
    /// bytes and a valid signature; every acknowledged hook has a final
    /// record (delivered or failed: the run waits for retry timers), and a
    /// delivered one reached the service.
    fn check_webhooks(&self, node: &Node, received: &[crate::service::Received]) {
        let header = |r: &crate::service::Received, name: &str| {
            r.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let mut by_hook: BTreeMap<String, Vec<&crate::service::Received>> = BTreeMap::new();
        for r in received {
            let Some(id) = header(r, "x-webhook-id") else {
                self.violation(format!("request {} without x-webhook-id", r.key));
                continue;
            };
            let want = format!(
                "sha256={}",
                hex(&kronik_effects::crypto::hmac_sha256(SIGNING_KEY, &r.body))
            );
            if header(r, "x-signature").as_deref() != Some(want.as_str()) {
                self.violation(format!("webhook {id}: bad signature"));
            }
            by_hook.entry(id).or_default().push(r);
        }
        for (id, reqs) in &by_hook {
            if reqs.iter().any(|r| r.body != reqs[0].body) {
                self.violation(format!("webhook {id}: attempts carry different bodies"));
            }
        }
        let responses: Vec<Vec<u8>> = self.st().responses.values().cloned().collect();
        let mut delivered = 0;
        for body in responses {
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) else {
                self.violation(format!(
                    "unparsable hook record {}",
                    String::from_utf8_lossy(&body)
                ));
                continue;
            };
            let id = v["id"].as_str().unwrap_or_default().to_owned();
            let source = v["source"].as_str().map(str::to_owned);
            let rows = (0..self.cfg.actors)
                .map(|a| format!("k{a}"))
                .filter(|k| source.as_deref().is_none_or(|s| s == k))
                .find_map(|k| {
                    node.store()
                        .db()
                        .kv_get("webhook-relay", &k, &format!("hook/{id}"))
                        .ok()
                        .flatten()
                });
            let Some(row) = rows else {
                self.violation(format!("acknowledged webhook {id} has no record"));
                continue;
            };
            let rec: serde_json::Value = serde_json::from_slice(&row).unwrap_or_default();
            match rec["status"].as_str() {
                Some("delivered") => {
                    delivered += 1;
                    if !by_hook.contains_key(&id) {
                        self.violation(format!(
                            "webhook {id} delivered but the service never saw it"
                        ));
                    }
                }
                Some("failed") => {}
                other => self.violation(format!("webhook {id} ended {other:?}")),
            }
        }
        self.event(format!(
            "webhooks: {} seen by the service, {delivered} delivered",
            by_hook.len()
        ));
    }

    /// The state a start recovered, taken before anything ran, equals a
    /// plain (not bulk) rebuild of the log up to the same LSN: the
    /// recovered-versus-rebuilt check of scripts/chaos.py.
    async fn check_recovered(&self, node_id: NodeId, applied: Lsn, recovered: String, node: &Node) {
        let mut records = Vec::new();
        if let Err(e) = node
            .reader()
            .read(1, applied, |c| {
                records.push(c);
                Ok(())
            })
            .await
        {
            return self.violation(format!("node {node_id}: reading the log: {e}"));
        }
        let rebuilt = Self::new_store().and_then(|s| {
            s.apply(&records).map_err(|e| e.to_string())?;
            derived_state(&s)
        });
        match rebuilt {
            Ok(r) if r == recovered => {
                self.event(format!("node {node_id} recovered state equals a rebuild"));
            }
            Ok(r) => self.violation(format!(
                "node {node_id} recovered at lsn {applied}: {recovered} is not the state rebuilt \
                 from the log: {r}"
            )),
            Err(e) => self.violation(format!("node {node_id}: rebuild: {e}")),
        }
    }

    async fn check_log(&self, node: &Node) {
        let mut records = Vec::new();
        let applied = node.applied_lsn();
        if let Err(e) = node
            .reader()
            .read(1, applied, |c| {
                records.push(c);
                Ok(())
            })
            .await
        {
            return self.violation(format!("reading the log: {e}"));
        }
        let mut keys: BTreeMap<(String, String), Lsn> = BTreeMap::new();
        let mut times: BTreeMap<ActorRef, u64> = BTreeMap::new();
        let mut prev = 0;
        for c in &records {
            if c.lsn != prev + 1 {
                self.violation(format!("lsn {} after {prev}", c.lsn));
            }
            prev = c.lsn;
            let Record::TurnRecord(t) = &c.record else {
                continue;
            };
            let Some(actor) = t.actor.as_ref().map(ActorRef::from_pb) else {
                continue;
            };
            if t.outcome.as_ref().map(|o| o.kind) != Some(pb::OutcomeKind::Committed as i32) {
                self.violation(format!("failed turn at lsn {}: {:?}", c.lsn, t.outcome));
            }
            let last = times.entry(actor.clone()).or_default();
            if t.logical_time_ms < *last {
                self.violation(format!(
                    "{actor}: logical time {} at lsn {} after {}",
                    t.logical_time_ms, c.lsn, last
                ));
            }
            *last = t.logical_time_ms;
            match t.input.as_ref().and_then(|i| i.kind.as_ref()) {
                Some(pb::input::Kind::Http(h)) if !h.idempotency_key.is_empty() => {
                    if let Some(first) =
                        keys.insert((actor.to_string(), h.idempotency_key.clone()), c.lsn)
                    {
                        self.violation(format!(
                            "{actor} key {} has turns at lsn {first} and {}",
                            h.idempotency_key, c.lsn
                        ));
                    }
                }
                Some(pb::input::Kind::Message(m)) if t.logical_time_ms < m.sent_logical_time_ms => {
                    self.violation(format!(
                        "{actor}: message at lsn {} runs at {} before it was sent at {}",
                        c.lsn, t.logical_time_ms, m.sent_logical_time_ms
                    ));
                }
                _ => {}
            }
        }
        // Every request committed exactly once.
        let requests = self.st().requests;
        if keys.len() != requests {
            self.violation(format!(
                "{} keyed turns for {requests} requests",
                keys.len()
            ));
        }
        // The materialized state equals a rebuild from the log.
        let rebuilt = match Self::new_store() {
            Ok(s) => s,
            Err(e) => return self.violation(e),
        };
        if let Err(e) = rebuilt.apply(&records) {
            return self.violation(format!("rebuild: {e}"));
        }
        let live = node.store();
        let actors: Vec<String> = self.st().expected.keys().cloned().collect();
        for key in actors {
            let a = live.db().kv_list("counter", &key).ok();
            let b = rebuilt.db().kv_list("counter", &key).ok();
            if a != b {
                self.violation(format!("counter/{key}: live {a:?} != rebuilt {b:?}"));
            }
        }
        let summary: Vec<String> = self
            .st()
            .expected
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        self.event(format!("final {} lsn={applied}", summary.join(" ")));
    }
}

/// The derived state a rebuild from the log must reproduce: the state hash
/// (the tables a snapshot hashes) and the open turns and recorded effects
/// of unfinished turns, which the next start re-runs.
fn derived_state(store: &Store) -> Result<String, String> {
    use std::fmt::Write as _;
    let mut out = store.state_hash().map_err(|e| e.to_string())?;
    let db = store.db();
    for (table, cols) in [
        ("open_turns", "execution_id, lsn, kind, key"),
        ("open_effects", "execution_id, ordinal"),
    ] {
        let mut st = db
            .conn()
            .prepare(&format!("SELECT {cols} FROM {table} ORDER BY {cols}"))
            .map_err(|e| e.to_string())?;
        let n = st.column_count();
        let rows = st
            .query_map([], |r| {
                (0..n)
                    .map(|i| r.get::<_, rusqlite::types::Value>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let row = row.map_err(|e| e.to_string())?;
            let _ = write!(out, " {table}{row:?}");
        }
    }
    Ok(out)
}

/// Runs one seed on the deterministic executor.
// The host's Instant only measures the run's wall time for the report.
#[allow(clippy::disallowed_methods)]
pub fn run(seed: u64, cfg: ScenarioConfig) -> Report {
    let started = Instant::now();
    let exec = Executor::new(seed);
    let handle = exec.handle();
    let wall_offset = Arc::new(AtomicI64::new(0));
    let clock: Arc<dyn Clock> = Arc::new(SimClock {
        exec: handle.clone(),
        wall_base_ms: 1_700_000_000_000,
        wall_offset_ms: wall_offset.clone(),
    });
    let code = match code() {
        Ok(c) => c,
        Err(e) => {
            return Report {
                seed,
                violations: vec![format!("loading the guest: {e}")],
                trace_hash: String::new(),
                events: 0,
                crashes: 0,
                requests: 0,
                turns: 0,
                end: RunEnd::Quiescent,
                polls: 0,
                virtual_time: Duration::ZERO,
                wall: started.elapsed(),
                recent: vec![],
                notes: String::new(),
            };
        }
    };
    let (fatal_tx, fatal_rx) = mpsc::unbounded_channel();
    let service = cfg
        .effects
        .map(|fx| SimService::new(clock.clone(), SimRng::new(seed, b"service"), fx.faults));
    let secrets = match cfg.effects.filter(|fx| fx.webhook).map(|_| {
        let conn = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
        kronik_privacy::SecretStore::open(conn, &kronik_privacy::MasterKey::from_bytes([7; 32]))
            .map(Arc::new)
            .map_err(|e| e.to_string())
    }) {
        Some(Ok(s)) => Some(s),
        Some(Err(e)) => {
            return Report {
                seed,
                violations: vec![format!("secret store: {e}")],
                trace_hash: String::new(),
                events: 0,
                crashes: 0,
                requests: 0,
                turns: 0,
                end: RunEnd::Quiescent,
                polls: 0,
                virtual_time: Duration::ZERO,
                wall: started.elapsed(),
                recent: vec![],
                notes: String::new(),
            };
        }
        None => None,
    };
    let world = Arc::new(World {
        secrets,
        service,
        seed,
        exec: handle.clone(),
        clock,
        faults: SimRng::new(seed, b"faults"),
        work: SimRng::new(seed, b"workload"),
        entropy: SimRng::new(seed, b"entropy"),
        disk: Arc::new(Mutex::new(Disk::default())),
        wall_offset,
        code,
        fatal_tx,
        state: Mutex::new(State::default()),
        cfg,
    });
    let w = world.clone();
    handle.spawn(
        SUPERVISOR,
        "supervisor",
        Box::pin(async move { w.supervisor(fatal_rx).await }),
    );
    for c in 0..world.cfg.clients {
        let w = world.clone();
        handle.spawn(
            SUPERVISOR,
            "client",
            Box::pin(async move { w.client(c).await }),
        );
    }
    let w = world.clone();
    let budget = world
        .cfg
        .long
        .map_or(50_000_000, |steps| steps.saturating_mul(2).max(50_000_000));
    let end = exec.run(budget, move || w.st().finished);
    if end != RunEnd::Stopped {
        world.violation(format!("run ended with {end:?} before finishing"));
    }
    // Drop every task (and with them the node's Arcs) before reporting.
    handle.kill_node(world.st().node_id);
    handle.kill_node(SUPERVISOR);
    let st = world.st();
    Report {
        seed: world.seed,
        violations: st.violations.clone(),
        trace_hash: st.trace.hash(),
        events: st.trace.events,
        crashes: st.crashes,
        requests: st.requests,
        turns: st.turns,
        end,
        polls: handle.polls(),
        virtual_time: handle.now(),
        wall: started.elapsed(),
        recent: st.trace.recent(),
        notes: st.notes.clone(),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
