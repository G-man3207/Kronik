//! One DST run: a workload of HTTP clients against the mini daemon, with
//! crashes at random points, torn/lost unsynced writes, a stale `state.db`
//! after restart, fsync failures, network faults, and wall-clock jumps.
//! Invariants are checked while running and at the end.
//!
//! The scenario is written against [`Backend`] so that the same code runs on
//! the own executor and on madsim.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::daemon::log::{Outcome, Record, scan, segment_path};
use crate::daemon::state::StateDb;
use crate::daemon::{
    self, Daemon, DeliveryClass, Event, Probe, Request, Response, idempotency_key, replay,
};
use crate::env::{BoxFuture, Clock, Env, Spawner};
use crate::sim::exec::{self, Executor, NodeId, RunEnd, SUPERVISOR};

/// `DST_TRACE=1` prints every event to stderr while running.
static LIVE_TRACE: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var_os("DST_TRACE").is_some());
use crate::sim::fs::{CrashModel, Disk, DiskFaults, SimFs};
use crate::sim::net::{Delivery, NetFaults, Payments, SimNet};
use crate::sim::{SimClock, SimEntropy, SimProcs, SimRng, SimSpawner, Trace};
use crate::wasm;

pub const DAEMON: NodeId = 1;

/// What the scenario needs from a simulation runtime.
pub trait Backend: Send + Sync + 'static {
    fn clock(&self) -> Arc<dyn Clock>;
    fn spawner(&self, node: NodeId) -> Arc<dyn Spawner>;
    /// Drops every task of `node` (a crash) and lets it be used again.
    fn kill(&self, node: NodeId);
    fn name(&self) -> &'static str;
    /// Offset added to the simulated wall clock (fault injection).
    fn wall_offset(&self) -> Arc<AtomicI64>;
}

#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    pub clients: usize,
    pub requests_per_client: usize,
    pub actors: usize,
    /// Mean virtual time between crash attempts (0 disables crashes).
    pub crash_every: Duration,
    pub crash_model: CrashModel,
    pub delivery: Delivery,
    pub net: NetFaults,
    pub fsync_error: f64,
    pub clock_jumps: bool,
    pub max_polls: u64,
    /// Run identity replay at the end (costs as much as the live turns).
    pub replay_check: bool,
    pub mutation: Option<daemon::Mutation>,
    /// Snapshot `state.db` on every commit (any commit since the last
    /// checkpoint may survive a crash). Long runs checkpoint every 64
    /// commits instead, because a snapshot costs O(database size).
    pub db_snapshot_every_commit: bool,
    /// Compare recovered state with a full log rebuild on every Nth restart.
    pub rebuild_check_every: u64,
}

impl ScenarioConfig {
    /// Fault mix derived from the seed, so that a seed range covers all models.
    pub fn for_seed(seed: u64) -> Self {
        Self {
            clients: 4,
            requests_per_client: 12,
            actors: 3,
            crash_every: Duration::from_millis(150),
            crash_model: if seed.is_multiple_of(2) {
                CrashModel::PrefixTorn
            } else {
                CrashModel::Reorder
            },
            delivery: if (seed / 2).is_multiple_of(2) {
                Delivery::IdempotencyKeyed
            } else {
                Delivery::Unsafe
            },
            net: NetFaults {
                connect_fail: 0.03,
                response_lost: 0.03,
                hang: 0.005,
            },
            fsync_error: 0.002,
            clock_jumps: true,
            max_polls: 50_000_000,
            replay_check: true,
            mutation: None,
            db_snapshot_every_commit: true,
            rebuild_check_every: 1,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub crashes: u64,
    pub fatal_restarts: u64,
    pub recoveries: u64,
    pub reruns: u64,
    pub truncated_tails: u64,
    pub valid_after_tear: u64,
    pub stale_db_restarts: u64,
    pub committed: u64,
    pub acked_ok: u64,
    pub acked_failed: u64,
    pub retries: u64,
    pub clock_jumps: u64,
    pub effects_applied: u64,
    pub orphan_effects: u64,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub backend: &'static str,
    pub seed: u64,
    pub trace_hash: String,
    pub events: u64,
    pub polls: u64,
    pub sim_time: Duration,
    pub wall_time: Duration,
    pub end: String,
    pub stats: Stats,
    pub violations: Vec<String>,
    pub recent: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.violations.is_empty()
    }
    pub fn line(&self) -> String {
        let s = &self.stats;
        format!(
            "{} seed={} hash={} {} polls={} events={} sim={:.1}s wall={:.0}ms crashes={} fatal={} reruns={} torn-tails={} valid-after-tear={} stale-db={} committed={} ok={} failed={} retries={} jumps={} effects={} orphan-effects={} end={}",
            if self.ok() { "PASS" } else { "FAIL" },
            self.seed,
            self.trace_hash,
            self.backend,
            self.polls,
            self.events,
            self.sim_time.as_secs_f64(),
            self.wall_time.as_secs_f64() * 1000.0,
            s.crashes,
            s.fatal_restarts,
            s.reruns,
            s.truncated_tails,
            s.valid_after_tear,
            s.stale_db_restarts,
            s.committed,
            s.acked_ok,
            s.acked_failed,
            s.retries,
            s.clock_jumps,
            s.effects_applied,
            s.orphan_effects,
            self.end,
        )
    }
}

struct DurableView {
    offset: usize,
    next_lsn: u64,
    max_time: u64,
    begin_keys: BTreeSet<String>,
}

impl Default for DurableView {
    fn default() -> Self {
        Self {
            offset: crate::daemon::log::HEADER_LEN as usize,
            next_lsn: 1,
            max_time: 0,
            begin_keys: BTreeSet::new(),
        }
    }
}

/// `state.db` under WAL `synchronous=NORMAL`: after a crash the database is
/// consistent and reflects some commit at or after the last checkpoint.
#[derive(Default)]
struct DbImages {
    durable: Option<Vec<u8>>,
    recent: Vec<Vec<u8>>,
}

pub struct World {
    pub seed: u64,
    cfg: ScenarioConfig,
    backend: Arc<dyn Backend>,
    rng: SimRng,
    trace: Mutex<Trace>,
    pub disk: Arc<Mutex<Disk>>,
    db: Mutex<DbImages>,
    pub payments: Arc<Mutex<Payments>>,
    pub wall_offset: Arc<AtomicI64>,
    daemon: Mutex<Option<Arc<Daemon>>>,
    incarnation: AtomicU64,
    restarting: AtomicBool,
    violations: Mutex<Vec<String>>,
    stats: Mutex<Stats>,
    clients_done: AtomicUsize,
    finished: AtomicBool,
    acked: Mutex<BTreeMap<(String, String), Response>>,
    /// Last logical time handed out in the current incarnation, and the
    /// maximum logical time in the durable log when it started.
    times: Mutex<(Option<u64>, u64)>,
    /// Incremental world-side view of the durable log: records that were
    /// durable once stay durable (recovery only truncates unsynced bytes),
    /// so the view never needs a reset. Used by the I14 and I15 checks.
    durable_view: Mutex<DurableView>,
    commits: AtomicU64,
    me: Weak<World>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn data_dir() -> PathBuf {
    PathBuf::from("/var/lib/kronik/branches/main")
}

fn log_path() -> PathBuf {
    segment_path(&data_dir().join("log"))
}

struct WorldProbe(Weak<World>);

impl Probe for WorldProbe {
    fn event(&self, e: Event) {
        if let Some(w) = self.0.upgrade() {
            w.on_event(e);
        }
    }
}

impl World {
    pub fn new(seed: u64, cfg: ScenarioConfig, backend: Arc<dyn Backend>) -> Arc<Self> {
        let delivery = cfg.delivery;
        let wall_offset = backend.wall_offset();
        Arc::new_cyclic(|me| World {
            seed,
            cfg,
            backend,
            rng: SimRng::new(seed, b"world"),
            trace: Mutex::new(Trace::default()),
            disk: Arc::new(Mutex::new(Disk::default())),
            db: Mutex::new(DbImages::default()),
            payments: Arc::new(Mutex::new(Payments::new(delivery))),
            wall_offset,
            daemon: Mutex::new(None),
            incarnation: AtomicU64::new(0),
            restarting: AtomicBool::new(false),
            violations: Mutex::new(Vec::new()),
            stats: Mutex::new(Stats::default()),
            clients_done: AtomicUsize::new(0),
            finished: AtomicBool::new(false),
            acked: Mutex::new(BTreeMap::new()),
            times: Mutex::new((None, 0)),
            durable_view: Mutex::new(DurableView::default()),
            commits: AtomicU64::new(0),
            me: me.clone(),
        })
    }

    fn arc(&self) -> Arc<World> {
        self.me
            .upgrade()
            .unwrap_or_else(|| unreachable!("world dropped while running"))
    }

    pub fn finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }

    fn now(&self) -> Duration {
        self.backend.clock().monotonic()
    }

    pub fn event(&self, line: impl Into<String>) {
        let at = self.now();
        let line = line.into();
        if *LIVE_TRACE {
            eprintln!("{:>12} [{}] {line}", at.as_micros(), self.seed);
        }
        lock(&self.trace).push(at, line);
    }

    fn violation(&self, v: String) {
        self.event(format!("VIOLATION {v}"));
        lock(&self.violations).push(v);
    }

    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        self.backend.clock().sleep(d)
    }

    fn spawn(
        &self,
        node: NodeId,
        name: &'static str,
        fut: impl Future<Output = ()> + Send + 'static,
    ) {
        self.backend.spawner(node).spawn(name, Box::pin(fut));
    }

    fn on_event(&self, e: Event) {
        match e {
            Event::TimeAssigned { actor, time_ms } => {
                let mut t = lock(&self.times);
                let (last, durable_max) = *t;
                if time_ms <= durable_max || last.is_some_and(|l| time_ms <= l) {
                    drop(t);
                    self.violation(format!("I15: {actor} got logical time {time_ms}, last {last:?}, durable max {durable_max}"));
                    return;
                }
                t.0 = Some(time_ms);
                drop(t);
                self.event(format!("time {actor} {time_ms}"));
            }
            Event::Committed {
                lsn,
                actor,
                ingress_key,
                ok,
            } => {
                lock(&self.stats).committed += 1;
                self.event(format!("commit lsn={lsn} {actor} {ingress_key} ok={ok}"));
            }
            Event::Recovered {
                applied_from,
                applied,
                reruns,
                truncated,
                valid_after_tear,
                hwm,
            } => {
                let mut s = lock(&self.stats);
                s.recoveries += 1;
                s.reruns += reruns as u64;
                s.truncated_tails += u64::from(truncated > 0);
                s.valid_after_tear += u64::from(valid_after_tear);
                drop(s);
                self.event(format!(
                    "recovered from={applied_from} applied={applied} reruns={reruns} truncated={truncated} valid-after-tear={valid_after_tear} hwm={hwm}"
                ));
            }
            Event::Fatal(msg) => {
                self.event(format!("fatal {msg}"));
                lock(&self.stats).fatal_restarts += 1;
                let w = self.arc();
                self.spawn(SUPERVISOR, "fatal-restart", async move {
                    w.crash_and_restart("fatal").await
                });
            }
            Event::Violation(v) => self.violation(v),
        }
    }

    fn env(&self) -> Env {
        let clock = self.backend.clock();
        let me = self.me.clone();
        Env {
            clock: clock.clone(),
            spawner: self.backend.spawner(DAEMON),
            entropy: Arc::new(SimEntropy(self.rng.clone())),
            fs: Arc::new(SimFs::new(
                self.disk.clone(),
                clock.clone(),
                self.rng.clone(),
                DiskFaults {
                    crash_model: self.cfg.crash_model,
                    fsync_error: self.cfg.fsync_error,
                },
            )),
            net: Arc::new(SimNet {
                payments: self.payments.clone(),
                clock: clock.clone(),
                rng: self.rng.clone(),
                faults: self.cfg.net,
                trace: Arc::new(move |s| {
                    if let Some(w) = me.upgrade() {
                        w.event(s);
                    }
                }),
            }),
            procs: Arc::new(SimProcs { clock }),
        }
    }

    fn open_db(&self) -> Result<StateDb, String> {
        let image = lock(&self.db).durable.clone();
        let mut conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        if let Some(img) = image {
            conn.deserialize_read_exact("main", &img[..], img.len(), false)
                .map_err(|e| e.to_string())?;
        }
        let me = self.me.clone();
        let hook: daemon::state::CommitHook = Box::new(move |c: &mut Connection| {
            let Some(w) = me.upgrade() else { return };
            let img_now = |c: &mut Connection| c.serialize("main").ok().map(|d| d.to_vec());
            let mut db = lock(&w.db);
            if w.cfg.db_snapshot_every_commit {
                let Some(img) = img_now(c) else { return };
                if w.rng.chance(0.25) {
                    db.durable = Some(img);
                    db.recent.clear();
                } else {
                    db.recent.push(img);
                }
            } else if w.commits.fetch_add(1, Ordering::Relaxed) % 64 == 63 {
                db.durable = img_now(c);
            }
        });
        StateDb::open(conn, Some(hook)).map_err(|e| e.to_string())
    }

    fn durable_log(&self) -> Vec<u8> {
        Disk::snapshot_durable(&self.disk, &log_path()).unwrap_or_default()
    }

    fn start_daemon(&self) {
        let w = self.arc();
        let incarnation = self.incarnation.load(Ordering::SeqCst);
        // World-side view of I15: nothing handed out from now on may be at or
        // below the newest logical time that is already durable.
        let durable_max = self.durable_view().max_time;
        *lock(&self.times) = (None, durable_max);
        self.spawn(DAEMON, "daemon-start", async move {
            let db = match w.open_db() {
                Ok(db) => db,
                Err(e) => return w.violation(format!("cannot open state.db image: {e}")),
            };
            let cfg = daemon::Config {
                data_dir: data_dir(),
                delivery: match w.cfg.delivery {
                    Delivery::IdempotencyKeyed => DeliveryClass::IdempotencyKeyed,
                    Delivery::Unsafe => DeliveryClass::Unsafe,
                },
                effect_timeout: Duration::from_secs(10),
                mutation: w.cfg.mutation,
            };
            let probe: Arc<dyn Probe> = Arc::new(WorldProbe(Arc::downgrade(&w)));
            match Daemon::start(w.env(), cfg, wasm::code(), probe, db).await {
                Ok(d) => {
                    if w.incarnation.load(Ordering::SeqCst) != incarnation {
                        return;
                    }
                    // Recovery equivalence: incremental recovery from a stale
                    // state.db == rebuild of the durable log from scratch.
                    let restarts = lock(&w.stats).crashes;
                    let image = if restarts.is_multiple_of(w.cfg.rebuild_check_every.max(1)) {
                        Some(w.durable_log())
                    } else {
                        None
                    };
                    match image
                        .as_deref()
                        .map(replay::rebuild)
                        .unwrap_or_else(|| Ok(d.dump()))
                    {
                        Ok(rebuilt) if rebuilt == d.dump() => {}
                        Ok(rebuilt) => w.violation(format!(
                            "recovered state differs from log rebuild: {} vs {} entries",
                            d.dump().len(),
                            rebuilt.len()
                        )),
                        Err(e) => {
                            w.violation(format!("durable log unreadable after recovery: {e}"))
                        }
                    }
                    *lock(&w.daemon) = Some(d);
                    w.restarting.store(false, Ordering::SeqCst);
                    w.event("daemon up");
                }
                Err(e) if e.contains("STORAGE_CORRUPT") => w.violation(e),
                Err(e) => {
                    // An injected fsync error during recovery: crash again.
                    w.event(format!("start failed: {e}"));
                    let w2 = w.clone();
                    w.spawn(SUPERVISOR, "restart-after-failed-start", async move {
                        w2.crash_and_restart("failed start").await
                    });
                }
            }
        });
    }

    async fn crash_and_restart(self: Arc<Self>, why: &'static str) {
        if self.restarting.swap(true, Ordering::SeqCst) && why != "failed start" {
            return;
        }
        self.incarnation.fetch_add(1, Ordering::SeqCst);
        *lock(&self.daemon) = None;
        self.backend.kill(DAEMON);
        {
            let mut disk = lock(&self.disk);
            disk.crash(self.cfg.crash_model, &self.rng);
        }
        {
            let mut db = lock(&self.db);
            let n = db.recent.len() as u64;
            let pick = self.rng.below(n + 1) as usize;
            if pick > 0 {
                db.durable = Some(db.recent[pick - 1].clone());
            }
            if pick < n as usize {
                lock(&self.stats).stale_db_restarts += 1;
            }
            db.recent.clear();
        }
        lock(&self.stats).crashes += 1;
        self.event(format!("crash ({why})"));
        self.sleep(
            self.rng
                .duration(Duration::from_millis(1), Duration::from_millis(40)),
        )
        .await;
        self.start_daemon();
    }

    /// Sends one request through the "gateway". `None` means no definite
    /// answer (connection refused, crash, timeout, 503): the client retries
    /// with the same idempotency key.
    async fn send(self: &Arc<Self>, req: Request) -> Option<Response> {
        // Bind first: a guard in a let-else initializer lives through the
        // else block, and holding a std mutex across an await deadlocks the
        // single-threaded simulator.
        let current = lock(&self.daemon).clone();
        let Some(d) = current else {
            self.sleep(Duration::from_millis(2)).await;
            return None;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.spawn(DAEMON, "request", async move {
            let _ = tx.send(d.handle(req).await);
        });
        let timeout = self.sleep(Duration::from_secs(30));
        let r = tokio::select! {
            biased;
            r = rx => r.ok(),
            () = timeout => None,
        };
        r.filter(|r| r.status != 503)
    }

    async fn client(self: Arc<Self>, c: usize) {
        for i in 0..self.cfg.requests_per_client {
            let actor_key = format!("a{}", self.rng.below(self.cfg.actors as u64));
            let ingress_key = format!("c{c}-r{i}");
            loop {
                self.sleep(self.rng.duration(Duration::ZERO, Duration::from_millis(20)))
                    .await;
                let req = Request {
                    actor_key: actor_key.clone(),
                    ingress_key: ingress_key.clone(),
                    body: Vec::new(),
                };
                match self.send(req).await {
                    Some(resp) => {
                        let ok = resp.status == 200;
                        self.event(format!(
                            "ack {actor_key} {ingress_key} {} {}",
                            resp.status,
                            String::from_utf8_lossy(&resp.body)
                        ));
                        let mut s = lock(&self.stats);
                        if ok {
                            s.acked_ok += 1;
                        } else {
                            s.acked_failed += 1;
                        }
                        drop(s);
                        lock(&self.acked)
                            .insert((format!("counter/{actor_key}"), ingress_key.clone()), resp);
                        break;
                    }
                    None => {
                        lock(&self.stats).retries += 1;
                        self.sleep(
                            self.rng
                                .duration(Duration::from_millis(5), Duration::from_millis(50)),
                        )
                        .await;
                    }
                }
            }
        }
        self.clients_done.fetch_add(1, Ordering::SeqCst);
    }

    fn clients_finished(&self) -> bool {
        self.clients_done.load(Ordering::SeqCst) == self.cfg.clients
    }

    async fn crasher(self: Arc<Self>) {
        if self.cfg.crash_every.is_zero() {
            return;
        }
        while !self.clients_finished() {
            let d = self.rng.duration(Duration::ZERO, self.cfg.crash_every * 2);
            self.sleep(d).await;
            if !self.clients_finished() && lock(&self.daemon).is_some() {
                self.clone().crash_and_restart("injected").await;
            }
        }
    }

    async fn clock_chaos(self: Arc<Self>) {
        while self.cfg.clock_jumps && !self.clients_finished() {
            self.sleep(
                self.rng
                    .duration(Duration::from_millis(50), Duration::from_millis(400)),
            )
            .await;
            if self.rng.chance(0.4) {
                let jump = self.rng.below(7000) as i64 - 5000;
                self.wall_offset.fetch_add(jump, Ordering::Relaxed);
                lock(&self.stats).clock_jumps += 1;
                self.event(format!("wall clock jump {jump}ms"));
            }
        }
    }

    /// The supervisor's main task.
    pub async fn main(self: Arc<Self>) {
        let me = self.me.clone();
        lock(&self.payments).set_check(Arc::new(move |req| match me.upgrade() {
            Some(w) => w.check_turn_begin_durable(req),
            None => Ok(()),
        }));
        self.event(format!(
            "start seed={} model={:?} delivery={:?}",
            self.seed, self.cfg.crash_model, self.cfg.delivery
        ));
        self.start_daemon();
        for c in 0..self.cfg.clients {
            let w = self.clone();
            self.spawn(SUPERVISOR, "client", async move { w.client(c).await });
        }
        let w = self.clone();
        self.spawn(SUPERVISOR, "crasher", async move { w.crasher().await });
        let w = self.clone();
        self.spawn(
            SUPERVISOR,
            "clock-chaos",
            async move { w.clock_chaos().await },
        );
        while !self.clients_finished() {
            self.sleep(Duration::from_millis(10)).await;
        }
        // Let in-flight recovery finish so the final daemon is up.
        while lock(&self.daemon).is_none() {
            self.sleep(Duration::from_millis(10)).await;
        }
        self.event("workload done");
        self.finished.store(true, Ordering::SeqCst);
    }

    /// I14, checked by the external service at the moment it receives a
    /// request: a `TurnBegin` producing this idempotency key must already be
    /// durable (contents fsynced *and* the segment's name durable).
    fn check_turn_begin_durable(&self, req: &crate::env::HttpRequest) -> Result<(), String> {
        let key = req
            .headers
            .iter()
            .find(|(n, _)| n == "idempotency-key")
            .map(|(_, v)| v.clone())
            .ok_or("I14: effect without idempotency key")?;
        let view = self.durable_view();
        if view.begin_keys.contains(&key) {
            Ok(())
        } else {
            Err(format!(
                "I14: external effect {key} before its TurnBegin was durable"
            ))
        }
    }

    /// Brings the durable view up to date with the disk and returns it.
    fn durable_view(&self) -> std::sync::MutexGuard<'_, DurableView> {
        let mut v = lock(&self.durable_view);
        if let Some((len, bytes)) = Disk::durable_suffix_of(&self.disk, &log_path(), v.offset)
            && len >= v.offset
        {
            let (recs, used) = crate::daemon::log::parse_records(&bytes, v.next_lsn);
            for (lsn, r) in recs {
                v.next_lsn = lsn + 1;
                match r {
                    Record::TurnBegin(b) => {
                        v.max_time = v.max_time.max(b.time_ms);
                        v.begin_keys.insert(idempotency_key(&b.causal_key, 0));
                    }
                    Record::TurnRecord(t) => v.max_time = v.max_time.max(t.begin.time_ms),
                    Record::EffectResult(_) => {}
                }
            }
            v.offset += used;
        }
        v
    }

    /// End-of-run invariants. Called after the executor stopped.
    pub fn finish(&self, end: RunEnd, polls: u64, wall: Duration) -> Report {
        if end != RunEnd::Stopped {
            self.violation(format!("run did not complete: {end:?}"));
        }
        let image = self.durable_log();
        let records = match scan(&image) {
            Ok(s) => s.records,
            Err(c) => {
                self.violation(format!("final log unreadable: {}", c.0));
                Vec::new()
            }
        };
        let rebuilt = replay::rebuild(&image).unwrap_or_default();
        if let Some(d) = lock(&self.daemon).clone()
            && d.dump() != rebuilt
        {
            self.violation("final live state differs from log rebuild".into());
        }
        if self.cfg.replay_check {
            match replay::identity_replay(&wasm::code(), &image) {
                Ok(r) => {
                    for m in r.mismatches {
                        self.violation(format!("identity replay: {m}"));
                    }
                    if r.state != rebuilt {
                        self.violation("identity replay state differs from rebuild".into());
                    }
                }
                Err(e) => self.violation(format!("identity replay failed: {e}")),
            }
        }

        // Committed turns per ingress key, in LSN order.
        let mut by_key: BTreeMap<(String, String), Vec<(u64, Outcome)>> = BTreeMap::new();
        let mut ok_n: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        let mut ok_keys: BTreeSet<String> = BTreeSet::new();
        for (lsn, r) in &records {
            if let Record::TurnRecord(t) = r {
                by_key
                    .entry((t.begin.actor.clone(), t.begin.ingress_key.clone()))
                    .or_default()
                    .push((*lsn, t.outcome.clone()));
                if let Outcome::Ok { body, .. } = &t.outcome {
                    let n = String::from_utf8_lossy(body)
                        .split_whitespace()
                        .find_map(|p| p.strip_prefix("n=")?.parse::<u64>().ok())
                        .unwrap_or(0);
                    ok_n.entry(t.begin.actor.clone()).or_default().push(n);
                    ok_keys.insert(idempotency_key(&t.begin.causal_key, 0));
                }
            }
        }
        for (k, v) in &by_key {
            if v.len() > 1 {
                self.violation(format!(
                    "exactly-once: ingress key {k:?} committed {} times",
                    v.len()
                ));
            }
        }
        // No acknowledged turn lost, and the acknowledgement matches the log.
        for ((actor, key), resp) in lock(&self.acked).iter() {
            match by_key
                .get(&(actor.clone(), key.clone()))
                .and_then(|v| v.first())
            {
                None => self.violation(format!(
                    "acked {actor} {key} ({}) has no TurnRecord",
                    resp.status
                )),
                Some((_, Outcome::Ok { status, body }))
                    if *status == resp.status && *body == resp.body => {}
                Some((_, Outcome::Failed { code, .. }))
                    if resp.status == 500 && code.as_bytes() == resp.body => {}
                Some((lsn, o)) => self.violation(format!(
                    "acked {actor} {key} {resp:?} but lsn {lsn} has {o:?}"
                )),
            }
        }
        // State applied exactly once: n runs 1..=N per actor, and equals state.
        for (actor, ns) in &ok_n {
            let expect: Vec<u64> = (1..=ns.len() as u64).collect();
            if *ns != expect {
                self.violation(format!(
                    "{actor}: committed n sequence {ns:?} is not 1..={}",
                    ns.len()
                ));
            }
            let state_n = rebuilt
                .get(&format!("kv {actor} n"))
                .cloned()
                .unwrap_or_default();
            if state_n != ns.len().to_string() {
                self.violation(format!(
                    "{actor}: state n={state_n} but {} committed increments",
                    ns.len()
                ));
            }
        }
        let expected_acks = self.cfg.clients * self.cfg.requests_per_client;
        if lock(&self.acked).len() != expected_acks {
            self.violation(format!(
                "{} of {expected_acks} requests acknowledged",
                lock(&self.acked).len()
            ));
        }
        // Effects: every committed increment's charge reached the service.
        let payments = lock(&self.payments);
        let applied: BTreeSet<String> = payments.applied.iter().map(|(k, _)| k.clone()).collect();
        for k in &ok_keys {
            if !applied.contains(k) {
                self.violation(format!(
                    "committed turn's effect {k} never reached the service"
                ));
            }
        }
        let violations_from_service = payments.violations.clone();
        let effects_applied = payments.applied.len() as u64;
        drop(payments);
        for v in violations_from_service {
            self.violation(v);
        }
        let mut stats = lock(&self.stats).clone();
        stats.effects_applied = effects_applied;
        stats.orphan_effects = effects_applied.saturating_sub(ok_keys.len() as u64);
        let trace = lock(&self.trace);
        Report {
            backend: self.backend.name(),
            seed: self.seed,
            trace_hash: trace.hash(),
            events: trace.events,
            polls,
            sim_time: self.now(),
            wall_time: wall,
            end: format!("{end:?}"),
            stats,
            violations: lock(&self.violations).clone(),
            recent: trace.recent(),
        }
    }
}

// ------------------------------------------------------------ own executor

pub struct OwnBackend {
    exec: exec::Handle,
    clock: Arc<SimClock>,
}

impl Backend for OwnBackend {
    fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }
    fn spawner(&self, node: NodeId) -> Arc<dyn Spawner> {
        Arc::new(SimSpawner {
            exec: self.exec.clone(),
            node,
        })
    }
    fn kill(&self, node: NodeId) {
        self.exec.kill_node(node);
    }
    fn name(&self) -> &'static str {
        "own"
    }
    fn wall_offset(&self) -> Arc<AtomicI64> {
        self.clock.wall_offset_ms.clone()
    }
}

/// Runs one seed on the own executor.
pub fn run_own(seed: u64, cfg: ScenarioConfig) -> Report {
    let started = Instant::now();
    let executor = Executor::new(seed);
    let clock = Arc::new(SimClock {
        exec: executor.handle(),
        wall_base_ms: 1_761_300_000_000,
        wall_offset_ms: Arc::new(AtomicI64::new(0)),
    });
    let backend = Arc::new(OwnBackend {
        exec: executor.handle(),
        clock,
    });
    let max_polls = cfg.max_polls;
    let world = World::new(seed, cfg, backend);
    let w = world.clone();
    executor
        .handle()
        .spawn(SUPERVISOR, "main", Box::pin(async move { w.main().await }));
    let end = executor.run(max_polls, || world.finished());
    let polls = executor.handle().polls();
    // Drop every task before the final checks (no more concurrent mutation).
    executor.handle().kill_node(DAEMON);
    executor.handle().kill_node(SUPERVISOR);
    world.finish(end, polls, started.elapsed())
}

// ------------------------------------------------------------ production mode

struct CountingProbe {
    committed: AtomicU64,
    violations: Mutex<Vec<String>>,
}

impl Probe for CountingProbe {
    fn event(&self, e: Event) {
        match e {
            Event::Committed { .. } => {
                self.committed.fetch_add(1, Ordering::Relaxed);
            }
            Event::Violation(v) | Event::Fatal(v) => lock(&self.violations).push(v),
            _ => {}
        }
    }
}

/// The same daemon code on tokio's multi-threaded runtime with the real file
/// system and a WAL `state.db`: concurrent requests, a restart through
/// recovery, and identity replay of the real log file.
pub fn run_real() -> Result<String, String> {
    use crate::env_real::{LoopbackNet, RealClock, RealEntropy, RealFs, RealProcs, RealSpawner};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir().join(format!("kronik-spike-d-real-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let code = wasm::code();
    let result = rt.block_on(async {
        let h = tokio::runtime::Handle::current();
        let received = Arc::new(Mutex::new(Vec::new()));
        let env = Env {
            clock: Arc::new(RealClock::default()),
            spawner: Arc::new(RealSpawner(h.clone())),
            entropy: Arc::new(RealEntropy),
            fs: Arc::new(RealFs(h.clone())),
            net: Arc::new(LoopbackNet { received: received.clone() }),
            procs: Arc::new(RealProcs),
        };
        let cfg = daemon::Config {
            data_dir: dir.clone(),
            delivery: DeliveryClass::IdempotencyKeyed,
            effect_timeout: Duration::from_secs(10),
            mutation: None,
        };
        let probe = Arc::new(CountingProbe { committed: AtomicU64::new(0), violations: Mutex::new(Vec::new()) });
        let open_db = || -> Result<StateDb, String> {
            let c = Connection::open(dir.join("state.db")).map_err(|e| e.to_string())?;
            c.pragma_update(None, "journal_mode", "WAL").map_err(|e| e.to_string())?;
            c.pragma_update(None, "synchronous", "NORMAL").map_err(|e| e.to_string())?;
            StateDb::open(c, None).map_err(|e| e.to_string())
        };
        let d = Daemon::start(env.clone(), cfg.clone(), code.clone(), probe.clone(), open_db()?).await?;
        let started = Instant::now();
        let mut joins = Vec::new();
        for c in 0..16usize {
            let d = d.clone();
            joins.push(tokio::spawn(async move {
                let mut ok = 0;
                for i in 0..25usize {
                    let req = Request { actor_key: format!("a{}", (c + i) % 4), ingress_key: format!("c{c}-r{i}"), body: Vec::new() };
                    if d.handle(req).await.status == 200 {
                        ok += 1;
                    }
                }
                ok
            }));
        }
        let mut ok = 0;
        for j in joins {
            ok += j.await.map_err(|e| e.to_string())?;
        }
        let elapsed = started.elapsed();
        let before = d.dump();
        drop(d);
        // Let the old writer and applier observe their closed channels.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let d2 = Daemon::start(env, cfg, code.clone(), probe.clone(), open_db()?).await?;
        let after = d2.dump();
        let image = std::fs::read(segment_path(&dir.join("log"))).map_err(|e| e.to_string())?;
        let rep = replay::identity_replay(&code, &image)?;
        let violations = lock(&probe.violations).clone();
        if after != before || rep.state != after || !rep.mismatches.is_empty() || !violations.is_empty() || ok != 400 {
            return Err(format!(
                "real mode mismatch: ok={ok} recovered_equal={} replay_equal={} mismatches={:?} violations={violations:?}",
                after == before,
                rep.state == after,
                rep.mismatches
            ));
        }
        Ok(format!(
            "real: 400 requests from 16 tasks on tokio multi-thread (4 workers): {ok} ok in {:.0} ms ({:.0} turns/s, group commit + fdatasync on {}), log {} bytes, {} effects; restart recovered identical state; identity replay of {} turns: 0 mismatches",
            elapsed.as_secs_f64() * 1000.0,
            400.0 / elapsed.as_secs_f64(),
            dir.display(),
            image.len(),
            lock(&received).len(),
            rep.turns
        ))
    });
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// Executor overhead without the daemon: `tasks` tasks each sleep a random
/// 0..100 µs `iters` times and bump a shared counter through a
/// `tokio::sync::Mutex`. Returns (polls, wall).
pub fn exec_bench_own(seed: u64, tasks: usize, iters: usize) -> (u64, Duration) {
    let started = Instant::now();
    let executor = Executor::new(seed);
    let h = executor.handle();
    let rng = SimRng::new(seed, b"bench");
    let counter = Arc::new(tokio::sync::Mutex::new(0u64));
    for _ in 0..tasks {
        let h2 = h.clone();
        let rng = rng.clone();
        let counter = counter.clone();
        h.spawn(
            SUPERVISOR,
            "bench",
            Box::pin(async move {
                for _ in 0..iters {
                    h2.sleep(Duration::from_micros(rng.below(100))).await;
                    *counter.lock().await += 1;
                }
            }),
        );
    }
    executor.run(u64::MAX, || false);
    (h.polls(), started.elapsed())
}
