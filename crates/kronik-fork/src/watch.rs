//! `kronik watch` (docs/design/m11-watch.md, ADR 0024): after a deployment,
//! compare the error rate and latency of its kinds' turns with the window
//! before it, evaluate the policy's guards, and alert or roll back.
//!
//! A watch is a daemon task that outlives the request that started it. It
//! is kept in `<data>/watches/<id>.json` and resumed after a restart; its
//! metrics are computed from the log alone, and every guard that fires is a
//! `GuardTriggered` record holding exactly what was evaluated.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{Lsn, random_id};
use kronik_log::LogError;
use kronik_policy::{GuardAction, GuardEvaluation, RuleSet};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::proposal::{Proposals, write_atomic};

/// How often a watch evaluates its guards.
pub const INTERVAL: Duration = Duration::from_secs(5);

/// The longest `--for`: 24 hours. Both windows are read from the log and
/// the samples after the deployment are kept in memory.
pub const MAX_FOR_MS: u64 = 24 * 60 * 60 * 1000;

/// How the `reason` of a guard's alert starts when its `when` could not be
/// evaluated. Such an alert does not use the guard up: it is evaluated
/// again, and can still fire its own action.
pub const EVAL_ERROR: &str = "the guard could not be evaluated: ";

const WATCHING: &str = "watching";

/// The persisted watch (`watches/<id>.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Watch {
    /// `w-` and 12 hex characters.
    pub id: String,
    /// The watched deployment's epoch and the LSN of its record.
    pub epoch: u64,
    pub deployment_lsn: Lsn,
    /// The length of both windows, in logical milliseconds.
    pub for_ms: u64,
    /// Where the window after the deployment starts: the later of its
    /// audit's wall time and the logical time of the last turn before it.
    pub deployment_time_ms: u64,
    /// `watching`, then `done` (the window passed), `rolled_back`,
    /// `superseded` (a later deployment of its kinds replaced the watched
    /// one; nothing acted), `stopped` or `failed`.
    pub status: String,
    pub reason: String,
    pub token_id: String,
    /// Wall time the watch was created (for humans).
    pub created_ms: u64,
    /// The guards that fired, in order; each fires at most once, besides
    /// one alert when it could not be evaluated ([`EVAL_ERROR`]).
    pub triggered: Vec<Triggered>,
    /// The `guard` object of the last evaluation.
    pub metrics: Option<Value>,
    pub error: Option<ApiError>,
    /// Who stopped the watch and why (`kronik watches stop`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<Stopped>,
}

/// `kronik watches stop`'s audit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stopped {
    pub token_id: String,
    pub reason: String,
    pub wall_time_ms: u64,
}

/// A guard that fired, as its `GuardTriggered` record says.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Triggered {
    pub guard: String,
    pub action: GuardAction,
    /// `alerted`, `rolled_back`, `rollback_refused_schema` or
    /// `rollback_failed`.
    pub outcome: String,
    /// The `GuardTriggered` record's LSN; 0 in a dry run, which lists the
    /// guards that would fire now.
    pub lsn: Lsn,
    /// The rollback deployment's epoch, 0 without one.
    pub rollback_epoch: u64,
    pub reason: String,
}

/// Every watch of the node.
pub struct Watches {
    node: Arc<Node>,
    proposals: Arc<Proposals>,
    dir: PathBuf,
    interval: Duration,
    watches: std::sync::Mutex<BTreeMap<String, Watch>>,
    /// Held while a watch decides and acts, and by `stop`: once `stop`
    /// returns, the watch writes no record and rolls nothing back.
    acting: tokio::sync::Mutex<()>,
}

fn internal(m: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, m.to_string())
}

fn log_err(e: LogError) -> ApiError {
    match e {
        LogError::Corrupt(m) => ApiError::new(ErrorCode::StorageCorrupt, m),
        other => internal(other),
    }
}

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn not_found(id: &str) -> ApiError {
    ApiError::new(
        ErrorCode::WatchNotFound,
        format!("no watch {id:?}; run: kronik watches list"),
    )
}

fn outcome_name(o: pb::GuardOutcome) -> &'static str {
    match o {
        pb::GuardOutcome::Alerted => "alerted",
        pb::GuardOutcome::RolledBack => "rolled_back",
        pb::GuardOutcome::RollbackRefusedSchema => "rollback_refused_schema",
        pb::GuardOutcome::RollbackFailed => "rollback_failed",
        pb::GuardOutcome::Unspecified => "unspecified",
    }
}

fn action_of(a: i32) -> GuardAction {
    if a == pb::GuardAction::Rollback as i32 {
        GuardAction::Rollback
    } else {
        GuardAction::Alert
    }
}

fn triggered_of(lsn: Lsn, g: &pb::GuardTriggered) -> Triggered {
    Triggered {
        guard: g.guard.clone(),
        action: action_of(g.action),
        outcome: outcome_name(g.outcome()).to_owned(),
        lsn,
        rollback_epoch: g.rollback_epoch,
        reason: g.reason.clone(),
    }
}

/// A turn counts as failed when the code or the host failed it: any
/// outcome but `COMMITTED` and `REJECTED` (the client's invalid input), or
/// a committed HTTP response with a 5xx status.
fn failed_turn(outcome: Option<&pb::Outcome>) -> bool {
    let Some(o) = outcome else {
        return true;
    };
    if o.kind == pb::OutcomeKind::Committed as i32 {
        matches!(&o.output, Some(pb::outcome::Output::Http(r)) if r.status >= 500)
    } else {
        o.kind != pb::OutcomeKind::Rejected as i32
    }
}

/// One window's turns while they are counted.
#[derive(Default)]
struct Side {
    from_lsn: Lsn,
    to_lsn: Lsn,
    turns: u64,
    failed: u64,
    /// Measured durations only: 0 means none (records from before M11,
    /// turns that never ran).
    durations: Vec<u64>,
}

impl Side {
    fn add(&mut self, lsn: Lsn, failed: bool, duration_us: u64) {
        if self.turns == 0 {
            self.from_lsn = lsn;
        }
        self.to_lsn = lsn;
        self.turns += 1;
        self.failed += u64::from(failed);
        if duration_us > 0 {
            self.durations.push(duration_us);
        }
    }

    fn window(&self, from_time_ms: u64, to_time_ms: u64) -> pb::GuardWindow {
        let turns = self.turns;
        let p = crate::diff::percentiles(self.durations.clone());
        pb::GuardWindow {
            from_lsn: self.from_lsn,
            to_lsn: self.to_lsn,
            from_time_ms,
            to_time_ms,
            turns,
            failed: self.failed,
            error_rate: if turns == 0 {
                0.0
            } else {
                self.failed as f64 / turns as f64
            },
            latency_p50_us: p.p50,
            latency_p99_us: p.p99,
        }
    }
}

/// The `before`/`after` object a guard sees for a window.
fn window_json(w: &pb::GuardWindow) -> Value {
    json!({
        "turns": w.turns,
        "failed": w.failed,
        "error_rate": w.error_rate,
        "latency_p50_ms": w.latency_p50_us as f64 / 1000.0,
        "latency_p99_ms": w.latency_p99_us as f64 / 1000.0,
    })
}

/// What a watch has read of the log so far.
struct Scan {
    /// The next LSN to read.
    next: Lsn,
    kinds: BTreeSet<String>,
    before: Side,
    /// The window before the deployment once the scan is past it: it is
    /// final then, so its percentiles are computed once and its samples
    /// dropped.
    before_window: Option<pb::GuardWindow>,
    after: Side,
    /// The highest logical time of any turn read.
    hwm: u64,
    /// This watch's `GuardTriggered` records, with their LSNs.
    logged: Vec<(Lsn, pb::GuardTriggered)>,
    /// The LSN of the first later `Deployment` that touches a watched kind
    /// (a promote, a deploy, a rollback): the window after the deployment
    /// ends there, as later turns run other code.
    end: Option<Lsn>,
    /// That deployment is a rollback this watch made: its epoch and the
    /// guard its audit names.
    rollback: Option<(u64, String)>,
}

impl Scan {
    /// Starts at the first segment that can hold a turn of the window
    /// before the deployment (segments know their highest logical time).
    fn start(node: &Node, w: &Watch, kinds: BTreeSet<String>) -> Result<Scan, ApiError> {
        let from_time = w.deployment_time_ms.saturating_sub(w.for_ms);
        let first = node
            .store()
            .db()
            .segments()
            .map_err(internal)?
            .into_iter()
            .find(|&(_, _, last_time)| last_time >= from_time)
            .map_or(w.deployment_lsn, |(start, _, _)| start);
        Ok(Scan {
            next: first.clamp(1, w.deployment_lsn.max(1)),
            kinds,
            before: Side::default(),
            before_window: None,
            after: Side::default(),
            hwm: 0,
            logged: Vec::new(),
            end: None,
            rollback: None,
        })
    }

    async fn read(&mut self, node: &Node, w: &Watch, upto: Lsn) -> Result<(), ApiError> {
        if upto < self.next {
            return Ok(());
        }
        let rollback_reason = format!("watch {}:", w.id);
        node.reader()
            .read(self.next, upto, |c| {
                self.add(w, &rollback_reason, c.lsn, c.record);
                Ok(())
            })
            .await
            .map_err(log_err)?;
        self.next = upto + 1;
        Ok(())
    }

    fn add(&mut self, w: &Watch, rollback_reason: &str, lsn: Lsn, record: Record) {
        let t_d = w.deployment_time_ms;
        // A rebase switch changes code with its embedded deployment (M13):
        // it ends the window as a `Deployment` does. Rebased turns are the
        // fork's, not main's under the watched code.
        let record = match record {
            Record::StateRebase(pb::StateRebase {
                part: Some(pb::state_rebase::Part::Switch(s)),
                ..
            }) => match s.deployment {
                Some(d) => Record::Deployment(d),
                None => return,
            },
            other => other,
        };
        match record {
            Record::TurnRecord(t) => {
                self.hwm = self.hwm.max(t.logical_time_ms);
                if !t
                    .actor
                    .as_ref()
                    .is_some_and(|a| self.kinds.contains(&a.kind))
                {
                    return;
                }
                let time = t.logical_time_ms;
                let failed = failed_turn(t.outcome.as_ref());
                if lsn < w.deployment_lsn && time < t_d && time >= t_d.saturating_sub(w.for_ms) {
                    self.before.add(lsn, failed, t.duration_us);
                } else if lsn > w.deployment_lsn
                    && self.end.is_none()
                    && t.config_epoch >= w.epoch
                    && time >= t_d
                    && time < t_d.saturating_add(w.for_ms)
                {
                    self.after.add(lsn, failed, t.duration_us);
                }
            }
            Record::GuardTriggered(g) if g.watch_id == w.id => self.logged.push((lsn, g)),
            Record::Deployment(d)
                if self.end.is_none()
                    && d.epoch > w.epoch
                    && d.kinds.iter().any(|k| self.kinds.contains(&k.kind)) =>
            {
                self.end = Some(lsn);
                let own = d.cause == pb::DeploymentCause::Rollback as i32
                    && d.rollback_of_epoch == w.epoch;
                // ``watch <id>: guard `<name>` fired``
                if own
                    && let Some(rest) = d
                        .audit
                        .as_ref()
                        .and_then(|a| a.reason.strip_prefix(rollback_reason))
                {
                    let guard = rest.split('`').nth(1).unwrap_or_default();
                    self.rollback = Some((d.epoch, guard.to_owned()));
                }
            }
            _ => {}
        }
    }

    /// Both windows as recorded, and the `guard` object the guards see.
    fn metrics(
        &mut self,
        w: &Watch,
        schema_changed: bool,
    ) -> (pb::GuardWindow, pb::GuardWindow, Value) {
        let t_d = w.deployment_time_ms;
        let before = match &self.before_window {
            Some(b) => *b,
            None => {
                let b = self.before.window(t_d.saturating_sub(w.for_ms), t_d);
                if self.next > w.deployment_lsn {
                    self.before = Side::default();
                    self.before_window = Some(b);
                }
                b
            }
        };
        let after = self.after.window(t_d, t_d.saturating_add(w.for_ms));
        let guard = json!({
            "epoch": w.epoch,
            "kinds": self.kinds,
            "schema_changed": schema_changed,
            "observed_ms": self.hwm.clamp(t_d, t_d.saturating_add(w.for_ms)) - t_d,
            "before": window_json(&before),
            "after": window_json(&after),
        });
        (before, after, guard)
    }
}

/// One evaluation of a watch's guards.
struct Evaluated {
    before: pb::GuardWindow,
    after: pb::GuardWindow,
    guard: Value,
    /// Why the rollback plan fails now, if it does (the dry run's outcome).
    rollback_error: Option<ErrorCode>,
    rules: RuleSet,
    evaluation: GuardEvaluation,
}

impl Evaluated {
    /// The `when` of the guard `name` in force, for the record.
    fn when(&self, name: &str) -> String {
        self.rules
            .effective_guards()
            .iter()
            .find(|g| g.name == name)
            .map(|g| g.when.clone())
            .unwrap_or_default()
    }

    /// A `GuardTriggered` with what was evaluated; the caller sets the
    /// outcome, the rollback's epoch and the reason.
    fn record(
        &self,
        w: &Watch,
        guard: &str,
        action: GuardAction,
        observed_lsn: Lsn,
    ) -> pb::GuardTriggered {
        pb::GuardTriggered {
            deployment_epoch: w.epoch,
            deployment_lsn: w.deployment_lsn,
            watch_id: w.id.clone(),
            guard: guard.to_owned(),
            action: match action {
                GuardAction::Alert => pb::GuardAction::Alert,
                GuardAction::Rollback => pb::GuardAction::Rollback,
            } as i32,
            outcome: pb::GuardOutcome::Unspecified as i32,
            before: Some(self.before),
            after: Some(self.after),
            observed_lsn,
            rollback_epoch: 0,
            reason: String::new(),
            audit: None,
        }
    }
}

fn kinds_of(d: &pb::Deployment) -> BTreeSet<String> {
    d.kinds.iter().map(|k| k.kind.clone()).collect()
}

impl Watches {
    /// Loads the watches recorded under `data/watches`. Call
    /// [`Watches::start`] to resume the unfinished ones.
    pub fn open(
        node: Arc<Node>,
        proposals: Arc<Proposals>,
        data: PathBuf,
    ) -> Result<Watches, ApiError> {
        let dir = data.join("watches");
        let mut watches = BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let path = e.path();
                if path.extension().is_none_or(|x| x != "json") {
                    continue;
                }
                let bytes = std::fs::read(&path).map_err(internal)?;
                let w: Watch = serde_json::from_slice(&bytes)
                    .map_err(|err| internal(format!("{}: {err}", path.display())))?;
                watches.insert(w.id.clone(), w);
            }
        }
        Ok(Watches {
            node,
            proposals,
            dir,
            interval: INTERVAL,
            watches: std::sync::Mutex::new(watches),
            acting: tokio::sync::Mutex::new(()),
        })
    }

    /// Test hook: evaluate every `interval` instead of [`INTERVAL`].
    #[doc(hidden)]
    pub fn with_interval(mut self, interval: Duration) -> Watches {
        self.interval = interval;
        self
    }

    /// Resumes every watch still `watching`: it recomputes its metrics from
    /// the log, and its `GuardTriggered` records decide what is left.
    pub fn start(self) -> Arc<Watches> {
        let this = Arc::new(self);
        let ids: Vec<String> = lock(&this.watches)
            .values()
            .filter(|w| w.status == WATCHING)
            .map(|w| w.id.clone())
            .collect();
        for id in ids {
            drop(this.spawn(id));
        }
        this
    }

    fn spawn(self: &Arc<Self>, id: String) -> kronik_core::env::JoinHandle<()> {
        self.node
            .env()
            .spawn("watch", run(Arc::downgrade(self), id))
    }

    fn save(&self, w: &Watch) -> Result<(), ApiError> {
        std::fs::create_dir_all(&self.dir).map_err(internal)?;
        let bytes = serde_json::to_vec_pretty(w).map_err(internal)?;
        write_atomic(&self.dir.join(format!("{}.json", w.id)), &bytes)
    }

    /// Changes the watch `id` and saves it.
    fn update(&self, id: &str, f: impl FnOnce(&mut Watch)) -> Result<Watch, ApiError> {
        let mut watches = lock(&self.watches);
        let w = watches.get_mut(id).ok_or_else(|| not_found(id))?;
        f(w);
        self.save(w)?;
        Ok(w.clone())
    }

    pub fn list(&self) -> Vec<Watch> {
        lock(&self.watches).values().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Result<Watch, ApiError> {
        lock(&self.watches)
            .get(id)
            .cloned()
            .ok_or_else(|| not_found(id))
    }

    /// `kronik watch <epoch> --for <for_ms>`: starts watching the
    /// deployment `epoch`, which must be the latest deployment of its
    /// kinds. With `wait` it returns when the watch is over; otherwise at
    /// once, `watching`. A dry run keeps nothing: it returns the current
    /// metrics and, in `triggered` (with LSN 0), the guards that would fire
    /// now.
    pub async fn watch(
        self: &Arc<Self>,
        epoch: u64,
        for_ms: u64,
        audit: pb::Audit,
        dry_run: bool,
        wait: bool,
    ) -> Result<Watch, ApiError> {
        if for_ms == 0 || for_ms > MAX_FOR_MS {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("for_ms must be more than 0 and at most {MAX_FOR_MS} (24h)"),
            )
            .with_hint(
                "Name how long to watch, up to 24h: kronik watch <epoch> --for 10m --reason \"...\"",
            ));
        }
        let deployments = self.node.store().db().deployments().map_err(internal)?;
        let Some((lsn, d)) = deployments.iter().find(|(_, d)| d.epoch == epoch).cloned() else {
            return Err(ApiError::new(
                ErrorCode::DeploymentNotFound,
                format!("no deployment with epoch {epoch}; run: kronik deployments list"),
            ));
        };
        let kinds = kinds_of(&d);
        // A guard's rollback restores the code from before this deployment:
        // after a later one it would undo that too.
        if let Some((_, later)) = deployments
            .iter()
            .find(|(_, l)| l.epoch > epoch && l.kinds.iter().any(|k| kinds.contains(&k.kind)))
        {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "epoch {epoch} is no longer the latest deployment of its kinds: epoch {} \
                     changed them since",
                    later.epoch
                ),
            )
            .with_hint("Watch the latest deployment of the kinds; see: kronik deployments list"));
        }
        let env = self.node.env();
        let before = self.node.logical_time_at(lsn).await?;
        let wall = d.audit.as_ref().map_or(0, |a| a.wall_time_ms);
        let deployment_time_ms = match (before, wall) {
            (None, 0) => self
                .node
                .logical_time_after(lsn)
                .await?
                .unwrap_or_else(|| env.clock.wall_ms()),
            (t, wall) => t.unwrap_or(0).max(wall),
        };
        let mut w = Watch {
            id: format!("w-{}", &random_id(env)[..12]),
            epoch,
            deployment_lsn: lsn,
            for_ms,
            deployment_time_ms,
            status: WATCHING.into(),
            reason: audit.reason.clone(),
            token_id: audit.token_id.clone(),
            created_ms: env.clock.wall_ms(),
            triggered: Vec::new(),
            metrics: None,
            error: None,
            stopped: None,
        };
        if dry_run {
            let mut scan = Scan::start(&self.node, &w, kinds)?;
            scan.read(&self.node, &w, self.node.applied_lsn()).await?;
            let ev = self.evaluate(&mut scan, &w)?;
            w.triggered = ev
                .evaluation
                .fired
                .iter()
                .map(|f| Triggered {
                    guard: f.name.clone(),
                    action: f.action,
                    outcome: match f.action {
                        GuardAction::Alert => "alerted",
                        GuardAction::Rollback => match ev.rollback_error {
                            None => "rolled_back",
                            Some(ErrorCode::RollbackSchemaChanged) => "rollback_refused_schema",
                            Some(_) => "rollback_failed",
                        },
                    }
                    .to_owned(),
                    lsn: 0,
                    rollback_epoch: 0,
                    reason: ev.when(&f.name),
                })
                .collect();
            w.metrics = Some(ev.guard);
            return Ok(w);
        }
        // A watch lives outside the log (M11); its start is audited (M28)
        // before it runs, so the event precedes anything the watch writes
        // and a caller that stops waiting cannot lose it. A crash before
        // the save over-reports, the safe direction (ADR 0083).
        let details = [
            ("epoch".to_owned(), epoch.to_string()),
            ("for_ms".to_owned(), for_ms.to_string()),
        ];
        self.node
            .record_audit_event("watch.start", &w.id, details.into(), audit)
            .await?;
        self.save(&w)?;
        let id = w.id.clone();
        lock(&self.watches).insert(id.clone(), w.clone());
        let handle = self.spawn(id.clone());
        if !wait {
            return Ok(w);
        }
        let _ = handle.await;
        self.get(&id)
    }

    /// `kronik watches stop <id>`: the watch ends `stopped`; it writes no
    /// record and rolls nothing back from then on. A dry run checks and
    /// changes nothing.
    pub async fn stop(&self, id: &str, audit: pb::Audit, dry_run: bool) -> Result<Watch, ApiError> {
        let _acting = self.acting.lock().await;
        let w = self.get(id)?;
        if w.status != WATCHING {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("watch {id} is over: it is {}", w.status),
            )
            .with_hint(format!("See it with: kronik watches show {id}")));
        }
        if dry_run {
            return Ok(w);
        }
        let w = self.update(id, |w| {
            w.status = "stopped".into();
            w.stopped = Some(Stopped {
                token_id: audit.token_id,
                reason: audit.reason,
                wall_time_ms: audit.wall_time_ms,
            });
        })?;
        tracing::info!(watch = %id, epoch = w.epoch, "watch stopped");
        Ok(w)
    }

    /// The metrics and the guards of the policy in force that fire on
    /// them. Nothing is evaluated while no turn ran after the deployment: a
    /// guard would divide by zero or decide on no data.
    fn evaluate(&self, scan: &mut Scan, w: &Watch) -> Result<Evaluated, ApiError> {
        let rollback_error = self.proposals.rollback_plan(w.epoch).err().map(|e| e.code);
        let schema_changed = rollback_error == Some(ErrorCode::RollbackSchemaChanged);
        let (before, after, guard) = scan.metrics(w, schema_changed);
        let (rules, _) = self.proposals.rules()?;
        let evaluation = if after.turns == 0 {
            GuardEvaluation {
                fired: Vec::new(),
                errors: Vec::new(),
            }
        } else {
            rules.evaluate_guards(&guard)
        };
        Ok(Evaluated {
            before,
            after,
            guard,
            rollback_error,
            rules,
            evaluation,
        })
    }

    /// Writes a guard's record, with the watch's audit, and reports it.
    async fn write(
        &self,
        w: &Watch,
        mut record: pb::GuardTriggered,
    ) -> Result<Triggered, ApiError> {
        record.audit = Some(pb::Audit {
            token_id: "kronik".into(),
            reason: format!("watch {}: {}", w.id, w.reason),
            wall_time_ms: self.node.env().clock.wall_ms(),
        });
        let lsn = self.node.record_guard(record.clone()).await?;
        let outcome = outcome_name(record.outcome());
        let action = action_of(record.action);
        kronik_metrics::inc(
            "kronik_guard_triggered_total",
            &[("action", action.as_str()), ("outcome", outcome)],
        );
        tracing::error!(
            watch = %w.id,
            epoch = w.epoch,
            guard = %record.guard,
            outcome,
            error_rate = record.after.as_ref().map_or(0.0, |a| a.error_rate),
            "a guard fired after a deployment"
        );
        Ok(triggered_of(lsn, &record))
    }

    /// One evaluation; `true` when the watch is over.
    async fn tick(&self, id: &str, scan: &mut Option<Scan>) -> Result<bool, ApiError> {
        let w = self.get(id)?;
        if w.status != WATCHING {
            return Ok(true);
        }
        let env = self.node.env();
        // Decided before reading, so the last read covers the whole window.
        let last = env.clock.wall_ms() >= w.deployment_time_ms.saturating_add(w.for_ms);
        let scan = match scan {
            Some(s) => s,
            None => {
                let deployments = self.node.store().db().deployments().map_err(internal)?;
                let kinds = deployments
                    .iter()
                    .find(|(_, d)| d.epoch == w.epoch)
                    .map(|(_, d)| kinds_of(d))
                    .unwrap_or_default();
                scan.insert(Scan::start(&self.node, &w, kinds)?)
            }
        };
        scan.read(&self.node, &w, self.node.applied_lsn()).await?;

        let _acting = self.acting.lock().await;
        // `stop` may have ended the watch while it read.
        let w = self.get(id)?;
        if w.status != WATCHING {
            return Ok(true);
        }
        // What the log already says this watch did (a resume).
        let mut triggered = w.triggered.clone();
        for (lsn, g) in &scan.logged {
            if !triggered.iter().any(|t| t.lsn == *lsn) {
                triggered.push(triggered_of(*lsn, g));
            }
        }
        if triggered.iter().any(|t| t.outcome == "rolled_back") {
            self.update(id, |w| {
                w.triggered = triggered;
                w.status = "rolled_back".into();
            })?;
            return Ok(true);
        }

        let ev = self.evaluate(scan, &w)?;
        let observed_lsn = scan.next - 1;
        // A rollback this watch made before a restart, without its record
        // (the daemon stopped between the two): record it, whatever the
        // guards say now, and don't roll back again.
        if let Some((epoch, name)) = scan.rollback.clone() {
            let record = pb::GuardTriggered {
                outcome: pb::GuardOutcome::RolledBack as i32,
                rollback_epoch: epoch,
                reason: format!("{} (recorded after a restart)", ev.when(&name)),
                ..ev.record(&w, &name, GuardAction::Rollback, observed_lsn)
            };
            triggered.push(self.write(&w, record).await?);
            self.update(id, |w| {
                w.triggered = triggered;
                w.metrics = Some(ev.guard);
                w.status = "rolled_back".into();
            })?;
            return Ok(true);
        }
        // A later deployment of the watched kinds replaced the deployment:
        // nothing acts on it any more.
        let mut superseded = scan.end.is_some();
        let mut rolled_back = false;
        if !superseded {
            for e in &ev.evaluation.errors {
                let reported = triggered
                    .iter()
                    .any(|t| t.guard == e.name && t.reason.starts_with(EVAL_ERROR));
                if !reported {
                    let record = pb::GuardTriggered {
                        outcome: pb::GuardOutcome::Alerted as i32,
                        reason: format!("{EVAL_ERROR}{}", e.message),
                        ..ev.record(&w, &e.name, GuardAction::Alert, observed_lsn)
                    };
                    triggered.push(self.write(&w, record).await?);
                }
            }
        }
        for fired in &ev.evaluation.fired {
            if superseded || rolled_back {
                break;
            }
            let used = triggered
                .iter()
                .any(|t| t.guard == fired.name && !t.reason.starts_with(EVAL_ERROR));
            if used {
                continue;
            }
            let mut reason = ev.when(&fired.name);
            let (outcome, rollback_epoch) = match fired.action {
                GuardAction::Alert => (pb::GuardOutcome::Alerted, 0),
                GuardAction::Rollback => {
                    let audit = pb::Audit {
                        token_id: "kronik".into(),
                        reason: format!("watch {id}: guard `{}` fired", fired.name),
                        wall_time_ms: env.clock.wall_ms(),
                    };
                    // shortcut: the pins compare code, so a later deployment
                    // of the very same code that lands between this tick's
                    // read and the switch is rolled back too (to the code
                    // the guard judged); pin by epoch if that ever matters.
                    match self.proposals.rollback_watched(w.epoch, audit).await {
                        Ok((epoch, _, _)) => (pb::GuardOutcome::RolledBack, epoch),
                        // The pins failed under the deploy lock: a later
                        // deployment of the kinds landed after the read.
                        Err(e) if e.code == ErrorCode::ProposalStale => {
                            tracing::warn!(
                                watch = %id,
                                epoch = w.epoch,
                                error = %e,
                                "the watched deployment was replaced; no rollback"
                            );
                            superseded = true;
                            break;
                        }
                        Err(e) => {
                            reason = format!("{reason}; {}", e.message);
                            if e.code == ErrorCode::RollbackSchemaChanged {
                                (pb::GuardOutcome::RollbackRefusedSchema, 0)
                            } else {
                                (pb::GuardOutcome::RollbackFailed, 0)
                            }
                        }
                    }
                }
            };
            let record = pb::GuardTriggered {
                outcome: outcome as i32,
                rollback_epoch,
                reason,
                ..ev.record(&w, &fired.name, fired.action, observed_lsn)
            };
            rolled_back = outcome == pb::GuardOutcome::RolledBack;
            triggered.push(self.write(&w, record).await?);
        }
        let over = rolled_back || superseded || last;
        self.update(id, |w| {
            w.triggered = triggered;
            w.metrics = Some(ev.guard);
            if rolled_back {
                w.status = "rolled_back".into();
            } else if superseded {
                w.status = "superseded".into();
            } else if last {
                w.status = "done".into();
            }
        })?;
        Ok(over)
    }
}

/// A watch's task: evaluate every interval until the watch is over. It
/// holds the watches weakly, so it ends with the daemon.
async fn run(watches: Weak<Watches>, id: String) {
    let mut scan = None;
    loop {
        let Some(this) = watches.upgrade() else {
            return;
        };
        match this.tick(&id, &mut scan).await {
            Ok(true) => return,
            Ok(false) => {}
            // The node is stopping: the watch resumes at the next start.
            Err(e) if e.code == ErrorCode::Unavailable => return,
            Err(e) => {
                tracing::error!(watch = %id, error = %e, "the watch stopped");
                let _ = this.update(&id, |w| {
                    w.status = "failed".into();
                    w.error = Some(e);
                });
                return;
            }
        }
        let sleep = this.node.env().clock.sleep(this.interval);
        drop(this);
        sleep.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(kind: pb::OutcomeKind, status: Option<u32>) -> pb::Outcome {
        pb::Outcome {
            kind: kind as i32,
            output: status.map(|status| {
                pb::outcome::Output::Http(pb::HttpResponse {
                    status,
                    ..Default::default()
                })
            }),
            ..Default::default()
        }
    }

    /// Review W-M4: client input errors are not failures; a committed 5xx
    /// is.
    #[test]
    fn failures_are_the_code_and_the_host_failing() {
        assert!(!failed_turn(Some(&outcome(
            pb::OutcomeKind::Committed,
            None
        ))));
        assert!(!failed_turn(Some(&outcome(
            pb::OutcomeKind::Committed,
            Some(404)
        ))));
        assert!(failed_turn(Some(&outcome(
            pb::OutcomeKind::Committed,
            Some(503)
        ))));
        assert!(!failed_turn(Some(&outcome(
            pb::OutcomeKind::Rejected,
            None
        ))));
        assert!(failed_turn(Some(&outcome(pb::OutcomeKind::Failed, None))));
        assert!(failed_turn(Some(&outcome(pb::OutcomeKind::Trap, None))));
        assert!(failed_turn(None));
    }

    /// Rebase watch list (M11 x M13): a rebase switch of a watched kind ends
    /// the window after the deployment, as a `Deployment` does.
    #[test]
    fn a_rebase_switch_ends_the_window() {
        let w = Watch {
            id: "w-1".into(),
            epoch: 2,
            deployment_lsn: 10,
            for_ms: 1_000,
            deployment_time_ms: 5_000,
            status: "watching".into(),
            reason: String::new(),
            token_id: String::new(),
            created_ms: 0,
            triggered: Vec::new(),
            metrics: None,
            error: None,
            stopped: None,
        };
        let mut scan = Scan {
            next: 1,
            kinds: BTreeSet::from(["counter".to_owned()]),
            before: Side::default(),
            before_window: None,
            after: Side::default(),
            hwm: 0,
            logged: Vec::new(),
            end: None,
            rollback: None,
        };
        let switch = Record::StateRebase(pb::StateRebase {
            rebase_id: "r-1".into(),
            part: Some(pb::state_rebase::Part::Switch(pb::RebaseSwitch {
                deployment: Some(pb::Deployment {
                    epoch: 3,
                    kinds: vec![pb::KindVersion {
                        kind: "counter".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            })),
        });
        scan.add(&w, "watch w-1:", 20, switch);
        assert_eq!(scan.end, Some(20));
    }

    /// Review W-M3: turns without a duration count as turns, not as 0 µs.
    #[test]
    fn turns_without_a_duration_are_not_latency_samples() {
        let mut side = Side::default();
        for lsn in 1..=9 {
            side.add(lsn, false, 0);
        }
        side.add(10, true, 4_000);
        let w = side.window(0, 1);
        assert_eq!((w.turns, w.failed, w.from_lsn, w.to_lsn), (10, 1, 1, 10));
        assert_eq!((w.latency_p50_us, w.latency_p99_us), (4_000, 4_000));
        let none = Side::default().window(0, 1);
        assert_eq!((none.turns, none.latency_p99_us), (0, 0));
    }
}
