//! Following the committed log for an export stream (m28-otel §3.6, §4.6,
//! ADR 0084): read records after the stream's cursor in batches, hand them
//! to a [`Sink`], and advance and save the cursor only once the sink
//! delivered them. At least once, in LSN order; off the turn path (an
//! `env.spawn` task of `kronik serve` that only reads).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::Lsn;
use kronik_log::Committed;
use kronik_sched::Node;

use crate::cursor::{Cursors, Entry};

/// What a sink did with a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Acknowledged: the cursor moves past the batch.
    Delivered,
    /// Refused for good (OTLP 400): the cursor moves past it, counted in
    /// `kronik_export_dropped_total`. `code` is shown in the status.
    Dropped { code: String },
    /// Not delivered: tried again after `after` (`Retry-After`) or the
    /// backoff, counted in `kronik_export_errors_total`.
    Retry {
        code: String,
        after: Option<Duration>,
    },
}

/// Where a stream's records go.
pub trait Sink: Send {
    /// What [`Sink::deliver`] sends, built once per batch and kept across
    /// retries, so `prepare` may move the sink's state forward.
    type Batch: Send + Sync;

    /// Builds the delivery for committed records, in LSN order. Never
    /// called with an empty batch.
    fn prepare(&mut self, records: Vec<Committed>) -> impl Future<Output = Self::Batch> + Send;

    /// Sends a prepared batch; called again with the same batch on retry.
    fn deliver(&mut self, batch: &Self::Batch) -> impl Future<Output = Delivery> + Send;

    /// The state saved with the cursor after a delivery, handed back by
    /// [`Cursors::get`] at the next start.
    fn state(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    /// Retention deleted `from..=to` before the stream read it. Called
    /// before the next batch; the cursor moves past the gap only once this
    /// returns Ok. Err is a stable code for the status; the follower keeps
    /// the cursor before the gap and calls it again after a backoff.
    fn gap(&mut self, _from: Lsn, _to: Lsn) -> impl Future<Output = Result<(), String>> + Send {
        async { Ok(()) }
    }

    /// The stream has delivered everything applied: called before the
    /// follower waits for more and again when the wait ends, so that what
    /// a sink ages (the audit hold) does not age while nothing lags.
    fn caught_up(&mut self) {}

    /// The cursor moved back (or on) to `to` (`kronik export rewind`):
    /// called before the next batch, so that a sink's state is rebuilt as
    /// it was after `to`.
    fn rewind(&mut self, _to: Lsn) -> impl Future<Output = ()> + Send {
        async {}
    }
}

/// A stream's progress, as `kronik export status` shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Progress {
    /// The last LSN delivered.
    pub cursor: Lsn,
    pub last_success_wall_ms: Option<u64>,
    /// When the follower started: the stall's start before a first success.
    pub started_wall_ms: Option<u64>,
    /// The last failure's code (`http_503`, `connect`, ...), never its text,
    /// which can contain the URL.
    pub last_error: Option<String>,
    /// Ranges retention deleted before the stream read them.
    pub gaps: u64,
}

/// One export stream: its settings for the status, its progress, and the
/// rewind requests the follower picks up.
pub struct Stream {
    /// `traces` or `audit`: the cursor's name and the metrics' label.
    pub name: &'static str,
    pub enabled: bool,
    /// The sink's or endpoint's scheme and host only ([`crate::http::scheme_host`]).
    pub sink: String,
    progress: Mutex<Progress>,
    rewind: Mutex<Option<Lsn>>,
    rewound: tokio::sync::Notify,
}

impl Stream {
    pub fn new(name: &'static str, enabled: bool, sink: String, cursor: Lsn) -> Arc<Stream> {
        Arc::new(Stream {
            name,
            enabled,
            sink,
            progress: Mutex::new(Progress {
                cursor,
                ..Progress::default()
            }),
            rewind: Mutex::new(None),
            rewound: tokio::sync::Notify::new(),
        })
    }

    pub fn progress(&self) -> Progress {
        lock(&self.progress).clone()
    }

    /// Asks the follower to resend from after `to` (`kronik export rewind`).
    /// It moves the cursor and saves it before its next batch.
    pub fn rewind(&self, to: Lsn) {
        *lock(&self.rewind) = Some(to);
        self.rewound.notify_one();
    }

    fn update(&self, f: impl FnOnce(&mut Progress)) {
        f(&mut lock(&self.progress));
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Batching of a follower.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// At most this many records per batch.
    pub batch: u64,
    /// A smaller batch waits this long for more records.
    pub interval: Duration,
}

const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A `Retry-After` longer than this is cut to it.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);
/// At most this many encoded record bytes per batch (review M3): a
/// backlog of large turn records must not pile up in memory (a record can
/// be 128 MiB). A larger record goes alone.
pub const BATCH_BYTES: usize = 4 << 20;
/// An idle follower wakes at least this far apart.
const MIN_IDLE_TICK: Duration = Duration::from_millis(100);

/// Runs [`follow`] as a task of its own with the sink `make` builds from
/// the stream's saved state, and runs it again after it died (a panic, a
/// bug), after a backoff, from the saved cursor and state: no exporter
/// stays dead until a restart of the daemon (review Low).
///
/// shortcut: only the trace stream runs supervised; a dead audit export
/// keeps its retention hold, which `kronik doctor` shows as a stall, until
/// the daemon restarts. Supervise it too (rebuilding its sink) if one ever
/// dies in production.
pub async fn supervise<S, F>(
    node: Arc<Node>,
    cursors: Arc<Cursors>,
    stream: Arc<Stream>,
    opts: Options,
    mut make: F,
) where
    S: Sink + 'static,
    F: FnMut(&serde_json::Value) -> S + Send,
{
    let env = node.env().clone();
    let mut backoff = FIRST_BACKOFF;
    loop {
        let saved = cursors.get(stream.name);
        let state = saved.as_ref().map(|e| e.state.clone()).unwrap_or_default();
        if let Some(saved) = &saved {
            stream.update(|p| p.cursor = saved.lsn);
        }
        let sink = make(&state);
        let task = env.spawn(
            stream.name,
            follow(node.clone(), cursors.clone(), stream.clone(), opts, sink),
        );
        // `follow` never returns: the task ended because it panicked (or the
        // runtime is shutting down, which drops this task too).
        if task.await.is_some() {
            return;
        }
        tracing::error!(
            stream = stream.name,
            "export: the exporter task died; restarting it from the saved cursor"
        );
        kronik_metrics::inc("kronik_export_errors_total", &[("stream", stream.name)]);
        stream.update(|p| p.last_error = Some("panic".into()));
        env.clock.sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Follows main's committed log from the stream's cursor forever.
pub async fn follow<S: Sink>(
    node: Arc<Node>,
    cursors: Arc<Cursors>,
    stream: Arc<Stream>,
    opts: Options,
    mut sink: S,
) {
    let env = node.env().clone();
    let name = stream.name;
    let labels = [("stream", name)];
    let batch = opts.batch.max(1);
    let mut cursor = stream.progress().cursor;
    let mut gap_backoff = FIRST_BACKOFF;
    let started = env.clock.wall_ms();
    stream.update(|p| p.started_wall_ms = Some(started));
    // Also while a sink is down, so the gauge shows the backlog growing.
    let lag = |cursor: Lsn| {
        kronik_metrics::set(
            "kronik_export_lag_records",
            &labels,
            node.applied_lsn().saturating_sub(cursor) as f64,
        );
    };
    loop {
        let rewind = lock(&stream.rewind).take();
        if let Some(to) = rewind {
            cursor = to;
            sink.rewind(to).await;
            stream.update(|p| p.cursor = to);
            save(&cursors, name, cursor, sink.state()).await;
        }
        if node.applied_lsn() <= cursor {
            sink.caught_up();
            // Awake once per interval while idle, so that `caught_up` keeps
            // what a sink ages fresh.
            let tick = opts.interval.max(MIN_IDLE_TICK);
            tokio::select! {
                biased;
                woke = env.timeout(tick, node.store().applied.wait(cursor + 1)) => {
                    if woke.is_err() {
                        continue;
                    }
                }
                () = stream.rewound.notified() => continue,
            }
            // Nothing lagged until now.
            sink.caught_up();
        }
        if node.applied_lsn() < cursor + batch {
            let _ = env
                .timeout(opts.interval, node.store().applied.wait(cursor + batch))
                .await;
        }
        // Retention may have deleted what the cursor has not reached
        // (traces do not hold retention; audit does until its hold is
        // released): one gap up to the first segment, then on from there.
        if let Ok(starts) = node.reader().starts().await
            && let Some(&first) = starts.first()
            && first > cursor + 1
        {
            if !report_gap(
                &env,
                &mut sink,
                &stream,
                cursor + 1,
                first - 1,
                &mut gap_backoff,
            )
            .await
            {
                continue;
            }
            cursor = first - 1;
            stream.update(|p| p.cursor = cursor);
        }
        let upto = node.applied_lsn().min(cursor + batch);
        let mut records = Vec::new();
        let (mut bytes, mut full) = (0, false);
        let read = node
            .reader()
            .read(cursor + 1, upto, |c| {
                let size = c.record.encoded_len();
                full |= !records.is_empty() && bytes + size > BATCH_BYTES;
                if !full {
                    bytes += size;
                    records.push(c);
                }
                Ok(())
            })
            .await;
        let upto = match records.last() {
            Some(last) if full => last.lsn,
            _ => upto,
        };
        if let Err(e) = read {
            tracing::warn!(stream = name, error = %e, "export: reading the log failed");
            kronik_metrics::inc("kronik_export_errors_total", &labels);
            stream.update(|p| p.last_error = Some("log_read".into()));
            env.clock.sleep(MAX_BACKOFF).await;
            continue;
        }
        // LSNs are dense: a later first record means retention deleted the
        // records in between since the check above.
        let first = records.first().map_or(upto + 1, |c| c.lsn);
        if first > cursor + 1
            && !report_gap(
                &env,
                &mut sink,
                &stream,
                cursor + 1,
                first - 1,
                &mut gap_backoff,
            )
            .await
        {
            continue;
        }
        let count = records.len() as u64;
        if !records.is_empty() {
            let prepared = sink.prepare(records).await;
            let mut backoff = FIRST_BACKOFF;
            loop {
                match sink.deliver(&prepared).await {
                    Delivery::Delivered => break,
                    Delivery::Dropped { code } => {
                        tracing::warn!(
                            stream = name,
                            code,
                            from = cursor + 1,
                            upto,
                            "export: the sink refused a batch; skipped"
                        );
                        kronik_metrics::add("kronik_export_dropped_total", &labels, count);
                        stream.update(|p| p.last_error = Some(code));
                        break;
                    }
                    Delivery::Retry { code, after } => {
                        tracing::warn!(stream = name, code, "export: delivery failed; retrying");
                        kronik_metrics::inc("kronik_export_errors_total", &labels);
                        lag(cursor);
                        stream.update(|p| p.last_error = Some(code));
                        let wait = after.map_or(backoff, |a| a.min(MAX_RETRY_AFTER));
                        env.clock.sleep(wait).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    }
                }
            }
        }
        cursor = upto;
        let wall = env.clock.wall_ms();
        stream.update(|p| {
            p.cursor = cursor;
            p.last_success_wall_ms = Some(wall);
        });
        save(&cursors, name, cursor, sink.state()).await;
        kronik_metrics::add("kronik_export_records_total", &labels, count);
        lag(cursor);
    }
}

/// Retention deleted `from..=to` before the stream read it: logged, handed
/// to the sink and, once the sink recorded it, counted. False after a
/// failed record, once the backoff passed: the caller keeps its cursor
/// before the gap and tries again, so a restart still sees the gap.
async fn report_gap<S: Sink>(
    env: &Env,
    sink: &mut S,
    stream: &Stream,
    from: Lsn,
    to: Lsn,
    backoff: &mut Duration,
) -> bool {
    tracing::warn!(
        stream = stream.name,
        from,
        to,
        "export: retention deleted records before they were exported"
    );
    let labels = [("stream", stream.name)];
    if let Err(code) = sink.gap(from, to).await {
        tracing::warn!(
            stream = stream.name,
            code,
            from,
            to,
            "export: recording a gap failed; retrying"
        );
        kronik_metrics::inc("kronik_export_errors_total", &labels);
        stream.update(|p| p.last_error = Some(code));
        env.clock.sleep(*backoff).await;
        *backoff = (*backoff * 2).min(MAX_BACKOFF);
        return false;
    }
    *backoff = FIRST_BACKOFF;
    kronik_metrics::inc("kronik_export_gaps_total", &labels);
    stream.update(|p| p.gaps += 1);
    true
}

/// A failed save only costs a resend after a restart (at least once), so
/// the follower goes on.
async fn save(cursors: &Cursors, name: &str, lsn: Lsn, state: serde_json::Value) {
    let entry = Entry { lsn, state };
    if let Err(e) = cursors.save(name, entry).await {
        tracing::warn!(stream = name, error = %e, "export: saving the cursor failed");
    }
}
