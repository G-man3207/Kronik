//! Following the committed log for an export stream (m28-otel §3.6, §4.6,
//! ADR 0084): read records after the stream's cursor in batches, hand them
//! to a [`Sink`], and advance and save the cursor only once the sink
//! delivered them. At least once, in LSN order; off the turn path (an
//! `env.spawn` task of `kronik serve` that only reads).

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::Lsn;
use kronik_log::Committed;
use kronik_sched::Node;

use crate::cursor::{Control, Cursors, Entry, Generation};

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
    /// called with an empty batch. Failure must leave sink state unchanged;
    /// the follower retries without advancing its cursor.
    fn prepare(
        &mut self,
        records: Vec<Committed>,
        generation: Generation,
    ) -> impl Future<Output = Result<Self::Batch, String>> + Send;

    /// Sends a prepared batch; called again with the same batch on retry.
    fn deliver(&mut self, batch: &Self::Batch) -> impl Future<Output = Delivery> + Send;

    /// Stages durable resume metadata without publishing its cursor. A retry
    /// must keep the same candidate until publication succeeds.
    fn checkpoint(
        &mut self,
        _lsn: Lsn,
    ) -> impl Future<Output = Result<serde_json::Value, String>> + Send {
        async { Ok(serde_json::Value::Null) }
    }

    /// The manifest now durably selects the staged state and generation.
    fn committed(&mut self, _lsn: Lsn, _generation: Generation, _rewind_pending: bool) {}

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
    fn rewind(
        &mut self,
        _to: Lsn,
        _generation: Generation,
    ) -> impl Future<Output = Result<(), String>> + Send {
        async { Ok(()) }
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
    cursors: Arc<Cursors>,
    control: tokio::sync::Mutex<()>,
    rewound: tokio::sync::Notify,
}

impl Stream {
    pub fn new(
        name: &'static str,
        enabled: bool,
        sink: String,
        cursor: Lsn,
        cursors: Arc<Cursors>,
    ) -> Arc<Stream> {
        Arc::new(Stream {
            name,
            enabled,
            sink,
            progress: Mutex::new(Progress {
                cursor,
                ..Progress::default()
            }),
            cursors,
            control: tokio::sync::Mutex::new(()),
            rewound: tokio::sync::Notify::new(),
        })
    }

    pub fn progress(&self) -> Progress {
        lock(&self.progress).clone()
    }

    /// Durably requests a new replay generation before waking the follower.
    /// The owned task completes even if the operator stops waiting.
    pub async fn rewind(self: &Arc<Self>, node: &Arc<Node>, to: Lsn) -> io::Result<()> {
        let (stream, node) = (self.clone(), node.clone());
        let env = node.env().clone();
        env.spawn("export-rewind", async move {
            let _control = stream.control.lock().await;
            let current = stream.cursors.get(stream.name).unwrap_or_default();
            let generation = loop {
                let generation = node.env().random_bytes();
                if generation != [0; 16]
                    && generation != current.generation()
                    && current
                        .pending_rewind()
                        .is_none_or(|r| r.generation != generation)
                {
                    break generation;
                }
            };
            let audit = stream.name == crate::sink::STREAM;
            if audit {
                node.retention_hold()
                    .rewind(generation, to, node.env().clock.wall_ms());
            }
            match stream
                .cursors
                .request_rewind(stream.name, generation, to)
                .await
            {
                Ok(pending) => {
                    if audit {
                        node.retention_hold().rewind(
                            pending.generation,
                            pending.to,
                            node.env().clock.wall_ms(),
                        );
                    }
                    stream.rewound.notify_one();
                    Ok(())
                }
                Err(error) => {
                    if audit {
                        let saved = stream.cursors.get(stream.name).unwrap_or_default();
                        node.retention_hold().restore_control(
                            generation,
                            saved.pending_rewind().map(|r| (r.generation, r.to)),
                            saved.lsn,
                            node.env().clock.wall_ms(),
                        );
                    }
                    Err(error)
                }
            }
        })
        .await
        .unwrap_or_else(|| Err(io::Error::other("export rewind task did not complete")))
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
pub async fn supervise<S, F, Fut>(node: Arc<Node>, stream: Arc<Stream>, opts: Options, mut make: F)
where
    S: Sink + 'static,
    F: FnMut(Entry) -> Fut + Send,
    Fut: Future<Output = Result<S, String>> + Send,
{
    let env = node.env().clone();
    let cursors = stream.cursors.clone();
    let mut backoff = FIRST_BACKOFF;
    loop {
        let saved = cursors.get(stream.name).unwrap_or_else(|| Entry {
            lsn: stream.progress().cursor,
            ..Entry::default()
        });
        stream.update(|p| p.cursor = saved.lsn);
        let sink = match cursors.stabilize().await {
            Ok(()) => make(saved).await,
            Err(_) => Err("cursor_save".into()),
        };
        let sink = match sink {
            Ok(sink) => sink,
            Err(code) => {
                stream.update(|p| p.last_error = Some(code));
                kronik_metrics::inc("kronik_export_errors_total", &[("stream", stream.name)]);
                pause(&env, &stream, backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        let task = env.spawn(
            stream.name,
            follow(node.clone(), stream.clone(), opts, sink),
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
pub async fn follow<S: Sink>(node: Arc<Node>, stream: Arc<Stream>, opts: Options, mut sink: S) {
    let env = node.env().clone();
    let name = stream.name;
    let labels = [("stream", name)];
    let batch = opts.batch.max(1);
    let mut entry = stream.cursors.get(name).unwrap_or_else(|| Entry {
        lsn: stream.progress().cursor,
        ..Entry::default()
    });
    let mut noticed = entry.lsn;
    let mut gap_backoff = FIRST_BACKOFF;
    let mut prepare_backoff = FIRST_BACKOFF;
    stream.update(|p| p.started_wall_ms = Some(env.clock.wall_ms()));
    let lag = |cursor: Lsn| {
        kronik_metrics::set(
            "kronik_export_lag_records",
            &labels,
            node.applied_lsn().saturating_sub(cursor) as f64,
        );
    };
    'records: loop {
        if rewind_requested(&stream, entry.generation()) {
            // A management request cannot supersede the first generation
            // checkpoint while its manifest publication is being retried.
            let _control = stream.control.lock().await;
            let pending = stream.cursors.get(name).and_then(|e| e.pending_rewind());
            if let Some(pending) = pending.filter(|r| r.generation != entry.generation()) {
                if let Err(code) = sink.rewind(pending.to, pending.generation).await {
                    failure(&stream, code);
                    drop(_control);
                    pause(&env, &stream, prepare_backoff).await;
                    prepare_backoff = (prepare_backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
                let candidate = Entry {
                    lsn: pending.to,
                    control: Some(Control::new(pending.generation)),
                    ..Entry::default()
                };
                match checkpoint(&node, &stream, &mut sink, candidate).await {
                    Ok(saved) => {
                        entry = saved;
                        noticed = entry.lsn;
                        prepare_backoff = FIRST_BACKOFF;
                    }
                    Err(code) => {
                        failure(&stream, code);
                        drop(_control);
                        pause(&env, &stream, prepare_backoff).await;
                        prepare_backoff = (prepare_backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                }
            }
        }
        let cursor = entry.lsn;
        let generation = entry.generation();
        if node.applied_lsn() <= cursor {
            sink.caught_up();
            let tick = opts.interval.max(MIN_IDLE_TICK);
            tokio::select! {
                biased;
                () = stream.rewound.notified() => continue,
                woke = env.timeout(tick, node.store().applied.wait(cursor.saturating_add(1))) => {
                    if woke.is_err() {
                        continue;
                    }
                }
            }
            sink.caught_up();
        }
        let end = cursor.saturating_add(batch);
        if node.applied_lsn() < end {
            tokio::select! {
                biased;
                () = stream.rewound.notified() => continue,
                _ = env.timeout(opts.interval, node.store().applied.wait(end)) => {}
            }
        }
        let gap = match gap_after(
            &node,
            &mut sink,
            &stream,
            cursor,
            &mut noticed,
            &mut gap_backoff,
        )
        .await
        {
            Ok(gap) => gap,
            Err(()) => continue,
        };
        if let Some(to) = gap {
            loop {
                if rewind_requested(&stream, generation) {
                    continue 'records;
                }
                let candidate = Entry {
                    lsn: to,
                    control: entry.control,
                    ..Entry::default()
                };
                match checkpoint(&node, &stream, &mut sink, candidate).await {
                    Ok(saved) => {
                        entry = saved;
                        continue 'records;
                    }
                    Err(code) => {
                        failure(&stream, code);
                        pause(&env, &stream, prepare_backoff).await;
                    }
                }
            }
        }
        let upto = node.applied_lsn().min(end);
        let mut records = Vec::new();
        let mut bytes = 0;
        let read = node
            .reader()
            .read_while(cursor.saturating_add(1), upto, |c| {
                let size = c.record.encoded_len();
                if !records.is_empty() && bytes + size > BATCH_BYTES {
                    return Ok(false);
                }
                bytes += size;
                records.push(c);
                Ok(true)
            })
            .await;
        if read.is_err() {
            failure(&stream, "log_read".into());
            pause(&env, &stream, MAX_BACKOFF).await;
            continue;
        }
        let Some(first) = records.first().map(|c| c.lsn) else {
            continue;
        };
        if first > cursor.saturating_add(1) {
            if !report_gap(
                &env,
                &mut sink,
                &stream,
                cursor.saturating_add(1),
                first - 1,
                &mut noticed,
                &mut gap_backoff,
            )
            .await
            {
                continue;
            }
            // Save the skipped range before preparing later records.
            loop {
                if rewind_requested(&stream, generation) {
                    continue 'records;
                }
                let candidate = Entry {
                    lsn: first - 1,
                    control: entry.control,
                    ..Entry::default()
                };
                match checkpoint(&node, &stream, &mut sink, candidate).await {
                    Ok(saved) => {
                        entry = saved;
                        continue 'records;
                    }
                    Err(code) => {
                        failure(&stream, code);
                        pause(&env, &stream, prepare_backoff).await;
                    }
                }
            }
        }
        let upto = records.last().map_or(upto, |c| c.lsn);
        let count = records.len() as u64;
        let prepared = match sink.prepare(records, generation).await {
            Ok(batch) => {
                prepare_backoff = FIRST_BACKOFF;
                batch
            }
            Err(code) => {
                failure(&stream, code);
                lag(cursor);
                pause(&env, &stream, prepare_backoff).await;
                prepare_backoff = (prepare_backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        let mut backoff = FIRST_BACKOFF;
        loop {
            if rewind_requested(&stream, generation) {
                continue 'records;
            }
            let delivery = tokio::select! {
                biased;
                () = stream.rewound.notified() => continue,
                delivery = sink.deliver(&prepared) => delivery,
            };
            match delivery {
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
                    failure(&stream, code);
                    lag(cursor);
                    let wait = after.map_or(backoff, |a| a.min(MAX_RETRY_AFTER));
                    let asleep = env.clock.sleep(wait);
                    tokio::pin!(asleep);
                    loop {
                        let _ = gap_after(
                            &node,
                            &mut sink,
                            &stream,
                            upto,
                            &mut noticed,
                            &mut gap_backoff,
                        )
                        .await;
                        tokio::select! {
                            biased;
                            () = stream.rewound.notified() => {
                                if rewind_requested(&stream, generation) {
                                    continue 'records;
                                }
                            }
                            () = &mut asleep => break,
                            () = env.clock.sleep(FIRST_BACKOFF) => lag(cursor),
                        }
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
        drop(prepared);
        // A successful remote delivery is frozen while local persistence
        // retries: do not prepare/post a later batch or lose staged metadata.
        loop {
            if rewind_requested(&stream, generation) {
                continue 'records;
            }
            let candidate = Entry {
                lsn: upto,
                control: entry.control,
                ..Entry::default()
            };
            match checkpoint(&node, &stream, &mut sink, candidate).await {
                Ok(saved) => {
                    entry = saved;
                    break;
                }
                Err(code) => {
                    failure(&stream, code);
                    pause(&env, &stream, prepare_backoff).await;
                    prepare_backoff = (prepare_backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
        kronik_metrics::add("kronik_export_records_total", &labels, count);
        lag(entry.lsn);
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
    noticed: &mut Lsn,
    backoff: &mut Duration,
) -> bool {
    let from = from.max(noticed.saturating_add(1));
    if from > to {
        return true;
    }
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
        pause(env, stream, *backoff).await;
        *backoff = (*backoff * 2).min(MAX_BACKOFF);
        return false;
    }
    *backoff = FIRST_BACKOFF;
    *noticed = to;
    kronik_metrics::inc("kronik_export_gaps_total", &labels);
    stream.update(|p| p.gaps += 1);
    true
}

fn rewind_requested(stream: &Stream, generation: Generation) -> bool {
    stream
        .cursors
        .get(stream.name)
        .and_then(|e| e.pending_rewind())
        .is_some_and(|r| r.generation != generation)
}

fn failure(stream: &Stream, code: String) {
    tracing::warn!(stream = stream.name, code, "export failed; retrying");
    kronik_metrics::inc("kronik_export_errors_total", &[("stream", stream.name)]);
    stream.update(|p| p.last_error = Some(code));
}

async fn pause(env: &Env, stream: &Stream, duration: Duration) {
    tokio::select! {
        biased;
        () = stream.rewound.notified() => {}
        () = env.clock.sleep(duration) => {}
    }
}

async fn gap_after<S: Sink>(
    node: &Node,
    sink: &mut S,
    stream: &Stream,
    after: Lsn,
    noticed: &mut Lsn,
    backoff: &mut Duration,
) -> Result<Option<Lsn>, ()> {
    let first = match node.reader().starts().await {
        Ok(starts) => starts.first().copied(),
        Err(_) => {
            failure(stream, "log_read".into());
            pause(node.env(), stream, *backoff).await;
            return Err(());
        }
    };
    let Some(first) = first.filter(|first| *first > after.saturating_add(1)) else {
        return Ok(None);
    };
    if report_gap(
        node.env(),
        sink,
        stream,
        after.saturating_add(1),
        first - 1,
        noticed,
        backoff,
    )
    .await
    {
        Ok(Some(first - 1))
    } else {
        Err(())
    }
}

async fn checkpoint<S: Sink>(
    node: &Node,
    stream: &Stream,
    sink: &mut S,
    mut entry: Entry,
) -> Result<Entry, String> {
    entry.state = sink.checkpoint(entry.lsn).await?;
    let mut backoff = FIRST_BACKOFF;
    loop {
        match stream.cursors.advance(stream.name, entry.clone()).await {
            Ok(saved) => {
                sink.committed(
                    saved.lsn,
                    saved.generation(),
                    saved.pending_rewind().is_some(),
                );
                stream.update(|p| {
                    p.cursor = saved.lsn;
                    p.last_success_wall_ms = Some(node.env().clock.wall_ms());
                });
                return Ok(saved);
            }
            Err(_) => {
                failure(stream, "cursor_save".into());
                pause(node.env(), stream, backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}
