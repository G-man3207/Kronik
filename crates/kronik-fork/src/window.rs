//! A fork window from `segments.last_time_ms` and a short tail read (#197).
//!
//! Logical time does not go backwards ([`kronik_core::time`]). A segment's
//! `last_time_ms` is the high-water mark at its last applied record, so a
//! segment whose mark is below `T` cannot hold a turn at or after `T`. A
//! non-turn record does not move the mark. A timestamp search that then
//! sees only a later turn walks older segments until it finds the turn or
//! the log starts (#217).

use std::collections::HashMap;
use std::path::Path;

use kronik_core::causal;
use kronik_core::ids::Lsn;
use kronik_log::{LogError, LogReader};
use kronik_proto::Record;

/// A root input inside the discovered window.
pub struct FoundRoot {
    pub lsn: Lsn,
    pub start_lsn: Lsn,
    pub logical_time_ms: u64,
}

/// What a window search read, and the roots it found.
pub struct WindowFound {
    /// Roots whose logical time is within the window, in LSN order.
    pub roots: Vec<FoundRoot>,
    /// Newest engine version in the tail, if the tail named one.
    pub engine: Option<String>,
}

/// Applied segment marks from a branch `state.db`, oldest first.
pub fn read_segments(state_db: &Path) -> Result<Vec<(Lsn, Lsn, u64)>, String> {
    let conn =
        rusqlite::Connection::open_with_flags(state_db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| e.to_string())?;
    let mut st = conn
        .prepare("SELECT start, last_lsn, last_time_ms FROM segments ORDER BY start")
        .map_err(|e| e.to_string())?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as Lsn,
                r.get::<_, i64>(1)? as Lsn,
                r.get::<_, i64>(2)? as u64,
            ))
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}

/// Roots in `(newest logical time - window_ms, head]`, without reading
/// segments the segment marks prove are older than that window.
///
/// `floor_lsn` is the oldest usable snapshot (0 when the log still starts at
/// LSN 1). A `TurnBegin` at or before it is ignored, matching a load that
/// starts after that snapshot.
pub async fn discover_window(
    reader: &LogReader,
    segments: &[(Lsn, Lsn, u64)],
    head: Lsn,
    window_ms: u64,
    floor_lsn: Lsn,
) -> Result<WindowFound, LogError> {
    if head == 0 {
        return Ok(WindowFound {
            roots: Vec::new(),
            engine: None,
        });
    }
    let starts = reader.starts().await?;
    let (newest, engine) = newest_root(reader, &starts, head).await?;
    let Some((_, newest_time, newest_segment)) = newest else {
        return Ok(WindowFound {
            roots: Vec::new(),
            engine,
        });
    };
    let start_time = newest_time.saturating_sub(window_ms);
    let jump = jump_lsn(segments, start_time, newest_segment, &starts);
    let roots = roots_from(reader, jump, head, start_time, floor_lsn).await?;
    Ok(WindowFound { roots, engine })
}

/// The last LSN whose turn ran at or before `ms`. Segments older than the
/// one that contains that turn are not read.
pub async fn last_lsn_at_or_before(
    reader: &LogReader,
    segments: &[(Lsn, Lsn, u64)],
    head: Lsn,
    ms: u64,
) -> Result<Lsn, LogError> {
    if head == 0 {
        return Ok(0);
    }
    let starts = reader.starts().await?;
    if starts.is_empty() {
        return Ok(0);
    }
    let from = timestamp_start(segments, &starts, ms);
    match scan_until(reader, from, head, ms).await? {
        Scan::Found(lsn) => Ok(lsn),
        // Empty: the read has no turn. Exceeded: its first turn is after
        // `ms`. A configuration-only segment keeps an older mark, so that
        // is not proof nothing earlier exists (#217).
        Scan::Empty | Scan::Exceeded => walk_back(reader, &starts, from, ms).await,
    }
}

fn jump_lsn(
    segments: &[(Lsn, Lsn, u64)],
    start_time: u64,
    newest_segment: Lsn,
    log_starts: &[Lsn],
) -> Lsn {
    if segments.is_empty() {
        return log_starts.first().copied().unwrap_or(1);
    }
    let jumped = segments
        .iter()
        .find(|(_, _, time)| *time >= start_time)
        .map(|(start, _, _)| *start)
        .unwrap_or(newest_segment);
    // The newest root's own segment is always in the window. A stale mark
    // must not start the read after it.
    jumped.min(newest_segment).max(1)
}

fn timestamp_start(segments: &[(Lsn, Lsn, u64)], log_starts: &[Lsn], ms: u64) -> Lsn {
    if segments.is_empty() {
        return log_starts.first().copied().unwrap_or(1);
    }
    if let Some(i) = segments.iter().position(|(_, _, time)| *time > ms) {
        if i == 0 {
            return segments[0].0;
        }
        // The crossing segment's mark is its last turn, which is past `ms`,
        // but it may hold earlier turns. Start one segment before it.
        return segments[i - 1].0;
    }
    segments.last().map(|(start, _, _)| *start).unwrap_or(1)
}

enum Scan {
    Found(Lsn),
    Exceeded,
    Empty,
}

async fn scan_until(reader: &LogReader, from: Lsn, head: Lsn, ms: u64) -> Result<Scan, LogError> {
    if from > head {
        return Ok(Scan::Empty);
    }
    let mut last = 0;
    let mut saw_turn = false;
    let mut exceeded = false;
    reader
        .read_while(from, head, |c| {
            if let Record::TurnRecord(t) = &c.record {
                saw_turn = true;
                if t.logical_time_ms > ms {
                    exceeded = true;
                    return Ok(false);
                }
                last = c.lsn;
            }
            Ok(true)
        })
        .await?;
    if last > 0 {
        return Ok(Scan::Found(last));
    }
    if exceeded || saw_turn {
        return Ok(Scan::Exceeded);
    }
    Ok(Scan::Empty)
}

async fn walk_back(
    reader: &LogReader,
    starts: &[Lsn],
    from: Lsn,
    ms: u64,
) -> Result<Lsn, LogError> {
    let Some(mut idx) = starts.iter().rposition(|start| *start <= from) else {
        return Ok(0);
    };
    while idx > 0 {
        idx -= 1;
        let upto = starts[idx + 1] - 1;
        match scan_until(reader, starts[idx], upto, ms).await? {
            Scan::Found(lsn) => return Ok(lsn),
            // This segment's first turn is after `ms`, or it has none.
            // An older segment can still hold the turn (#217).
            Scan::Empty | Scan::Exceeded => {}
        }
    }
    Ok(0)
}

async fn newest_root(
    reader: &LogReader,
    starts: &[Lsn],
    head: Lsn,
) -> Result<(Option<(Lsn, u64, Lsn)>, Option<String>), LogError> {
    let mut engine = None;
    for (i, &start) in starts.iter().enumerate().rev() {
        if start > head {
            continue;
        }
        let upto = starts
            .get(i + 1)
            .copied()
            .map(|next| next - 1)
            .unwrap_or(head)
            .min(head);
        if upto < start {
            continue;
        }
        let mut found = None;
        let mut seg_engine = None;
        reader
            .read(start, upto, |c| {
                match &c.record {
                    Record::TurnRecord(t) if causal::is_root_input(t) => {
                        found = Some((c.lsn, t.logical_time_ms));
                        seg_engine = Some(t.engine_version.clone());
                    }
                    Record::TurnRecord(t) => seg_engine = Some(t.engine_version.clone()),
                    Record::TurnBegin(t) => seg_engine = Some(t.engine_version.clone()),
                    Record::EngineUpgrade(u) => {
                        seg_engine = Some(u.to_engine_version.clone());
                    }
                    _ => {}
                }
                Ok(())
            })
            .await?;
        // Walking backward: the first engine marker is the newest.
        if engine.is_none() {
            engine = seg_engine;
        }
        if let Some((lsn, time)) = found {
            return Ok((Some((lsn, time, start)), engine));
        }
    }
    Ok((None, engine))
}

async fn roots_from(
    reader: &LogReader,
    from: Lsn,
    head: Lsn,
    start_time: u64,
    floor_lsn: Lsn,
) -> Result<Vec<FoundRoot>, LogError> {
    let mut begins: HashMap<String, Lsn> = HashMap::new();
    let mut roots = Vec::new();
    if from > head {
        return Ok(roots);
    }
    reader
        .read(from, head, |c| {
            match &c.record {
                Record::TurnBegin(t) => {
                    if let Some(key) = &t.causal_key
                        && key.path.is_empty()
                    {
                        begins.entry(key.root.clone()).or_insert(c.lsn);
                    }
                }
                Record::TurnRecord(t)
                    if causal::is_root_input(t) && t.logical_time_ms >= start_time =>
                {
                    let begin = t
                        .causal_key
                        .as_ref()
                        .and_then(|key| begins.get(&key.root).copied());
                    // A begin at or before the snapshot was not in the old
                    // load, which started after it. Ignore that begin.
                    let start_lsn = match begin {
                        Some(b) if b > floor_lsn => b.min(c.lsn),
                        _ => c.lsn,
                    }
                    .max(floor_lsn + 1);
                    roots.push(FoundRoot {
                        lsn: c.lsn,
                        start_lsn,
                        logical_time_ms: t.logical_time_ms,
                    });
                }
                _ => {}
            }
            Ok(())
        })
        .await?;
    Ok(roots)
}
