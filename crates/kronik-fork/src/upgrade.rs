//! `kronik upgrade check` (docs/design/m6-storage.md §7): an identity
//! replay of the last window of main with this binary's engine, against a
//! data directory a running daemon may still be writing (read-only: the log
//! through what is on disk, snapshots, components).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::Lsn;
use kronik_log::LogReader;
use kronik_runtime::{CodeStore, ENGINE_VERSION, PoolSize, build_engine};
use kronik_sched::upgrade::{REPORT_SCHEMA, UpgradeReport};

use crate::diff::{Diff, DiffOptions, Mode};
use crate::{ProductionIndex, ReplaySetup, config_at, fork_kinds, pick_base};

/// Fuel is not compared across engines (a new Wasmtime may count
/// differently); a finite stand-in for "no threshold" keeps the diff's JSON
/// valid.
const NO_FUEL_THRESHOLD: f64 = 1e12;

/// A finished check.
pub struct Checked {
    pub report: UpgradeReport,
    pub diff: Diff,
    pub diff_bytes: Vec<u8>,
}

/// The newest LSN on disk: the records of the last segment.
async fn head(reader: &LogReader, log_dir: &Path) -> Result<Lsn, String> {
    let starts = kronik_log::segment_starts(log_dir).map_err(|e| e.to_string())?;
    let Some(&last) = starts.last() else {
        return Ok(0);
    };
    let mut head = last - 1;
    reader
        .read(last, Lsn::MAX, |c| {
            head = c.lsn;
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok(head)
}

/// The engine version of the newest turn in the window (what the data was
/// written with).
fn recorded_engine(index: &ProductionIndex) -> Option<String> {
    index.records.iter().rev().find_map(|c| match &c.record {
        kronik_proto::Record::TurnRecord(t) => Some(t.engine_version.clone()),
        kronik_proto::Record::TurnBegin(t) => Some(t.engine_version.clone()),
        kronik_proto::Record::EngineUpgrade(u) => Some(u.to_engine_version.clone()),
        _ => None,
    })
}

/// Replays `(fork point, head]` of `data`'s main, where the fork point is
/// `window` of logical time before the newest root input (or the oldest
/// point retention keeps), in both modes with the same code.
pub async fn check(
    env: &Env,
    data: &Path,
    window: Duration,
    workers: usize,
) -> Result<Checked, String> {
    let branch = "main";
    let log_dir = data.join("branches").join(branch).join("log");
    let reader = LogReader::new(env.clone(), log_dir.clone(), branch);
    let head = head(&reader, &log_dir).await?;
    if head == 0 {
        return Err(format!("{} holds no log", data.display()));
    }
    // The fork point: every root input retention keeps, then the window.
    let oldest = pick_base(data, branch, head, true)?;
    let from = oldest.as_ref().map_or(0, |b| b.lsn);
    let all = ProductionIndex::load_from(&reader, oldest, from, head)
        .await
        .map_err(|e| e.to_string())?;
    let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    let fork_lsn = match all.roots.last() {
        Some(newest) => {
            let since = newest.logical_time_ms.saturating_sub(window_ms);
            all.roots
                .iter()
                .find(|r| r.logical_time_ms >= since)
                .map_or(head, |r| r.start_lsn - 1)
        }
        None => head,
    };
    let from_engine = recorded_engine(&all).unwrap_or_else(|| ENGINE_VERSION.to_owned());
    drop(all);
    let base = pick_base(data, branch, fork_lsn, false)?;
    let index = Arc::new(
        ProductionIndex::load_from(&reader, base, fork_lsn, head)
            .await
            .map_err(|e| e.to_string())?,
    );
    let engine = build_engine(PoolSize {
        concurrency: workers.max(1) as u32,
    })
    .map_err(|e| e.to_string())?;
    let code = CodeStore::new(engine, Some(data.join("code"))).map_err(|e| e.to_string())?;
    let fc = fork_kinds(
        &index,
        fork_lsn,
        |h| code.get(h).map_err(|e| e.to_string()),
        &[],
    )
    .map_err(|e| e.to_string())?;
    let config = config_at(&index, fork_lsn);
    let setup = Arc::new(ReplaySetup::new(
        format!("upgrade-{ENGINE_VERSION}"),
        index.clone(),
        fc.kinds,
        config,
        None,
    ));
    let options = DiffOptions {
        mode: Mode::Both,
        fuel_threshold: NO_FUEL_THRESHOLD,
        ..DiffOptions::default()
    };
    let out = crate::run(
        env,
        setup,
        &options,
        workers.max(1),
        None,
        fc.before,
        fc.after,
        &[],
    )
    .await
    .map_err(|e| e.to_string())?;
    let report = UpgradeReport {
        schema: REPORT_SCHEMA.into(),
        from_engine,
        to_engine: ENGINE_VERSION.into(),
        window_ms,
        fork_lsn,
        checked_through_lsn: head,
        root_inputs: out.diff.summary.root_inputs,
        turns: out.diff.summary.turns_prod,
        diff_hash: out.hash.clone(),
        passed: !out.diff.summary.changed,
        checked_wall_ms: env.clock.wall_ms(),
    };
    Ok(Checked {
        report,
        diff: out.diff,
        diff_bytes: out.bytes,
    })
}
