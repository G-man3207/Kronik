//! `kronik upgrade check` (docs/design/m6-storage.md §7): an identity
//! replay of the last window of main with this binary's engine, against a
//! data directory a running daemon may still be writing (read-only: the log
//! through what is on disk, snapshots, components).

use std::collections::{BTreeMap, btree_map::Entry};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::{CodeHash, Lsn};
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

/// Replays `(fork point, head]` of `data`'s main, where the fork point is
/// `window` of logical time before the newest root input (or the oldest
/// point retention keeps), in both modes with the same code. `sealer` opens
/// the sealed values in the window, as the daemon's does
/// ([`kronik_sched::offline_sealer`]).
pub async fn check(
    env: &Env,
    data: &Path,
    window: Duration,
    workers: usize,
    sealer: Option<Arc<kronik_privacy::sealer::Sealer>>,
) -> Result<Checked, String> {
    // Room for each worker's turn and the callees of its calls, which a
    // replay runs inside the worker. A pool of one instance per worker
    // failed the first replayed call, as a divergence.
    let pool = kronik_sched::pool::replay_instances(workers, kronik_sched::pool::available_cpus());
    check_with_pool(
        env,
        data,
        window,
        workers,
        sealer,
        PoolSize::instances(pool),
    )
    .await
}

/// [`check`] on an instance pool of `pool`. A turn that finds the pool full
/// stops the check as one that could not run, with
/// [`ReplayError::Unavailable`](crate::ReplayError::Unavailable)'s message,
/// never as a divergence. Tests use it to make the pool too small.
#[doc(hidden)]
pub async fn check_with_pool(
    env: &Env,
    data: &Path,
    window: Duration,
    workers: usize,
    sealer: Option<Arc<kronik_privacy::sealer::Sealer>>,
    pool: PoolSize,
) -> Result<Checked, String> {
    let branch = "main";
    let log_dir = data.join("branches").join(branch).join("log");
    let reader = LogReader::new(env.clone(), log_dir.clone(), branch);
    let head = head(&reader, &log_dir).await?;
    if head == 0 {
        return Err(format!("{} holds no log", data.display()));
    }
    // The fork point from segment marks and a short tail read. Offline: the
    // daemon may still be writing, so the segments table can lag the log
    // tail, which the search still reads.
    let rebase = kronik_sched::snapshots::last_rebase_at(data, branch);
    let oldest = pick_base(data, branch, head, true, rebase)?;
    let floor = oldest.as_ref().map_or(0, |b| b.lsn);
    let state_db = data.join("branches").join(branch).join("state.db");
    let segments = crate::window::read_segments(&state_db).unwrap_or_default();
    let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
    let found = crate::window::discover_window(&reader, &segments, head, window_ms, floor)
        .await
        .map_err(|e| e.to_string())?;
    let fork_lsn = match found.roots.last() {
        Some(newest) => {
            let since = newest.logical_time_ms.saturating_sub(window_ms);
            found
                .roots
                .iter()
                .find(|r| r.logical_time_ms >= since)
                .map_or(head, |r| r.start_lsn - 1)
        }
        None => head,
    };
    let from_engine = found.engine.unwrap_or_else(|| ENGINE_VERSION.to_owned());
    let base = pick_base(data, branch, fork_lsn, false, rebase)?;
    let mut index = ProductionIndex::load_from(&reader, base, fork_lsn, head)
        .await
        .map_err(|e| e.to_string())?;
    // Sealed values in the window open as they do for the daemon's forks.
    let privacy = sealer.map(|sealer| crate::privacy::ForkPrivacy {
        sealer,
        no_pii: false,
    });
    if let Some(p) = &privacy {
        index.reveal(p);
    }
    let index = Arc::new(index);
    let engine = build_engine(pool).map_err(|e| e.to_string())?;
    let code = CodeStore::new(engine, Some(data.join("code"))).map_err(|e| e.to_string())?;
    let fc = fork_kinds(
        &index,
        fork_lsn,
        |h| code.get(h).map_err(|e| e.to_string()),
        &[],
    )
    .map_err(|e| e.to_string())?;
    let config = config_at(&index, fork_lsn);
    let mut setup = ReplaySetup::recorded(
        format!("upgrade-{ENGINE_VERSION}"),
        index.clone(),
        fc.kinds,
        config,
        None,
    );
    let mut config_history = kronik_effects::ConfigHistory::default();
    let mut versions = BTreeMap::new();
    for (_, record) in index.config_records_upto(head) {
        if let kronik_proto::Record::Deployment(deployment) = &record {
            for kind in &deployment.kinds {
                let hash =
                    CodeHash::from_slice(&kind.code_hash).ok_or("corrupt deployment code hash")?;
                versions.insert(hash, kind.schema_version);
            }
        }
        config_history.push(record);
    }
    for committed in index.records.iter().filter(|c| c.lsn > fork_lsn) {
        if let kronik_proto::Record::TurnRecord(turn) = &committed.record {
            let hash =
                CodeHash::from_slice(&turn.code_hash).ok_or("corrupt recorded turn code hash")?;
            if let Entry::Vacant(entry) = setup.upgrade_code.entry(hash) {
                let schema_version = *versions
                    .get(&hash)
                    .ok_or("recorded code has no deployment metadata")?;
                entry.insert(crate::ForkKind {
                    hash,
                    program: code.get(&hash).map_err(|e| e.to_string())?,
                    schema_version,
                });
            }
        }
    }
    setup.upgrade_config = Some(std::sync::Mutex::new(config_history));
    if let Some(p) = privacy {
        setup.privacy = p;
    }
    // Blobs (M25, M26): the replayed turns read production's blobs, and
    // those they write go to a space of the check's own, removed after it.
    // Its name (`upgrade-` and the engine version, with `.` and `+`) is never
    // a fork's (`[a-z][a-z0-9-]*`).
    setup.blobs = open_blobs(env, data).await?;
    let blob_space = data.join("branches").join(&setup.fork);
    let setup = Arc::new(setup);
    let options = DiffOptions {
        mode: Mode::Both,
        fuel_threshold: NO_FUEL_THRESHOLD,
        ..DiffOptions::default()
    };
    let blobs = setup.blobs.is_some();
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
    .await;
    // The check leaves the data directory as it found it.
    if blobs {
        match std::fs::remove_dir_all(&blob_space) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "removing the upgrade check's blobs {}: {e}",
                    blob_space.display()
                ));
            }
        }
    }
    let out = out.map_err(|e| e.to_string())?;
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
        unverifiable: out.diff.summary.unverifiable,
        passed: !out.diff.summary.changed,
        checked_wall_ms: env.clock.wall_ms(),
    };
    Ok(Checked {
        report,
        diff: out.diff,
        diff_bytes: out.bytes,
    })
}

/// The data directory's blob store, when it has one (M25 on): read-mostly,
/// as a fork uses main's.
async fn open_blobs(env: &Env, data: &Path) -> Result<Option<Arc<kronik_blob::BlobStore>>, String> {
    if !data.join("blobs").is_dir() {
        return Ok(None);
    }
    kronik_blob::BlobStore::open(env.clone(), data, kronik_blob::StoreConfig::default())
        .await
        .map(Some)
        .map_err(|e| format!("opening the blob store: {e}"))
}
