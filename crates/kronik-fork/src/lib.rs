//! Branches, isolated and continuous replay, the diff engine with causal
//! grouping, catch-up, and rendering of behavior diffs to JSON and Markdown
//! (docs/design/m3-fork.md).

pub mod diff;
pub mod index;
pub mod markdown;
pub mod privacy;
pub mod proposal;
pub mod replay;
pub mod sample;
pub mod simulators;
pub mod stubs;
pub mod upgrade;
pub mod watch;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{CodeHash, Lsn};
use kronik_effects::Config;
use kronik_proto::Record;
use kronik_runtime::Program;
use kronik_sched::Node;

pub use diff::{CodeEntry, Diff, DiffOptions, Mode};
pub use index::{ProductionIndex, RootInput};
pub use replay::{
    Continuous, ForkKind, ForkTurn, LiveAccess, ReplayError, ReplaySetup, TreeResult,
};

/// The snapshot a replay of a branch reads from (m6-storage §3): the
/// newest (or, with `oldest`, the oldest) snapshot at or below `at_most`
/// that the log continues. `None` when the log still starts at LSN 1 and
/// no snapshot qualifies, or for `oldest` whenever the log starts at LSN 1
/// (it reaches further back than any snapshot); an error when the log was
/// compacted past everything usable ("outside retention"). `rebase`: the
/// branch's newest StateRebase switch (its LSN, its base LSN), from the node
/// (`Node::last_rebase`) or, offline, `snapshots::last_rebase_at`.
pub fn pick_base(
    data: &std::path::Path,
    branch: &str,
    at_most: Lsn,
    oldest: bool,
    rebase: Option<(Lsn, Lsn)>,
) -> Result<Option<index::Base>, String> {
    let log_dir = data.join("branches").join(branch).join("log");
    let log_first = kronik_log::segment_starts(&log_dir)
        .map_err(|e| e.to_string())?
        .first()
        .copied()
        .unwrap_or(1);
    // Snapshots older than an erasure are deleted (§6.6). A fork that the
    // log itself still holds does not need one of those snapshots, so it
    // is not outside retention. A fork the log no longer reaches must not
    // use a snapshot from before the erasure: that copy still has the
    // subject's rows.
    let floor = kronik_sched::snapshots::erasure_floor(data, branch);
    // A replay through a rebase switch at R rebuilds the state at its base
    // (ADR 0017): a snapshot between the base and R cannot start it
    // (review M13-2); the one at or before the base, which retention keeps
    // until a snapshot after R exists, can.
    let rebase = rebase.filter(|(r, _)| at_most >= *r);
    let snaps = kronik_sched::snapshots::list(data, branch);
    let mut usable = snaps.iter().filter(|(_, m)| {
        m.lsn <= at_most
            && m.lsn + 1 >= log_first
            && floor.is_none_or(|f| m.lsn >= f)
            && rebase.is_none_or(|(r, base)| m.lsn <= base || m.lsn >= r)
    });
    let pick = if oldest {
        // A log that still starts at LSN 1 reaches further back than any
        // snapshot, erasure or not.
        if log_first <= 1 {
            return Ok(None);
        }
        usable.next()
    } else {
        usable.next_back()
    };
    match pick {
        Some((dir, m)) => index::Base::open(m.lsn, dir.clone()).map(Some),
        None if log_first <= 1 => Ok(None),
        None => Err(format!(
            "outside retention: the log starts at lsn {log_first} and no snapshot at or \
             before lsn {at_most} continues it"
        )),
    }
}

const RETENTION_HINT: &str =
    "Pick a later fork point, or lengthen [retention] history, then run: kronik integrity";

pub(crate) fn history_text(history: Duration) -> String {
    let ms = history.as_millis();
    if ms == 0 {
        return "0ms".to_owned();
    }
    if ms.is_multiple_of(86_400_000) {
        return format!("{}d", ms / 86_400_000);
    }
    if ms.is_multiple_of(3_600_000) {
        return format!("{}h", ms / 3_600_000);
    }
    if ms.is_multiple_of(60_000) {
        return format!("{}m", ms / 60_000);
    }
    if ms.is_multiple_of(1_000) {
        return format!("{}s", ms / 1_000);
    }
    format!("{ms}ms")
}

fn outside(message: String) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, message).with_hint(RETENTION_HINT)
}

/// Refuses a fork point outside `retention.history`, or past what the log
/// and snapshots still hold. No-op when the node has no storage config
/// (DST, and `Node::start` with `storage: None`): neither the time window
/// nor `pick_base` is required then.
pub async fn ensure_fork_retained(node: &Node, data: &Path, fork_lsn: Lsn) -> Result<(), ApiError> {
    let Some(storage) = node.storage_config() else {
        return Ok(());
    };
    let hwm = node
        .store()
        .db()
        .time_hwm()
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    let cutoff = kronik_sched::snapshots::history_cutoff(hwm, storage.history);
    let history = history_text(storage.history);
    // A point with no turn at or before it is the usual fork point (the
    // LSN before the first input). Do not treat that missing time as 0:
    // logical time is unix milliseconds, and `0 < cutoff` would refuse a
    // young propose. Use the earliest later turn instead. No later turn,
    // or a later turn still inside the window, is allowed.
    let at = match node.logical_time_at(fork_lsn).await? {
        Some(t) => Some(t),
        None => node.logical_time_after(fork_lsn).await?,
    };
    if let Some(at) = at
        && at < cutoff
    {
        return Err(outside(format!(
            "fork point {fork_lsn} is outside retention: logical time {at} is before \
             cutoff {cutoff} (history {history})"
        )));
    }
    let rebase = node.last_rebase()?;
    if let Err(m) = pick_base(data, node.branch(), fork_lsn, false, rebase) {
        return Err(outside(format!(
            "{m} (fork point {fork_lsn}, cutoff logical time {cutoff}, history {history})"
        )));
    }
    Ok(())
}

/// Writes `bytes` to `path` through a synced temporary file and a rename,
/// then syncs the directory so the rename survives a crash.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// The configuration (grants, limits) after main's records up to `lsn`.
/// Kinds with no `sql_bytes_per_actor` in a `Limits` record use 1 GiB.
pub fn config_at(index: &ProductionIndex, lsn: Lsn) -> Config {
    config_at_with(index, lsn, 0)
}

/// Like [`config_at`], with `sql_default` as the installation SQL cap.
/// `0` keeps [`kronik_effects::KindLimits::default`] (1 GiB).
pub fn config_at_with(index: &ProductionIndex, lsn: Lsn, sql_default: u64) -> Config {
    let mut c = if sql_default == 0 {
        Config::default()
    } else {
        Config::default().with_sql_default(sql_default)
    };
    for r in index.config_records(lsn) {
        c.apply(&r);
    }
    c
}

/// A fork's code: its kinds and the diff's `code.before` / `code.after`.
pub struct ForkCode {
    pub kinds: BTreeMap<String, ForkKind>,
    pub before: Vec<CodeEntry>,
    pub after: Vec<CodeEntry>,
}

/// Each kind's code at `lsn`, loaded with `load`, then replaced or extended
/// by `new`.
pub fn fork_kinds(
    index: &ProductionIndex,
    lsn: Lsn,
    load: impl Fn(&CodeHash) -> Result<Arc<Program>, String>,
    new: &[(String, ForkKind)],
) -> Result<ForkCode, ReplayError> {
    let mut kinds = BTreeMap::new();
    let mut before = Vec::new();
    for (name, v) in index.kinds_at(lsn) {
        let hash = CodeHash::from_slice(&v.code_hash)
            .ok_or_else(|| ReplayError::Host(format!("kind {name:?} has a malformed code hash")))?;
        let program = load(&hash).map_err(ReplayError::Host)?;
        before.push(CodeEntry::new(&name, &hash, v.schema_version));
        kinds.insert(
            name,
            ForkKind {
                hash,
                program,
                schema_version: v.schema_version,
            },
        );
    }
    for (name, k) in new {
        kinds.insert(name.clone(), k.clone());
    }
    let after = kinds
        .iter()
        .map(|(n, k)| CodeEntry::new(n, &k.hash, k.schema_version))
        .collect();
    Ok(ForkCode {
        kinds,
        before,
        after,
    })
}

/// A finished replay.
pub struct ReplayOutput {
    pub diff: Diff,
    /// The canonical diff bytes and their hash.
    pub bytes: Vec<u8>,
    pub hash: String,
    /// The continuous fork (catch-up continues it), when it ran.
    pub continuous: Option<Continuous>,
}

/// Runs isolated replay (sampled, on `workers` workers) and/or continuous
/// replay as `options.mode` says, and builds the diff. `head` are the fork's
/// own leading records for continuous replay.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    env: &Env,
    setup: Arc<ReplaySetup>,
    options: &DiffOptions,
    workers: usize,
    proposal_id: Option<&str>,
    before: Vec<CodeEntry>,
    after: Vec<CodeEntry>,
    head: &[Record],
) -> Result<ReplayOutput, ReplayError> {
    diff::check_options(options).map_err(ReplayError::Host)?;
    let index = setup.index.clone();
    let (trees, continuous) =
        replay::both(env, setup.clone(), options, workers, proposal_id, head).await?;
    let prod_store = if let Some(store) = &setup.prod_store {
        Some(store.clone())
    } else {
        match &continuous {
            Some(_) => Some(replay::production_store(&index)?),
            None => None,
        }
    };
    let turns = continuous
        .as_ref()
        .map(Continuous::turns)
        .unwrap_or_default();
    let view = match (&continuous, &prod_store) {
        (Some(c), Some(p)) => Some(diff::ContinuousView {
            turns: &turns,
            fork: &c.store,
            prod: p,
        }),
        _ => None,
    };
    let d = diff::build(diff::DiffInput {
        fork: &setup.fork,
        proposal_id,
        index: &index,
        before,
        after,
        options,
        isolated: trees.as_deref(),
        continuous: view,
        rebase: false,
    })?;
    let bytes = d.to_bytes();
    let hash = diff::diff_hash(&bytes);
    Ok(ReplayOutput {
        diff: d,
        bytes,
        hash,
        continuous,
    })
}
