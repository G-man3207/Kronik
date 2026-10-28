//! The scheduler: actor activation and per-actor serialization, mailboxes,
//! logical time, the turn pipeline, deployments, dead letters and startup
//! recovery.
//!
//! Turn pipeline (brief, "Turn-semantik"): an input is queued on its actor;
//! the actor's worker runs one turn at a time on a fresh instance; the turn
//! record is fsynced; the applier applies it in LSN order; only then are
//! messages delivered and the caller answered. Everything here uses only
//! [`Env`] and `tokio::sync`, so the same code runs in production and in the
//! simulator (ADR 0004).

pub mod effects;
mod gate;
pub mod host;
mod node;
mod privacy;
mod rebase;
pub use rebase::rebase_turn_bytes;
mod reseal;
pub mod scrub;
mod sealing;
pub mod snapshots;
mod timers;
pub mod upgrade;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_log::LogConfig;
use kronik_runtime::{CodeStore, PoolSize, build_engine};
use kronik_store::Store;
use kronik_store::sql::{FileOpener, Limits, SqlPool};

pub use gate::Drain;
pub use node::{
    CodeSwitch, DeployResult, Ingress, METHODS, Node, NodeParts, Probe, RouteEntry, StartError,
    Waiter, normalize_pattern,
};
pub use privacy::{ErasureDone, PrivacyModeChange};
pub use reseal::{
    ResealDone, ResealProgress, clear_reupload, keystore_retention_ms, reupload_ready,
};

/// The first byte of an ingress `request_hash` (the gateway's): 3, the
/// requester is the request's subject, or its `Authorization` value without
/// one. A saved row of another version (1: no requester, 2: also `Cookie`)
/// counts as expired: its key is used anew and its response never replayed.
pub const INGRESS_HASH_VERSION: u8 = 3;

/// Scheduler settings.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub branch: String,
    /// Turns running at once (Wasm instances).
    pub concurrency: usize,
    /// How long an ingress `Idempotency-Key` is remembered (default 24 h).
    pub ingress_ttl: Duration,
    /// Records applied per `state.db` transaction at most.
    pub apply_batch: usize,
    /// `[keys] master_key_file`; default `<data_dir>/keys/master.key`.
    pub master_key_file: Option<std::path::PathBuf>,
    /// The sandboxes behind `foreign://` (M7); none in DST, forks and the
    /// test host, where foreign calls are never live.
    pub foreign: kronik_effects::foreign::ForeignSlot,
    /// Snapshots and retention (m6-storage); `start_local` keeps them under
    /// its data directory with the defaults when unset; none in DST.
    pub storage: Option<snapshots::StorageConfig>,
    /// `[log]` overrides for `start_local`: segment size and age, group
    /// commit window (defaults: 64 MiB, 60 s, 2 ms).
    pub segment_max_bytes: Option<u64>,
    pub segment_max_age: Option<Duration>,
    pub group_commit_window: Option<Duration>,
    /// Test hook: a caller's turn stops right after its callee answered and
    /// before the result is recorded, so a test can crash exactly there.
    #[doc(hidden)]
    pub test_hold_after_call: bool,
    /// Test hook: every code switch (promote, rollback, the rebase switch)
    /// parks after its record is applied and before the code is installed,
    /// until the hold releases it (ADR 0013, 0018).
    #[doc(hidden)]
    pub test_hold_switch: Option<Arc<SwitchHold>>,
    /// `privacy.keystore_backup_retention` (default 30 days). Erasure
    /// completion and keystore backup expiry use this window.
    pub keystore_backup_retention: Duration,
    /// `[sql] max_size_per_actor`. The default when a kind has no
    /// `sql_bytes_per_actor` in a `Limits` record. DST and tests keep 1 GiB.
    pub sql_bytes_per_actor: u64,
    /// `[log] disk_reserve`: below this much free space on the log's file
    /// system, new root inputs and mutations are refused with UNAVAILABLE
    /// (turns already running finish), so new work does not drive the disk
    /// full. Running turns, timers, queued messages and foreign actors keep
    /// writing, so a log write can still fail on a shared file system.
    /// 0 turns the check off.
    pub disk_reserve: u64,
    /// A startup replay of at least this many records is a bulk replay:
    /// scattered indexes dropped, large batches (default 8 192). DST's
    /// `rebuild` scenario sets it low so its runs cut turns across batches.
    pub bulk_replay_min: u64,
    /// Records per `state.db` transaction in a bulk replay of records that
    /// are not simple turns (default 131 072). The live applier keeps
    /// `apply_batch`, so a crash there does not redo a huge batch.
    pub startup_apply_batch: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            branch: "main".into(),
            concurrency: 64,
            ingress_ttl: Duration::from_secs(24 * 3600),
            apply_batch: 512,
            master_key_file: None,
            foreign: kronik_effects::foreign::ForeignSlot::default(),
            storage: None,
            segment_max_bytes: None,
            segment_max_age: None,
            group_commit_window: None,
            test_hold_after_call: false,
            test_hold_switch: None,
            keystore_backup_retention: Duration::from_secs(30 * 86_400),
            sql_bytes_per_actor: 1 << 30,
            disk_reserve: 0,
            bulk_replay_min: 8_192,
            startup_apply_batch: 131_072,
        }
    }
}

/// Test hook for [`NodeConfig::test_hold_switch`]: counts the switches that
/// parked and the turns that came to take their code, and lets each parked
/// switch go on one permit of `release`.
#[doc(hidden)]
#[derive(Debug)]
pub struct SwitchHold {
    pub parked: std::sync::atomic::AtomicUsize,
    pub arrived: std::sync::atomic::AtomicUsize,
    pub release: tokio::sync::Semaphore,
}

impl Default for SwitchHold {
    fn default() -> Self {
        SwitchHold {
            parked: Default::default(),
            arrived: Default::default(),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

/// The result of a finished turn, committed or failed.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnResult {
    pub turn_id: kronik_core::ids::TurnId,
    pub outcome: kronik_proto::log::v1::Outcome,
}

impl TurnResult {
    pub fn committed(&self) -> bool {
        self.outcome.kind == kronik_proto::log::v1::OutcomeKind::Committed as i32
    }
}

/// Opens a node over a data directory (docs/design/m1-core.md §2):
/// `code/`, and `branches/<branch>/{log/, state.db, sql/}`.
pub async fn start_local(
    env: Env,
    data: &Path,
    mut config: NodeConfig,
) -> Result<Arc<Node>, StartError> {
    let branch_dir = data.join("branches").join(&config.branch);
    std::fs::create_dir_all(&branch_dir)
        .map_err(|e| StartError::Log(kronik_log::LogError::Io(e)))?;
    if config.storage.is_none() {
        config.storage = Some(snapshots::StorageConfig::new(data.to_path_buf()));
    }
    snapshots::prepare_state(data, &config.branch).map_err(StartError::Corrupt)?;
    let state = rusqlite::Connection::open(branch_dir.join("state.db"))
        .map_err(|e| StartError::Store(e.into()))?;
    let pool = SqlPool::new(
        Arc::new(FileOpener {
            root: branch_dir.join("sql"),
        }),
        Limits::default(),
        256,
    );
    let store = Store::open(state, pool)?;
    let engine = build_engine(PoolSize {
        concurrency: config.concurrency as u32,
    })?;
    let code = Arc::new(CodeStore::new(engine, Some(data.join("code")))?);
    let mut log = LogConfig::new(branch_dir.join("log"), config.branch.clone());
    if let Some(b) = config.segment_max_bytes {
        log.segment_max_bytes = b;
    }
    if let Some(a) = config.segment_max_age {
        log.segment_max_age = a;
    }
    if let Some(w) = config.group_commit_window {
        log.group_commit_window = w;
    }
    let key_path = config
        .master_key_file
        .clone()
        .unwrap_or_else(|| data.join("keys").join("master.key"));
    let fresh = env.random_bytes::<32>();
    let keys = data.join("keys");
    let (master, created) =
        kronik_privacy::MasterKey::open(&key_path, &keys, Some(fresh)).map_err(key_error)?;
    if created {
        tracing::warn!(path = %key_path.display(), "created a new master key; back it up");
    }
    private_files(&keys, &["secrets.db", "keystore.db"])
        .map_err(|e| StartError::Log(kronik_log::LogError::Io(e)))?;
    let secrets_conn = rusqlite::Connection::open(keys.join("secrets.db"))
        .map_err(|e| StartError::Store(e.into()))?;
    let secrets = kronik_privacy::SecretStore::open(secrets_conn, &master).map_err(key_error)?;
    let keystore_conn = rusqlite::Connection::open(keys.join("keystore.db"))
        .map_err(|e| StartError::Store(e.into()))?;
    let keystore =
        kronik_privacy::keystore::Keystore::open(keystore_conn, &master).map_err(key_error)?;
    Node::start(NodeParts {
        env,
        config,
        log,
        store,
        code,
        secrets: Some(Arc::new(secrets)),
        sealer: Some(Arc::new(
            kronik_privacy::sealer::Sealer::new(Arc::new(keystore))
                .with_pseudonyms(kronik_privacy::keystore::Pseudonyms::new(&master)),
        )),
    })
    .await
}

/// A wrong or missing master key has its own code; anything else in the
/// key or the stores is corruption.
fn key_error(e: kronik_privacy::PrivacyError) -> StartError {
    match e {
        kronik_privacy::PrivacyError::KeyMissing(_)
        | kronik_privacy::PrivacyError::KeyMismatch(_) => StartError::Key(e),
        e => StartError::Corrupt(e.to_string()),
    }
}

/// `dir` (`keys/`) is the daemon's alone (0700), and so are the `databases`
/// in it, with SQLite's `-wal` and `-shm`, and `master.key` (0600), whatever
/// the umask was when they were made. The databases are created with that
/// mode, which SQLite gives their new `-wal` and `-shm` too.
fn private_files(dir: &Path, databases: &[&str]) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    for name in databases {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join(name))?;
    }
    for name in databases.iter().chain(&["master.key"]) {
        for suffix in ["", "-wal", "-shm"] {
            let path = dir.join(format!("{name}{suffix}"));
            if path.exists() {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn key_stores_become_private_whatever_their_mode_was() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        std::fs::create_dir(&keys).unwrap();
        for name in ["secrets.db", "secrets.db-wal"] {
            std::fs::write(keys.join(name), b"").unwrap();
            std::fs::set_permissions(keys.join(name), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
        super::private_files(&keys, &["secrets.db", "keystore.db"]).unwrap();
        let mode = |name: &str| {
            std::fs::metadata(keys.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(""), 0o700);
        for name in ["secrets.db", "secrets.db-wal", "keystore.db"] {
            assert_eq!(mode(name), 0o600, "{name}");
        }
    }
}
