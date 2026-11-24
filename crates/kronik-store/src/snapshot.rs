//! Snapshots of the materialized state (docs/design/m6-storage.md §2-§3,
//! §8): consistent copies of `state.db` and every actor database at one
//! LSN, their installation, and the state hash.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use kronik_core::ids::Lsn;
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, MAIN_DB};

use crate::sql::{SqlActor, actor_file};
use crate::{Store, StoreError};

/// Tables of `state.db` the state hash covers: materialized state, not the
/// derived indexes (`turn_index`, `trees`, positions of open turns).
const HASHED_TABLES: &[&str] = &[
    "actors",
    "kv",
    "timers",
    "mailbox",
    "deliveries",
    "ingress_keys",
    "dead_letters",
    "orphans",
    // Rows only: empty in every state from before it, whose hash it leaves.
    "timed_out_calls",
    "deployments",
    "kinds",
    "config_records",
    "policies",
    "approvals",
    "secret_versions",
    "secret_highwater",
    "secret_format",
    "secret_links",
    "secret_link_history",
    // M24: derived from the log like every table above.
    "connections",
    // M26: what actors hold. Rows only, so a state without blobs hashes as
    // before; and only who holds what ([`HASHED_COLUMNS`]).
    "blob_refs",
];

/// Tables hashed with some of their columns, in this order: a hold is the
/// state, not the LSN of the record that made it (M26 §5.3). `timers` and
/// `mailbox` omit `subject`: it is an index probe derived from the body,
/// which is already hashed, so an old snapshot's hash does not move when
/// the column is added on open.
const HASHED_COLUMNS: &[(&str, &[&str])] = &[
    ("blob_refs", &["kind", "key", "hash"]),
    (
        "timers",
        &["kind", "key", "timer_id", "due_ms", "msg", "causal", "lsn"],
    ),
    (
        "mailbox",
        &[
            "message_id",
            "to_kind",
            "to_key",
            "lsn",
            "ordinal",
            "input",
            "causal",
        ],
    ),
];

/// What `Store::snapshot_to` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCopy {
    pub lsn: Lsn,
    pub state_hash: String,
    /// Paths relative to the snapshot directory: `state.db`, `sql/...`.
    pub files: Vec<PathBuf>,
}

fn sqlite(e: rusqlite::Error) -> StoreError {
    StoreError::Sqlite(e)
}

/// Rows of `tables` in key order, type-tagged, into `h`.
/// The hash of `tables` of `db` (all hashed ones when empty), for tests of
/// what the state hash covers.
#[cfg(test)]
pub(crate) fn hash_for_test(db: &crate::db::StateDb, tables: &[&str]) -> String {
    assert!(tables.iter().all(|t| HASHED_TABLES.contains(t)));
    let mut h = blake3::Hasher::new();
    let tables = if tables.is_empty() {
        HASHED_TABLES
    } else {
        tables
    };
    hash_tables(db.conn(), tables, &mut h).unwrap();
    h.finalize().to_hex().to_string()
}

fn hash_tables(conn: &Connection, tables: &[&str], h: &mut blake3::Hasher) -> rusqlite::Result<()> {
    for t in tables {
        let mut cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?
            .query_map([t], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if cols.is_empty() {
            continue;
        }
        if let Some((_, some)) = HASHED_COLUMNS.iter().find(|(name, _)| name == t) {
            cols = some.iter().map(|c| (*c).to_owned()).collect();
        }
        let order = (1..=cols.len())
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let select = cols
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut st = conn.prepare(&format!("SELECT {select} FROM \"{t}\" ORDER BY {order}"))?;
        let n = st.column_count();
        let mut rows = st.query([])?;
        while let Some(row) = rows.next()? {
            h.update(format!("row|{t}|").as_bytes());
            for i in 0..n {
                match row.get_ref(i)? {
                    ValueRef::Null => h.update(b"N;"),
                    ValueRef::Integer(v) => h.update(format!("I{v};").as_bytes()),
                    ValueRef::Real(v) => h.update(format!("R{:016x};", v.to_bits()).as_bytes()),
                    ValueRef::Text(b) => {
                        h.update(format!("T{}:", b.len()).as_bytes());
                        h.update(b)
                    }
                    ValueRef::Blob(b) => {
                        h.update(format!("B{}:", b.len()).as_bytes());
                        h.update(b)
                    }
                };
            }
            h.update(b"\n");
        }
    }
    Ok(())
}

/// A compact copy of the database at `path` (replaced). `VACUUM INTO`
/// writes live rows only, so free pages that held deleted rows never reach
/// a snapshot (H11); the logical content, and so the state hash, is equal.
///
/// A snapshot's caller holds the apply lock for this database only, so
/// what is copied is the applied state: an actor turn's
/// `SAVEPOINT kronik_turn` is always rolled back, and its changeset is
/// applied under the store's apply lock. `VACUUM INTO` refuses to
/// run inside a transaction, and the connection can be inside one (a turn
/// keeps its savepoint open between its statements, v0.1 re-review R1).
/// Then the copy is made from the committed state on disk instead: the
/// database and WAL files are copied while the caller holds the
/// connection's lock (actor databases use exclusive locking, so no other
/// connection can read them), and opening the copy keeps only committed
/// WAL frames.
pub(crate) fn vacuum_into(conn: &Connection, path: &Path) -> Result<(), StoreError> {
    let target = path
        .to_str()
        .ok_or_else(|| rusqlite::Error::InvalidPath(path.to_path_buf()))?;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(e)),
    }
    if conn.is_autocommit() {
        conn.execute("VACUUM INTO ?1", [target]).map_err(sqlite)?;
        return Ok(());
    }
    let Some(file) = conn.path().filter(|p| !p.is_empty()) else {
        return Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("an in-memory database inside a transaction cannot be copied".into()),
        )));
    };
    let staging = path.with_extension("committed");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(io)?;
    let copied = (|| {
        let db = staging.join("db");
        std::fs::copy(file, &db).map_err(io)?;
        let wal = format!("{file}-wal");
        if Path::new(&wal).exists() {
            std::fs::copy(&wal, staging.join("db-wal")).map_err(io)?;
        }
        let source = Connection::open(&db).map_err(sqlite)?;
        source.execute("VACUUM INTO ?1", [target]).map_err(sqlite)?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&staging);
    copied
}

impl SqlActor {
    /// A consistent, compact copy of this database ([`vacuum_into`]).
    pub fn backup_to(&self, path: &Path) -> Result<(), StoreError> {
        self.set_host();
        // `VACUUM INTO` attaches its target; guests may attach nothing.
        self.conn
            .set_limit(Limit::SQLITE_LIMIT_ATTACHED, 1)
            .map_err(sqlite)?;
        let copied = vacuum_into(&self.conn, path);
        self.conn
            .set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
            .map_err(sqlite)?;
        copied
    }

    /// The canonical hash of the committed rows. A running turn's open
    /// savepoint shows its rows on this connection, so then the hash comes
    /// from a [`vacuum_into`] copy next to the database, deleted after. The
    /// copy is named [`HASH_COPY_PREFIX`]`<file>.tmp`, never `*.db`, and
    /// [`sweep_hash_copies`] deletes one a crash left.
    pub fn committed_hash(&self) -> Result<String, StoreError> {
        let file = self.conn.path().filter(|p| !p.is_empty());
        // shortcut: an in-memory database (DST, forks) hashes live, a running
        // turn's rows included; give it a copy path if one ever needs this.
        let (Some(file), false) = (file, self.conn.is_autocommit()) else {
            return self.canonical_hash().map_err(sqlite);
        };
        let file = Path::new(file);
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        let copy = file.with_file_name(format!("{HASH_COPY_PREFIX}{name}.tmp"));
        self.backup_to(&copy)?;
        let hash = Connection::open(&copy)
            .and_then(|c| crate::sql::canonical_hash_raw(&c))
            .map_err(sqlite);
        let _ = std::fs::remove_file(&copy);
        hash
    }

    /// Replaces this database's content with the copy at `path`.
    pub fn restore_from(&mut self, path: &Path) -> Result<(), StoreError> {
        self.set_host();
        self.conn
            .restore(MAIN_DB, path, None::<fn(rusqlite::backup::Progress)>)
            .map_err(sqlite)?;
        self.reset_caches();
        Ok(())
    }

    /// Replaces this database's content with `src`'s (a rebase switch, ADR
    /// 0017).
    pub fn copy_from(&mut self, src: &SqlActor) -> Result<(), StoreError> {
        self.set_host();
        src.set_host();
        {
            let backup =
                rusqlite::backup::Backup::new(&src.conn, &mut self.conn).map_err(sqlite)?;
            backup
                .run_to_completion(1024, std::time::Duration::ZERO, None)
                .map_err(sqlite)?;
        }
        self.reset_caches();
        Ok(())
    }

    /// Drops every table and view but Kronik's own and sets the applied LSN
    /// to `lsn`, in one transaction (a rebase switch for an actor the old
    /// code gave no database).
    pub fn clear_at(&mut self, lsn: u64) -> Result<(), StoreError> {
        self.set_host();
        let tx = self.conn.transaction().map_err(sqlite)?;
        let objects: Vec<(String, String)> = {
            let mut st = tx
                .prepare(
                    "SELECT type, name FROM sqlite_schema WHERE type IN ('table', 'view') \
                     AND name NOT LIKE 'sqlite_%' AND name != '_kronik_meta'",
                )
                .map_err(sqlite)?;
            let rows = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(sqlite)?;
            rows.collect::<Result<_, _>>().map_err(sqlite)?
        };
        for (kind, name) in objects {
            let kind = if kind == "view" { "VIEW" } else { "TABLE" };
            tx.execute_batch(&format!(
                "DROP {kind} IF EXISTS \"{}\"",
                name.replace('"', "\"\"")
            ))
            .map_err(sqlite)?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO _kronik_meta (k, v) VALUES ('applied_lsn', ?1)",
            [lsn as i64],
        )
        .map_err(sqlite)?;
        tx.commit().map_err(sqlite)?;
        self.reset_caches();
        Ok(())
    }

    /// Sets the database's applied LSN (a rebase switch replaced it at
    /// `lsn`).
    pub fn stamp_applied(&mut self, lsn: u64) -> Result<(), StoreError> {
        self.set_host();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO _kronik_meta (k, v) VALUES ('applied_lsn', ?1)",
                [lsn as i64],
            )
            .map_err(sqlite)?;
        Ok(())
    }

    /// Raises the applied LSN to `to` when it is below `floor`: this
    /// database has no change since, so it is complete through `to`, which
    /// the caller knows because it holds the apply lock ([`Store::raise_idle_sql`]).
    /// Never lowers it. `None` when a turn has its savepoint open on this
    /// connection between its statements: the stamp would be rolled back
    /// with the turn, so the caller must try again.
    pub fn raise_applied(&mut self, floor: u64, to: u64) -> Result<Option<bool>, StoreError> {
        self.set_host();
        let applied = self.applied_lsn().map_err(sqlite)?;
        if applied >= floor || applied >= to {
            return Ok(Some(false));
        }
        if !self.conn.is_autocommit() {
            return Ok(None);
        }
        self.stamp_applied(to)?;
        Ok(Some(true))
    }

    /// Makes what is committed durable: under `synchronous=NORMAL` a WAL is
    /// synced only when it is checkpointed. `false` when a turn is open on
    /// the connection and the checkpoint could not run.
    pub fn checkpoint_durable(&self) -> Result<bool, StoreError> {
        self.set_host();
        if !self.conn.is_autocommit() {
            return Ok(false);
        }
        let busy: i64 = self
            .conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
            .map_err(sqlite)?;
        Ok(busy == 0)
    }
}

/// Retries when the applied LSN moves between per-database copies.
const SNAPSHOT_LSN_RETRIES: usize = 128;

#[cfg(test)]
thread_local! {
    static SNAPSHOT_APPLY_LOCK_HOLDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Runs once inside `state_hash`, on the hashing thread, not under the apply lock.
    static STATE_HASH_HOOK: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
}

/// SQL actors from a `state.db` copy.
fn sql_actors_at(state: &Path) -> Result<Vec<String>, StoreError> {
    let conn = Connection::open(state).map_err(sqlite)?;
    let mut st = conn
        .prepare("SELECT kind, key FROM actors WHERE sql = 1 ORDER BY kind, key")
        .map_err(sqlite)?;
    let rows = st.query_map([], |r| {
        Ok(format!(
            "{}/{}",
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?
        ))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// State hash from on-disk snapshot copies (not the live store).
fn hash_snapshot_at(dir: &Path, state: &Path, actors: &[String]) -> Result<String, StoreError> {
    let mut h = blake3::Hasher::new();
    let conn = Connection::open(state).map_err(sqlite)?;
    hash_tables(&conn, HASHED_TABLES, &mut h).map_err(sqlite)?;
    for name in actors {
        let rel = actor_file(Path::new("sql"), name);
        let copy = Connection::open(dir.join(&rel)).map_err(sqlite)?;
        let hash = crate::sql::canonical_hash_raw(&copy).map_err(sqlite)?;
        h.update(format!("sql|{name}|{hash}\n").as_bytes());
    }
    Ok(format!("b3:{}", h.finalize().to_hex()))
}

fn remove_snapshot_copies(dir: &Path, actors: &[String]) -> Result<(), StoreError> {
    let _ = std::fs::remove_file(dir.join("state.db"));
    for name in actors {
        let _ = std::fs::remove_file(dir.join(actor_file(Path::new("sql"), name)));
    }
    Ok(())
}

fn snapshot_apply_lock(store: &Store) -> crate::ApplyLock<'_> {
    #[cfg(test)]
    SNAPSHOT_APPLY_LOCK_HOLDS.with(|c| c.set(c.get() + 1));
    store.apply_lock()
}

#[cfg(test)]
fn fire_state_hash_hook() {
    STATE_HASH_HOOK.with(|c| {
        if let Some(f) = c.take() {
            f();
        }
    });
}

/// Even epoch: no apply holds the lock. Spins while one does, without taking it.
fn wait_even_epoch(store: &Store) -> u64 {
    loop {
        let g = store.apply_epoch.load(Ordering::Acquire);
        if g & 1 == 0 {
            std::sync::atomic::fence(Ordering::Acquire);
            return g;
        }
        std::thread::yield_now();
    }
}

fn epoch_stable(store: &Store, g: u64) -> bool {
    std::sync::atomic::fence(Ordering::Acquire);
    store.apply_epoch.load(Ordering::Acquire) == g
}

/// A staging directory under `sql/` so [`sweep_hash_copies`] removes one a crash left.
struct HashStaging(PathBuf);

impl HashStaging {
    fn create(state_db: &Path) -> Result<Self, StoreError> {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = state_db
            .parent()
            .unwrap_or(Path::new("."))
            .join("sql")
            .join(format!("{HASH_COPY_PREFIX}{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(io)?;
        Ok(Self(dir))
    }
}

impl Drop for HashStaging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Copies a database and its WAL or journal. Skips `-shm`: SQLite rebuilds it,
/// and a partial index would hide frames the copy should see.
fn copy_db(from: &Path, to: &Path) -> Result<(), StoreError> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    copy_private(from, to).map_err(io)?;
    for suffix in ["-wal", "-journal"] {
        let src = with_suffix(from, suffix);
        if src.is_file() {
            copy_private(&src, &with_suffix(to, suffix)).map_err(io)?;
        }
    }
    Ok(())
}

impl Store {
    /// Copies `state.db` and every actor database at the applied LSN into
    /// `dir` (created). The apply lock is taken only to read the LSN and for
    /// each database copy, never for the whole-state hash (v0.1 re-review R1
    /// hashes actor copies, not live savepoints). If the applied LSN moves
    /// during the copies the pass retries.
    pub fn snapshot_to(&self, dir: &Path) -> Result<SnapshotCopy, StoreError> {
        std::fs::create_dir_all(dir.join("sql")).map_err(io)?;
        let state_path = dir.join("state.db");
        for _ in 0..SNAPSHOT_LSN_RETRIES {
            let (lsn, actors) = {
                let _apply = snapshot_apply_lock(self);
                let lsn = self.applied.get();
                let actors = self.db().sql_actors()?;
                (lsn, actors)
            };
            {
                let _apply = snapshot_apply_lock(self);
                if self.applied.get() != lsn {
                    continue;
                }
                self.db().backup_to(&state_path)?;
            }
            let mut files = vec![PathBuf::from("state.db")];
            let mut complete = true;
            for name in &actors {
                let rel = actor_file(Path::new("sql"), name);
                let dest = dir.join(&rel);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(io)?;
                }
                let _apply = snapshot_apply_lock(self);
                if self.applied.get() != lsn {
                    complete = false;
                    break;
                }
                let db = self.sql.get(name)?;
                db.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .backup_to(&dest)?;
                files.push(rel);
            }
            if !complete {
                remove_snapshot_copies(dir, &actors)?;
                continue;
            }
            let actors = sql_actors_at(&state_path)?;
            let state_hash = hash_snapshot_at(dir, &state_path, &actors)?;
            return Ok(SnapshotCopy {
                lsn,
                state_hash,
                files,
            });
        }
        Err(StoreError::Corrupt(
            "snapshot: the applied LSN kept moving during copy".into(),
        ))
    }

    /// The state hash (m6-storage §8) at the applied LSN.
    ///
    /// A file-backed store hashes a private copy of the committed databases
    /// and does not hold the apply lock across that copy or the hash
    /// (ADR 0153). An in-memory store has no file to copy: it hashes the
    /// live connections and retries if an apply lands mid-hash.
    pub fn state_hash(&self) -> Result<String, StoreError> {
        let path = {
            let db = self.db();
            db.conn()
                .path()
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
        };
        if let Some(path) = path {
            self.state_hash_from_files(&path)
        } else {
            // shortcut: in-memory (DST, forks) has no file; retry covers an apply.
            self.state_hash_consistent()
        }
    }

    fn state_hash_from_files(&self, state_path: &Path) -> Result<String, StoreError> {
        let mut last = None;
        for _ in 0..SNAPSHOT_LSN_RETRIES {
            let g = wait_even_epoch(self);
            #[cfg(test)]
            fire_state_hash_hook();
            if !epoch_stable(self, g) {
                continue;
            }
            match self.copy_and_hash(state_path, g) {
                Ok(Some(hash)) => return Ok(hash),
                Ok(None) => continue,
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            StoreError::Corrupt("state hash: the applied state kept moving".into())
        }))
    }

    /// Copies `state.db` and every actor database, then hashes the copies.
    /// `None` when an apply landed during the copy: the bytes may be mixed.
    fn copy_and_hash(&self, state_path: &Path, epoch: u64) -> Result<Option<String>, StoreError> {
        let staging = HashStaging::create(state_path)?;
        let dest_state = staging.0.join("state.db");
        copy_db(state_path, &dest_state)?;
        let actors = sql_actors_at(&dest_state)?;
        for name in &actors {
            let src = self.actor_db_path(name)?;
            let dest = staging.0.join(actor_file(Path::new("sql"), name));
            copy_db(&src, &dest)?;
        }
        if !epoch_stable(self, epoch) {
            return Ok(None);
        }
        Ok(Some(hash_snapshot_at(&staging.0, &dest_state, &actors)?))
    }

    fn actor_db_path(&self, name: &str) -> Result<PathBuf, StoreError> {
        let db = self.sql.get(name).map_err(sqlite)?;
        let guard = db.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .conn
            .path()
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| StoreError::Corrupt(format!("actor {name} has no database file")))
    }

    fn state_hash_consistent(&self) -> Result<String, StoreError> {
        for _ in 0..SNAPSHOT_LSN_RETRIES {
            let g = wait_even_epoch(self);
            #[cfg(test)]
            fire_state_hash_hook();
            if !epoch_stable(self, g) {
                continue;
            }
            let hash = self.state_hash_locked()?;
            if epoch_stable(self, g) {
                return Ok(hash);
            }
        }
        Err(StoreError::Corrupt(
            "state hash: the applied state kept moving".into(),
        ))
    }

    fn state_hash_locked(&self) -> Result<String, StoreError> {
        let mut h = blake3::Hasher::new();
        hash_tables(self.db().conn(), HASHED_TABLES, &mut h).map_err(sqlite)?;
        let actors = self.db().sql_actors()?;
        for name in actors {
            let db = self.sql.get(&name)?;
            let hash = db
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .committed_hash()?;
            h.update(format!("sql|{name}|{hash}\n").as_bytes());
        }
        Ok(format!("b3:{}", h.finalize().to_hex()))
    }

    /// An in-memory copy of a snapshot directory (replay cursors): its
    /// `state.db` and actor databases loaded into memory.
    pub fn open_snapshot_in_memory(dir: &Path) -> Result<std::sync::Arc<Store>, StoreError> {
        let mut conn = Connection::open_in_memory().map_err(sqlite)?;
        conn.restore(
            MAIN_DB,
            dir.join("state.db"),
            None::<fn(rusqlite::backup::Progress)>,
        )
        .map_err(sqlite)?;
        let store = Store::open(
            conn,
            crate::sql::SqlPool::new(
                std::sync::Arc::new(crate::sql::MemOpener),
                crate::sql::Limits::default(),
                usize::MAX,
            ),
        )?;
        let actors = store.db().sql_actors()?;
        for name in actors {
            let file = actor_file(&dir.join("sql"), &name);
            let db = store.sql.get(&name)?;
            db.lock()
                .unwrap_or_else(|e| e.into_inner())
                .restore_from(&file)?;
        }
        Ok(store)
    }
}

static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(1);
static NEXT_CURSOR: AtomicU64 = AtomicU64::new(1);

/// One read-only image of a snapshot directory. Replay workers open cursors
/// on it; a page is copied only when that cursor writes (#197).
pub struct SnapshotImage {
    id: u64,
    share: std::sync::Arc<crate::sql::CowShare>,
    state: std::sync::Arc<[u8]>,
    actors: Vec<(String, std::sync::Arc<[u8]>)>,
    image_bytes: u64,
}

impl SnapshotImage {
    /// A consistent image of `dir`, including a WAL a raw file read would miss.
    pub fn load(dir: &Path) -> Result<SnapshotImage, StoreError> {
        let state = std::sync::Arc::<[u8]>::from(consistent_image(&dir.join("state.db"))?);
        let names = actor_names(&dir.join("state.db"))?;
        let mut actors = Vec::with_capacity(names.len());
        let mut image_bytes = state.len() as u64;
        for name in names {
            let file = actor_file(&dir.join("sql"), &name);
            let bytes = std::sync::Arc::<[u8]>::from(consistent_image(&file)?);
            image_bytes += bytes.len() as u64;
            actors.push((name, bytes));
        }
        Ok(SnapshotImage {
            id: NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed),
            share: std::sync::Arc::new(crate::sql::CowShare::new()),
            state,
            actors,
            image_bytes,
        })
    }

    /// Bytes of the shared image. Workers must not multiply this by their count.
    pub fn image_bytes(&self) -> u64 {
        self.image_bytes
    }

    /// Pages copied because a cursor wrote. Shared across every cursor of this image.
    pub fn private_bytes(&self) -> u64 {
        self.share.private_bytes()
    }

    /// A writable cursor. Its unmodified pages stay in [`Self::image_bytes`].
    pub fn open(&self) -> Result<std::sync::Arc<Store>, StoreError> {
        let tag = NEXT_CURSOR.fetch_add(1, Ordering::Relaxed);
        let state_path = format!("kcow{}c{tag}s", self.id);
        self.share.bind(&state_path, self.state.clone());
        let conn = Connection::open_with_flags_and_vfs(
            &state_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            crate::sql::cow_vfs_name(),
        )
        .map_err(sqlite)?;
        conn.execute_batch(
            "PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=MEMORY; PRAGMA mmap_size=0;",
        )
        .map_err(sqlite)?;
        let opener = CowOpener {
            share: self.share.clone(),
            id: self.id,
            tag,
            actors: self.actors.iter().cloned().collect(),
        };
        Store::open_in(
            conn,
            crate::sql::SqlPool::new(
                std::sync::Arc::new(opener),
                crate::sql::Limits::default(),
                usize::MAX,
            ),
            Some(self.share.clone()),
        )
    }
}

struct CowOpener {
    share: std::sync::Arc<crate::sql::CowShare>,
    id: u64,
    tag: u64,
    actors: std::collections::HashMap<String, std::sync::Arc<[u8]>>,
}

impl crate::sql::SqliteOpener for CowOpener {
    fn open(&self, actor: &str, vfs: &str) -> rusqlite::Result<Connection> {
        let path = format!(
            "kcow{}c{}a{}",
            self.id,
            self.tag,
            blake3::hash(actor.as_bytes()).to_hex()
        );
        // An actor created after the snapshot has no image. An empty
        // database is what an in-memory cursor opened for it.
        if let Some(bytes) = self.actors.get(actor) {
            self.share.bind(&path, bytes.clone());
        }
        crate::sql::arm_cow_vfs(vfs).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let conn = Connection::open_with_flags_and_vfs(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            vfs,
        )?;
        conn.execute_batch(
            "PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=MEMORY; PRAGMA mmap_size=0;",
        )?;
        Ok(conn)
    }

    fn exists(&self, actor: &str) -> bool {
        self.actors.contains_key(actor)
    }
}

fn consistent_image(path: &Path) -> Result<Vec<u8>, StoreError> {
    let src = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(sqlite)?;
    let mut mem = Connection::open_in_memory().map_err(sqlite)?;
    {
        let backup = rusqlite::backup::Backup::new(&src, &mut mem).map_err(sqlite)?;
        backup
            .run_to_completion(64, std::time::Duration::ZERO, None)
            .map_err(sqlite)?;
    }
    crate::sql::serialize_main(&mem).map_err(StoreError::Corrupt)
}

fn actor_names(state_db: &Path) -> Result<Vec<String>, StoreError> {
    let conn = Connection::open_with_flags(state_db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(sqlite)?;
    let mut st = conn
        .prepare("SELECT kind, key FROM actors WHERE sql = 1 ORDER BY kind, key")
        .map_err(sqlite)?;
    let rows = st
        .query_map([], |r| {
            Ok(format!(
                "{}/{}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?
            ))
        })
        .map_err(sqlite)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite)
}

#[cfg(test)]
mod shared_image {
    use super::*;

    #[test]
    fn four_cursors_do_not_copy_the_snapshot_four_times() {
        let dir = tempfile::tempdir().unwrap();
        let blob = vec![0xABu8; 2 << 20];
        crate::db::StateDb::write_blob_db(&dir.path().join("state.db"), &blob).unwrap();
        let image = SnapshotImage::load(dir.path()).unwrap();
        assert!(image.image_bytes() >= blob.len() as u64);
        let cursors: Vec<_> = (0..4).map(|_| image.open().unwrap()).collect();
        for store in &cursors {
            assert_eq!(store.db().blob_for_test().unwrap(), blob);
        }
        let private = image.private_bytes();
        assert!(
            private < image.image_bytes(),
            "4 cursors copied the snapshot: private {private} image {}",
            image.image_bytes()
        );
    }
}

/// The subject keys the snapshot's state needs ([`crate::db::sealed_keys`]),
/// read without changing the snapshot.
pub fn sealed_keys(snapshot: &Path) -> Result<crate::db::SubjectKeys, StoreError> {
    let conn = rusqlite::Connection::open_with_flags(
        snapshot.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    crate::db::sealed_keys(&conn)
}

/// The first log segment a start from `snapshot` needs before the
/// snapshot's own LSN: the one holding the `TurnBegin` of the oldest turn
/// open at the snapshot (its re-run reads the begin from the log). `None`
/// when no turn was open. Read without changing the snapshot.
pub fn open_turn_segment(snapshot: &Path) -> Result<Option<kronik_core::ids::Lsn>, StoreError> {
    let conn = rusqlite::Connection::open_with_flags(
        snapshot.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let first: Option<i64> =
        conn.query_row("SELECT min(segment) FROM open_turns", [], |r| r.get(0))?;
    Ok(first.map(|segment| segment as kronik_core::ids::Lsn))
}

/// The turn open at `snapshot` whose `TurnBegin` is in the oldest segment
/// ([`open_turn_segment`]): that segment's first LSN and the turn's
/// execution id, which retention names when it keeps the segment for it.
/// `None` when no turn was open. Read without changing the snapshot.
pub fn oldest_open_turn(snapshot: &Path) -> Result<Option<(Lsn, String)>, StoreError> {
    let conn = rusqlite::Connection::open_with_flags(
        snapshot.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement =
        conn.prepare("SELECT segment, execution_id FROM open_turns ORDER BY segment, lsn LIMIT 1")?;
    let mut rows = statement.query([])?;
    Ok(match rows.next()? {
        Some(row) => Some((row.get::<_, i64>(0)? as Lsn, row.get::<_, String>(1)?)),
        None => None,
    })
}

/// The blob identities the state in `state_db` roots (M26 §7: pinned, not
/// erased; M26 adds holds), sorted, with their sizes, read without changing
/// the file. A state from before blobs has no blob tables and roots none.
pub fn state_blob_roots(state_db: &Path) -> Result<Vec<(String, u64)>, StoreError> {
    let conn = rusqlite::Connection::open_with_flags(
        state_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let has_tables: bool = conn.query_row(
        "SELECT count(*) = 2 FROM sqlite_schema WHERE type = 'table' AND name IN ('blobs', 'blob_pins')",
        [],
        |r| r.get(0),
    )?;
    if !has_tables {
        return Ok(Vec::new());
    }
    crate::db::StateDb::roots_of(&conn)
}

/// The code hashes the snapshot's `deployments` table names, as `<64 hex>`
/// strings (the name a `code/` object carries before `.wasm`), read without
/// changing the snapshot. A restore downloads these and the ones the
/// segments' deployment records name (m6-storage §6 step 3). The table
/// holds every deployment ever applied, so an older snapshot's set is
/// contained in a newer one's.
pub fn deployment_code_hashes(
    snapshot: &Path,
) -> Result<std::collections::BTreeSet<String>, StoreError> {
    let conn = rusqlite::Connection::open_with_flags(
        snapshot.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = conn.prepare("SELECT record FROM deployments")?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = std::collections::BTreeSet::new();
    for row in rows {
        let deployment: kronik_proto::log::v1::Deployment = crate::db::decode(&row?, "deployment")?;
        for kind in &deployment.kinds {
            let hash =
                kronik_core::ids::CodeHash::from_slice(&kind.code_hash).ok_or_else(|| {
                    StoreError::Corrupt(format!(
                        "a deployment of {} names a code hash that is not 32 bytes",
                        kind.kind
                    ))
                })?;
            out.insert(hash.hex());
        }
    }
    Ok(out)
}

/// Installs a snapshot directory as a branch's state: `state.db` and the
/// actor databases are copied into `branch_dir` (`state.db`, `sql/`),
/// replacing what is there. The daemon must not run on it.
///
/// The copies are staged and fsynced, and their directories fsynced, before
/// the live tree is replaced. A failure before that directory fsync leaves
/// the previous `state.db`.
pub fn install(snapshot: &Path, branch_dir: &Path) -> Result<(), StoreError> {
    recover_interrupted_install(branch_dir)?;
    let stage = branch_dir.join(INSTALL_STAGE);
    #[cfg(test)]
    INSTALL_SYNCS.with(|s| s.borrow_mut().clear());
    let staged = (|| {
        std::fs::create_dir_all(stage.join("sql")).map_err(io)?;
        std::fs::copy(snapshot.join("state.db"), stage.join("state.db")).map_err(io)?;
        copy_tree(&snapshot.join("sql"), &stage.join("sql")).map_err(io)?;
        stamp_installed(snapshot, &stage.join("sql"))?;
        for path in sync_order(&stage).map_err(io)? {
            sync_path(&path)?;
        }
        // The stage's name, before anything live is removed.
        sync_path(branch_dir)
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(e);
    }
    publish_install(&stage, branch_dir)
}

/// A crash left these beside the live tree. Not state: a start opens
/// `state.db` and `sql/`.
const INSTALL_STAGE: &str = ".snapshot-install";
const INSTALL_ASIDE: &str = ".snapshot-install-old";

/// Puts back an actor tree [`install`] renamed aside and did not replace,
/// and deletes a stage or old tree a crash left. The stage holds actor rows
/// an erasure would not reach. Called before the store opens, including
/// when this start does not install.
pub fn recover_interrupted_install(branch_dir: &Path) -> Result<(), StoreError> {
    let sql = branch_dir.join("sql");
    let aside = branch_dir.join(INSTALL_ASIDE);
    if aside.exists() && !sql.exists() {
        std::fs::rename(&aside, &sql).map_err(io)?;
        sync_path(branch_dir)?;
        tracing::warn!("restored actor databases an interrupted snapshot install left aside");
    } else if aside.exists() {
        std::fs::remove_dir_all(&aside).map_err(io)?;
        sync_path(branch_dir)?;
    }
    let stage = branch_dir.join(INSTALL_STAGE);
    if stage.exists() {
        std::fs::remove_dir_all(&stage).map_err(io)?;
        sync_path(branch_dir)?;
        tracing::info!("deleted a snapshot install a crash left unfinished");
    }
    Ok(())
}

fn publish_install(stage: &Path, branch_dir: &Path) -> Result<(), StoreError> {
    // The old WAL is named for `state.db`. It must be durably gone before
    // the replacement takes that name, or the next open would replay it
    // into the snapshot's file.
    for name in ["state.db-wal", "state.db-shm"] {
        match std::fs::remove_file(branch_dir.join(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io(e)),
            _ => {}
        }
    }
    sync_path(branch_dir)?;
    std::fs::rename(stage.join("state.db"), branch_dir.join("state.db")).map_err(io)?;
    let live_sql = branch_dir.join("sql");
    let aside = branch_dir.join(INSTALL_ASIDE);
    if live_sql.exists() {
        std::fs::rename(&live_sql, &aside).map_err(io)?;
    }
    if let Err(e) = std::fs::rename(stage.join("sql"), &live_sql) {
        if aside.exists() && !live_sql.exists() {
            let _ = std::fs::rename(&aside, &live_sql);
        }
        return Err(io(e));
    }
    sync_path(branch_dir)?;
    if aside.exists() {
        std::fs::remove_dir_all(&aside).map_err(io)?;
    }
    std::fs::remove_dir_all(stage).map_err(io)?;
    sync_path(branch_dir)
}

/// Every file under `dir` (breadth first), then each directory, children
/// first: the order in which to fsync a tree. Empty if `dir` does not exist.
pub fn sync_order(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if !dir.exists() {
        return Ok(files);
    }
    let mut dirs = vec![dir.to_path_buf()];
    let mut i = 0;
    while i < dirs.len() {
        let current = dirs[i].clone();
        for entry in std::fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                dirs.push(path);
            } else {
                files.push(path);
            }
        }
        i += 1;
    }
    dirs.reverse();
    files.extend(dirs);
    Ok(files)
}

fn sync_path(path: &Path) -> Result<(), StoreError> {
    #[cfg(test)]
    {
        if path.is_dir() && FAIL_INSTALL_DIR_SYNC.with(|c| c.get()) {
            return Err(io(std::io::Error::other(
                "injected failure before directory fsync",
            )));
        }
        INSTALL_SYNCS.with(|s| s.borrow_mut().push(path.to_path_buf()));
    }
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(io)
}

#[cfg(test)]
thread_local! {
    static INSTALL_SYNCS: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static FAIL_INSTALL_DIR_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn install_syncs() -> Vec<PathBuf> {
    INSTALL_SYNCS.with(|s| s.borrow().clone())
}

#[cfg(test)]
struct FailInstallDirSync;

#[cfg(test)]
impl FailInstallDirSync {
    fn arm() -> Self {
        FAIL_INSTALL_DIR_SYNC.with(|c| c.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for FailInstallDirSync {
    fn drop(&mut self) {
        FAIL_INSTALL_DIR_SYNC.with(|c| c.set(false));
    }
}

/// A snapshot is a consistent cut: every actor database in it is complete
/// through the snapshot's LSN, however long ago its last change was. An
/// actor database's own applied LSN says only where its last change was
/// (`SqlActor::apply`), and `Store::replay_from` reads it as the point the
/// log is needed from, so the copies carry the cut: otherwise an idle actor
/// would send the start back to a log the snapshot replaced. The snapshot
/// itself is not touched (its manifest hashes the files).
fn stamp_installed(snapshot: &Path, sql: &Path) -> Result<(), StoreError> {
    let lsn = snapshot_lsn(snapshot)?;
    for_each_db(sql, &mut |path| {
        let conn = Connection::open(path).map_err(sqlite)?;
        conn.execute(
            "UPDATE _kronik_meta SET v = ?1 WHERE k = 'applied_lsn' AND v < ?1",
            [lsn as i64],
        )
        .map_err(sqlite)?;
        // The stamp is a WAL frame until it is checkpointed. The file
        // `install` fsyncs has to hold the cut: a power loss drops the WAL.
        let busy: i64 = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
            .map_err(sqlite)?;
        if busy != 0 {
            return Err(StoreError::Corrupt(format!(
                "snapshot install: checkpoint of {} was busy",
                path.display()
            )));
        }
        Ok(())
    })
}

/// The applied LSN of a snapshot's `state.db`: the LSN of its cut.
fn snapshot_lsn(snapshot: &Path) -> Result<Lsn, StoreError> {
    let conn = Connection::open_with_flags(
        snapshot.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(sqlite)?;
    let lsn: i64 = conn
        .query_row("SELECT v FROM meta WHERE k = 'applied_lsn'", [], |r| {
            r.get(0)
        })
        .map_err(sqlite)?;
    Ok(lsn as Lsn)
}

/// `f` for every actor database file (`*.db`) under `dir` (`<xx>/<file>.db`).
fn for_each_db(
    dir: &Path,
    f: &mut dyn FnMut(&Path) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for e in entries {
        let e = e.map_err(io)?;
        let path = e.path();
        if e.file_type().map_err(io)?.is_dir() {
            for_each_db(&path, f)?;
        } else if path.extension().is_some_and(|x| x == "db") {
            f(&path)?;
        }
    }
    Ok(())
}

/// What a branch directory's databases say about where the log must be
/// replayed from: what [`Store::replay_from`] computes once the store is
/// open, read before it opens (`prepare_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Markers {
    /// `state.db`'s applied LSN.
    pub state: Lsn,
    /// The lowest applied LSN of `state.db` and of the actor databases it
    /// lists. A listed database whose file is missing counts 0: the store
    /// would create it empty and replay from the start.
    pub lowest: Lsn,
    /// Actor databases that could not be read. Only in read-only mode, after
    /// a direct open and a private copy both failed. A successful plan treats
    /// this as unanswered and does not pass; the start never leaves one unread.
    pub unread: usize,
}

/// The [`Markers`] of `branch_dir`, or `None` when it has no `state.db`.
/// `log_first` is the first LSN the log holds: while it is 1 no database can
/// be behind it, and when `state.db` itself is behind it the start installs
/// a snapshot whatever the actor databases say, so in both cases they are not
/// read (`lowest` is then `state`) and a start that has nothing to repair
/// opens nothing extra. Read-only mode (`kronik upgrade check`, which may run
/// beside a daemon) does not wait for a database the daemon holds. It reads
/// that applied LSN from a private copy of the file and its WAL, without
/// taking the lock or writing the original. A database that still cannot be
/// read is counted in [`Markers::unread`] and is not treated as current.
pub fn read_markers(
    branch_dir: &Path,
    read_only: bool,
    log_first: Option<Lsn>,
) -> Result<Option<Markers>, StoreError> {
    let state_db = branch_dir.join("state.db");
    if !state_db.exists() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(&state_db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(sqlite)?;
    let state = conn
        .query_row("SELECT v FROM meta WHERE k = 'applied_lsn'", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_or(0, |v| v as Lsn);
    let first = log_first.unwrap_or(1);
    if first <= 1 || state + 1 < first {
        return Ok(Some(Markers {
            state,
            lowest: state,
            unread: 0,
        }));
    }
    let actors: Vec<String> =
        match conn.prepare("SELECT kind, key FROM actors WHERE sql = 1 ORDER BY kind, key") {
            Ok(mut st) => st
                .query_map([], |r| {
                    Ok(format!(
                        "{}/{}",
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?
                    ))
                })
                .and_then(|rows| rows.collect::<rusqlite::Result<_>>())
                .map_err(sqlite)?,
            // A state database from before the actors table has no SQL actors.
            Err(_) => Vec::new(),
        };
    let mut out = Markers {
        state,
        lowest: state,
        unread: 0,
    };
    let root = branch_dir.join("sql");
    for name in actors {
        let file = crate::sql::actor_file(&root, &name);
        if !file.exists() {
            out.lowest = 0;
            continue;
        }
        let flags = if read_only {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let read = open_applied_lsn(&file, flags);
        match read {
            Ok(v) => out.lowest = out.lowest.min(v),
            // The daemon's exclusive lock refuses the direct open. Read the
            // same LSN from a private copy instead of waiting or ignoring it.
            Err(_) if read_only => match applied_lsn_from_private_copy(&file) {
                Some(v) => out.lowest = out.lowest.min(v),
                None => out.unread += 1,
            },
            Err(e) => return Err(sqlite(e)),
        }
    }
    Ok(Some(out))
}

/// `applied_lsn` of an actor database, without waiting for a lock the caller
/// does not hold.
fn open_applied_lsn(file: &Path, flags: rusqlite::OpenFlags) -> rusqlite::Result<Lsn> {
    let conn = Connection::open_with_flags(file, flags)?;
    conn.busy_timeout(std::time::Duration::ZERO)?;
    let v: i64 = conn.query_row(
        "SELECT v FROM _kronik_meta WHERE k = 'applied_lsn'",
        [],
        |r| r.get(0),
    )?;
    Ok(v as Lsn)
}

/// A directory removed on drop, mode `0700` where the platform allows it.
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn create() -> Option<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        let pid = std::process::id();
        for _ in 0..8 {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("kronik-actor-lsn-{pid}-{n}"));
            if create_private(&dir).is_ok() {
                return Some(Self(dir));
            }
        }
        None
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn create_private(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(dir)
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// Copies `from` to a new file `to`. On Unix the destination is created at
/// mode `0600` before any byte is written: an actor database holds plaintext
/// rows, and this copy must not be briefly world-readable.
fn copy_private(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut src = std::fs::File::open(from)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut dest = opts.open(to)?;
    std::io::copy(&mut src, &mut dest)?;
    Ok(())
}

/// The applied LSN of `file` read without taking a lock another process holds.
///
/// Actor databases use WAL and `locking_mode=EXCLUSIVE`, so a second
/// connection cannot open the original while the daemon holds it, and the
/// latest `applied_lsn` may exist only in the WAL. The bytes are copied
/// (the lock is advisory and does not block a read) into a private directory
/// outside the data directory, opened there, and deleted. The `-shm` index
/// is not copied: it is the daemon's heap or a live shared mapping, and
/// SQLite rebuilds it from the WAL. A torn copy fails the open and the
/// caller must not treat the database as current. No path is returned.
fn applied_lsn_from_private_copy(file: &Path) -> Option<Lsn> {
    let dir = PrivateDir::create()?;
    let dest = dir.0.join("actor.db");
    copy_private(file, &dest).ok()?;
    // The journal, if any, must sit beside the copy under SQLite's own name.
    // Skip `-shm`: a partial index would hide WAL frames the copy should see.
    for suffix in ["-wal", "-journal"] {
        let src = with_suffix(file, suffix);
        if src.is_file() {
            copy_private(&src, &with_suffix(&dest, suffix)).ok()?;
        }
    }
    // Read-write so SQLite can recover the WAL into the copy only.
    open_applied_lsn(&dest, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE).ok()
}

/// Copies the files under `from` into `to`, creating subdirectories; nothing if `from` is missing.
pub fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    if !from.exists() {
        return Ok(());
    }
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let dest = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            std::fs::create_dir_all(&dest)?;
            copy_tree(&e.path(), &dest)?;
        } else {
            std::fs::copy(e.path(), &dest)?;
        }
    }
    Ok(())
}

fn io(e: std::io::Error) -> StoreError {
    StoreError::Corrupt(format!("snapshot I/O: {e}"))
}

/// The file a bulk replay keeps beside `state.db` while that may be torn
/// or partly applied (journaling off, docs/perf.md).
fn bulk_marker(state_db: &Path) -> PathBuf {
    let mut name = state_db.as_os_str().to_owned();
    name.push("-bulk");
    PathBuf::from(name)
}

fn bulk_io(e: std::io::Error) -> StoreError {
    StoreError::Corrupt(format!("bulk replay marker I/O: {e}"))
}

fn sync_parent(path: &Path) -> Result<(), StoreError> {
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(bulk_io)?;
    }
    Ok(())
}

/// Writes the marker durably before a bulk replay turns journaling off.
pub(crate) fn write_bulk_marker(state_db: &Path, from: Lsn) -> Result<(), StoreError> {
    let marker = bulk_marker(state_db);
    let f = std::fs::File::create(&marker).map_err(bulk_io)?;
    std::io::Write::write_all(&mut &f, format!("bulk replay from lsn {from}\n").as_bytes())
        .map_err(bulk_io)?;
    f.sync_all().map_err(bulk_io)?;
    sync_parent(&marker)
}

/// Makes `state.db` durable, then removes the marker: the replay is done.
pub(crate) fn remove_bulk_marker(state_db: &Path) -> Result<(), StoreError> {
    std::fs::File::open(state_db)
        .and_then(|f| f.sync_all())
        .map_err(bulk_io)?;
    std::fs::remove_file(bulk_marker(state_db)).map_err(bulk_io)?;
    sync_parent(state_db)
}

/// The name prefix of [`SqlActor::committed_hash`]'s copies (and of their
/// staging directories and WAL files).
pub const HASH_COPY_PREFIX: &str = ".hash-copy-";

/// Before the node runs: deletes the [`HASH_COPY_PREFIX`] copies a crash
/// left under the actor databases' directory `sql` (`sql/<xx>/`, and a
/// staging directory an integrity hash left directly under `sql/`). They
/// hold an actor's rows, which an erasure would not reach. Returns how many.
pub fn sweep_hash_copies(sql: &Path) -> Result<usize, StoreError> {
    let mut swept = 0;
    let Ok(dirs) = std::fs::read_dir(sql) else {
        return Ok(0);
    };
    for dir in dirs {
        let dir = dir.map_err(io)?;
        if dir
            .file_name()
            .to_string_lossy()
            .starts_with(HASH_COPY_PREFIX)
        {
            remove_hash_copy(&dir)?;
            swept += 1;
            continue;
        }
        let Ok(entries) = std::fs::read_dir(dir.path()) else {
            continue;
        };
        for e in entries {
            let e = e.map_err(io)?;
            if !e
                .file_name()
                .to_string_lossy()
                .starts_with(HASH_COPY_PREFIX)
            {
                continue;
            }
            remove_hash_copy(&e)?;
            swept += 1;
        }
    }
    Ok(swept)
}

fn remove_hash_copy(e: &std::fs::DirEntry) -> Result<(), StoreError> {
    if e.file_type().map_err(io)?.is_dir() {
        std::fs::remove_dir_all(e.path()).map_err(io)
    } else {
        std::fs::remove_file(e.path()).map_err(io)
    }
}

/// Before `state.db` opens. When a bulk replay was interrupted (its marker
/// is there), removes `state.db` with its WAL and the replay's scratch file,
/// and the actor databases, then the marker: the start then installs the
/// newest snapshot and applies the log as for a missing `state.db` (I4).
/// Returns whether it did.
pub fn discard_interrupted_bulk_replay(branch_dir: &Path) -> Result<bool, StoreError> {
    let state = branch_dir.join("state.db");
    let marker = bulk_marker(&state);
    if !marker.exists() {
        return Ok(false);
    }
    for f in ["state.db", "state.db-wal", "state.db-shm", "state.db-trees"] {
        match std::fs::remove_file(branch_dir.join(f)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(bulk_io(e)),
            _ => {}
        }
    }
    let sql = branch_dir.join("sql");
    if sql.exists() {
        std::fs::remove_dir_all(&sql).map_err(bulk_io)?;
    }
    sync_parent(&state)?;
    std::fs::remove_file(&marker).map_err(bulk_io)?;
    sync_parent(&state)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    //! The applied LSN of an actor database is where its last change was; an
    //! idle actor is complete through any later LSN.

    // A test measures a wait with the wall clock; this is not daemon code.
    #![allow(clippy::disallowed_methods)]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use rusqlite::Connection;

    use super::*;
    use crate::sql::{FileOpener, Limits, SqlPool, TurnOpts};

    /// A store over files in `dir` (`state.db`, `sql/`), as the daemon opens
    /// one, with `actors` registered as SQL actors whose databases have the
    /// given applied LSNs, and the store itself applied through `applied`.
    fn store_with(dir: &Path, applied: Lsn, actors: &[(&str, u64)]) -> Arc<Store> {
        let store = Store::open(
            Connection::open(dir.join("state.db")).unwrap(),
            SqlPool::new(
                Arc::new(FileOpener {
                    root: dir.join("sql"),
                }),
                Limits::default(),
                8,
            ),
        )
        .unwrap();
        for (name, marker) in actors {
            let (kind, key) = name.split_once('/').unwrap();
            store
                .db()
                .conn()
                .execute(
                    "INSERT INTO actors (kind, key, schema_version, first_lsn, last_lsn, turns, sql) \
                     VALUES (?1, ?2, 0, 1, ?3, 1, 1)",
                    rusqlite::params![kind, key, *marker as i64],
                )
                .unwrap();
            let db = store.sql.get(name).unwrap();
            db.lock().unwrap().stamp_applied(*marker).unwrap();
        }
        store
            .db()
            .conn()
            .execute(
                "UPDATE meta SET v = ?1 WHERE k = 'applied_lsn'",
                [applied as i64],
            )
            .unwrap();
        store.applied.set(applied);
        store
    }

    fn marker_of(file: &Path) -> u64 {
        Connection::open(file)
            .unwrap()
            .query_row(
                "SELECT v FROM _kronik_meta WHERE k = 'applied_lsn'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap() as u64
    }

    fn opts() -> TurnOpts {
        TurnOpts {
            seed: [1; 32],
            time_ms: 1,
            default_subject: None,
            migrate: true,
            sql_budget: 1_000_000,
            max_bytes: 0,
        }
    }

    #[test]
    fn an_idle_actor_is_raised_and_nothing_else_is_touched() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(
            dir.path(),
            100,
            &[("a/idle", 5), ("b/recent", 90), ("c/ahead", 150)],
        );
        let hash = store.state_hash().unwrap();
        let out = store.raise_idle_sql(50, 2).unwrap();
        assert_eq!((out.checked, out.raised), (3, 1), "{out:?}");
        assert!(out.blocked.is_empty());
        let applied = |name: &str| {
            let db = store.sql.get(name).unwrap();
            db.lock().unwrap().applied_lsn().unwrap()
        };
        assert_eq!(applied("a/idle"), 100);
        // Above the floor already, so left as it was; never lowered.
        assert_eq!(applied("b/recent"), 90);
        assert_eq!(applied("c/ahead"), 150);
        // What replay starts from is no longer the idle actor's old change.
        assert_eq!(store.replay_from().unwrap(), 90);
        // A second pass has nothing to do.
        assert_eq!(store.raise_idle_sql(50, 2).unwrap().raised, 0);
        // The applied LSN of a database is not state: the hash of the state
        // (which skips `_kronik%`) does not move, so no format changes and a
        // binary without this code reads the raised value as it always did.
        assert_eq!(store.state_hash().unwrap(), hash);
    }

    /// The raise is a WAL frame under `synchronous=NORMAL`, synced only when
    /// the WAL is checkpointed. Retention deletes the log after the raise
    /// returns, so the raise must already be in the database file: a copy of
    /// that file alone (no WAL, as after a power loss) must hold it.
    #[test]
    fn a_raise_is_in_the_database_file_when_it_returns() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), 100, &[("a/idle", 5)]);
        store.raise_idle_sql(50, 64).unwrap();
        let file = actor_file(&dir.path().join("sql"), "a/idle");
        let copy = dir.path().join("only-the-file.db");
        std::fs::copy(&file, &copy).unwrap();
        assert_eq!(marker_of(&copy), 100);
    }

    #[test]
    fn a_database_with_a_turn_open_is_waited_for_and_then_blocks_the_pass() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), 100, &[("a/idle", 5), ("b/idle", 6)]);
        {
            // A turn keeps its savepoint open between its statements.
            let db = store.sql.get("a/idle").unwrap();
            db.lock().unwrap().begin_turn(&opts()).unwrap();
            let out = store.raise_idle_sql(50, 64).unwrap();
            assert_eq!(out.blocked, ["a/idle"], "{out:?}");
            assert_eq!(out.raised, 1, "the other database is raised: {out:?}");
            // The stamp did not slip into the turn: it would be rolled back.
            assert_eq!(db.lock().unwrap().applied_lsn().unwrap(), 5);
            db.lock().unwrap().end_turn(false).unwrap();
        }
        let out = store.raise_idle_sql(50, 64).unwrap();
        assert!(out.blocked.is_empty(), "{out:?}");
        assert_eq!(out.raised, 1);
    }

    #[test]
    fn a_missing_database_blocks_the_pass_and_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), 100, &[("a/idle", 5)]);
        // The pool's connection is dropped with the store; the file goes.
        drop(store);
        let file = actor_file(&dir.path().join("sql"), "a/idle");
        std::fs::remove_file(&file).unwrap();
        let store = Store::open(
            Connection::open(dir.path().join("state.db")).unwrap(),
            SqlPool::new(
                Arc::new(FileOpener {
                    root: dir.path().join("sql"),
                }),
                Limits::default(),
                8,
            ),
        )
        .unwrap();
        let out = store.raise_idle_sql(50, 64).unwrap();
        assert_eq!(out.blocked, ["a/idle"], "{out:?}");
        assert!(!file.exists(), "stamping must not invent an empty database");
    }

    #[test]
    fn snapshot_takes_the_apply_lock_once_per_database_not_for_the_hash() {
        SNAPSHOT_APPLY_LOCK_HOLDS.with(|c| c.set(0));
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), 100, &[("a/idle", 5), ("b/recent", 90)]);
        let snap = dir.path().join("snap");
        let before = store.state_hash().unwrap();
        SNAPSHOT_APPLY_LOCK_HOLDS.with(|c| c.set(0));
        let copy = store.snapshot_to(&snap).unwrap();
        assert_eq!(copy.state_hash, before);
        // LSN read, `state.db`, two actors — never one hold for copy and hash.
        SNAPSHOT_APPLY_LOCK_HOLDS.with(|c| assert_eq!(c.get(), 4));
    }

    static HASH_ENTERED: AtomicBool = AtomicBool::new(false);
    static PROBE_ATTEMPTING: AtomicBool = AtomicBool::new(false);

    fn pause_while_a_probe_takes_the_lock() {
        HASH_ENTERED.store(true, Ordering::Release);
        let start = Instant::now();
        while !PROBE_ATTEMPTING.load(Ordering::Acquire) {
            if start.elapsed() > Duration::from_secs(2) {
                panic!("the apply-lock probe did not start");
            }
            std::thread::yield_now();
        }
        // Longer than the bound below: a lock held across this pause fails the check.
        std::thread::sleep(Duration::from_millis(400));
    }

    /// Issue #163: an integrity state hash must not hold the apply lock across
    /// the hash or an actor-database copy. Another thread takes the lock during
    /// a pause in that section; a hold across the pause exceeds the bound.
    #[test]
    fn state_hash_does_not_hold_the_apply_lock_across_the_hash() {
        HASH_ENTERED.store(false, Ordering::Release);
        PROBE_ATTEMPTING.store(false, Ordering::Release);
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), 100, &[("a/idle", 5), ("b/recent", 90)]);
        let snap = dir.path().join("snap");
        let copy = store.snapshot_to(&snap).unwrap();
        let acquires = crate::apply_lock_acquires();
        STATE_HASH_HOOK.with(|c| c.set(Some(pause_while_a_probe_takes_the_lock)));
        let probed = Arc::clone(&store);
        let probe = std::thread::spawn(move || {
            let start = Instant::now();
            while !HASH_ENTERED.load(Ordering::Acquire) {
                if start.elapsed() > Duration::from_secs(2) {
                    panic!("state hash never reached the unlocked section");
                }
                std::thread::yield_now();
            }
            PROBE_ATTEMPTING.store(true, Ordering::Release);
            let t = Instant::now();
            let _held = probed.apply_lock();
            t.elapsed()
        });
        let hash = store.state_hash().unwrap();
        assert_eq!(
            crate::apply_lock_acquires(),
            acquires,
            "state hash took the apply lock"
        );
        let waited = probe.join().unwrap();
        assert!(
            waited < Duration::from_millis(250),
            "apply lock held for {waited:?} during the state hash"
        );
        assert_eq!(hash, copy.state_hash);
        let left = std::fs::read_dir(dir.path().join("sql"))
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(HASH_COPY_PREFIX)
            });
        assert!(!left, "a hash copy was left under sql/");
    }

    #[test]
    fn an_in_memory_state_hash_does_not_take_the_apply_lock() {
        let store = Store::memory().unwrap();
        let acquires = crate::apply_lock_acquires();
        let _ = store.state_hash().unwrap();
        assert_eq!(crate::apply_lock_acquires(), acquires);
    }

    #[test]
    fn an_open_turn_is_not_part_of_the_state_hash() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), 100, &[("a/idle", 5)]);
        let before = store.state_hash().unwrap();
        {
            let db = store.sql.get("a/idle").unwrap();
            let mut db = db.lock().unwrap();
            db.begin_turn(&opts()).unwrap();
            db.query("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)", &[])
                .unwrap();
            db.query("INSERT INTO t VALUES (1, 'open')", &[]).unwrap();
        }
        assert_eq!(store.state_hash().unwrap(), before);
        store
            .sql
            .get("a/idle")
            .unwrap()
            .lock()
            .unwrap()
            .end_turn(false)
            .unwrap();
        assert_eq!(store.state_hash().unwrap(), before);
    }

    #[test]
    fn sweep_removes_an_integrity_hash_staging_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sql = dir.path().join("sql");
        let staging = sql.join(format!("{HASH_COPY_PREFIX}crash"));
        std::fs::create_dir_all(staging.join("sql/ab")).unwrap();
        std::fs::write(staging.join("state.db"), b"rows").unwrap();
        let xx = sql.join("ab");
        std::fs::create_dir_all(&xx).unwrap();
        let leftover = xx.join(format!("{HASH_COPY_PREFIX}actor.db.tmp"));
        std::fs::write(&leftover, b"rows").unwrap();
        assert_eq!(sweep_hash_copies(&sql).unwrap(), 2);
        assert!(!staging.exists());
        assert!(!leftover.exists());
    }

    #[test]
    fn install_carries_the_cut_to_every_database_and_leaves_the_snapshot_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), 100, &[("a/idle", 5), ("b/recent", 90)]);
        let snap = dir.path().join("snap");
        store.snapshot_to(&snap).unwrap();
        drop(store);
        let branch = dir.path().join("restored");
        std::fs::create_dir_all(&branch).unwrap();
        install(&snap, &branch).unwrap();
        let sql = branch.join("sql");
        assert_eq!(marker_of(&actor_file(&sql, "a/idle")), 100);
        assert_eq!(marker_of(&actor_file(&sql, "b/recent")), 100);
        // The snapshot's own copies keep what they had (its manifest hashes them).
        let theirs = snap.join("sql");
        assert_eq!(marker_of(&actor_file(&theirs, "a/idle")), 5);
        assert_eq!(marker_of(&actor_file(&theirs, "b/recent")), 90);
        // And the installed directory starts from the cut.
        let markers = read_markers(&branch, false, Some(50)).unwrap().unwrap();
        assert_eq!(
            (markers.state, markers.lowest, markers.unread),
            (100, 100, 0)
        );
    }

    #[test]
    fn the_markers_read_before_the_store_opens_are_the_ones_replay_from_gives() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), 100, &[("a/idle", 5), ("b/recent", 90)]);
        let replay_from = store.replay_from().unwrap();
        // A running daemon holds its databases exclusively: a read-only look
        // reads them from a private copy and does not wait.
        let started = std::time::Instant::now();
        let seen = read_markers(dir.path(), true, Some(50)).unwrap().unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        // The store holds both databases exclusively, and the applied LSN may
        // live only in the WAL. The read-only look must still see it, without
        // waiting or taking the lock.
        assert_eq!(
            (seen.state, seen.lowest, seen.unread),
            (100, replay_from, 0),
            "{seen:?}"
        );
        drop(store);
        let seen = read_markers(dir.path(), false, Some(50)).unwrap().unwrap();
        assert_eq!(
            (seen.state, seen.lowest, seen.unread),
            (100, replay_from, 0)
        );
        assert_eq!(replay_from, 5);
        // A file that is not a database cannot be copied into a readable
        // applied LSN. It is not treated as current.
        let idle = actor_file(&dir.path().join("sql"), "a/idle");
        std::fs::remove_file(&idle).unwrap();
        std::fs::create_dir(&idle).unwrap();
        let seen = read_markers(dir.path(), true, Some(50)).unwrap().unwrap();
        assert_eq!(seen.unread, 1, "{seen:?}");
        // A missing file counts 0. An unreadable one must not: `b/recent`
        // is still 90, and the idle file is not folded in as current either.
        assert_eq!(seen.lowest, 90, "{seen:?}");
        // They are not read when they cannot matter: a log from LSN 1 (or no
        // log yet), or a state.db that is behind the log by itself.
        for first in [None, Some(1), Some(102)] {
            let seen = read_markers(dir.path(), false, first).unwrap().unwrap();
            assert_eq!((seen.state, seen.lowest), (100, 100), "{first:?}");
        }
        // No state.db: nothing to read.
        let empty = tempfile::tempdir().unwrap();
        assert!(
            read_markers(empty.path(), false, Some(50))
                .unwrap()
                .is_none()
        );
    }

    fn applied_of(file: &Path) -> i64 {
        Connection::open(file)
            .unwrap()
            .query_row("SELECT v FROM meta WHERE k = 'applied_lsn'", [], |r| {
                r.get(0)
            })
            .unwrap()
    }

    /// A live branch at applied LSN 7, a snapshot of the same store at 100,
    /// and a write-ahead log that must not be replayed into the replacement.
    fn live_and_snapshot() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), 100, &[("a/idle", 5)]);
        let snap = dir.path().join("snap");
        store.snapshot_to(&snap).unwrap();
        drop(store);
        let conn = Connection::open(dir.path().join("state.db")).unwrap();
        conn.execute("UPDATE meta SET v = 7 WHERE k = 'applied_lsn'", [])
            .unwrap();
        // In the file, not only a WAL the next line replaces.
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
        drop(conn);
        std::fs::write(dir.path().join("state.db-wal"), b"old-wal").unwrap();
        (dir, snap)
    }

    /// Issue #218: the copy can fail before the directory fsync. The previous
    /// `state.db` is still the live one, including its write-ahead log.
    #[test]
    fn a_failed_directory_fsync_leaves_the_previous_state_db() {
        let (dir, snap) = live_and_snapshot();
        let branch = dir.path();
        let before = std::fs::read(branch.join("state.db")).unwrap();
        let actor = actor_file(&branch.join("sql"), "a/idle");
        let marker = marker_of(&actor);
        let _fail = super::FailInstallDirSync::arm();
        let err = install(&snap, branch).unwrap_err();
        assert!(
            err.to_string()
                .contains("injected failure before directory fsync"),
            "{err}"
        );
        assert_eq!(std::fs::read(branch.join("state.db")).unwrap(), before);
        assert_eq!(
            std::fs::read(branch.join("state.db-wal")).unwrap(),
            b"old-wal"
        );
        assert_eq!(marker_of(&actor), marker);
        assert!(!branch.join(".snapshot-install").exists());
    }

    /// The installed files and their directories are fsynced before `install`
    /// returns, and the old write-ahead log is not left beside the new file.
    /// The actor cut is in the database file, not only a WAL.
    #[test]
    fn install_fsyncs_the_replacement_before_it_replaces_the_live_tree() {
        let (dir, snap) = live_and_snapshot();
        let branch = dir.path();
        install(&snap, branch).unwrap();
        assert!(!branch.join("state.db-wal").exists());
        assert!(!branch.join("state.db-shm").exists());
        assert_eq!(applied_of(&branch.join("state.db")), 100);
        assert!(!branch.join(".snapshot-install").exists());
        assert!(!branch.join(".snapshot-install-old").exists());
        let actor = actor_file(&branch.join("sql"), "a/idle");
        let only = branch.join("only-the-file.db");
        std::fs::copy(&actor, &only).unwrap();
        assert_eq!(marker_of(&only), 100);

        let syncs = super::install_syncs();
        let staged_state = branch.join(".snapshot-install/state.db");
        let staged_actor = branch.join(".snapshot-install").join(
            actor_file(&snap.join("sql"), "a/idle")
                .strip_prefix(&snap)
                .unwrap(),
        );
        let state_at = syncs.iter().position(|p| p == &staged_state);
        let actor_at = syncs.iter().position(|p| p == &staged_actor);
        let actor_dir = syncs
            .iter()
            .position(|p| p == staged_actor.parent().unwrap());
        let dir_at = syncs.iter().rposition(|p| p == branch);
        assert!(
            state_at.is_some() && actor_at.is_some() && actor_dir.is_some() && dir_at.is_some(),
            "{syncs:?}"
        );
        let (state_at, actor_at, actor_dir, dir_at) = (
            state_at.unwrap(),
            actor_at.unwrap(),
            actor_dir.unwrap(),
            dir_at.unwrap(),
        );
        assert!(
            actor_at < actor_dir && state_at < dir_at && actor_dir < dir_at,
            "{syncs:?}"
        );
    }

    #[test]
    fn an_interrupted_install_keeps_one_actor_tree_and_drops_the_stage() {
        let dir = tempfile::tempdir().unwrap();
        let branch = dir.path();
        std::fs::write(branch.join("state.db"), b"live-state").unwrap();
        let sql = branch.join("sql/ab");
        std::fs::create_dir_all(&sql).unwrap();
        std::fs::write(sql.join("actor.db"), b"live-rows").unwrap();
        std::fs::rename(branch.join("sql"), branch.join(".snapshot-install-old")).unwrap();
        let stage = branch.join(".snapshot-install/sql/ab");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("actor.db"), b"staged-rows").unwrap();

        recover_interrupted_install(branch).unwrap();
        assert_eq!(
            std::fs::read(branch.join("sql/ab/actor.db")).unwrap(),
            b"live-rows"
        );
        assert_eq!(
            std::fs::read(branch.join("state.db")).unwrap(),
            b"live-state"
        );
        assert!(!branch.join(".snapshot-install-old").exists());
        assert!(!branch.join(".snapshot-install").exists());

        std::fs::create_dir_all(branch.join(".snapshot-install-old")).unwrap();
        std::fs::write(branch.join(".snapshot-install-old/leftover"), b"old").unwrap();
        recover_interrupted_install(branch).unwrap();
        assert!(branch.join("sql/ab/actor.db").exists());
        assert!(!branch.join(".snapshot-install-old").exists());
    }
}
