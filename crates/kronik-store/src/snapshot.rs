//! Snapshots of the materialized state (docs/design/m6-storage.md §2-§3,
//! §8): consistent copies of `state.db` and every actor database at one
//! LSN, their installation, and the state hash.

use std::path::{Path, PathBuf};

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
    "deployments",
    "kinds",
    "config_records",
    "policies",
    "approvals",
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
fn hash_tables(conn: &Connection, tables: &[&str], h: &mut blake3::Hasher) -> rusqlite::Result<()> {
    for t in tables {
        let cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?
            .query_map([t], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if cols.is_empty() {
            continue;
        }
        let order = (1..=cols.len())
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let mut st = conn.prepare(&format!("SELECT * FROM \"{t}\" ORDER BY {order}"))?;
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
/// The caller holds the apply lock, so what is committed is the applied
/// state: an actor turn's `SAVEPOINT kronik_turn` is always rolled back,
/// and its changeset is applied under that lock. `VACUUM INTO` refuses to
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
}

impl Store {
    /// Copies `state.db` and every actor database at the applied LSN into
    /// `dir` (created), holding the apply lock so all copies are at the
    /// same LSN. Also computes the state hash at that LSN: of the actor
    /// databases from their copies, since a running turn's open savepoint
    /// shows its rows on the live connection (v0.1 re-review R1).
    pub fn snapshot_to(&self, dir: &Path) -> Result<SnapshotCopy, StoreError> {
        let _apply = self.apply_lock();
        let lsn = self.applied.get();
        std::fs::create_dir_all(dir.join("sql")).map_err(io)?;
        let mut files = vec![PathBuf::from("state.db")];
        self.db().backup_to(&dir.join("state.db"))?;
        let mut h = blake3::Hasher::new();
        hash_tables(self.db().conn(), HASHED_TABLES, &mut h).map_err(sqlite)?;
        let actors = self.db().sql_actors()?;
        for name in &actors {
            let rel = actor_file(Path::new("sql"), name);
            if let Some(parent) = dir.join(&rel).parent() {
                std::fs::create_dir_all(parent).map_err(io)?;
            }
            let db = self.sql.get(name)?;
            db.lock()
                .unwrap_or_else(|e| e.into_inner())
                .backup_to(&dir.join(&rel))?;
            let copy = Connection::open(dir.join(&rel)).map_err(sqlite)?;
            let hash = crate::sql::canonical_hash_raw(&copy).map_err(sqlite)?;
            h.update(format!("sql|{name}|{hash}\n").as_bytes());
            files.push(rel);
        }
        let state_hash = format!("b3:{}", h.finalize().to_hex());
        Ok(SnapshotCopy {
            lsn,
            state_hash,
            files,
        })
    }

    /// The state hash (m6-storage §8) at the applied LSN.
    pub fn state_hash(&self) -> Result<String, StoreError> {
        let _apply = self.apply_lock();
        self.state_hash_locked()
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

/// The subject keys the snapshot's state needs ([`crate::db::sealed_keys`]),
/// read without changing the snapshot.
pub fn sealed_keys(snapshot: &Path) -> Result<crate::db::SubjectKeys, StoreError> {
    let conn = rusqlite::Connection::open_with_flags(
        snapshot.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    crate::db::sealed_keys(&conn)
}

/// Installs a snapshot directory as a branch's state: `state.db` and the
/// actor databases are copied into `branch_dir` (`state.db`, `sql/`),
/// replacing what is there. The daemon must not run on it.
pub fn install(snapshot: &Path, branch_dir: &Path) -> Result<(), StoreError> {
    let sql = branch_dir.join("sql");
    if sql.exists() {
        std::fs::remove_dir_all(&sql).map_err(io)?;
    }
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let p = branch_dir.join(f);
        if p.exists() {
            std::fs::remove_file(&p).map_err(io)?;
        }
    }
    std::fs::create_dir_all(&sql).map_err(io)?;
    std::fs::copy(snapshot.join("state.db"), branch_dir.join("state.db")).map_err(io)?;
    copy_tree(&snapshot.join("sql"), &sql)?;
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), StoreError> {
    if !from.exists() {
        return Ok(());
    }
    for e in std::fs::read_dir(from).map_err(io)? {
        let e = e.map_err(io)?;
        let dest = to.join(e.file_name());
        if e.file_type().map_err(io)?.is_dir() {
            std::fs::create_dir_all(&dest).map_err(io)?;
            copy_tree(&e.path(), &dest)?;
        } else {
            std::fs::copy(e.path(), &dest).map_err(io)?;
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
/// left under the actor databases' directory `sql` (`sql/<xx>/`). They hold
/// an actor's rows, which an erasure would not reach. Returns how many.
pub fn sweep_hash_copies(sql: &Path) -> Result<usize, StoreError> {
    let mut swept = 0;
    let Ok(dirs) = std::fs::read_dir(sql) else {
        return Ok(0);
    };
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir.map_err(io)?.path()) else {
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
            if e.file_type().map_err(io)?.is_dir() {
                std::fs::remove_dir_all(e.path()).map_err(io)?;
            } else {
                std::fs::remove_file(e.path()).map_err(io)?;
            }
            swept += 1;
        }
    }
    Ok(swept)
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
