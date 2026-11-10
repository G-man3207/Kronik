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
    "secret_versions",
    "secret_highwater",
    "secret_format",
    "secret_links",
    "secret_link_history",
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
    stamp_installed(snapshot, &sql)
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
    /// Actor databases that could not be read. Only in read-only mode, where
    /// a running daemon's exclusive lock refuses the read.
    pub unread: usize,
}

/// The [`Markers`] of `branch_dir`, or `None` when it has no `state.db`.
/// `log_first` is the first LSN the log holds: while it is 1 no database can
/// be behind it, and when `state.db` itself is behind it the start installs
/// a snapshot whatever the actor databases say, so in both cases they are not
/// read (`lowest` is then `state`) and a start that has nothing to repair
/// opens nothing extra. Read-only mode (`kronik upgrade check`, which may run
/// beside a daemon) counts a database it cannot read instead of waiting for
/// it or failing.
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
        let read = Connection::open_with_flags(&file, flags).and_then(|c| {
            c.busy_timeout(std::time::Duration::ZERO)?;
            c.query_row(
                "SELECT v FROM _kronik_meta WHERE k = 'applied_lsn'",
                [],
                |r| r.get::<_, i64>(0),
            )
        });
        match read {
            Ok(v) => out.lowest = out.lowest.min(v as Lsn),
            Err(_) if read_only => out.unread += 1,
            Err(e) => return Err(sqlite(e)),
        }
    }
    Ok(Some(out))
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

#[cfg(test)]
mod tests {
    //! The applied LSN of an actor database is where its last change was; an
    //! idle actor is complete through any later LSN.

    // A test measures a wait with the wall clock; this is not daemon code.
    #![allow(clippy::disallowed_methods)]

    use std::sync::Arc;

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
        // counts them and does not wait.
        let started = std::time::Instant::now();
        let seen = read_markers(dir.path(), true, Some(50)).unwrap().unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(seen.unread, 2, "{seen:?}");
        drop(store);
        let seen = read_markers(dir.path(), false, Some(50)).unwrap().unwrap();
        assert_eq!(
            (seen.state, seen.lowest, seen.unread),
            (100, replay_from, 0)
        );
        assert_eq!(replay_from, 5);
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
}
