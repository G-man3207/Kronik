//! Per-actor SQL state (ADR 0005): one SQLite database per actor, changes
//! captured as per-subject changesets and applied after the turn record is
//! durable.

mod actor;
mod ffi;
mod rewrite;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex};

pub use actor::{
    FileOpener, Limits, MemOpener, Rows, SqlActor, SqlError, SqlResult, SqliteOpener, TableRows,
    TurnOpts, TurnSql, actor_file, canonical_hash_raw,
};
pub(crate) use ffi::{CowShare, arm_cow_vfs, cow_vfs_name, serialize_main};
pub use rewrite::pseudonymize_changeset;

use rusqlite::types::Value;

/// One decoded row change of a changeset (behavior diffs).
#[derive(Debug, Clone, PartialEq)]
pub struct RowChange {
    pub table: String,
    /// `insert`, `update` or `delete`.
    pub op: &'static str,
    /// The primary-key values (from the new row for an insert).
    pub pk: Vec<Value>,
    /// Old values (update and delete; `None` for unchanged columns).
    pub old: Vec<Option<Value>>,
    /// New values (insert and update; `None` for unchanged columns).
    pub new: Vec<Option<Value>>,
}

fn value_of(v: ffi::Val) -> Value {
    match v {
        ffi::Val::Null => Value::Null,
        ffi::Val::Int(i) => Value::Integer(i),
        ffi::Val::Real(r) => Value::Real(r),
        ffi::Val::Text(t) => Value::Text(t),
        ffi::Val::Blob(b) => Value::Blob(b),
    }
}

/// Decodes a changeset into row changes, in changeset order.
pub fn changeset_rows(cs: &[u8]) -> Result<Vec<RowChange>, String> {
    let changes = ffi::changes(cs).map_err(|e| e.to_string())?;
    Ok(changes
        .into_iter()
        .map(|c| {
            let op = match c.op {
                ffi::Op::Insert => "insert",
                ffi::Op::Update => "update",
                ffi::Op::Delete => "delete",
            };
            let key_row = if op == "insert" { &c.new } else { &c.old };
            let pk =
                c.pk.iter()
                    .zip(key_row)
                    .filter(|(is_pk, _)| **is_pk)
                    .map(|(_, v)| v.clone().map_or(Value::Null, value_of))
                    .collect();
            RowChange {
                table: c.table,
                op,
                pk,
                old: c.old.into_iter().map(|v| v.map(value_of)).collect(),
                new: c.new.into_iter().map(|v| v.map(value_of)).collect(),
            }
        })
        .collect())
}

/// Open actor databases. Past `capacity`, the least recently used connection
/// that no caller holds is closed. The live pool ([`SqlPool::for_node`]) grows
/// that cap with the actors opened (ADR 0156). A miss opens outside this
/// mutex: one actor's `open` does not stall another's `get`.
pub struct SqlPool {
    opener: Arc<dyn SqliteOpener>,
    limits: Limits,
    inner: Mutex<PoolInner>,
    /// Wakes a `get` waiting on another thread's open of the same actor.
    cv: Condvar,
}

#[derive(Default)]
struct PoolInner {
    tick: u64,
    capacity: usize,
    /// Grow `capacity` with the actors opened, up to this. `None` keeps the
    /// constructed capacity and evicts past it.
    retain_max: Option<usize>,
    open: HashMap<String, (u64, Arc<Mutex<SqlActor>>)>,
    /// Actors with an overlay savepoint, while an overlay is active.
    overlay: Option<std::collections::BTreeSet<String>>,
    /// Actors whose database is being opened outside this mutex.
    opening: HashSet<String>,
}

fn overlay_err(e: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
        Some(format!("overlay savepoint: {e}")),
    )
}

/// Soft `Max open files`, or 1024 when `/proc` cannot be read. Parsing the
/// file keeps `getrlimit` out of this crate: `unsafe` is denied here.
fn open_file_soft_limit() -> usize {
    let Ok(text) = std::fs::read_to_string("/proc/self/limits") else {
        return 1024;
    };
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("Max open files") else {
            continue;
        };
        let Some(soft) = rest.split_whitespace().next() else {
            continue;
        };
        if soft == "unlimited" {
            return 1 << 20;
        }
        if let Ok(n) = soft.parse() {
            return n;
        }
    }
    1024
}

/// Actors the live pool may keep. Two descriptors each (the database and its
/// WAL). Leave 1024 for the log, `state.db` and the listeners the open-file
/// budget already counts, and at least the old 256.
fn live_pool_cap() -> usize {
    let spare = open_file_soft_limit().saturating_sub(1024) / 2;
    spare.max(256)
}

impl SqlPool {
    pub fn new(opener: Arc<dyn SqliteOpener>, limits: Limits, capacity: usize) -> SqlPool {
        SqlPool {
            opener,
            limits,
            inner: Mutex::new(PoolInner {
                capacity: capacity.max(1),
                ..PoolInner::default()
            }),
            cv: Condvar::new(),
        }
    }

    /// The live node's pool: 256 connections, growing with the actors opened
    /// until two descriptors per actor would leave fewer than 1024 (ADR 0156).
    pub fn for_node(opener: Arc<dyn SqliteOpener>, limits: Limits) -> SqlPool {
        let pool = SqlPool::new(opener, limits, 256);
        pool.retain_opened(live_pool_cap());
        pool
    }

    /// Keep every actor this pool opens, up to `max`. The constructed
    /// capacity stays the floor. A later call only raises the ceiling.
    pub(crate) fn retain_opened(&self, max: usize) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let max = max.max(g.capacity);
        g.retain_max = Some(g.retain_max.map_or(max, |had| had.max(max)));
    }

    /// The database of `actor` ("kind/key"), opened (and created) on demand.
    pub fn get(&self, actor: &str) -> rusqlite::Result<Arc<Mutex<SqlActor>>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            g.tick += 1;
            let tick = g.tick;
            if let Some((t, a)) = g.open.get_mut(actor) {
                *t = tick;
                let a = a.clone();
                self.finish(&mut g, actor, &a)?;
                return Ok(a);
            }
            if g.opening.contains(actor) {
                g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
                continue;
            }
            g.opening.insert(actor.to_owned());
            break;
        }
        drop(g);

        // Exclusive locking: a second open of the same file blocks until the
        // first connection closes. `opening` lets only one thread reach here.
        #[cfg(test)]
        assert!(
            !crate::apply_lock_held(),
            "SQL open of {actor} ran under the apply lock"
        );
        let opened = SqlActor::open(self.opener.as_ref(), actor, self.limits);

        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.opening.remove(actor);
        let a = match opened {
            Ok(db) => {
                g.tick += 1;
                let tick = g.tick;
                if let Some((t, existing)) = g.open.get_mut(actor) {
                    *t = tick;
                    existing.clone()
                } else {
                    let a = Arc::new(Mutex::new(db));
                    g.open.insert(actor.to_owned(), (tick, a.clone()));
                    a
                }
            }
            Err(e) => {
                self.cv.notify_all();
                return Err(e);
            }
        };
        self.cv.notify_all();
        self.finish(&mut g, actor, &a)?;
        Ok(a)
    }

    fn finish(
        &self,
        g: &mut PoolInner,
        actor: &str,
        a: &Arc<Mutex<SqlActor>>,
    ) -> rusqlite::Result<()> {
        if let Some(touched) = g.overlay.as_mut()
            && touched.insert(actor.to_owned())
        {
            a.lock()
                .unwrap_or_else(|e| e.into_inner())
                .overlay_begin()
                .map_err(overlay_err)?;
        }
        evict(g);
        Ok(())
    }

    /// Starts an overlay: every database used until `overlay_rollback`
    /// gets a savepoint that is rolled back then.
    pub fn overlay_begin(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).overlay =
            Some(std::collections::BTreeSet::new());
    }

    pub fn overlay_rollback(&self) -> Result<(), String> {
        let open: Vec<Arc<Mutex<SqlActor>>> = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let touched = g.overlay.take().unwrap_or_default();
            touched
                .iter()
                .filter_map(|k| g.open.get(k).map(|(_, a)| a.clone()))
                .collect()
        };
        for a in open {
            a.lock()
                .unwrap_or_else(|e| e.into_inner())
                .overlay_rollback()?;
        }
        Ok(())
    }

    /// Whether `actor` has a database (open or on disk) without creating one.
    pub fn exists(&self, actor: &str) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.open.contains_key(actor) || self.opener.exists(actor)
    }

    /// A crash of the process that keeps the databases: every turn in
    /// progress is rolled back, as SQLite does when a connection dies.
    pub fn abort_turns(&self) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for (_, db) in g.open.values() {
            db.lock().unwrap_or_else(|e| e.into_inner()).abort_turn();
        }
    }

    /// Actors whose turn still has its savepoint open. Erasure must open
    /// these so the delete is deferred until the turn ends (#196). Names
    /// only: this does not create a database.
    pub(crate) fn open_sessions(&self) -> Vec<String> {
        let open: Vec<_> = {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.open
                .iter()
                .map(|(name, (_, db))| (name.clone(), db.clone()))
                .collect()
        };
        open.into_iter()
            .filter(|(_, db)| db.lock().unwrap_or_else(|e| e.into_inner()).has_session())
            .map(|(name, _)| name)
            .collect()
    }

    /// Drops every open connection (simulated crash, shutdown).
    pub fn close_all(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .open
            .clear();
    }
}

fn evict(g: &mut PoolInner) {
    if let Some(max) = g.retain_max
        && g.open.len() > g.capacity
    {
        g.capacity = g.open.len().min(max).max(g.capacity);
    }
    if g.open.len() <= g.capacity || g.overlay.is_some() {
        return;
    }
    let mut idle: Vec<(u64, String)> = g
        .open
        .iter()
        .filter(|(_, (_, a))| Arc::strong_count(a) == 1)
        .map(|(k, (t, _))| (*t, k.clone()))
        .collect();
    idle.sort_unstable();
    let excess = g.open.len() - g.capacity;
    for (_, k) in idle.into_iter().take(excess) {
        g.open.remove(&k);
    }
}

#[cfg(test)]
mod tests;
