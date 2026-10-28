//! Per-actor SQL state (ADR 0005): one SQLite database per actor, changes
//! captured as per-subject changesets and applied after the turn record is
//! durable.

mod actor;
mod ffi;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub use actor::{
    FileOpener, Limits, MemOpener, Rows, SqlActor, SqlError, SqlResult, SqliteOpener, TableRows,
    TurnOpts, TurnSql, actor_file, canonical_hash_raw,
};

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

/// Open actor databases, least recently used evicted beyond `capacity`
/// (only when no turn holds them).
pub struct SqlPool {
    opener: Arc<dyn SqliteOpener>,
    limits: Limits,
    capacity: usize,
    inner: Mutex<PoolInner>,
}

#[derive(Default)]
struct PoolInner {
    tick: u64,
    open: HashMap<String, (u64, Arc<Mutex<SqlActor>>)>,
    /// Actors with an overlay savepoint, while an overlay is active.
    overlay: Option<std::collections::BTreeSet<String>>,
}

impl SqlPool {
    pub fn new(opener: Arc<dyn SqliteOpener>, limits: Limits, capacity: usize) -> SqlPool {
        SqlPool {
            opener,
            limits,
            capacity: capacity.max(1),
            inner: Mutex::new(PoolInner::default()),
        }
    }

    /// The database of `actor` ("kind/key"), opened (and created) on demand.
    pub fn get(&self, actor: &str) -> rusqlite::Result<Arc<Mutex<SqlActor>>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.tick += 1;
        let tick = g.tick;
        let a = if let Some((t, a)) = g.open.get_mut(actor) {
            *t = tick;
            a.clone()
        } else {
            let a = Arc::new(Mutex::new(SqlActor::open(
                self.opener.as_ref(),
                actor,
                self.limits,
            )?));
            g.open.insert(actor.to_owned(), (tick, a.clone()));
            a
        };
        if let Some(touched) = g.overlay.as_mut()
            && touched.insert(actor.to_owned())
        {
            a.lock()
                .unwrap_or_else(|e| e.into_inner())
                .overlay_begin()
                .map_err(|e| {
                    rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                        Some(format!("overlay savepoint: {e}")),
                    )
                })?;
        }
        if g.open.len() > self.capacity && g.overlay.is_none() {
            let mut idle: Vec<(u64, String)> = g
                .open
                .iter()
                .filter(|(_, (_, a))| Arc::strong_count(a) == 1)
                .map(|(k, (t, _))| (*t, k.clone()))
                .collect();
            idle.sort_unstable();
            let excess = g.open.len() - self.capacity;
            for (_, k) in idle.into_iter().take(excess) {
                g.open.remove(&k);
            }
        }
        Ok(a)
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

    /// Drops every open connection (simulated crash, shutdown).
    pub fn close_all(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .open
            .clear();
    }
}

#[cfg(test)]
mod tests;
