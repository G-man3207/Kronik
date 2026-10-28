//! Materialized state (`state.db`): derived from the log (I4), applied by a
//! single applier in LSN order, with `applied_lsn` and the logical-time
//! high-water mark written in the same transaction as the changes.
//!
//! Production opens a WAL file with `synchronous=NORMAL` (consistent after a
//! crash, may lose the last commits). The simulator opens an in-memory
//! database and models the same guarantee by snapshotting on commit (see
//! `scenario::DbImages`).

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, params};

use super::log::{Outcome, Record, TurnRecord};

pub type CommitHook = Box<dyn FnMut(&mut Connection) + Send>;

pub struct StateDb {
    conn: Connection,
    on_commit: Option<CommitHook>,
}

/// Saved response for an ingress idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl StateDb {
    pub fn open(conn: Connection, on_commit: Option<CommitHook>) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (actor TEXT NOT NULL, key TEXT NOT NULL, value BLOB NOT NULL, PRIMARY KEY (actor, key));
             CREATE TABLE IF NOT EXISTS ingress_keys (actor TEXT NOT NULL, key TEXT NOT NULL, status INTEGER NOT NULL, body BLOB NOT NULL, lsn INTEGER NOT NULL, PRIMARY KEY (actor, key));
             CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);",
        )?;
        Ok(Self { conn, on_commit })
    }

    fn meta(&self, k: &str) -> rusqlite::Result<u64> {
        let v: Option<i64> = self
            .conn
            .query_row("SELECT v FROM meta WHERE k = ?1", [k], |r| r.get(0))
            .optional()?;
        Ok(v.unwrap_or(0) as u64)
    }

    pub fn applied_lsn(&self) -> rusqlite::Result<u64> {
        self.meta("applied_lsn")
    }

    pub fn time_hwm(&self) -> rusqlite::Result<u64> {
        self.meta("time_hwm")
    }

    pub fn get(&self, actor: &str, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT value FROM kv WHERE actor = ?1 AND key = ?2",
                params![actor, key],
                |r| r.get(0),
            )
            .optional()
    }

    pub fn keys(&self, actor: &str, prefix: &str) -> rusqlite::Result<Vec<String>> {
        let mut st = self
            .conn
            .prepare("SELECT key FROM kv WHERE actor = ?1 ORDER BY key")?;
        let rows = st.query_map([actor], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for k in rows {
            let k = k?;
            if k.starts_with(prefix) {
                out.push(k);
            }
        }
        Ok(out)
    }

    pub fn saved_response(
        &self,
        actor: &str,
        key: &str,
    ) -> rusqlite::Result<Option<SavedResponse>> {
        self.conn
            .query_row(
                "SELECT status, body FROM ingress_keys WHERE actor = ?1 AND key = ?2",
                params![actor, key],
                |r| {
                    Ok(SavedResponse {
                        status: r.get::<_, i64>(0)? as u16,
                        body: r.get(1)?,
                    })
                },
            )
            .optional()
    }

    /// Applies one committed record. Must be called in strictly increasing
    /// LSN order with no gaps; records at or below `applied_lsn` are skipped.
    pub fn apply(&mut self, lsn: u64, rec: &Record) -> rusqlite::Result<bool> {
        if lsn <= self.applied_lsn()? {
            return Ok(false);
        }
        let tx = self.conn.transaction()?;
        let time = match rec {
            Record::TurnBegin(b) => Some(b.time_ms),
            Record::EffectResult(_) => None,
            Record::TurnRecord(t) => {
                apply_turn(&tx, lsn, t)?;
                Some(t.begin.time_ms)
            }
        };
        tx.execute("INSERT INTO meta (k, v) VALUES ('applied_lsn', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1", [lsn as i64])?;
        if let Some(t) = time {
            tx.execute(
                "INSERT INTO meta (k, v) VALUES ('time_hwm', ?1) ON CONFLICT(k) DO UPDATE SET v = max(v, ?1)",
                [t as i64],
            )?;
        }
        tx.commit()?;
        if let Some(hook) = self.on_commit.as_mut() {
            hook(&mut self.conn);
        }
        Ok(true)
    }

    /// Canonical dump for comparisons: every kv row and ingress key, ordered.
    pub fn dump(&self) -> rusqlite::Result<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        let mut st = self
            .conn
            .prepare("SELECT actor, key, value FROM kv ORDER BY actor, key")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (a, k, v) = row?;
            out.insert(
                format!("kv {a} {k}"),
                String::from_utf8_lossy(&v).into_owned(),
            );
        }
        let mut st = self
            .conn
            .prepare("SELECT actor, key, status, body FROM ingress_keys ORDER BY actor, key")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        for row in rows {
            let (a, k, s, b) = row?;
            out.insert(
                format!("ingress {a} {k}"),
                format!("{s} {}", String::from_utf8_lossy(&b)),
            );
        }
        Ok(out)
    }
}

fn apply_turn(tx: &rusqlite::Transaction<'_>, lsn: u64, t: &TurnRecord) -> rusqlite::Result<()> {
    let actor = &t.begin.actor;
    let (status, body) = match &t.outcome {
        Outcome::Ok { status, body } => {
            for (k, v) in &t.writes {
                match v {
                    Some(v) => tx.execute(
                        "INSERT INTO kv (actor, key, value) VALUES (?1, ?2, ?3) ON CONFLICT(actor, key) DO UPDATE SET value = ?3",
                        params![actor, k, v],
                    )?,
                    None => tx.execute("DELETE FROM kv WHERE actor = ?1 AND key = ?2", params![actor, k])?,
                };
            }
            (*status, body.clone())
        }
        Outcome::Failed { code, .. } => (500, code.as_bytes().to_vec()),
    };
    tx.execute(
        "INSERT INTO ingress_keys (actor, key, status, body, lsn) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![actor, t.begin.ingress_key, status as i64, body, lsn as i64],
    )?;
    Ok(())
}
