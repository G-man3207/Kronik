//! Materialized state: `state.db` (actors, key-value state, mailbox, ingress
//! keys, dead letters, deployments) and the per-actor SQL databases. All of
//! it is derived from the log and rebuilt from it after a crash (I4).

pub mod db;
pub mod snapshot;
pub mod sql;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use kronik_core::ids::Lsn;
use kronik_log::Committed;
use kronik_privacy::sealer::Opened;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use tokio::sync::Notify;

pub use db::{CatchupRows, StateDb};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("state.db: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Maps to `STORAGE_CORRUPT`: the materialized state disagrees with the
    /// log (e.g. a changeset conflict).
    #[error("STORAGE_CORRUPT: {0}")]
    Corrupt(String),
}

/// The highest applied LSN, with a wake-up for waiters.
#[derive(Default)]
pub struct AppliedLsn {
    lsn: AtomicU64,
    notify: Notify,
}

impl AppliedLsn {
    pub fn get(&self) -> Lsn {
        self.lsn.load(Ordering::Acquire)
    }

    fn set(&self, lsn: Lsn) {
        self.lsn.store(lsn, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Resolves once `lsn` is applied.
    pub async fn wait(&self, lsn: Lsn) {
        loop {
            let notified = self.notify.notified();
            if self.get() >= lsn {
                return;
            }
            notified.await;
        }
    }
}

/// `state.db` plus the SQL pool of one branch.
pub struct Store {
    db: Mutex<StateDb>,
    pub sql: sql::SqlPool,
    pub applied: AppliedLsn,
    /// Held for a whole `apply` batch, and by snapshots, so a snapshot sees
    /// `state.db` and every actor database at one LSN.
    apply_lock: Mutex<()>,
    /// Reads sealed SQL changesets (docs/design/m8-privacy.md §4, §6);
    /// plain until the node sets its own.
    sealer: Mutex<Arc<kronik_privacy::sealer::Sealer>>,
}

impl Store {
    pub fn open(state: rusqlite::Connection, sql: sql::SqlPool) -> Result<Arc<Store>, StoreError> {
        let db = StateDb::open(state)?;
        let applied = AppliedLsn::default();
        applied.set(db.applied_lsn()?);
        Ok(Arc::new(Store {
            db: Mutex::new(db),
            sql,
            applied,
            apply_lock: Mutex::new(()),
            sealer: Mutex::new(Arc::new(kronik_privacy::sealer::Sealer::plain())),
        }))
    }

    /// The sealer that opens sealed SQL changesets when they are applied.
    pub fn set_sealer(&self, sealer: Arc<kronik_privacy::sealer::Sealer>) {
        *self.sealer.lock().unwrap_or_else(|e| e.into_inner()) = sealer;
    }

    fn sealer(&self) -> Arc<kronik_privacy::sealer::Sealer> {
        self.sealer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Starts an overlay over `state.db` and every actor database used
    /// until `overlay_rollback` (isolated replay).
    pub fn overlay_begin(&self) -> Result<Lsn, StoreError> {
        self.db().overlay_begin()?;
        self.sql.overlay_begin();
        Ok(self.applied.get())
    }

    /// Discards everything applied since `overlay_begin`, which returned
    /// `applied`.
    pub fn overlay_rollback(&self, applied: Lsn) -> Result<(), StoreError> {
        self.sql.overlay_rollback().map_err(StoreError::Corrupt)?;
        self.db().overlay_rollback()?;
        self.applied.lsn.store(applied, Ordering::Release);
        Ok(())
    }

    fn apply_lock(&self) -> MutexGuard<'_, ()> {
        self.apply_lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Read access to `state.db`.
    pub fn db(&self) -> MutexGuard<'_, StateDb> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Applies consecutive durable records: SQL changes to the actor
    /// databases first (each tracks its own applied LSN, so a record is
    /// applied to an actor database at most once even when `state.db` is
    /// ahead or behind it), then `state.db` in one transaction (records at or
    /// below its applied LSN are skipped), then wakes waiters.
    pub fn apply(&self, batch: &[Committed]) -> Result<(), StoreError> {
        let Some(last) = batch.last() else {
            return Ok(());
        };
        let _apply = self.apply_lock();
        for (i, c) in batch.iter().enumerate() {
            match &c.record {
                Record::TurnRecord(t) => self.apply_sql(c.lsn, t)?,
                Record::Erasure(e) => self.erase_sql(c.lsn, &e.subject, &batch[..i])?,
                _ => {}
            }
        }
        self.db().apply(batch)?;
        if batch.iter().any(|c| matches!(c.record, Record::Erasure(_))) {
            self.db().checkpoint();
        }
        self.applied.set(self.applied.get().max(last.lsn));
        Ok(())
    }

    /// Applies [`CatchupRows`] like [`Store::apply`] of their records
    /// (simple turns change no actor database).
    pub fn apply_catchup(&self, rows: CatchupRows) -> Result<(), StoreError> {
        let Some(last) = rows.last_lsn() else {
            return Ok(());
        };
        let _apply = self.apply_lock();
        self.db().apply_rows(rows)?;
        self.applied.set(self.applied.get().max(last));
        Ok(())
    }
    /// Startup catch-up of a long gap (docs/perf.md). Not used by the live
    /// applier. [`Store::end_bulk_replay`] restores the indexes.
    pub fn begin_bulk_replay(&self) -> Result<(), StoreError> {
        self.db().begin_bulk_replay()
    }

    /// Finishes a bulk catch-up: sorted `trees` load and the secondary index.
    pub fn end_bulk_replay(&self) -> Result<(), StoreError> {
        self.db().end_bulk_replay()
    }

    /// Ends a bulk catch-up that failed, keeping its marker so the next
    /// start rebuilds `state.db` ([`StateDb::abort_bulk_replay`]).
    pub fn abort_bulk_replay(&self) -> Result<(), StoreError> {
        self.db().abort_bulk_replay()
    }

    /// The LSN from which the log must be replayed: the lowest applied LSN
    /// of `state.db` and of every actor database it knows about. The
    /// databases commit independently with `synchronous=NORMAL`, so after a
    /// power loss any of them may be behind the others.
    pub fn replay_from(&self) -> Result<Lsn, StoreError> {
        let mut from = self.applied.get();
        let actors = self.db().sql_actors()?;
        for name in actors {
            let db = self.sql.get(&name)?;
            let applied = db.lock().unwrap_or_else(|e| e.into_inner()).applied_lsn()?;
            from = from.min(applied);
        }
        Ok(from)
    }

    fn apply_sql(&self, lsn: Lsn, t: &pb::TurnRecord) -> Result<(), StoreError> {
        let committed = t
            .outcome
            .as_ref()
            .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32);
        if !committed || (t.sql_changes.is_empty() && t.sql_schema.is_empty()) {
            return Ok(());
        }
        let Some(actor) = &t.actor else {
            return Err(StoreError::Corrupt("turn record without actor".into()));
        };
        let name = format!("{}/{}", actor.kind, actor.key);
        let db = self.sql.get(&name)?;
        let mut db = db.lock().unwrap_or_else(|e| e.into_inner());
        if db.applied_lsn()? >= lsn {
            return Ok(());
        }
        let mut changesets = Vec::with_capacity(t.sql_changes.len());
        let mut sealer = None;
        for c in &t.sql_changes {
            let s = match c.changeset.as_ref() {
                Some(pb::Sealable {
                    subject,
                    value: Some(pb::sealable::Value::Plain(b)),
                }) => {
                    changesets.push((subject.clone(), b.clone()));
                    continue;
                }
                Some(s) if s.value.is_some() => s,
                _ => {
                    return Err(StoreError::Corrupt(format!(
                        "turn at lsn {lsn} has an empty SQL changeset"
                    )));
                }
            };
            match sealer.get_or_insert_with(|| self.sealer()).open(s) {
                Opened::Value(b) => changesets.push((s.subject.clone(), b.into_owned())),
                // An erased subject's changes are gone; its Erasure record,
                // later in the log, deletes whatever rows remain (§6.3).
                Opened::Erased { .. } => {}
                Opened::Unreadable { subject, why } => {
                    return Err(StoreError::Corrupt(format!(
                        "turn at lsn {lsn}: the SQL changeset of {subject} cannot be unsealed: {why}"
                    )));
                }
            }
        }
        let turn = sql::TurnSql {
            ddl: t.sql_schema.iter().map(|s| s.statement.clone()).collect(),
            changesets,
            vm_steps: 0,
            whole: Vec::new(),
        };
        db.apply(&turn, lsn, &BTreeSet::new())
            .map_err(|e| StoreError::Corrupt(format!("SQL apply of {name} at lsn {lsn}: {e}")))
    }

    /// The erasure operation on the actor databases (§6.3): every row of
    /// the subject in a table with a `_subject` column is deleted, in every
    /// actor database that has not applied this LSN yet. Replayed on every
    /// rebuild, so a rebuilt database equals the live one. `earlier` is the
    /// batch before the record: state.db, which lists the actor databases,
    /// is applied after them, so the ones these records create are added.
    fn erase_sql(&self, lsn: Lsn, subject: &str, earlier: &[Committed]) -> Result<(), StoreError> {
        let mut actors: BTreeSet<String> = self.db().sql_actors()?.into_iter().collect();
        for c in earlier {
            if let Record::TurnRecord(t) = &c.record
                && (!t.sql_changes.is_empty() || !t.sql_schema.is_empty())
                && let Some(a) = &t.actor
            {
                actors.insert(format!("{}/{}", a.kind, a.key));
            }
        }
        for name in actors {
            let db = self.sql.get(&name)?;
            let mut db = db.lock().unwrap_or_else(|e| e.into_inner());
            if db.applied_lsn()? >= lsn {
                continue;
            }
            db.erase_subject(subject, lsn)
                .map_err(|e| StoreError::Corrupt(format!("erasure in {name} at lsn {lsn}: {e}")))?;
        }
        Ok(())
    }
}
