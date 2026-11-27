//! Materialized state: `state.db` (actors, key-value state, mailbox, ingress
//! keys, dead letters, deployments) and the per-actor SQL databases. All of
//! it is derived from the log and rebuilt from it after a crash (I4).

pub mod db;
pub mod rebase;
pub mod ship_blobs;
pub mod snapshot;
pub mod sql;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use kronik_core::ids::Lsn;
use kronik_core::sync::lock;
use kronik_log::Committed;
use kronik_privacy::sealer::Opened;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use tokio::sync::Notify;

pub use db::{CatchupRows, StateDb};

#[cfg(test)]
thread_local! {
    /// Test hook: a rebase switch fails right after an actor database's
    /// copy, like a crash there.
    pub(crate) static CRASH_AFTER_COPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static APPLY_LOCK_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static APPLY_LOCK_ACQUIRES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Actor WAL checkpoints after an erasure. A test asserts this moved.
    pub(crate) static ACTOR_ERASURE_CHECKPOINTS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static APPLY_LOCK_ENTER: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
    static APPLY_LOCK_HOLD_NS: std::cell::Cell<u128> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn apply_lock_held() -> bool {
    APPLY_LOCK_DEPTH.with(|c| c.get() > 0)
}

/// Asserts that `sql`, with `arg` bound to `?1`, uses an index and scans
/// no table.
#[cfg(test)]
#[track_caller]
pub(crate) fn assert_search(conn: &rusqlite::Connection, sql: &str, arg: impl rusqlite::ToSql) {
    let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let plan: Vec<String> = st
        .query_map([arg], |r| r.get(3))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        plan.iter().any(|d| d.starts_with("SEARCH ")),
        "{sql} has no indexed lookup: {plan:?}"
    );
    assert!(
        plan.iter().all(|d| !d.starts_with("SCAN ")),
        "{sql} scans: {plan:?}"
    );
}

/// How many times this thread has taken the apply lock. A state-hash test
/// asserts an integrity request does not add to it.
#[cfg(test)]
pub(crate) fn apply_lock_acquires() -> usize {
    APPLY_LOCK_ACQUIRES.with(|c| c.get())
}

/// How long this thread has held the apply lock since the last take.
/// Test instrumentation only: daemon time comes from `Env::clock`.
#[cfg(test)]
pub(crate) fn take_apply_lock_hold() -> std::time::Duration {
    let ns = APPLY_LOCK_HOLD_NS.with(|c| c.replace(0));
    std::time::Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
}

/// A [`Committed`] record at `lsn` in a test log segment.
#[cfg(test)]
pub(crate) fn committed(lsn: Lsn, record: Record) -> Committed {
    Committed {
        lsn,
        pos: kronik_log::Position {
            segment: 0,
            offset: 0,
        },
        record,
    }
}

/// A committed `notes` SQL turn that runs `statement`.
#[cfg(test)]
pub(crate) fn sql_turn(lsn: Lsn, key: &str, statement: &str) -> Committed {
    committed(
        lsn,
        Record::TurnRecord(pb::TurnRecord {
            actor: Some(pb::ActorRef {
                kind: "notes".into(),
                key: key.into(),
            }),
            causal_key: Some(kronik_core::causal::root(format!("r{lsn}"))),
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Http(pb::HttpInput::default())),
            }),
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                ..Default::default()
            }),
            sql_schema: vec![pb::SqlSchemaChange {
                statement: statement.into(),
            }],
            ..Default::default()
        }),
    )
}

/// A [`Store`] over files in `dir` (`state.db`, `sql/`), as the daemon opens
/// one, with room for `capacity` actor databases.
#[cfg(test)]
pub(crate) fn file_store(dir: &std::path::Path, capacity: usize) -> Arc<Store> {
    Store::open(
        rusqlite::Connection::open(dir.join("state.db")).unwrap(),
        crate::sql::SqlPool::new(
            Arc::new(crate::sql::FileOpener {
                root: dir.join("sql"),
            }),
            capacity,
        ),
    )
    .unwrap()
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
fn mark_lock_enter() {
    APPLY_LOCK_ENTER.with(|c| c.set(Some(std::time::Instant::now())));
}

#[cfg(test)]
fn mark_lock_exit() {
    let Some(start) = APPLY_LOCK_ENTER.with(std::cell::Cell::take) else {
        return;
    };
    let elapsed = start.elapsed().as_nanos();
    APPLY_LOCK_HOLD_NS.with(|c| c.set(c.get().saturating_add(elapsed)));
}

/// The apply lock. Dropping it publishes the even epoch a state-hash copy
/// waits for, and in tests clears the depth a checkpoint asserts.
pub(crate) struct ApplyLock<'a> {
    _guard: MutexGuard<'a, ()>,
    epoch: &'a AtomicU64,
}

impl Drop for ApplyLock<'_> {
    fn drop(&mut self) {
        // Even: the writes under the lock are visible to a copy that sees this.
        self.epoch.fetch_add(1, Ordering::Release);
        #[cfg(test)]
        {
            mark_lock_exit();
            APPLY_LOCK_DEPTH.with(|c| c.set(c.get().saturating_sub(1)));
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("state.db: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Maps to `STORAGE_CORRUPT`: the materialized state disagrees with the
    /// log (e.g. a changeset conflict).
    #[error("STORAGE_CORRUPT: {0}")]
    Corrupt(String),
    /// An erasure cannot be applied: a foreign key would fail, or applying
    /// it would change a row of another subject. Not a corrupt log. The
    /// `Erasure` record must not be appended.
    #[error("{0}")]
    Constraint(String),
}

/// What [`Store::raise_idle_sql`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IdleRaise {
    /// Actor databases looked at.
    pub checked: usize,
    /// Of those, raised and made durable.
    pub raised: usize,
    /// Databases that could not be raised or made durable (a turn open on
    /// them, a missing file): the log must not be deleted yet.
    pub blocked: Vec<String>,
}

fn erasure_store_error(context: &str, err: String) -> StoreError {
    let msg = format!("{context}: {err}");
    if err.starts_with("constraint:") {
        StoreError::Constraint(msg)
    } else {
        StoreError::Corrupt(msg)
    }
}

/// Tries to raise a database a turn has open, and to make a raise durable,
/// this many more times, [`BUSY_WAIT`] apart.
const BUSY_RETRIES: usize = 50;
const BUSY_WAIT: std::time::Duration = std::time::Duration::from_millis(2);

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

/// Pseudonym of one SQL cell: `(subject, value) -> bytes`.
type SqlCellRewrite = Arc<dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync>;

/// `state.db` plus the SQL pool of one branch.
pub struct Store {
    db: Mutex<StateDb>,
    pub sql: sql::SqlPool,
    pub applied: AppliedLsn,
    /// Held for a whole `apply` batch, and briefly by snapshots per database
    /// copy, so a snapshot sees `state.db` and every actor database at one
    /// LSN. An integrity state hash does not take it (ADR 0153).
    apply_lock: Mutex<()>,
    /// Odd while [`Self::apply_lock`] is held. A state hash copies files only
    /// while this stays even, so the copy does not take the lock.
    apply_epoch: AtomicU64,
    /// Reads sealed SQL changesets (docs/design/m8-privacy.md §4, §6);
    /// plain until the node sets its own.
    sealer: Mutex<Arc<kronik_privacy::sealer::Sealer>>,
    /// Set by a `--no-pii` fork. Subject-tagged SQL changesets are
    /// pseudonymized with this as they are applied. Production leaves it
    /// unset, so recorded cells are applied as they are.
    sql_rewrite: Mutex<Option<SqlCellRewrite>>,
    /// Dropped last, so shared snapshot paths stay bound until connections close.
    #[allow(dead_code)]
    cow: Option<Arc<sql::CowShare>>,
}

impl Store {
    pub fn open(state: rusqlite::Connection, sql: sql::SqlPool) -> Result<Arc<Store>, StoreError> {
        Self::open_in(state, sql, None)
    }

    pub(crate) fn open_in(
        state: rusqlite::Connection,
        sql: sql::SqlPool,
        cow: Option<Arc<sql::CowShare>>,
    ) -> Result<Arc<Store>, StoreError> {
        let db = StateDb::open(state)?;
        let applied = AppliedLsn::default();
        applied.set(db.applied_lsn()?);
        let store = Arc::new(Store {
            db: Mutex::new(db),
            sql,
            applied,
            apply_lock: Mutex::new(()),
            apply_epoch: AtomicU64::new(0),
            sealer: Mutex::new(Arc::new(kronik_privacy::sealer::Sealer::plain())),
            sql_rewrite: Mutex::new(None),
            cow,
        });
        store.backfill_sql_subjects()?;
        Ok(store)
    }

    /// An empty in-memory store (rebase shadows).
    pub fn memory() -> Result<Arc<Store>, StoreError> {
        let conn = rusqlite::Connection::open_in_memory()?;
        Store::open(
            conn,
            sql::SqlPool::new(Arc::new(sql::MemOpener), usize::MAX),
        )
    }

    /// The sealer that opens sealed SQL changesets when they are applied.
    pub fn set_sealer(&self, sealer: Arc<kronik_privacy::sealer::Sealer>) {
        *lock(&self.sealer) = sealer;
    }

    /// Pseudonymizes text and blob cells of subject-tagged SQL changesets
    /// as they are applied. A `--no-pii` fork sets this; production does not.
    pub fn set_sql_rewrite(
        &self,
        rewrite: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) {
        *lock(&self.sql_rewrite) = Some(Arc::new(rewrite));
    }

    fn sql_rewrite(&self) -> Option<SqlCellRewrite> {
        lock(&self.sql_rewrite).clone()
    }

    /// The sealer this store opens SQL changesets with.
    pub fn sealer_arc(&self) -> Arc<kronik_privacy::sealer::Sealer> {
        self.sealer()
    }

    fn sealer(&self) -> Arc<kronik_privacy::sealer::Sealer> {
        lock(&self.sealer).clone()
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

    fn apply_lock(&self) -> ApplyLock<'_> {
        let guard = lock(&self.apply_lock);
        // Odd before any write, so a copy that started earlier discards itself.
        self.apply_epoch.fetch_add(1, Ordering::Release);
        #[cfg(test)]
        {
            APPLY_LOCK_DEPTH.with(|c| c.set(c.get() + 1));
            APPLY_LOCK_ACQUIRES.with(|c| c.set(c.get() + 1));
            mark_lock_enter();
        }
        ApplyLock {
            _guard: guard,
            epoch: &self.apply_epoch,
        }
    }

    /// Read access to `state.db`.
    pub fn db(&self) -> MutexGuard<'_, StateDb> {
        lock(&self.db)
    }

    /// Applies consecutive durable records: SQL changes to the actor
    /// databases first (each tracks its own applied LSN, so a record is
    /// applied to an actor database at most once even when `state.db` is
    /// ahead or behind it), then `state.db` in one transaction (records at or
    /// below its applied LSN are skipped), then wakes waiters. Actor databases
    /// are opened before the apply lock, so a cold open does not stall other
    /// actors. An erasure's actor-database WAL checkpoints run after the lock
    /// is released.
    pub fn apply(&self, batch: &[Committed]) -> Result<(), StoreError> {
        let Some(last) = batch.last() else {
            return Ok(());
        };
        if let Some(c) = batch.iter().find(|c| c.record.rebase_switch().is_some()) {
            return Err(StoreError::Corrupt(format!(
                "the StateRebase switch at lsn {} needs its shadow",
                c.lsn
            )));
        }
        let (actors, checkpoint_state) = loop {
            let names = self.sql_targets(batch)?;
            let pinned = self.pin_sql(names.iter())?;
            let done = {
                let _apply = self.apply_lock();
                // A concurrent apply may have created an actor this erasure
                // must open. Drop the lock and pin it; do not open under it.
                if self.sql_targets(batch)? != names {
                    continue;
                }
                let mut actors = Vec::new();
                for (i, c) in batch.iter().enumerate() {
                    match &c.record {
                        Record::TurnRecord(t) => self.apply_sql(c.lsn, t)?,
                        Record::Erasure(e) => {
                            actors.extend(self.erase_sql(c.lsn, &e.subject, &batch[..i])?);
                        }
                        _ => {}
                    }
                }
                self.db().apply(batch)?;
                let checkpoint_state = batch.iter().any(|c| matches!(c.record, Record::Erasure(_)));
                self.applied.set(self.applied.get().max(last.lsn));
                (actors, checkpoint_state)
            };
            drop(pinned);
            break done;
        };
        // The state.db WAL checkpoint is the same class of stall as the
        // actor one: it runs after the apply lock (#196).
        if checkpoint_state {
            self.db().checkpoint();
        }
        self.checkpoint_erased(&actors);
        Ok(())
    }

    /// [`Store::apply`] for batches that may hold a StateRebase switch: each
    /// switch not applied yet is applied with the shadow `shadow` returns
    /// for it (ADR 0017). A switch `state.db` has applied whose copy an
    /// actor database lost (a power loss) has that copy redone, with the
    /// shadow too.
    pub fn apply_with(
        &self,
        batch: &[Committed],
        shadow: &mut dyn FnMut(&Committed) -> Result<Arc<Store>, StoreError>,
    ) -> Result<(), StoreError> {
        let mut start = 0;
        for (k, c) in batch.iter().enumerate() {
            let Some((_, sw)) = c.record.rebase_switch() else {
                continue;
            };
            self.apply(&batch[start..k])?;
            if c.lsn > self.applied.get() {
                let s = shadow(c)?;
                self.apply_switch(c, sw, &s)?;
            } else {
                let lost = self.lost_copies(c.lsn, sw)?;
                if !lost.is_empty() {
                    let s = shadow(c)?;
                    let pinned = self.pin_copies(&lost, &s)?;
                    {
                        let _apply = self.apply_lock();
                        self.copy_actors(c.lsn, &lost, &s)?;
                    }
                    drop(pinned);
                }
            }
            start = k + 1;
        }
        self.apply(&batch[start..])
    }

    /// The affected actors of the switch at `lsn`, which `state.db` has
    /// applied, whose database is below it: the copy of the switch was
    /// lost. `state.db` keeps main's and the rebased turns in
    /// `turn_index`, so the actors are known without the shadow.
    pub fn lost_copies(
        &self,
        lsn: Lsn,
        sw: &pb::RebaseSwitch,
    ) -> Result<Vec<(String, String)>, StoreError> {
        if lsn > self.applied.get() {
            return Ok(Vec::new());
        }
        let mut lost = Vec::new();
        let actors = self.db().turn_actors(sw.base_lsn, lsn)?;
        for (kind, key) in actors {
            let name = format!("{kind}/{key}");
            let sql = self.db().actor(&kind, &key)?.is_some_and(|a| a.sql);
            if !sql && !self.sql.exists(&name) {
                continue;
            }
            let db = self.sql.get(&name)?;
            let applied = lock(&db).applied_lsn()?;
            if applied < lsn {
                lost.push((kind, key));
            }
        }
        Ok(lost)
    }

    /// The transplant of a StateRebase switch (docs/design/m13-rebase.md
    /// section 3): the affected actors' databases are replaced first (each
    /// stamped with the switch's LSN in the same write, so a crash repeats
    /// the switch without copying twice), then `state.db` in one transaction.
    fn apply_switch(
        &self,
        c: &Committed,
        sw: &pb::RebaseSwitch,
        shadow: &Store,
    ) -> Result<(), StoreError> {
        let actors = self.db().rebase_actors(&shadow.db(), sw.base_lsn, c.lsn)?;
        let pinned = self.pin_copies(&actors, shadow)?;
        {
            let _apply = self.apply_lock();
            // shortcut: one applier, so this list cannot change before the
            // lock; re-read if apply becomes concurrent
            self.copy_actors(c.lsn, &actors, shadow)?;
            self.db().apply_switch(c, sw, &shadow.db(), &actors)?;
            self.applied.set(self.applied.get().max(c.lsn));
        }
        drop(pinned);
        Ok(())
    }

    /// Each actor database of `actors` below `lsn` becomes the shadow's
    /// (or empty) and carries `lsn` as its applied LSN, in one write.
    fn copy_actors(
        &self,
        lsn: Lsn,
        actors: &[(String, String)],
        shadow: &Store,
    ) -> Result<(), StoreError> {
        for (kind, key) in actors {
            let name = format!("{kind}/{key}");
            let theirs = shadow.db().actor(kind, key)?.is_some_and(|a| a.sql);
            if !theirs && !self.sql.exists(&name) {
                continue;
            }
            let db = self.sql.get(&name)?;
            let mut db = lock(&db);
            if db.applied_lsn()? >= lsn {
                continue;
            }
            if theirs {
                let src = shadow.sql.get(&name)?;
                let mut src = lock(&src);
                // The copy carries the stamp: no window where the content
                // is the shadow's but the applied LSN is main's.
                src.stamp_applied(lsn)?;
                db.copy_from(&src)?;
            } else {
                db.clear_at(lsn)?;
            }
            #[cfg(test)]
            if CRASH_AFTER_COPY.with(std::cell::Cell::get) {
                return Err(StoreError::Corrupt("test crash after an actor copy".into()));
            }
        }
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
            let applied = lock(&db).applied_lsn()?;
            from = from.min(applied);
        }
        Ok(from)
    }

    /// Before the log below `floor` is deleted: raises the applied LSN of
    /// every actor database that is below `floor` to the store's applied LSN,
    /// and makes the raise durable.
    ///
    /// An actor database's applied LSN is where its last change was, and
    /// [`Store::replay_from`] reads it as the point the log is needed from.
    /// An actor that has not changed since a long time is complete through
    /// any later LSN, but says otherwise, so retention would delete the log
    /// that the next start asks for. Under the apply lock every database is
    /// complete through what is applied (the SQL of a record is applied
    /// before `state.db` takes it, under the one lock), which is what makes
    /// the raise true. The lock is taken in batches of `batch` databases so
    /// that turns are never held for a whole pass; the checkpoint that makes
    /// a batch durable (a WAL is synced only when it is checkpointed under
    /// `synchronous=NORMAL`) runs outside it. A durable raise implies every
    /// earlier commit of that file is durable.
    ///
    /// Databases that cannot be raised now (a turn has its savepoint open on
    /// them, or the file is missing) are returned in `blocked`: the caller
    /// must not delete the log.
    pub fn raise_idle_sql(&self, floor: Lsn, batch: usize) -> Result<IdleRaise, StoreError> {
        let names = self.db().sql_actors()?;
        let mut out = IdleRaise::default();
        for chunk in names.chunks(batch.max(1)) {
            // Opening a database is the slow part and needs no lock of ours.
            let mut dbs = Vec::with_capacity(chunk.len());
            for name in chunk {
                out.checked += 1;
                if self.sql.exists(name) {
                    dbs.push((name.clone(), self.sql.get(name)?));
                } else {
                    out.blocked.push(name.clone());
                }
            }
            let mut raised = Vec::new();
            let mut busy = Vec::new();
            {
                let _apply = self.apply_lock();
                let to = self.applied.get();
                for (name, db) in dbs {
                    let mut guard = lock(&db);
                    match guard.raise_applied(floor, to)? {
                        Some(true) => raised.push((name, db.clone())),
                        Some(false) => {}
                        None => busy.push((name, db.clone())),
                    }
                }
            }
            // A turn on an idle actor ends in milliseconds: try again a few
            // times before giving up on the pass.
            for _ in 0..BUSY_RETRIES {
                if busy.is_empty() {
                    break;
                }
                std::thread::sleep(BUSY_WAIT);
                let _apply = self.apply_lock();
                let to = self.applied.get();
                let mut still = Vec::new();
                for (name, db) in busy {
                    let mut guard = lock(&db);
                    match guard.raise_applied(floor, to)? {
                        Some(true) => raised.push((name, db.clone())),
                        Some(false) => {}
                        None => still.push((name, db.clone())),
                    }
                }
                busy = still;
            }
            out.blocked.extend(busy.into_iter().map(|(name, _)| name));
            // Durable before the caller deletes anything.
            let total = raised.len();
            let mut pending = raised;
            for _ in 0..=BUSY_RETRIES {
                let mut still = Vec::new();
                for (name, db) in pending {
                    let durable = lock(&db).checkpoint_durable()?;
                    if !durable {
                        still.push((name, db));
                    }
                }
                pending = still;
                if pending.is_empty() {
                    break;
                }
                std::thread::sleep(BUSY_WAIT);
            }
            out.raised += total - pending.len();
            out.blocked
                .extend(pending.into_iter().map(|(name, _)| name));
        }
        Ok(out)
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
        let mut db = lock(&db);
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
            // Not in the log. apply combines `changesets` (ADR 0160).
            whole: Vec::new(),
        };
        let applied = if let Some(rewrite) = self.sql_rewrite() {
            db.apply_rewriting(&turn, lsn, &BTreeSet::new(), rewrite.as_ref())
        } else {
            db.apply(&turn, lsn, &BTreeSet::new())
        };
        applied.map_err(|e| StoreError::Corrupt(format!("SQL apply of {name} at lsn {lsn}: {e}")))
    }

    /// Why `privacy erase` of `subject` must not append an `Erasure`
    /// record: a row that is not theirs references a row the erasure would
    /// delete. `Ok(None)` when the deletes can be applied.
    ///
    /// shortcut: a turn that commits such a reference after this check and
    /// before apply can still append a record apply cannot finish. Close
    /// that by holding SQL writers from the check through apply.
    pub fn erasure_blocked(&self, subject: &str) -> Result<Option<String>, StoreError> {
        for name in self.actors_for_erasure(subject, &[])? {
            let db = self.sql.get(&name)?;
            let db = lock(&db);
            if let Some(blocked) = db
                .erasure_blocked_by(subject)
                .map_err(|e| StoreError::Corrupt(format!("erasure check in {name}: {e}")))?
            {
                return Ok(Some(format!("{name}: {blocked}")));
            }
        }
        Ok(None)
    }

    /// The erasure operation on the actor databases (§6.3): every row of
    /// the subject in a table with a `_subject` column is deleted, in every
    /// actor that has such a row (or a turn still open, which may be writing
    /// one). Replayed on every rebuild, so a rebuilt database equals the
    /// live one. `earlier` is the batch before the record: state.db, which
    /// records those actors, is applied after them.
    ///
    /// Names whose deletes ran and whose WAL still needs a checkpoint. The
    /// checkpoint itself runs after the apply lock is released.
    fn erase_sql(
        &self,
        lsn: Lsn,
        subject: &str,
        earlier: &[Committed],
    ) -> Result<Vec<String>, StoreError> {
        let mut checkpoint = Vec::new();
        for name in self.actors_for_erasure(subject, earlier)? {
            let db = self.sql.get(&name)?;
            let mut db = lock(&db);
            if db.applied_lsn()? >= lsn {
                continue;
            }
            let (_n, needs) = db
                .erase_subject_at(subject, lsn)
                .map_err(|e| erasure_store_error(&format!("erasure in {name} at lsn {lsn}"), e))?;
            if needs {
                checkpoint.push(name);
            }
        }
        Ok(checkpoint)
    }

    /// Actors an erasure of `subject` must open: the index, turns in
    /// `records` whose changesets carry the subject (not yet in the index),
    /// and any open SQL session (the delete waits for that turn).
    fn actors_for_erasure(
        &self,
        subject: &str,
        records: &[Committed],
    ) -> Result<BTreeSet<String>, StoreError> {
        let mut actors: BTreeSet<String> = self
            .db()
            .sql_actors_for_subject(subject)?
            .into_iter()
            .collect();
        for c in records {
            if let Record::TurnRecord(t) = &c.record
                && changeset_has_subject(t, subject)
                && let Some(name) = turn_actor(t)
            {
                actors.insert(name);
            }
        }
        actors.extend(self.sql.open_sessions());
        Ok(actors)
    }

    /// Databases written before `sql_subjects` existed: one scan, outside
    /// the apply lock, then the flag so an erasure does not repeat it.
    fn backfill_sql_subjects(&self) -> Result<(), StoreError> {
        if self.db().sql_subjects_ready()? {
            return Ok(());
        }
        for (kind, key) in self.db().sql_actor_refs()? {
            let name = format!("{kind}/{key}");
            let subjects = {
                let db = self.sql.get(&name)?;
                let mut db = lock(&db);
                db.distinct_subjects()
                    .map_err(|e| StoreError::Corrupt(format!("subjects in {name}: {e}")))?
            };
            self.db().note_actor_subjects(&kind, &key, &subjects)?;
        }
        self.db().mark_sql_subjects_ready()?;
        Ok(())
    }

    fn checkpoint_erased(&self, names: &[String]) {
        for name in names {
            match self.sql.get(name) {
                Ok(db) => {
                    let mut db = lock(&db);
                    db.checkpoint_erasure();
                }
                Err(e) => {
                    tracing::warn!(
                        actor = name,
                        error = %e,
                        "actor WAL checkpoint after an erasure failed"
                    );
                }
            }
        }
    }

    /// The erasure operation of `subject` through `key_version` again, on
    /// `state.db` and the actors that have the subject's rows, keeping the
    /// applied LSNs: a rebase shadow after its staged turns (m13-rebase §3),
    /// and a fork's continuous replay at the place of production's `Erasure`
    /// record, so the fork's state loses what production's lost there
    /// (ADR 0109). Actor-database WAL checkpoints run after the apply lock
    /// is released.
    pub fn erase_again(&self, subject: &str, key_version: u32) -> Result<(), StoreError> {
        let checkpoint = loop {
            let names = self.actors_for_erasure(subject, &[])?;
            let pinned = self.pin_sql(names.iter())?;
            let checkpoint = {
                let _apply = self.apply_lock();
                let now = self.actors_for_erasure(subject, &[])?;
                if now != names {
                    continue;
                }
                let mut checkpoint = Vec::new();
                for name in &names {
                    let db = self.sql.get(name)?;
                    let mut db = lock(&db);
                    let applied = db.applied_lsn()?;
                    let (_n, needs) = db
                        .erase_subject_at(subject, applied)
                        .map_err(|e| erasure_store_error(&format!("erasure in {name}"), e))?;
                    if needs {
                        checkpoint.push(name.clone());
                    }
                }
                // At this place: after every record applied here, so an actor's
                // blobs of the subject count until its next turn (ADR 0119).
                self.db()
                    .erase_subject_rows(subject, key_version, self.applied.get() + 1)?;
                checkpoint
            };
            drop(pinned);
            break checkpoint;
        };
        self.checkpoint_erased(&checkpoint);
        Ok(())
    }

    /// Actors `apply` will open: committed SQL turns, and, when the batch
    /// erases, the actors that have the subject's rows (plus an open session).
    fn sql_targets(&self, batch: &[Committed]) -> Result<BTreeSet<String>, StoreError> {
        let mut names = BTreeSet::new();
        let mut subjects = Vec::new();
        for c in batch {
            match &c.record {
                Record::TurnRecord(t) if turn_committed(t) && turn_has_sql(t) => {
                    if let Some(name) = turn_actor(t) {
                        names.insert(name);
                    }
                }
                Record::Erasure(e) => subjects.push(e.subject.as_str()),
                _ => {}
            }
        }
        for subject in subjects {
            names.extend(self.actors_for_erasure(subject, batch)?);
        }
        Ok(names)
    }

    fn pin_sql<'a>(
        &self,
        names: impl IntoIterator<Item = &'a String>,
    ) -> Result<Vec<Arc<Mutex<sql::SqlActor>>>, StoreError> {
        let mut pinned = Vec::new();
        for name in names {
            pinned.push(self.sql.get(name)?);
        }
        Ok(pinned)
    }

    /// The connections [`Self::copy_actors`] would open, held so that walk
    /// does not open under the apply lock.
    fn pin_copies(
        &self,
        actors: &[(String, String)],
        shadow: &Store,
    ) -> Result<Vec<Arc<Mutex<sql::SqlActor>>>, StoreError> {
        let mut pinned = Vec::new();
        for (kind, key) in actors {
            let name = format!("{kind}/{key}");
            let shadow_sql = shadow.db().actor(kind, key)?.is_some_and(|a| a.sql);
            if !shadow_sql && !self.sql.exists(&name) {
                continue;
            }
            pinned.push(self.sql.get(&name)?);
            if shadow_sql {
                pinned.push(shadow.sql.get(&name)?);
            }
        }
        Ok(pinned)
    }
}

fn turn_actor(t: &pb::TurnRecord) -> Option<String> {
    t.actor.as_ref().map(|a| format!("{}/{}", a.kind, a.key))
}

fn turn_has_sql(t: &pb::TurnRecord) -> bool {
    !t.sql_changes.is_empty() || !t.sql_schema.is_empty()
}

fn changeset_has_subject(t: &pb::TurnRecord, subject: &str) -> bool {
    t.sql_changes
        .iter()
        .any(|c| c.changeset.as_ref().and_then(|s| s.subject.as_deref()) == Some(subject))
}

fn turn_committed(t: &pb::TurnRecord) -> bool {
    t.outcome
        .as_ref()
        .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32)
}

#[cfg(test)]
mod erasure_lock_tests {
    use super::*;

    /// The schema of the SQL actor the erasure tests erase.
    const CREATE_NOTES: &str =
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, _subject TEXT)";

    /// Issue #161: an erasure's actor-database WAL checkpoint does not run
    /// while the apply lock is held.
    #[test]
    fn erasure_checkpoints_actor_databases_outside_the_apply_lock() {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path(), 8);
        store
            .db()
            .conn()
            .execute(
                "INSERT INTO actors (kind, key, schema_version, first_lsn, last_lsn, turns, sql) \
                 VALUES ('notes', 'n', 0, 1, 1, 1, 1)",
                [],
            )
            .unwrap();
        store
            .db()
            .conn()
            .execute(
                "INSERT INTO sql_subjects (subject, kind, key) VALUES ('user:1', 'notes', 'n')",
                [],
            )
            .unwrap();
        store
            .db()
            .conn()
            .execute("UPDATE meta SET v = 1 WHERE k = 'applied_lsn'", [])
            .unwrap();
        store.applied.set(1);
        store
            .sql
            .get("notes/n")
            .unwrap()
            .lock()
            .unwrap()
            .stamp_applied(1)
            .unwrap();
        ACTOR_ERASURE_CHECKPOINTS.with(|c| c.set(0));
        store
            .apply(&[committed(
                2,
                Record::Erasure(pb::Erasure {
                    subject: "user:1".into(),
                    key_version: 1,
                    ..Default::default()
                }),
            )])
            .unwrap();
        ACTOR_ERASURE_CHECKPOINTS.with(|c| {
            assert_eq!(c.get(), 1, "the actor database was not checkpointed");
        });
        assert!(!apply_lock_held());
    }

    /// Issue #196: one subject's erasure does not open every SQL actor or
    /// scan `deliveries`, and it still deletes the row and tombstones the
    /// saved call answer.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn erasure_opens_only_the_actor_that_has_the_subject() {
        use prost::Message;

        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path(), 64);
        const N: u64 = 32;
        for i in 1..=N {
            store
                .apply(&[sql_turn(i, &format!("a{i}"), CREATE_NOTES)])
                .unwrap();
        }
        let bytes = {
            let mut side = crate::sql::SqlActor::open(&crate::sql::MemOpener, "side").unwrap();
            let mut opts = crate::sql::TurnOpts {
                seed: [1; 32],
                time_ms: 1,
                default_subject: Some("user:1".into()),
                migrate: true,
                sql_budget: 50_000_000,
                max_bytes: 0,
            };
            side.begin_turn(&opts).unwrap();
            side.query(
                "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, \
                 _subject TEXT DEFAULT (kronik_subject()))",
                &[],
            )
            .unwrap();
            let schema = side.end_turn(true).unwrap();
            side.apply(&schema, 1, &std::collections::BTreeSet::new())
                .unwrap();
            opts.migrate = false;
            side.begin_turn(&opts).unwrap();
            side.query("INSERT INTO notes(body) VALUES ('mine')", &[])
                .unwrap();
            let dml = side.end_turn(true).unwrap();
            dml.changesets.into_iter().next().unwrap().1
        };
        store
            .apply(&[committed(
                N + 1,
                Record::TurnRecord(pb::TurnRecord {
                    actor: Some(pb::ActorRef {
                        kind: "notes".into(),
                        key: "a1".into(),
                    }),
                    causal_key: Some(kronik_core::causal::root("ins".into())),
                    input: Some(pb::Input {
                        kind: Some(pb::input::Kind::Http(pb::HttpInput::default())),
                    }),
                    outcome: Some(pb::Outcome {
                        kind: pb::OutcomeKind::Committed as i32,
                        ..Default::default()
                    }),
                    sql_changes: vec![pb::SqlChangeset {
                        changeset: Some(pb::Sealable {
                            subject: Some("user:1".into()),
                            value: Some(pb::sealable::Value::Plain(bytes)),
                        }),
                    }],
                    ..Default::default()
                }),
            )])
            .unwrap();
        let reply = pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            output: Some(pb::outcome::Output::Reply(pb::Message {
                body: Some(pb::Sealable {
                    subject: Some("user:1".into()),
                    value: Some(pb::sealable::Value::Plain(b"reply".to_vec())),
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        {
            let db = store.db();
            crate::assert_search(
                db.conn(),
                "SELECT message_id, outcome FROM deliveries \
                 WHERE subject = ?1 AND outcome IS NOT NULL",
                "user:1",
            );
            let tx = db.conn().unchecked_transaction().unwrap();
            tx.execute(
                "INSERT INTO deliveries (message_id, lsn, outcome, subject) \
                 VALUES ('c1', ?1, ?2, 'user:1')",
                rusqlite::params![i64::try_from(N + 1).unwrap(), reply.encode_to_vec()],
            )
            .unwrap();
            {
                let mut other = tx
                    .prepare(
                        "INSERT INTO deliveries (message_id, lsn, outcome, subject) \
                         VALUES (?1, 1, NULL, 'other')",
                    )
                    .unwrap();
                for n in 0..20_000 {
                    other.execute([format!("o{n}")]).unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let _ = take_apply_lock_hold();
        let started = std::time::Instant::now();
        store
            .apply(&[committed(
                N + 2,
                Record::Erasure(pb::Erasure {
                    subject: "user:1".into(),
                    key_version: 1,
                    ..Default::default()
                }),
            )])
            .unwrap();
        let elapsed = started.elapsed();
        let hold = take_apply_lock_hold();
        assert!(
            hold < std::time::Duration::from_secs(2) && elapsed < std::time::Duration::from_secs(2),
            "erasure hold {hold:?} elapsed {elapsed:?} over 32 actors and 20 000 deliveries"
        );
        let mine = store.sql.get("notes/a1").unwrap();
        assert_eq!(mine.lock().unwrap().applied_lsn().unwrap(), N + 2);
        let left: i64 = mine
            .lock()
            .unwrap()
            .conn
            .query_row(
                "SELECT count(*) FROM notes WHERE _subject = 'user:1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(left, 0, "the subject's row was not deleted");
        for i in 2..=N {
            let db = store.sql.get(&format!("notes/a{i}")).unwrap();
            assert_eq!(
                db.lock().unwrap().applied_lsn().unwrap(),
                i,
                "erasure opened notes/a{i}"
            );
        }
        let (_, outcome) = store.db().call_outcome("c1").unwrap().unwrap();
        assert_eq!(outcome.kind, pb::OutcomeKind::Committed as i32);
        let Some(pb::outcome::Output::Reply(message)) = outcome.output else {
            panic!("saved answer lost its reply");
        };
        assert!(kronik_privacy::sealer::is_erased(
            message.body.as_ref().unwrap()
        ));
    }

    /// An in-flight turn is not in the index yet. Erasure still opens it,
    /// so the delete runs when the turn ends instead of being skipped.
    #[test]
    fn erasure_defers_on_an_open_sql_session() {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path(), 8);
        store.apply(&[sql_turn(1, "n", CREATE_NOTES)]).unwrap();
        {
            let db = store.sql.get("notes/n").unwrap();
            let mut actor = db.lock().unwrap();
            actor
                .begin_turn(&crate::sql::TurnOpts {
                    seed: [2; 32],
                    time_ms: 2,
                    default_subject: Some("user:9".into()),
                    migrate: false,
                    sql_budget: 50_000_000,
                    max_bytes: 0,
                })
                .unwrap();
            actor
                .query(
                    "INSERT INTO notes(body, _subject) VALUES ('x', 'user:9')",
                    &[],
                )
                .unwrap();
        }
        store
            .apply(&[committed(
                2,
                Record::Erasure(pb::Erasure {
                    subject: "user:9".into(),
                    key_version: 1,
                    ..Default::default()
                }),
            )])
            .unwrap();
        let db = store.sql.get("notes/n").unwrap();
        let mut actor = db.lock().unwrap();
        actor.end_turn(true).unwrap();
        assert_eq!(
            actor.applied_lsn().unwrap(),
            2,
            "the open session was not erased when the turn ended"
        );
    }
}

#[cfg(test)]
mod sql_pool_apply_tests {
    #![allow(clippy::disallowed_methods)]

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use rusqlite::Connection;

    use super::*;
    use crate::sql::{MemOpener, SqlPool, SqliteOpener};

    struct Counting {
        inner: MemOpener,
        opens: AtomicUsize,
        opens_under_lock: AtomicUsize,
    }

    impl SqliteOpener for Counting {
        fn open(&self, actor: &str, vfs: &str) -> rusqlite::Result<Connection> {
            self.opens.fetch_add(1, Ordering::Relaxed);
            if apply_lock_held() {
                self.opens_under_lock.fetch_add(1, Ordering::Relaxed);
            }
            self.inner.open(actor, vfs)
        }

        fn exists(&self, actor: &str) -> bool {
            self.inner.exists(actor)
        }
    }

    struct Gate {
        inner: MemOpener,
        entered: AtomicBool,
        release: Mutex<bool>,
        cv: Condvar,
    }

    impl SqliteOpener for Gate {
        fn open(&self, actor: &str, vfs: &str) -> rusqlite::Result<Connection> {
            if actor == "cold/a" {
                self.entered.store(true, Ordering::Release);
                let mut release = self.release.lock().unwrap();
                while !*release {
                    release = self.cv.wait(release).unwrap();
                }
            }
            self.inner.open(actor, vfs)
        }

        fn exists(&self, _actor: &str) -> bool {
            false
        }
    }

    fn store(capacity: usize) -> (Arc<Store>, Arc<Counting>) {
        let counting = Arc::new(Counting {
            inner: MemOpener,
            opens: AtomicUsize::new(0),
            opens_under_lock: AtomicUsize::new(0),
        });
        let pool = SqlPool::new(counting.clone(), capacity);
        (
            Store::open(Connection::open_in_memory().unwrap(), pool).unwrap(),
            counting,
        )
    }

    fn apply_round(store: &Store, start: u64, n: usize, statement: &str) {
        for i in 0..n {
            store
                .apply(&[sql_turn(start + i as u64, &format!("a{i}"), statement)])
                .unwrap();
        }
    }

    /// Issue #195: a round-robin of 1 000 SQL actors does not open SQLite
    /// while the apply lock is held, and that hold stays with a warm run.
    #[test]
    fn a_thousand_sql_actors_do_not_open_under_the_apply_lock() {
        let (warm, _) = store(64);
        apply_round(&warm, 1, 64, "CREATE TABLE t (id INTEGER PRIMARY KEY)");
        let _ = take_apply_lock_hold();
        apply_round(&warm, 65, 64, "CREATE TABLE t2 (id INTEGER PRIMARY KEY)");
        let warm_per = take_apply_lock_hold() / 64u32;

        let (cold, counting) = store(256);
        apply_round(&cold, 1, 1_000, "CREATE TABLE t (id INTEGER PRIMARY KEY)");
        assert_eq!(
            counting.opens_under_lock.load(Ordering::Relaxed),
            0,
            "a cold open ran under the apply lock"
        );
        let cold_per = take_apply_lock_hold() / 1_000u32;
        assert!(
            cold_per < Duration::from_millis(5),
            "apply-lock hold {cold_per:?} per turn includes a SQLite open; warm 64 was {warm_per:?}"
        );
        assert!(
            cold_per < warm_per.saturating_mul(8) + Duration::from_millis(1),
            "1000-actor hold {cold_per:?} is not within a small factor of warm 64 {warm_per:?}"
        );
    }

    #[test]
    fn the_live_pool_keeps_a_thousand_actors_open() {
        let (store, counting) = store(256);
        store.sql.retain_opened(1_000);
        apply_round(&store, 1, 1_000, "CREATE TABLE t (id INTEGER PRIMARY KEY)");
        let opened = counting.opens.load(Ordering::Relaxed);
        apply_round(
            &store,
            1_001,
            1_000,
            "CREATE TABLE t2 (id INTEGER PRIMARY KEY)",
        );
        assert_eq!(
            counting.opens.load(Ordering::Relaxed),
            opened,
            "a retained actor was opened again on the next turn"
        );
        assert_eq!(counting.opens_under_lock.load(Ordering::Relaxed), 0);
    }

    /// A miss must not hold the pool mutex across `open`: another actor's
    /// apply has to finish while that open is still blocked.
    #[test]
    fn a_miss_does_not_stall_another_actors_apply() {
        let gate = Arc::new(Gate {
            inner: MemOpener,
            entered: AtomicBool::new(false),
            release: Mutex::new(false),
            cv: Condvar::new(),
        });
        let store = Store::open(
            Connection::open_in_memory().unwrap(),
            SqlPool::new(gate.clone(), 8),
        )
        .unwrap();
        store
            .apply(&[sql_turn(
                1,
                "warm",
                "CREATE TABLE t (id INTEGER PRIMARY KEY)",
            )])
            .unwrap();

        let blocked = store.clone();
        std::thread::spawn(move || {
            let _ = blocked.sql.get("cold/a");
        });
        let start = std::time::Instant::now();
        while !gate.entered.load(Ordering::Acquire) {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "the cold open did not start"
            );
            std::thread::yield_now();
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let applying = store.clone();
        std::thread::spawn(move || {
            applying
                .apply(&[sql_turn(
                    2,
                    "warm",
                    "CREATE TABLE t2 (id INTEGER PRIMARY KEY)",
                )])
                .unwrap();
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(2))
            .expect("a warm apply stalled while another actor was opening");

        *gate.release.lock().unwrap() = true;
        gate.cv.notify_all();
    }
}
