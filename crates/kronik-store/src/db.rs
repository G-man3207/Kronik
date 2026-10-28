//! `state.db`: the materialized state of one branch, derived from the log.
//!
//! Every applied batch of records is one SQLite transaction that also
//! advances `applied_lsn`, so after a crash the applier resumes at the first
//! record it had not applied. Durability is not needed here (the log is the
//! truth), only atomicity: WAL with `synchronous=NORMAL`.

use kronik_core::ids::Lsn;
use kronik_log::{Committed, Position};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use prost::Message as _;
use rusqlite::{Connection, OptionalExtension, params};

use crate::StoreError;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL) WITHOUT ROWID;
INSERT OR IGNORE INTO meta VALUES ('format', 1), ('applied_lsn', 0), ('time_hwm', 0), ('config_epoch', 0);
CREATE TABLE IF NOT EXISTS actors (
  kind TEXT NOT NULL, key TEXT NOT NULL, schema_version INTEGER NOT NULL,
  first_lsn INTEGER NOT NULL, last_lsn INTEGER NOT NULL, turns INTEGER NOT NULL,
  sql INTEGER NOT NULL,
  PRIMARY KEY (kind, key)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS kv (
  kind TEXT NOT NULL, key TEXT NOT NULL, k TEXT NOT NULL,
  value BLOB NOT NULL, subject TEXT, lsn INTEGER NOT NULL,
  sealed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (kind, key, k)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS turn_index (
  lsn INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL,
  segment INTEGER NOT NULL, offset INTEGER NOT NULL, outcome INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mailbox (
  message_id TEXT PRIMARY KEY, to_kind TEXT NOT NULL, to_key TEXT NOT NULL,
  lsn INTEGER NOT NULL, ordinal INTEGER NOT NULL, input BLOB NOT NULL, causal BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS mailbox_order ON mailbox (lsn, ordinal);
CREATE TABLE IF NOT EXISTS deliveries (
  message_id TEXT PRIMARY KEY, lsn INTEGER NOT NULL, outcome BLOB,
  subject TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ingress_keys (
  kind TEXT NOT NULL, key TEXT NOT NULL, idem_key TEXT NOT NULL,
  request_hash BLOB NOT NULL, lsn INTEGER NOT NULL, logical_time_ms INTEGER NOT NULL,
  outcome BLOB NOT NULL, subject TEXT,
  PRIMARY KEY (kind, key, idem_key)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dead_letters (
  lsn INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, input BLOB NOT NULL,
  error_code TEXT NOT NULL, message TEXT NOT NULL, resent_as INTEGER, subject TEXT);
CREATE TABLE IF NOT EXISTS deployments (
  epoch INTEGER PRIMARY KEY, lsn INTEGER NOT NULL, record BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS config_records (
  lsn INTEGER PRIMARY KEY, epoch INTEGER NOT NULL, kind INTEGER NOT NULL, record BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS open_turns (
  execution_id TEXT PRIMARY KEY, lsn INTEGER NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
  segment INTEGER NOT NULL, offset INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS open_effects (
  execution_id TEXT NOT NULL, ordinal INTEGER NOT NULL, record BLOB NOT NULL,
  PRIMARY KEY (execution_id, ordinal)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS timers (
  kind TEXT NOT NULL, key TEXT NOT NULL, timer_id INTEGER NOT NULL, due_ms INTEGER NOT NULL,
  msg BLOB NOT NULL, causal BLOB NOT NULL, lsn INTEGER NOT NULL,
  PRIMARY KEY (kind, key, timer_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS timers_due ON timers (due_ms);
CREATE TABLE IF NOT EXISTS orphans (
  call_message_id TEXT PRIMARY KEY, callee_kind TEXT NOT NULL, callee_key TEXT NOT NULL,
  callee_turn TEXT NOT NULL, caller_kind TEXT NOT NULL, caller_key TEXT NOT NULL,
  caller_lsn INTEGER NOT NULL, compensation_id TEXT, resolved_lsn INTEGER) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS kinds (
  kind TEXT PRIMARY KEY, code_hash BLOB NOT NULL, schema_version INTEGER NOT NULL,
  epoch INTEGER NOT NULL, lsn INTEGER NOT NULL, version BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS policies (
  epoch INTEGER PRIMARY KEY, lsn INTEGER NOT NULL, record BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS approvals (
  lsn INTEGER PRIMARY KEY, proposal_id TEXT NOT NULL, record BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS approvals_proposal ON approvals (proposal_id);
CREATE TABLE IF NOT EXISTS trees (
  root TEXT NOT NULL, lsn INTEGER NOT NULL, PRIMARY KEY (root, lsn)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS segments (
  start INTEGER PRIMARY KEY, last_lsn INTEGER NOT NULL, last_time_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS erasures (
  subject TEXT PRIMARY KEY, key_version INTEGER NOT NULL, lsn INTEGER NOT NULL) WITHOUT ROWID;
";

/// One row of `actors`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorRow {
    pub kind: String,
    pub key: String,
    pub schema_version: u32,
    pub first_lsn: Lsn,
    pub last_lsn: Lsn,
    pub turns: u64,
    pub sql: bool,
}

/// One row of `kv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvRow {
    pub k: String,
    /// The plain bytes, or an encoded `Sealed` when `sealed`.
    pub value: Vec<u8>,
    pub subject: Option<String>,
    pub lsn: Lsn,
    pub sealed: bool,
}

impl KvRow {
    /// The value as the log recorded it.
    pub fn sealable(&self) -> Result<pb::Sealable, StoreError> {
        sealable_of(self.value.clone(), self.subject.clone(), self.sealed)
    }
}

fn sealable_of(
    value: Vec<u8>,
    subject: Option<String>,
    sealed: bool,
) -> Result<pb::Sealable, StoreError> {
    let value = if sealed {
        pb::sealable::Value::Sealed(
            pb::Sealed::decode(value.as_slice())
                .map_err(|e| corrupt(format!("a sealed state value: {e}")))?,
        )
    } else {
        pb::sealable::Value::Plain(value)
    };
    Ok(pb::Sealable {
        subject,
        value: Some(value),
    })
}

/// A turn of an actor's history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnRef {
    pub lsn: Lsn,
    pub pos: Position,
}

/// A committed message not yet consumed by its receiver.
#[derive(Debug, Clone, PartialEq)]
pub struct MailboxRow {
    pub message_id: String,
    pub to: kronik_core::ids::ActorRef,
    pub input: pb::Input,
    /// The causal key of the receiving turn.
    pub causal_key: pb::CausalKey,
}

/// A saved ingress response.
#[derive(Debug, Clone, PartialEq)]
pub struct IngressRow {
    pub request_hash: Vec<u8>,
    pub lsn: Lsn,
    pub logical_time_ms: u64,
    pub outcome: pb::Outcome,
}

/// One dead letter.
#[derive(Debug, Clone, PartialEq)]
pub struct DeadLetterRow {
    pub lsn: Lsn,
    pub actor: kronik_core::ids::ActorRef,
    pub input: pb::Input,
    pub error_code: String,
    pub message: String,
    pub resent_as: Option<Lsn>,
}

/// A `TurnBegin` without a turn record.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenTurn {
    pub execution_id: String,
    pub lsn: Lsn,
    pub actor: kronik_core::ids::ActorRef,
    pub pos: Position,
}

/// A pending timer.
#[derive(Debug, Clone, PartialEq)]
pub struct TimerRow {
    pub actor: kronik_core::ids::ActorRef,
    pub timer_id: u64,
    pub due_ms: u64,
    pub msg: pb::Message,
    /// The causal key of the turn the timer fires.
    pub causal_key: pb::CausalKey,
    /// The lsn of the scheduling turn.
    pub lsn: Lsn,
}

/// A change made by a call whose caller then failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanRow {
    pub call_message_id: String,
    pub callee: kronik_core::ids::ActorRef,
    pub callee_turn: String,
    pub caller: kronik_core::ids::ActorRef,
    pub caller_lsn: Lsn,
    pub compensation_id: Option<String>,
    pub resolved_lsn: Option<Lsn>,
}

/// A kind's current code.
#[derive(Debug, Clone, PartialEq)]
pub struct KindRow {
    pub version: pb::KindVersion,
    pub epoch: u64,
    pub lsn: Lsn,
}

pub struct StateDb {
    conn: Connection,
    /// Startup catch-up: `trees` rows go to an unindexed stage and
    /// `turn_index_actor` is dropped until [`StateDb::end_bulk_replay`].
    bulk: bool,
    trees_pending: Vec<(String, i64)>,
    /// Applied LSN of an in-progress catch-up. Not written until the
    /// buffered `turn_index` load commits, so a crash replays.
    catchup_lsn: Option<Lsn>,
    overlay: std::cell::Cell<bool>,
}

fn corrupt(msg: impl Into<String>) -> StoreError {
    StoreError::Corrupt(msg.into())
}

fn decode<M: prost::Message + Default>(bytes: &[u8], what: &str) -> Result<M, StoreError> {
    M::decode(bytes).map_err(|e| corrupt(format!("{what} in state.db: {e}")))
}

fn i(v: u64) -> i64 {
    v as i64
}

impl StateDb {
    /// Prepares `conn` (WAL, NORMAL) and creates the schema.
    pub fn open(conn: Connection) -> Result<StateDb, StoreError> {
        // `journal_mode` returns a row; in-memory databases report "memory".
        let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        // H11: freed cells and pages are zeroed, so an erased row leaves no
        // copy in the file (the WAL is truncated after an erasure).
        conn.execute_batch(
            "PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = OFF; PRAGMA secure_delete = ON;",
        )?;
        conn.execute_batch(SCHEMA)?;
        // M8: `kv.sealed` says whether `value` is an encoded `Sealed`
        // (privacy mode) or the plain bytes; older databases gain it.
        let has_sealed: bool = conn.query_row(
            "SELECT count(*) > 0 FROM pragma_table_info('kv') WHERE name = 'sealed'",
            [],
            |r| r.get(0),
        )?;
        if !has_sealed {
            conn.execute_batch("ALTER TABLE kv ADD COLUMN sealed INTEGER NOT NULL DEFAULT 0")?;
        }
        add_subject_columns(&conn)?;
        let db = StateDb {
            conn,
            bulk: false,
            trees_pending: Vec::new(),
            catchup_lsn: None,
            overlay: std::cell::Cell::new(false),
        };
        if !db.file_path().is_empty() {
            // Actor history (`history`) on every node; in-memory replay
            // stores do not serve it. A bulk replay drops and rebuilds it.
            db.conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS turn_index_actor ON turn_index (kind, key, lsn);",
            )?;
        }
        Ok(db)
    }

    fn stage_exists(&self) -> Result<bool, StoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'trees_stage'",
            [],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// The database file, empty for an in-memory database.
    fn file_path(&self) -> String {
        self.conn
            .query_row(
                "SELECT file FROM pragma_database_list WHERE name = 'main'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_default()
    }

    /// Writes the bulk replay's applied LSN.
    fn load_turn_index(&mut self) -> Result<(), StoreError> {
        if let Some(lsn) = self.catchup_lsn.take() {
            self.conn
                .execute("UPDATE meta SET v = ?1 WHERE k = 'applied_lsn'", [i(lsn)])?;
        }
        Ok(())
    }

    /// Drops the scattered indexes a long startup replay would maintain row
    /// by row and turns journaling off (docs/perf.md). The live applier
    /// never enters this mode. A file-backed database first writes a
    /// durable marker beside itself; while it exists the file may be torn
    /// or partly applied, and the next start discards it and rebuilds it
    /// from the snapshot and the log ([`crate::snapshot::discard_interrupted_bulk_replay`]).
    pub fn begin_bulk_replay(&mut self) -> Result<(), StoreError> {
        if self.bulk {
            return Ok(());
        }
        let from = self.applied_lsn()?;
        let path = self.file_path();
        if !path.is_empty() {
            crate::snapshot::write_bulk_marker(std::path::Path::new(&path), from)?;
        }
        let _ = self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        let _: String = self
            .conn
            .query_row("PRAGMA journal_mode = OFF", [], |r| r.get(0))?;
        self.conn.execute_batch(
            "PRAGMA synchronous = OFF;
             PRAGMA cache_size = -262144;
             PRAGMA temp_store = MEMORY;
             PRAGMA threads = 2;
             DROP INDEX IF EXISTS turn_index_actor;
             CREATE TABLE IF NOT EXISTS trees_stage (
               root TEXT NOT NULL, lsn INTEGER NOT NULL
             );",
        )?;
        self.catchup_lsn = Some(from);
        let _ = self.conn.cache_flush();
        self.bulk = true;
        Ok(())
    }

    /// Sorted bulk-load of staged `trees` rows, then the secondary index.
    pub fn end_bulk_replay(&mut self) -> Result<(), StoreError> {
        self.finish_bulk()?;
        self.bulk = false;
        Ok(())
    }

    /// Ends a bulk replay that failed: journaling back on, but neither the
    /// applied LSN of the catch-up rows nor the marker's removal is
    /// written. With journaling off, a failed batch may have left rows
    /// behind, so the next start must discard this file and rebuild it
    /// ([`crate::snapshot::discard_interrupted_bulk_replay`]).
    pub fn abort_bulk_replay(&mut self) -> Result<(), StoreError> {
        if !self.bulk {
            return Ok(());
        }
        self.bulk = false;
        self.catchup_lsn = None;
        self.trees_pending = Vec::new();
        if self.file_path().is_empty() {
            return Ok(());
        }
        self.restore_journal()
    }

    /// WAL and the live applier's settings again, after a bulk replay.
    fn restore_journal(&mut self) -> Result<(), StoreError> {
        let mut switched = false;
        for _ in 0..50 {
            match self
                .conn
                .query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
            {
                Ok(mode) if mode.eq_ignore_ascii_case("wal") || mode == "memory" => {
                    switched = true;
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        if !switched {
            return Err(corrupt("could not restore WAL after catch-up"));
        }
        self.conn
            .execute_batch("PRAGMA synchronous = NORMAL; PRAGMA cache_size = -2000;")?;
        Ok(())
    }

    fn finish_bulk(&mut self) -> Result<(), StoreError> {
        let path: String = self
            .conn
            .query_row(
                "SELECT file FROM pragma_database_list WHERE name = 'main'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_default();
        if path.is_empty() {
            // An in-memory replay store (kronik-fork's cursors, production
            // and continuous stores). Its journal is "off", so it takes the
            // `CatchupRows` path, which writes `time_hwm` and `segments`
            // like a file-backed store. The `trees` rows of simple turns are
            // dropped: fork code reads actors, kv, timers and configuration
            // from these stores, takes causal trees from the production
            // index, and times from the recording or the wall clock.
            self.trees_pending = Vec::new();
            self.load_turn_index()?;
            if self.stage_exists()? {
                self.conn.execute_batch(
                    "INSERT OR IGNORE INTO trees (root, lsn)
                     SELECT root, lsn FROM trees_stage ORDER BY root, lsn;
                     DROP TABLE trees_stage;",
                )?;
            }
            return Ok(());
        }
        self.conn.busy_timeout(std::time::Duration::from_secs(60))?;
        // Beside state.db, not in /dev/shm: that is often small (64 MiB in a
        // container) and the scratch holds every staged row.
        let trees_path = format!("{path}-trees");
        let trees = std::mem::take(&mut self.trees_pending);
        // A plain thread, not Env::spawn: a pure function of the staged
        // rows into a scratch database, joined before its result is read,
        // so the outcome does not depend on scheduling (ADR 0004's opt-out;
        // unreachable from kronik-sim, whose stores are in-memory).
        let trees_build = {
            let dst = trees_path.clone();
            #[allow(clippy::disallowed_methods)]
            std::thread::spawn(move || build_trees_db(&dst, trees))
        };
        self.load_turn_index()?;
        // `temp_store = FILE` lets the sorter spill runs and sort them on
        // `threads` workers; an in-memory sort is single-threaded and slower.
        self.conn.execute_batch(
            "PRAGMA cache_size = -1048576;
             PRAGMA temp_store = FILE;
             CREATE INDEX IF NOT EXISTS turn_index_actor ON turn_index (kind, key, lsn);",
        )?;
        trees_build
            .join()
            .map_err(|_| corrupt("trees build thread panicked"))??;
        if std::path::Path::new(&trees_path).exists() {
            let escaped = trees_path.replace('\'', "''");
            self.conn.execute_batch(&format!(
                "ATTACH '{escaped}' AS trees_build;
                 CREATE TABLE trees_new (
                   root TEXT NOT NULL, lsn INTEGER NOT NULL,
                   PRIMARY KEY (root, lsn)
                 ) WITHOUT ROWID;
                 -- The same table shape on both sides: SQLite copies the
                 -- rows without decoding them.
                 INSERT INTO trees_new SELECT * FROM trees_build.trees;
                 INSERT OR IGNORE INTO trees_new (root, lsn)
                 SELECT root, lsn FROM trees;
                 DROP TABLE trees;
                 ALTER TABLE trees_new RENAME TO trees;
                 DETACH trees_build;"
            ))?;
            let _ = std::fs::remove_file(&trees_path);
        }
        // Turns the normal path applied during the replay staged theirs.
        if self.stage_exists()? {
            self.conn.execute_batch(
                "INSERT OR IGNORE INTO trees (root, lsn) SELECT root, lsn FROM trees_stage;
                 DROP TABLE trees_stage;",
            )?;
        }
        let _ = self.conn.cache_flush();
        self.restore_journal()?;
        crate::snapshot::remove_bulk_marker(std::path::Path::new(&path))
    }

    fn meta(&self, k: &str) -> Result<u64, StoreError> {
        let v: i64 = self
            .conn
            .prepare_cached("SELECT v FROM meta WHERE k = ?1")?
            .query_row([k], |r| r.get(0))?;
        Ok(v as u64)
    }

    /// Starts an overlay: everything applied until `overlay_rollback` is
    /// discarded then (isolated replay, docs/design/m3-fork.md §3.3).
    pub fn overlay_begin(&self) -> Result<(), StoreError> {
        self.overlay.set(true);
        // Not `prepare_cached`: cached savepoint statements made isolated
        // replay 2.3 times slower (docs/perf.md).
        self.conn.execute_batch("SAVEPOINT kronik_overlay")?;
        Ok(())
    }

    pub fn overlay_rollback(&self) -> Result<(), StoreError> {
        self.overlay.set(false);
        self.conn
            .execute_batch("ROLLBACK TO kronik_overlay; RELEASE kronik_overlay")?;
        Ok(())
    }

    /// A consistent, compact copy of `state.db` at `path` (replaced):
    /// `VACUUM INTO` copies live rows only, never free pages (H11).
    pub fn backup_to(&self, path: &std::path::Path) -> Result<(), StoreError> {
        crate::snapshot::vacuum_into(&self.conn, path)
    }

    /// Truncates the WAL after an erasure (H11): with `secure_delete` the
    /// deleted rows are zeroed in their pages, and no older page copy
    /// stays in the WAL. Skipped in an overlay and in a bulk replay
    /// (journal off), where there is no WAL to clear.
    pub fn checkpoint(&self) {
        if !self.bulk && self.conn.is_autocommit() {
            checkpoint_truncate(&self.conn, "state.db");
        }
    }

    /// The connection, for read-only whole-database work (state hash).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn applied_lsn(&self) -> Result<Lsn, StoreError> {
        self.meta("applied_lsn")
    }

    pub fn time_hwm(&self) -> Result<u64, StoreError> {
        self.meta("time_hwm")
    }

    pub fn config_epoch(&self) -> Result<u64, StoreError> {
        self.meta("config_epoch")
    }

    /// Applies a batch of consecutive records in one transaction. Records at
    /// or below `applied_lsn` are skipped. SQL changes are applied to the
    /// actor databases by the caller before this runs.
    pub fn apply(&mut self, batch: &[Committed]) -> Result<(), StoreError> {
        if self.bulk
            && let Some(rows) = CatchupRows::of(batch, self.catchup_applied()?)?
        {
            return self.apply_rows(rows);
        }
        let mut applied = self.applied_lsn()?;
        let mut hwm = self.time_hwm()?;
        let epoch_before = self.config_epoch()?;
        let mut epoch = epoch_before;
        let tx = self.conn.savepoint()?;
        // Per segment: the last LSN and logical time applied (retention).
        let mut segments: std::collections::BTreeMap<u64, (Lsn, u64)> = Default::default();
        // The engine that wrote the newest turn (m6-storage §7).
        let mut engine: Option<&str> = None;
        // A turn that begins and ends in this batch never needs `open_turns`
        // or `open_effects`: the insert and the delete would cancel. A turn
        // that began in an earlier batch has its rows there, and its record
        // deletes them (chaos at cc2cd52: startup cuts batches at segments
        // and every 131 072 records).
        let closed: std::collections::HashSet<&str> = if self.bulk {
            let begun: std::collections::HashSet<&str> = batch
                .iter()
                .filter_map(|c| match &c.record {
                    Record::TurnBegin(t) if c.lsn > applied => Some(t.execution_id.as_str()),
                    _ => None,
                })
                .collect();
            batch
                .iter()
                .filter_map(|c| match &c.record {
                    Record::TurnRecord(t) if begun.contains(t.execution_id.as_str()) => {
                        Some(t.execution_id.as_str())
                    }
                    _ => None,
                })
                .collect()
        } else {
            std::collections::HashSet::new()
        };
        for c in batch {
            if c.lsn <= applied {
                continue;
            }
            if c.lsn != applied + 1 {
                return Err(corrupt(format!(
                    "applier expected lsn {}, got {}",
                    applied + 1,
                    c.lsn
                )));
            }
            match &c.record {
                Record::TurnRecord(t) => {
                    hwm = hwm.max(t.logical_time_ms);
                    engine = Some(&t.engine_version);
                    apply_turn(
                        &tx,
                        c,
                        t,
                        self.bulk,
                        closed.contains(t.execution_id.as_str()),
                    )?;
                }
                Record::TurnBegin(t) => {
                    hwm = hwm.max(t.logical_time_ms);
                    engine = Some(&t.engine_version);
                    if !closed.contains(t.execution_id.as_str()) {
                        let a = t
                            .actor
                            .as_ref()
                            .ok_or_else(|| corrupt("turn begin without actor"))?;
                        tx.prepare_cached(
                            "INSERT OR REPLACE INTO open_turns (execution_id, lsn, kind, key, segment, offset) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        )?
                        .execute(params![
                            t.execution_id,
                            i(c.lsn),
                            a.kind,
                            a.key,
                            i(c.pos.segment),
                            i(c.pos.offset)
                        ])?;
                    }
                }
                Record::EffectResult(e) => {
                    if !closed.contains(e.execution_id.as_str()) {
                        let rec = e
                            .effect
                            .as_ref()
                            .ok_or_else(|| corrupt("effect result without effect"))?;
                        tx.prepare_cached(
                            "INSERT OR REPLACE INTO open_effects (execution_id, ordinal, record) VALUES (?1, ?2, ?3)",
                        )?
                        .execute(params![e.execution_id, rec.ordinal, rec.encode_to_vec()])?;
                    }
                }
                Record::Deployment(d) => {
                    epoch = epoch.max(d.epoch);
                    apply_deployment(&tx, c.lsn, d)?;
                }
                // Not written before later milestones; valid records still
                // advance the applied LSN and the configuration epoch.
                Record::Grant(g) => {
                    epoch = epoch.max(g.epoch);
                    config_insert(&tx, c.lsn, g.epoch, &c.record)?;
                }
                Record::Limits(l) => {
                    epoch = epoch.max(l.epoch);
                    config_insert(&tx, c.lsn, l.epoch, &c.record)?;
                }
                Record::Policy(p) => {
                    epoch = epoch.max(p.epoch);
                    tx.prepare_cached(
                        "INSERT OR REPLACE INTO policies (epoch, lsn, record) VALUES (?1, ?2, ?3)",
                    )?
                    .execute(params![
                        i(p.epoch),
                        i(c.lsn),
                        p.encode_to_vec()
                    ])?;
                }
                Record::Approval(a) => {
                    tx.prepare_cached(
                        "INSERT OR REPLACE INTO approvals (lsn, proposal_id, record) VALUES (?1, ?2, ?3)",
                    )?
                    .execute(params![i(c.lsn), a.proposal_id, a.encode_to_vec()])?;
                }
                Record::PrivacyMode(p) => {
                    epoch = epoch.max(p.epoch);
                    config_insert(&tx, c.lsn, p.epoch, &c.record)?;
                }
                Record::ForeignActor(f) => {
                    epoch = epoch.max(f.epoch);
                    config_insert(&tx, c.lsn, f.epoch, &c.record)?;
                }
                Record::Erasure(e) => {
                    epoch = epoch.max(e.epoch);
                    // The erasure operation on state.db (§6.3): the
                    // subject's state values and saved responses and dead
                    // letters go with its keys.
                    erase_rows(&tx, &e.subject)?;
                    tx.prepare_cached(
                        "INSERT OR REPLACE INTO erasures (subject, key_version, lsn) VALUES (?1, ?2, ?3)",
                    )?
                    .execute(rusqlite::params![e.subject, e.key_version, c.lsn as i64])?;
                }
                Record::EngineUpgrade(u) => {
                    epoch = epoch.max(u.epoch);
                    engine = Some(&u.to_engine_version);
                }
                Record::BranchCreated(_) | Record::SnapshotMarker(_) => {}
            }
            applied = c.lsn;
            segments.insert(c.pos.segment, (c.lsn, hwm));
        }
        for (start, (last_lsn, last_time)) in segments {
            tx.prepare_cached(
                "INSERT INTO segments (start, last_lsn, last_time_ms) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (start) DO UPDATE SET last_lsn = excluded.last_lsn, \
                 last_time_ms = excluded.last_time_ms",
            )?
            .execute(params![i(start), i(last_lsn), i(last_time)])?;
        }
        {
            let mut st = tx.prepare_cached("UPDATE meta SET v = ?2 WHERE k = ?1")?;
            st.execute(params!["applied_lsn", i(applied)])?;
            st.execute(params!["time_hwm", i(hwm)])?;
            if epoch != epoch_before {
                st.execute(params!["config_epoch", i(epoch)])?;
            }
        }
        if let Some(e) = engine.filter(|e| !e.is_empty()) {
            tx.prepare_cached("INSERT OR REPLACE INTO meta (k, v) VALUES ('engine_version', ?1)")?
                .execute([e])?;
        }
        tx.commit()?;
        if self.bulk {
            // A bulk window mixes this path with the counter-style
            // catch-up path, which advances `catchup_lsn`. This path
            // advances the `applied_lsn` meta itself, so it must move
            // `catchup_lsn` along too: `end_bulk_replay` writes
            // `catchup_lsn` back as `applied_lsn`, and a stale value would
            // rewind the meta to where the window started.
            self.catchup_lsn = Some(self.catchup_lsn.map_or(applied, |c| c.max(applied)));
        }
        Ok(())
    }
    /// The LSN a bulk replay has applied: the catch-up rows of an in-memory
    /// database reach `applied_lsn` only at the end.
    fn catchup_applied(&self) -> Result<Lsn, StoreError> {
        let db_lsn = self.applied_lsn()?;
        Ok(self.catchup_lsn.unwrap_or(db_lsn).max(db_lsn))
    }

    /// Writes [`CatchupRows`] in one transaction with `applied_lsn` and
    /// `time_hwm`: the end state of [`StateDb::apply`] of their records. In
    /// a bulk replay the `trees` rows wait for [`StateDb::end_bulk_replay`].
    pub fn apply_rows(&mut self, rows: CatchupRows) -> Result<(), StoreError> {
        if rows.last < rows.first {
            return Ok(());
        }
        let applied = self.catchup_applied()?;
        if rows.first != applied + 1 {
            return Err(corrupt(format!(
                "applier expected lsn {}, got {}",
                applied + 1,
                rows.first
            )));
        }
        let hwm = self.time_hwm()?;
        let tx = self.conn.savepoint()?;
        // With both tables empty, no turn record has an open turn or effect
        // to delete.
        let open_rows: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM open_turns) OR EXISTS (SELECT 1 FROM open_effects)",
            [],
            |r| r.get(0),
        )?;
        if open_rows {
            let mut del_turn =
                tx.prepare_cached("DELETE FROM open_turns WHERE execution_id = ?1")?;
            let mut del_effects =
                tx.prepare_cached("DELETE FROM open_effects WHERE execution_id = ?1")?;
            let mut start = 0;
            for &end in &rows.closing_ends {
                let id = rows.closing.get(start..end).unwrap_or_default();
                del_turn.execute([id])?;
                del_effects.execute([id])?;
                start = end;
            }
        }
        {
            let mut st = tx.prepare_cached(
                "INSERT OR REPLACE INTO open_turns (execution_id, lsn, kind, key, segment, offset) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for o in rows.open.iter().flatten() {
                st.execute(params![
                    o.execution_id,
                    o.lsn,
                    o.kind,
                    o.key,
                    o.segment,
                    o.offset
                ])?;
            }
        }
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO turn_index (lsn, kind, key, segment, offset, outcome) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for t in &rows.turns {
                let (kind, key) = rows.actor(t.actor)?;
                st.execute(params![t.lsn, kind, key, t.segment, t.offset, t.outcome])?;
            }
        }
        if !self.bulk {
            let mut st =
                tx.prepare_cached("INSERT OR IGNORE INTO trees (root, lsn) VALUES (?1, ?2)")?;
            for (root, lsn) in &rows.trees {
                st.execute(params![root, lsn])?;
            }
        }
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO actors (kind, key, schema_version, first_lsn, last_lsn, turns, sql) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0) \
                 ON CONFLICT (kind, key) DO UPDATE SET \
                   schema_version = CASE WHEN ?7 THEN excluded.schema_version ELSE schema_version END, \
                   last_lsn = excluded.last_lsn, turns = turns + excluded.turns, \
                   sql = max(sql, excluded.sql)",
            )?;
            for (kind, key, a) in &rows.actors {
                st.execute(params![
                    kind,
                    key,
                    a.schema_version,
                    a.first_lsn,
                    a.last_lsn,
                    a.turns,
                    a.set_schema
                ])?;
            }
        }
        {
            let mut set = tx.prepare_cached(
                "INSERT INTO kv (kind, key, k, value, subject, lsn, sealed) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                 ON CONFLICT (kind, key, k) DO UPDATE SET value = excluded.value, \
                 subject = excluded.subject, lsn = excluded.lsn, sealed = excluded.sealed",
            )?;
            let mut del =
                tx.prepare_cached("DELETE FROM kv WHERE kind = ?1 AND key = ?2 AND k = ?3")?;
            for (actor, k, row) in &rows.kvs {
                let (kind, key) = rows.actor(*actor)?;
                match &row.op {
                    KvOp::Set {
                        value,
                        subject,
                        sealed,
                    } => set.execute(params![kind, key, k, value, subject, row.lsn, sealed])?,
                    KvOp::Del => del.execute(params![kind, key, k])?,
                };
            }
        }
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO segments (start, last_lsn, last_time_ms) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (start) DO UPDATE SET last_lsn = excluded.last_lsn, \
                 last_time_ms = excluded.last_time_ms",
            )?;
            for &(start, last_lsn, time) in &rows.segments {
                st.execute(params![i(start), i(last_lsn), i(time.max(hwm))])?;
            }
            let mut st = tx.prepare_cached("UPDATE meta SET v = ?2 WHERE k = ?1")?;
            st.execute(params!["applied_lsn", i(rows.last)])?;
            st.execute(params!["time_hwm", i(rows.max_time.max(hwm))])?;
        }
        if let Some(e) = &rows.engine {
            tx.prepare_cached("INSERT OR REPLACE INTO meta (k, v) VALUES ('engine_version', ?1)")?
                .execute([e])?;
        }
        tx.commit()?;
        if self.bulk {
            self.catchup_lsn = Some(rows.last);
            self.trees_pending.extend(rows.trees);
        }
        Ok(())
    }

    /// The engine version of the newest turn or engine upgrade applied
    /// (`None` before the first).
    pub fn engine_version(&self) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .prepare_cached("SELECT v FROM meta WHERE k = 'engine_version'")?
            .query_row([], |r| r.get(0))
            .optional()?)
    }

    pub fn kv_get(&self, kind: &str, key: &str, k: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn
            .prepare_cached("SELECT value FROM kv WHERE kind = ?1 AND key = ?2 AND k = ?3")?
            .query_row([kind, key, k], |r| r.get(0))
            .optional()?)
    }

    /// One state value for a guest's read: a plain value without its subject
    /// (the guest doesn't see it, so off mode reads what it read before
    /// M8), a sealed one with the subject that names its key.
    pub fn kv_get_for_guest(
        &self,
        kind: &str,
        key: &str,
        k: &str,
    ) -> Result<Option<pb::Sealable>, StoreError> {
        let row: Option<(Vec<u8>, Option<String>, bool)> = self
            .conn
            .prepare_cached(
                "SELECT value, CASE WHEN sealed THEN subject END, sealed FROM kv \
                 WHERE kind = ?1 AND key = ?2 AND k = ?3",
            )?
            .query_row([kind, key, k], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()?;
        row.map(|(v, s, sealed)| sealable_of(v, s, sealed))
            .transpose()
    }

    /// One state value as the log recorded it (sealed or plain, with its
    /// subject).
    pub fn kv_get_sealable(
        &self,
        kind: &str,
        key: &str,
        k: &str,
    ) -> Result<Option<pb::Sealable>, StoreError> {
        let row: Option<(Vec<u8>, Option<String>, bool)> = self
            .conn
            .prepare_cached(
                "SELECT value, subject, sealed FROM kv WHERE kind = ?1 AND key = ?2 AND k = ?3",
            )?
            .query_row([kind, key, k], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()?;
        row.map(|(v, s, sealed)| sealable_of(v, s, sealed))
            .transpose()
    }

    pub fn kv_keys(&self, kind: &str, key: &str, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT k FROM kv WHERE kind = ?1 AND key = ?2 AND k >= ?3 ORDER BY k",
        )?;
        let mut out = Vec::new();
        for k in st.query_map([kind, key, prefix], |r| r.get::<_, String>(0))? {
            let k = k?;
            if !k.starts_with(prefix) {
                break;
            }
            out.push(k);
        }
        Ok(out)
    }

    pub fn kv_list(&self, kind: &str, key: &str) -> Result<Vec<KvRow>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT k, value, subject, lsn, sealed FROM kv WHERE kind = ?1 AND key = ?2 ORDER BY k",
        )?;
        let rows = st.query_map([kind, key], |r| {
            Ok(KvRow {
                k: r.get(0)?,
                value: r.get(1)?,
                subject: r.get(2)?,
                lsn: r.get::<_, i64>(3)? as u64,
                sealed: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn actor(&self, kind: &str, key: &str) -> Result<Option<ActorRow>, StoreError> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT kind, key, schema_version, first_lsn, last_lsn, turns, sql \
                 FROM actors WHERE kind = ?1 AND key = ?2",
            )?
            .query_row([kind, key], actor_row)
            .optional()?)
    }

    /// Actors in (kind, key) order after `after`, optionally of one kind.
    pub fn actors(
        &self,
        kind: Option<&str>,
        after: Option<(&str, &str)>,
        limit: usize,
    ) -> Result<Vec<ActorRow>, StoreError> {
        let (ak, ay) = after.unwrap_or(("", ""));
        let mut st = self.conn.prepare_cached(
            "SELECT kind, key, schema_version, first_lsn, last_lsn, turns, sql FROM actors \
             WHERE (?1 IS NULL OR kind = ?1) AND (kind > ?2 OR (kind = ?2 AND key > ?3)) \
             ORDER BY kind, key LIMIT ?4",
        )?;
        let rows = st.query_map(params![kind, ak, ay, limit as i64], actor_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The actor's turns, newest first, below `before`.
    pub fn history(
        &self,
        kind: &str,
        key: &str,
        before: Option<Lsn>,
        limit: usize,
    ) -> Result<Vec<TurnRef>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT lsn, segment, offset FROM turn_index \
             WHERE kind = ?1 AND key = ?2 AND lsn < ?3 ORDER BY lsn DESC LIMIT ?4",
        )?;
        let rows = st.query_map(
            params![
                kind,
                key,
                i(before.unwrap_or(i64::MAX as u64)),
                limit as i64
            ],
            turn_ref,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn turn(&self, lsn: Lsn) -> Result<Option<TurnRef>, StoreError> {
        Ok(self
            .conn
            .prepare_cached("SELECT lsn, segment, offset FROM turn_index WHERE lsn = ?1")?
            .query_row([i(lsn)], turn_ref)
            .optional()?)
    }

    /// The newest completed turn at or below `at_most`.
    pub fn latest_turn_at(&self, at_most: Lsn) -> Result<Option<TurnRef>, StoreError> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT lsn, segment, offset FROM turn_index WHERE lsn <= ?1 \
                 ORDER BY lsn DESC LIMIT 1",
            )?
            .query_row([i(at_most)], turn_ref)
            .optional()?)
    }

    /// The newest open turn (a `TurnBegin` not yet closed) at or below `at_most`.
    pub fn latest_open_turn_at(&self, at_most: Lsn) -> Result<Option<TurnRef>, StoreError> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT lsn, segment, offset FROM open_turns WHERE lsn <= ?1 \
                 ORDER BY lsn DESC LIMIT 1",
            )?
            .query_row([i(at_most)], turn_ref)
            .optional()?)
    }

    /// The oldest completed turn strictly after `after`.
    pub fn earliest_turn_after(&self, after: Lsn) -> Result<Option<TurnRef>, StoreError> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT lsn, segment, offset FROM turn_index WHERE lsn > ?1 \
                 ORDER BY lsn ASC LIMIT 1",
            )?
            .query_row([i(after)], turn_ref)
            .optional()?)
    }

    /// The oldest open turn strictly after `after`.
    pub fn earliest_open_turn_after(&self, after: Lsn) -> Result<Option<TurnRef>, StoreError> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT lsn, segment, offset FROM open_turns WHERE lsn > ?1 \
                 ORDER BY lsn ASC LIMIT 1",
            )?
            .query_row([i(after)], turn_ref)
            .optional()?)
    }

    /// Every pending message, in commit order.
    pub fn mailbox(&self) -> Result<Vec<MailboxRow>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT message_id, to_kind, to_key, input, causal FROM mailbox ORDER BY lsn, ordinal",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (message_id, kind, key, input, causal) = row?;
            out.push(MailboxRow {
                message_id,
                to: kronik_core::ids::ActorRef { kind, key },
                input: decode(&input, "mailbox input")?,
                causal_key: decode(&causal, "mailbox causal key")?,
            });
        }
        Ok(out)
    }

    /// The turn that consumed `message_id`, if any.
    pub fn delivery(&self, message_id: &str) -> Result<Option<Lsn>, StoreError> {
        Ok(self
            .conn
            .prepare_cached("SELECT lsn FROM deliveries WHERE message_id = ?1")?
            .query_row([message_id], |r| r.get::<_, i64>(0))
            .optional()?
            .map(|v| v as u64))
    }

    pub fn ingress(
        &self,
        kind: &str,
        key: &str,
        idem_key: &str,
    ) -> Result<Option<IngressRow>, StoreError> {
        let row = self
            .conn
            .prepare_cached(
                "SELECT request_hash, lsn, logical_time_ms, outcome FROM ingress_keys \
                 WHERE kind = ?1 AND key = ?2 AND idem_key = ?3",
            )?
            .query_row([kind, key, idem_key], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .optional()?;
        row.map(|(request_hash, lsn, t, outcome)| {
            Ok(IngressRow {
                request_hash,
                lsn: lsn as u64,
                logical_time_ms: t as u64,
                outcome: decode(&outcome, "ingress outcome")?,
            })
        })
        .transpose()
    }

    pub fn dead_letters(&self, after: Lsn, limit: usize) -> Result<Vec<DeadLetterRow>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT lsn, kind, key, input, error_code, message, resent_as FROM dead_letters \
             WHERE lsn > ?1 ORDER BY lsn LIMIT ?2",
        )?;
        let rows = st.query_map(params![i(after), limit as i64], dead_letter_raw)?;
        rows.map(|r| dead_letter(r?)).collect()
    }

    pub fn dead_letter(&self, lsn: Lsn) -> Result<Option<DeadLetterRow>, StoreError> {
        let raw = self
            .conn
            .prepare_cached(
                "SELECT lsn, kind, key, input, error_code, message, resent_as FROM dead_letters \
                 WHERE lsn = ?1",
            )?
            .query_row([i(lsn)], dead_letter_raw)
            .optional()?;
        raw.map(dead_letter).transpose()
    }

    pub fn deployments(&self) -> Result<Vec<(Lsn, pb::Deployment)>, StoreError> {
        let mut st = self
            .conn
            .prepare_cached("SELECT lsn, record FROM deployments ORDER BY epoch")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (lsn, bytes) = row?;
            out.push((lsn as u64, decode(&bytes, "deployment")?));
        }
        Ok(out)
    }

    pub fn kinds(&self) -> Result<Vec<KindRow>, StoreError> {
        let mut st = self
            .conn
            .prepare_cached("SELECT version, epoch, lsn FROM kinds ORDER BY kind")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (v, epoch, lsn) = row?;
            out.push(KindRow {
                version: decode(&v, "kind version")?,
                epoch: epoch as u64,
                lsn: lsn as u64,
            });
        }
        Ok(out)
    }

    /// Grant, Limits and ForeignActor records in log order.
    pub fn config_records(&self) -> Result<Vec<Record>, StoreError> {
        let mut st = self
            .conn
            .prepare_cached("SELECT kind, record FROM config_records ORDER BY lsn")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, bytes) = row?;
            out.push(
                Record::decode(kind as u8, &bytes)
                    .map_err(|e| corrupt(format!("config record in state.db: {e}")))?,
            );
        }
        Ok(out)
    }

    /// The policy in force: the `Policy` record with the highest epoch.
    pub fn policy(&self) -> Result<Option<(Lsn, pb::Policy)>, StoreError> {
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .prepare_cached("SELECT lsn, record FROM policies ORDER BY epoch DESC LIMIT 1")?
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        row.map(|(lsn, b)| {
            pb::Policy::decode(b.as_slice())
                .map(|p| (lsn as u64, p))
                .map_err(|e| corrupt(format!("policy record in state.db: {e}")))
        })
        .transpose()
    }

    /// Applied segments: (start LSN, last LSN, last logical time), by start.
    pub fn segments(&self) -> Result<Vec<(Lsn, Lsn, u64)>, StoreError> {
        let mut st = self
            .conn
            .prepare_cached("SELECT start, last_lsn, last_time_ms FROM segments ORDER BY start")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as Lsn,
                r.get::<_, i64>(1)? as Lsn,
                r.get::<_, i64>(2)? as u64,
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Compaction (m6-storage §5): forgets index rows of LSNs below
    /// `first_lsn` (their segments are gone) and ingress keys older than
    /// `ingress_before_ms`.
    pub fn compact(&mut self, first_lsn: Lsn, ingress_before_ms: u64) -> Result<(), StoreError> {
        let tx = self.conn.savepoint()?;
        tx.execute(
            "DELETE FROM turn_index WHERE lsn < ?1",
            params![i(first_lsn)],
        )?;
        tx.execute("DELETE FROM trees WHERE lsn < ?1", params![i(first_lsn)])?;
        tx.execute(
            "DELETE FROM segments WHERE last_lsn < ?1",
            params![i(first_lsn)],
        )?;
        tx.execute(
            "DELETE FROM ingress_keys WHERE logical_time_ms < ?1",
            params![i(ingress_before_ms)],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The turns of a causal tree (root id), in LSN order.
    pub fn tree(&self, root: &str) -> Result<Vec<TurnRef>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT t.lsn, t.segment, t.offset FROM trees r JOIN turn_index t ON t.lsn = r.lsn \
             WHERE r.root = ?1 ORDER BY r.lsn",
        )?;
        let rows = st.query_map([root], turn_ref)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The approvals (and approval requests) of a proposal, in log order.
    pub fn approvals(&self, proposal_id: &str) -> Result<Vec<(Lsn, pb::Approval)>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT lsn, record FROM approvals WHERE proposal_id = ?1 ORDER BY lsn",
        )?;
        let rows = st.query_map([proposal_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (lsn, b) = row?;
            out.push((
                lsn as u64,
                pb::Approval::decode(b.as_slice())
                    .map_err(|e| corrupt(format!("approval record in state.db: {e}")))?,
            ));
        }
        Ok(out)
    }

    /// Every subject with an applied `Erasure` record and the highest key
    /// version it erased (docs/design/m8-privacy.md §6.1: recovery compares
    /// this with the keystore's erasures).
    pub fn erasures(&self) -> Result<Vec<(String, u32)>, StoreError> {
        let mut st = self
            .conn
            .prepare_cached("SELECT subject, key_version FROM erasures")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
    /// The earliest applied erasure's LSN, if any. `pick_base` will not go
    /// back past it (docs/design/m8-privacy.md §6.6).
    pub fn erasure_floor(&self) -> Result<Option<Lsn>, StoreError> {
        let min: Option<i64> = self
            .conn
            .query_row("SELECT min(lsn) FROM erasures", [], |r| r.get(0))?;
        Ok(min.map(|v| v as u64))
    }

    /// After a segment rewrite (docs/design/m8-privacy.md §8): the new
    /// offsets of that segment's records, and the rows its rewritten turns
    /// (`turns`, by LSN) still own, in one transaction: `kv` values, saved
    /// ingress and call responses, dead-letter inputs. A row is updated
    /// only when its `lsn` is still the turn's, so a later write is left;
    /// rows an erasure deleted or tombstoned stay so.
    pub fn fix_reseal(
        &mut self,
        segment: Lsn,
        offsets: &[(Lsn, u64)],
        turns: &[(Lsn, pb::TurnRecord)],
    ) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        for (lsn, offset) in offsets {
            tx.execute(
                "UPDATE turn_index SET offset = ?1 WHERE lsn = ?2 AND segment = ?3",
                params![*offset as i64, *lsn as i64, segment as i64],
            )?;
            tx.execute(
                "UPDATE open_turns SET offset = ?1 WHERE lsn = ?2 AND segment = ?3",
                params![*offset as i64, *lsn as i64, segment as i64],
            )?;
        }
        for (lsn, t) in turns {
            let lsn = i(*lsn);
            let Some(actor) = &t.actor else { continue };
            for w in t.writes.iter().filter(|w| w.op == pb::StateOp::Set as i32) {
                let Some(v) = &w.value else { continue };
                let (bytes, sealed) = match &v.value {
                    Some(pb::sealable::Value::Plain(b)) => (b.clone(), false),
                    Some(pb::sealable::Value::Sealed(s)) => (s.encode_to_vec(), true),
                    None => continue,
                };
                tx.execute(
                    "UPDATE kv SET value = ?1, subject = ?2, sealed = ?3 \
                     WHERE kind = ?4 AND key = ?5 AND k = ?6 AND lsn = ?7",
                    params![bytes, v.subject, sealed, actor.kind, actor.key, w.key, lsn],
                )?;
            }
            let (Some(input), Some(outcome)) = (&t.input, &t.outcome) else {
                continue;
            };
            match &input.kind {
                Some(pb::input::Kind::Message(m)) if m.source == pb::MessageSource::Call as i32 => {
                    tx.execute(
                        "UPDATE deliveries SET outcome = ?1 \
                         WHERE message_id = ?2 AND lsn = ?3 AND subject IS NOT NULL",
                        params![outcome.encode_to_vec(), m.message_id, lsn],
                    )?;
                }
                Some(pb::input::Kind::Message(_) | pb::input::Kind::Timer(_)) => {
                    tx.execute(
                        "UPDATE dead_letters SET input = ?1 WHERE lsn = ?2",
                        params![input.encode_to_vec(), lsn],
                    )?;
                }
                Some(pb::input::Kind::Http(h)) if !h.idempotency_key.is_empty() => {
                    tx.execute(
                        "UPDATE ingress_keys SET outcome = ?1 \
                         WHERE kind = ?2 AND key = ?3 AND idem_key = ?4 AND lsn = ?5",
                        params![
                            outcome.encode_to_vec(),
                            actor.kind,
                            actor.key,
                            h.idempotency_key,
                            lsn
                        ],
                    )?;
                }
                _ => {}
            }
        }
        tx.commit()?;
        // The plain copies are gone from the pages; clear the WAL's too.
        self.checkpoint();
        Ok(())
    }

    /// (epoch, lsn) of every Grant, Limits and ForeignActor record.
    pub fn config_record_lsns(&self) -> Result<Vec<(u64, u64)>, StoreError> {
        let mut st = self
            .conn
            .prepare_cached("SELECT epoch, lsn FROM config_records ORDER BY lsn")?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// `TurnBegin`s without a turn record, in log order.
    pub fn open_turns(&self) -> Result<Vec<OpenTurn>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT execution_id, lsn, kind, key, segment, offset FROM open_turns ORDER BY lsn",
        )?;
        let rows = st.query_map([], |r| {
            Ok(OpenTurn {
                execution_id: r.get(0)?,
                lsn: r.get::<_, i64>(1)? as u64,
                actor: kronik_core::ids::ActorRef {
                    kind: r.get(2)?,
                    key: r.get(3)?,
                },
                pos: Position {
                    segment: r.get::<_, i64>(4)? as u64,
                    offset: r.get::<_, i64>(5)? as u64,
                },
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The recorded effect results of an open turn, by ordinal.
    pub fn open_effects(&self, execution_id: &str) -> Result<Vec<pb::EffectRecord>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT record FROM open_effects WHERE execution_id = ?1 ORDER BY ordinal",
        )?;
        let rows = st.query_map([execution_id], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(decode(&row?, "open effect")?);
        }
        Ok(out)
    }

    /// The saved outcome of the call turn that consumed `message_id`.
    pub fn call_outcome(&self, message_id: &str) -> Result<Option<(Lsn, pb::Outcome)>, StoreError> {
        let row = self
            .conn
            .prepare_cached("SELECT lsn, outcome FROM deliveries WHERE message_id = ?1")?
            .query_row([message_id], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<Vec<u8>>>(1)?))
            })
            .optional()?;
        match row {
            Some((lsn, Some(bytes))) => Ok(Some((lsn as u64, decode(&bytes, "call outcome")?))),
            _ => Ok(None),
        }
    }

    pub fn timer_pending(&self, kind: &str, key: &str, id: u64) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .prepare_cached("SELECT 1 FROM timers WHERE kind = ?1 AND key = ?2 AND timer_id = ?3")?
            .query_row(params![kind, key, id as i64], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// Pending timers, earliest first; of one actor when given.
    pub fn timers(&self, actor: Option<(&str, &str)>) -> Result<Vec<TimerRow>, StoreError> {
        let (k, y) = actor.unwrap_or(("", ""));
        let mut st = self.conn.prepare_cached(
            "SELECT kind, key, timer_id, due_ms, msg, causal, lsn FROM timers \
             WHERE (?1 = '' OR (kind = ?1 AND key = ?2)) ORDER BY due_ms, kind, key, timer_id",
        )?;
        let rows = st.query_map(params![k, y], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, key, id, due, msg, causal, lsn) = row?;
            out.push(TimerRow {
                actor: kronik_core::ids::ActorRef { kind, key },
                timer_id: id as u64,
                due_ms: due as u64,
                msg: decode(&msg, "timer message")?,
                causal_key: decode(&causal, "timer causal key")?,
                lsn: lsn as u64,
            });
        }
        Ok(out)
    }

    /// Orphaned changes; only unresolved ones unless `all`.
    pub fn orphans(&self, all: bool) -> Result<Vec<OrphanRow>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT call_message_id, callee_kind, callee_key, callee_turn, caller_kind, caller_key, \
             caller_lsn, compensation_id, resolved_lsn FROM orphans \
             WHERE ?1 OR resolved_lsn IS NULL ORDER BY caller_lsn, call_message_id",
        )?;
        let rows = st.query_map([all], |r| {
            Ok(OrphanRow {
                call_message_id: r.get(0)?,
                callee: kronik_core::ids::ActorRef {
                    kind: r.get(1)?,
                    key: r.get(2)?,
                },
                callee_turn: r.get(3)?,
                caller: kronik_core::ids::ActorRef {
                    kind: r.get(4)?,
                    key: r.get(5)?,
                },
                caller_lsn: r.get::<_, i64>(6)? as u64,
                compensation_id: r.get(7)?,
                resolved_lsn: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Actors with SQL state ("kind/key").
    pub fn sql_actors(&self) -> Result<Vec<String>, StoreError> {
        let mut st = self
            .conn
            .prepare_cached("SELECT kind, key FROM actors WHERE sql = 1 ORDER BY kind, key")?;
        let rows = st.query_map([], |r| {
            Ok(format!(
                "{}/{}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Whether any turn of `kind` exists (a deploy over history needs
    /// verification).
    pub fn kind_has_history(&self, kind: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .prepare_cached("SELECT 1 FROM actors WHERE kind = ?1 LIMIT 1")?
            .query_row([kind], |_| Ok(()))
            .optional()?
            .is_some())
    }
}

fn actor_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ActorRow> {
    Ok(ActorRow {
        kind: r.get(0)?,
        key: r.get(1)?,
        schema_version: r.get::<_, i64>(2)? as u32,
        first_lsn: r.get::<_, i64>(3)? as u64,
        last_lsn: r.get::<_, i64>(4)? as u64,
        turns: r.get::<_, i64>(5)? as u64,
        sql: r.get::<_, i64>(6)? != 0,
    })
}

fn turn_ref(r: &rusqlite::Row<'_>) -> rusqlite::Result<TurnRef> {
    Ok(TurnRef {
        lsn: r.get::<_, i64>(0)? as u64,
        pos: Position {
            segment: r.get::<_, i64>(1)? as u64,
            offset: r.get::<_, i64>(2)? as u64,
        },
    })
}

type DeadLetterRaw = (i64, String, String, Vec<u8>, String, String, Option<i64>);

fn dead_letter_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<DeadLetterRaw> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
    ))
}

fn dead_letter(raw: DeadLetterRaw) -> Result<DeadLetterRow, StoreError> {
    let (lsn, kind, key, input, error_code, message, resent_as) = raw;
    Ok(DeadLetterRow {
        lsn: lsn as u64,
        actor: kronik_core::ids::ActorRef { kind, key },
        input: decode(&input, "dead letter input")?,
        error_code,
        message,
        resent_as: resent_as.map(|v| v as u64),
    })
}

fn apply_turn(
    tx: &Connection,
    c: &Committed,
    t: &pb::TurnRecord,
    bulk: bool,
    skip_open: bool,
) -> Result<(), StoreError> {
    let lsn = i(c.lsn);
    let actor = t
        .actor
        .as_ref()
        .ok_or_else(|| corrupt("turn record without actor"))?;
    let (kind, key) = (actor.kind.as_str(), actor.key.as_str());
    let outcome = t
        .outcome
        .as_ref()
        .ok_or_else(|| corrupt("turn record without outcome"))?;
    let committed = outcome.kind == pb::OutcomeKind::Committed as i32;
    let has_sql = !t.sql_changes.is_empty() || !t.sql_schema.is_empty();

    tx.prepare_cached(
        "INSERT INTO actors (kind, key, schema_version, first_lsn, last_lsn, turns, sql) \
         VALUES (?1, ?2, ?3, ?4, ?4, 1, ?5) \
         ON CONFLICT (kind, key) DO UPDATE SET \
           schema_version = CASE WHEN ?6 THEN excluded.schema_version ELSE schema_version END, \
           last_lsn = excluded.last_lsn, turns = turns + 1, sql = max(sql, excluded.sql)",
    )?
    .execute(params![
        kind,
        key,
        if committed { t.schema_version } else { 0 },
        lsn,
        committed && has_sql,
        committed
    ])?;
    tx.prepare_cached(
        "INSERT INTO turn_index (lsn, kind, key, segment, offset, outcome) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![
        lsn,
        kind,
        key,
        i(c.pos.segment),
        i(c.pos.offset),
        outcome.kind
    ])?;
    if let Some(k) = &t.causal_key {
        if bulk {
            tx.prepare_cached("INSERT INTO trees_stage (root, lsn) VALUES (?1, ?2)")?
                .execute(params![k.root, lsn])?;
        } else {
            tx.prepare_cached("INSERT OR IGNORE INTO trees (root, lsn) VALUES (?1, ?2)")?
                .execute(params![k.root, lsn])?;
        }
    }

    if committed {
        let mut set = tx.prepare_cached(
            "INSERT INTO kv (kind, key, k, value, subject, lsn, sealed) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT (kind, key, k) DO UPDATE SET value = excluded.value, \
             subject = excluded.subject, lsn = excluded.lsn, sealed = excluded.sealed",
        )?;
        let mut del =
            tx.prepare_cached("DELETE FROM kv WHERE kind = ?1 AND key = ?2 AND k = ?3")?;
        for w in &t.writes {
            if w.op == pb::StateOp::Set as i32 {
                let v = w
                    .value
                    .as_ref()
                    .ok_or_else(|| corrupt("state write without value"))?;
                let (bytes, sealed) = match &v.value {
                    Some(pb::sealable::Value::Plain(b)) => (b.clone(), false),
                    Some(pb::sealable::Value::Sealed(s)) => (s.encode_to_vec(), true),
                    None => return Err(corrupt("state write with empty value")),
                };
                set.execute(params![kind, key, w.key, bytes, v.subject, lsn, sealed])?;
            } else {
                del.execute(params![kind, key, w.key])?;
            }
        }
        let parent_key = t
            .causal_key
            .as_ref()
            .ok_or_else(|| corrupt("turn record without causal key"))?;
        let sender = kronik_core::ids::ActorRef::from_pb(actor);
        for m in &t.messages {
            let input = message_input(pb::MessageSource::Actor, actor, m, t.logical_time_ms, "");
            let causal = kronik_core::causal::child(parent_key, &sender, m.ordinal);
            mailbox_insert(tx, m, lsn, &input, &causal)?;
        }
        let mut schedule = tx.prepare_cached(
            "INSERT OR REPLACE INTO timers (kind, key, timer_id, due_ms, msg, causal, lsn) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        let mut cancel =
            tx.prepare_cached("DELETE FROM timers WHERE kind = ?1 AND key = ?2 AND timer_id = ?3")?;
        for op in &t.timers {
            if op.kind == pb::TimerOpKind::Schedule as i32 {
                let msg = op
                    .msg
                    .as_ref()
                    .ok_or_else(|| corrupt("timer without message"))?;
                let causal = kronik_core::causal::child(parent_key, &sender, op.ordinal);
                schedule.execute(params![
                    kind,
                    key,
                    op.timer_id as i64,
                    i(op.due_ms),
                    msg.encode_to_vec(),
                    causal.encode_to_vec(),
                    lsn
                ])?;
            } else {
                cancel.execute(params![kind, key, op.timer_id as i64])?;
            }
        }
    } else {
        // A failed turn: compensations are delivered, and every successful
        // call becomes an orphan until its compensation succeeds.
        let parent_key = t
            .causal_key
            .as_ref()
            .ok_or_else(|| corrupt("turn record without causal key"))?;
        let caller = kronik_core::ids::ActorRef::from_pb(actor);
        for m in &t.compensations {
            let to =
                m.to.as_ref()
                    .ok_or_else(|| corrupt("compensation without target"))?;
            let callee = kronik_core::ids::ActorRef::from_pb(to);
            let compensates = kronik_core::causal::message_id(parent_key, m.ordinal);
            let input = message_input(
                pb::MessageSource::Compensation,
                actor,
                m,
                t.logical_time_ms,
                &compensates,
            );
            let causal = kronik_core::causal::compensation(parent_key, &caller, m.ordinal, &callee);
            mailbox_insert(tx, m, lsn, &input, &causal)?;
        }
        for e in &t.effects {
            if e.kind != "actor.call" || e.status != pb::EffectStatus::Ok as i32 {
                continue;
            }
            // Routing never reads user data: the callee is the plain target
            // (`actor:<kind>/<key>`) and the call's message id derives from
            // the causal key. The payloads may be sealed (privacy mode) or
            // unreadable; the callee's turn id is then unknown.
            let Some(to) = e
                .target
                .strip_prefix("actor:")
                .and_then(|t| kronik_core::ids::ActorRef::parse(t).ok())
            else {
                // Not a call this node can route; nothing to compensate.
                continue;
            };
            let call_message_id = kronik_core::causal::message_id(parent_key, e.ordinal);
            let callee_turn =
                pb::CallEffectResponse::decode(sealable_plain(e.response.as_ref()).as_slice())
                    .map(|r| r.turn_id)
                    .unwrap_or_default();
            let compensation = t
                .compensations
                .iter()
                .find(|m| m.ordinal == e.ordinal)
                .map(|m| m.message_id.clone());
            tx.prepare_cached(
                "INSERT OR IGNORE INTO orphans (call_message_id, callee_kind, callee_key, callee_turn, \
                 caller_kind, caller_key, caller_lsn, compensation_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?
            .execute(params![
                call_message_id,
                to.kind,
                to.key,
                callee_turn,
                kind,
                key,
                lsn,
                compensation
            ])?;
        }
    }

    let input = t
        .input
        .as_ref()
        .ok_or_else(|| corrupt("turn record without input"))?;
    match &input.kind {
        Some(pb::input::Kind::Message(m)) => {
            let source =
                pb::MessageSource::try_from(m.source).unwrap_or(pb::MessageSource::Unspecified);
            if matches!(
                source,
                pb::MessageSource::Actor | pb::MessageSource::Compensation
            ) {
                tx.prepare_cached("DELETE FROM mailbox WHERE message_id = ?1")?
                    .execute([&m.message_id])?;
            }
            if matches!(
                source,
                pb::MessageSource::Actor
                    | pb::MessageSource::Compensation
                    | pb::MessageSource::Call
            ) {
                let call = source == pb::MessageSource::Call;
                let saved = call.then(|| outcome.encode_to_vec());
                let subject = outcome_subject(outcome).filter(|_| call);
                tx.prepare_cached(
                    "INSERT OR IGNORE INTO deliveries (message_id, lsn, outcome, subject) \
                     VALUES (?1, ?2, ?3, ?4)",
                )?
                .execute(params![m.message_id, lsn, saved, subject])?;
            }
            if source == pb::MessageSource::DeadLetterResend
                && let Some(of) = kronik_core::ids::TurnId::parse(&m.resend_of)
            {
                tx.prepare_cached(
                    "UPDATE dead_letters SET resent_as = ?2 WHERE lsn = ?1 AND resent_as IS NULL",
                )?
                .execute(params![i(of.lsn), lsn])?;
            }
            if committed && !m.compensates.is_empty() {
                tx.prepare_cached(
                    "UPDATE orphans SET resolved_lsn = ?2 WHERE call_message_id = ?1 AND resolved_lsn IS NULL",
                )?
                .execute(params![m.compensates, lsn])?;
            }
            // The caller of a failed call got the error; it is no dead letter.
            if !committed && source != pb::MessageSource::Call {
                dead_letter_insert(tx, lsn, kind, key, input, outcome)?;
            }
        }
        Some(pb::input::Kind::Timer(tm)) => {
            tx.prepare_cached("DELETE FROM timers WHERE kind = ?1 AND key = ?2 AND timer_id = ?3")?
                .execute(params![kind, key, tm.timer_id as i64])?;
            if !committed {
                dead_letter_insert(tx, lsn, kind, key, input, outcome)?;
            }
        }
        Some(pb::input::Kind::Http(h)) if !h.idempotency_key.is_empty() => {
            tx.prepare_cached(
                "INSERT OR REPLACE INTO ingress_keys \
                 (kind, key, idem_key, request_hash, lsn, logical_time_ms, outcome, subject) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?
            .execute(params![
                kind,
                key,
                h.idempotency_key,
                h.request_hash,
                lsn,
                i(t.logical_time_ms),
                outcome.encode_to_vec(),
                outcome_subject(outcome).or_else(|| input_subject(input))
            ])?;
        }
        _ => {}
    }
    if !skip_open {
        tx.prepare_cached("DELETE FROM open_turns WHERE execution_id = ?1")?
            .execute([&t.execution_id])?;
        tx.prepare_cached("DELETE FROM open_effects WHERE execution_id = ?1")?
            .execute([&t.execution_id])?;
    }
    Ok(())
}

fn sealable_plain(s: Option<&pb::Sealable>) -> Vec<u8> {
    match s.and_then(|s| s.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.clone(),
        _ => Vec::new(),
    }
}

fn message_input(
    source: pb::MessageSource,
    sender: &pb::ActorRef,
    m: &pb::OutboundMessage,
    sent: u64,
    compensates: &str,
) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: source as i32,
            sender: Some(sender.clone()),
            msg: m.msg.clone(),
            message_id: m.message_id.clone(),
            sent_logical_time_ms: sent,
            compensates: compensates.to_owned(),
            ..Default::default()
        })),
    }
}

fn mailbox_insert(
    tx: &Connection,
    m: &pb::OutboundMessage,
    lsn: i64,
    input: &pb::Input,
    causal: &pb::CausalKey,
) -> Result<(), StoreError> {
    let to =
        m.to.as_ref()
            .ok_or_else(|| corrupt("message without target"))?;
    tx.prepare_cached(
        "INSERT INTO mailbox (message_id, to_kind, to_key, lsn, ordinal, input, causal) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?
    .execute(params![
        m.message_id,
        to.kind,
        to.key,
        lsn,
        m.ordinal,
        input.encode_to_vec(),
        causal.encode_to_vec()
    ])?;
    Ok(())
}

fn dead_letter_insert(
    tx: &Connection,
    lsn: i64,
    kind: &str,
    key: &str,
    input: &pb::Input,
    outcome: &pb::Outcome,
) -> Result<(), StoreError> {
    tx.prepare_cached(
        "INSERT INTO dead_letters (lsn, kind, key, input, error_code, message, subject) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?
    .execute(params![
        lsn,
        kind,
        key,
        input.encode_to_vec(),
        outcome.error_code,
        outcome.message,
        input_subject(input)
    ])?;
    Ok(())
}

fn http_subject<'a>(headers: &'a [pb::Header], body: Option<&'a pb::Body>) -> Option<&'a str> {
    let body = match body {
        Some(pb::Body {
            value: Some(pb::body::Value::Inline(s)),
        }) => s.subject.as_deref(),
        _ => None,
    };
    body.or_else(|| {
        headers
            .iter()
            .find_map(|h| h.value.as_ref()?.subject.as_deref())
    })
}

/// The subject of an outcome's reply or HTTP response (the runtime tags
/// all of it with the turn's subject at the end).
fn outcome_subject(o: &pb::Outcome) -> Option<&str> {
    match &o.output {
        Some(pb::outcome::Output::Reply(m)) => m.body.as_ref()?.subject.as_deref(),
        Some(pb::outcome::Output::Http(h)) => http_subject(&h.headers, h.body.as_ref()),
        None => None,
    }
}

/// The subject of an input's body (message, timer) or request.
fn input_subject(input: &pb::Input) -> Option<&str> {
    let msg = match &input.kind {
        Some(pb::input::Kind::Http(h)) => return http_subject(&h.headers, h.body.as_ref()),
        Some(pb::input::Kind::Message(m)) => m.msg.as_ref(),
        Some(pb::input::Kind::Timer(t)) => t.msg.as_ref(),
        _ => None,
    };
    msg?.body.as_ref()?.subject.as_deref()
}

/// What a saved call response of an erased subject becomes: the message
/// stays delivered (no second run), and a repeated call gets this failure.
fn erased_call_outcome() -> Vec<u8> {
    pb::Outcome {
        kind: pb::OutcomeKind::Failed as i32,
        error_code: "SUBJECT_ERASED".into(),
        message: "the call's response belonged to an erased subject".into(),
        output: None,
    }
    .encode_to_vec()
}

/// The erasure operation on state.db's user data (§6.3), live, on rebuild
/// and for erasures applied before these tables had a subject.
fn erase_rows(tx: &Connection, subject: &str) -> Result<(), StoreError> {
    for sql in [
        "DELETE FROM kv WHERE subject = ?1",
        "DELETE FROM ingress_keys WHERE subject = ?1",
        "DELETE FROM dead_letters WHERE subject = ?1",
    ] {
        tx.prepare_cached(sql)?.execute([subject])?;
    }
    tx.prepare_cached("UPDATE deliveries SET outcome = ?2, subject = NULL WHERE subject = ?1")?
        .execute(params![subject, erased_call_outcome()])?;
    Ok(())
}

/// H9: databases from before `subject` on `deliveries`, `ingress_keys`
/// and `dead_letters` gain the column, filled from the stored blobs, and
/// lose the rows of subjects erased before (one transaction).
fn add_subject_columns(conn: &Connection) -> Result<(), StoreError> {
    let has: bool = conn.query_row(
        "SELECT count(*) > 0 FROM pragma_table_info('dead_letters') WHERE name = 'subject'",
        [],
        |r| r.get(0),
    )?;
    if has {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "ALTER TABLE deliveries ADD COLUMN subject TEXT;
         ALTER TABLE ingress_keys ADD COLUMN subject TEXT;
         ALTER TABLE dead_letters ADD COLUMN subject TEXT;",
    )?;
    let outcome = |b: &[u8]| -> Result<Option<String>, StoreError> {
        let o: pb::Outcome = decode(b, "saved outcome")?;
        Ok(outcome_subject(&o).map(str::to_owned))
    };
    backfill(
        &tx,
        "SELECT message_id, outcome FROM deliveries WHERE outcome IS NOT NULL",
        "UPDATE deliveries SET subject = ?2 WHERE message_id = ?1",
        1,
        outcome,
    )?;
    backfill(
        &tx,
        "SELECT kind, key, idem_key, outcome FROM ingress_keys",
        "UPDATE ingress_keys SET subject = ?4 WHERE kind = ?1 AND key = ?2 AND idem_key = ?3",
        3,
        outcome,
    )?;
    backfill(
        &tx,
        "SELECT lsn, input FROM dead_letters",
        "UPDATE dead_letters SET subject = ?2 WHERE lsn = ?1",
        1,
        |b| {
            let input: pb::Input = decode(b, "dead letter input")?;
            Ok(input_subject(&input).map(str::to_owned))
        },
    )?;
    let erased: Vec<String> = tx
        .prepare("SELECT subject FROM erasures")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for s in &erased {
        erase_rows(&tx, s)?;
    }
    tx.commit()?;
    Ok(())
}

/// Sets `subject` on each row `select` returns: its first `keys` columns
/// identify it (`update`'s first parameters), the next is the blob.
fn backfill(
    tx: &Connection,
    select: &str,
    update: &str,
    keys: usize,
    subject: impl Fn(&[u8]) -> Result<Option<String>, StoreError>,
) -> Result<(), StoreError> {
    let rows: Vec<(Vec<rusqlite::types::Value>, Vec<u8>)> = tx
        .prepare(select)?
        .query_map([], |r| {
            let key = (0..keys).map(|i| r.get(i)).collect::<Result<Vec<_>, _>>()?;
            Ok((key, r.get(keys)?))
        })?
        .collect::<Result<_, _>>()?;
    let mut up = tx.prepare(update)?;
    for (mut key, blob) in rows {
        if let Some(s) = subject(&blob)? {
            key.push(rusqlite::types::Value::Text(s));
            up.execute(rusqlite::params_from_iter(key))?;
        }
    }
    Ok(())
}

/// `wal_checkpoint(TRUNCATE)` after an erasure (H11). The deletes are
/// committed already, so a failure is logged, not returned.
pub(crate) fn checkpoint_truncate(conn: &Connection, what: &str) {
    match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
        r.get::<_, i64>(0)
    }) {
        Ok(0) => {}
        Ok(_) => tracing::warn!(db = what, "the WAL checkpoint after an erasure was blocked"),
        Err(e) => tracing::warn!(db = what, error = %e, "WAL checkpoint after an erasure failed"),
    }
}

fn config_insert(tx: &Connection, lsn: Lsn, epoch: u64, record: &Record) -> Result<(), StoreError> {
    tx.prepare_cached(
        "INSERT INTO config_records (lsn, epoch, kind, record) VALUES (?1, ?2, ?3, ?4)",
    )?
    .execute(params![i(lsn), i(epoch), record.kind(), record.encode()])?;
    Ok(())
}

fn apply_deployment(tx: &Connection, lsn: Lsn, d: &pb::Deployment) -> Result<(), StoreError> {
    tx.prepare_cached("INSERT INTO deployments (epoch, lsn, record) VALUES (?1, ?2, ?3)")?
        .execute(params![i(d.epoch), i(lsn), d.encode_to_vec()])?;
    let mut st = tx.prepare_cached(
        "INSERT OR REPLACE INTO kinds (kind, code_hash, schema_version, epoch, lsn, version) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for k in &d.kinds {
        st.execute(params![
            k.kind,
            k.code_hash,
            k.schema_version,
            i(d.epoch),
            i(lsn),
            k.encode_to_vec()
        ])?;
    }
    Ok(())
}

struct ActorAcc {
    schema_version: i64,
    set_schema: bool,
    first_lsn: i64,
    last_lsn: i64,
    turns: i64,
}

#[derive(Default)]
struct KvAcc {
    lsn: i64,
    op: KvOp,
}

#[derive(Default)]
enum KvOp {
    #[default]
    Del,
    Set {
        value: Vec<u8>,
        subject: Option<String>,
        sealed: bool,
    },
}

fn simple_http(t: &pb::TurnRecord) -> bool {
    t.messages.is_empty()
        && t.timers.is_empty()
        && t.compensations.is_empty()
        && t.effects.is_empty()
        && t.sql_changes.is_empty()
        && t.sql_schema.is_empty()
        && matches!(
            t.input.as_ref().and_then(|i| i.kind.as_ref()),
            Some(pb::input::Kind::Http(h)) if h.idempotency_key.is_empty()
        )
}

/// A `turn_index` row of [`CatchupRows`]; `actor` indexes its actors.
struct CatchupTurn {
    lsn: i64,
    actor: usize,
    segment: i64,
    offset: i64,
    outcome: i32,
}

/// An `open_turns` row: a turn begin whose record is not in the run.
struct CatchupOpen {
    execution_id: String,
    lsn: i64,
    kind: String,
    key: String,
    segment: i64,
    offset: i64,
}

/// What a run of simple turns (HTTP input without an idempotency key; no
/// effects, messages, timers or SQL) adds to `state.db`, built record by
/// record without the database. Startup replay builds it where it decodes
/// the records and drops each record right away (docs/perf.md);
/// [`StateDb::apply_rows`] writes it.
pub struct CatchupRows {
    /// Records up to here are skipped (`state.db` has them).
    applied: Lsn,
    /// The run is `first..=last`; empty when `last < first`.
    first: Lsn,
    last: Lsn,
    max_time: u64,
    engine: Option<String>,
    /// Per segment: its start, the run's last LSN in it, and the newest
    /// logical time of the run up to that record.
    segments: Vec<(u64, Lsn, u64)>,
    actors: Vec<(String, String, ActorAcc)>,
    /// kind -> key -> index in `actors`.
    actor_ix: std::collections::HashMap<String, std::collections::HashMap<String, usize>>,
    /// Per actor: key -> index in `kvs`.
    kv_ix: Vec<std::collections::HashMap<String, usize>>,
    turns: Vec<CatchupTurn>,
    trees: Vec<(String, i64)>,
    /// The last write per `(actor, key)`.
    kvs: Vec<(usize, String, KvAcc)>,
    /// Turn begins; `None` once their record is in the run too.
    open: Vec<Option<CatchupOpen>>,
    /// Execution id -> index in `open`.
    open_ix: std::collections::HashMap<String, usize>,
    /// Execution ids of turn records whose begin is not in the run, end to
    /// end; `closing_ends` splits them.
    closing: String,
    closing_ends: Vec<usize>,
}

impl CatchupRows {
    /// An empty run after `applied`.
    pub fn new(applied: Lsn) -> CatchupRows {
        CatchupRows {
            applied,
            first: applied + 1,
            last: applied,
            max_time: 0,
            engine: None,
            segments: Vec::new(),
            actors: Vec::new(),
            actor_ix: Default::default(),
            kv_ix: Vec::new(),
            turns: Vec::new(),
            trees: Vec::new(),
            kvs: Vec::new(),
            open: Vec::new(),
            open_ix: Default::default(),
            closing: String::new(),
            closing_ends: Vec::new(),
        }
    }

    /// The rows of `records`, or `None` when one of them is not a simple
    /// turn (apply those with [`StateDb::apply`]).
    pub fn of(records: &[Committed], applied: Lsn) -> Result<Option<CatchupRows>, StoreError> {
        let mut rows = CatchupRows::new(applied);
        for c in records {
            if !rows.push(c)? {
                return Ok(None);
            }
        }
        Ok(Some(rows))
    }

    /// Adds the next record. `false` when it is not a simple turn: the rows
    /// are then incomplete and the records must be applied instead.
    pub fn push(&mut self, c: &Committed) -> Result<bool, StoreError> {
        match &c.record {
            Record::TurnRecord(t) if simple_http(t) => {}
            Record::TurnBegin(_) => {}
            _ => return Ok(false),
        }
        if c.lsn <= self.applied {
            return Ok(true);
        }
        if self.last >= self.first && c.lsn != self.last + 1 {
            return Err(corrupt(format!(
                "applier expected lsn {}, got {}",
                self.last + 1,
                c.lsn
            )));
        }
        if self.last < self.first {
            self.first = c.lsn;
        }
        let lsn = i(c.lsn);
        match &c.record {
            Record::TurnRecord(t) => {
                self.time_and_engine(t.logical_time_ms, &t.engine_version);
                let actor = t
                    .actor
                    .as_ref()
                    .ok_or_else(|| corrupt("turn record without actor"))?;
                let outcome = t
                    .outcome
                    .as_ref()
                    .ok_or_else(|| corrupt("turn record without outcome"))?;
                let committed = outcome.kind == pb::OutcomeKind::Committed as i32;
                // A turn that begins and ends in the run never touches
                // `open_turns`.
                let begun = if self.open_ix.is_empty() {
                    None
                } else {
                    self.open_ix.remove(&t.execution_id)
                };
                match begun {
                    Some(o) => {
                        if let Some(slot) = self.open.get_mut(o) {
                            *slot = None;
                        }
                    }
                    None => {
                        self.closing.push_str(&t.execution_id);
                        self.closing_ends.push(self.closing.len());
                    }
                }
                let a = self.actor_index(&actor.kind, &actor.key, lsn);
                if let Some((_, _, acc)) = self.actors.get_mut(a) {
                    if committed {
                        acc.schema_version = i64::from(t.schema_version);
                        acc.set_schema = true;
                    }
                    acc.last_lsn = lsn;
                    acc.turns += 1;
                }
                self.turns.push(CatchupTurn {
                    lsn,
                    actor: a,
                    segment: i(c.pos.segment),
                    offset: i(c.pos.offset),
                    outcome: outcome.kind,
                });
                if let Some(k) = &t.causal_key {
                    self.trees.push((k.root.clone(), lsn));
                }
                if committed {
                    for w in &t.writes {
                        self.write(a, lsn, w)?;
                    }
                }
            }
            Record::TurnBegin(t) => {
                self.time_and_engine(t.logical_time_ms, &t.engine_version);
                let a = t
                    .actor
                    .as_ref()
                    .ok_or_else(|| corrupt("turn begin without actor"))?;
                self.open_ix.insert(t.execution_id.clone(), self.open.len());
                self.open.push(Some(CatchupOpen {
                    execution_id: t.execution_id.clone(),
                    lsn,
                    kind: a.kind.clone(),
                    key: a.key.clone(),
                    segment: i(c.pos.segment),
                    offset: i(c.pos.offset),
                }));
            }
            _ => {}
        }
        self.last = c.lsn;
        match self.segments.last_mut() {
            Some(s) if s.0 == c.pos.segment => *s = (s.0, c.lsn, self.max_time),
            _ => self.segments.push((c.pos.segment, c.lsn, self.max_time)),
        }
        Ok(true)
    }

    fn time_and_engine(&mut self, time: u64, engine: &str) {
        self.max_time = self.max_time.max(time);
        if !engine.is_empty() && self.engine.as_deref() != Some(engine) {
            self.engine = Some(engine.to_owned());
        }
    }

    fn actor_index(&mut self, kind: &str, key: &str, lsn: i64) -> usize {
        if let Some(&a) = self.actor_ix.get(kind).and_then(|keys| keys.get(key)) {
            return a;
        }
        let a = self.actors.len();
        self.actors.push((
            kind.to_owned(),
            key.to_owned(),
            ActorAcc {
                schema_version: 0,
                set_schema: false,
                first_lsn: lsn,
                last_lsn: lsn,
                turns: 0,
            },
        ));
        self.kv_ix.push(Default::default());
        self.actor_ix
            .entry(kind.to_owned())
            .or_default()
            .insert(key.to_owned(), a);
        a
    }

    fn write(&mut self, a: usize, lsn: i64, w: &pb::StateWrite) -> Result<(), StoreError> {
        let op = if w.op == pb::StateOp::Set as i32 {
            let v = w
                .value
                .as_ref()
                .ok_or_else(|| corrupt("state write without value"))?;
            let (value, sealed) = match &v.value {
                Some(pb::sealable::Value::Plain(b)) => (b.clone(), false),
                Some(pb::sealable::Value::Sealed(s)) => (s.encode_to_vec(), true),
                None => return Err(corrupt("state write with empty value")),
            };
            KvOp::Set {
                value,
                subject: v.subject.clone(),
                sealed,
            }
        } else {
            KvOp::Del
        };
        let row = KvAcc { lsn, op };
        let keys = self
            .kv_ix
            .get_mut(a)
            .ok_or_else(|| corrupt("catch-up row without its actor"))?;
        match keys.get(w.key.as_str()) {
            Some(&k) => {
                if let Some(slot) = self.kvs.get_mut(k) {
                    slot.2 = row;
                }
            }
            None => {
                keys.insert(w.key.clone(), self.kvs.len());
                self.kvs.push((a, w.key.clone(), row));
            }
        }
        Ok(())
    }

    /// The last LSN of the run, `None` when it is empty.
    pub fn last_lsn(&self) -> Option<Lsn> {
        (self.last >= self.first).then_some(self.last)
    }

    fn actor(&self, i: usize) -> Result<(&str, &str), StoreError> {
        self.actors
            .get(i)
            .map(|(kind, key, _)| (kind.as_str(), key.as_str()))
            .ok_or_else(|| corrupt("catch-up row without its actor"))
    }
}

fn build_trees_db(path: &str, rows: Vec<(String, i64)>) -> Result<(), StoreError> {
    let _ = std::fs::remove_file(path);
    if rows.is_empty() {
        return Ok(());
    }
    // The first 8 bytes, big-endian, order like the string: most
    // comparisons never touch the heap.
    let mut rows: Vec<(u64, String, i64)> = rows
        .into_iter()
        .map(|(root, lsn)| {
            let mut p = [0u8; 8];
            let n = root.len().min(8);
            p[..n].copy_from_slice(&root.as_bytes()[..n]);
            (u64::from_be_bytes(p), root, lsn)
        })
        .collect();
    rows.sort_unstable();
    let conn = rusqlite::Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = OFF;
         PRAGMA synchronous = OFF;
         CREATE TABLE trees (
           root TEXT NOT NULL, lsn INTEGER NOT NULL, PRIMARY KEY (root, lsn)
         ) WITHOUT ROWID;",
    )?;
    let tx = conn.unchecked_transaction()?;
    {
        let mut st = tx.prepare("INSERT INTO trees VALUES (?1, ?2)")?;
        for (_, root, lsn) in &rows {
            st.execute(params![root, lsn])?;
        }
    }
    tx.commit()?;
    conn.close().map_err(|(_, e)| StoreError::from(e))?;
    Ok(())
}

/// The subject keys sealed values need: (subject, key version), each with
/// one value sealed under it, so a check can try the key on it.
pub type SubjectKeys = std::collections::BTreeMap<(String, u32), pb::Sealed>;

/// Notes `sealed` under (subject, version), keeping a value with
/// ciphertext over a tombstone as the sample.
pub fn note_key(keys: &mut SubjectKeys, subject: &str, sealed: &pb::Sealed) {
    let slot = keys
        .entry((subject.to_owned(), sealed.key_version))
        .or_insert_with(|| sealed.clone());
    if slot.ciphertext.is_empty() && !sealed.ciphertext.is_empty() {
        *slot = sealed.clone();
    }
}

/// Notes every sealed value in `s`.
pub fn note_sealed(keys: &mut SubjectKeys) -> impl FnMut(&mut pb::Sealable) + '_ {
    |s: &mut pb::Sealable| {
        if let (Some(subject), Some(pb::sealable::Value::Sealed(x))) = (&s.subject, &s.value) {
            note_key(keys, subject, x);
        }
    }
}

/// Every subject key that a sealed value in this state database needs: kv
/// values, call outcomes, saved responses, mailbox and dead-letter inputs,
/// timer messages and open effects. A restore checks them against the
/// keystore it installs, and `kronik integrity` against the live one
/// (m8-privacy §10).
pub fn sealed_keys(conn: &Connection) -> Result<SubjectKeys, StoreError> {
    use kronik_proto::sealables;
    let mut keys = SubjectKeys::new();
    let mut st =
        conn.prepare("SELECT subject, value FROM kv WHERE sealed AND subject IS NOT NULL")?;
    let mut q = st.query([])?;
    while let Some(r) = q.next()? {
        let subject: String = r.get(0)?;
        let bytes: Vec<u8> = r.get(1)?;
        let s = pb::Sealed::decode(bytes.as_slice())
            .map_err(|e| corrupt(format!("a sealed state value: {e}")))?;
        note_key(&mut keys, &subject, &s);
    }
    for (sql, what) in [
        (
            "SELECT outcome FROM deliveries WHERE outcome IS NOT NULL",
            "outcome",
        ),
        ("SELECT outcome FROM ingress_keys", "outcome"),
        ("SELECT input FROM mailbox", "input"),
        ("SELECT input FROM dead_letters", "input"),
        ("SELECT msg FROM timers", "message"),
        ("SELECT record FROM open_effects", "effect"),
    ] {
        let mut st = conn.prepare(sql)?;
        let mut q = st.query([])?;
        while let Some(r) = q.next()? {
            let b: Vec<u8> = r.get(0)?;
            let bad = |e: prost::DecodeError| corrupt(format!("a stored {what}: {e}"));
            let f = &mut note_sealed(&mut keys);
            match what {
                "outcome" => sealables::outcome_mut(
                    Some(&mut pb::Outcome::decode(b.as_slice()).map_err(bad)?),
                    f,
                ),
                "input" => sealables::input_mut(
                    Some(&mut pb::Input::decode(b.as_slice()).map_err(bad)?),
                    f,
                ),
                "message" => sealables::message_mut(
                    Some(&mut pb::Message::decode(b.as_slice()).map_err(bad)?),
                    f,
                ),
                _ => sealables::effect_mut(
                    &mut pb::EffectRecord::decode(b.as_slice()).map_err(bad)?,
                    f,
                ),
            }
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> Option<pb::ActorRef> {
        Some(pb::ActorRef {
            kind: "counter".into(),
            key: "a".into(),
        })
    }

    fn causal(root: &str) -> Option<pb::CausalKey> {
        Some(pb::CausalKey {
            root: root.into(),
            path: vec![],
        })
    }

    fn http_input() -> Option<pb::Input> {
        Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput::default())),
        })
    }

    fn message_input() -> Option<pb::Input> {
        Some(pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::Operator as i32,
                ..Default::default()
            })),
        })
    }

    fn committed(lsn: u64, record: Record) -> Committed {
        Committed {
            lsn,
            pos: Position {
                segment: 0,
                offset: 0,
            },
            record,
        }
    }

    fn begin(exec: &str, root: &str, input: Option<pb::Input>) -> Record {
        Record::TurnBegin(pb::TurnBegin {
            execution_id: exec.into(),
            actor: actor(),
            causal_key: causal(root),
            input,
            ..Default::default()
        })
    }

    fn turn(exec: &str, root: &str, input: Option<pb::Input>) -> Record {
        Record::TurnRecord(pb::TurnRecord {
            execution_id: exec.into(),
            actor: actor(),
            causal_key: causal(root),
            input,
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    fn turn_with_effects(exec: &str, root: &str) -> Record {
        let mut t = turn(exec, root, http_input());
        let Record::TurnRecord(r) = &mut t else {
            unreachable!("turn() builds a TurnRecord");
        };
        r.effects.push(pb::EffectRecord::default());
        t
    }

    /// Review H1/H2 (v0.1): a failed turn whose successful call has a
    /// sealed request (privacy mode) or bytes that no longer decode (the old
    /// byte-level scrub) is applied: the orphan comes from the plain target
    /// and the derived message id, never from the payload. Data directories
    /// with such records start again.
    #[test]
    fn a_failed_turns_call_with_unreadable_payloads_is_applied() {
        let conn = Connection::open_in_memory().unwrap();
        let mut db = StateDb::open(conn).unwrap();
        let mut t = turn("e1", "r1", message_input());
        let Record::TurnRecord(r) = &mut t else {
            unreachable!("turn() builds a TurnRecord");
        };
        r.outcome = Some(pb::Outcome {
            kind: pb::OutcomeKind::Failed as i32,
            ..Default::default()
        });
        let sealed = Some(pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed::default())),
        });
        let garbage = Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(vec![0x0e, 0xff, 0x16, 0x07])),
        });
        for (ordinal, request) in [(1, sealed), (2, garbage)] {
            r.effects.push(pb::EffectRecord {
                ordinal,
                kind: "actor.call".into(),
                target: format!("actor:counter/b{ordinal}"),
                status: pb::EffectStatus::Ok as i32,
                request: request.clone(),
                response: request,
                ..Default::default()
            });
        }
        db.apply(&[
            committed(1, begin("e1", "r1", message_input())),
            committed(2, t),
        ])
        .unwrap();
        let orphans = db.orphans(false).unwrap();
        assert_eq!(orphans.len(), 2, "{orphans:?}");
        let parent = causal("r1").unwrap();
        for (o, ordinal) in orphans.iter().zip([1u32, 2]) {
            assert_eq!(o.callee.key, format!("b{ordinal}"));
            assert_eq!(
                o.call_message_id,
                kronik_core::causal::message_id(&parent, ordinal)
            );
            assert_eq!(o.callee_turn, "");
        }
    }

    /// A bulk window that mixes simple catch-up batches (counter-style
    /// HTTP turns) with normal-path batches (a message turn, a turn with
    /// an effect) must leave `applied_lsn` at the highest applied LSN,
    /// not rewind it to where the window started, and the store must
    /// accept the next consecutive batch afterwards.
    #[test]
    fn bulk_replay_keeps_applied_lsn_monotonic_across_mixed_batches() {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("state.db")).unwrap();
        let mut db = StateDb::open(conn).unwrap();
        db.begin_bulk_replay().unwrap();
        // Simple batch: the counter-style catch-up path advances only
        // `catchup_lsn` (plus, on a file-backed database, the meta).
        db.apply(&[
            committed(1, begin("e1", "r1", http_input())),
            committed(2, turn("e1", "r1", http_input())),
        ])
        .unwrap();
        // Non-simple batch: a message-input turn and a turn with an
        // effect take the normal apply path.
        db.apply(&[
            committed(3, begin("e2", "r2", message_input())),
            committed(4, turn("e2", "r2", message_input())),
            committed(5, begin("e3", "r3", http_input())),
            committed(6, turn_with_effects("e3", "r3")),
        ])
        .unwrap();
        db.end_bulk_replay().unwrap();
        assert_eq!(db.applied_lsn().unwrap(), 6);
        // The next consecutive batch applies after the window.
        db.apply(&[
            committed(7, begin("e4", "r4", http_input())),
            committed(8, turn("e4", "r4", http_input())),
        ])
        .unwrap();
        assert_eq!(db.applied_lsn().unwrap(), 8);
    }

    /// The same mixed window on an in-memory database, where the
    /// catch-up path defers all writes until `end_bulk_replay`.
    #[test]
    fn bulk_replay_memory_keeps_applied_lsn_monotonic() {
        let conn = Connection::open_in_memory().unwrap();
        let mut db = StateDb::open(conn).unwrap();
        db.begin_bulk_replay().unwrap();
        db.apply(&[
            committed(1, begin("e1", "r1", http_input())),
            committed(2, turn("e1", "r1", http_input())),
        ])
        .unwrap();
        db.apply(&[
            committed(3, begin("e2", "r2", message_input())),
            committed(4, turn("e2", "r2", message_input())),
        ])
        .unwrap();
        db.end_bulk_replay().unwrap();
        assert_eq!(db.applied_lsn().unwrap(), 4);
        db.apply(&[
            committed(5, begin("e3", "r3", http_input())),
            committed(6, turn("e3", "r3", http_input())),
        ])
        .unwrap();
        assert_eq!(db.applied_lsn().unwrap(), 6);
    }

    /// Chaos at cc2cd52: a bulk replay whose batch ends between a turn's
    /// begin and its record (startup cuts batches at 131 072 records and
    /// at every segment) kept the finished turn in `open_turns` and
    /// `open_effects`, so the start re-ran it and sent its effect again.
    /// Both apply paths, a begin that stays open, and a batch that starts
    /// below the applied LSN with a begin the store already has.
    #[test]
    fn bulk_replay_closes_turns_begun_in_an_earlier_batch() {
        let effect = |exec: &str, ordinal: u32| {
            Record::EffectResult(pb::EffectResult {
                execution_id: exec.into(),
                effect: Some(pb::EffectRecord {
                    ordinal,
                    ..Default::default()
                }),
            })
        };
        let batches = [
            // Normal path: e1 begins and records an effect.
            vec![
                committed(1, begin("e1", "r1", message_input())),
                committed(2, effect("e1", 0)),
                committed(3, begin("e2", "r2", message_input())),
                committed(4, turn("e2", "r2", message_input())),
            ],
            // e1's next effect and record, in the next batch.
            vec![
                committed(5, effect("e1", 1)),
                committed(6, turn("e1", "r1", message_input())),
            ],
            // Catch-up rows path for e3's begin, normal path for its record.
            vec![committed(7, begin("e3", "r3", http_input()))],
            vec![committed(8, turn("e3", "r3", message_input()))],
            vec![committed(9, begin("e4", "r4", http_input()))],
            vec![committed(10, begin("e5", "r5", message_input()))],
            // From below the applied LSN (the store skips what it has): the
            // begin's row came from the batch before, and the record ends it.
            vec![
                committed(10, begin("e5", "r5", message_input())),
                committed(11, effect("e5", 0)),
                committed(12, turn("e5", "r5", message_input())),
            ],
        ];
        let dir = tempfile::tempdir().unwrap();
        let open =
            |name: &str| StateDb::open(Connection::open(dir.path().join(name)).unwrap()).unwrap();
        let mut normal = open("normal.db");
        let mut bulk = open("bulk.db");
        bulk.begin_bulk_replay().unwrap();
        for b in &batches {
            normal.apply(b).unwrap();
            bulk.apply(b).unwrap();
        }
        bulk.end_bulk_replay().unwrap();
        for table in ["open_turns", "open_effects"] {
            assert_eq!(rows_of(&bulk, table), rows_of(&normal, table), "{table}");
        }
        let open_turns = bulk.open_turns().unwrap();
        assert_eq!(
            open_turns
                .iter()
                .map(|t| t.execution_id.as_str())
                .collect::<Vec<_>>(),
            ["e4"]
        );
        assert_eq!(rows_of(&bulk, "open_effects"), Vec::<String>::new());
    }

    fn rows_of(db: &StateDb, table: &str) -> Vec<String> {
        let mut st = db.conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let n = st.column_count();
        let mut rows: Vec<String> = st
            .query_map([], |r| {
                (0..n)
                    .map(|i| r.get::<_, rusqlite::types::Value>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
            .map(|r| format!("{:?}", r.unwrap()))
            .collect();
        rows.sort();
        rows
    }

    /// A bulk replay's catch-up rows leave `state.db` as the normal apply
    /// path does: turns that begin in one run and end in the next, a begin
    /// left open, the last write of a key winning, a delete, per-segment
    /// times and the engine version.
    #[test]
    fn catchup_rows_match_the_normal_apply() {
        let write = |key: &str, value: Option<&[u8]>| pb::StateWrite {
            op: if value.is_some() {
                pb::StateOp::Set as i32
            } else {
                pb::StateOp::Delete as i32
            },
            key: key.into(),
            value: value.map(|v| pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(v.to_vec())),
            }),
        };
        let turn_at = |exec: &str, key: &str, time: u64, writes: Vec<pb::StateWrite>| {
            let mut t = turn(exec, exec, http_input());
            let Record::TurnRecord(r) = &mut t else {
                unreachable!("turn() builds a TurnRecord");
            };
            r.actor = Some(pb::ActorRef {
                kind: "counter".into(),
                key: key.into(),
            });
            r.logical_time_ms = time;
            r.engine_version = format!("engine-{time}");
            r.writes = writes;
            t
        };
        let at = |lsn: u64, segment: u64, record: Record| Committed {
            lsn,
            pos: Position {
                segment,
                offset: lsn * 10,
            },
            record,
        };
        let runs = [
            vec![
                at(1, 1, begin("e1", "e1", http_input())),
                at(2, 1, turn_at("e2", "a", 20, vec![write("n", Some(b"1"))])),
                at(
                    3,
                    1,
                    turn_at(
                        "e3",
                        "b",
                        10,
                        vec![write("n", Some(b"7")), write("m", None)],
                    ),
                ),
            ],
            vec![
                at(4, 1, turn("e1", "e1", http_input())),
                at(5, 4, begin("e5", "e5", http_input())),
                at(6, 4, turn_at("e6", "a", 30, vec![write("n", Some(b"2"))])),
                at(7, 4, turn_at("e7", "a", 25, vec![write("n", Some(b"3"))])),
            ],
        ];
        let dir = tempfile::tempdir().unwrap();
        let open = |name: &str| {
            let db = StateDb::open(Connection::open(dir.path().join(name)).unwrap()).unwrap();
            // A key the window deletes.
            db.conn
                .execute(
                    "INSERT INTO kv (kind, key, k, value, lsn) VALUES ('counter', 'b', 'm', x'00', 0)",
                    [],
                )
                .unwrap();
            db
        };
        let mut normal = open("normal.db");
        for run in &runs {
            normal.apply(run).unwrap();
        }
        let mut bulk = open("bulk.db");
        bulk.begin_bulk_replay().unwrap();
        for run in &runs {
            let rows = CatchupRows::of(run, bulk.catchup_applied().unwrap())
                .unwrap()
                .unwrap();
            bulk.apply_rows(rows).unwrap();
        }
        bulk.end_bulk_replay().unwrap();
        for table in [
            "actors",
            "kv",
            "turn_index",
            "open_turns",
            "open_effects",
            "trees",
            "segments",
            "meta",
        ] {
            assert_eq!(rows_of(&bulk, table), rows_of(&normal, table), "{table}");
        }
        assert_eq!(bulk.applied_lsn().unwrap(), 7);
        assert_eq!(rows_of(&bulk, "open_turns").len(), 1);
    }

    fn tagged(subject: &str, text: &str) -> Option<pb::Sealable> {
        Some(pb::Sealable {
            subject: Some(subject.into()),
            value: Some(pb::sealable::Value::Plain(text.as_bytes().to_vec())),
        })
    }

    fn message(source: pb::MessageSource, id: &str, subject: &str) -> Option<pb::Input> {
        Some(pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: source as i32,
                message_id: id.into(),
                msg: Some(pb::Message {
                    name: "m".into(),
                    body: tagged(subject, "body"),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        })
    }

    fn with_outcome(mut r: Record, outcome: pb::Outcome) -> Record {
        if let Record::TurnRecord(t) = &mut r {
            t.outcome = Some(outcome);
        }
        r
    }

    fn reply(subject: &str) -> pb::Outcome {
        pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            output: Some(pb::outcome::Output::Reply(pb::Message {
                body: tagged(subject, "reply"),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// H9: an erasure deletes the subject's dead letters and saved ingress
    /// responses and tombstones its saved call responses; another
    /// subject's rows stay.
    #[test]
    fn erasure_reaches_saved_responses_and_dead_letters() {
        let conn = Connection::open_in_memory().unwrap();
        let mut db = StateDb::open(conn).unwrap();
        let failed = pb::Outcome {
            kind: pb::OutcomeKind::Failed as i32,
            error_code: "TURN_FAILED".into(),
            ..Default::default()
        };
        let op = pb::MessageSource::Operator;
        let idem = Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                idempotency_key: "k1".into(),
                ..Default::default()
            })),
        });
        let batch = [
            with_outcome(turn("e1", "r1", message(op, "a", "user:1")), failed.clone()),
            with_outcome(turn("e2", "r2", message(op, "b", "user:2")), failed),
            with_outcome(turn("e3", "r3", idem), reply("user:1")),
            with_outcome(
                turn("e4", "r4", message(pb::MessageSource::Call, "c1", "user:1")),
                reply("user:1"),
            ),
            Record::Erasure(pb::Erasure {
                subject: "user:1".into(),
                key_version: 1,
                ..Default::default()
            }),
        ];
        let batch: Vec<_> = batch
            .into_iter()
            .enumerate()
            .map(|(i, r)| committed(i as u64 + 1, r))
            .collect();
        db.apply(&batch[..4]).unwrap();
        assert_eq!(db.dead_letters(0, 10).unwrap().len(), 2);
        assert!(db.ingress("counter", "a", "k1").unwrap().is_some());
        db.apply(&batch[4..]).unwrap();
        let dl = db.dead_letters(0, 10).unwrap();
        assert_eq!(dl.iter().map(|d| d.lsn).collect::<Vec<_>>(), vec![2]);
        assert!(db.ingress("counter", "a", "k1").unwrap().is_none());
        // The call stays delivered; a repeat gets the tombstone, not a rerun.
        assert_eq!(db.delivery("c1").unwrap(), Some(4));
        let (lsn, o) = db.call_outcome("c1").unwrap().unwrap();
        assert_eq!((lsn, o.error_code.as_str()), (4, "SUBJECT_ERASED"));
        assert!(o.output.is_none());
    }

    /// H9: a database from before the `subject` columns gains them, filled
    /// from the blobs, and loses the rows of subjects erased before.
    #[test]
    fn old_databases_gain_subjects_and_lose_erased_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE dead_letters (
               lsn INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, input BLOB NOT NULL,
               error_code TEXT NOT NULL, message TEXT NOT NULL, resent_as INTEGER);
             CREATE TABLE ingress_keys (
               kind TEXT NOT NULL, key TEXT NOT NULL, idem_key TEXT NOT NULL,
               request_hash BLOB NOT NULL, lsn INTEGER NOT NULL, logical_time_ms INTEGER NOT NULL,
               outcome BLOB NOT NULL,
               PRIMARY KEY (kind, key, idem_key)) WITHOUT ROWID;
             CREATE TABLE deliveries (
               message_id TEXT PRIMARY KEY, lsn INTEGER NOT NULL, outcome BLOB) WITHOUT ROWID;
             CREATE TABLE erasures (
               subject TEXT PRIMARY KEY, key_version INTEGER NOT NULL, lsn INTEGER NOT NULL) WITHOUT ROWID;
             INSERT INTO erasures VALUES ('user:1', 1, 9);",
        )
        .unwrap();
        let op = pb::MessageSource::Operator;
        for (lsn, subject) in [(1, "user:1"), (2, "user:2")] {
            conn.execute(
                "INSERT INTO dead_letters VALUES (?1, 'counter', 'a', ?2, 'X', '', NULL)",
                params![lsn, message(op, "m", subject).unwrap().encode_to_vec()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO ingress_keys VALUES ('counter', 'a', ?1, x'', ?2, 0, ?3)",
                params![subject, lsn, reply(subject).encode_to_vec()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO deliveries VALUES (?1, ?2, ?3)",
                params![subject, lsn, reply(subject).encode_to_vec()],
            )
            .unwrap();
        }
        let db = StateDb::open(conn).unwrap();
        let subjects = |sql: &str| -> Vec<Option<String>> {
            let mut st = db.conn.prepare(sql).unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let two = vec![Some("user:2".to_owned())];
        assert_eq!(subjects("SELECT subject FROM dead_letters"), two);
        assert_eq!(subjects("SELECT subject FROM ingress_keys"), two);
        assert_eq!(
            subjects("SELECT subject FROM deliveries ORDER BY lsn"),
            vec![None, Some("user:2".to_owned())]
        );
        let (_, o) = db.call_outcome("user:1").unwrap().unwrap();
        assert_eq!(o.error_code, "SUBJECT_ERASED");
    }
}
