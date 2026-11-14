//! The blob index (M26 §5, ADR 0120 §1): which blobs committed records
//! reference, and which rows of other tables keep one. The applier writes it
//! in the transaction of each record; the retention pass compacts it; the
//! collector and the API read it.
//!
//! - `blobs`: every blob a committed record references, with the LSN of the
//!   first and of the last record that does (`last_ref_lsn`), and whether
//!   its subject was erased through its key version.
//! - `blob_pins`: rows of other tables that reference a blob, inserted and
//!   deleted with the rows they mirror: 1 a queued message or compensation
//!   (`mailbox`), 2 a scheduled timer, 3 a dead letter, 4 a saved idempotent
//!   response, 5 a saved `call` outcome (`deliveries`), 6 an open turn's
//!   input and 7 an open turn's recorded effect.
//! - `blob_refs` (M26): what each actor holds (`retain`, `put`), from the
//!   `RETAIN` and `RELEASE` operations of its committed turns.
//!
//! - `blob_releases`: the last `RELEASE` of each blob (who, at which LSN),
//!   so the dry run can say who let a blob go once its records are gone.
//!
//! `blobs`, `blob_pins` and `blob_releases` are bookkeeping, like the
//! positions of open turns, and not in the state hash; `blob_refs` is (M26
//! §5.3).

use kronik_core::ids::Lsn;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use rusqlite::{Connection, OptionalExtension, params};

use super::{StateDb, corrupt, i};
use crate::StoreError;

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS blobs (
  hash TEXT PRIMARY KEY, size INTEGER NOT NULL, subject TEXT, key_version INTEGER NOT NULL,
  first_lsn INTEGER NOT NULL, last_ref_lsn INTEGER NOT NULL,
  erased INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blobs_subject ON blobs (subject) WHERE subject IS NOT NULL;
CREATE TABLE IF NOT EXISTS blob_pins (
  hash TEXT NOT NULL, source INTEGER NOT NULL, owner TEXT NOT NULL, lsn INTEGER NOT NULL,
  PRIMARY KEY (hash, source, owner)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blob_pins_owner ON blob_pins (source, owner);
CREATE TABLE IF NOT EXISTS blob_refs (
  kind TEXT NOT NULL, key TEXT NOT NULL, hash TEXT NOT NULL, lsn INTEGER NOT NULL,
  PRIMARY KEY (kind, key, hash)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blob_refs_hash ON blob_refs (hash);
CREATE TABLE IF NOT EXISTS blob_releases (
  hash TEXT PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, lsn INTEGER NOT NULL)
  WITHOUT ROWID;
";

/// The pin sources of M26 §5.1. M25 writes 4, 6 and 7.
pub mod source {
    pub const MAILBOX: i64 = 1;
    pub const TIMER: i64 = 2;
    pub const DEAD_LETTER: i64 = 3;
    pub const INGRESS_KEY: i64 = 4;
    pub const DELIVERY: i64 = 5;
    pub const OPEN_TURN: i64 = 6;
    pub const OPEN_EFFECT: i64 = 7;

    /// The name of a source in the API (`kronik blobs inspect`).
    pub fn name(source: i64) -> &'static str {
        match source {
            MAILBOX => "message",
            TIMER => "timer",
            DEAD_LETTER => "dead-letter",
            INGRESS_KEY => "saved-response",
            DELIVERY => "saved-call",
            OPEN_TURN => "open-turn",
            OPEN_EFFECT => "open-effect",
            _ => "unknown",
        }
    }
}

/// The SQL condition that a `blobs` row (aliased `blobs`) is kept by the
/// state: a pin or a hold.
const KEPT_BY_STATE: &str = "(EXISTS (SELECT 1 FROM blob_pins p WHERE p.hash = blobs.hash) \
     OR EXISTS (SELECT 1 FROM blob_refs h WHERE h.hash = blobs.hash))";

/// The owner of the pins of a saved idempotent response: the ingress key's
/// row, its fields separated by the unit separator, which none of them
/// contains.
fn ingress_owner(kind: &str, key: &str, idempotency_key: &str) -> String {
    format!("{kind}\u{1f}{key}\u{1f}{idempotency_key}")
}

/// The owner of the pins of an open turn's recorded effect.
fn effect_owner(execution_id: &str, ordinal: u32) -> String {
    format!("{execution_id}/{ordinal}")
}

/// The owner of the pins of a scheduled timer.
fn timer_owner(kind: &str, key: &str, timer_id: i64) -> String {
    format!("{kind}\u{1f}{key}\u{1f}{timer_id}")
}

/// Pins the blobs of `input`, a message waiting in the mailbox as
/// `message_id` (source 1).
pub(super) fn pin_message(
    tx: &Connection,
    message_id: &str,
    input: &pb::Input,
    lsn: i64,
) -> Result<(), StoreError> {
    let mut refs = Vec::new();
    kronik_proto::blobs::input(Some(input), &mut refs);
    for r in refs {
        pin(tx, &r.hash, source::MAILBOX, message_id, lsn as Lsn)?;
    }
    Ok(())
}

/// Pins the blobs of a timer's message (source 2), replacing the pins of a
/// timer of the same id.
pub(super) fn pin_timer(
    tx: &Connection,
    kind: &str,
    key: &str,
    timer_id: i64,
    msg: &pb::Message,
    lsn: i64,
) -> Result<(), StoreError> {
    let owner = timer_owner(kind, key, timer_id);
    unpin(tx, source::TIMER, &owner)?;
    for r in &msg.blobs {
        pin(tx, &r.hash, source::TIMER, &owner, lsn as Lsn)?;
    }
    Ok(())
}

/// Unpins a timer that fired or was cancelled.
pub(super) fn unpin_timer(
    tx: &Connection,
    kind: &str,
    key: &str,
    timer_id: i64,
) -> Result<(), StoreError> {
    unpin(tx, source::TIMER, &timer_owner(kind, key, timer_id))
}

/// Pins the blobs of a dead letter's input (source 3), owner its LSN.
pub(super) fn pin_dead_letter(
    tx: &Connection,
    lsn: i64,
    input: &pb::Input,
) -> Result<(), StoreError> {
    let mut refs = Vec::new();
    kronik_proto::blobs::input(Some(input), &mut refs);
    let owner = lsn.to_string();
    for r in refs {
        pin(tx, &r.hash, source::DEAD_LETTER, &owner, lsn as Lsn)?;
    }
    Ok(())
}

/// Pins the blobs of a saved `call` outcome (source 5), owner the call's
/// message id.
pub(super) fn pin_delivery(
    tx: &Connection,
    message_id: &str,
    outcome: &pb::Outcome,
    lsn: i64,
) -> Result<(), StoreError> {
    let mut refs = Vec::new();
    kronik_proto::blobs::outcome(Some(outcome), &mut refs);
    for r in refs {
        pin(tx, &r.hash, source::DELIVERY, message_id, lsn as Lsn)?;
    }
    Ok(())
}

/// Deletes the pins of one row.
pub(super) fn unpin(tx: &Connection, source: i64, owner: &str) -> Result<(), StoreError> {
    tx.prepare_cached("DELETE FROM blob_pins WHERE source = ?1 AND owner = ?2")?
        .execute(params![source, owner])?;
    Ok(())
}

/// Deletes the pins of rows of `source` that are gone: rows other than the
/// usual paths delete (an erasure, the cap on connection dead letters, a
/// rebase switch). Each source's rows by their owner.
pub(super) fn prune_orphan_pins(tx: &Connection, source: i64) -> Result<u64, StoreError> {
    let exists = match source {
        source::MAILBOX => "EXISTS (SELECT 1 FROM mailbox m WHERE m.message_id = blob_pins.owner)",
        source::TIMER => {
            "EXISTS (SELECT 1 FROM timers t WHERE t.kind || char(31) || t.key || char(31) || \
             t.timer_id = blob_pins.owner)"
        }
        source::DEAD_LETTER => {
            "EXISTS (SELECT 1 FROM dead_letters d WHERE CAST(d.lsn AS TEXT) = blob_pins.owner \
             AND d.resent_as IS NULL)"
        }
        source::INGRESS_KEY => {
            "EXISTS (SELECT 1 FROM ingress_keys k WHERE k.kind || char(31) || k.key || char(31) \
             || k.idem_key = blob_pins.owner)"
        }
        source::DELIVERY => {
            "EXISTS (SELECT 1 FROM deliveries d WHERE d.message_id = blob_pins.owner)"
        }
        _ => return Ok(0),
    };
    let deleted = tx.execute(
        &format!("DELETE FROM blob_pins WHERE source = ?1 AND NOT {exists}"),
        [source],
    )?;
    Ok(deleted as u64)
}

/// The holds of a committed turn (M26 §3, §4): `RETAIN` adds the actor's
/// hold (a hold it has stays as it was), `RELEASE` ends it. A failed turn
/// holds nothing new and lets nothing go: it records no operation.
fn apply_holds(tx: &Connection, lsn: Lsn, t: &pb::TurnRecord) -> Result<(), StoreError> {
    if t.blob_refs.is_empty() {
        return Ok(());
    }
    let committed = t
        .outcome
        .as_ref()
        .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32);
    if !committed {
        return Err(corrupt(format!(
            "the failed turn at lsn {lsn} records blob reference operations"
        )));
    }
    let actor = t
        .actor
        .as_ref()
        .ok_or_else(|| corrupt("turn record without actor"))?;
    for op in &t.blob_refs {
        let blob = op.blob.as_ref().ok_or_else(|| {
            corrupt(format!(
                "a blob reference operation at lsn {lsn} without its blob"
            ))
        })?;
        match pb::blob_ref_op::Kind::try_from(op.kind) {
            Ok(pb::blob_ref_op::Kind::Retain) => {
                tx.prepare_cached(
                    "INSERT OR IGNORE INTO blob_refs (kind, key, hash, lsn) VALUES (?1, ?2, ?3, ?4)",
                )?
                .execute(params![actor.kind, actor.key, blob.hash, i(lsn)])?;
            }
            Ok(pb::blob_ref_op::Kind::Release) => {
                tx.prepare_cached(
                    "DELETE FROM blob_refs WHERE kind = ?1 AND key = ?2 AND hash = ?3",
                )?
                .execute(params![actor.kind, actor.key, blob.hash])?;
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO blob_releases (hash, kind, key, lsn) \
                     VALUES (?1, ?2, ?3, ?4)",
                )?
                .execute(params![blob.hash, actor.kind, actor.key, i(lsn)])?;
            }
            _ => {
                return Err(corrupt(format!(
                    "a blob reference operation of kind {} at lsn {lsn}",
                    op.kind
                )));
            }
        }
    }
    Ok(())
}

/// One blob of the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRow {
    pub hash: String,
    pub size: u64,
    pub subject: Option<String>,
    pub key_version: u32,
    pub first_lsn: Lsn,
    pub last_ref_lsn: Lsn,
    pub erased: bool,
}

/// One pin of a blob: its source, its owner and the LSN that set it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobPin {
    pub source: i64,
    pub owner: String,
    pub lsn: Lsn,
}

/// Adds `r` to the index, or raises its last reference to `lsn`. A
/// reference whose size, subject or key version differs from the row's is
/// a damaged log (`STORAGE_CORRUPT`): one identity has one content.
fn index_ref(tx: &Connection, lsn: Lsn, r: &pb::BlobRef) -> Result<(), StoreError> {
    let existing: Option<(i64, Option<String>, i64)> = tx
        .prepare_cached("SELECT size, subject, key_version FROM blobs WHERE hash = ?1")?
        .query_row([&r.hash], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .optional()?;
    match existing {
        Some((size, subject, key_version)) => {
            if size != i(r.size) || subject != r.subject || key_version != i64::from(r.key_version)
            {
                return Err(corrupt(format!(
                    "blob {} at lsn {lsn} differs from its earlier references (size, subject or \
                     key version)",
                    r.hash
                )));
            }
            tx.prepare_cached(
                "UPDATE blobs SET last_ref_lsn = max(last_ref_lsn, ?2) WHERE hash = ?1",
            )?
            .execute(params![r.hash, i(lsn)])?;
        }
        None => {
            // A subject erased through this key version before the blob was
            // first referenced: its bytes are gone (a rebuild, a restore).
            let erased = match &r.subject {
                Some(subject) => tx
                    .prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM erasures WHERE subject = ?1 AND key_version >= ?2)",
                    )?
                    .query_row(params![subject, i64::from(r.key_version)], |row| row.get(0))?,
                None => false,
            };
            tx.prepare_cached(
                "INSERT INTO blobs (hash, size, subject, key_version, first_lsn, last_ref_lsn, erased) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
            )?
            .execute(params![
                r.hash,
                i(r.size),
                r.subject,
                i64::from(r.key_version),
                i(lsn),
                erased
            ])?;
        }
    }
    Ok(())
}

fn pin(tx: &Connection, hash: &str, source: i64, owner: &str, lsn: Lsn) -> Result<(), StoreError> {
    tx.prepare_cached(
        "INSERT OR IGNORE INTO blob_pins (hash, source, owner, lsn) VALUES (?1, ?2, ?3, ?4)",
    )?
    .execute(params![hash, source, owner, i(lsn)])?;
    Ok(())
}

/// The index work of one record (M26 §5.2), in the applier's transaction:
/// every reference into `blobs`; the pins of an open turn's input (6) and of
/// its recorded effects (7), unless the turn begins and ends in the batch
/// (`closed`); a turn's record deletes them and replaces the pins of its
/// saved idempotent response (4).
pub(super) fn apply(
    tx: &Connection,
    lsn: Lsn,
    record: &Record,
    closed: bool,
) -> Result<(), StoreError> {
    let refs = kronik_proto::blobs::refs(record);
    for r in &refs {
        index_ref(tx, lsn, r)?;
    }
    match record {
        Record::TurnBegin(b) if !closed => {
            for r in &refs {
                pin(tx, &r.hash, source::OPEN_TURN, &b.execution_id, lsn)?;
            }
        }
        Record::EffectResult(e) if !closed => {
            if let Some(effect) = &e.effect {
                let owner = effect_owner(&e.execution_id, effect.ordinal);
                for r in &refs {
                    pin(tx, &r.hash, source::OPEN_EFFECT, &owner, lsn)?;
                }
            }
        }
        Record::TurnRecord(t) => {
            apply_holds(tx, lsn, t)?;
            unpin_execution(tx, &t.execution_id)?;
            if let (Some(actor), Some(pb::input::Kind::Http(h))) = (
                t.actor.as_ref(),
                t.input.as_ref().and_then(|input| input.kind.as_ref()),
            ) && !h.idempotency_key.is_empty()
            {
                let owner = ingress_owner(&actor.kind, &actor.key, &h.idempotency_key);
                tx.prepare_cached("DELETE FROM blob_pins WHERE source = ?1 AND owner = ?2")?
                    .execute(params![source::INGRESS_KEY, owner])?;
                let mut saved = Vec::new();
                kronik_proto::blobs::outcome(t.outcome.as_ref(), &mut saved);
                for r in saved {
                    pin(tx, &r.hash, source::INGRESS_KEY, &owner, lsn)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Deletes the pins of an open turn and of its recorded effects.
fn unpin_execution(tx: &Connection, execution_id: &str) -> Result<(), StoreError> {
    tx.prepare_cached("DELETE FROM blob_pins WHERE source = ?1 AND owner = ?2")?
        .execute(params![source::OPEN_TURN, execution_id])?;
    // Owners `<execution id>/<ordinal>`: the range after "<id>/" and before
    // "<id>0" ('0' follows '/').
    tx.prepare_cached(
        "DELETE FROM blob_pins WHERE source = ?1 AND owner >= ?2 || '/' AND owner < ?2 || '0'",
    )?
    .execute(params![source::OPEN_EFFECT, execution_id])?;
    Ok(())
}

/// A rebase switch (ADR 0017) replaces the rows of the rebased actors, the
/// mailbox, the dead letters and the deliveries after `base` with the
/// shadow's: their holds and pins follow, and the blobs the shadow's rows
/// reference join the index (M26 §5.2).
pub(super) fn apply_switch(
    shadow: &Connection,
    tx: &Connection,
    actors: &[(String, String)],
    base: i64,
) -> Result<(), StoreError> {
    let copy = |sql_main: &str,
                sql_shadow: &str,
                params: &[&dyn rusqlite::ToSql]|
     -> Result<(), StoreError> {
        tx.execute(sql_main, params)?;
        let mut st = shadow.prepare(sql_shadow)?;
        let mut rows = st.query(params)?;
        while let Some(r) = rows.next()? {
            tx.prepare_cached(
                "INSERT OR REPLACE INTO blob_pins (hash, source, owner, lsn) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?
            ])?;
        }
        Ok(())
    };
    // The mailbox and the dead letters are replaced whole.
    for s in [source::MAILBOX, source::DEAD_LETTER] {
        copy(
            "DELETE FROM blob_pins WHERE source = ?1",
            "SELECT hash, source, owner, lsn FROM blob_pins WHERE source = ?1",
            &[&s],
        )?;
    }
    // Deliveries after the base.
    copy(
        "DELETE FROM blob_pins WHERE source = ?1 AND lsn > ?2",
        "SELECT hash, source, owner, lsn FROM blob_pins WHERE source = ?1 AND lsn > ?2",
        &[&source::DELIVERY, &base],
    )?;
    for (kind, key) in actors {
        // The rebased actors' timers and holds.
        let prefix = format!("{kind}\u{1f}{key}\u{1f}");
        copy(
            "DELETE FROM blob_pins WHERE source = ?1 AND owner >= ?2 AND owner < ?2 || char(127)",
            "SELECT hash, source, owner, lsn FROM blob_pins WHERE source = ?1 AND owner >= ?2 \
             AND owner < ?2 || char(127)",
            &[&source::TIMER, &prefix],
        )?;
        tx.execute(
            "DELETE FROM blob_refs WHERE kind = ?1 AND key = ?2",
            params![kind, key],
        )?;
        let mut st =
            shadow.prepare("SELECT hash, lsn FROM blob_refs WHERE kind = ?1 AND key = ?2")?;
        let rows = st.query_map(params![kind, key], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (hash, lsn) = row?;
            tx.prepare_cached(
                "INSERT INTO blob_refs (kind, key, hash, lsn) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![kind, key, hash, lsn])?;
        }
    }
    // The shadow's releases (bookkeeping, as the index).
    {
        let mut st = shadow.prepare("SELECT hash, kind, key, lsn FROM blob_releases")?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            tx.prepare_cached(
                "INSERT OR REPLACE INTO blob_releases (hash, kind, key, lsn) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?
            ])?;
        }
    }
    // Every blob the shadow knows that main does not, and later references.
    let mut st = shadow.prepare(
        "SELECT hash, size, subject, key_version, first_lsn, last_ref_lsn, erased FROM blobs",
    )?;
    let mut rows = st.query([])?;
    while let Some(r) = rows.next()? {
        tx.prepare_cached(
            "INSERT INTO blobs (hash, size, subject, key_version, first_lsn, last_ref_lsn, erased) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (hash) DO UPDATE SET \
             last_ref_lsn = max(last_ref_lsn, excluded.last_ref_lsn), \
             erased = max(erased, excluded.erased)",
        )?
        .execute(params![
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, bool>(6)?
        ])?;
    }
    Ok(())
}

/// The prefix range of the hashes in shard `shard` (two hex characters):
/// the first byte of the digest names the shard, in `b3:` and `b3s:`.
fn shard_ranges(shard: &str) -> [(String, String); 2] {
    ["b3:", "b3s:"].map(|prefix| {
        let low = format!("{prefix}{shard}");
        let high = format!("{low}\u{7f}");
        (low, high)
    })
}

impl StateDb {
    /// The blob index's part of a retention pass (M26 §5.4): the pins of
    /// saved responses whose row is gone (expired or erased), of rows other
    /// paths deleted, and of saved `call` outcomes below `floor` that no
    /// open turn that began before them may still repeat. The rows that
    /// nothing keeps go after the collector's sweep has deleted their files
    /// ([`StateDb::forget_blobs`]), so that its dry run can still say why a
    /// file has no root. Returns how many pins it deleted.
    pub fn prune_blob_pins(&mut self, floor: Lsn) -> Result<u64, StoreError> {
        let tx = self.conn.savepoint()?;
        let mut deleted = 0;
        for s in [
            source::MAILBOX,
            source::TIMER,
            source::DEAD_LETTER,
            source::INGRESS_KEY,
            source::DELIVERY,
        ] {
            deleted += prune_orphan_pins(&tx, s)?;
        }
        deleted += tx.execute(
            "DELETE FROM blob_pins WHERE source = ?1 AND lsn < ?2 \
             AND NOT EXISTS (SELECT 1 FROM open_turns o WHERE o.lsn < blob_pins.lsn)",
            params![source::DELIVERY, i(floor)],
        )? as u64;
        tx.commit()?;
        Ok(deleted)
    }

    /// The rows that no root of the index keeps: erased, or neither kept by
    /// the state nor referenced at or above `floor`.
    pub fn unrooted_blobs(&self, floor: Lsn) -> Result<Vec<String>, StoreError> {
        let mut statement = self.conn.prepare_cached(&format!(
            "SELECT hash FROM blobs WHERE erased = 1 OR (last_ref_lsn < ?1 AND NOT {KEPT_BY_STATE}) \
             ORDER BY hash"
        ))?;
        let rows = statement.query_map([i(floor)], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Deletes the rows of `hashes` that are still unrooted at `floor` (a
    /// record applied meanwhile keeps its row). An erased blob's row stays
    /// while a hold or a pin keeps it: they still name it, and a read of it
    /// must answer `erased`, not that the actor does not hold it (M26 §9.3).
    /// Returns how many it deleted.
    pub fn forget_blobs(&mut self, hashes: &[String], floor: Lsn) -> Result<u64, StoreError> {
        let tx = self.conn.savepoint()?;
        let mut deleted = 0;
        {
            let mut statement = tx.prepare_cached(&format!(
                "DELETE FROM blobs WHERE hash = ?1 AND NOT {KEPT_BY_STATE} \
                 AND (erased = 1 OR last_ref_lsn < ?2)"
            ))?;
            for hash in hashes {
                deleted += statement.execute(params![hash, i(floor)])? as u64;
            }
        }
        tx.execute(
            "DELETE FROM blob_releases WHERE NOT EXISTS \
             (SELECT 1 FROM blobs b WHERE b.hash = blob_releases.hash)",
            [],
        )?;
        tx.commit()?;
        Ok(deleted)
    }

    /// Who released `hash` last, and at which LSN (`kind`, `key`, `lsn`):
    /// the dry run's `released_by` (M26 §6.6).
    pub fn released_by(&self, hash: &str) -> Result<Option<(String, String, Lsn)>, StoreError> {
        Ok(self
            .conn
            .prepare_cached("SELECT kind, key, lsn FROM blob_releases WHERE hash = ?1")?
            .query_row([hash], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as Lsn))
            })
            .optional()?)
    }

    /// One blob of the index.
    pub fn blob(&self, hash: &str) -> Result<Option<BlobRow>, StoreError> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT hash, size, subject, key_version, first_lsn, last_ref_lsn, erased \
                 FROM blobs WHERE hash = ?1",
            )?
            .query_row([hash], row)
            .optional()?)
    }

    /// The pins of a blob, oldest first.
    pub fn blob_pins(&self, hash: &str) -> Result<Vec<BlobPin>, StoreError> {
        let mut statement = self.conn.prepare_cached(
            "SELECT source, owner, lsn FROM blob_pins WHERE hash = ?1 ORDER BY lsn, source, owner",
        )?;
        let pins = statement.query_map([hash], |r| {
            Ok(BlobPin {
                source: r.get(0)?,
                owner: r.get(1)?,
                lsn: r.get::<_, i64>(2)? as Lsn,
            })
        })?;
        Ok(pins.collect::<Result<_, _>>()?)
    }

    /// The hashes in shard `shard` (two hex characters) that the index
    /// keeps: every row that is not erased and that the state keeps or
    /// whose last reference is at or above `floor` (ADR 0120 §3).
    pub fn rooted_blobs_in_shard(
        &self,
        shard: &str,
        floor: Lsn,
    ) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        let mut statement = self.conn.prepare_cached(&format!(
            "SELECT hash FROM blobs WHERE hash >= ?1 AND hash < ?2 AND erased = 0 \
             AND (last_ref_lsn >= ?3 OR {KEPT_BY_STATE}) ORDER BY hash"
        ))?;
        for (low, high) in shard_ranges(shard) {
            let rows =
                statement.query_map(params![low, high, i(floor)], |r| r.get::<_, String>(0))?;
            for hash in rows {
                out.push(hash?);
            }
        }
        Ok(out)
    }

    /// The rows of shard `shard`, for the collector's dry run.
    pub fn blobs_in_shard(&self, shard: &str) -> Result<Vec<BlobRow>, StoreError> {
        let mut out = Vec::new();
        let mut statement = self.conn.prepare_cached(
            "SELECT hash, size, subject, key_version, first_lsn, last_ref_lsn, erased \
             FROM blobs WHERE hash >= ?1 AND hash < ?2 ORDER BY hash",
        )?;
        for (low, high) in shard_ranges(shard) {
            for r in statement.query_map(params![low, high], row)? {
                out.push(r?);
            }
        }
        Ok(out)
    }

    /// Whether the state keeps `hash` (a pin; M26: a hold).
    pub fn blob_kept_by_state(&self, hash: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM blob_pins WHERE hash = ?1)")?
            .query_row([hash], |r| r.get(0))?)
    }

    /// The identities this state roots, for a snapshot's `blobs.idx` and a
    /// fork's `blobs.roots` (M26 §7): pinned (M26: or held), not erased,
    /// sorted.
    pub fn state_blob_roots(&self) -> Result<Vec<String>, StoreError> {
        Ok(Self::roots_of(&self.conn)?
            .into_iter()
            .map(|(hash, _)| hash)
            .collect())
    }

    /// [`StateDb::state_blob_roots`] of any connection to a state database,
    /// with each blob's size.
    pub(crate) fn roots_of(conn: &Connection) -> Result<Vec<(String, u64)>, StoreError> {
        let mut statement = conn.prepare(&format!(
            "SELECT hash, size FROM blobs WHERE erased = 0 AND {KEPT_BY_STATE} ORDER BY hash"
        ))?;
        let rows = statement.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The complete reference of `hash` when the actor `kind`/`key` holds it
    /// (M26 §2).
    pub fn held(
        &self,
        kind: &str,
        key: &str,
        hash: &str,
    ) -> Result<Option<pb::BlobRef>, StoreError> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT b.size, b.subject, b.key_version FROM blob_refs h JOIN blobs b \
                 ON b.hash = h.hash WHERE h.kind = ?1 AND h.key = ?2 AND h.hash = ?3",
            )?
            .query_row(params![kind, key, hash], |r| {
                Ok(pb::BlobRef {
                    hash: hash.to_owned(),
                    size: r.get::<_, i64>(0)? as u64,
                    subject: r.get(1)?,
                    key_version: r.get::<_, i64>(2)? as u32,
                })
            })
            .optional()?)
    }

    /// The bytes of the distinct blobs the actor `kind`/`key` holds, for
    /// its quota (ADR 0117 §8).
    pub fn held_bytes(&self, kind: &str, key: &str) -> Result<u64, StoreError> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT coalesce(sum(b.size), 0) FROM blob_refs h JOIN blobs b ON b.hash = h.hash \
                 WHERE h.kind = ?1 AND h.key = ?2",
            )?
            .query_row(params![kind, key], |r| r.get::<_, i64>(0))? as u64)
    }

    /// The holds of the actor `kind`/`key`, by hash, from `after` on, at
    /// most `limit` (`kronik blobs list --actor`).
    pub fn holds(
        &self,
        kind: &str,
        key: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<(pb::BlobRef, Lsn)>, StoreError> {
        let mut st = self.conn.prepare_cached(
            "SELECT h.hash, b.size, b.subject, b.key_version, h.lsn FROM blob_refs h \
             JOIN blobs b ON b.hash = h.hash WHERE h.kind = ?1 AND h.key = ?2 AND h.hash > ?3 \
             ORDER BY h.hash LIMIT ?4",
        )?;
        let rows = st.query_map(params![kind, key, after, limit as i64], |r| {
            Ok((
                pb::BlobRef {
                    hash: r.get(0)?,
                    size: r.get::<_, i64>(1)? as u64,
                    subject: r.get(2)?,
                    key_version: r.get::<_, i64>(3)? as u32,
                },
                r.get::<_, i64>(4)? as Lsn,
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every blob first referenced at or before `lsn`, not erased, sorted:
    /// a superset of what the state at `lsn` roots, for a fork's
    /// `blobs.roots` when that state is not at hand.
    pub fn blobs_referenced_through(&self, lsn: Lsn) -> Result<Vec<String>, StoreError> {
        let mut statement = self.conn.prepare_cached(
            "SELECT hash FROM blobs WHERE first_lsn <= ?1 AND erased = 0 ORDER BY hash",
        )?;
        let rows = statement.query_map([i(lsn)], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The number of blobs in the index and their bytes (not erased).
    pub fn blob_totals(&self) -> Result<(u64, u64), StoreError> {
        Ok(self.conn.query_row(
            "SELECT count(*), coalesce(sum(size), 0) FROM blobs WHERE erased = 0",
            [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )?)
    }
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<BlobRow> {
    Ok(BlobRow {
        hash: r.get(0)?,
        size: r.get::<_, i64>(1)? as u64,
        subject: r.get(2)?,
        key_version: r.get::<_, i64>(3)? as u32,
        first_lsn: r.get::<_, i64>(4)? as Lsn,
        last_ref_lsn: r.get::<_, i64>(5)? as Lsn,
        erased: r.get(6)?,
    })
}

/// Whether `record` references a blob: the bulk catch-up path, which keeps
/// no index, leaves such records to the applier.
pub(super) fn references_blobs(record: &Record) -> bool {
    !kronik_proto::blobs::refs(record).is_empty()
}

#[cfg(test)]
#[path = "blobs_tests.rs"]
mod tests;
