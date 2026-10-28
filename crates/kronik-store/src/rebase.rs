//! Rollback via replay (docs/design/m13-rebase.md, ADR 0017): the shadow
//! state a `StateRebase` switch installs, built from main's log alone. The
//! state at the switch's `base_lsn` (a snapshot at or before it plus main's
//! records), then main's records after it in LSN order, of which only this
//! rebase's turns and the erasures apply.

use std::path::Path;
use std::sync::Arc;

use kronik_core::ids::Lsn;
use kronik_log::Committed;
use kronik_privacy::sealer::Sealer;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

use crate::{Store, StoreError};

fn corrupt(msg: impl Into<String>) -> StoreError {
    StoreError::Corrupt(msg.into())
}

/// A shadow being built: the state at `base_lsn` plus everything fed so far.
pub struct Shadow {
    pub store: Arc<Store>,
    pub rebase_id: String,
    pub base_lsn: Lsn,
    /// The last record of main fed to the shadow.
    pub read_to: Lsn,
    /// This rebase's turns applied: first and last LSN, and how many.
    pub first_turn: Lsn,
    pub last_turn: Lsn,
    pub turns: u64,
    /// The fork LSN of the last of this rebase's turns fed.
    pub staged_fork_lsn: Lsn,
    /// The subjects erased after the base, in order.
    erased: Vec<String>,
}

impl Shadow {
    /// The state at `base_lsn`: the snapshot `snapshot` (its LSN at most
    /// `base_lsn`), or an empty store, then `records` up to `base_lsn`.
    /// `records` continue the snapshot (they start right after it, or at 1);
    /// a switch among them is rebuilt from the same records.
    pub fn at_base(
        rebase_id: &str,
        base_lsn: Lsn,
        snapshot: Option<(Lsn, &Path)>,
        records: &[Committed],
        sealer: Arc<Sealer>,
    ) -> Result<Shadow, StoreError> {
        let store = match snapshot {
            Some((lsn, _)) if lsn > base_lsn => {
                return Err(corrupt(format!(
                    "the rebase {rebase_id} needs the state at lsn {base_lsn}, but the snapshot is at {lsn}"
                )));
            }
            Some((_, dir)) => Store::open_snapshot_in_memory(dir)?,
            None => Store::memory()?,
        };
        store.set_sealer(sealer.clone());
        let upto: Vec<&Committed> = records.iter().filter(|c| c.lsn <= base_lsn).collect();
        for chunk in upto.chunks(4096) {
            let chunk: Vec<Committed> = chunk.iter().map(|c| (*c).clone()).collect();
            store.apply_with(&chunk, &mut |c| {
                let (id, sw) = c
                    .record
                    .rebase_switch()
                    .ok_or_else(|| corrupt("not a switch"))?;
                shadow_for(id, sw, c.lsn, snapshot, records, sealer.clone())
            })?;
        }
        if store.applied.get() != base_lsn {
            return Err(corrupt(format!(
                "the rebase {rebase_id} needs main's log up to lsn {base_lsn}, but it ends at {}",
                store.applied.get()
            )));
        }
        store.db().set_allow_gaps();
        Ok(Shadow {
            store,
            rebase_id: rebase_id.to_owned(),
            base_lsn,
            read_to: base_lsn,
            first_turn: 0,
            last_turn: 0,
            turns: 0,
            staged_fork_lsn: 0,
            erased: Vec::new(),
        })
    }

    /// Feeds main's records after the base, in LSN order: this rebase's
    /// turns are applied as turn records at their own LSN and position,
    /// erasures as erasures; everything else changes nothing here.
    pub fn feed(&mut self, records: &[Committed]) -> Result<(), StoreError> {
        let mut apply = Vec::new();
        for c in records {
            if c.lsn <= self.read_to {
                continue;
            }
            self.read_to = c.lsn;
            match &c.record {
                Record::StateRebase(r) if r.rebase_id == self.rebase_id => {
                    if let Some(pb::state_rebase::Part::Turn(t)) = &r.part {
                        let record = t
                            .record
                            .clone()
                            .ok_or_else(|| corrupt("a rebased turn without its record"))?;
                        if self.turns == 0 {
                            self.first_turn = c.lsn;
                        }
                        self.last_turn = c.lsn;
                        self.turns += 1;
                        self.staged_fork_lsn = t.fork_lsn;
                        apply.push(Committed {
                            lsn: c.lsn,
                            pos: c.pos,
                            record: Record::TurnRecord(record),
                        });
                    }
                }
                Record::Erasure(e) => {
                    self.erased.push(e.subject.clone());
                    apply.push(c.clone());
                }
                _ => {}
            }
        }
        for chunk in apply.chunks(4096) {
            self.store.apply(chunk)?;
        }
        Ok(())
    }

    /// The switch names the turns this shadow applied.
    pub fn check(&self, sw: &pb::RebaseSwitch) -> Result<(), StoreError> {
        if (self.first_turn, self.last_turn, self.turns)
            != (sw.first_turn_lsn, sw.last_turn_lsn, sw.turns)
        {
            return Err(corrupt(format!(
                "the rebase {} switch names turns {}..={} ({}), the log holds {}..={} ({})",
                self.rebase_id,
                sw.first_turn_lsn,
                sw.last_turn_lsn,
                sw.turns,
                self.first_turn,
                self.last_turn,
                self.turns
            )));
        }
        Ok(())
    }

    /// Before the switch installs it: [`Shadow::check`], then every
    /// erasure after the base again. Turns staged after an erasure (the
    /// replay of inputs before it) must not bring the subject's values
    /// back (m13-rebase §3).
    pub fn finish(&self, sw: &pb::RebaseSwitch) -> Result<(), StoreError> {
        self.check(sw)?;
        for subject in &self.erased {
            self.store.erase_again(subject)?;
        }
        Ok(())
    }
}

/// The shadow of the switch `id` at `lsn`, from `records` (continuing
/// `snapshot`, through at least `lsn - 1`).
pub fn shadow_for(
    id: &str,
    sw: &pb::RebaseSwitch,
    lsn: Lsn,
    snapshot: Option<(Lsn, &Path)>,
    records: &[Committed],
    sealer: Arc<Sealer>,
) -> Result<Arc<Store>, StoreError> {
    let mut s = Shadow::at_base(id, sw.base_lsn, snapshot, records, sealer)?;
    let after: Vec<Committed> = records
        .iter()
        .filter(|c| c.lsn > sw.base_lsn && c.lsn < lsn)
        .cloned()
        .collect();
    s.feed(&after)?;
    s.finish(sw)?;
    Ok(s.store)
}

#[cfg(test)]
mod tests;
