//! Rollback via replay on main (docs/design/m13-rebase.md, ADR 0017, ADR
//! 0018): the shadow a `StateRebase` switch installs, the applier's use of
//! it, the staging of the fork's turns and the bounded pause of the switch.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{CodeHash, Lsn};
use kronik_log::{Committed, LogReader};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_store::rebase::Shadow;
use kronik_store::{Store, StoreError};

use crate::node::Node;
use crate::node::{internal, store_err};

/// What staging the fork turn `record` of rebase `id` writes to main's log,
/// at most (review N13-2, round 3): the turn wrapped in its StateRebase
/// record (the id, the fork LSN and two message headers), the log frame (17
/// bytes), and a quarter more for sealing its values (a key id, a nonce and
/// a tag each).
pub fn rebase_turn_bytes(id: &str, record: &pb::TurnRecord) -> u64 {
    let wrapped = prost::Message::encoded_len(record) as u64 + id.len() as u64 + 32;
    wrapped + wrapped / 4 + 17 + 64
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn stale(msg: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::ProposalStale, msg).with_hint(
        "Run the promote again; the turns already written are reused. If this keeps \
         happening, raise [rebase] max_pause in kronik.toml.",
    )
}

/// What the applier needs for a switch: the log, the snapshots, and the
/// shadow of the rebase being promoted on this node.
#[derive(Clone)]
pub(crate) struct RebaseCtx {
    pub(crate) reader: LogReader,
    snapshots: Option<PathBuf>,
    live: Arc<Mutex<Option<Shadow>>>,
}

impl RebaseCtx {
    pub(crate) fn new(reader: LogReader, snapshots: Option<PathBuf>) -> RebaseCtx {
        RebaseCtx {
            reader,
            snapshots,
            live: Arc::new(Mutex::new(None)),
        }
    }

    /// Applies a batch, building the shadow of every switch in it: the live
    /// shadow when this node prepared it, else from the log (recovery).
    pub(crate) async fn apply(&self, store: &Store, batch: &[Committed]) -> Result<(), StoreError> {
        if batch.iter().all(|c| c.record.rebase_switch().is_none()) {
            return store.apply(batch);
        }
        let mut shadows: HashMap<Lsn, Arc<Store>> = HashMap::new();
        for c in batch {
            let Some((id, sw)) = c.record.rebase_switch() else {
                continue;
            };
            if c.lsn <= store.applied.get() {
                // Applied; an actor database that lost its copy (a power
                // loss) gets it again from the log's shadow.
                if !store.lost_copies(c.lsn, sw)?.is_empty() {
                    let shadow = self.shadow_from_log(store, id, sw, c.lsn).await?;
                    shadows.insert(c.lsn, shadow);
                }
                continue;
            }
            let live = lock(&self.live)
                .as_ref()
                .filter(|s| s.rebase_id == id)
                .map(|s| s.read_to);
            let shadow = match live {
                // The shadow this node prepared: fed up to the switch.
                Some(read_to) => {
                    let gap = self.read(read_to, c.lsn - 1).await?;
                    let mut guard = lock(&self.live);
                    let s = guard
                        .as_mut()
                        .filter(|s| s.rebase_id == id)
                        .ok_or_else(|| StoreError::Corrupt(format!("rebase {id} shadow gone")))?;
                    s.feed(&gap)?;
                    s.finish(sw)?;
                    s.store.clone()
                }
                None => self.shadow_from_log(store, id, sw, c.lsn).await?,
            };
            shadows.insert(c.lsn, shadow);
        }
        store.apply_with(batch, &mut |c| {
            shadows
                .get(&c.lsn)
                .cloned()
                .ok_or_else(|| StoreError::Corrupt(format!("no shadow for lsn {}", c.lsn)))
        })
    }

    /// The newest snapshot at or before `lsn`, if snapshots are kept.
    fn snapshot_at_most(&self, lsn: Lsn) -> Option<(Lsn, PathBuf)> {
        let dir = self.snapshots.as_ref()?;
        let mut best: Option<(Lsn, PathBuf)> = None;
        for e in std::fs::read_dir(dir).ok()?.flatten() {
            let Ok(at) = e.file_name().to_string_lossy().parse::<Lsn>() else {
                continue;
            };
            if at <= lsn
                && e.path().join("manifest.json").exists()
                && best.as_ref().is_none_or(|(b, _)| at > *b)
            {
                best = Some((at, e.path()));
            }
        }
        best
    }

    /// The records after `from` through `to`, in order.
    async fn read(&self, from: Lsn, to: Lsn) -> Result<Vec<Committed>, StoreError> {
        let mut out = Vec::new();
        if to > from {
            self.reader
                .read(from + 1, to, |c| {
                    out.push(c);
                    Ok(())
                })
                .await
                .map_err(|e| StoreError::Corrupt(format!("reading the log for a rebase: {e}")))?;
        }
        Ok(out)
    }

    /// The state at `base_lsn` from the log: the newest snapshot at or
    /// before it, else from LSN 1.
    async fn at_base(&self, store: &Store, id: &str, base_lsn: Lsn) -> Result<Shadow, StoreError> {
        let snap = self.snapshot_at_most(base_lsn);
        let from = snap.as_ref().map_or(0, |(l, _)| *l);
        let records = self.read(from, base_lsn).await?;
        if records.first().is_some_and(|c| c.lsn != from + 1) {
            return Err(StoreError::Corrupt(format!(
                "the rebase {id} needs the log from lsn {}, but it starts later",
                from + 1
            )));
        }
        Shadow::at_base(
            id,
            base_lsn,
            snap.as_ref().map(|(l, d)| (*l, d.as_path())),
            &records,
            store.sealer_arc(),
        )
    }

    /// Recovery: the shadow of the switch at `lsn` from the log alone.
    async fn shadow_from_log(
        &self,
        store: &Store,
        id: &str,
        sw: &pb::RebaseSwitch,
        lsn: Lsn,
    ) -> Result<Arc<Store>, StoreError> {
        tracing::info!(
            rebase = id,
            lsn,
            base_lsn = sw.base_lsn,
            "building a rebase shadow from the log"
        );
        let mut shadow = self.at_base(store, id, sw.base_lsn).await?;
        let after = self.read(sw.base_lsn, lsn - 1).await?;
        shadow.feed(&after)?;
        shadow.finish(sw)?;
        Ok(shadow.store)
    }
}

impl Node {
    /// The newest StateRebase switch: (its LSN, its base LSN).
    pub fn last_rebase(&self) -> Result<Option<(Lsn, Lsn)>, ApiError> {
        self.store().db().last_rebase().map_err(store_err)
    }

    /// Builds the shadow of rebase `id` at `base_lsn` from main's log, and
    /// feeds it everything main logged since; kept for the switch.
    pub async fn rebase_prepare(&self, id: &str, base_lsn: Lsn) -> Result<(), ApiError> {
        let ready = lock(&self.rebase.live)
            .as_ref()
            .is_some_and(|s| s.rebase_id == id && s.base_lsn == base_lsn);
        if !ready {
            let shadow = self
                .rebase
                .at_base(self.store(), id, base_lsn)
                .await
                .map_err(|e| ApiError::new(ErrorCode::BadRequest, e.to_string()))?;
            *lock(&self.rebase.live) = Some(shadow);
        }
        self.rebase_refresh(id).await
    }

    /// Feeds the live shadow main's records since it last read.
    async fn rebase_refresh(&self, id: &str) -> Result<(), ApiError> {
        let from = lock(&self.rebase.live)
            .as_ref()
            .filter(|s| s.rebase_id == id)
            .map(|s| s.read_to)
            .ok_or_else(|| internal(format!("rebase {id} is not prepared")))?;
        let records = self
            .rebase
            .read(from, self.applied_lsn())
            .await
            .map_err(store_err)?;
        let mut live = lock(&self.rebase.live);
        let shadow = live
            .as_mut()
            .filter(|s| s.rebase_id == id)
            .ok_or_else(|| internal(format!("rebase {id} is not prepared")))?;
        shadow.feed(&records).map_err(store_err)
    }

    /// A snapshot at the switch, so later rebuilds start after it (ADR
    /// 0017); without storage there is nothing to do. Also below `[log]
    /// disk_reserve`: until it exists compaction holds the log (it may have
    /// to rebuild across the switch), so refusing it would keep the node
    /// below the reserve (review N13-2, round 3).
    pub async fn snapshot_after_rebase(&self) {
        if self.storage_config().is_some()
            && let Err(e) = self.take_snapshot("rebase").await
        {
            tracing::warn!(error = %e, "no snapshot after the rebase switch");
        }
    }

    /// The fork LSN of the last turn of rebase `id` already in main's log.
    pub fn rebase_staged_to(&self, id: &str) -> Option<Lsn> {
        lock(&self.rebase.live)
            .as_ref()
            .filter(|s| s.rebase_id == id)
            .map(|s| s.staged_fork_lsn)
    }

    /// Refuses when main erased a subject after `not_after`: the rebase
    /// read its values before (ADR 0017).
    fn rebase_erasure_check(&self, not_after: Lsn) -> Result<(), ApiError> {
        if let Some(e) = self.store().db().last_erasure_lsn().map_err(store_err)?
            && e > not_after
        {
            return Err(ApiError::new(
                ErrorCode::ProposalStale,
                format!(
                    "a subject was erased at lsn {e}, after the rebase read main's history; \
                     its values must not come back"
                ),
            )
            .with_hint("Run kronik rollback <epoch> --by-replay again."));
        }
        Ok(())
    }

    /// Writes fork turns of rebase `id` (fork LSN, record; in fork order)
    /// into main's log and feeds them to the shadow.
    pub async fn rebase_stage(
        &self,
        id: &str,
        turns: Vec<(Lsn, pb::TurnRecord)>,
        not_after: Lsn,
        pause: Option<&crate::gate::Drain>,
    ) -> Result<(), ApiError> {
        // Under the rebase pause the deploy lock is the pause's.
        let _guard = match pause {
            Some(p) if p.holds_deploy_lock() => None,
            _ => Some(self.deploy_lock.lock().await),
        };
        self.rebase_erasure_check(not_after)?;
        // Nothing more is written once the pause's bound has passed (ADR 0018).
        if pause.is_some_and(crate::gate::Drain::expired) {
            return Err(stale(
                "the last round did not fit in rebase.max_pause; nothing was switched",
            ));
        }
        let Some(last_fork) = turns.last().map(|(l, _)| *l) else {
            return self.rebase_refresh(id).await;
        };
        // Every batch keeps to the reserve, not only the estimate before the
        // first: turns staged so far stay unused and are reused by a later
        // promote (review N13-2, round 3).
        let bytes: u64 = turns.iter().map(|(_, r)| rebase_turn_bytes(id, r)).sum();
        if self.disk_below_reserve().is_some()
            || self.disk_budget().is_some_and(|room| bytes > room)
        {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                format!(
                    "staging {bytes} more bytes of rebased turns would take main's log below \
                     [log] disk_reserve; nothing was switched"
                ),
            )
            .with_hint(
                "Free disk space and promote again (the turns staged so far are reused), or roll \
                 back the code only: kronik rollback <epoch> --reason \"...\"",
            ));
        }
        let records = turns
            .into_iter()
            .map(|(fork_lsn, record)| {
                Record::StateRebase(pb::StateRebase {
                    rebase_id: id.to_owned(),
                    part: Some(pb::state_rebase::Part::Turn(pb::RebasedTurn {
                        fork_lsn,
                        record: Some(record),
                    })),
                })
            })
            .collect();
        self.commit_all(records).await?;
        self.rebase_refresh(id).await?;
        let staged = self.rebase_staged_to(id);
        if staged != Some(last_fork) {
            return Err(internal(format!(
                "rebase {id}: staged through fork lsn {staged:?}, expected {last_fork}"
            )));
        }
        Ok(())
    }

    /// Refuses a rebase switch main's history no longer allows (m13-rebase
    /// §6): a deployment after the rolled-back one, another rebase switch
    /// after the fork point, a kind of the rolled-back deployment no longer
    /// running its code, or a route another kind took meanwhile. Called
    /// under the deploy lock.
    fn rebase_still_valid(
        &self,
        sw: &pb::RebaseSwitch,
        kinds: &[pb::KindVersion],
    ) -> Result<(), ApiError> {
        let hint = "Run kronik rollback <epoch> --by-replay again.";
        let deployments = self.store().db().deployments().map_err(store_err)?;
        if let Some((_, d)) = deployments
            .iter()
            .find(|(_, d)| d.epoch > sw.rolled_back_epoch)
        {
            return Err(ApiError::new(
                ErrorCode::ProposalStale,
                format!(
                    "deployment {} came after {}: a rollback via replay undoes main's newest \
                     code change only",
                    d.epoch, sw.rolled_back_epoch
                ),
            )
            .with_hint(hint));
        }
        if let Some((r, _)) = self.last_rebase()?
            && r > sw.base_lsn
        {
            return Err(ApiError::new(
                ErrorCode::ProposalStale,
                format!("main's state was rebased at lsn {r}, after this rebase's fork point"),
            )
            .with_hint(hint));
        }
        let target = deployments
            .iter()
            .find(|(_, d)| d.epoch == sw.rolled_back_epoch)
            .map(|(_, d)| d.kinds.as_slice())
            .unwrap_or_default();
        for v in target {
            if self
                .deployed(&v.kind)
                .is_none_or(|k| k.code_hash != v.code_hash)
            {
                return Err(ApiError::new(
                    ErrorCode::ProposalStale,
                    format!(
                        "kind {:?} no longer runs the code of deployment {}",
                        v.kind, sw.rolled_back_epoch
                    ),
                )
                .with_hint(hint));
            }
        }
        self.check_set_routes(kinds)
    }

    /// The switch of rebase `id` (pause held): the last staged turns must
    /// already be in the log. Writes the `StateRebase` switch with the code
    /// `kinds`; the applier installs the shadow; the node switches its code
    /// and reloads its timers and queued messages. Returns (epoch, lsn).
    /// Takes the pause: the switch's task holds it until the switch is
    /// done, also when the caller goes away.
    pub async fn rebase_switch(
        &self,
        pause: crate::gate::Drain,
        id: &str,
        mut sw: pb::RebaseSwitch,
        kinds: Vec<pb::KindVersion>,
        not_after: Lsn,
        audit: pb::Audit,
    ) -> Result<(u64, Lsn), ApiError> {
        // The pause holds the deploy lock (lock order: deploy lock, drain,
        // switch gate).
        if !pause.holds_deploy_lock() {
            return Err(internal("a rebase switch needs the drain of rebase_pause"));
        }
        self.rebase_erasure_check(not_after)?;
        self.rebase_still_valid(&sw, &kinds)?;
        self.rebase_refresh(id).await?;
        let mut installs = Vec::with_capacity(kinds.len());
        for v in &kinds {
            let hash = CodeHash::from_slice(&v.code_hash).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::BadRequest,
                    format!("kind {:?}: bad code hash", v.kind),
                )
            })?;
            let program = self.code().get(&hash).map_err(internal)?;
            installs.push((v.clone(), program, hash));
        }
        let epoch = self.epoch() + 1;
        {
            let live = lock(&self.rebase.live);
            let s = live
                .as_ref()
                .filter(|s| s.rebase_id == id)
                .ok_or_else(|| internal(format!("rebase {id} is not prepared")))?;
            sw.first_turn_lsn = s.first_turn;
            sw.last_turn_lsn = s.last_turn;
            sw.turns = s.turns;
        }
        sw.deployment = Some(pb::Deployment {
            epoch,
            kinds,
            effective_lsn: 0,
            verified_through_lsn: sw.verified_through_lsn,
            unverified_inputs: 0,
            cause: pb::DeploymentCause::Rollback as i32,
            proposal_id: id.to_owned(),
            rollback_of_epoch: sw.rolled_back_epoch,
            audit: Some(audit.clone()),
        });
        sw.audit = Some(audit);
        if pause.expired() {
            return Err(stale(
                "the last catch-up did not fit in rebase.max_pause; nothing was switched",
            ));
        }
        let gate = self.gate.switch().await;
        // With the gate held no turn starts; a callee turn whose caller
        // gave up may have started before it.
        pause.check_quiet()?;
        let record = Record::StateRebase(pb::StateRebase {
            rebase_id: id.to_owned(),
            part: Some(pb::state_rebase::Part::Switch(sw)),
        });
        let lsn = self
            .finish_switch(pause, gate, record, installs, epoch, true)
            .await?;
        tracing::info!(rebase = id, epoch, lsn, "state rebased");
        Ok((epoch, lsn))
    }
}

impl RebaseCtx {
    /// The switch is done: the live shadow is no longer needed.
    pub(crate) fn clear_live(&self) {
        *lock(&self.live) = None;
    }
}
