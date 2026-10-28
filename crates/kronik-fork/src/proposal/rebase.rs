//! Rollback via replay (docs/design/m13-rebase.md): a rebase proposal and
//! its switch.

use super::*;

/// What `kronik rollback <epoch> --by-replay` needs.
#[derive(Debug, Clone)]
pub struct RebaseRequest {
    /// The deployment to roll back.
    pub epoch: u64,
    pub options: DiffOptions,
    pub workers: Option<usize>,
    pub audit: pb::Audit,
    pub dry_run: bool,
}

/// A rebase proposal's own facts (`proposal.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RebaseInfo {
    pub rolled_back_epoch: u64,
    /// The fork point: main's last LSN before the rolled-back deployment.
    pub base_lsn: Lsn,
    #[serde(default)]
    pub irreversible_effects: u64,
    /// The `StateRebase` switch, once promoted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_lsn: Option<Lsn>,
}

/// What the switch of a rebase did.
#[derive(Debug, Clone, PartialEq)]
pub struct RebaseDone {
    /// The `StateRebase` switch (0 for a dry run).
    pub lsn: Lsn,
    pub base_lsn: Lsn,
    /// The fork's turns that became main's state.
    pub turns: u64,
    pub irreversible_effects: u64,
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, msg)
}

impl Proposals {
    /// `[rebase] max_pause`: how long a switch may hold main's turns.
    pub fn with_rebase(mut self, max_pause: Duration) -> Proposals {
        self.rebase_max_pause = max_pause;
        self
    }

    /// The lowest fork point: main's newest rebase switch (m13-rebase §6).
    pub(super) fn fork_floor(&self) -> Result<Lsn, ApiError> {
        Ok(self.node.last_rebase()?.map_or(0, |(r, _)| r))
    }

    /// Promote of a proposal whose fork point main's state was rebased
    /// past since (m13-rebase §6): `PROPOSAL_STALE`.
    pub(super) fn check_fork_floor(&self, fork_lsn: Lsn) -> Result<(), ApiError> {
        let floor = self.fork_floor()?;
        if fork_lsn < floor {
            return Err(ApiError::new(
                ErrorCode::ProposalStale,
                format!("fork point {fork_lsn} is before main's state rebase at lsn {floor}"),
            )
            .with_hint("Main's state changed under the proposal; propose again."));
        }
        Ok(())
    }

    /// `PROPOSAL_STALE` when a deployment (or a rebase switch) landed after
    /// the rolled-back one since the rebase was created (H2): its switch
    /// would silently revert that code.
    fn check_newest(&self, epoch: u64) -> Result<(), ApiError> {
        let deployments = self.node.store().db().deployments().map_err(internal)?;
        match deployments.iter().map(|(_, d)| d.epoch).find(|e| *e > epoch) {
            None => Ok(()),
            Some(newer) => Err(ApiError::new(
                ErrorCode::ProposalStale,
                format!(
                    "deployment {newer} came after {epoch}: a rollback via replay undoes main's \
                     newest code change only"
                ),
            )
            .with_hint(format!(
                "Roll back deployment {newer} first: kronik rollback {newer} --by-replay --reason \"...\""
            ))),
        }
    }

    /// `kronik rollback <epoch> --by-replay`: a rebase proposal that replays
    /// every root input since the deployment through the code before it.
    pub async fn rebase(&self, req: RebaseRequest) -> Result<(Proposal, bool), ApiError> {
        // New work (a replay of a window, a fork log): refused below
        // `[log] disk_reserve`, like proposals.
        self.node.check_running()?;
        diff::check_options(&req.options).map_err(bad)?;
        if !req.options.mode.continuous() {
            return Err(bad(
                "a rollback via replay needs continuous replay: --mode continuous or both",
            ));
        }
        // Its turns become main's state: recordings only, no simulators,
        // model or live GETs (m13-rebase §8; `setup` with `rebase`).
        if !req.options.stubs.is_empty()
            || !req.options.live_allowlist.is_empty()
            || !req.options.simulator_overrides.is_empty()
        {
            return Err(bad(
                "a rollback via replay answers effects from recordings only: no stubs, simulator overrides or live hosts",
            ));
        }
        let options = req.options.clone();
        let deployments = self.node.store().db().deployments().map_err(internal)?;
        let Some((dlsn, target)) = deployments.iter().find(|(_, d)| d.epoch == req.epoch) else {
            return Err(ApiError::new(
                ErrorCode::DeploymentNotFound,
                format!(
                    "no deployment with epoch {}; run: kronik deployments list",
                    req.epoch
                ),
            ));
        };
        if let Some((_, newer)) = deployments.iter().find(|(_, d)| d.epoch > req.epoch) {
            return Err(bad(format!(
                "deployment {} came after {}: a rollback via replay undoes main's newest code \
                 change only",
                newer.epoch, req.epoch
            ))
            .with_hint(format!(
                "Roll back deployment {} first: kronik rollback {} --by-replay --reason \"...\"",
                newer.epoch, newer.epoch
            )));
        }
        if target.cause == pb::DeploymentCause::Rollback as i32
            && target.proposal_id.starts_with("r-")
        {
            return Err(bad(format!(
                "deployment {} is itself a rollback via replay; propose new code instead",
                req.epoch
            )));
        }
        let mut before: BTreeMap<String, pb::KindVersion> = BTreeMap::new();
        for (_, d) in &deployments {
            if d.epoch < req.epoch {
                for k in &d.kinds {
                    before.insert(k.kind.clone(), k.clone());
                }
            }
        }
        let mut kinds = Vec::with_capacity(target.kinds.len());
        for k in &target.kinds {
            let Some(prev) = before.get(&k.kind) else {
                return Err(bad(format!(
                    "kind {:?} did not exist before epoch {}; a deployment cannot remove it",
                    k.kind, req.epoch
                )));
            };
            kinds.push(prev.clone());
        }
        let base_lsn = match target.effective_lsn {
            0 => dlsn - 1,
            e => e - 1,
        };
        crate::ensure_fork_retained(&self.node, &self.data, base_lsn).await?;
        let head = self.node.applied_lsn();
        let id = format!("r-{}", &random_id(self.node.env())[..12]);
        let workers = req.workers.unwrap_or(self.workers).clamp(1, 64);
        let mut live = self
            .replay(
                &id,
                base_lsn,
                head,
                &[],
                &options,
                workers,
                None,
                req.dry_run,
                true,
                Some(copies::REBASE),
            )
            .await?;
        let (d, bytes, hash) = self.build(&id, &live, &options)?;
        let policy = self.evaluate(&bytes)?;
        let denied = policy["outcome"] == "deny";
        let meta = Proposal {
            id: id.clone(),
            fork: id.clone(),
            status: if denied { "rejected" } else { "evaluated" }.into(),
            fork_lsn: base_lsn,
            created_lsn: head,
            verified_through_lsn: d.summary.verified_through_lsn,
            diff_hash: hash,
            policy,
            summary: serde_json::to_value(&d.summary).map_err(internal)?,
            options,
            kinds: kinds
                .iter()
                .map(|k| base64::engine::general_purpose::STANDARD.encode(k.encode_to_vec()))
                .collect(),
            reason: req.audit.reason.clone(),
            approved: None,
            promoted: None,
            plain_fork: false,
            unchanged: Vec::new(),
            window_cut: None,
            error: None,
            preview: None,
            rebase: Some(RebaseInfo {
                rolled_back_epoch: req.epoch,
                base_lsn,
                irreversible_effects: d.irreversible.as_ref().map_or(0, |i| i.count),
                switch_lsn: None,
            }),
        };
        if req.dry_run {
            return Ok((meta, true));
        }
        self.write_log(&id, &mut live).await?;
        self.save(&meta, Some(&bytes))?;
        self.save_samples(&id, &live, &d)?;
        self.entries.lock().await.insert(
            id,
            Entry {
                meta: meta.clone(),
                live: Some(live),
            },
        );
        Ok((meta, false))
    }

    /// Writes the fork's continuous turns not yet in main's log, each after
    /// it is in the fork's own log (a resume compares against that, H3).
    async fn stage(
        &self,
        id: &str,
        live: &mut Live,
        rolled_back_epoch: u64,
        not_after: Lsn,
        pause: Option<&kronik_sched::Drain>,
    ) -> Result<(), ApiError> {
        self.write_log(id, live).await?;
        self.check_newest(rolled_back_epoch)?;
        let staged = self.node.rebase_staged_to(id).unwrap_or(0);
        let turns: Vec<(Lsn, pb::TurnRecord)> = live
            .continuous
            .as_ref()
            .map(Continuous::turns)
            .unwrap_or_default()
            .into_iter()
            .filter(|t| t.lsn > staged)
            .map(|t| (t.lsn, t.record))
            .collect();
        for batch in turns.chunks(512) {
            self.node
                .rebase_stage(id, batch.to_vec(), not_after, pause)
                .await?;
        }
        Ok(())
    }

    /// The highest fork LSN of rebase `id`'s turns in main's log (0: none).
    async fn staged_in_log(&self, id: &str, fork_lsn: Lsn) -> Result<Lsn, ApiError> {
        let mut staged = 0;
        self.node
            .reader()
            .read(fork_lsn + 1, self.node.applied_lsn(), |c| {
                if let Record::StateRebase(pb::StateRebase {
                    rebase_id,
                    part: Some(pb::state_rebase::Part::Turn(t)),
                }) = &c.record
                    && rebase_id == id
                {
                    staged = staged.max(t.fork_lsn);
                }
                Ok(())
            })
            .await
            .map_err(internal)?;
        Ok(staged)
    }

    /// The turns of the fork's own log (LSN, record hash), in order.
    async fn logged_turns(&self, id: &str) -> Result<Vec<(Lsn, blake3::Hash)>, ApiError> {
        let dir = self.dir(id).join("log");
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        kronik_log::LogReader::new(self.node.env().clone(), dir, id)
            .read(1, Lsn::MAX, |c| {
                // The fork log is sealed like production's (nonces differ
                // per write): compared as plaintext, as the fresh replay
                // is (N13-1).
                let mut record = c.record;
                self.node.sealer().unseal_record(&mut record);
                if let Record::TurnRecord(t) = &record {
                    out.push((c.lsn, blake3::hash(&t.encode_to_vec())));
                }
                Ok(())
            })
            .await
            .map_err(internal)?;
        Ok(out)
    }

    /// `kronik promote` of a rebase proposal (m13-rebase §4): catch-up, an
    /// approval for the diff, staging, the bounded pause, the last round and
    /// the `StateRebase` switch.
    pub(super) async fn promote_rebase(
        &self,
        entry: &mut Entry,
        id: &str,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<PromoteResult, ApiError> {
        let epoch = entry
            .meta
            .rebase
            .as_ref()
            .ok_or_else(|| internal("not a rebase"))?
            .rolled_back_epoch;
        if let Err(e) = self.check_newest(epoch) {
            if !dry_run {
                entry.meta.status = "stale".into();
                self.save(&entry.meta, None)?;
            }
            return Err(e);
        }
        // A dry run (I12) works on a copy of the proposal and a replay of
        // its own: it writes no fork log, saves nothing and leaves the kept
        // replay state and the proposal as they were (N13-4).
        if dry_run {
            let mut meta = entry.meta.clone();
            let mut live = self
                .replay(
                    id,
                    meta.fork_lsn,
                    meta.verified_through_lsn,
                    &[],
                    &meta.options,
                    self.workers,
                    None,
                    true,
                    true,
                    Some(copies::REBASE),
                )
                .await?;
            let mut consistent = true;
            return self
                .promote_rebase_live(&mut meta, &mut live, None, &mut consistent, id, audit, true)
                .await;
        }
        // A round that fails or is cancelled leaves the replay half-way, so
        // it is out of the entry and back only while consistent (H3).
        let (mut live, logged) = match entry.live.take() {
            Some(live) => (live, None),
            None => {
                // What an earlier attempt logged (and maybe staged), read
                // before the fresh replay replaces the fork's log.
                let logged = self.logged_turns(id).await?;
                let live = self
                    .replay(
                        id,
                        entry.meta.fork_lsn,
                        entry.meta.verified_through_lsn,
                        &[],
                        &entry.meta.options,
                        self.workers,
                        None,
                        false,
                        true,
                        Some(copies::REBASE),
                    )
                    .await?;
                (live, Some(logged))
            }
        };
        let mut consistent = true;
        let result = self
            .promote_rebase_live(
                &mut entry.meta,
                &mut live,
                logged,
                &mut consistent,
                id,
                audit,
                dry_run,
            )
            .await;
        let switched = result.as_ref().is_ok_and(|r| r.lsn != 0);
        if consistent && !switched {
            entry.live = Some(live);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn promote_rebase_live(
        &self,
        meta: &mut Proposal,
        live: &mut Live,
        logged: Option<Vec<(Lsn, blake3::Hash)>>,
        consistent: &mut bool,
        id: &str,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<PromoteResult, ApiError> {
        let info = meta
            .rebase
            .clone()
            .ok_or_else(|| internal("not a rebase"))?;
        let kinds = meta.kind_versions()?;
        let options = meta.options.clone();
        let fork_lsn = meta.fork_lsn;
        let not_after = meta.created_lsn;
        // 1. Catch-up and the policy, as promote.
        *consistent = false;
        let converged = self.catch_up_to_gap(id, live, &options, false).await?;
        *consistent = true;
        if !converged {
            meta.status = "stale".into();
            if !dry_run {
                self.save(meta, None)?;
            }
            return Err(ApiError::new(
                ErrorCode::ProposalStale,
                format!(
                    "catch-up did not converge within {:?}",
                    self.catch_up_timeout
                ),
            ));
        }
        // A fresh replay (a restart, a failed round) must give exactly the
        // turns already staged into main's log, or none may be added (H3).
        if let Some(logged) = logged {
            let staged = self.staged_in_log(id, fork_lsn).await?;
            let fresh: Vec<(Lsn, blake3::Hash)> = live
                .continuous
                .as_ref()
                .map(Continuous::turns)
                .unwrap_or_default()
                .iter()
                .filter(|t| t.lsn <= staged)
                // As the fork log holds it (`write_log`), before sealing.
                .map(|t| (t.lsn, blake3::hash(&super::shown_record(t).encode_to_vec())))
                .collect();
            let before: Vec<_> = logged.into_iter().filter(|(l, _)| *l <= staged).collect();
            if fresh != before {
                *consistent = false;
                return Err(ApiError::new(
                    ErrorCode::ProposalStale,
                    format!(
                        "the replay of {id} differs from the {} turn(s) it already wrote into \
                         main's log; they stay inert",
                        before.len()
                    ),
                )
                .with_hint(format!(
                    "Create the rebase again: kronik rollback {} --by-replay --reason \"...\"",
                    info.rolled_back_epoch
                )));
            }
        }
        if !dry_run {
            self.write_log(id, live).await?;
        }
        let (d, bytes, hash) = self.build(id, live, &options)?;
        let policy = self.evaluate(&bytes)?;
        let outcome = policy["outcome"].as_str().unwrap_or("deny").to_owned();
        meta.verified_through_lsn = live.index.to_lsn;
        meta.diff_hash = hash.clone();
        meta.policy = policy.clone();
        meta.summary = serde_json::to_value(&d.summary).map_err(internal)?;
        let irreversible = d.irreversible.as_ref().map_or(0, |i| i.count);
        if outcome == "deny" {
            if !dry_run {
                meta.status = "rejected".into();
                self.save(meta, Some(&bytes))?;
                self.save_samples(id, live, &d)?;
            }
            return Err(ApiError::new(
                ErrorCode::PolicyDenied,
                format!("the policy denies proposal {id}: {}", fired_names(&policy)),
            ));
        }
        // 2. The switch always needs an approval for this diff.
        let approved = meta.approved.as_ref().is_some_and(|a| {
            a.diff_hash == hash
                || (outcome_rank(&outcome) <= outcome_rank(&a.outcome)
                    && changed_targets(&d).iter().all(|t| a.targets.contains(t)))
        });
        if !approved {
            if !dry_run {
                self.save(meta, Some(&bytes))?;
                self.save_samples(id, live, &d)?;
            }
            return Err(ApiError::new(
                ErrorCode::ApprovalRequired,
                format!(
                    "a rollback via replay switches main's state and needs an approval for \
                     this diff; run: kronik approve {id} --reason '...'"
                ),
            ));
        }
        let turns = live
            .continuous
            .as_ref()
            .map_or(0, |c| c.turns().len() as u64);
        if dry_run {
            return Ok(PromoteResult {
                epoch: self.node.epoch() + 1,
                lsn: 0,
                verified_through_lsn: live.index.to_lsn,
                unverified_inputs: 0,
                kinds,
                policy,
                rebase: Some(RebaseDone {
                    lsn: 0,
                    base_lsn: fork_lsn,
                    turns,
                    irreversible_effects: irreversible,
                }),
            });
        }
        // Staging appends up to a window of turns to main's log: not on a
        // disk below `[log] disk_reserve`, and not more than the room above
        // it (N13-2). `kronik rollback` (code only) stays the incident action.
        let staged_bytes: u64 = live
            .continuous
            .as_ref()
            .map(|c| {
                c.turns()
                    .iter()
                    .map(|t| kronik_sched::rebase_turn_bytes(id, &t.record))
                    .sum()
            })
            .unwrap_or(0);
        if self.node.disk_below_reserve().is_some()
            || self
                .node
                .disk_budget()
                .is_some_and(|room| staged_bytes > room)
        {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                format!(
                    "a rollback via replay stages {staged_bytes} bytes of turns into main's log, \
                     more than the room above [log] disk_reserve"
                ),
            )
            .with_hint(format!(
                "Free disk space, or roll back the code only: kronik rollback {} --reason \"...\"",
                info.rolled_back_epoch
            )));
        }
        // What is approved and shown is the diff just built, also when the
        // switch below gives up.
        self.save(meta, Some(&bytes))?;
        self.save_samples(id, live, &d)?;
        // 3. Staging while main runs, then the pause and the last round.
        self.node.rebase_prepare(id, fork_lsn).await?;
        self.stage(id, live, info.rolled_back_epoch, not_after, None)
            .await?;
        // The deploy lock, then the drain: no set switch lands before ours.
        let pause = self.node.rebase_pause(self.rebase_max_pause).await?;
        // The whole pause is bounded (H5): the last round reads only main's
        // records since the catch-up, and gives up at the deadline.
        *consistent = false;
        let last = async {
            let head = self.node.applied_lsn();
            if head > live.index.to_lsn {
                self.catch_up(id, live, head, &options, false).await?;
            }
            self.stage(id, live, info.rolled_back_epoch, not_after, Some(&pause))
                .await
        };
        match self
            .node
            .env()
            .clone()
            .timeout(pause.remaining(), last)
            .await
        {
            Ok(r) => r?,
            Err(_) => {
                drop(pause);
                return Err(ApiError::new(
                    ErrorCode::ProposalStale,
                    "the last catch-up did not fit in rebase.max_pause; nothing was switched",
                )
                .with_hint(
                    "Run the promote again; the turns already written are reused. If this keeps \
                     happening, raise [rebase] max_pause in kronik.toml.",
                ));
            }
        }
        *consistent = true;
        let sw = pb::RebaseSwitch {
            base_lsn: fork_lsn,
            rolled_back_epoch: info.rolled_back_epoch,
            verified_through_lsn: live.index.to_lsn,
            diff_hash: hash,
            irreversible_effects: irreversible,
            ..Default::default()
        };
        let (epoch, lsn) = self
            .node
            .rebase_switch(pause, id, sw, kinds.clone(), not_after, audit)
            .await?;
        // 4. The saved diff covers main's turns up to the switch.
        self.write_log(id, live).await?;
        let (d, bytes, hash) = self.build(id, live, &options)?;
        let turns = live
            .continuous
            .as_ref()
            .map_or(0, |c| c.turns().len() as u64);
        let irreversible = d.irreversible.as_ref().map_or(0, |i| i.count);
        let verified = live.index.to_lsn;
        meta.verified_through_lsn = verified;
        meta.diff_hash = hash;
        meta.summary = serde_json::to_value(&d.summary).map_err(internal)?;
        meta.status = "promoted".into();
        meta.promoted = Some(Promoted { epoch, lsn });
        meta.rebase = Some(RebaseInfo {
            irreversible_effects: irreversible,
            switch_lsn: Some(lsn),
            ..info
        });
        self.save(meta, Some(&bytes))?;
        self.save_samples(id, live, &d)?;
        self.node.snapshot_after_rebase().await;
        Ok(PromoteResult {
            epoch,
            lsn,
            verified_through_lsn: verified,
            unverified_inputs: 0,
            kinds,
            policy,
            rebase: Some(RebaseDone {
                lsn,
                base_lsn: fork_lsn,
                turns,
                irreversible_effects: irreversible,
            }),
        })
    }
}
