# M13 rollback via replay

Status: binding for M13. Builds on `m3-fork.md` (§3 replay, §8 promote,
catch-up and rollback), `m6-storage.md` (snapshots, retention, shipping),
`m8-privacy.md` (sealing, erasure); brief section "v0.3: Rikare replay", M13,
and the invariants I4, I5, I7, I13–I17. ADR 0017 records the log format and
how the rebased state stays derivable from the log; ADR 0018 records the
switch.

A rollback of a deployment that migrated state cannot just point back at
the old hash: the actors' state is in the new schema. `kronik rollback
<epoch> --by-replay` instead computes the state the old code would have
produced from every root input since the deployment, shows it in a diff
with the external effects that already happened and cannot be undone, and,
once approved, switches main to that state and that code in one log
record. Main's history stays as it was.

## 1. The flow

1. `kronik rollback <epoch> --by-replay --reason "..."` (API `POST
   /v1/deployments/{epoch}/rebase`) creates a **rebase proposal**
   `r-<12 hex>`: a proposal, so a fork with a diff (I13). Its fork point is
   the deployment's `effective_lsn` minus one, the last LSN before the
   `Deployment` record and so before any migration turn of the new code.
   The fork runs the code in force at that point, which is the old code of
   every kind. Continuous replay runs every root input of main since the
   fork point through it (`--mode both` adds isolated replay to the diff).
2. The diff is the usual `kronik.diff/v1` (`state.continuous` is the old
   code's state per actor against main's) plus `irreversible` (§5): main's
   external effects since the deployment that the old code would not have
   made in the same way. The policy is evaluated as for any proposal.
3. `kronik approve r-...` is required: the switch needs an approval for the
   diff even when the policy outcome is `allow`.
4. `kronik promote r-...` does the switch (§3): catch-up as promote does,
   then the fork's turns are written into main's log, then main pauses new
   turns for at most `rebase.max_pause` (2 s), the last root inputs are
   caught up, and one `StateRebase` record switches state and code.

Preconditions, all refused with `BAD_REQUEST` before anything is written:
the deployment must be main's newest code change (no later `Deployment`
or `StateRebase`); every kind of it must have existed before it (a
deployment cannot remove a kind, as for `kronik rollback`); `--mode
isolated` alone is refused (the switch needs continuous replay); stubs and
live hosts are refused (§8). A fork point outside retention is
`BAD_REQUEST` as for propose (`PROPOSAL_STALE` when promote finds it).
When a deployment or a rebase switch lands after the rolled-back one
between creation and the switch, promote is `PROPOSAL_STALE` (checked
before staging and again at the switch, under the deploy lock); any
proposal whose fork point is before main's newest switch is
`PROPOSAL_STALE` at promote (§6).

## 2. Log records (ADR 0017)

One new record kind, `StateRebase`, envelope kind **16** (M12 took 15), in
`proto/kronik/log/v1/branch.proto`, with a `rebase_id` and one of two
parts:

- `RebasedTurn {fork_lsn, record}`: one turn of the rebase fork's
  continuous history, the fork's `TurnRecord` exactly as the fork recorded
  it, and its LSN in the fork's log. Written to main's log during promote,
  before the switch, in fork order. Until a switch with the same
  `rebase_id` follows, these records change nothing in main's state.
- `RebaseSwitch {base_lsn, rolled_back_epoch, verified_through_lsn,
  first_turn_lsn, last_turn_lsn, turns, deployment, diff_hash, audit}`: the
  switch. `deployment` is the code from here on (cause `ROLLBACK`,
  `rollback_of_epoch`, `proposal_id` = the rebase id, a new epoch).
  `[first_turn_lsn, last_turn_lsn]` and `turns` name this rebase's
  `RebasedTurn` records.

Every value-bearing field of the embedded `TurnRecord` is sealed, resealed
and erased like a turn record's (`record_mut` includes it).

## 3. State after the switch, from the log alone (I4)

The switch record at LSN `R` defines main's state after it as

> state(R) = transplant(state(R − 1), shadow), where shadow = state(base) +
> this rebase's `RebasedTurn` records and every `Erasure` record in
> `(base, R)`, applied in LSN order, each at its own LSN and log position.

`state(base)` and every input of the shadow are in main's log: the records
up to `base_lsn` (or a snapshot at or before it plus the records after it)
and the `RebasedTurn` records between `base_lsn` and `R`. Applying a
recorded turn runs no guest code, so the rebuild is the ordinary apply of
recorded turns (recovery step 2 holds), independent of the engine version
and of the fork's directory, which can be deleted afterwards.

The shadow is exactly the fork's continuous state: the same records on the
same starting state, with main's LSNs instead of the fork's. Erasures that
main recorded after the fork point apply to it at their places, so the
rows of an erased subject are deleted from the rebased state too. A
staged turn is sealed when it is written; a subject erased after the
rebase read main's history would get a new key and its old values would
come back, so promote refuses (`PROPOSAL_STALE`, create the rebase again)
when an erasure was recorded after the rebase was created; staging and the
switch hold the deploy lock, which erasures take too.

**Transplant**: one `state.db` transaction at `R`, after the actor
databases are replaced.

| Table | After the switch |
| --- | --- |
| `actors`, `kv`, `timers` | For every *affected actor*, the shadow's rows (none if the old code never created it); others unchanged. Affected: an actor with a turn of main in `(base, R)` (`turn_index`) or a row in the shadow last written after `base`. |
| per-actor SQL databases | For every affected actor, the shadow's database (schema and rows of the old code), or none; `applied_lsn = R`. |
| `mailbox` | The shadow's: the old code's pending messages. |
| `deliveries` | Rows after `base` are the shadow's (message dedup and call answers of the old code's history). |
| `dead_letters`, `orphans` | The shadow's. |
| `turn_index` | Main's, plus the rebased turns at their LSNs, so `main:<lsn>` of a rebased turn resolves (history and `GET /v1/turns` show it as a turn). |
| `trees` | Main's: a trace shows the tree production ran. |
| `ingress_keys` | Main's: a retry of a request answered before the switch gets the answer the client saw, and creates no root input. |
| `deployments`, `kinds`, config, `policies`, `approvals`, `erasures` | Main's, plus the switch's `Deployment` (I5). |
| `meta` | `applied_lsn = R`, `config_epoch` = the switch's epoch, `time_hwm` = the larger of main's and the shadow's (I15). |

**Timers** are the old code's: main's timers scheduled by the new code are
gone, fork timers still pending fire when due. **Dead letters** are the
old code's failures; main's dead letters from after the deployment stay in
the history (the failed turns are in the log) but can no longer be resent
(a resend held by the pause is answered `DEAD_LETTER_NOT_FOUND` at the
switch), so a root input that the old code ran successfully is never
applied twice. **Erased subjects** stay erased: every erasure after the
base is applied again after the last staged turn.
**Orphans** are the old code's. **SQL state** is the old code's databases,
in the old schema; the actors' `schema_version` is the old one, so the old
code runs no migration. LSNs inside rebased records that refer to the
fork's log (a timer input's `scheduled_by`) are kept as recorded.

## 4. The switch (ADR 0018)

`kronik promote r-...`:

1. **Catch-up** as promote (m3-fork §8): continuous replay continues to
   HEAD in rounds until the gap is at most `promote.max_gap`. The policy is
   evaluated again; an approval must hold for the diff (same hash, or not
   stricter with no new changed targets).
2. **Staging**: every fork turn not yet in main's log is appended as a
   `RebasedTurn` (fork order), after it is in the fork's own log. The node
   builds the shadow in memory from main's log (the state at `base_lsn`)
   and applies each staged record to it. Staging resumes where it stopped
   after an abort. A round that failed or was cancelled drops the replay
   state; the replay that replaces it (also after a restart) must give
   exactly the turns already staged, compared by fork LSN and record hash
   with the fork's log, else promote refuses with `PROPOSAL_STALE` and a
   hint to create the rebase again (the staged turns stay inert). Each
   round also queues the fork store's pending timers and messages that
   main has run since the previous round.
3. **Pause**: the node stops starting turns: root inputs (gateway, API
   messages, resends), messages and timers wait in their actors' queues;
   only the callee turns of `call`s already made run. It waits until no
   turn runs. From this moment, held requests wait at most
   `rebase.max_pause`.
4. **Last round**: root inputs committed since step 1 are caught up (only
   main's records after the previous round are read) and their fork turns
   staged, under the pause's deadline.
5. **Switch**: erasures since `base_lsn` are applied to the shadow and the
   `StateRebase` switch is committed; the applier transplants the shadow.
   The node then switches its code to the old code, reloads its timer wheel
   and replaces the queued messages and timers with the rebased mailbox,
   and resumes. With storage configured it takes a snapshot at `R`.
6. If steps 3 and 4 do not finish within `rebase.max_pause`, the last
   round is abandoned and nothing more is written: the node resumes, the
   held turns run on main's state as before, and promote fails with
   `PROPOSAL_STALE` and a hint to run it again (staged turns stay inert and
   are reused). The diff of the attempt is saved; if traffic since the
   approval changed new targets, the retry asks for a new approval.

**No root input is lost or duplicated.** A root input enters the history
when its turn record is committed. One committed before the switch was in
main's window, so the fork replayed it exactly once (the last round covers
everything committed while turns were paused), and its turns are in the
rebased state. One that had not started is held and runs once, after the
switch, on the rebased state with the old code. None runs across the
switch, because the switch waits until no turn runs. A client retry of a
request answered before the switch is deduplicated by main's
`ingress_keys`. Inner messages, compensations and timers are not root
inputs. The rebase fork runs one only when main's history has its turn
(the fork answers its effects from that turn's recordings); one main had
not run when the round was indexed (in flight at the pause, or new under
the old code) stays pending in the fork's store, so in the rebased
mailbox and timers, and main runs it after the switch, under the old code
and with real effects. Messages pending at the fork point are delivered
in the order main delivered them. A dead-letter resend in the window is
skipped when the fork's run of the original succeeded. The new code's
pending messages and timers are replaced by the old code's.

After the switch, main runs the old code on the rebased state, and its
history after `R` continues from there. `kronik rollback --by-replay` of
the switch's own deployment is refused (no newer code to roll back); a new
proposal changes the code again.

## 5. `irreversible` in the diff

Only in a rebase diff (absent otherwise; `kronik.diff/v1` is extended
additively):

```json
"irreversible": {"count": 3, "items": [
  {"turn_prod": "main:41", "kind": "http.fetch", "method": "GET",
   "host": "api.example.com", "route": "/v1/charges/{}/extra",
   "status": "ok", "delivery": "unsafe", "idempotency_key": "..."}]}
```

An external effect of main's turns in the window (any status but `denied`,
which never left) is irreversible when the fork has no effect with
`GROUNDING_EXACT` at the same causal key and ordinal: the old code did not
make that same request, so the world saw something the rebased state does
not account for, and someone may have to compensate. Effects the old code
also made (exact matches) are not listed: they happened once and the
rebased state includes their recorded results. Items are capped at 200;
`count` covers all. The diff is rebuilt once after the switch, so the
saved diff covers main's turns up to `R` (the root inputs of the last
round, at most `promote.max_gap` of traffic, are added after the approval).

## 6. Recovery, snapshots, shipping and restore, retention

- **Recovery.** When the applier reaches a switch it has not applied
  (a crash after the record was written, or a rebuild from an older
  snapshot or from LSN 1), it builds the shadow from the log: the newest
  snapshot at or before `base_lsn` (else LSN 1), main's records up to
  `base_lsn`, the rebase's `RebasedTurn` records and the erasures, then
  transplants. Replacing an actor database gives it `applied_lsn = R` in
  the same write (the shadow's copy is stamped before it is copied;
  clearing and stamping are one transaction), and `state.db` commits
  last, so a crash in the middle repeats the switch
  (`a_crash_after_an_actor_copy_repeats_the_switch`,
  `a_crash_between_the_switch_record_and_state_db_repeats_the_switch`).
  A switch `state.db` has but an affected actor database lost (a power
  loss with `synchronous=NORMAL`) has that actor's copy redone from a
  shadow built from the log (`a_lost_actor_copy_is_redone`).
- **Snapshots.** A snapshot after `R` is an ordinary snapshot. One taken
  between `base_lsn` and `R` is main's state at its LSN, but a rebuild
  cannot start from it and cross `R`; the switch takes a snapshot at `R`
  (storage configured), so later rebuilds start after it.
- **Retention.** While the newest snapshot is older than the newest switch,
  compaction deletes nothing and the newest snapshot at or before that
  switch's `base_lsn` is not pruned.
- **Shipping and restore.** `StateRebase` records ship with their segments.
  `kronik restore` picks the newest snapshot; if a switch in the restored
  segments has a `base_lsn` below it, it also downloads the newest
  snapshot at or before that `base_lsn`, which the first start uses to
  build the shadow.
- **Forks after a switch.** A fork point is never before main's newest
  switch: propose clamps its window to start after it, and `--at` or
  `kronik fork create --at` before it is `BAD_REQUEST`. A production cursor
  that crosses a switch (a base snapshot before it) builds the shadow from
  the same records.

## 7. API, CLI, configuration

| Method and path | Request | Response |
| --- | --- | --- |
| `POST /v1/deployments/{epoch}/rebase` | `{"mode": "continuous" \| "both", "threads", "reason", "dry_run"}` | `{"dry_run", "proposal": {... "rebase": {"rolled_back_epoch", "base_lsn", "irreversible_effects"}}}` |
| `POST /v1/proposals/{id}/promote` | as before | as before, plus `"rebase": {"lsn", "base_lsn", "turns", "irreversible_effects"}` for a rebase |

Creating a rebase needs the `propose` scope (it writes only a fork) and
`pii:read`: it replays on full data, so it cannot be the `--no-pii` fork a
token without `pii:read` gets (review N13-5, ADR 0018). The switch is a
promote (`promote` scope) and needs an approval (`approve`).
`kronik rollback <epoch> --by-replay [--mode continuous|both] [--threads
N] --reason "..." [--dry-run] [--json]` prints the proposal, its summary
and the irreversible effects, and the next commands (`kronik diff show`,
`kronik approve`, `kronik promote`).

`kronik.toml`:

```toml
[rebase]
max_pause = "2s"   # the longest the switch holds new requests
```

No new error codes: refusals are `BAD_REQUEST`, `PROPOSAL_STALE`,
`APPROVAL_REQUIRED`, `POLICY_DENIED` as for proposals.

## 8. Limits

- The replay sees configuration as at the fork point (I5, as every fork):
  grants or limits changed after the deployment are not applied to the old
  code's replay. Its turns become main's state, so effects are answered
  from production's recordings (exact, approximate) or fail closed (I7):
  no simulators, no model and no live GETs; requests with stubs or live
  hosts are refused, and the diff's `options.simulators` is empty. A
  fail-closed answer in a rebase diff means the old code's state rests on
  an effect that never happened, and the grounding rows show it. Fork
  turns are scrubbed of revealed secrets as production's are (I8).
- The last round reads only main's records since the previous round, but
  replays every root input among them; when it does not fit in
  `rebase.max_pause` the switch is refused (step 6) and the operator
  raises `rebase.max_pause`.
- The transplant after the record is not bounded by `rebase.max_pause`:
  its cost is the state of the affected actors.
- One node (v0.3); M16 turns the pause into a per-shard step.

## 9. Tests

| Criterion | Test |
| --- | --- |
| A rollback via replay after a migration gives the old code's state and a list of irreversible effects | `kronik-fork` `rollback_by_replay_after_a_migration_restores_the_old_state` (counter → a schema-1 build that migrates and makes an extra GET; the diff's state, `irreversible`, approval required, the switch: old code, old schema, no migrated key, state as the old code computes it, history kept). |
| Recovery from the log after a `StateRebase` gives the same state as before the restart | `kronik-fork` `the_rebased_state_is_rebuilt_from_the_log` (state hash after the switch = after a restart = after a rebuild from a snapshot before the switch, which crosses the switch and builds the shadow from the log). |
| No root input is lost or duplicated during the switch | `kronik-fork` `no_root_input_is_lost_or_duplicated_during_the_switch` (requests with idempotency keys sent from threads during promote: each key in exactly one root turn of main's effective history, the counter equals the number of answered requests), and `a_switch_that_cannot_pause_in_time_writes_nothing` (a turn hanging on an effect: `PROPOSAL_STALE`, no switch record, held requests answered). |
| Review hardening (v0.3 review) | `kronik-fork` `tests/rebase.rs`: `a_deployment_after_the_rebase_makes_its_promote_stale`, `a_proposal_from_before_a_rebase_switch_is_stale` (§1, §6); `a_timer_fired_during_catch_up_is_replayed_in_its_place`, `a_resume_that_cannot_prove_its_staged_turns_is_refused` (§4 step 2); `consequences_in_flight_at_the_pause_run_on_main_after_the_switch` (§4); `the_pause_holds_requests_at_most_max_pause` (step 6); `a_rebase_scrubs_revealed_secrets_like_production`, `a_rebase_uses_recordings_only_and_its_dry_run_writes_nothing` (§8, I8, I12); `a_message_pending_at_the_fork_point_is_replayed`, `a_resend_of_a_message_the_old_code_ran_is_skipped` (§4); `a_rebase_replaces_and_clears_sql_actor_databases` (§3, SQL actors). |

Plus `kronik-proto` compatibility fixtures for both parts of
`StateRebase`, `kronik-api` `rebase_endpoints`, and the schema checks of a
rebase diff.
