# 0017. StateRebase: the fork's turns in main's log, and a switch derived from them

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

M13: a rollback via replay forks before a deployment, replays every root
input since then through the old code, and switches main to the state that
replay produced: "Mains historik behålls, och tillståndet byggs därefter
vidare från forken." I4 says state tables, indexes and snapshots are
derived and can be rebuilt from the log. Main's log holds the new code's
turns since the deployment; the state after the switch is built from the
old code's turns, which until now existed only in the fork (in memory and
in `branches/<fork>/log`, which a user can delete). A new record needs a
versioned Protobuf schema and a compatibility fixture (I5, I16, SPEC
"Format changes"); M12 took envelope kind 15.

## Decision

- **One new record kind, `StateRebase`, envelope kind 16** (the next free
  number after M12's 15; branches that add records later take 17 and up),
  in `proto/kronik/log/v1/branch.proto`: `rebase_id` and `oneof part
  {RebasedTurn turn; RebaseSwitch switch}`.
- **The fork's turns are copied into main's log** as `RebasedTurn {fork_lsn,
  record}` records before the switch, one per fork turn, in fork order.
  They do nothing to main's state until a switch with the same id. Each
  gets a main LSN and log position, so state rows built from it (`kv.lsn`,
  dead letters, `actors.last_lsn`, `deliveries`) carry LSNs that resolve in
  main's log.
- **The switch defines main's state as a function of main's log**:
  `state(R) = transplant(state(R − 1), shadow)`, with `shadow = state(base) +
  the rebase's RebasedTurn records + main's Erasure records in (base, R)`,
  all applied as recorded (no guest code). The transplant replaces the
  affected actors' rows and databases, the mailbox, the old code's
  deliveries, dead letters and orphans, adds the rebased turns to
  `turn_index`, and keeps main's ingress keys, trees, configuration and
  history (`docs/design/m13-rebase.md` §3).
- **The switch carries its `Deployment`** (cause `ROLLBACK`, the rebase id
  as `proposal_id`), so code and state change in one record and one
  `state.db` transaction; no new `DeploymentCause` value.
- **Rebuilds that cross a switch** build the shadow from the newest
  snapshot at or before `base_lsn` (else LSN 1). The switch takes a
  snapshot at `R` when storage is configured; until a snapshot at or after
  the newest switch exists, retention keeps that base snapshot and the log
  after it, and restore downloads it when the newest remote snapshot is
  between a switch's base and the switch.
- Compatibility fixtures: the bytes of a `StateRebase` with each part
  (`crates/kronik-proto/tests/fixtures/state-rebase-*-v1.hex`).

## Alternatives

- **Re-run the replay on rebuild** (the switch names the old code and the
  window; recovery runs the deterministic replay). The log would stay
  small, but recovery would run guest code, and only the same engine
  version guarantees the same result (I1): after an engine upgrade the
  state could not be rebuilt.
- **Reference the fork's log** (keep `branches/<fork>/log` as part of
  main's history). Two logs would be the truth: shipping, restore,
  retention and reseal would each have to know about them, and deleting a
  fork would break main.
- **A state delta in the switch record** (the difference between main's
  state and the fork's, as writes and SQL changesets). One record, but it
  can exceed the 128 MiB record limit, schema changes of SQL tables cannot
  be expressed as changesets, and rows written by the old code would have
  no turn to point at.
- **Copy all the fork's turns at the switch.** Simpler, but the copy is as
  large as the window's history and would not fit in the 2 s pause.
- **A snapshot as the source.** Snapshots are derived (I4); they cannot be
  the only record of a state.

## Consequences

- Main's log grows by the window's rebased turns (about the size of the
  history since the deployment).
- Code that reads turns at an LSN treats a `RebasedTurn` as a turn
  (`Record::turn`): history, `GET /v1/turns`, reseal of the values it owns.
  Trace keeps showing the production tree.
- A fork point before main's newest switch is refused; replays never mix
  the history before a switch with the state after it. A proposal created
  before a switch is `PROPOSAL_STALE` at promote.
- A rebased turn holds no revealed secret value: fork turns are scrubbed
  as production's are (I8) before they are logged or staged, so main's log,
  its shipped segments and the rebased state carry `[secret:<name>]`.
- Staged records of a rebase that is never switched stay inert in the log;
  a later switch of another rebase ignores them (it names its own records
  by id and LSN range).
