# 0024. Watch after promote: guards from the log

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

M11: "`kronik watch <deployment> --for 10m` compares the error rate and
latency after the deployment's `effective_lsn` with a window before it.
The rules are `[[guard]]` in the policy, with action `alert` or
`rollback`. On a breach a `GuardTriggered` record with the metrics is
written, and a rollback runs if it is allowed; a deployment with a schema
change alerts instead." Everything is history (I5), and the watch adds no
concept (I13).

The process-wide metrics (`kronik_turn_duration_seconds`) are write-only by
design and are not in the log; the log had no wall latency of a turn.

## Decision

- **Metrics from the log only.** Error rate from turn outcomes; latency
  from a new, additive `TurnRecord.duration_us` (field 23) the node writes.
  Windows are by logical time around the deployment and filtered by
  `config_epoch`, so the same log gives the same metrics.
- **Guards in the policy file.** `[[guard]]` next to `[[rule]]`, the same
  CEL engine and limits, the variable `guard` instead of `diff`. An
  erroring guard fires as `alert`. Without guards, two defaults apply:
  error rate up (rollback) and p99 up (alert), each after 10 turns.
- **A daemon job per watch**, persisted under `<data>/watches/` and
  resumed after a restart, like proposal jobs (ADR 0022) but resumable,
  because it is cheap to recompute from the log.
- **Record kind 17 `GuardTriggered`**, informational, written once per
  guard and watch with both windows, the LSN the metrics observed through
  and the outcome.
- **Rollback first, then the record.** The record holds the outcome and
  the rollback's epoch, which are known only after the attempt. A crash in
  between is closed at resume: a rollback deployment whose audit names the
  watch is recorded, not repeated.
- **Schema changes alert.** The rollback path's own check decides
  (`ROLLBACK_SCHEMA_CHANGED`); the record says `ROLLBACK_REFUSED_SCHEMA`.

## Alternatives

- **Gateway status codes and response times.** Not in the log; a watch
  could not be checked or resumed from history.
- **`fuel_used` as latency.** Deterministic but not what an operator calls
  latency; a slow external call costs no fuel.
- **Write `GuardTriggered` before the rollback.** It would need a second
  record when the rollback fails, or claim an epoch that did not exist yet.
- **A separate guards file or record.** A second policy concept; the
  rules file is already versioned by `Policy` records.

## Amendment (2026-10-27): a watch never undoes a later deployment

The M11 review found that a guard's rollback could revert a newer
deployment, and that the statistics could roll back healthy code.

- **Only the latest deployment of its kinds is watched**, and the window
  after it ends at the first later `Deployment` that touches one of them.
  The watch then ends `superseded` and acts no more: the code it judged no
  longer runs.
- **The rollback pins the watched code.** Its `CodeSwitch` pins the
  watched deployment's `KindVersion`s, checked under the deploy lock with
  the switch, so the plan read outside the lock holds and only the watched
  kinds go back. A failed pin ends the watch `superseded`.
- **A rollback without its record is recorded at resume** for the guard
  its audit reason names, without evaluating again.
- **Statistics.** No evaluation before the first turn after the
  deployment. An erroring guard no longer fires: it alerts once and is
  evaluated again. A guard naming `diff` is refused. `REJECTED` turns are
  client errors, not failures; a committed HTTP 5xx is a failure. Turns
  without a duration are not latency samples. The default rollback needs
  20 turns and 3 failures, the latency alert a measured p99 before.
- **Control.** `kronik watches stop`; `--for` at most 24 hours; a `guard`
  key, even `guard = []`, replaces the defaults, and `policy show` prints
  the guards in force.
