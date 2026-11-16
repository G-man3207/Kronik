# 0151. A promote orders turn appends against its gap

- **Status:** Accepted (2026-11-16)
- **Date:** 2026-11-16
- **Amends:** ADR 0013's set-switch path for `PROMOTE`

## Context

m3-fork §8 defines a promote's `Deployment.unverified_inputs` as the main root
turns whose LSN is in `(verified_through_lsn, effective_lsn]`, where
`effective_lsn` is the Deployment's own LSN. The #85 fix took the count under
the switch gate, so roots that committed while the switch waited for the gate
are included (issue #85). But the gate only stops turns from *starting*: a
turn that started before the switch keeps running, and its `TurnRecord` could
be appended between the count and the `Deployment`. Its LSN was then inside
the interval while the count did not include it (issue #126).

Two ways to close that window have different failures.

- Waiting until no turn runs also waits for every in-flight effect. A turn
  parked after a call, as a crash test leaves it and a restart recovers it,
  never finishes before promote. The promote would wait for ever (the
  existing `a_rerun_across_a_schema_raising_switch_keeps_its_code_version`
  fails).
- Serializing every turn append makes each turn wait for the previous
  append's fsync, losing group commit and roughly halving throughput.

The count cannot be recomputed from the Deployment's LSN after the fact
without making the persisted record mutable or teaching every log reader to
recompute it.

## Decision

A second gate orders turn **record appends**, not whole turns.

- A turn whose record is a `TurnRecord` takes the commit gate's read half
  immediately before it enqueues the record, and releases it when the append
  has its LSN. The read half is shared: appends still group-commit together.
  Every other record (an effect result, a begin, configuration) is outside it.
- A promote takes the switch gate for writing as before, then the commit
  gate's write half, then sends a log barrier. The barrier writes no record
  and answers with the last LSN already in the log, which is the end of every
  append that won the read half. The promote counts root turns through that
  head and appends its `Deployment` while the write half is still held; the
  write half is released once that record is applied.
- Therefore an append under way before the count is in the gap, an append
  that reaches the gate after it is ordered above the Deployment and is not
  in the gap, and none can land between them. A running turn need not finish:
  the existing open-turn re-run and crash tests keep working. Such a turn
  finishes old code above the Deployment's LSN, the case §8 already states
  for running turns, and is not counted as having run old code *below* the
  switch.
- The commit write guard travels into the switch task with the deploy lock
  and the switch write guard, so a caller that disconnects cannot release the
  ordering before the Deployment is appended. A revoked request gives up
  while waiting for the guard, before anything is written.
- A dry run takes the same commit gate and barrier and counts through it,
  without appending anything. For the same state it projects what the real
  promote records.

Deploy and rollback record no gap and keep their path. The rebase switch
already drains with `rebase.max_pause`; a rebase promote does not use this
path.

## Alternatives

- **Drain every running turn before counting.** Correct for the gap and
  rejected: an open turn held after a call blocks promote for ever, and these
  turns are exactly the crash-recovery path promote must work through.
- **Count in the applier from the Deployment's LSN.** The record's field would
  be a placeholder in the log, and every reader, verifier and replay would
  have to recompute it from state that may have been compacted.
- **Serialize all turn appends behind one mutex.** It closes the window but
  costs group commit: appends would fsync one at a time.
- **A barrier record written into the log before the count.** There is no
  no-op record that older readers accept, and a real record would enter
  history, indexes and retention for no state.

## Consequences

`unverified_inputs` is now the log interval it names, including a turn that
was already appending when the switch began and excluding one that reaches
the append after the Deployment. Promote does not wait for running effects,
so an open turn does not block an upgrade; its later record runs the old code
it started with and is outside the gap, as §8 already says for running turns.

Turn appends to main serialize against a promote only while the promote's
barrier and Deployment are written. An append that reaches the gate during
the switch waits for the Deployment to be applied; it does not hold up the
install, and appends that arrived before it still group-commit. Reads,
effects and already-running turns are unaffected.

The crash/re-run test (`a_rerun_across_a_schema_raising_switch_keeps_its_code_version`)
and the `a_promote_waits_for_a_running_turn_and_counts_it` regression cover
the ordering: a turn parked just before its record append holds the read
half, promote waits, the turn commits below the Deployment, and the count
equals the log's root turns in the interval. The dry-run test asserts the
projection matches the recorded count.
