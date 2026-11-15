# 0124. An erased answer keeps the callee's commit

- **Status:** Accepted (2026-11-15)
- **Date:** 2026-11-15

## Context

`call` is not atomic. If the caller fails after a successful call, the
callee's turn stands: that is why a call may carry a compensation, and why a
standing call is registered as an orphan (Build-Brief §Turn semantics).
ADR 0123 added a third answer the caller cannot read: a callee that committed
while its subject was erased answers with that erasure's tombstone, and the
caller's gate records a `SUBJECT_ERASED` call error. The caller's guest is
right to treat that as a call failure, but the record made it
indistinguishable from a callee turn that did *not* commit (issue #80).

Every consumer of that fact keys on `EffectRecord::successful_call()`:
`TurnFx::call` remembers the compensation only for a successful or timed-out
call; the store's failed-turn pass skips everything else, so it inserts no
`orphans` row and delivers no compensation; `close_open_turn` recovers
neither; and the fork diff's `new_orphans` under-reports. The store's own
erasure path had the same shape: applying an `Erasure` replaced a committed
saved call answer with an `OutcomeKind::Failed` placeholder. `call_committed`
therefore read the callee as failed, and a #30 timed-out call whose callee
committed before the erasure was dropped as "nothing changed".

A record-shape decision was needed because the committed fact has to survive
in the log (I16) and a v0.5.0 record must read the same way.

## Decision

- **The committed fact is carried by existing fields.** A call whose callee
  committed but whose answer is the erasure's tombstone keeps
  `EffectStatus::FAILED` and the host's error text
  `SUBJECT_ERASED: the call's response belonged to an erased subject`; it
  also carries the actual callee in `callee_source` and the observed
  committed outcome in `observed_callee_status = OK`. No field is added and
  the log format does not change. Validation accepts `observed_callee_status
  = OK` only for exactly this status/error/source combination on
  `actor.call`, as it already accepts the observed outcome of a withheld
  reply.
- **A v0.5.0 record counts too.** Such a record has no
  `observed_callee_status`: it was written before this decision. Its
  `status = FAILED`, exact host error text and `callee_source` are the
  committed fact for `successful_call()`. This keeps old logs, snapshots and
  fork comparisons reading as they did, at the cost of trusting the host's
  exact wording rather than an explicit observation; a new record always
  writes the observation.
- **The guest-visible result does not change.** `CallOutcome::Erased` is
  host-internal: the runtime maps it to `call-error::failed` with the same
  text, the `EffectRecord` keeps `status = FAILED` and the same error, and
  the caller's guest still sees `SUBJECT_ERASED`. What changes is the
  bookkeeping: `successful_call()` is true, so the compensation is remembered
  and the orphan is recorded and delivered.
- **A saved answer keeps its commit.** Applying an `Erasure` rewrites the
  subject's values in a `deliveries` outcome to the erasure's tombstone and
  keeps `OutcomeKind::Committed`; a repeated call gets the same
  `SUBJECT_ERASED` error from the tombstoned reply. If the stored outcome
  cannot be decoded it is replaced by a committed reply whose body is the
  tombstone. `call_committed` still treats a v0.5.0 `SUBJECT_ERASED` failure
  placeholder as committed, because that is what it replaced.
- **The orphan names its callee.** The store takes the orphan's callee turn
  from `EffectRecord::callee_source` when the erased answer has no
  `CallEffectResponse` body. The turn is the source the record already
  proves, not a guess.

## Alternatives

- **A new `EffectRecord.callee_committed` bool.** It would be the clearest
  shape, but it changes the log format for one class and forces older
  readers to treat the field as unknown. Existing `callee_source` and
  `observed_callee_status` already say where and what.
- **A new `EffectStatus` or WIT `call-error` variant.** `EffectStatus` is a
  persisted enum and the call error is the guest ABI; a new value there
  would change one of those contracts for a bookkeeping fact.
- **Keep the failure and scan the callee's turn in every consumer.** The
  store, the gate and the child applier each have the call id, but the
  caller's record crosses branches and may be read without the callee's;
  the fact belongs on the record that observed it. The #30 timeout path
  needs the scan because it never observed the callee.
- **Change `keep_erasures`/the sealer instead.** The erased answer is
  correctly unreadable; the defect is that unreadability was recorded as a
  failed callee.

## Consequences

- A caller that fails after an erased answer gets exactly one orphan row
  and its compensation is delivered exactly once, as it is for
  `HOST_REDACTION_FAILURE` that observed OK and for a committed timed-out
  call after #30.
- A callee that fails normally, even with error text of its own, is still
  not a standing call: only a committed outcome mapped by the gate (or the
  exact v0.5.0 host text with a source) sets the predicate, and the new
  record also carries `observed_callee_status = OK`.
- Rebuilds and forks agree: `state.db` keeps the committed outcome, the
  fork's gate uses the same `map_call_outcome`/`prepare_call_outcome`, and
  the diff counts the same orphan.
- The erasure still removes the plaintext: only the structure and the
  commit remain, and every value of the subject is the empty-nonce
  tombstone.
- Verification: `crates/kronik-sched/tests/erased_replies.rs`
  (`a_failed_caller_orphans_an_erased_answer_and_delivers_its_compensation`),
  the store's `an_erased_saved_answer_keeps_a_failed_callers_compensation`,
  the proto's `an_erased_committed_answer_is_a_successful_call`, the sched
  unit test for `prepare_call_outcome`, and the fork diff's orphan test.
  The #30 guards (`timed_out` store test and the effects integration test)
  stay green.

## Related

- ADR 0123 (an erasure stops the plaintext already in flight)
- issue #30 (a call that timed out may still commit at its callee)
- issue #80 (this defect)
