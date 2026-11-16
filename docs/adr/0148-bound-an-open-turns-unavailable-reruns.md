# 0148. Bound an open turn's UNAVAILABLE re-runs to three starts

- **Status:** Accepted (2026-11-16)
- **Date:** 2026-11-16

## Context

A `TurnBegin` without a turn record is re-run at every start (m2-effects
§4). The worker retries a re-run that ends `UNAVAILABLE` twelve times over
about 36 s (commit "let a re-run wait for what is unavailable for a
while"), because most causes of that code — a recorded call whose callee
turn the applier has not caught up with, a projection that is still being
built — are temporary within one start. The distinction matters: an
`UNSAFE` effect is never redone (I17), so the turn must not end while its
recorded prerequisite is merely late.

The retries were bounded within a start, not across starts. A condition
that never clears (for example a recorded successful `call` whose reply
the gate cannot hand to the guest, see `effects::Gate::call`) therefore
spent the same 36 s at every start, ahead of the actor's later inputs, and
kept its begin's segment from retention for ever: the log grew, and the
actor's mailbox did not move. Issue #76 asked whether such a turn should
be failed after N starts or a time bound, and how an operator sees it.

`SECRET_UNAVAILABLE` is a different case. The recorded value is needed
again, and design m23 §5.3 says a turn waits for a secret backend without
bound; failing it for good on a provider outage would break the replay
guarantee the value exists for. A time bound would also fire after a long
downtime in which no start ever tried the turn, and a new error code
would have to say what is not yet known: whether the prerequisite is
gone or merely late.

## Decision

A start whose re-run still ends `UNAVAILABLE` after its in-start retries
counts one start. On the third such start the turn is closed as failed
with `UNAVAILABLE`, under its own execution id, with its latest recorded
effects, through the existing closing ladder (`close_open_turn`); a
message or timer input other than a `call`'s becomes a dead letter, which
can be resent after the prerequisite is fixed. The count is kept in
`state.db`'s `meta` table, per branch and execution id:

- a start with `SECRET_UNAVAILABLE`, a successful or otherwise closed
  turn, or a node that has failed (`self.fatal()`) does not count;
- a turn that ends within its in-start retries never reads the count;
- a count no open turn owns is deleted at the next start, and the count
  is not part of the state hash (it is recovery bookkeeping, not
  materialized state). A rebuilt `state.db` starts from zero and gives
  the turn three fresh starts;
- each start that leaves the turn open, and the closing start, logs a
  warning naming the actor, execution id, starts used and the limit.

Three is the number of starts at which a condition has survived each
start's own retries twice; it bounds repeated downtime without treating
one restart with a slow applier as a permanent failure. A fork's copy of
`state.db` counts for its own branch, so a fork does not spend main's
starts.

## Alternatives

- **Close at the end of the first start's retries.** A restart is often
  what clears an unavailable applier or a callee that has not committed
  yet; this fails turns that the existing retry budget existed to keep.
- **A wall-clock bound since the `TurnBegin`.** It measures downtime as
  well as attempts, so a daemon restored after a long stop would fail
  every open turn on its first start, before trying once.
- **Leave the turn open and drop it from the actor's queue.** The turn is
  the delivery of its input: later inputs for the actor must not overtake
  it, and a failed record is what releases its log segment.
- **A new error code.** The turn failed because its prerequisite stayed
  unavailable; `UNAVAILABLE` is that code. A new one would have to
  classify a state the host cannot observe and would grow the stable
  catalog for a recovery detail.
- **A log record for the count.** The count is host recovery bookkeeping,
  not turn state; adding an envelope kind would be a format change for a
  counter that a rebuilt state is allowed to reset.

## Consequences

- An actor's later inputs wait behind at most three starts' worth of
  `UNAVAILABLE` retries, and a stuck turn's segment is released when its
  closing record applies.
- An operator sees the warnings, then the failed turn in `history` and,
  for a message or timer other than a `call`'s, in `dead-letters list` with
  `UNAVAILABLE` and the message naming the start count. Fixing the cause and
  `kronik dead-letters resend` is a new root input.
- A dependency on a secret backend stays unbounded and keeps its own
  visible stall (`kronik_secret_recovery_stalled`, the wait warning).
- The bound is verified by the recovery unit test
  `an_open_turn_is_closed_after_three_starts_whose_rerun_is_unavailable`
  (three starts, the closing record, one dead letter, a fourth start that
  runs nothing) and the `rerun_waits` tests, which pin one start's
  allowance and the secret exemption.
- Revisit if operators need the number configurable, or if real backends
  produce `UNAVAILABLE` outages that outlast three starts.
