# 0006. Logical time: +1 ms only across restarts

- **Status:** Accepted (deviates from the brief's formula; the maintainers
  may overrule)
- **Date:** 2026-10-25

## Context

A turn's `now-ms` is its logical time, constant within the turn and
recorded in `TurnBegin`/`TurnRecord`. The brief ("Turn-semantik", logical
time and randomness) defines it as the largest of three values:

1. the host's wall clock at turn start,
2. the log's high-water mark plus 1 ms,
3. the logical time of the message or timer that started the turn.

I15 requires that logical time never goes backwards within a branch and
shard, even when the host clock does or leadership moves, and that a turn
never gets a lower time than the message or timer that started it.

Read literally, (2) adds 1 ms per turn: every turn's time is at least the
previous turn's time plus 1 ms. That makes times unique, but logical time
must then advance by at least 1 ms per turn. Above 1 000 turns per second on
a node it runs ahead of the wall clock, and under sustained load the gap
grows without bound:

- M1 measured about 220 turns/s for one actor, and the brief's target is at
  least 1 000 turns/s for the Rust counter. At 2 000 turns/s logical time
  gains one second per second. The 1 000 turns/s figure is the drift line,
  not the throughput gate ([ADR 0111](0111-cross-actor-throughput.md)).
- `now-ms` then reports times in the future: timestamps that guests store,
  compare with external systems, or show to users drift from reality.
- Timers (M2) are due at a logical time. With logical time ahead of the
  wall clock, the scheduler must either fire them early in real time or
  stop comparing them with the wall clock.
- The drift only recovers when load drops below 1 000 turns/s, and then at
  the rate the load allows.

The purpose of the high-water mark, as the brief states, is that it "lies
in the log and follows when leadership moves": a restarted node or a new
leader must never hand out a time below what the log already contains.
That only needs the +1 ms at the point where a new process takes over.

## Decision

`now-ms = max(wall clock at turn start, hwm, parent)`, where:

- `parent` is the starting message's `sent_logical_time_ms` or the timer's
  due time (0 for root inputs);
- `hwm` is the largest logical time this process has handed out, updated
  under one lock together with the assignment;
- at startup (and, from v0.4, when a node becomes leader of a shard) `hwm`
  starts at the largest logical time in the log plus 1 ms. `state.db` keeps
  it as `meta.time_hwm`, the maximum over all `TurnBegin` and `TurnRecord`
  times, applied in the same transaction as the records.

Within one run, several turns may therefore share a millisecond. Code that
needs unique, ordered identities uses `causal-id` or the turn id
(`<branch>:<lsn>`), not `now-ms`.

Implemented in `kronik-core::time::LogicalClock` and recovered in
`kronik-sched::Node::start`; documented in `docs/design/m1-core.md` §3.

## Why I15 still holds

- **Clock jumps.** Each assignment takes the maximum with `hwm`, the
  largest time already handed out, so a host clock that moves backwards
  never lowers `now-ms` (unit test `clock_jump_back_never_lowers_time`; the
  simulator moves the wall clock back by up to 10 s in every run, and the
  webhook workload once by 5 to 10 minutes).
- **Restarts and leadership changes.** A new process starts above every
  time in the log. Times handed out by the old process to turns that never
  reached the log were never observed durably: such a turn sent no response,
  committed nothing and, from M2, performed no effect before its fsynced
  `TurnBegin`, which carries the time and is part of the maximum.
- **Causality.** `parent` is part of the maximum, so a receiver never runs
  before its message or timer (checked on every message turn in every DST
  run, and in `kronik-sched` tests).
- **Per actor.** An actor runs one turn at a time and takes its time at
  turn start, so its times are non-decreasing in log order (checked per
  actor over the whole log, across crashes, in every DST run).

What neither formula guarantees is monotonic time in LSN order *across*
actors: time is taken when a turn starts and the LSN when it commits, so two
concurrent turns can commit in the opposite order of their times. This is
the same under the literal brief formula and is not required by I15 as
written ("never backwards" refers to time handed out, and to the starting
message).

## Alternatives

- **The literal formula (+1 ms per turn).** Unique, strictly increasing
  times, but unbounded drift above 1 000 turns/s per node (see Context).
  Rejected.
- **+1 ms only when the wall clock has not advanced**
  (`max(wall, hwm + 1)`). The same drift: every turn in a busy millisecond
  pushes `hwm` forward. Rejected.
- **A hybrid logical clock** (milliseconds plus a logical counter). Unique
  and bounded, but the WIT's `now-ms` is a plain `u64` of milliseconds, and
  hiding a counter in it would change its meaning. Could be added as a
  separate host function if guests need unique ordered timestamps.
  Not needed now.

## Timers (2026-11-13)

The first version of this ADR said that timers "can be due against
[`now-ms`] directly". The wheel compared due times with the wall clock
alone, though. After the host clock stepped back by Δ (an NTP correction, a
VM resume, an operator fixing a clock that ran ahead), a timer already due
in logical time waited until the wall clock had climbed back by Δ. The
simulator corrected its clock before it waited for the webhook retries, so
that runs could finish (issue #40).

A timer is due when either of these comes first:

- logical time, `max(wall clock, hwm)`, reaches its due time;
- the delay it had left when the wheel took it has passed on the
  monotonic clock. The wheel takes a timer when its turn commits, or at
  start for the rows in `state.db`, and the delay left is the due time
  less the logical time then.

The deadline lives only in memory. Nothing recorded changes: the due time,
the `TimerInput` and the timer turn's `now-ms`, `max(wall, hwm, due)`, are
as before, and I15 holds as above. Only the moment a timer fires changes,
and that is not recorded.

So a host clock that steps back delays no timer. Logical time holds still
at `hwm` until the wall clock catches up, except that a timer turn runs at
its due time. A timer that fires during the catch-up therefore moves
logical time forward to its due time. `now-ms` stays at most Δ ahead of the
wall clock and returns to it once timers stop firing. It cannot run further
ahead: a due time is its scheduling turn's time plus a delay, and the
monotonic clock has counted that delay too. A clock that steps forward
fires at once the timers that logical time passes, as before.

Alternatives considered:

- **Compare due times with `max(wall, hwm)` only.** Timers already due fire
  at once, but one due later still waits out the step, since logical time
  holds still. Adding 1 ms per turn while the wall clock is behind moves
  logical time only with traffic. Rejected.
- **A wall-clock deadline per timer.** A step back after the timer was set
  delays it just the same. Rejected.
- **Keep the stall and document it.** Retries, leases and holds built on
  timers would be late by the step, minutes after an NTP correction.
  Rejected.

Tested by the wheel's unit tests, by `a_clock_step_back_delays_no_timer`
in `crates/kronik-sched/tests/effects.rs` (a 1 s timer set before and one
set after a 5-minute step back both fire after about 1 s), and by DST:
the webhook workload's wall clock steps back 5 to 10 minutes once and is
no longer corrected before the drain, and every run checks that a timer
turn runs at or after its due time.

## Consequences

- `now-ms` stays within the host clock's error of real time under any
  load. After the host clock steps back by Δ, it holds still for up to Δ
  (or runs at the due times of the timers that fire meanwhile) until the
  wall clock catches up.
- A timer fires when logical time reaches its due time or when its delay
  has passed on the monotonic clock, whichever is first, so a clock step
  back does not delay it (see Timers above).
- Equal `now-ms` values in different turns are normal; guests must not use
  `now-ms` as a unique key (docs for the SDK should say so).
- Revisit if the maintainers prefer the literal formula, or if a cluster design
  (v0.4) needs strictly increasing time per shard.
