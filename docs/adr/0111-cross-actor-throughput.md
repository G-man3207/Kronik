# 0111. The 1 000 turns/s target is across actors

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

The build brief's performance targets require at least 1 000 committed
turns/s for the Rust counter with group commit. The brief says to measure,
record the number in `docs/perf.md`, and adjust the target by an ADR.

[`docs/perf.md`](../perf.md) records the M1 run (2026-10-25). Across actors
the counter commits about 7 900 turns/s on the development machine and
2 770 turns/s on the 2-vCPU VPS: 7 842 and 2 769 with 64 actors, 7 995 and
2 774 with 256 actors, with no errors. One actor commits about 180 to 210
turns/s: 181 and 174 with one client, 206 and 190 with 16 clients. The
recorded cause is that an actor runs one turn at a time, so each turn waits
for the group-commit window and one fsync, about 4 to 5 ms.

Read per actor, that rate is below 1 000. Read across actors, the 64- and
256-actor rows are above 1 000. No earlier ADR said which reading is the
gate.

[ADR 0006](0006-logical-time.md) uses 1 000 turns/s as the line above which
the brief's literal logical-time formula (+1 ms per turn) runs ahead of the
wall clock. That use of the number is the drift line. It is not this
throughput gate, and this decision does not change it.

## Decision

The brief's 1 000 committed turns/s target is across actors, not per actor.
It is met: about 7 900/s on the development machine and 2 770/s on the
2-vCPU VPS. The per-actor rate, about 180 to 210 turns/s, is not a gate.

The measurement table is not rewritten to claim that the per-actor rate
meets 1 000/s. The group-commit window and the fsync path are unchanged.

[ADR 0006](0006-logical-time.md)'s 1 000 turns/s remains the logical-time
drift line. The formula and the threshold are not changed.

## Alternatives

- **Treat 1 000/s as a per-actor gate, and change group commit or fsync
  until one actor reaches it.** The measured per-actor rate would stay a
  miss until that change. Rejected: the target is across actors and is
  already met, and this decision does not change the commit path.
- **Replace 1 000/s with the measured rate across actors.** The brief's
  number already holds when read across actors. Replacing it would also
  invite moving the drift line in ADR 0006. Rejected.
- **Raise or lower the ADR 0006 drift line to follow the throughput
  reading.** The literal formula still drifts above 1 000 turns/s per node,
  including at the measured rate across actors. Rejected. The drift line
  stays at 1 000 turns/s.

## Consequences

- The throughput gate is met. A per-actor rate of about 180 to 210 turns/s
  is recorded, explained, and not a failure of this target.
- A later change to group commit or fsync needs its own measurement, and an
  ADR if it changes a target or an invariant.
- Revisit if a per-actor rate becomes a gate, or if a later measurement
  across actors falls below 1 000 committed turns/s.
