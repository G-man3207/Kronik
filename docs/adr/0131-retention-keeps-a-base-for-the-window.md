# 0131. Retention keeps a base for the whole history window

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13

## Context

The brief: "`retention.history`, 7 days by default, controls how far back
forks and replay can go. Segments older than the window are deleted when a
snapshot covers them." `kv_versions` serves "production's state at any LSN
in the window", which Kronik answers with a snapshot at or before the LSN
plus the log after it.

Before 0.5 compaction deleted segments older than the window that the
newest snapshot covered, and pruning kept the newest `snapshots_kept` (48)
and the oldest snapshot the log continued. That snapshot was between 2 and
7 days old, so a fork older than it had no base and was "outside
retention" (issue #66). The design's "newest snapshot at or below the
oldest retained LSN" could not hold either.

A snapshot taken while a turn is open also holds that turn's `open_turns`
row: the position of its `TurnBegin`, which the start reads to run the turn
again. Compaction could delete that segment (issue #35).

## Decision

- **The window's base** is the newest snapshot whose state is older than
  the start of the window (its logical time strictly before the cutoff, as
  a fork point is outside the window only when its time is: turns share
  milliseconds, so a snapshot of the cutoff's own millisecond can be newer
  than a fork point of that millisecond that is in the window).
  Compaction deletes only segments the base covers, so the log and a
  snapshot reach every point in the window. While no snapshot is old
  enough, nothing is deleted and the oldest snapshot is kept to become it.
  After an erasure deleted the snapshots before it and none after it is
  old enough yet, the oldest one after it is the base.
- **Kept snapshots:** the newest `snapshots_kept`, the base, and one per
  seventh of `history` (at least `snapshot_interval` apart) between them.
  The base moves in steps of at most that, so the log reaches back at most
  a step and an interval further than `history`.
- **Open turns pin the log.** No segment is deleted from the one holding
  the `TurnBegin` of a turn open in the live state or in any kept snapshot;
  the manifest's `segments` include it. A start that still misses it is
  `STORAGE_CORRUPT` naming the execution id.

## Alternatives

- **Change the documents to the old behavior.** The brief makes `history`
  the bound for forks and replay; the old behavior refused up to five days
  of the window.
- **Keep every snapshot of the window.** One per interval: 168 copies of
  the state with the defaults. Thinning to one a day bounds the extra
  replay to a day of records at about six more copies.
- **Copy each open `TurnBegin` into `state.db`.** A second copy of turn
  inputs that reseal and erasure would also have to cover, and no help for
  snapshots older releases took. The log stays the one copy instead.

## Consequences

- More disk: about six more snapshots, up to a day more log than
  `history`, and after an upgrade no deletion until a kept snapshot has
  aged out of the window (up to about 5 days with the defaults). A turn
  open longer than `history` holds back retention until it ends.
- A cursor applies at most `snapshot_interval` of records within the
  newest `snapshots_kept` intervals and at most a step and an interval
  older than that.
- Verified by the plan's unit tests over weeks of hourly snapshots, a fork
  at the old edge of the window after the base moved, and a start from a
  snapshot with an open turn after retention.
- Revisit if snapshots become incremental, or if `history` is made much
  longer than a week.
