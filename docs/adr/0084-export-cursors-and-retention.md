# 0084. Export cursors, and the audit export holds retention

- **Status:** Proposed
- **Date:** 2026-10-27

## Context

The exporters follow the log from a position of their own. Retention
(`Node::compact`) deletes a closed segment once a snapshot covers it and it
is older than `[retention] history`. It looks at no reader, and
`LogReader::read` silently starts at the first segment that still exists.
`kronik-ship` has the same exposure today.

- **Audit:** a sink that is down for longer than the history window would
  lose records without anyone noticing, and the export could not be
  complete.
- **Traces:** losing spans is acceptable; losing audit lines is not.
- **Reseal** rewrites segments in place, but only their sealable values.

## Decision

- **One cursor file.** `<data>/export.json` holds `{"traces": lsn, "audit":
  lsn}`. It is written as `write_synced` writes: temp file, fsync, rename,
  directory fsync. A cursor moves only after the sink acknowledged the
  batch.
- **The audit export holds retention, but never production.**
  - `Node::compact` takes a floor, the audit cursor, set through a
    `RetentionHold` the exporter updates. A segment holding records past it
    is kept.
  - The hold is released when free disk falls below `[audit] hold_release`
    (default 2 × `[log] disk_reserve`), before the reserve starts refusing
    root inputs: a sink down for days must not stop the node (I10). Free
    disk is measured for it with or without a reserve.
  - `[audit] max_hold` (default `0s`, no time cap) can also cap the hold.
  - Past either, retention deletes as before. The export then writes an
    `AuditEvent` `audit.gap` with the lost range, through the `check_alive`
    path, and counts `kronik_export_gaps_total{stream="audit"}`. The node
    keeps serving.
  - Lag shows in `kronik export status`, `kronik_export_lag_records` and
    `kronik doctor`, which warns once the hold is older than
    `[retention] history`.
- **Traces do not hold retention.** Past retention, they skip to the first
  segment and count a gap.
- **Reseal.** Neither export carries a sealable value, and `record_hash` is
  over the canonical form (each sealable replaced by its subject tag,
  ADR 0083), so a reseal changes nothing either exports.
- **First start.** `[audit] from = "start"` (default) exports from the first
  retained record; `"now"` starts at the applied LSN.
- **Rewind.** `kronik export rewind <stream> --to LSN --reason R [--dry-run]`
  moves a cursor back to re-send. It is audited with an `AuditEvent`. The
  audit hold drops to its point at once and stays there until the follower
  resends from it.
- **Restore.** The first start after `kronik restore` clamps every cursor
  to the restored log before it removes the restore marker, with the
  exports on or off.

## Alternatives

- **No hold, as `ship` does.** Simple, but an outage longer than the
  history window breaks completeness silently.
- **An unbounded hold** (this ADR's first draft). Review H2: below the disk
  reserve the node refuses new work, so an outside sink could stop
  production.
- **A hold capped by default (e.g. 30 days).** Bounds disk use, but turns a
  long outage into a gap that is recorded yet permanent. The default leans
  to completeness, and the cap is one setting (open question in m28-otel
  §12).
- **A cursor in `state.db`.** It would be rebuilt from the log on a
  `state.db` loss and is not part of the replicated state. The export
  position belongs to this node's exporter, like `ship.json`.

## Consequences

- A sink that stays down makes the log grow until the release point; then
  the hold gives way and the gap is itself an audited, exported record. The
  hole is never silent, and production never waits on the sink.
- Tests: a sink answering 503 with a disk budget near the reserve gives a
  gap record while root inputs are still admitted.
- `kronik-ship` could later use the same hold for unshipped segments. That
  is out of scope here and listed as a follow-up.
- Verified by tests:
  - compaction with a hold below a segment keeps it;
  - with `max_hold` exceeded, it deletes the segment and the gap
    `AuditEvent` appears;
  - a restart resumes from the cursor (part of the audit e2e test).
