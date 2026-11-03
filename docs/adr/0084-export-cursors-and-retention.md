# 0084. Export cursors, and the audit export holds retention

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

The exporters follow the log from a position of their own. Historically,
retention (`Node::compact`) deleted eligible segments without consulting
export readers, and `LogReader::read` started at the first retained segment.
The cursor and retention hold must therefore preserve replay requests and
make any skipped source range explicit.

- **Audit:** a sink that is down for longer than the history window would
  lose records without anyone noticing, and the export could not be
  complete.
- **Traces:** losing spans is acceptable; losing audit lines is not.
- **Reseal** rewrites segments in place, but only their sealable values.

## Decision

- **One cursor file.** `<data>/export.json` holds per-stream cursor entries,
  committed by temp file, sync, rename and directory sync. Optional
  `control` version 1 carries the applied 128-bit generation and a durable
  pending replay: its earliest cut and old acknowledged-through position.
  Acknowledgement merges newer requests rather than overwriting them.
  The first checkpoint for a new generation is exactly at its cut; pending
  replay clears only when that same generation reaches its replay head.
- **Owned rewind.** `Stream::rewind` runs in an owned `Env` task, so caller
  cancellation cannot lose a request. Audit intent precedes the effect;
  failure records an event and stable error code. New requests wake retry
  loops. Webhook retry keys bind generation; S3 replay gets a new create-only slot.
- **The audit export holds retention, but never production.**
  - `Node::compact` takes a floor set through `RetentionHold`. It is restored
    before the exporter spawns and updated only after durable checkpoints.
    A segment holding records past the floor is kept.
  - The hold is released when free disk falls below `[audit] hold_release`
    (default 2 × `[log] disk_reserve`), before the reserve starts refusing
    root inputs: a sink down for days must not stop the node (I10). Free
    disk is measured for it with or without a reserve.
  - `[audit] max_hold` (default `0s`, no time cap) can also cap the hold.
  - Past either limit, retention deletes as before. The exporter derives
    `audit.gap` from authoritative retained source positions even while a
    remote batch is retrying. Gap notices deduplicate across checkpoint
    failure and restart, and the skipped range itself is durably saved
    before preparing later records. The append uses `check_alive` and
    `kronik_export_gaps_total{stream="audit"}` counts it; the node serves.
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
  requests durable replay. The audit hold follows the durable earliest
  pending cut; an older in-flight acknowledgement cannot cancel it.
- **Trace resume state.** A small `kronik.trace-state/v1` reference holds
  `format`, `slot`, `generation`, `end`, `lsn` and `hash`. Two fixed files
  (`trace-state.0`, `trace-state.1`) plus `trace-state.tmp` hold checksummed
  snapshot/delta frames. The hash chain binds the header, offsets, prior
  hash, length and payload. Dirty keys alone append; compaction starts once
  appended bytes reach the larger of the snapshot size and 64 KiB.
  Original kept-entry sequence and next-sequence values are preserved.
  Each load forces a fresh snapshot rather than resyncing a possibly
  failed inode; pending retries retain the identical reference.
  Legacy null/open-pair/`{open,kept}` state migrates strictly once, before
  audit cursor writes. Corrupt selected modern metadata stalls the trace
  factory rather than discarding causal state.
  Payload limits share the log's 128 MiB `MAX_RECORD`; the selected prefix
  is at most `24 + 2 * (40 + 128 MiB)` bytes. Serialization is bounded
  before allocation; excess is `trace_state_limit`, never truncation.
  The open/kept entry-count limits are not a blanket heap bound.
- **Storage failures.** Ordinary open/write failures retry. Any sync
  failure or EIO latches that writer as `storage_sync`: no later filesystem
  attempts or cursor acknowledgements. Repair/quarantine storage, create
  a new writer and safely rewind. Restart alone is not proof of repaired
  durability.
- **Exports off.** With both cursor exporters off, unreadable `export.json`
  is tolerated without modifying it. Configuration observations remain
  source-audited even when the cache is unavailable.
- **Restore.** Before removing the marker, startup durably clamps or
  initializes both trace and audit cursors, even if absent or configured
  from `"now"`. It drops lost-tail resume state, resets the lost-tail
  audit-configuration hash, preserves/clamps pending replay, and assigns
  a new applied generation. Marker removal is followed by parent-directory
  sync, after the durable cursor writes, with exports on or off.

## Alternatives

- **No hold, as `ship` does.** Simple, but an outage longer than the
  history window breaks completeness silently.
- **An unbounded hold** (this ADR's first draft). Below the disk reserve the
  node refuses new work, so an outside sink could stop production.
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
- Current control/checkpoint evidence is the complete 102-test exporter
  run plus seven actual binary audit tests, including crash-point restore,
  lost audit-configuration cache and fresh from-now initialization.
- `kronik-ship` could later use the same hold for unshipped segments. That
  is out of scope here and listed as a follow-up.
- A real local S3 binary run exercises readback, intentional rewind,
  restart and an unsupported conditional-create stall without cursor
  advance. Its new numbered namespace is append-only; no proof assumes
  arbitrary external deletion plus stale-listing safety.
- Earlier daemon/API/OTLP privacy evidence remains scoped to its observed
  cases; complete retained external/deleted-version coverage is M23 work.
