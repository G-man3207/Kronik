# 0011. Closed-segment footer index

- **Status:** Accepted
- **Date:** 2026-10-25

## Context

SPEC.md requires a closed segment to be immutable and to carry a footer
index from actor to offset. `kronik-log` already reserved kind 255 and
readers already skip that kind without consuming an LSN. Nothing wrote it.
A format version bump would make every segment written so far unreadable.
The index must not be a `Record` and must not live in `state.db`: retention
deletes a segment file on its own, and history already has `turn_index`.

A crash can happen after the last record is fsynced and before the footer
is. That segment must still open. Reseal rewrites a segment only when a
record changes; a rewrite that changes nothing must not change bytes.

## Decision

- Payload version 1, little-endian, after the existing envelope: `FIDX`,
  `u32` version `1`, then entries of `u16` kind length, kind, `u16` key
  length, key, `u32` count, and `count` times `u64` file offset. Offsets
  are that actor's `TurnBegin` and `TurnRecord` entries in this segment,
  ascending. Actors are sorted by kind, then key. Empty actor strings are
  omitted. The envelope LSN is 0 and is not a log LSN. Kind 255. No format
  version bump.
- The writer appends the footer when a segment rolls, fsyncs it, then
  switches to the next segment. Nothing is appended after a footer. On
  open, if the last segment's last valid entry is a footer, that segment
  is closed and the next segment starts at `next_lsn`. A torn footer is a
  torn tail and is truncated, as any other torn tail.
- `rewrite_segment` drops the old footer and writes a new one, with the
  new offsets, only when a record changed, and fsyncs that image as it
  already did. A no-op rewrite leaves the file alone, including a missing
  footer.
- `footer_index(path)` returns `None` when there is no footer, and `Err`
  when a footer is present but does not parse or an offset is outside the
  segment. Callers may keep using `turn_index`. A segment with no footer
  still decodes.

## Alternatives

- **A log format version bump.** Kind 255 was reserved so old readers skip
  the entry. A new version would reject segments that have no footer.
- **Store the index in `state.db`.** The segment file would not carry its
  own index, and compaction deletes segments without consulting that table
  for this purpose. The brief puts the index on the segment.
- **Invent a footer on every rewrite, including a no-op.** Reseal treats
  unchanged bytes as unchanged. Writing a footer would make a no-op
  rewrite look like a change.
- **Require a footer to read a segment.** Every segment written before
  this, and a crash before the footer is fsynced, would be
  `STORAGE_CORRUPT`.

## Consequences

- Closed segments written from now on end with kind 255. Readers that
  already skip that kind see the same records and the same next LSN.
- History does not switch to the footer. The acceptance is that the index
  exists and is correct (`footer_index`, tested in `kronik-log`).
- A crash before the footer fsync leaves the segment open. A crash after
  it starts the next segment instead of appending after the footer.
- Revisit this if a reader needs the index on the hot path, or if an actor
  key no longer fits in a `u16` length.
