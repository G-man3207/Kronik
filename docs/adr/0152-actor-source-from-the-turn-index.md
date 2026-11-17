# 0152. An actor source is the indexed frame

- **Status:** Accepted
- **Date:** 2026-11-17

## Context

Every successful `actor.call` waited on `Node::actor_source` before the caller
could record the effect. That walk started at `LogConfig::first_lsn` (default
1), captured before `Log::open` and never replaced with the opened log's first
LSN, and decoded every record through the callee LSN. On a node that still
held its first segment each call was a blocking read per retained record.
After retention moved the log start past 1, the first delivered frame was not
LSN 1, the walk reported an incomplete prefix, and the call failed with
`UNAVAILABLE` (issue #160).

`turn_index` and `open_turns` already store that frame's segment and offset.
The applier writes a row only after decoding the records through that LSN, so
the index is a dense-prefix watermark. A gap before the opened log's first LSN
is retention, not a missing prefix.

## Decision

Resolve a callee `ActorSource` from `turn_index` (a completed turn) or
`open_turns` (a `TurnBegin` that has not closed) and one
`read_at_with_namespace`. Do not walk earlier records on the call.

The native source profile's start LSN is the opened log's first LSN, not the
config default. A frame the index does not hold is unavailable, including a
CRC-valid frame appended after an unknown record. The namespace still comes
from the segment header of the file that holds the frame.

A CRC-valid unknown frame spliced into an already-applied prefix, without
moving the indexed offset, is not re-read on each call. That repeated walk was
the cost. Revisit this when a provenance projection can name such a frame
without scanning the retained log.

## Alternatives

- Keep the walk and only start it at the opened log's first LSN. Restarts
  after compaction would succeed, but every call would still read the retained
  prefix, and a compaction that happens after start would still fail until the
  next open.
- Scan the prefix once per process and cache a watermark, then `read_at`. The
  first start of a node holding 7 days of history would still pay the walk,
  and a splice after that scan would wait until the next start.

## Consequences

A call whose callee frame is still in the log succeeds after the log start
moves past 1. A call does not issue a blocking read per preceding record. A
frame that was never applied is not a source.
