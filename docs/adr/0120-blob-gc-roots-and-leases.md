# 0120. Collecting blobs: roots, leases and a two-phase sweep

- **Status:** Proposed
- **Date:** 2026-11-13

## Context

The build brief, M26: physical deletion happens only through garbage
collection, when no root references the blob. The roots are references that
actors hold, messages in queues and in outboxes, timers, dead letters, stored
responses for idempotency and `call`, responses being streamed out, turns,
replays and proposals in progress, forks, snapshots and log records within
retention. Turns, replays and proposals in progress hold their roots as
leases that are renewed while they run, so a crashed replay releases its
lease instead of holding blobs forever. `blobs.release` releases only the
actor's own reference: a blob in a timer due in 30 days lives on with a
retention window of 7 days. `kronik blobs gc --dry-run` shows what would be
cleaned up and which root is missing. The DST must show that no blob a root
references is deleted and that a blob without roots is eventually deleted.

M25 adds that a borrowed reference's blob "lives as long as a log record
within retention references it".

Facts the decision builds on:

- `state.db` is derived and written only by the single applier, in LSN
  order (m1-core §2). It holds `mailbox`, `timers`, `dead_letters`
  (with `resent_as`), `ingress_keys` (deleted after `idempotency_ttl` by the
  retention pass), `deliveries` (saved `call` outcomes, never deleted),
  `open_turns` and `open_effects`.
- Retention deletes closed segments once a kept snapshot covers them and
  they are older than `history` (m6-storage §5). A fork can be created only
  inside the window; proposal and preview forks live in memory and in
  `branches/<fork>/`, outside main's `state.db`.
- `Fs` has no file times, and the wall clock can jump.
- `kronik upgrade check` runs in its own process beside the daemon and does
  not write the data directory.

Blob identities, the store and the reference graph are ADRs
[0117](0117-blob-store.md), [0118](0118-sealed-blob-identity.md) and
[0119](0119-blob-reference-graph.md).

## Decision

### 1. Two layers

- **The index**, in `state.db`, written only by the applier:
  - `blob_refs (kind, key, hash, lsn)`: what actors hold;
  - `blob_pins (hash, source, owner)`: rows of other tables that reference a
    blob, inserted and deleted with the rows they mirror;
  - `blobs (hash, size, subject, key_version, first_lsn, last_ref_lsn,
    erased)`: every blob a committed record references, with the LSN of the
    last record that does.

  The retention pass deletes a `blobs` row that nothing holds, nothing pins,
  whose `last_ref_lsn` is below the *floor* (§3) and, for an erased blob,
  always once unreferenced.
- **The sweep**, in `kronik-blob`: deletes a file whose identity has no
  `blobs` row and no other root (§4).

### 2. The pins

| `source` | Owner | Pinned while |
| --- | --- | --- |
| 1 mailbox | `message_id` | the message is queued (also in a cluster's outbox, M16) |
| 2 timer | kind/key/timer id | the timer is scheduled |
| 3 dead letter | its LSN | the dead letter exists and has not been resent |
| 4 ingress key | kind/key/idempotency key | the saved response exists (until `idempotency_ttl`) |
| 5 delivery | `message_id` | the saved `call` outcome's LSN is at or above the floor, or an open turn began before it (a re-run may repeat the call) |
| 6 open turn | execution id | the `TurnBegin`'s input is open |
| 7 open effect | execution id/ordinal | the recorded effect result is open |

A resent dead letter no longer pins: its resend's record references the same
blobs.

### 3. The floor: log records within retention

`floor = min(first LSN the log still holds, fork_lsn + 1 of every fork that
exists, the LSN of every replay lease)`. A blob referenced by a record at or
after the floor is a root. Because `last_ref_lsn` is maintained on apply,
this costs one comparison per blob, not a scan of the log.

### 4. The other roots

- **Snapshots:** every kept local snapshot carries `blobs.idx`, the sorted
  identities of its `blobs` rows that are not erased, written with the
  snapshot and listed in its manifest. A blob that only a timer in a snapshot
  references stays as long as the snapshot is kept, locally and remotely
  ([ADR 0122](0122-shipping-and-restoring-blobs.md)).
- **Forks:** at creation a fork writes `branches/<fork>/blobs.roots`, the
  identities its base state roots (the same query as `blobs.idx` on the state
  it starts from). Its own space holds the blobs it creates and is deleted
  with it. Main's records after its fork point are covered by the floor.
- **Leases**, in the daemon's memory (`kronik_blob::Leases`), each with a
  holder name and an expiry of `[blobs] lease_ttl` (5 min) that the holder
  renews every 30 s while it runs:
  - a turn in progress: its set `T` and the blobs it created, until its
    record is applied (or its attempt is abandoned);
  - an upload: from its spool until the root turn's record is applied;
  - a response being streamed to a client, and an API download;
  - a replay, proposal, catch-up, rebase or preview run: a floor lease at
    its fork point plus the identities it reads from forks' spaces.

  A crash ends every lease; a holder that stops renewing loses its lease at
  expiry. `kronik upgrade check`, a separate process, takes no lease: it
  replays inside the retention window, and a blob it misses fails the check
  with `BLOB_MISSING` instead of passing.
- **Erasure** is not a root but overrides them: the files of an erased
  subject's blobs are deleted when the erasure is applied
  ([ADR 0118](0118-sealed-blob-identity.md) §4).

### 5. The sweep

- Shard by shard (256 directories), so memory is bounded by one directory.
- Two phases: a file without roots in pass `n` becomes a candidate; pass
  `n + 1` deletes it if it still has none and nobody claimed it in between.
  The grace is one pass, `[blobs] gc_interval` (1 h); a restart forgets the
  candidates and starts over. `kronik blobs gc --immediate` skips the grace
  for an operator who needs the space now.
- Deletion holds the store's claim lock (ADR 0117 §6) and skips leased
  identities. A creation that deduplicates onto an object therefore either
  claims it before the sweep looks or finds it gone and writes it again.
- It runs after every retention pass (snapshot, then segment compaction),
  and on `kronik blobs gc`. It needs no clock beyond the interval: files have
  no times.

### 6. What the dry run says

`kronik blobs gc --dry-run` (`GET /v1/blobs/gc`) lists exactly the blobs
without roots, each with why: `loose` (no committed record ever referenced
it: a crash before commit, a failed turn's creation, a rejected upload),
`released` (its last holder released it at an LSN), `out-of-retention` (its
last reference is below the floor) or `fork-deleted`; with its size, its last
referencing LSN and its subject (shown only with `pii:read`).
`kronik blobs inspect <hash>` lists the roots that keep one.

## Alternatives

- **Reference counts with eager deletion.** A crash between the count and
  the delete, or any drift, deletes committed bytes; a rebuild would have to
  reproduce counts exactly. Recomputing roots each pass cannot drift.
- **Scanning the retained log every pass.** Seven days of segments on every
  pass; `last_ref_lsn` gives the same answer from the index.
- **A grace period by file time.** `Fs` has no times and clocks jump; the
  two-phase pass needs neither.
- **Leases on disk, shared across processes.** The only other process that
  reads blobs (`upgrade check`) stays inside retention and fails closed;
  memory leases end with the process, which is what "a crashed replay
  releases its lease" asks for.
- **Keeping dead letters' blobs only within retention.** A dead letter is
  resent from its stored input; losing its blob would make the resend fail
  later for no reason the operator can see.

## Consequences

- The DST invariants are checkable: after every pass, every root's file
  exists; at the end of a run, after the roots are gone and time passes the
  window, no file without a root is left.
- Blobs live longer than strictly needed: up to one extra pass, while a fork
  exists, while a snapshot that indexed them is kept, and for dead letters
  that are never resent.
- The derived tables follow the rebase switch (M13) like the other state
  tables, and `blob_refs` is part of the state hash; `blob_pins` and `blobs`
  are bookkeeping and are not.
- Revisit for the cluster (M16): an outbox row is a pin, and a blob must be
  on every replica of the shard before the record that references it
  commits.
