# 0153. Integrity hash off the apply lock

- **Status:** Accepted
- **Date:** 2026-11-17

## Context

`GET /v1/integrity` compared a restored node with its source by hashing live
state and then every retained log record. `Store::state_hash` held the apply
lock across the table scans and, when a turn savepoint was open, across a
copy of each actor database. The log hash started at LSN 1 on every request.
Snapshot hashing had already moved off that lock. This caller had not.

The hash values are the check a restore is compared against. They must stay
the hash of the applied state and of the encoded records still in the log.

## Decision

- A file-backed state hash copies `state.db` and each actor database while
  the apply epoch is even and unchanged, then hashes the copies. It does not
  take the apply lock. The epoch is odd for the whole hold, so a copy that
  overlaps an apply is discarded and retried. An open turn's savepoint is
  not in the copy: opening it keeps committed WAL frames only.
- The copies live under `sql/` with the `.hash-copy-` prefix, mode `0600`,
  and are deleted when the hash returns. A crash leftover is swept at start,
  with the copies `committed_hash` already left.
- An in-memory store has no file to copy. It hashes the live connections and
  retries if the epoch moves. It still does not take the apply lock.
- The log hash is the same BLAKE3 over encoded records. The process keeps
  the hasher and prefix marks, and reads only records after the last hashed
  LSN. A `through` behind the tip resumes from the newest mark at or before
  that LSN. Retention moving the log start drops the cache.

## Alternatives

- **Hold the apply lock for each database copy, as snapshots do.** A large
  actor database would still freeze turns for the copy.
- **Replay from the newest snapshot onto a private store.** Correct, and it
  also avoids the lock, but every integrity request would replay the log
  since the snapshot, including when no snapshot exists.
- **Persist the log hash in a segment footer.** That is a format change for
  a value the next process can rebuild once. The pause this removes is the
  one on every request, not the one on process start.

## Consequences

- An integrity request no longer freezes turns for the size of the state.
  The first request in a process still reads the retained log once; later
  requests read only the suffix, or nothing.
- The state hash and the log hash of a node restored to the same applied
  LSN are unchanged.
- Revisit this if integrity must be cheap on the first request after start,
  or if the in-memory path is served under load: hashing live connections
  can still stall an apply that needs those connections.
