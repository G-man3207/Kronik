# 0157. Erasure scans the subject's rows, not every actor

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

Applying an `Erasure` held the apply lock across two scans issue #161 did
not index. `erase_sql` opened every actor database that had ever used SQL
and ran `DELETE FROM t WHERE _subject = ?` on every subject table. Kronik
created no index on `_subject`. `erase_rows` then selected `deliveries` by
`subject`. That table has no subject index, gains a row for every delivered
message, and compaction never deleted it. The same apply checkpointed
`state.db` before releasing the lock. Issue #196.

A privacy erasure must still delete the subject's SQL rows and tombstone
its saved call answers. A saved call answer below the history floor can go:
the log no longer holds the call, except when an open turn began before
that row and a re-run may repeat it (ADR 0120, pin 5). ADR 0120 recorded
the then-current fact that `deliveries` were never deleted.

## Decision

- When a table gains a `_subject` column, and when an actor database from
  before this index is opened, Kronik creates an index on that column
  unless one already leads with it. The erasure delete is a search.
- `state.db` records `(subject, kind, key)` when a committed turn's SQL
  changeset names the subject. Erasure opens those actors, plus any turn in
  the same batch whose changeset names the subject (the index is written
  with `state.db`, after the actor databases), plus an actor whose SQL
  session is still open (the delete waits for that turn, as before). It
  does not open every SQL actor. The index is not part of the state hash.
  A database from before the index is scanned once, on open, outside the
  apply lock.
- `deliveries(subject)` and `deliveries(lsn)` are indexed. Retention
  deletes saved call outcomes below the history floor, except a row an
  open turn began before. That is the same bound as the delivery pin.
- The `state.db` WAL checkpoint after an erasure runs after the apply lock,
  as the actor-database checkpoint already does.

## Alternatives

- **Open every actor, but only after the indexes exist.** The delete of
  zero rows is cheap, and opening thousands of databases under the apply
  lock is not. The pause would still grow with the number of actors.
- **Keep `deliveries` forever.** ADR 0120's pin table already treats a
  saved call below the floor as unpinned, unless an open turn may repeat
  it. Leaving the row made `state.db` and every snapshot grow without a
  retention bound.

## Consequences

An erasure's apply-lock hold follows the subject's rows, not the number of
SQL actors or the history of every call. A repeated call whose outcome was
retained still gets the saved answer; one past the floor, with no open turn
that began before it, runs again if the caller sends it. Revisit this if a
caller can resend a call message id after the history floor without an open
turn, and that second run would be wrong.
