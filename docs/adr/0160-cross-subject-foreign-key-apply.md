# 0160. Apply a turn's SQL changesets together

- **Status:** Accepted
- **Date:** 2026-11-19

## Context

A turn's changeset is stored as one sealed blob per subject
([ADR 0005](0005-sql-state.md) §6). The 2026-11-13 amendment applies each
blob with its own `sqlite3changeset_apply_v2` call, in subject order.
SQLite checks foreign keys once, at the end of that call. A child whose
subject sorts before its parent is inserted while the parent insert is
still in the other blob. The conflict aborts the apply. The turn record is
already durable, so every restart fails on that record and the node stays
down. The opposite delete, a parent whose subject sorts before its child,
fails the same way. Issue #242.

The per-subject bytes are what erasure and sealing use. They stay in the log.

## Decision

- Apply combines the turn's changesets with `sqlite3changegroup` and applies
  that once, on the live path and on a rebuild. The foreign-key check then
  sees every subject's changes.
- A conflict that remains after that combined apply still aborts. The
  savepoint rolls back. Nothing is applied.
- The log is unchanged: one changeset per subject, sealed under that
  subject. The unsplit changeset is still not written. Tests may still apply
  it.
- A subject whose changeset cannot be opened is still omitted. The rest are
  combined.

## Alternatives

- **Defer foreign keys across the per-subject calls, then check.** That is a
  second foreign-key implementation next to SQLite's, and a later edit can
  forget the check. One apply already defers the check to the end.
- **Write the unsplit changeset to the log and apply that.** Sealing and
  erasure would have a second copy of every row, or would have to stop using
  the per-subject bytes. ADR 0005 §6 keeps one blob per subject.
- **Reject the turn at commit.** The guest transaction is valid. The failure
  is apply order, not the schema.

## Consequences

A billing schema that tags the account and the line with different subjects
commits and restarts. A changeset that still conflicts fails closed, as
before. Revisit if a turn's subjects ever share a primary key: changegroup
would merge those rows, and the split does not produce that today.
