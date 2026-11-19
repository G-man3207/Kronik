# 0159. Erasure defers foreign keys and refuses another subject's reference

- **Status:** Accepted
- **Date:** 2026-11-19

## Context

`privacy erase` deletes every table with a `_subject` column in name order,
with `PRAGMA foreign_keys = ON`. A parent whose name sorts before its child
is deleted first. SQLite rejects that delete. The subject's keys are already
destroyed and the `Erasure` record is already in the log, so the next start
replays the record, maps the constraint to `STORAGE_CORRUPT`, and stops.
The rows the erasure was supposed to delete are still in the actor database.
Issue #241.

Turning foreign keys off would let the deletes run, and would also leave a
row of another subject dangling when it references a deleted parent. An
`ON DELETE CASCADE` or `SET NULL` would change that other subject's row.
Neither is an erasure of the subject.

## Decision

- Inside the erasure savepoint, foreign-key checks are deferred until every
  delete of this subject has run. The savepoint is released only if the
  check passes. A failed statement still rolls the savepoint back.
- Before the keys are destroyed, and before an `Erasure` record is
  appended, the same actors the apply would open are checked. If a row that
  is not the subject's references a row the erasure would delete, the call
  fails with `ERASURE_BLOCKED`. A dry run fails the same way.
- That constraint is not a corrupt log. Apply of a record that still hits
  it returns the constraint, not `STORAGE_CORRUPT`.

## Alternatives

- **Delete child tables first.** Name order is not a foreign-key order, and
  a self-reference or a cycle has no such order. Deferring the check covers
  those without a schema walk at delete time.
- **Turn foreign keys off for the erasure.** The other subject's referencing
  row would dangle, or a cascade would delete it. Erasure must not do either.
- **Append the record and skip the failed delete on restart.** The keys are
  already gone and the rows remain. The node would start, and the erasure
  would not have happened.

## Consequences

A parent and child of the same subject erase together, and a restart
applies that record. A reference from another subject fails the call with
the rows and the keys still in place. A turn that commits such a reference
after the check and before apply can still append a record apply cannot
finish; closing that means holding SQL writers across the check and the
apply.
