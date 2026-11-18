# 0158. A SQL secret is scanned once, then only in rows the turn wrote

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

If a committed turn used SQL and remembered any secret, `SqlActor::scrub`
ran `UPDATE ... instr(column, secret) > 0` for every user table, every
column, and every secret, including blob cells. `instr` cannot use an
index. This ran before the turn record was built, while the actor's
SQLite mutex was held, even when the secret never appeared in SQL. The
client waited. The cost was not bounded by the rows the turn wrote.

That scan is what keeps a secret out of the changeset and the actor
database. A fix must not put the secret back into the log or the actor
database. Issue #198. Not #37, which made the blob scan exist.

## Decision

- A turn that used a secret and did not write SQL does not run `instr`.
- The first write that presents a secret value (its name and the BLAKE3
  of the bytes) scans every user cell once, inside the turn, so the
  replacement is in that turn's changeset. The actor database remembers
  the value. A discarded turn does not: the memory is confirmed only when
  that changeset is applied.
- A later turn replaces the secret only in the rows it wrote, by primary
  key or rowid. It does not scan unchanged tables.
- Values shorter than 4 bytes are still skipped. A blob cell stays a
  blob. The marker is still `[secret:<name>]`.

## Alternatives

- **Scan on every turn, but only tables the turn wrote.** An unchanged
  table can already hold the secret. Skipping it on the first sighting
  leaves the value in the actor database.
- **Scrub historical cells outside the turn, directly in the file.** A
  rebuild applies the log and would put the secret back. The replacement
  has to be in a changeset.
- **A new log record for the one-time scan.** That is a format change for
  a cost one turn can already record.

## Consequences

SQL end of a later turn that updates one row does not grow with the
table. The first write that sees a secret still scans; that cost is once
per value per actor, including across a restart.

A value written after that scan, by a turn that did not use the secret,
stays until a turn that uses the secret writes that cell. The old image
of a row the scan rewrites can still hold the secret, as it did when
every turn scanned: the changeset has to name the row it replaces.
Revisit this if a turn that does not reveal a secret must not be able to
leave that secret in a cell the next revealing turn does not write.
