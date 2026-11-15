# 0146. Restore installs the newest snapshot its log reaches

- **Status:** Accepted (2026-11-15)
- **Date:** 2026-11-15

## Context

`kronik restore` lists `<prefix>/main/snapshots/`, takes the newest manifest and
downloads every `<prefix>/main/segments/` object. The design
([m6-storage](../design/m6-storage.md) §6) requires the staged log to reach the
snapshot, and the code checked the other direction only (the log must not start
after the snapshot). Nothing checked that the log's *end* reached the snapshot's
LSN.

A shipper round can upload a snapshot ahead of the segments that hold its
records. Steps 2 and 3 of the round read the segments and their references;
step 4 uploads snapshots, including one taken after step 2's read. A record the
node applied in between is in no uploaded segment until the next round, and
losing the source before that round makes the state permanent. Issue #98
reproduced it: snapshot 8 and the log ending at 6, so restore installed 8 and
the first `kronik serve` exited 1 with `STORAGE_CORRUPT: state.db has applied
lsn 8, but the log ends at 6`. The bucket still held snapshot 6, which the log
reached exactly.

The choice is fail closed with a named error, or install the newest older
snapshot the log reaches. The former never installs an unstartable directory
but loses the usable recovery point that is in the same bucket; the latter
installs older state and must say so, because the recovery point is no longer
the newest manifest. The issue's acceptance permits either and requires that
`kronik serve` start on what restore wrote.

## Decision

- **Stage the log first, and measure it.** `through_lsn` is the largest record
  LSN in the remote segments, or 0 when the bucket has no segments. It no
  longer starts at the snapshot's LSN, which made a short log indistinguishable
  from a complete one.
- **Install the newest covered snapshot.** Of all readable manifests, take the
  one with the largest `lsn <= through_lsn`. Manifests with a larger LSN are
  skipped, not downloaded. The existing check that the log starts no later than
  the selected snapshot's LSN + 1 still applies, to the selected snapshot.
- **Fail before installing when none is covered.** Restore returns
  `ShipError::Restore` naming the log's last LSN and the oldest snapshot, and
  writes no state: a bucket whose log has lost records must be repaired, not
  silently restored to a point it cannot start from.
- **Report the recovered point.** `RestoreReport`/`kronik restore --json` gain
  `log_last_lsn`, and `snapshots_skipped` (ascending LSNs, possibly empty). The
  human output prints `Log last LSN` and a `Skipped` line when non-empty. The
  `restored.json` marker's `through_lsn` stays the log's last LSN, so the
  restore audit event names the point actually recovered; the design
  ([m6-storage](../design/m6-storage.md) §6) and the restore runbook tell the
  operator to treat a skipped line as an incomplete bucket.
- **The selected snapshot is the installed one everywhere else.** Its state,
  sealed keys, blobs, components, rebase fallback and on-disk
  `snapshots/<LSN>/` directory are the snapshot's, as before.

The rule is verified by `kronik-ship/tests/ship.rs`
`restore_keeps_the_snapshot_the_bucket_log_reaches` (shipped snapshots 6 and 8,
then the segment objects holding 8's records removed: restore reports 6 and
starts), `restore_refuses_a_bucket_whose_log_reaches_no_snapshot` (no segments:
refused, nothing installed), and the existing covered-bucket restores, which
keep their `snapshot_lsn`.

## Alternatives

- **Fail closed whenever the newest manifest is not reached.** It never
  installs older state, but it refuses a bucket whose recovery point is
  present and usable, needs a new operator flag to select a snapshot, and
  makes the common lost/copied-segment object incident unrecoverable through
  the documented command.
- **Take the manifest's `segments` list as proof of coverage.** That list names
  the segments a start from the snapshot reads, not the snapshot's LSN, and is
  written from the live log rather than from what the bucket holds. It cannot
  distinguish a lost segment object.
- **Repair the bucket by shipping again.** The source is gone in the incident
  this path exists for; restore must choose a usable point from what the bucket
  has.
- **A new `--snapshot <LSN>` flag instead of a rule.** It moves the decision to
  an operator who cannot see the bucket's log end from the CLI today, and the
  default would still install an unstartable directory. The report now gives
  the operator that end; a selection flag can be added on top if needed.

## Consequences

- Restore can install state older than the bucket's newest snapshot. It is
  always state the restored log reaches, so `kronik serve` starts, and the
  skipped LSNs are printed and in the JSON rather than silent.
- The recovered point is `log_last_lsn` (the marker's `through_lsn`), not
  `snapshot_lsn`; operators and audit readers can tell them apart.
- The newest snapshot's files are not downloaded when it is skipped, so a
  bucket with a newer but unusable snapshot does not spend its transfer.
- Records after the bucket log's end are not recovered by this command. A
  skipped snapshot is evidence that the bucket may hold less than the source
  acknowledged; take a fresh backup path, not a second restore of the same
  bucket, if the gap matters.
- The restore still verifies coverage at the log's end, not contiguity inside
  the retained window; a bucket missing a middle segment remains a separate
  concern.
- Revisit if the bucket can cheaply prove a snapshot's record range, or if
  operators need to pin a particular older snapshot for an upgrade check.
