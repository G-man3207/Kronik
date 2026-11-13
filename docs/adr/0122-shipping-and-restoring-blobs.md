# 0122. Shipping and restoring blobs: uploads before references, deletions after them

- **Status:** Proposed
- **Date:** 2026-11-13

## Context

The build brief, M26: shipping follows the same roots as collection; a blob
that a timer in a snapshot references remains in object storage even when
the log record that created it has been compacted away, so that `restore`
always works; shipping uploads blobs before the segments that reference
them: loose bytes are okay, missing committed bytes never are. The acceptance
criterion: `restore` from object storage restores a blob that only a timer
references, even after the record that created it was compacted away, and no
log record references a blob that is missing.

The shipper (m6-storage §4, `kronik-ship`) uploads every 10 s: closed
segments once, the active segment again whenever it grew, snapshots (files,
manifest last) and components; it deletes remote segments and snapshots that
retention deleted locally; it records what it uploaded in `<data>/ship.json`,
which it rewrites whole. It reads a segment whole (at most 64 MiB) and
compresses every object with zstd. `restore` downloads the newest remote
snapshot, every remote segment and the components into a staging directory,
checks them and moves them into place.

Erasure: a subject's blob files are deleted when the erasure is applied, and
an erasure is complete only when nothing of the subject is left in shipped
copies either ([ADR 0118](0118-sealed-blob-identity.md) §4, m8-privacy §6).
The collector's roots are [ADR 0120](0120-blob-gc-roots-and-leases.md).

## Decision

### 1. Remote layout

```text
<prefix>/blobs/<2 hex>/<name>      one object per blob: the local file's bytes
```

Main's store only; forks are not shipped. Objects are the files exactly as
stored (ADR 0117 §2), not compressed: sealed blobs do not compress, and most
large plain ones (images, video, PDFs) are compressed already. Uploads larger
than 8 MiB are multipart uploads of 8 MiB parts read from the local file, so
the shipper's memory stays bounded.

### 2. What has been uploaded

`<data>/ship-blobs.db`, a small SQLite database the shipper owns:
`shipped (name PRIMARY KEY, body_digest)`. It is node-local like `ship.json`
and never shipped or restored; when it is lost, the shipper asks the bucket
(a `HEAD`) before it uploads again.

### 3. The order of a round

1. **Blobs that references need.** For each segment the round will upload
   (closed ones not yet shipped, and the active one's new tail since the last
   round, read from the offset the round stopped at), and for each snapshot
   the round will upload (its `blobs.idx`), every referenced blob not yet
   shipped is uploaded. A blob of an erased subject is skipped. A missing
   blob that is not erased stops the round with `BLOB_MISSING` and an error
   log line: the segment is not uploaded without its blobs.
2. Segments, as today.
3. Snapshots: files (`blobs.idx` among them), then the manifest.
4. Remote snapshots gone locally (manifest first), as today.
5. Remote segments gone locally, as today.
6. **Remote blobs gone locally**, deleted by the collector or by an
   erasure, and only in a round whose steps 4 and 5 completed: a shipped
   blob whose local file is gone, that has no row in the `blobs` index or an
   erased one, and that no local snapshot's `blobs.idx` lists. A shipped
   blob whose file is gone while its index row is live was not collected:
   the shipper keeps the remote object, logs an error and counts it in
   `kronik_blob_missing_total`.

Uploads come before the references that need them (steps 1 to 3); deletions
of references come before the deletion of what they referenced (steps 4 to
6). A round that stops anywhere leaves at most loose objects.

Why mirroring local deletions is safe: after steps 4 and 5, the remote
segments and snapshots are a subset of the local ones, whose references are
roots locally, so a blob the collector deleted locally is referenced by no
remote object that step 6 could orphan.

### 4. Reseal and erasure

- `kronik privacy reseal` rewrites plain files of subjects' blobs sealed, in
  place, and writes a marker `blobs/reupload/<name>`; the next round uploads
  the sealed file over the plain object and removes the marker. Until then
  `privacy status` counts the blob in `reseal.pending_blobs`.
- An erasure deletes the subject's local files at once; the next round
  deletes the remote objects (step 6). `privacy status` reports an erasure
  as pending while any of its blob objects remains in the bucket, in
  addition to the existing conditions.

### 5. Restore

After the snapshot and the segments are staged and the keystore backup is
checked (m6-storage §6, m8-privacy §10):

1. The set of blobs to restore: the snapshot's `blobs.idx` plus every
   reference in the staged segments.
2. Blobs of subjects erased in the restored keystore or by `Erasure` records
   in the restored log are accounted as erased and not downloaded.
3. Every other blob is downloaded, streamed into
   `.restore/blobs/objects/<shard>/<name>`, and checked: header, size, body
   digest, and for `b3:` the identity. A blob that is missing or fails its
   check fails the restore with `BLOB_MISSING` naming it, before anything is
   written to the data directory (`--allow-missing-blobs` installs anyway and
   lists them; the node then reads them as `BLOB_MISSING`).
4. Installing moves the staged store into `<data>/blobs` with the rest.

So after a restore no log record and no restored state references a blob
that is missing, unless the operator chose `--allow-missing-blobs`.

## Alternatives

- **Uploading blobs as part of the segment upload.** One object per segment
  with its blobs would duplicate blobs referenced from many segments and
  re-upload them with every growth of the active segment.
- **Remote reference counts or a remote root set.** A second collector with
  its own bugs; mirroring local deletions after references gives the same
  result.
- **zstd on blobs.** CPU for little gain on media and none on sealed blobs.
- **Lazy restore** (download on first read). Faster to start, but a restored
  node would depend on the bucket for correctness and a missing blob would
  be found only when a guest reads it. Eager restore checks everything once.
- **Tracking uploads in `ship.json`.** It is rewritten whole on every save;
  with millions of blobs that would be megabytes per upload.

## Consequences

- A segment never reaches the bucket before its blobs; a snapshot's manifest
  never before the blobs its state references.
- Restore time and bucket size grow with the blob store; `kronik restore`
  prints the number and bytes of blobs it restored.
- A node that ships after running without shipping uploads, with its first
  snapshot, every blob its state roots.
- Verified by the M26 acceptance test against a `file://` bucket and MinIO
  (the existing harnesses): a blob referenced only by a timer survives the
  compaction of its creating record, is restored, and the timer gets the
  right bytes; and by a fault test that stops a round between each step.
