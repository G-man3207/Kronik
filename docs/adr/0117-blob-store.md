# 0117. The blob store: content-addressed files, durable before they are referenced

- **Status:** Proposed
- **Date:** 2026-11-13

## Context

M25 and M26 of the build brief move large bodies and apps' large objects out
of the log into a blob store, the new crate `kronik-blob`. The brief fixes
the rules this store must keep:

- Bodies above a threshold, 1 MiB by default, are stored content-addressed;
  the log holds only the hash and the size.
- A blob is fsynced before the turn record that references it, and shipping
  uploads blobs before the segments that reference them: loose bytes are
  okay, missing committed bytes never are.
- Turn semantics stay deterministic (I1): what a guest observes is a function
  of recorded inputs, so anything that depends on the machine (free disk,
  timing) either never reaches the guest or is recorded.
- The core needs no external service (I10), runs on a VPS without KVM (I11),
  and every daemon component does its I/O through `kronik_core::env::Env`, so
  the simulator can crash it (ADR 0004).

The brief also names quotas and a disk reserve for the crate, but not their
semantics. Today the log has `[log] disk_reserve` (default 512 MiB): below it
new inputs are refused with `UNAVAILABLE`. `Fs` has `open`, `read_at`,
`write_at`, `sync_data`, `rename`, `sync_dir`, `read_dir`, `remove_file` and
`available`, and no file times. SQL state already has a deterministic
per-actor size cap (ADR 0005 §5).

How a blob of a data subject is named and sealed is
[ADR 0118](0118-sealed-blob-identity.md); who may use a reference is
[ADR 0119](0119-blob-reference-graph.md); when a file is deleted is
[ADR 0120](0120-blob-gc-roots-and-leases.md). The designs that build on these
decisions are [M25 streaming bodies](../design/m25-streaming-bodies.md) and
[M26 blob storage for apps](../design/m26-blobs.md).

## Decision

### 1. Layout

```text
<data>/blobs/objects/<2 hex>/<name>     immutable blob files, 256 shard directories
<data>/blobs/tmp/<16 hex>.part          files being written
<data>/blobs/reupload/<name>            reseal markers for the shipper (ADR 0122)
<data>/branches/<fork>/blobs/...        a fork's own space, the same layout
```

`<name>` is the identity with `:` replaced by `-`: `b3-<64 hex>` or
`b3s-<64 hex>`; the shard is the first two hex characters of the digest. The
store creates the 256 shard directories when it is created. Main's store is
not under `branches/main` because forks read it too; a fork writes new blobs
only into its own space, which is deleted with the fork. One store per data
directory; an operator who wants blobs on another disk mounts one at
`<data>/blobs`.

### 2. File format, version 1

A 512-byte header, then frames of 64 KiB of plaintext each.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | magic `KRNKBLOB` |
| 8 | 4 | format, `u32` = 1 |
| 12 | 4 | flags, `u32`: bit 0 sealed |
| 16 | 8 | size: plaintext bytes, `u64` |
| 24 | 4 | frame size, `u32` = 65 536 |
| 28 | 4 | key version, `u32` (0 without a subject) |
| 32 | 32 | identity digest (the 32 bytes the name encodes) |
| 64 | 32 | body digest: BLAKE3 of every byte after the header |
| 96 | 16 | nonce prefix (sealed; zero otherwise) |
| 112 | 2 | subject length, `u16`, at most 256 |
| 114 | 256 | subject, zero padded |
| 370 | 138 | reserved, zero |
| 508 | 4 | CRC32C of bytes 0 to 507 |

Integers are little endian. Frame `i` carries plaintext bytes
`[i * 65536, min(size, (i + 1) * 65536))`:

- **plain:** the bytes, then their CRC32C (4 bytes);
- **sealed:** XChaCha20-Poly1305 under the blob key
  `BLAKE3-derive-key("kronik blob seal v1", K(s, v))`, derived from the
  subject key of the key version (so blob frames and sealed values never
  share a key), nonce = nonce prefix ‖ `u64_le(i)`, associated data =
  `"kronik blob v1" 0x00 subject 0x00 u32_le(key version) identity digest
  u64_le(i) u8(last)`; the ciphertext and its 16-byte tag. A sealed blob has
  at least one frame, so even an empty one authenticates its end.

The file length is a function of the header, so a truncated file is
detected before any frame is read. Overhead: 512 bytes per file and 4 (plain)
or 16 (sealed) bytes per 64 KiB.

### 3. Identity

`b3:` + 64 lowercase hex characters of BLAKE3 over the content for a blob
without a subject; `b3s:` + 64 hex of a keyed BLAKE3 for a blob with one
(ADR 0118). `blob-ref.size` is the plaintext size. A reference names the pair
(identity, size); the store rejects a size that does not match.

### 4. Writing: the only way an object appears

1. A writer opens `tmp/<16 hex from Env::entropy>.part`, writes a zeroed
   header and then frames as data arrives, hashing the plaintext for the
   identity and the stored bytes for the body digest.
2. `finish` writes the header, calls `sync_data` on the part file, and only
   then renames it to `objects/<shard>/<name>`. If the name exists already
   (the same content), the writer *claims* the existing object (§6) and
   removes its part file. Either way the shard directory is marked dirty.
3. Before any log record that references a blob is appended (`TurnBegin`
   with an uploaded input, `EffectResult`, `TurnRecord`, a rebased turn),
   the appender calls `ensure_durable` for every blob the record references:
   one `sync_dir` per dirty shard directory, coalesced across concurrent
   callers.
4. At start, the store calls `sync_dir` on every shard directory before it
   serves anything, then deletes everything in `tmp/`.

Content is durable before its name exists (step 2), and a name is durable
before anything refers to it (step 3); a name seen after a restart is
durable after step 4 even if the process, not the machine, crashed. A crash
can leave a part file or an object no committed record references: loose
bytes, which step 4 and the collector remove. It cannot leave a committed
reference without its bytes.

### 5. Reading

A reader opens an object by identity and size, checks the header (magic,
CRC, identity, size, file length) and returns byte ranges. Only the frames a
range touches are read and checked (CRC32C or the AEAD tag): reads are lazy,
so a replay fetches only what the guest reads. A failed check is
`STORAGE_CORRUPT` naming the blob, never wrong bytes. A fork looks in its own
space first, then in main's store. A whole-file check (body digest, and for
`b3:` the identity) runs on restore and on `kronik blobs inspect --verify`.

### 6. Deduplication and claims

There is one object per identity. Creating content that exists already
claims the existing object: under the store's claim lock the writer checks
the name again and adds the identity to its caller's lease
([ADR 0120](0120-blob-gc-roots-and-leases.md)); the collector deletes only
under the same lock and never a leased identity. A claim of an object
created by this process whose directory is still dirty makes the claimer
wait for its `sync_dir` (§4.3). Deduplication is invisible to the guest: the
same identity, the same fuel, and no clock.

### 7. The threshold

`Limits.blob_threshold_bytes` (per kind, history like every limit, I5),
default 1 MiB and at most the kind's `message_bytes`. For a component that
reads blobs ([ADR 0119](0119-blob-reference-graph.md) §1), an HTTP request
body or an effect response larger than the threshold becomes a blob; a
smaller one stays inline. The decision is made once, at admission or when
the effect completes, and is recorded in the input or the effect result, so
re-runs and replays never make it again.

### 8. Quotas: deterministic, per actor

- `Limits.blob_bytes_per_actor` (default 1 GiB): the sizes of the distinct
  blobs an actor holds, after the turn's buffered `retain`, `put` and
  `release`, may not exceed it, and neither may the bytes one turn creates.
  A `put`, `retain` or writer `write` that would cross it returns
  `blob-error::quota-exceeded` (`BLOB_QUOTA_EXCEEDED`). The answer depends
  only on the actor's state at turn start and the turn's own calls, so it is
  not recorded, like SQL's `too-large`.
- `Limits.upload_bytes` (default 64 MiB): the largest HTTP request body the
  gateway accepts for a kind that reads blobs (413 `PAYLOAD_TOO_LARGE` above
  it). A kind that does not read blobs keeps `[gateway] max_body`.
- `Limits.effect_response_bytes` (default 10 MiB, unchanged): the largest
  effect response, inline or blob.

### 9. The disk reserve: never recorded, retried in place

`[blobs] disk_reserve` (default twice `[log] disk_reserve`, 1 GiB) on the
file system that holds `<data>/blobs`, measured with `Fs::available` by the
existing disk loop. Free space is not a function of history, so it never
becomes a guest-visible result:

- Below the reserve the gateway refuses a body that would become a blob,
  before admission: 503 `BLOB_STORE_FULL`, nothing recorded.
- A blob write inside a turn that reaches the reserve (or `ENOSPC`) abandons
  the turn attempt without a record, like a host failure. The scheduler keeps
  the input at the head of the actor's queue and runs it again with backoff
  (100 ms doubling to 30 s) while the condition lasts: a turn that wrote a
  `TurnBegin` runs again as a re-run with its recorded effect results (m2
  §4), any other from scratch. The actor's order is kept and no failed
  attempt enters history.
- An effect response that cannot be stored is handled like a crash after the
  request left: no `EffectResult` is written, and the re-run applies the
  target's delivery class (I17: `unsafe` gets `outcome-unknown`).

The blob reserve is above the log's, so blobs stop before the log does.

### 10. I/O and simulation

All file I/O goes through `Env::fs`, randomness through `Env::entropy`, time
through `Env::clock`. `kronik-blob` holds no key: callers pass the derived
identity key and the sealing key ([ADR 0118](0118-sealed-blob-identity.md)).
It needs no new dependency (BLAKE3, XChaCha20-Poly1305 and CRC32C are in the
workspace).

## Alternatives

- **Blobs as SQLite rows, or in the log.** SQLite pages and WAL copies of
  gigabytes, and a log whose records hold bodies is what M25 removes (issue
  #26 shows what oversized records do).
- **Raw files without frames.** Simpler tooling, but a range read could not
  tell corruption from data; whole-file checks on every read cost a full
  pass.
- **BLAKE3 verified streaming (bao).** Verifies ranges against the identity
  itself, but adds a dependency and does not cover sealed blobs; frames with
  CRC32C or AEAD tags cover both.
- **Fsync at commit only, for every blob of the turn.** Fewer fsyncs for
  many small blobs, but a blob another turn deduplicates onto, or that an
  effect sends before commit, must already be durable. Allowed as an
  optimization if it keeps §4: content before name, name before reference.
- **A per-branch store, copying main's blobs into a fork.** Forks would copy
  gigabytes they only read.
- **Recording a full disk as a guest-visible failure.** The result would
  depend on the machine, and an identity replay would turn it into a "fixed"
  error. Retrying in place keeps history free of it.
- **Global quotas.** The answer for one actor would depend on other actors'
  turns, so it would have to be recorded; per-actor quotas need nothing.

## Consequences

- One `sync_data` per blob and one `sync_dir` per dirty shard directory per
  batch of records. A crash leaves at most loose bytes.
- An actor stalls, in order, while the blob store is below its reserve;
  `kronik_blob_store_below_reserve` and `/v1/health` say so.
- The format is versioned (`format = 1`) with committed fixtures of a plain
  and a sealed file; a new format needs a new version and a reader for the
  old one (I16).
- Verified in `kronik-sim` with the simulated disk (torn and lost unsynced
  writes and names) and in the M25/M26 acceptance tests.
- Revisit when a shard directory holds more than a few million objects, when
  object storage should serve reads directly, or when the cluster (M16)
  needs blobs on a majority before commit.
