# M26 blob storage for apps: design

Status: proposed design for M26 (v0.5). It completes
[M25 streaming bodies](m25-streaming-bodies.md), whose store, interface,
gateway and effect paths it uses, and fixes what the slices of §18 build.
The decisions are ADRs [0117](../adr/0117-blob-store.md) to
[0122](../adr/0122-shipping-and-restoring-blobs.md);
[ADR 0118](../adr/0118-sealed-blob-identity.md) is the one the brief asks
for (how a sealed blob is identified, and where its subject and key version
are recorded). It builds on [M1 core](m1-core.md), [M2 effects](m2-effects.md),
[M3 fork](m3-fork.md), [M6 storage](m6-storage.md) and
[M8 privacy](m8-privacy.md).

## 1. Scope

The brief's M26 bullets:

| | Requirement | Where |
| --- | --- | --- |
| R1 | `blobs.put`, `get`, `retain` and `release` in WIT, with `BlobRef` as a type of its own; `put` gives a reference the actor holds | §3 |
| R2 | An incoming reference is borrowed for the turn, `retain` takes ownership, `release` lets go | §2, §3 |
| R3 | The reference graph is the authorization graph; the edges; a self-constructed reference gives `BLOB_NOT_HELD` | §2 |
| R4 | `BlobRefOp` `RETAIN` and `RELEASE` in `TurnRecord.blob_refs`, `put` as `RETAIN`; a hash in bytes is neither a reference nor an authorization | §4 |
| R5 | Bytes are written directly, reference changes are buffered and committed with the turn | §3, §11 |
| R6 | A `BlobRef` travels in `message.blobs`, for `send`, `call`, timers and compensations | §3 |
| R7 | Deletion only by collection, when no root references a blob; the roots; leases renewed while turns, replays and proposals run | §6 |
| R8 | `release` releases only the actor's own reference | §3 |
| R9 | Shipping follows the same roots; blobs are uploaded before the segments that reference them | §8 |
| R10 | `kronik blobs gc --dry-run` shows what would be cleaned up and which root is missing | §6.6 |
| R11 | Blobs of a subject are sealed with its key; erasure works as for other values; identity and metadata (ADR 0118) | §9 |
| R12 | A fork reads blobs from the same store; new blobs go to the fork's own space | §10 |

Acceptance criteria (numbered for §17):

1. The image app `media-ts` stores and fetches blobs, and identity replay
   gives an empty diff.
2. Authorization: actor A creates a blob, actor B learns the hash but gets no
   reference. B can neither read nor retain the blob and gets
   `BLOB_NOT_HELD`. When A sends the reference in `message.blobs`, B can read
   it and retain it.
3. Crash before commit after `blobs.release`: the actor still holds the
   reference after the restart.
4. Crash before commit after `blobs.retain`: no new reference exists after
   the restart.
5. A blob referenced only by a fork, a snapshot or a log record within
   retention is not cleaned away. A blob without references is cleaned up
   after the retention window.
6. A blob that only sits in a timer with a 30-day delay survives a retention
   window of 7 days, and the timer gets the right bytes when it fires.
7. A blob that a replay in progress is reading is not cleaned away during the
   replay.
8. Crash after the blob has been fsynced but before the turn record: the
   bytes remain without a reference and are eventually cleaned up.
9. Crash after the turn record but before the materialized edge: recovery
   builds the edge from the log, and the blob survives.
10. A hash stored as ordinary bytes does not keep a blob alive, but
    `blobs.retain` does.
11. `kronik blobs gc --dry-run` lists exactly the blobs that lack roots.
12. `erase` of a subject makes its blobs unreadable, even after `state.db`
    has been rebuilt from the log.
13. `restore` from object storage restores a blob that only a timer
    references, even when the log record that created it has been compacted
    away. No log record references a blob that is missing.

## 2. The model

A turn may use exactly the references in its set `T`
([ADR 0119](../adr/0119-blob-reference-graph.md) §2): what its actor holds,
what its input carries, and what it obtained during the turn. Any other
reference, whatever its hash, is `BLOB_NOT_HELD`.

| A reference in `T` is | Because | Until |
| --- | --- | --- |
| held | the actor retained it (`retain`, `put`) in a committed turn | a committed `release` |
| borrowed | it arrived on an edge, or the turn created or fetched it | the end of the turn |

The edges, each from a turn that had the reference in its `T`:

| Edge | Carried in the log by |
| --- | --- |
| HTTP request body (an upload) | `HttpInput.body` |
| `fetch` response | `HttpEffectResponse.body_blob`, `EffectRecord.blobs` |
| `send` | `OutboundMessage.msg.blobs` → `MessageInput.msg.blobs` |
| `call` and its reply | `CallEffectRequest.msg.blobs`, `CallEffectResponse.reply.blobs`, `EffectRecord.blobs` |
| timer | `TimerOp.msg.blobs` → `TimerInput.msg.blobs` |
| compensation | `TurnRecord.compensations[].msg.blobs` |
| dead-letter resend | the dead letter's input, copied into the resend's input |

What keeps a blob's bytes ([ADR 0120](../adr/0120-blob-gc-roots-and-leases.md)):
a hold, a queued message, a timer, a dead letter, a saved idempotent or
`call` response, an open turn, a record within retention, a snapshot, a
fork, or a lease. A hash in state, SQL or a body keeps nothing.

## 3. Owning blobs in the guest

The interface is the one [ADR 0121](../adr/0121-blob-interface-and-wasi-0-3.md)
§1 defines and M25 lands whole (M25 §5.1); M26 makes `put`, `retain`,
`release` and blobs in messages work.

| Call | Checks | Effect at commit |
| --- | --- | --- |
| `put(bytes)` | at most 1 MiB; quota | the blob is written now (default subject at the call), added to `T`, and held: a `RETAIN` |
| `retain(r)` | `r` in `T`, else `not-held`; quota | held: a `RETAIN` unless it was held at turn start |
| `release(r)` | held (at turn start or retained in this turn), else `not-held` | not held: a `RELEASE` unless it was not held at turn start |
| `send(to, msg)`, `call(to, msg, compensate)`, `schedule(delay, msg)`, `output::reply(msg)` | every reference in `msg.blobs` (and `compensate.blobs`) in `T`, at most 256 per message, else the turn traps with `BLOB_NOT_HELD` | the references travel complete on the edge |

- **Quota** (ADR 0117 §8): the sizes of the distinct blobs the actor would
  hold after the call, from `blob_refs` and `blobs` at turn start plus the
  turn's buffered operations, may not exceed `blob_bytes_per_actor`; nor may
  the bytes the turn created. Over it: `quota-exceeded`. The answer depends
  only on the actor's state at turn start and the turn's calls, so a re-run
  and a replay give the same.
- **Net operations.** The host keeps `held_at_start` (looked up per blob in
  `blob_refs` when first needed) and `held_now`; at commit
  `TurnRecord.blob_refs` gets `RETAIN` for `held_now \ held_at_start` and
  `RELEASE` for `held_at_start \ held_now`, sorted by identity, at most 1 024.
  A failed turn records none.
- **`T` only grows** within a turn: a released blob stays readable.
- **Secrets.** `put`'s bytes are scrubbed of the values the turn has revealed
  so far, like a writer's (M25 §5.2).
- `check_message` stops refusing `blobs`; a message to a component that does
  not read blobs still carries them, and that component cannot use them.
- The SDK chooses a subject for `put` with `privacy.set-subject` around the
  call (§16); there is no `put-for` in the WIT.
- `kronik send` (operator messages) carries no blobs.

## 4. The log

All additive in log format v1; the field numbers are M25 §8.1.

- **`TurnRecord.blob_refs` (19)**: the net `BlobRefOp`s of a committed turn
  (§3), each with a complete `BlobRef` (subject and key version, ADR 0118
  §3). `RETAIN` and `RELEASE` carry ownership only.
- **`Message.blobs` (4)**: complete references, in outbound messages, timer
  operations, compensations, call requests and replies, and inputs.
- **`EffectRecord.blobs` (14)** of an `actor.call`: the references of its
  message, its compensation and its reply.
- `TurnRecord` fields 24–29 stay reserved; M26 needs none.
- Validation as M25 §8.2; `BlobRefOp.kind` 0 or unknown is `STORAGE_CORRUPT`
  on apply.
- Fixtures (`crates/kronik-proto/tests/fixtures/`): a committed turn with a
  `RETAIN` and a `RELEASE`, a `send` and a timer operation with blobs, a call
  effect with blobs in the request and the reply.

## 5. Materialized state

### 5.1 Tables

`state.db` gains, created on open like the other tables (no backfill: no
blob existed before v0.5):

```sql
-- what actors hold (ADR 0119)
CREATE TABLE IF NOT EXISTS blob_refs (
  kind TEXT NOT NULL, key TEXT NOT NULL, hash TEXT NOT NULL, lsn INTEGER NOT NULL,
  PRIMARY KEY (kind, key, hash)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blob_refs_hash ON blob_refs (hash);
-- rows of other tables that reference a blob (ADR 0120 §2)
CREATE TABLE IF NOT EXISTS blob_pins (
  hash TEXT NOT NULL, source INTEGER NOT NULL, owner TEXT NOT NULL, lsn INTEGER NOT NULL,
  PRIMARY KEY (hash, source, owner)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blob_pins_owner ON blob_pins (source, owner);
-- every blob a committed record references (ADR 0118 §3, ADR 0120 §1)
CREATE TABLE IF NOT EXISTS blobs (
  hash TEXT PRIMARY KEY, size INTEGER NOT NULL, subject TEXT, key_version INTEGER NOT NULL,
  first_lsn INTEGER NOT NULL, last_ref_lsn INTEGER NOT NULL,
  erased INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blobs_subject ON blobs (subject) WHERE subject IS NOT NULL;
```

`source`: 1 mailbox (owner `message_id`), 2 timer (`kind/key/timer_id`),
3 dead letter (its LSN), 4 ingress key (`kind/key/idempotency key`),
5 delivery (`message_id`), 6 open turn (execution id), 7 open effect
(execution id/ordinal). M25 uses 4, 6 and 7.

### 5.2 Applying records

The applier (single writer, LSN order, the same transaction as
`applied_lsn`):

| Record | Index work |
| --- | --- |
| any record | for every reference of `kronik_proto::blobs::refs` (M25 §8.2): insert into `blobs` (`first_lsn = last_ref_lsn = lsn`) or raise `last_ref_lsn`; metadata that differs from the row's is `STORAGE_CORRUPT`; a row whose subject has an `erasures` entry at or above its key version is `erased` |
| `TurnBegin` | with `open_turns`: pins 6 for its input's references |
| `EffectResult` | with `open_effects`: pins 7 for `EffectRecord.blobs` |
| `TurnRecord`, committed | `blob_refs`: `RETAIN` inserts (ignore if present), `RELEASE` deletes; each message: with its `mailbox` row, pins 1; each timer `SCHEDULE`: replace the timer's pins 2; `CANCEL`: delete them |
| `TurnRecord`, failed | each compensation: with its `mailbox` row, pins 1 |
| `TurnRecord`, by input | message from the mailbox: delete its pins 1; timer: delete its pins 2; a failed message or timer becomes a dead letter: pins 3; a resend: delete the pins 3 of the dead letter it resends; a call (callee): with its `deliveries` row, pins 5; an HTTP input with an idempotency key: replace the key's pins 4 |
| `TurnRecord`, always | delete pins 6 and 7 of its execution id |
| `Erasure` | mark the subject's rows with key version up to the record's erased; after the apply commits, the node deletes their files (§9.3) |
| `StateRebase` switch | `blob_refs` and the pins follow the rows the switch replaces (holds of the rebased actors, their mailbox, timers, dead letters, deliveries and ingress keys), as the switch does for `kv` |

### 5.3 The state hash

`blob_refs` (kind, key, hash) is hashed after the existing tables, with its
table marker only when it has rows, so a state without blobs hashes exactly
as before and v0.4 snapshots and restores keep their hashes. `blob_pins` and
`blobs` are bookkeeping, like positions, and are not hashed.

### 5.4 Compaction

`Db::compact` (the retention pass, m6-storage §5) gains, with the floor of
§6.2:

1. pins 4 of the ingress rows it deletes;
2. pins 5 with an LSN below the floor, unless an open turn began before them
   (a re-run may repeat the call);
3. `blobs` rows that nothing holds or pins and whose `last_ref_lsn` is below
   the floor (erased rows once unreferenced).

The rows a rebuild produces can differ from the live ones only in rows the
next pass deletes.

## 6. Collection

### 6.1 Roots

| Root | Where it is | Kept while |
| --- | --- | --- |
| holds | `blob_refs` | held |
| queued messages, compensations | pins 1 | queued (in a cluster, also while in an outbox) |
| timers | pins 2 | scheduled, however long the delay |
| dead letters | pins 3 | not yet resent |
| saved idempotent responses | pins 4 | until `idempotency_ttl` |
| saved `call` responses | pins 5 | above the floor, or while an older open turn exists |
| open turns and their recorded effects | pins 6, 7 | open |
| log records within retention | `blobs.last_ref_lsn >= floor` | the floor passes them |
| snapshots | each kept snapshot's `blobs.idx` | the snapshot is kept |
| forks | `branches/<fork>/blobs.roots`, the fork's space, and the floor | the fork exists |
| turns in progress | turn leases | the turn's record is applied or its attempt abandoned |
| uploads | upload leases | the root turn's record is applied |
| responses streaming, API downloads | stream leases | the stream ends |
| replays, proposals, catch-up, rebase, previews | floor leases and set leases | the run ends or stops renewing |

### 6.2 The floor

`floor = min(first LSN of main's log, fork_lsn + 1 of every fork in
branches/, every floor lease)`. Forks are known from `branches/` and their
`BranchCreated` (or `proposal.json`) when the pass starts.

### 6.3 Leases

`kronik_blob::Leases` (in memory):

```rust
pub struct Leases { /* holder -> (expiry, set of identities, optional floor) */ }
impl Leases {
    pub fn take(&self, holder: &'static str) -> Lease;   // expires after [blobs] lease_ttl
    pub fn floor(&self, holder: &'static str, lsn: Lsn) -> Lease;
}
impl Lease {
    pub fn add(&self, id: BlobId);
    pub fn renew(&self);   // the holder's loop, at least every 30 s
}
impl Drop for Lease { /* removes it */ }
```

| Holder | Takes | Renews | Ends |
| --- | --- | --- | --- |
| a turn (`TurnBlobs`) | a set: `T` and created blobs | every host call and every 30 s while it waits | after its record is applied, or when the attempt is abandoned |
| an upload | a set: its blob | the spool, and the job while queued | after the root turn's record is applied |
| a response or API download | a set: its blob | per frame | at the end of the stream |
| a replay, proposal, catch-up, rebase, preview run | a floor at its fork point, and a set for blobs it reads from fork spaces or (rebase) copies into main's store | per root input | at the end of the run, after the records that reference copied blobs are applied |

`kronik upgrade check` runs in its own process and takes no lease (ADR 0120
§4).

### 6.4 The sweep

`BlobStore::sweep` with `Roots` implemented by the node:

```text
for shard in 00..ff:
    names   = read_dir(objects/<shard>)                     # one shard in memory
    rooted  = index rows in this shard (blobs table, not erased)
            ∪ snapshot idx entries in this shard (sorted files, merged)
            ∪ fork roots in this shard ∪ leased identities in this shard
    for name in names - rooted:
        lock claims
        if name is leased or claimed since the pass began: skip
        elif name in candidates (from the previous pass) or immediate: delete, count
        else: add to candidates
        unlock
    sync_dir(objects/<shard>) if anything was deleted
```

- A pass reads the index in one `state.db` read transaction at the applied
  LSN; a record appended but not yet applied references only blobs that a
  turn or upload lease still covers.
- Erased blobs' files are deleted at the erasure (§9.3); a file the erasure
  missed has no root and the sweep deletes it too.
- Fork spaces are deleted with their fork; scratch spaces with their tree.
- Runs after every retention pass and on `kronik blobs gc`; never during
  startup recovery (the gateway and the sweep start after it).

### 6.5 Cadence and memory

`[blobs] gc_interval` (1 h): a blob without roots goes in at most two passes.
Memory: one shard's names plus the candidates.

### 6.6 The dry run and inspection

`kronik blobs gc --dry-run` (`GET /v1/blobs/gc`, scope `read`) lists every
blob of main's store without a root, now, ignoring the two-phase grace:

```json
{"blobs": [{"hash": "b3:…", "size": 31457280, "subject": "user:1", "reason": "released",
            "last_ref_lsn": 1203, "released_by": "media/alice", "candidate": true}],
 "count": 1, "bytes": 31457280, "floor": 1190, "kept": 812}
```

`reason`: `loose` (no committed record ever referenced it), `released` (its
last holder released it), `out-of-retention` (its last reference is below the
floor), `fork-deleted` (only a deleted fork referenced it). `subject` is
null without `pii:read`. `--verify` also recomputes the pins by decoding the
rows they mirror (mailbox, timers, dead letters, ingress keys, deliveries,
open turns and effects) and reports any difference from `blob_pins` as
`"drift"`; it should always be empty. `kronik blobs gc --reason R [--immediate]` (`POST
/v1/blobs/gc`, scope `operate`, `dry_run` supported) runs a pass now and
records an `AuditEvent` `blobs.gc`. `kronik blobs inspect <hash>` lists the
roots that keep a blob (`{"roots": [{"kind": "held", "actor": "media/alice"},
{"kind": "timer", "actor": …, "timer_id": …}, {"kind": "log", "lsn": …},
{"kind": "snapshot", "lsn": …}, …]}`).

## 7. Snapshots

- `snapshots/<branch>/<L>/blobs.idx`: the identities the snapshot's state
  roots (`SELECT hash FROM blob_refs UNION SELECT hash FROM blob_pins`,
  without erased ones), sorted, one per line, written from the snapshot's own
  `state.db` copy before the manifest. It is in the manifest's `files` (size
  and BLAKE3, so shipping and restore check it). Blobs that only records
  reference are not listed: the restored segments root them.
- `manifest.json` gains `"blobs": {"count": N, "bytes": B}` with a serde
  default; `format` stays 1. A manifest without it (v0.4) reads as no blobs.
  Fixtures for both.
- Pruning a snapshot drops its index with it. A fork's `blobs.roots` is the
  same query on the state the fork starts from, written at fork creation.

## 8. Shipping and restore

[ADR 0122](../adr/0122-shipping-and-restoring-blobs.md) is the design;
implementation specifics:

- `ship_once` gains steps 1 and 6 of the ADR's order. Segment references are
  read with `kronik_log`'s decoder from the bytes the shipper reads anyway;
  for the active segment, from the offset recorded in `ship.json`
  (`active_scanned`, additive, default 0). Step 6 deletes a remote object
  only under the ADR's three conditions (file gone, index row absent or
  erased, in no local `blobs.idx`), read in one `state.db` transaction.
- `<data>/ship-blobs.db`: `shipped (name TEXT PRIMARY KEY, body_digest BLOB
  NOT NULL)`. A blob whose body digest changed (resealed) is uploaded again;
  so is one with a `blobs/reupload/<name>` marker, which the upload clears.
- Uploads stream from the local file: one `put` up to 8 MiB, otherwise a
  multipart upload of 8 MiB parts (`object_store`'s `put_multipart`).
- `kronik_blob_ship_pending` (gauge): referenced blobs not yet uploaded.
- `restore` (ADR 0122 §5) adds `--allow-missing-blobs`; `RestoreReport`
  gains `blobs: {restored, bytes, erased, missing}`; the CLI prints them.
- A fault test stops a round after each of the six steps and checks that the
  bucket never has a segment or manifest whose blobs are missing.

## 9. Privacy

### 9.1 Subjects

| Blob | Subject |
| --- | --- |
| an upload | the request's subject (`privacy.subject_from`) |
| a `fetch` response, a spooled `fetch` request body | the guest's default subject at the call (`FetchRequest.subject`) |
| `put`, a `writer` | the default subject at the call or construction |

A blob has at most one subject, like every value.

### 9.2 Identity and sealing

As ADR 0118: `b3s:` keyed with the subject's oldest live key version (created
on the first blob of a subject, also in mode `off`), sealed with that version
when the mode is `on`, plain otherwise.

### 9.3 Erasure

`Node::erase_subject` is unchanged up to the record. Applying `Erasure`
marks the subject's index rows erased (§5.2). Then, in the node's
`after_erasure` hook next to the snapshot it takes today, the store deletes
every file of an erased row, in main's store and in every fork space, and
writes nothing else. The shipper deletes the remote objects in its next
round (ADR 0122 §3, step 6).

- A guest read returns `erased`; the API answers `SUBJECT_ERASED`; a replay
  marks the turn unverifiable (ADR 0109); holds, pins and log references
  remain and point at an erased blob.
- `POST /v1/privacy/erase` answers also `blobs` (the files deleted) and
  `pending_blob_objects` (remote objects not yet deleted).
- `privacy status` reports an erasure as pending while any of its blob
  objects is still in the bucket.
- Rebuilding `state.db` from the log applies the same record: the rows are
  marked again, and the deletion finds nothing left.

### 9.4 Reseal

`kronik privacy reseal` gains a blob pass after the segments: for every
`blobs` row with a subject, not erased, whose file is plain, it writes the
file sealed under the row's key version (ADR 0117 §2) as a part file, fsyncs
it, renames it over the plain one, syncs the directory and writes a
`blobs/reupload/<name>` marker. Progress: `reseal.blobs_sealed` and
`reseal.pending_blobs` in `GET /v1/privacy`.

### 9.5 Forks without PII and redaction

A `--no-pii` fork reads a subject's blob as its pseudonym (M25 §9). The API
shows a reference's subject only with `pii:read`; its hash is shown to every
`read` caller: for a subject's blob it is keyed and reveals nothing.

### 9.6 Keys at restore

The restore's keystore check (m8-privacy §10) also covers every
(subject, key version) that a restored reference names: its key is in the
installed backup, or the subject is erased through that version; otherwise
`KEYSTORE_INCOMPLETE` before anything is written.

## 10. Forks and replay

- **Reads** go to the fork's space, then main's store. A fork's base state
  holds what main held at the fork point; `blobs.roots` keeps those bytes
  (§7).
- **Writes**: continuous replay, catch-up, `send_to_fork` and previews write
  the fork's space; each isolated tree writes its scratch space.
- **Determinism**: a fork turn's `T`, its identities and its quota answers
  are those production had for the same inputs and code, so an identity
  replay has the same `blob_refs`, messages and bodies.
- **The diff** compares bodies by reference (M25 §9) and blob operations as
  state: `state.isolated[].blobs` and `state.continuous[].blobs` list
  `{"op": "retain" | "release" | "held", "hash", "size", "prod", "fork"}`
  differences (additive in `kronik.diff/v1`); a message's `blobs` compare by
  identity and size.
- **Rebase** copies the fork-space blobs that rebased turns reference into
  main's store before it appends them (M25 §4.3).

## 11. Crash cases

| Crash | What survives | Why |
| --- | --- | --- |
| after `release`, before commit (criterion 3) | the hold | the `RELEASE` was in memory; `blob_refs` is unchanged |
| after `retain` or `put`, before commit (criterion 4) | no new hold; `put`'s bytes are loose | the `RETAIN` was in memory; nothing references the bytes |
| after the blob's `finish`, before the record (criterion 8) | loose bytes | no committed record references them; the sweep deletes them in two passes |
| after the record's fsync, before it is applied (criterion 9) | the edge and the blob | recovery applies the record (`blob_refs`, pins, `blobs`); the blob was durable before the record; the sweep runs only after recovery |
| during an upload | a part file | `tmp/` is emptied at start |
| between a rename and its directory sync | the name, or nothing | no record referenced it before `ensure_durable` |
| during a sweep | some deleted unrooted files | deletion is per file, under the claim lock |
| during an erasure's deletion | some files | the deletion runs again after the next start (rows marked erased whose file exists) |

## 12. API, CLI and MCP

M25 §15's surfaces, plus:

| Surface | Scope | Answer |
| --- | --- | --- |
| `GET /v1/actors/{kind}/{key}` / `kronik actors inspect` | `read` | adds `"blobs": {"held": N, "bytes": B}` |
| `GET /v1/actors/{kind}/{key}/blobs?after=&limit=` / `kronik blobs list --actor KIND/KEY` | `read` | `{"blobs": [{"hash", "size", "subject", "lsn"}], "next"}` |
| `GET /v1/blobs/gc` / `kronik blobs gc --dry-run` | `read` | §6.6 |
| `POST /v1/blobs/gc` / `kronik blobs gc --reason R [--immediate] [--dry-run]` | `operate` | `{"dry_run", "deleted", "bytes", "candidates"}`; an `AuditEvent` `blobs.gc` |
| `GET /v1/blobs/{hash}` / `kronik blobs inspect` | `read` | adds `roots` (§6.6) |
| `POST /v1/limits` / `kronik limits set --blob-size-per-actor` | `operate` | the quota |
| `GET /v1/privacy`, `POST /v1/privacy/erase` | as today | the fields of §9 |
| MCP `blob_gc_plan` | `read` | as `GET /v1/blobs/gc` |

The OpenAPI document, the CLI's JSON schemas, `docs/reference/cli.md`,
`api-examples.md` and `json.md` are regenerated with each route.

## 13. Configuration, metrics and errors

Configuration and limits are M25 §12 (`blob_bytes_per_actor` is M26's).
Metrics, added to the catalog:

| Metric | Type | Labels |
| --- | --- | --- |
| `kronik_blob_gc_runs_total` | counter | |
| `kronik_blob_gc_deleted_total`, `kronik_blob_gc_freed_bytes_total` | counter | |
| `kronik_blob_gc_duration_seconds` | histogram | |
| `kronik_blob_gc_candidates` | gauge | |
| `kronik_blob_leases` | gauge | |
| `kronik_blob_ship_pending` | gauge | |
| `kronik_blob_erased_total` | counter | |

Errors: `BLOB_QUOTA_EXCEEDED` (409), with M25's four (M25 §14).

## 14. Deterministic simulation

A new workload in `kronik-sim` (`ScenarioConfig::blobs_for_seed`, `--scenario
blobs`), run by `scripts/dst.sh` with the others (200 seeds per change,
10 000 nightly).

- **Guest:** the test actor's `blobs` feature (kind `media`): messages that
  `put` seeded bytes and store their digest in state, `retain`, `release`,
  `send` a reference to another actor, schedule a timer carrying one with a
  long delay, and read a held or received blob and check its digest.
- **Knobs from the seed:** threshold 256 bytes, blobs of 0 to 200 KiB,
  `history` of a few virtual seconds, snapshots and sweeps every virtual
  second with `immediate` on half the seeds, the existing crash models, the
  disk's lost and torn unsynced writes and names, and `keep_store_p`.
- **Targeted crashes:** besides random crashes, a seeded fault point fires a
  crash at the n-th occurrence of: a blob's `finish` before its record, a
  record's append before its apply, a turn with buffered `retain` or
  `release` before its commit, a sweep between two deletions.
- **Invariants**, checked after every sweep, every restart and at the end:
  - B1: every rooted blob's file exists and reads with its digest;
  - B2: every reference in every committed record exists or is erased;
  - B3: after recovery, `blob_refs` equals a rebuild from the log (the
    existing `check_recovery` comparison, extended);
  - B4: a crash before commit changes no hold;
  - B5: every read a guest made returned the bytes written (the guest's
    digest check, as a turn failure if not);
  - B6: at the end, after every hold is released, every timer has fired and
    the virtual clock passes the window, the store has no file without a
    root after two passes.
- **Mutations** of the harness (as `mutation_ack_before_fsync`): a sweep
  that ignores timers, and a store that skips `ensure_durable`; each must
  make some seed fail.

## 15. The `media-ts` example

`examples/media-ts`, a TypeScript actor built by `kronik build`, kind
`media`, key = an album. SQL table:

```sql
CREATE TABLE images (id TEXT PRIMARY KEY, hash TEXT NOT NULL, size INTEGER NOT NULL,
  content_type TEXT NOT NULL, created_ms INTEGER NOT NULL,
  _subject TEXT DEFAULT (kronik_subject()));
```

| Route | Does |
| --- | --- |
| `POST /media/{key}/images` | the body (blob or inline; `put` for an inline one) is retained; a row with the hash; answers `{id, hash, size}` |
| `GET /media/{key}/images/{id}` | responds with the blob and its content type |
| `GET /media/{key}/images` | the rows |
| `DELETE /media/{key}/images/{id}` | `release` and delete the row |
| `POST /media/{key}/images/{id}/share/{album}` | `send`s the reference in `message.blobs` to another album, which retains it |
| `POST /media/{key}/import` | `fetch`es an image URL (needs a grant) and retains the response blob |
| `POST /media/{key}/images/{id}/expire?days=N` | a timer carrying the reference; when it fires, the image is released |

The stored hash is a string in SQL: it keeps nothing alive (criterion 10),
the hold does. Unit tests run against the SDK's test kit;
`scripts/identity-examples.sh` runs a workload of uploads, reads, shares,
imports against a local server and expiries, then an identity replay that
must be empty; the README walks through it, including a grant for the
import host.

## 16. SDKs

M25 §16's reading and writing, plus:

| Need | Rust | TypeScript | Python | Go |
| --- | --- | --- | --- | --- |
| store bytes and hold them | `ctx.blobs().put(&bytes)?` | `ctx.blobs.put(bytes)` | `ctx.blobs.put(data)` | `ctx.Blobs().Put(data)` |
| for another subject | `ctx.blobs().put_for(subject, &bytes)` | `ctx.blobs.putFor(subject, bytes)` | `put_for` | `PutFor` |
| hold, let go | `retain(&b)?`, `release(&b)?` | `retain(b)`, `release(b)` | `retain`, `release` | `Retain`, `Release` |
| send with blobs | `Message::new(name).blob(b)` | `{ name, body, blobs: [b] }` | `blobs=[b]` | `Message{Blobs: …}` |
| blobs of an input | `msg.blobs()` | `msg.blobs` | `msg.blobs` | `msg.Blobs` |

`put_for` sets the default subject around `put` and restores it. Errors:
`not-held` → `BLOB_NOT_HELD`, `quota-exceeded` → `BLOB_QUOTA_EXCEEDED`,
`erased` → `SUBJECT_ERASED`, each pointing to `kronik explain`. The test
kits keep holds per actor across turns and apply the same rules.

## 17. Acceptance plan

`kronik-sched/tests/blobs.rs` runs a node in-process; `kronik/tests/blobs.rs`
and `blobs_kill.rs` run `kronik serve` as a child process, with hidden
`serve` flags for test holds like `--test-hold-after-call` today:
`--test-hold blob-finished`, `record-appended` and `before-commit` hold the
turn at that point and signal the harness, which `kill -9`s the daemon.
`scripts/acceptance-m26.sh` runs the release-binary tests on the test VPS.

| # | Test | What it does |
| --- | --- | --- |
| 1 | `scripts/identity-examples.sh` with `media-ts`; `kronik/tests/blobs.rs` `media_ts_round_trip` | the workload of §15, then a fork with the same code: empty diff in both modes; the downloaded bytes equal the uploaded ones |
| 2 | `kronik-sched/tests/blobs.rs` `a_learned_hash_is_not_a_reference` | A `put`s and sends the hash as message body text to B; B's `get` and `retain` give `not-held`, and its turn that responds with it fails with `BLOB_NOT_HELD`; A sends the reference in `message.blobs`; B reads it, retains it, and still reads it in a later turn |
| 3 | `kronik/tests/blobs_kill.rs` `a_crash_before_commit_keeps_a_released_hold` | the actor holds a blob; a turn releases it and holds `before-commit`; `kill -9`; restart: `blob_refs` and a read in a new turn show the hold |
| 4 | same file, `a_crash_before_commit_adds_no_hold` | a turn retains a borrowed blob (and `put`s another), holds `before-commit`; `kill -9`; restart: no hold; the `put` blob is loose (dry run lists it as `loose`) |
| 5 | `kronik-sched/tests/blobs.rs` `roots_keep_and_the_window_releases` | with `history` of seconds: one blob only in a fork's base state, one only in a snapshot's index (its holder released after the snapshot), one only in a retained record; two immediate passes keep all three; after the fork is deleted, the snapshot pruned and the record compacted, two passes delete them |
| 6 | DST seeds of §14, and `kronik-sched/tests/blobs.rs` `a_timer_outlives_the_window` | a timer due after 30 days of virtual time (DST) or 30 s with `history` = 5 s (in-process) carries the only reference; snapshots, compactions and passes run past the window; the timer fires and its turn reads the right digest |
| 7 | `kronik-sched/tests/blobs.rs` `a_running_replay_keeps_what_it_reads` | a replay paused by a test hook after it began reading a blob whose only root was a retained record; the record is compacted and immediate passes run; the replay resumes and reads every byte; after it ends, the blob is collected |
| 8 | `blobs_kill.rs` `a_crash_after_the_blob_leaves_loose_bytes` | hold `blob-finished`; `kill -9`; restart: the file exists, the dry run lists it as `loose`, two passes delete it |
| 9 | `blobs_kill.rs` `a_crash_before_apply_rebuilds_the_edge` | hold `record-appended` (the turn record is fsynced, not applied); `kill -9`; restart: the hold exists, the blob reads, a pass keeps it; also with `state.db` deleted before the restart |
| 10 | `kronik-sched/tests/blobs.rs` `bytes_in_state_keep_nothing` | blob 1's hash in state and SQL only, blob 2 retained; after its record leaves retention, two passes delete 1 and keep 2 |
| 11 | same file, `the_dry_run_lists_exactly_the_unrooted` | a store with one blob for each root kind and five without a root (loose, released, out of retention, fork deleted, and an erased-and-deleted control); the dry run's set equals the five, with their reasons |
| 12 | `kronik/tests/privacy_mode.rs` `erasing_a_subject_erases_its_blobs` | mode `on`: a subject's upload and `put`, a second subject's blob from the same turn; erase the first; reads give `SUBJECT_ERASED`, the files are gone, a scan of the data directory finds no plaintext; delete `state.db`, restart: still erased, the second subject's blob still reads; again in mode `off` (files deleted, identity unlinkable) |
| 13 | `kronik/tests/m6_cli.rs` `restore_keeps_a_timer_only_blob` (a `file://` bucket), and the same against MinIO in `kronik-ship/tests/ship.rs` | a blob whose only root is a timer; the creating record compacted away (short `history`, snapshots); shipping; `restore` into a new directory; the restored node's timer fires and reads the right bytes; a check over every restored reference finds none missing |

DST (§14) covers criteria 3, 4, 5, 6, 8 and 9 under random crashes as well.

## 18. Implementation plan

### 18.1 Slices

M25's slices (B1–B13, M25 §18) come first. M26's:

| Slice | Touches | Proven by | M24 |
| --- | --- | --- | --- |
| **B14** holds and edges | `kronik-runtime` (`put`, `retain`, `release`, blobs in messages, replies and timers, net operations, quota), `kronik-sched` (`TurnBlobs` holds, call and compensation edges, `EffectRecord.blobs` for calls), `kronik-store` (`blob_refs`, pins 1, 2, 3, 5, state hash, rebase switch), error code `BLOB_QUOTA_EXCEEDED` | criteria 2 and 10; state hash unchanged for states without blobs; rebuild equals live | parallel (textual edits in `host.rs`, `node.rs`) |
| **B15** privacy | `kronik-sched` (erasure deletion, reseal pass), `kronik-store` (erased marking), `kronik-privacy` (restore key check), `kronik-api` (privacy fields) | criterion 12 | parallel |
| **B16** collection for holds | the roots of M26 in `Roots`, dry-run reasons, `inspect` roots, MCP `blob_gc_plan`, actors' `blobs` views | criteria 5, 7, 11 | parallel |
| **B17** simulation | `kronik-sim` (the `blobs` workload, fault points, invariants, mutations), `scripts/dst.sh`, `tests/guests` | 200 seeds; the mutations fail | parallel |
| **B18** crash holds and acceptance | `kronik-sched` test holds, `kronik serve --test-hold`, `kronik/tests/blobs.rs`, `blobs_kill.rs`, the restore test, `scripts/acceptance-m26.sh` | criteria 3, 4, 6, 8, 9, 13 | parallel |
| **B19** `media-ts` and SDKs | `examples/media-ts`, `sdk/*` (§16), test kits, `scripts/identity-examples.sh`, guides | criterion 1; `scripts/ci.sh examples ts sdks` | textual conflicts in SDK files |
| **B20** release | remove `[blobs] enabled` (M25 §18.2), `AGENT_GUIDE.md`, quickstart, glossary, compatibility corpus entry, operations guide, `kronik explain blob` | the doc-surface gate; the whole of `scripts/ci.sh` | after M24's last WIT change |

### 18.2 Order and parallel work

| Slice | Needs | Slice | Needs |
| --- | --- | --- | --- |
| B1, B2, B3 | nothing (in parallel) | B12 | B3, B11 |
| B4 | nothing; serialized with M24's WIT slice | B13 | B7, B8, B9, B10, B11, B12 |
| B5 | B3, B4 | B14 | B6, B11 |
| B6 | B1, B2, B5 | B15 | B14 |
| B7, B8, B11 | B6 | B16 | B11, B14 |
| B9 | B7 | B17 | B14, B16 |
| B10 | B6, B7 | B18 | B12, B14, B15, B16 |
| | | B19 | B13, B14 |
| | | B20 | every other slice, and M24's last WIT change |

Conflicts with M24, all agreed with its design: the WIT file, the allowlist
and the version bump (B4, serialized: whoever lands first bumps to 0.1.1);
`proto/kronik/log/v1` (B3, different fields); the gateway's `body.rs` and
`server.rs` (B8, either order); `replay.rs` and `diff.rs` (B10); the SDKs,
`turn.schema.json` and `diff-v1.schema.json` (whoever lands second
regenerates). Everything else runs in parallel.

## 19. Risks

| Risk | Mitigation |
| --- | --- |
| The collector deletes committed bytes through a missing root | two-phase sweep; leases; DST invariants B1, B2 and the two mutations; `kronik_blob_missing_total` alert; `gc_interval = "0s"` turns the automatic pass off |
| Pins drift from the rows they mirror | pins are written in the same transaction as their rows; DST compares recovered and rebuilt state; a dry run with `--verify` can recompute roots by decoding the tables |
| Dead letters that are never resent keep blobs forever | `kronik blobs inspect` shows the dead letter; dead letters already keep their input forever |
| A subject's key is created in mode `off` | documented; the only keystore write in that mode, once per subject |
| Restore time and bucket size grow with blobs | eager, checked restore (ADR 0122); `kronik restore` prints counts and bytes |
| Many small `put`s each cost an fsync | the batching optimization ADR 0117 allows; measured in `docs/perf.md` |
| The rebase switch (M13) and the turn-record ceiling of issue #26 meet blob tables | B14 extends `apply_switch`; references count toward the ceiling |
| Cross-subject duplicates cost disk | accepted (ADR 0118); revisit with pilot data |

## 20. Open questions

Each with a recommendation; M25 §20 has two more on default limits.

1. **Subject keys in privacy mode `off`.** A subject's first blob creates its
   key so that a later erasure can unlink the blob's identity (ADR 0118).
   Recommendation: accept. The alternative, a master-keyed identity in mode
   `off`, keeps the operator able to link an erased subject's blob to its
   content.
2. **Disk full inside a turn.** The design retries the attempt in place and
   never records it (ADR 0117 §9): an actor stalls while the store is full.
   Recommendation: accept. Recording the failure would let the machine's
   free space into history and break identity replay.
3. **Blob content through the API.** `kronik blobs get` streams a blob's
   bytes to `read` callers (`pii:read` for a subject's blob), through the
   current secret output matcher. Recommendation: include it; operators need
   to see what was uploaded, and inline bodies are already visible to the
   same scopes.
4. **Releasing a dead letter's blobs.** Dead letters keep their blobs until
   resent. Recommendation: keep it so in v0.5, and add a `kronik dead-letters
   purge` before v0.8 if pilots show dead letters piling up.
