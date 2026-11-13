# 0118. How a sealed blob is identified, and where its subject and key version are recorded

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13

## Context

M26 of the build brief asks for this decision in an ADR:

- A blob can be tied to a subject and sealed with the subject's key, so that
  erasure works as for other values.
- The identity of a sealed blob must not make replay non-deterministic, and a
  hash of the plaintext must not leak content. A keyed hash per subject is a
  candidate: deduplication then happens only within a subject, and once the
  key is erased the hash can no longer be linked to the content. Global
  deduplication across subjects is excluded: it would need an index outside
  the replay identity.
- The blob's subject and key version must be reconstructible from the log,
  like the ownership edges, so that `erase`, `reseal` and `restore` work after
  `state.db` has been rebuilt, for blobs from `put` as for bodies and effect
  responses. Where this metadata is written is part of this decision, for
  example a record of its own when the blob is created; `RETAIN` and
  `RELEASE` are then only about ownership.

What constrains the answer:

- **The identity is guest-visible.** `blob-ref.hash` is a string the guest
  receives, stores in state or SQL, compares and sends. A re-run after a
  crash, an isolated or continuous replay, a catch-up and `kronik upgrade
  check` must give the guest the same string for the same bytes, or every
  turn that stored it diverges.
- **References are plain.** `Body.blob`, `Message.blobs` and
  `BlobRefOp.blob` are not `Sealable`: the collector, the shipper and the
  history read them without keys. Anyone with the `read` scope sees them.
- **Subject keys** (m8-privacy §2) live in `keys/keystore.db`, wrapped by the
  master key, numbered from 1, created on first use. `erase` deletes every
  version; a later key of the same subject is numbered after the erased ones.
  `rotate` exists but is not exposed for data subjects (only OIDC principals
  use it). In privacy mode `off` the keystore is never touched.
- `Sealer::keyed_hash` is keyed by a master-derived key: it hides values from
  outsiders, but the operator can still confirm a guess, and erasing a
  subject does not change it.

## Decision

### 1. The identity

- **Without a subject:** `b3:` + hex(BLAKE3(content)). Global
  deduplication among blobs without a subject.
- **With subject `s`:** `b3s:` + hex(BLAKE3-keyed(`K_id`, content)), where
  `K_id = BLAKE3-derive-key("kronik blob identity v1", K(s, v))` and `v`,
  the blob's *key version*, is the subject's oldest key version that is not
  erased, created (numbered after any erased versions) when the subject has
  none. This holds in both privacy modes: in `off` mode the first blob of a
  subject is the one time that subject's key is created, once, then cached.

Why this is deterministic: the bytes the guest writes are the same in a
re-run or replay, and `v` changes only through an erasure of `s`, after
which the turn that met `s`'s data is unverifiable anyway (ADR 0109). A fork,
a `--no-pii` fork included, computes identities on the host from the bytes its
guest wrote; it never shows the guest anything the identity is derived from.

Why it does not leak: without `K(s, v)` nobody can check a guessed content
against the identity. `K(s, v)` is wrapped by the master key and destroyed by
`kronik privacy erase`; from then on not even the operator can link the
identity to content. Deduplication happens within one subject and key
version only; the same file uploaded by two subjects is stored twice.

Deduplication is invisible to the guest (ADR 0117 §6).

### 2. Sealing

In privacy mode `on`, a subject's blob is sealed when it is written, under a
key derived from `K(s, v)` for the same `v` (frames, ADR 0117 §2). In mode
`off` it is stored plain. Whether a file is sealed is a physical property of the file (its
header), not part of the identity or of the log: `reseal` seals a plain file
in place, under the same name and identity.

### 3. The metadata: self-describing references, no record of their own

`BlobRef` (common.proto) gains two fields:

```proto
message BlobRef {
  string hash = 1;                  // "b3:" or "b3s:" + 64 hex characters
  uint64 size = 2;
  optional string subject = 3;      // set exactly for "b3s:"
  uint32 key_version = 4;           // >= 1 exactly for "b3s:", 0 for "b3:"
}
```

Every `BlobRef` the host writes into any record is complete: in
`HttpInput.body`, in an `Outcome`'s reply or HTTP response, in
`Message.blobs` (messages, timers, compensations and their inputs), in
`EffectRecord.blobs` and the effect request and response bodies, and in
`BlobRefOp.blob`. The guest's `blob-ref` stays `{hash, size}`; the host
completes it from the turn's set of references it may use
([ADR 0119](0119-blob-reference-graph.md)).

So every reference in the log says whose blob it is and which key version
it needs, without unsealing anything. `state.db` keeps an index from
identity to (size, subject, key version) that a rebuild reconstructs from the
references and snapshots carry ([ADR 0120](0120-blob-gc-roots-and-leases.md));
it is derived, never the source.

Validation on apply: a `b3:` reference with a subject or a key version, a
`b3s:` reference without a valid subject or with key version 0, or two
references to one identity with different metadata is `STORAGE_CORRUPT`.

`RETAIN` and `RELEASE` say only that an actor takes or drops ownership; that
their `BlobRef` is complete like every other changes nothing about them.

### 4. What uses the metadata

- **Erase.** Applying `Erasure { subject s, key_version L }` marks every
  indexed blob of `s` with key version at most `L` as erased, also one first
  referenced after the record. The node deletes those files locally, plain or
  sealed, and the shipper deletes them remotely (ADR 0122). A guest read gets
  `blob-error::erased`, an API read `SUBJECT_ERASED`, and a replay marks the
  turn unverifiable. Rebuilding `state.db` applies the same record and gets
  the same result.
- **Reseal.** With the mode `on`, every plain file of a subject's blob
  (written in mode `off`) is rewritten sealed under its recorded key version,
  with the same name; the shipper re-uploads it.
- **Restore.** The index comes from the snapshot and the segments; blobs of
  erased subjects count as erased, not as missing.

## Alternatives

- **Plain BLAKE3 for every blob** (global deduplication). Anyone who can read
  history could confirm a guess of a subject's document forever, erasure
  could never unlink it, and the brief excludes global deduplication.
- **A master-keyed hash (`Sealer::keyed_hash`).** Hides content from
  outsiders, but the operator keeps a way to link it after an erasure.
- **A random identity per creation, recorded.** The guest would see a
  different string in a re-run and in every replay unless each creation were
  matched to a recording like an effect; no deduplication.
- **The hash of the ciphertext.** Ciphertext depends on a random nonce; a
  nonce derived from the content would turn it into a keyed hash with extra
  steps.
- **Keying the identity with the newest key version.** A rotation, if one is
  ever exposed for subjects, would change the identity of content created
  again and make replays of older turns diverge. The oldest live version
  changes only with an erasure.
- **A record of its own (`BlobCreated`) when a blob is created.** One more
  append and fsync per blob; it would have to be atomic with the first
  reference anyway; a reference alone would not be enough to find a blob's
  subject, and retention could compact the creating record while references
  remain. Self-describing references have none of these problems. Envelope
  kind 19 stays reserved in case review prefers it.

## Consequences

- In privacy mode `off`, a subject's first blob creates its key: the only
  keystore write in that mode; `privacy status` counts it. It is what lets
  erasure unlink the identity of a blob written while the mode was `off`.
- A keyed BLAKE3 pass costs the same as a plain one.
- No cross-subject deduplication.
- `kronik-privacy` gains `Keystore::identity_key(subject)` (oldest live
  version, created when missing) and `Sealer::blob_keys(subject)`, without a
  schema change; keystore backups cover the keys as before. A node without a
  keystore refuses blobs with a subject; tests and the simulator use a fixed
  test key.
- Log format v1 gains two optional `BlobRef` fields: additive (I16), with a
  compatibility fixture of a `b3s:` reference.
- How erase, reseal and restore use this is specified in
  [M26 §9](../design/m26-blobs.md#9-privacy).
- Revisit if subject key rotation is ever exposed for data subjects (blobs
  would keep their identity version and seal with it), or if a production
  pilot shows that cross-subject duplicates cost too much disk.
