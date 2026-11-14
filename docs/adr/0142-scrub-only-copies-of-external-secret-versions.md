# 0142. Encrypted scrub-only copies of recorded external secret versions

- **Status:** Accepted (2026-11-14)
- **Date:** 2026-11-14

## Context

The views that remove secret values from what they show (`history`,
`actors inspect`, turns, traces, dead letters, the audit log and others)
need the value of every secret version that the node recorded, also the
old ones: a value can sit in actor state or in a snapshot for as long as
that data lives (a `call` hands it to a callee as its input, a target can
echo it in a response), not only in the log. The M23 design (§6) kept the
values of secrets linked to an external backend in memory only, "never
written to disk, which would put external secrets at rest in a second
place". After a restart the node fetched every recorded version again by
the backend's own id for it. When the backend no longer served one (a
destroyed version, one removed by a version limit, a changed `env`
variable), the inventory could never be completed again: every read that
scrubs answered 503 `SECRET_UNAVAILABLE`, a known defect of 0.5.0-dev,
seen against OpenBao, moto and the GCP and Azure emulators.

Three remedies were weighed after the M23 review; the maintainers chose
to keep encrypted, scrub-only copies of the recorded versions.

## Decision

1. **What is stored.** For each version of a secret linked to a backend
   other than `file` that the node records (each `SecretVersion` that
   becomes active), one row in the table `external_scrub_copies` of
   `<data>/keys/secrets.db`: the name, Kronik's version number, the
   backend, the canonical reference, the backend's version id, the keyed
   version hash, a random 24-byte nonce, the ciphertext and the wall time
   it was written. Never the plaintext.
2. **Encrypted how.** XChaCha20-Poly1305 under a key derived with BLAKE3
   (`derive_key`, context `kronik external scrub copies v1`) from the
   secret store's storage key, which is itself derived from the master
   seed; derived for each operation and wiped after it. The associated
   data is the version's whole identity (name, version, backend, canonical
   reference, version id and version hash, each length-prefixed), so a
   copy opens only as the value of exactly that recorded version, and
   never as a built-in secret or the other way round. A copy that opens is
   also checked against the keyed version hash. Under another master key
   no copy opens.
3. **When it is written.** While the node holds the value: after the
   version's `RESERVED` record and before its `ACTIVE` record, whichever
   observation recorded it (an effect's fetch, the refresher, `secret
   refresh`, `secret link`, a catalogue listing). A version recorded before
   this release, or whose write failed, gets its copy the next time the
   node holds its value: when it observes the version again, or when the
   inventory rebuild fetches it by its version id. A failed write fails
   nothing; it is logged (`could not keep the scrub-only copy of a secret
   version`) and made up for that way.
4. **What it is used for.** The scrub inventory only. Its rebuild takes a
   recorded external version's value from the copy before it asks the
   backend, and holds it as scrub-only, the way it already held retained
   values. A copy never answers an effect, the crash re-run of a turn
   (which still fails with `SECRET_VERSION_GONE` when the backend no
   longer serves the version), a fork computation (ADR 0132 reads only
   operational values), a reveal or a foreign actor, and no API, CLI or
   MCP answer contains it. The cached recertification after a
   configuration commit does no I/O and does not read copies. Offline,
   `keys wrap` scrubs its reason with the built-in store's values and the
   copies (`SecretStore::values`).
5. **When it is deleted.** A copy whose version did not become active (a
   crash between the copy and the `ACTIVE` record leaves the version
   `FAILED` at the next start) is deleted at the next start, as is any
   copy without an active external version. Otherwise a copy lives as long
   as its version's `SecretVersion` record, which today is for good: the
   scrub inventory needs every recorded version for as long as state or a
   snapshot can hold its value. That is the lifetime of the built-in
   store's own scrub needles: its deleted versions also stay encrypted in
   `secrets.db`. `secret unlink` deletes no copy (the versions stay in the
   history and in the data), a linked name cannot be deleted with `secret
   delete` (`SECRET_EXTERNAL`), and an erasure concerns a data subject's
   data, which a secret value is not.
6. **Shipping and restore.** The copies are part of `secrets.db`, which
   travels inside snapshots, encrypted under the master key; nothing else
   is shipped for them, and the master key never is. A restore installs
   them with the snapshot. A version recorded after the newest shipped
   snapshot has its copy only on the source machine, as a built-in secret
   set after it has its value there; the restored node fetches that version
   once and keeps its copy then. Only a version that the backend also no
   longer serves leaves the reads that scrub at 503 there.
7. **Keys.** `keys rewrap` and `keys wrap` keep the seed, so the copies'
   key and every copy stay valid; nothing is re-encrypted. There is no
   seed rotation.
8. **Upgrade.** The table is created at the first start of a release with
   this decision, and the versions recorded before get their copies as in
   3, while the backend still serves them.

## Alternatives

- **Keyed fingerprints** (a keyed hash per version, and a scan of every
  window of each recorded length in the text to scrub): no value at rest,
  but a scan cost of the text times the number of distinct lengths on every
  scrubbed read, where scrubbing is an exact replacement today.
- **An audited command that retires a lost version** from the inventory and
  accepts unscrubbed reads: it leaves the risk to the operator.
- **Copies of only the versions that an effect used:** the inventory needs
  every recorded version, and a version the refresher recorded is the one
  the next effect uses; partial copies would leave the defect for the rest.
- **Deleting a copy once no log record within retention references its
  version:** unsafe while actor state or a snapshot can still hold the
  value; it needs the scrub inventory to drop such versions first, a
  separate decision.
- **A file of its own** instead of a table of `secrets.db`: it would need
  its own snapshot, shipping, restore and permission handling, which the
  table inherits.

## Consequences

- After a restart the scrub inventory asks the backend only for versions
  without a copy, and for the list of versions of a name with a
  `secret-reveal` grant (its catalogue): while the backend is down, the
  reads that scrub still answer 503 for such a name, as before.
- External secret values are at rest in a second place, encrypted:
  `keys/secrets.db` (mode 0600), the snapshots and the shipped bucket.
  Whoever holds the data directory and the master seed can read them, as
  they can read the built-in store. Revocation at the backend still ends
  every operational use at once; it no longer removes every trace of a
  value from the node.
- M23 §6's "never written to disk" now says what is stored, where, how and
  until when; the in-memory cache itself is unchanged.
- Verified by the unit tests of `kronik-privacy` (a copy opens only for its
  identity and under its master key, a changed ciphertext fails, no column
  holds the plaintext) and the daemon test
  `a_destroyed_version_is_scrubbed_from_its_copy_after_a_restart`
  (`crates/kronik/tests/secret_backends.rs`): after the backend destroyed a
  version a callee holds, a restart answers `actors inspect` and `history`
  with 200 and the placeholder, the backend is not asked for that version,
  and neither value is in plaintext in `keys/` or the snapshot.
