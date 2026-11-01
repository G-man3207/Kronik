# 0090. Secret backends and versions in the log

- **Status:** Accepted design for M23 B2–B5; implementation and exercised evidence are tracked separately in STATUS.md.
- **Supersedes:** the parked proposal's source-version-only identity and independent store `max+1` allocation.

## Context

M23 requires external secrets to have the same version-hash and replay guarantees as the built-in store. The built-in store already encrypts values and computes a keyed hash over name, Kronik version and value. Current mutation auditing is reused; the parked statement that secret mutations have no log records describes an older baseline, not the current code.

A provider version ID is not globally unique: unrelated KV paths can both start at version 1. A name can also be unlinked, relinked or rebound to a different trusted provider. A failed set intent can consume a log version before the separate encrypted SQLite write succeeds. Allocating the next number from the store alone can then reuse that reservation and confuse acknowledged values.

## Decision

### Immutable provenance

Use record kinds 45 (`SecretVersion`) and 46 (`SecretLink`), with durable format fixtures and normal store, snapshot, classifier, history and replay support. A version records the Kronik name/version, keyed value hash and immutable provenance:

- backend ID and validated public provider binding;
- logical and canonical resource reference as required by the provider;
- link generation;
- provider's immutable source version.

Never deduplicate by source version alone. Old observations retain their own reference and generation. Credentials and endpoints come only from trusted node configuration; recorded metadata cannot choose another endpoint, module or credential source. Returned resource identities and every paginated continuation authority are validated against that configuration.

A link/unlink is a configuration change: it records its monotone generation and configuration epoch through the existing configuration barrier. Link management requires admin scope, a reason and a default-deny `allowed_refs` prefix allowlist. Validation must resolve the intended canonical resource before publication. Dry-run may validate/fetch, but commits no link/version and fills no operational cache. Unlink returns subsequent live turns to the built-in source without redirecting historical provenance.

### One allocator and durable publication

One serialized per-name log-derived allocator covers built-in sets/deletes, provider observations, refresh and first use. Rebuild its high-water mark from committed reservations, including older mutation intents and failed attempts. Failed numbers are consumed; successful versions need not be dense.

The encrypted store accepts an explicitly reserved version. It must not allocate independently or replace another version's ciphertext. Reserved, failed and completed states are distinct. A reservation is never the current value merely because its number is largest or its ciphertext exists. Publish only after matching value verification and durable completion; reconcile crashes explicitly while retaining the last acknowledged completed value. Orphaned or failed writes cannot overwrite or become that value. External values are not mirrored into this store.

Import pre-M23 built-in metadata before external links become usable. Preserve the existing keyed value-hash bytes; do not substitute a hash of backend identity. The same name, Kronik version and value retain the same effect hash across source implementations.

### Turn and replay ordering

Cold `current`, immutable `version` and version-list I/O caused by a turn happens only after that turn's durable `TurnBegin` (I14). A later metadata commit is additional provenance, not a replacement for `TurnBegin`. Background refresh and explicit management validation are separate operations.

Resolve using the admitted configuration epoch and exact link generation. A fetch racing relink cannot populate the replacement generation. Commit a newly observed value's version metadata before using its bytes in an effect, and record the version actually used.

Recorded HTTP and crypto matches do not fetch a value. Upgrade identity follows each production turn's recorded code/configuration/link history. Ordinary forks and proposals retain the fork-point/candidate configuration plus explicit overrides; they do not silently follow subsequent main grants or links. Forks never fetch externally. An unmatched fork effect can use only an already-held, still-authorized value for that fork point's exact provenance.

If recorded replay/resend needs bytes, recover the recorded immutable identity, never current. Availability retries may hold that actor, not unrelated actors. Definitive version loss or hash/binding mismatch fails before the guest can observe a substituted outcome; never rewrite an already-recorded success into a new guest-visible error.

## Consequences

Values and credentials stay out of provenance, history, diffs and MCP. Metadata replication later uses this same command/state machine and allocator; it does not create a competing cluster counter. Provider configuration, sessions and value caches remain node-local. File/env defaults and master-seed identity are unchanged.

Complete retained-value coverage is a separate requirement in ADR 0091, not satisfied by recording only current versions. A changed or destroyed immutable value can make affected scrub-dependent output unavailable rather than permit a fallback.

## Acceptance evidence required

No test is preclaimed by this accepted design. Required exercised evidence includes failed/concurrent set reservations, crash publication boundaries, legacy import, same-version IDs across refs/generations, provider binding and pagination attacks, hash equivalence, old-version rotation/history, no-network replay, historical upgrade configuration/code/link semantics and actual supported secret-service lifecycles. See [the M23 design](../design/m23-secret-backends.md) and STATUS.md for observed results.
