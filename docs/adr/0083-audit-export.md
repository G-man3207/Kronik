# 0083. The audit export: the log is the audit trail

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

The M28 brief:
- "Audit-loggen över alla mutationer exporteras löpande som JSON-rader till
  fil, webhook eller objektlagring."
- Acceptance: "Den exporterade audit-loggen är fullständig jämfört med
  loggens poster, och ett test jämför dem."

Historical starting point, before M28:
- Ten record kinds carry `pb::Audit {token_id, reason, wall_time_ms}`:
  Deployment, Grant, Limits, Policy, Approval, PrivacyMode, ForeignActor,
  Erasure, EngineUpgrade, and operator sends and resends through
  `MessageInput.audit`.
- Twelve mutating routes leave no audited record in main's log:
  - secrets and tokens, which are kept in `keys/*.db`;
  - forks and proposals, in branch directories;
  - snapshot create and reseal.

  Six of them drop their `reason`.

So "fullständig jämfört med loggens poster" holds only once every mutation
is a log record.

## Decision

1. **New record kind 40, `AuditEvent {action, target, details, audit}`.**
   - Twelve routes write it: secret set/delete, token create/revoke, fork
     create/delete/deploy/replay/send, proposal create, privacy reseal,
     snapshot create. Five routes of v0.2 join them: watch start and stop,
     preview create and delete, and a rollback via replay's proposal
     (`rebase.create`).
   - Secret/token changes, preview create/delete, watch stop and proposal
     submission record intent before the effect; failures record
     `<action>.failed`. Intent is not proof of success. Watch start also
     records before waiting. Long-lived lifecycle work runs in an owned
     task once its intent is durable, so caller cancellation cannot hide
     the effect. Other durable-object operations record their result.
   - Reasons, targets and details are scrubbed of stored secret values and
     token secrets when written; when the stored secrets cannot be loaded
     the text is withheld rather than written unscrubbed.
   - The append uses the `check_alive` path: the disk reserve never
     refuses it.
   - It is also written for `export rewind`, and as system events
     (`token_id = "system"`): `audit.gap` (ADR 0084), `restore` on the
     first start after `kronik restore`, and `audit.config` when the export
     settings change.
   - Applying it changes no state.
   - Dry runs write none.
   - `crates/kronik-api/tests/mutations.rs` gains a column naming the
     record each mutating route writes. A new route without one fails.
2. **What is exported.** An audited item is a record of kind 4–10, 12, 13, 15, 17,
   a rebase's switch (16) or 40, a `TurnRecord` whose input is an `OPERATOR` or
   `DEAD_LETTER_RESEND` message, or a `secret.reveal` effect of any
   `TurnRecord` (the brief: a reveal "syns i audit"). The export writes one
   JSON line (`kronik.audit/v2`, m28-otel §4.3) per audited item, in LSN
   order:
   - the record's `lsn`, the effect ordinal for a reveal, `kind`, `action`,
     `token_id`, `at_wall_ms`, scrubbed `reason`;
   - per-kind `details` under ADR 0082 (a reveal names the secret, never
     the value);
   - `record_hash`, the domain-separated blake3 of the record's canonical
     form: sealables become subject tags and free text is canonically
     withheld/token-scrubbed, so a reseal does not change it.
     An erasure's subject is replaced by its keyed label, and the key in a
     `fork.send` event's `details.actor` by its keyed label (`kind/` plus
     the label), so the hash cannot confirm a guessed
     subject or actor key.

   A unit test fails when a record message with an `Audit` field is not
   classified.
3. **Completeness.** For a range (F, L], the exported lines deduplicated by
   (`lsn`, `effect`, `record_hash`) equal the audited items in (F, L] on
   (`lsn`, `effect`, `kind`, `action`, `token_id`, `at_wall_ms`,
   `record_hash`), with nothing missing, extra or conflicting. The LSN alone
   is not a key: after a restore from an older ship point, new records
   reuse the lost tail's LSNs.
   - Verification accepts only known schemas, exact source-derived hashes
     and matching identity fields. Legacy `kronik.audit/v1` is read-only
     compatibility, not an alternate emission format; mixed v1/v2 retries
     represent one logical source item.
   - Only trusted source restore records authorize superseding a lost tail;
     sink-supplied restore lines cannot authorize cuts. `restore.through_lsn`
     and `audit.gap.from`/`to` are action-specific validated `u64` positions:
     v2 emits JSON numbers; legacy v1 requires decimal strings.
   - `kronik audit verify --sink` computes this against the log.
   - `crates/kronik/tests/audit.rs` drives every mutating route, a reveal
     and a restore (dry runs too, which must export nothing), with a
     restart in between. It builds its expected lines from the actions it
     drove, not from the exporter's classifier, and also runs `verify`.
4. **Sinks.**
   - A directory (`file://`): exclusive-create `audit-v2-<sequence:020>.jsonl`
     files, numbered independently of wall time and LSN,
     fsynced before the cursor moves. The configured threshold is
     1 B–1 GiB (default 64 MiB), soft at whole-batch boundaries; oversized
     records are not dropped. Tail recovery scans with a fixed buffer.
     Files are no-follow, regular and uniquely linked; removed directories
     are recreated and recoverable open/write errors retry.
     Historical LSN-named files are read first in their original order and
     sealed for new appends; current files are read/recovered by sequence.
     Archive names must not be renumbered; retain the newest numbered
     file when rotating across a writer restart.
     Any sync failure or EIO latches that writer as `storage_sync`: no
     later filesystem attempts or cursor acknowledgement, while the node
     remains usable. Repair/quarantine storage, create a new writer and
     safely rewind; restart alone does not prove durability was repaired.
   - A webhook (`https://`): NDJSON batches with an `idempotency-key`
     header binding the durable replay generation, range and body hash.
   - Object storage (`s3://`, through `kronik-ship`'s `Remote`):
     `audit/v2/<sequence:020>.jsonl`, published with atomic create only.
     Tail recovery streams the listing once; create/collision confirms an
     occupied slot, while an unknown write failure never advances it.
     A collision is not an ACK; a lost ACK can yield a later duplicate.
     Legacy top-level wall-time objects are read first. New v2 objects
     require append-only retention and an atomic, durable backend create
     contract; arbitrary deletion plus a stale listing is not safe.
     Unsupported conditional create stalls as `s3_unsupported`.
   - After a restore reuses LSNs, no sink loses or deduplicates away the
     lines it got before.
   - Delivery is at least once and in order. Consumers dedup by (`lsn`, `effect`, `record_hash`).

## Alternatives

- **Read secrets, tokens and forks from their own stores.** Their history
  is incomplete: delete drops the reason, and forks keep no caller or time.
  Exporting from several sources makes "complete" undefinable.
- **After-change everywhere.** A crash between a credential/destructive
  lifecycle change and its event would hide the change. Those operations
  use durable intent and failure events; durable-object result records
  remain where losing the caller cannot lose the operation.
- **Reconcile the stores at start** against the latest events. It covers
  the same window with more code than intent-first.
- **A separate audit file written by the API.** It would be a second
  source of truth beside the log, unordered with respect to it, and
  outside snapshots and shipping.
- **Export only what the API saw** (request logs). That includes requests
  that failed and misses records written by recovery (the erasure
  recovery, the engine upgrade).

## Consequences

- `AuditEvent` is a new record kind. It is additive and gets a compat
  fixture (I16). Binaries from before M28 cannot open a log that has one,
  as with any new kind.
- The log becomes the complete audit trail (I5). `kronik history
  --operations`, which the build brief promises, can later read the same
  records.
- Re-sent batches duplicate lines, so consumers must dedup by (`lsn`,
  `effect`, `record_hash`). This is documented with the sink formats.
- The file sink truncates its newest file to the last newline at start, so
  a crash mid-append leaves no torn line.
- Exercised current evidence: all 102 permanent exporter tests pass,
  including control/checkpoint failure, causal resume, gap restart,
  bounded metadata, fatal-sync latching and versioned archive boundaries.
  All seven actual binary audit tests pass, including fresh from-now
  restore, lost configuration-cache recovery and owned-file mtime rollback.
- An actual local Moto S3 run (27.31 s, pinned image) verifies conditional
  create, readback of legacy/current namespaces, rejection of a forged
  legacy line, rewind/restart without overwrite, and an unsupported-create
  coded stall with unchanged durable cursor while turns remain usable.
  All seven resulting archive objects and daemon logs exclude the needle.
  Human export tables and owned-container cleanup were observed.
- The earlier 2.66 s daemon/API/OTLP smoke covers unavailable local secret
  ciphertext: three API 503s, both export cursors frozen and a usable
  unrelated turn. Two actual OTLP binary tests also passed.
- These are not physical fsync-repair, cloud IAM or HSM proofs. Historical
  archive misordering is not repaired. Complete retained external/deleted
  secret inventory across restart remains M23 work.
