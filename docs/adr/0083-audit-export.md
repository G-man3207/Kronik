# 0083. The audit export: the log is the audit trail

- **Status:** Proposed
- **Date:** 2026-10-27

## Context

The M28 brief:
- "Audit-loggen över alla mutationer exporteras löpande som JSON-rader till
  fil, webhook eller objektlagring."
- Acceptance: "Den exporterade audit-loggen är fullständig jämfört med
  loggens poster, och ett test jämför dem."

What exists:
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
     (`rebase.create`, perf review P2).
   - The four secret and token routes write it *before* the change, as the
     intent, and a `<action>.failed` event if the change then fails, so a
     crash can over-report but never hide a credential change. The others
     write it after the change succeeded, except the two that wait for a
     job: `watch.start` is written before the watch starts and
     `proposal.create` before the request waits for the replay (perf
     review P3), so a caller that stops waiting cannot lose them.
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
   JSON line (`kronik.audit/v1`, m28-otel §4.3) per audited item, in LSN
   order:
   - the record's `lsn`, the effect ordinal for a reveal, `kind`, `action`,
     `token_id`, `at_wall_ms`, scrubbed `reason`;
   - per-kind `details` under ADR 0082 (a reveal names the secret, never
     the value);
   - `record_hash`, the blake3 of the record's canonical form, each
     sealable replaced by its subject tag, so a reseal does not change it.
     An erasure's subject is replaced by its keyed label, and the key in a
     `fork.send` event's `details.actor` by its keyed label (`kind/` plus
     the label, perf review R1), so the hash cannot confirm a guessed
     subject or actor key.

   A unit test fails when a record message with an `Audit` field is not
   classified.
3. **Completeness.** For a range (F, L], the exported lines deduplicated by
   (`lsn`, `effect`, `record_hash`) equal the audited items in (F, L] on
   (`lsn`, `effect`, `kind`, `action`, `token_id`, `at_wall_ms`,
   `record_hash`), with nothing missing, extra or conflicting. The LSN alone
   is not a key: after a restore from an older ship point, new records
   reuse the lost tail's LSNs.
   - `kronik audit verify --sink` computes this against the log.
   - `crates/kronik/tests/audit.rs` drives every mutating route, a reveal
     and a restore (dry runs too, which must export nothing), with a
     restart in between. It builds its expected lines from the actions it
     drove, not from the exporter's classifier, and also runs `verify`.
4. **Sinks.**
   - A directory (`file://`): `audit-<first lsn>.jsonl`, fsynced before the
     cursor moves. A new file never takes an existing name.
   - A webhook (`https://`): NDJSON batches with an `idempotency-key`
     header of the range and a hash of the body.
   - Object storage (`s3://`, through `kronik-ship`'s `Remote`): one object
     per batch, named by the wall time it was prepared and its LSN range.
   - After a restore reuses LSNs, no sink loses or deduplicates away the
     lines it got before (code review H-B).
   - Delivery is at least once and in order. Consumers dedup by (`lsn`, `effect`, `record_hash`).

## Alternatives

- **Read secrets, tokens and forks from their own stores.** Their history
  is incomplete: delete drops the reason, and forks keep no caller or time.
  Exporting from several sources makes "complete" undefinable.
- **After-change everywhere.** A crash between a secret or token change and
  its event would hide a credential change, so those four routes write the
  intent first. For forks, proposals and snapshots, after-change is kept:
  the object stays visible in its store, and the window is one fsync.
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
  --operations`, which SPEC promises, can later read the same records.
- Re-sent batches duplicate lines, so consumers must dedup by (`lsn`,
  `effect`, `record_hash`). This is documented with the sink formats.
- The file sink truncates its newest file to the last newline at start, so
  a crash mid-append leaves no torn line.
- Verified by the audit test above, the needle tests (ADR 0082), and
  `kronik audit verify` against the S3 sink on the testbench.
