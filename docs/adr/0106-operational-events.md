# 0106. Operational events follow committed records and existing audit cursors

- **Status:** Accepted
- **Date:** 2026-10-31

## Context

M30 needs a published operational feed for proposals, approvals, deployment,
guards, dead letters, upgrades and the actual additional control/secret records.
It must not become a second journal, scrubber, authorization path or global LSN.
M28 already owns safe record projection, protected identity, durable cursors,
retention and fail-closed disclosure. M23 owns secret identity and HMAC values.

## Decision

- Publish `kronik.event/v1` envelopes and the versioned schema
  registry from actual records. The schema fixtures decode the corresponding
  wire records, not a second list of labels. Internal delivery receipts are not
  invented operational events. Reuse the canonical M28 Mapper and Sealable
  visitor; free audit text, arbitrary detail maps, bodies, claims and private
  credentials are not copied into an event payload.
- A validated `PrivacyMode.reseal_requested` records
  `privacy.reseal.request`, not completion. Ordinary mode records retain
  `privacy.mode`; only the existing post-success Audit40 is `privacy.reseal`.
- Event IDs are canonical **operational identity**, not a universal payload
  hash. Use M28's protected `kronik audit record v3` keyed projection, actual
  installation/source position and deterministic subindex. Sealable values are
  excluded by that projection, so a value-only change need not change an ID.
  Missing protected identity fails closed; there is no public SHA/empty fallback.
  Retry, reseal and replay preserve the same event identity.
  For actor events, bind `Event.branch` and the ID to the actual validated
  `ActorSource.branch` carried by that committed frame. A reader head named
  `rebased-main` does not relabel older `main` or fork frames. The canonical
  source namespace is 1–256 UTF-8 bytes, excluding ASCII controls, `:`, `/`
  and `\`; it is not the narrower configured identity-label vocabulary.
  When frame and feed branches already agree, this correction does not change
  IDs. An older durable batch prepared with the wrong reader-head namespace
  must conflict-hold instead of being silently rewritten. Only ordinary
  authorized, audited replay with its reason may regenerate that source's
  correctly bound event; there is no legacy ID alias or automatic conversion.
  Metadata IDs remain independent of actor feed selection.
  SecretVersion's validated native-adoption sidecar is not part of that record
  hash. Changing only that sidecar at the same metadata index can retain the
  same ID; immutable history and prepared-body conflict checks must hold on
  such a rewrite. Do not treat IDs as hashes of every visible envelope field.
- Keep `actor-native`, each actual `actor-N`, and `metadata` separate. An absent
  actor shard is not shard zero. Metadata indices are actual committed metadata
  positions, never actor LSN aliases. There is no cross-source total order.
  Resume cursors retain typed sources and the next event subindex.
  `ResumeCursor.identity.branch` selects the feed and is not per-record
  provenance. Native pages use the actual held `ShardReader` and its
  `(ActorSource, Committed)` frames; no source is reconstructed from a
  shard-looking label or a current head. Metadata events have no actor branch.
- Sparse metadata scans advance only through their certified examined prefix.
  A full limited batch is not permission to jump to its durable head. A missing
  coverage prefix is explicit, repeatable and source-tagged; schema-floor loss
  must not be described as physical retention deletion. Before skipping a lost
  prefix, write the fixed validated gap audit durably and advance under the
  same cursor control generation. A concurrent rewind remains authoritative.
- A durable prepared webhook body/pin/timestamp is retried before checking fresh
  coverage. Known-coordinate history rewrites hold with a conflict; they are not
  converted into gaps. Compaction and restart must not silently discard an
  unacknowledged prepared event.
  Bind each sink to its one real configured `Stream` and cursor registry.
  Delivery retains the same original lease with the actual source reader and
  certified snapshot publication; a newer epoch cannot repair an older
  checkpoint's authority.
- Keep concrete Member registration in the existing Member frontend, not in
  common Fleet/API delivery. That producer checks the actual inventory/source
  pointer, scope, branch, shard, cursor registry and stream binding before
  constructing the common runtime callbacks. It retains those real resources.
  Actor capture returns one actual `Arc<ShardReader>` and the common path
  propagates that same Arc with the paired snapshot/publication and full
  original through response EOF and cursor publication. No Node fallback,
  synthetic inventory, extra feature gate or replacement authority is allowed.
  The registered actor-gap callback keeps the actual fixed actor gap producer
  and deduplication; it is not the metadata-gap DTO. Actual metadata hosts retain
  their `MetadataAuditSource` and existing `MetadataRuntime` unchanged.
- Native-imported authority history carries only a closed optional adoption
  marker, derived from actual typed provenance after shared validation.
  `current_projection=false` is archive history; true identifies the captured
  current projection. Neither is a new creation or permission grant. Unknown
  original audit/source remains unknown, not a fabricated issuer or timestamp.
  Common event consumers obtain only the sole mapper's closed typed adoption
  fact after validation of the actual source and provenance. They neither read
  an AuditEvent wire-origin field nor interpret free details or source labels.
  Full supported canonical AuditEvent origin and SecretVersion sidecar semantics
  remain in that mapper; an unsupported import factory stays explicitly held.
  Duplicate or conflicting provenance is rejected, never reconstructed from
  boot state, schema versions or actor source labels.
- `GET /v1/events`, `/v1/events/stream` (SSE), `/v1/events/ws` (WebSocket),
  `/v1/events/schemas` and `kronik events tail` share ordinary capture and read
  scopes. Authorization precedes metadata/excerpts and the original lease stays
  with the stream. Bounded buffers use backpressure; revocation/logout cancels
  waits and future frame admission rather than silently dropping events.
  `source` optionally selects one configured typed source for SSE/WS or
  `events tail --source`; omitting it preserves the all-source stream.
- Webhooks use the existing M28 follower, cursor writer and replay generation,
  not another queue. Persist the prepared canonical UTF-8 JSON body, event ID,
  signature timestamp, immutable full M23 secret identity and generation before
  the first send. Non-2xx/transport failures retain that pending body and use
  bounded exponential backoff. Only an acknowledged delivery advances the
  cursor. Lost ACKs produce **at-least-once** duplicates, not exactly-once delivery.
  Preparation stages the immutable batch in memory; its first delivery uses the
  exact retained disclosure guard to fsync pending state before any MAC or
  network admission. A denied guard creates neither a new pending manifest nor
  transport work. Subsequent retries reuse the persisted bytes and pin; an ACK
  checkpoint is published by the existing follower under that delivery's guard.
- The signing input is the UTF-8 prefix below followed by the exact canonical
  JSON body bytes. Each `\n` denotes one LF byte (`0x0a`), not a backslash:

  ```text
  kronik.webhook/v1\n<TIMESTAMP_MS>\n<EVENT_ID>\n<BODY_BYTES>
  ```

  Send `Kronik-Signature-Version: v1`; `Kronik-Timestamp-Ms` is the prepared
  decimal timestamp, and both `Kronik-Event-Id` and `Idempotency-Key` are the
  exact event ID.
  `Kronik-Signature` is `v1=` followed by lowercase hex HMAC-SHA256 of the
  signing input. The timestamp is the prepared batch timestamp, not a fresh
  clock value on each retry. The signature and secret never go in the URL.
- Resolve MACs through the current M23 registry with allowed references and the
  complete immutable version/link binding. Do not export or disk-mirror an
  external value. Configuration rotation may select a new pin for future
  delivery and replay, but an already prepared event retries with its old pin.
  Record the fixed configuration audit before activating the new cursor pin.
- Actor-free metadata hosts supply the actual Env, shared protected sealer,
  certified physical catalogue and original registered execution/leader lease;
  never construct a stand-in actor Node. The catalogue is privacy data, not
  authority. Recheck the same original execution after the signing await and
  before catalogue inspection; a revoked job is not a secret-coverage failure.
  Capture the certified snapshot/publication pair before reading an
  authoritative metadata page. Its catalogue callback cannot warm a provider
  or substitute an empty inventory. Gap and key-change producers receive the
  exact passed original lease; neither recaptures a bootstrap principal.
  Use the canonical `Net::http_authorized`: connector, pool and sender-ready waits
  stay outside publication; the original lease admits Hyper's synchronous
  `try_send_request` queue operation. A lazy legacy-client future or an Env task
  enqueue is not that final boundary. Existing bounded owned completion retains
  the original lease through response or timeout, including waiter cancellation.
  Response headers are not completion: bounded response-body collection stays
  inside the same total timeout, retaining the original and owned resources
  through actual body EOF.
  There is no second fleet client.
- Replay is an ordinary admin operation with reason and dry-run. Metadata replay
  first receives the actual durable metadata audit receipt under the original
  user lease, then uses the existing cursor rewind job with that same lease.
  A physical boot lease is not a substitute user principal. Dry-run neither
  writes an audit mutation nor advances/replays a cursor.

## Alternatives

- A generic event bus/queue, independent scrubber or synthetic global sequence:
  duplicates existing M28 machinery and risks inconsistent privacy or ordering.
- A body hash as a universal identity: leaks or changes private-value identity
  and makes reseal/retry semantics misleading.
- Latest-secret lookup on retry or a copied external key file: breaks immutable
  version/rotation and provider authorization guarantees.
- Dropping an old prepared batch on a gap, reset or rewind: loses the durable
  at-least-once contract.

## Consequences

Secret coverage or protected identity failure returns `503 SECRET_UNAVAILABLE`
and holds export/cursors; it does not publish unsanitized or empty substitute
content. Receivers should authenticate the exact body and deduplicate by event
ID while tolerating lost-ACK duplicates.

`scripts/e2e-events.py` exercises a real supplied binary and finite independent
receiver in a capped Docker `network none` namespace. The native scenario passed
actual SSE resume, WS, CLI, HMAC negative cases, 503/backoff, lost ACK, durable
restart, replay, old pending pin and new-key identity continuity. An earlier
native acknowledgement wait timed out; the instrumented run passed, but its
cause was not observed and is not claimed fixed. Native proof does not replace
real member/leader/zero-actor metadata or unified IO producer acceptance.

The changed receiver also flushes a real successful response's headers while
withholding its body. The native consumer kept both API and durable cursors,
and the immutable pending delivery, unchanged until body EOF; all 19 receiver
checks passed with the immutable Native35 binary. This new boundary test does
not attribute the newer streaming/borrowed-catalogue source or member path.

The current Root source selection consumes the mapper's validated closed typed
adoption fact; it does not attach an unsupported AuditEvent origin field or
activate an import factory. The canonical imported-origin consumer is preserved
separately from that exact held Root edge. All other reachable ordinary event,
secret-sidecar, cursor, HMAC, replay and revocation consumers remain selected.
This source cohort has not been built or executed; the historical native receipts
above are not transferred to it, and do not establish genuine Member, registered
source, zero-actor metadata or the separately held unified IO path.
