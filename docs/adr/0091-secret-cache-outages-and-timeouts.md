# 0091. Secret cache, outages and complete retained-value coverage

- **Status:** Accepted design for M23 B2–B5 and the shared M28 confidentiality
  boundary; implementation and exercised evidence are tracked separately on
  [the project status page](https://github.com/G-man3207/Kronik/wiki/Project-status).
- **Supersedes:** the parked two-method backend trait and observed-current-only coverage assumptions.

## Context

External services are opt-in. Their outage must not stop unrelated actors or daemon startup (I10), but a successful response must not expose retained secret values (I8). A cache containing only current versions cannot scrub an older revealed value after rotation or restart. Returning an empty list after decrypt/list/fetch failure falsely claims complete coverage.

The existing canonical scrubber remains the one convention. This decision does not introduce a second redaction algorithm, a disk mirror or a provider SDK framework.

## Decision

### Backend operations and immutable identity

The backend boundary provides current value, immutable version lookup and paginated retained-version metadata listing. The listing returns IDs plus an explicit continuation; success must distinguish an empty complete catalogue from a denied, failed, unsupported or truncated catalogue.

Every value carries ADR 0090 provenance: trusted backend/public binding, reference/canonical resource, link generation and immutable source version. Validate returned resources and every continuation authority against trusted configuration. Metadata never chooses credentials or an endpoint. Use typed `Unavailable`, `Denied`, `NotFound`, `VersionGone` and `Invalid` errors; do not infer authorization from sanitized error strings or expose provider bodies.

### Operational cache

External values are memory-only and zeroizing. The built-in encrypted store remains the only built-in write source; external cache values are never mirrored into it. Guest data that can contain a revealed value remains subject to the complete scrub boundary below.

- Warm fresh access performs no network request.
- Cold access is bounded by the configured Env deadline (default two seconds); failure produces the existing recorded effect-error behavior for a new effect.
- A negative result is cached for five seconds, scoped to exact provenance, not merely a name.
- Only typed `Unavailable` permits a previously authorized value to remain operational until `max_stale` (default 24 hours). Definitive denial, missing version or invalid binding revokes operational use immediately.
- Retained scrub-only storage is not an authorization fallback. It cannot resurrect a revoked operational value.
- Background refresh uses Env tasks/time/randomness, bounded retries and jitter. It records newly observed versions through the same allocator. OpenBao token renewal/relogin and cloud token refresh reuse the existing scoped authentication transport.

Turn-caused cold current/version/list work starts only after durable `TurnBegin`; background warm/management work is separate. A timeout holds only an actor that needs the value. Turns using no linked secret do not wait for cache refresh or provider recovery.

Foreign actors resolve through the same operational cache at start. Rotation does not restart an already-running foreign actor; its next explicit or supervised start uses the then-current authorized version.

### Complete inventory for disclosure boundaries

A successful inventory is complete for a specific observed-version registry revision and source/link generations. It includes the union of:

1. required immutable versions derived from retained log references, current state and snapshots, including values whose first reveal is no longer in the retained log;
2. every still-retained provider version of a reveal-capable name, obtained through complete paginated listing.

Retained log references include those in sealed requests. The request of an erased subject (its key destroyed, or a tombstone left by a reseal) is gone for everyone and derives no required version, and the required set does not shrink because of it: the versions it named stay in the ledger. A request that cannot be opened and was not erased (no key store, a missing key version, a value that fails to unseal) keeps coverage incomplete, and the key store is the remediation (ADR 0108, amendment on erased requests).

A grant revocation, relink, current-version change, omitted provider ID or restart does not silently remove a required historical value. A new registry observation invalidates/reconciles coverage before disclosure. Listing races are merged/rechecked; do not claim stronger snapshot semantics than the provider supplies. Durable log-before-use provenance closes the set of values Kronik could have exposed.

Bound work and memory, but never call a capped or truncated catalogue complete. Failure or resource exhaustion preserves incomplete status and an operator-visible least-privilege/remediation hint. Required immutable versions are fetched by version and their recorded hashes checked, never replaced with current.

The file catalogue contains retained store versions. The environment source has only its current keyed content identity; a changed or lost old environment value is `VersionGone`, not an excuse to mirror it to disk or use the replacement value. A genuinely unrecoverable required version can keep affected output unavailable until retained-data/coverage remediation.

Read surfaces that need scrubbing—history, inspect, audit, preview and foreign logs—return `SECRET_UNAVAILABLE`/503 while coverage is incomplete. Never return partially scrubbed success, empty successful logs or raw provider errors. Audit/trace export preparation retries without moving its cursor or mutating delivery state. Successfully empty coverage is distinct from failure.

Secret mutation ACK also certifies the actual current registry/configuration
revision for these read surfaces. SET, DELETE, LINK, UNLINK and explicit
REFRESH release their per-name mutation lock, wake the existing independently
authorized collector, and await its semantic-revision completion within the
existing fetch deadline. A wake alone is not completion. Both actual
configuration-epoch publishers invalidate coverage and, before they return,
recertify it from the catalogue that the last full rebuild captured. They wake
the collector only when that recertification could not restore the
certificate: a change that restored its own certificate is not followed by a
full rebuild, which would retire the certificate at its first step and leave
the next request without an inventory until it ends. A skipped stale wake does
not reset the periodic refresh deadline. Metadata reads never fetch a provider
or fill the cache to hide incomplete coverage.

If this bounded publication fails after the immutable mutation is committed,
return `SECRET_UNAVAILABLE` with the committed-state hint; keep its real
Active/deleted/configuration state. Do not rewrite it as Failed or automatically
submit another mutation. Once inventory is available, inspect history before
an explicit new operation. A successful certificate is scoped to its real
revision and does not promise availability after a later concurrent change.

Writes use canonical whole-text withholding for unavailable free-text coverage, so an unrelated mutation need not stop. Canonical identifiers retain the existing target policy; that is not permission to publish arbitrary unsanitized text. Metadata-only health, keys and doctor remain available. No master-seed/KMS reload happens on these paths.

### Replay and authorization

Recorded matching effects need no provider. An immutable replay/resend that needs bytes uses its recorded provenance and must not replace an already-recorded outcome. Availability retries affect that actor only. Missing/mismatched immutable data fails before the guest sees a substituted result. A provider authorization revocation cannot be bypassed with stale or scrub-only storage.

Forks never fetch. Their configuration/link epoch remains the fork point plus explicit candidate overrides, while upgrade identity follows recorded production configuration/code/link history. An unmatched fork use requires an already-held, still-authorized value for that exact identity.

## Acceptance evidence required

This design does not preclaim tests. Exercise cold/warm/stale/deadline boundaries, typed revocation, pagination/truncation and authority attacks, generation races, failed/reserved publication, cross-restart closure from log/state/snapshots, changed environment values, no-network replay, unrelated-actor progress, foreign starts, and no leaked needles from every affected API/export/marker. See [the M23 design](../design/m23-secret-backends.md); observed results are
  tracked on [the project status page](https://github.com/G-man3207/Kronik/wiki/Project-status).
