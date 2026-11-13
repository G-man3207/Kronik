# 0082. What telemetry and audit export may carry off the node

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

Spans, metrics and audit lines go to systems Kronik does not control: a
tracing backend, a webhook, a bucket. Once something is there, Kronik
cannot erase it or reseal it.

The rules so far:
- **I8:** a secret is never written to the log, diffs, history or MCP, and
  a revealed value is scrubbed from records.
- **M8:** a subject's values are sealed. Callers without `pii:read` never
  see them or a subject id. Erasure deletes the key.
- **Actor keys are identities, plain everywhere** (privacy guide). They can
  still be an e-mail address.

Some free text in records is written by guest code or by operators and is
not sealable:
- `Outcome.message` and `EffectRecord.error` (guest code: it can hold a
  value the guest read from state);
- `Audit.reason` (operators).

## Decision

**Never exported:**
- any `Sealable` value: bodies, headers, request lines with a subject,
  message bodies, effect requests and responses, replies, writes,
  changesets;
- `Outcome.message` and `EffectRecord.error`;
- paths and query strings: spans carry the route pattern;
- subject ids, anywhere;
- secret values;
- token secrets.

**Exported:**
- kinds, route patterns, methods, status codes, outcome kinds and error
  codes;
- effect kinds, statuses and grounding;
- the host of an `http:` target, and scrubbed secret and token names;
- code hashes, epochs and LSNs.

**Hashed:**
- **Subject ids**, where the audit line needs to say which subject (an
  erasure): `s:` plus 12 hex of the keyed hash the diff already uses
  (`"kronik diff subject v1"`).
- **Actor keys**, by default (`[otel] actor_keys = "hashed"`): `kh:` plus 12
  hex of `Sealer::keyed_hash("kronik otel key v1", [kind, key])`. This is
  stable for correlation and cannot be reversed without the master key.
  `"plain"` and `"none"` are opt-in alternatives. The audit export applies
  the same setting to the actor of an operator send and of a reveal. A node
  without a master key hashes with a node-local key (`<data>/otel.key`).
- **Span and trace ids** other than a root's random trace id, in every
  `actor_keys` mode: they derive from the causal key, which names each
  step's actor key, so they are keyed blake3 with a key derived from the
  same key under `"kronik otel ids v1"` (ADR 0080).

**Scrubbed and capped:**
- Free text, names and span labels are scrubbed for available secret
  values and token spellings, both at mutation recording and export.
  The audit `record_hash` must not become a guessing oracle for private
  text. It hashes the scrubbed free text, never replaced by a placeholder,
  and `kronik.audit/v3` keys that hash with the master key (ADR 0083,
  amended).
- Subject masking recognizes case and percent-encoded spellings at
  identifier boundaries, rather than replacing arbitrary substrings.
- `reason` is capped at 4 KiB in the line and at the API (`BAD_REQUEST`
  above that limit). Do not put personal data in reasons.
- An unavailable secret inventory fails closed: privacy-sensitive API
  projections return HTTP 503 `SECRET_UNAVAILABLE`; mutating audit text
  is safely withheld; exporter preparation stalls without cursor advance.
  The current LocalSecretStore inventory does not establish complete
  retained external/deleted-version coverage across restart; that remains
  M23 work. Numeric restore/gap positions are validated action-specific
  `u64` values, not generic exemptions for keys or free text.
- `kronik export status` (scope `read`) shows a sink's scheme and host only,
  and an error's code, not its text.

**`traceparent`:** an incoming header is used only for its two ids, as a
link, after a strict format check, even when sealed.

**Plain HTTP:** OTLP over `http://` to a host that is not loopback is
refused when `headers_env` is set, since those headers usually carry
credentials.

## Alternatives

- **Export everything and let the backend's access control decide.** Out
  of Kronik's reach, against I8 and M8, and erasure could not follow.
- **Export sealed values encrypted.** The backend cannot use them, and the
  key would have to travel with them.
- **Plain actor keys by default.** That matches the in-node model. A
  third-party backend is not the node, so the default leans the safe way;
  it is a one-line config change (open question in m28-otel §12).

## Consequences

- An erasure needs no action at the backends. No subject value or id was
  ever sent there, only keyed hashes that are useless without the master
  key.
- Traces show structure and timing, not data. A failing turn shows its
  error code, not its message. To see a turn's values, an operator opens
  it in Kronik with `pii:read`.
- Verified by needle tests:
  - unit tests in `kronik-otel` over spans and lines built from records
    full of marked values;
  - the audit e2e test (m28-otel §4.5), with a secret value, a subject id,
    a message body and a token secret, none of which may appear in any line
    or span.
