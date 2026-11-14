# 0134. Per-kind HTTP fingerprint rules

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13

## Context

The brief defines the HTTP fingerprint as the method, scheme, host, path,
sorted query parameters, a hash of the body and an allowlist of headers.
By default `authorization`, `cookie`, `date`, `idempotency-key`,
`user-agent` and `x-request-id` are left out, and "the rules can be set per
actor type" (Build-Brief.md, effects). The exact rules are left to an ADR.
Kronik had only the six defaults, as a constant for the whole process
(issue #39).

Some targets need more. A rotating `x-api-key`, an `x-amz-security-token`,
or a timestamp, nonce or cache-busting query parameter makes the same
logical request a different fingerprint every time. A recovery re-run then
sees `REPLAY_DIVERGED`, a fork's exact match becomes approximate, and a
diff reports a changed request that did not change.

The fingerprint decides matching (I1, I7), so the rules must be part of
the log (I5): a replay must decide as production did, whatever the
configuration is now.

## Decision

**Rules.** Each actor type has two lists: header names and query-parameter
names left out of its `http.fetch` and `foreign.http` fingerprints. They
add to the six default headers, which always stay out; the defaults cannot
be put back. Header names are tokens, compared without case. Query names
are compared with the parameter's name as the URL writes it, case and
percent-encoding included. Each list holds at most 64 names of at most 128
bytes, and is kept canonical: lowercase headers, sorted, without
duplicates or default headers.

**Configuration.** The lists are fields of the `Limits` record, 11 and 12,
each a `NameList` message. A set list replaces the kind's, an empty one
clears it, and an unset one keeps it, like the other limits.
`kronik limits set <kind> --fingerprint-exclude-header x-api-key
--fingerprint-exclude-query ts,nonce --reason ...` and `POST /v1/limits`
(`fingerprint_exclude_headers`, `fingerprint_exclude_query`) write them.
`kronik limits show` and `GET /v1/limits` show the lists in force. A turn
uses the rules of its configuration epoch, as it uses its limits.

**Recording, version 3.** A request whose actor type has rules is recorded
with `HttpEffectRequest.fingerprint_version` 3 and the lists in fields 6
and 7. Version 3 is version 2's prepared encoding and hash, less the listed
names. After the headers it also hashes the two lists, under its own
domain `kronik.fingerprint.http.v3`, so that fingerprints made under
different rules never meet. A request without rules is version 2, byte for
byte as before. A version 2 request with lists, or a version 3 request
whose lists are empty or not canonical, is invalid.

**Matching.** A recording's fingerprint is always recomputed from the
recording itself, never from the configuration now. A recovery re-run
uses the configuration of the turn's recorded epoch, which is the
recording's. A fork compares its new request with a production recording
under that recording's lists (`under_rules_of`): identity replay stays
exact after the rules change, and a fork with other rules still finds its
exact matches. The fork records its own requests under the rules of its
turn's epoch, as production does. Neighbor and model simulators, which
match by similarity, take version 3 like version 2.

## Alternatives

- **Rules on the `Grant` (per target).** The brief sets the rules per
  actor type, and a grant is per type and target. Per-target rules can come
  later, as further fields. Not now.
- **A record type of its own** (`FingerprintRules`, `kronik fingerprint
  set`). This needs a new versioned schema, fixtures, an API route and a
  command, about twice the surface for the same effect. The `Limits`
  record is already the per-kind, per-epoch configuration the gate reads.
- **Extend version 2** (hash the lists only when present). This is
  smaller, but two algorithms would share one version. A binary from
  before this ADR would compute a different fingerprint for the same
  version and fail with `REPLAY_DIVERGED` or approximate matches, instead
  of refusing a version it does not know.
- **Rules from the configuration now.** A rules change would make every
  older recording mismatch. Rejected (I1).
- **Body rules.** Leaving out the whole body is too coarse, and leaving
  out JSON paths is a design of its own. Neither is part of this ADR; a
  later one can add JSON-path exclusion if targets need it.

## Consequences

- An operator can make a volatile header or query parameter of one actor
  type's targets stop breaking exact matches. Other types are unaffected.
- Logs with version 3 requests cannot be read by binaries from before
  this ADR: they refuse version 3 as unknown. Version 2 recordings keep
  their bytes and fingerprints; a test pins one.
- A listed value is left out of the fingerprint, not of the recording:
  the request is still recorded whole, scrubbed as before.
- Verified by: fingerprint unit tests (the version 2 pin, version 3's
  exclusions, canonical lists, comparison under a recording's rules), the
  compatibility fixtures `limits-fingerprint-v1` and
  `effect-record-http-v3-v1`, a node test with the rules of two kinds, and
  an identity replay across a rules change that stays exact in both modes.
- Revisit for per-target or body rules.
