# 0112. A grant chooses whether a fork may compute with a production key

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

The build brief's effect table says an unmatched `crypto.hmac-sha256` or
`crypto.sign-ed25519` is computed by the host, and that the value never
leaves the host. `docs/design/m3-fork.md` §3.5 says the same: a fork gets a
real HMAC or signature over data its code chose, and the key stays on the
host.

That computation is what the brief requires. It is also a capability: code
deployed into a fork can have arbitrary data signed with a production key.
Project status already named the mitigation: a per-grant
`--in-forks compute|recorded` mode, a log line, and a metric. The grant
record had no field for it.

A fork must not fetch (I7). A name linked to an external backend is already
denied with `SECRET_EXTERNAL`. `secret.reveal` in a fork already returns
the placeholder `[secret:<name>]`. A preview passes no secret store, so its
crypto calls already answer `replay: no recording`. None of those change.

## Decision

Each grant has an in-forks mode, `compute` or `recorded`.

- **Wire.** `Grant.in_forks` is field 8, a string, added the same way as
  `ForeignActor.fork_mode`. Empty, which is every grant written before this
  field, means `compute` (the behavior those records already had). A value
  other than empty, `compute`, or `recorded` is invalid. No log format
  version bump: adding a field is the compatible change.
- **New grants.** `kronik grant` and `POST /v1/grants` write `recorded`
  unless the operator passes `compute`. Re-granting without an explicit
  `compute` choice writes `recorded`, including over an older grant that
  had no field. Operators who want the old behavior pass
  `--in-forks compute`.
- **Fork crypto.** A fingerprint match still returns the recording. An
  unmatched linked name is still `SECRET_EXTERNAL`. An unmatched built-in
  name is computed only when the grant mode is `compute`. `recorded` denies
  it with the existing `replay: no recording` and does not compute. A
  preview still has no secret store, so it still answers `replay: no
  recording` and does not compute.
- **The key stays on the host.** `compute` returns the signature or HMAC to
  the guest. The key is not placed in the guest result, the effect record,
  or the diff. The computation is a tracing line (algorithm, secret name,
  actor kind) and one `kronik_fork_crypto_computations_total` sample. The
  line and the metric do not carry the key, the signed data, or the
  signature.

`secret.reveal` in a fork is unchanged.

## Alternatives

- **Remove host computation.** It would violate the brief's effect table.
  The grant mode keeps the path and makes it an operator choice.
- **A node-wide switch.** One installation often wants some secrets
  signable in a fork and others not. The grant is already the unit of
  permission.
- **A new error code for the recorded denial.** `replay: no recording`
  already says the call was not computed, and preview and a missing key
  use it. A second code would not change what the guest must handle.
- **Fetch a linked secret in the fork and compute with it.** A fork must
  not fetch (I7). Linked names stay `SECRET_EXTERNAL`.

## Consequences

A new `secret:` grant no longer lets a fork sign with that key unless the
operator asks for `compute`. Existing grants keep signing until they are
re-granted. A fork computation is visible in the daemon log and in
`/metrics`. The security guide states the same rule.

Revisit this if the brief stops requiring host computation, or if a
recorded denial needs a distinct stable code because guests cannot treat
it as `replay: no recording`.
