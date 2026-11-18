# 0155. `subject_from` requires a trusted proxy

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

`privacy.subject_from` reads a request header or an unverified JWT claim and
tags the root input with that subject. The ingress idempotency hash then
treats the subject as the only requester identity and deliberately omits
`Authorization`, so a proxy's rotating token is still a replay of the same
client.

`[gateway] trusted_proxies` empty used to mean every peer is a proxy. Any
client that could reach the gateway could choose the subject. Repeating the
method, path, query, body and `Idempotency-Key`, and forging the victim's
subject, returned the saved response. No victim credential was required. The
privacy guide stated the two halves separately and not their combination.
Issue #192.

The subject still does not authenticate anyone. The proxy in front of the
gateway does. An empty list is not a way to say "this node has no proxy, so
trust the header."

## Decision

- `kronik serve` refuses to start when `subject_from` is set and
  `trusted_proxies` is empty. The error names the list and says to list the
  authenticating proxy or unset `subject_from`.
- An empty list trusts no peer. A `GatewayConfig` built without going through
  the file check refuses a present subject the same way a non-proxy peer is
  refused when the list is set: `400 BAD_REQUEST`, not a turn and not a saved
  response.
- A listed proxy's own retry, with the same subject and a rotated
  `Authorization`, remains a replay. With `subject_from` unset, anonymous and
  `Authorization` binding are unchanged.

## Alternatives

- **Keep the empty-list mode and document that idempotency does not
  distinguish requesters.** That matches the old guide, and it leaves the
  saved response available to anyone who can forge the subject. The binding
  the guide promises is then false in the default combination.
- **Hash `Authorization` next to the subject.** A refreshed token would become
  `IDEMPOTENCY_KEY_REUSED` for the proxy's own retry, which is the case the
  subject binding exists to allow.
- **Drop the subject when the peer is not trusted, and run the turn.** The
  request's data would be stored unsealed and could not be erased. Refusal
  is the existing rule for a non-proxy peer.

## Consequences

- A node that set `subject_from` and left `trusted_proxies` empty does not
  start until the proxy is listed or `subject_from` is unset. That is the
  point: the previous combination was the hole.
- `0.0.0.0/0` in the list still trusts every connecting peer. The check is
  that a proxy was named, not that the range is tight. Revisit if a deployment
  needs the file to reject an any-address block.
- The JWT signature is still not verified. The proxy remains responsible for
  replacing the subject header and for authenticating the client.
