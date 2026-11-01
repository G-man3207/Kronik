# 0105. Fleet enrollment uses an ordinary principal and an outbound connection

- **Status:** Accepted
- **Date:** 2026-10-31

## Context

M29 must reach installations behind NAT without another listening port or a
privileged remote command API. The controller is an untrusted request origin,
not an issuer of local scopes, policy, credentials or CA configuration. M10's
ordinary API and M16's original execution/principal admission remain the
security boundary. Audit records describe operations; their issuer text is not
an authorization credential.

## Decision

- `fleet enroll URL --token ONE_TIME --reason ...` uses the locally configured
  canonical controller origin, realm CA, installation/node/cluster identity and
  exact ordinary scopes. The controller cannot replace those values through a
  reply, redirect, cookie or request header. Prefer `--token-stdin` or an owned
  `--token-file` to avoid an argument in shell history and process listings.
  An ordinary API bearer is never an implicit enrollment credential.
- Before the first enrollment request, persist the installation's owned leaf key,
  CSR and public request identity. Use the existing host identity library and
  secure-file/KeySource custody; do not generate a production root CA or send a
  private key to the controller. Host-only identity dependencies stay optional
  in Core and out of default WASI guest graphs.
  Private leaf and enrollment-body buffers use the existing B1 zeroizing Bytes
  owner; secure-write buffers stay guarded through deferred I/O and failure.
- Trusted server TLS admits the one-time enrollment exchange. The returned client
  certificate must match the exact CSR key, request, enrollment epoch and local
  identity, and pass trusted-chain/client-auth checks before activation. Pure
  DER/protobuf validation is structural validation, not a CA or signature proof.
- A lost reply resumes only the same durable request/CSR identity. It does not
  resend the bootstrap token or turn token rejection into permissive reuse.
  `Requested` recovery is not an ordinary command authority: the original
  enrollment caller's lease remains required through the certificate/body wait
  and final activation enqueue. A new explicit recovery request uses its own
  ordinary authorization, never upgrades the old job. Dry-run generates no key,
  consumes no credential, changes no durable authority and contacts no controller.
- Fleet control state is `AuditEvent.operation` 5 (`FleetState`); installation
  identity is operation 6. Existing record kinds and fields 1–4 are unchanged.
  These are bounded typed public authority facts, not JSON in `details`.
  Free audit reasons still use the shared scrubber or are withheld when secret
  inventory is unavailable. Secret spelling must not change public identities,
  schema names, origins, certificate bindings or numeric positions.
- Activation creates an ordinary local TokenStore credential bound to the exact
  durable fleet request, enrollment epoch and scopes. Its new local bearer has
  owned 0600 restart custody; it is not a disk mirror of an external secret.
  Managed scopes use the versioned strict BLOB format with required matching
  provenance. Ordinary scope TEXT is unchanged. Missing/mixed provenance is
  rejected, and the old TEXT-only reader must fail closed before a grant.
- The installation initiates the authenticated outbound connection. Unary,
  SSE and WebSocket requests use ordinary API capture, scopes, policy and audit;
  controller-supplied credentials/cookies do not replace the captured local
  principal. There is no fleet-only privileged dispatcher.
- All composed revocations use one publication fence. A bounded synchronous
  final mutation enqueue under the original lease is the admission point;
  capacity/body/network/ReadIndex waits occur outside that fence. Recheck exact
  durable authority after those waits. A leader receiver resolves current
  authority from the original principal/version proof, not serialized scopes.
- Revoke durably publishes `Revoked` and fences old channels, queued requests and
  new final admissions before acknowledging success. Preserve the certificate's
  enrollment epoch on revoke; only a new enrollment advances it. Active phase,
  request identity and control revision also participate in admission, so a
  delayed old reply cannot reactivate a revoked request. A specifically owned,
  already-admitted revoke may finish its durable completion, not issue new
  authority. Already-admitted effects may finish; revocation is not global undo.

## Alternatives

- Incoming fleet ports or a second control framework: unnecessary reachability
  and authorization surfaces.
- Requiring a manually provisioned client key/certificate for normal bootstrap:
  excludes the one-time enrollment workflow without improving local custody.
- Controller-issued local scopes, a cached Caller, or audit issuer/action text as
  authority: bypasses current ordinary policy and revocation.
- Incrementing the certificate-bound epoch on revoke: invalidates the retained
  certificate's own binding and makes a valid Active → Revoked transition fail.

## Consequences

The local CLI/API remains useful when the controller is unavailable. Rotation,
restart, recovery and revocation are explicit durable transitions. A private
controller fixture is evidence tooling, not a commercial controller product.

`scripts/e2e-fleet.py` exercises a supplied real binary with private internal
Docker LAN/router/WAN networks and actual SNAT, no published ports. The native
scenario passed enrollment, wrong-CA and wrong-binding rejection, lost reply,
restart, revoke/re-enroll, scope parity, ignored higher remote credentials and
native SSE/WebSocket traffic. This source/native proof is not an external audit
or proof of the complete member/leader final-admission path; that path requires
its own real race evidence before a whole M29 acceptance claim.

An earlier narrow native byte-body/B6 cohort independently rebuilt Proto and Core
and exercised original enqueue/EOF ownership, seeded leaf/CSR custody, pinned
mutual TLS, protected filesystem transitions and standard WebSocket traffic.
Default Core and the separate maintained SDK also built for `wasm32-wasip2`;
their normal/build graphs excluded host identity crypto and native entropy
packages. This does not remove Core's existing `blake3` C build helper.

WebSocket terminal reads retain the existing house sticky-close behavior under
the same read mutex. A valid protocol close stays EOF; an actual TLS truncation
before protocol close remains an error. Both boundaries were exercised over
real mutual TLS. These component receipts do not substitute for the combined
current fleet/ordinary-authority or real member/leader race proof.

The current Root adoption is source-only. Its buffered enrollment transport,
retained startup original, ordinary TokenStore producer and actual native API
and command-line consumers must be adopted together. No historical component
or native-product receipt establishes that newer source cohort. Concrete Member
and registered-source factories remain independently required, not substituted
with a native fallback or an apparently ready empty resource.
