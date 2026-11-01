# 0103. Verified OIDC principals with ordinary scoped authority

- **Status:** Accepted
- **Date:** 2026-10-30

## Context

M27 requires browser approvals to identify an actual verified OIDC principal,
without weakening ordinary bearer/Unix authentication or the proposal/hash,
catch-up and policy checks. An email, display name, unsigned JWT or special
privileged UI dispatcher does not establish that identity. I5, I6, I8 and I12
still apply. A browser session is authentication, not an additional permission.

## Decision
This representation is the parent's engineering choice under the M27 task.
Acceptance of this ADR is not evidence that a human reviewed the product or
explicitly approved a representation or invariant change.


Use the standard authorization-code flow with S256 PKCE. The operator fixes
one HTTPS issuer, public client ID and exact HTTPS admin callback URI. Discovery
must report that exact issuer; authorization, token and JWKS URLs must retain
its HTTPS authority, with no credentials, query, fragment or redirect following.
Providers whose endpoints use another authority need an explicit future reviewed
trust configuration; do not follow a token-provided issuer, `jku`, `jwk`, `x5u`
or certificate chain. TLS uses a separately scoped existing `Env::Net` client;
provider CA roots never enter the guest effect client.

A single-use random state is bound to an independent HttpOnly, Secure,
SameSite=Lax host-only login cookie. State, PKCE verifier and nonce expire after
five minutes and are consumed before exchange, including on failed callbacks.
The state table and provider payloads are bounded. Callback query parameters
cannot be duplicated. Authorization codes, verifiers, ID/access tokens and
cookies are not logged, audited, returned to JavaScript or persisted.

The maintained `jsonwebtoken` 10.4.0 parser/claim verifier has all default and
crypto features disabled. Its immutable process-wide provider is a narrow
verification-only adapter to the existing `ring` RS256 primitive, requiring
2048–8192-bit RSA public keys. There is no product signing capability or private
key. The exact feature graph contains no RSA 0.9, AWS-LC, PEM or ASN.1 dependency.
Use only configured JWKS, reject duplicate key IDs, unsupported/ambiguous key
usage or algorithms, and require the exact issuer, subject, audience, expiry,
issued-at and flow nonce. `nbf` is checked when present; `azp` must match when
present and is required for multiple audiences. NumericDate checks use the
existing Env clock, not an independent global clock. The JWT `scope` and role
claims grant nothing.

An explicit trusted mapping associates the exact verified issuer and subject
with an existing ordinary token name. Missing bindings and missing/revoked
tokens deny access. Every session admission reads that token's live scopes.
All OIDC `Caller.token_id`, audit origins and public approval identifiers are
`oidc:<lowercase protected-binding-HMAC hex>`, using the existing Sealer
`kronik oidc binding v1` domain and length-prefixed issuer/subject inputs.
This is a stable opaque cryptographic identifier, not a mathematically
collision-free encoding. Base64 does not protect PII and is not an identity
representation.

Before provider I/O, a private operation authority retains the already-bound
original physical boot (not a pre-JWT session) and exact pending/profile/runtime
epoch. It delegates original admission once and checks only bounded auth state
inside that same fence. A configuration's provider preflight retains the
original administrator before the configuration's own epoch denial; its
already-admitted exact completion publishes only the prepared provider for the
actual durable source. Provider failure remains inactive/503 without replacing
the durable profile or disabling ordinary token/Unix recovery. Dry runs do not
perform provider preflight. The provider uses the actual current Root
`Net::http_authorized` transport with that same authority through final enqueue
and response EOF, never a new current lease. This requires the coupled current
Root transport source; it is not a claim about the older frozen transport.

An actual OIDC approval additionally carries optional
`Approval.verified_identity` field 7. Its existing `Sealable` subject is that
exact opaque principal; its authenticated payload is bounded canonical UTF-8
JSON containing exactly the verified issuer and subject. The host captures
the original verified session, protected payload and original authority before
body I/O. Native/bearer approvals leave the field absent and retain their old
bytes; request bodies and headers cannot supply identity authority.

Use the already loaded per-subject keystore and forced existing sealing path,
even with Actor privacy mode off. No plaintext fallback, new root-key purpose,
identity service or key reload is permitted. The host authenticates the stored
payload and recomputes the pair's protected binding against its owner and
opaque audit identity. Only `pii:read` reveals the historical stored pair;
other readers receive opaque/redacted identity. Erased keys produce `ERASED`;
unknown or unreadable keys fail closed. A current session is not evidence for
a historical approval. Shared visitors cover sealing, erasure, resealing,
snapshot key inventory and restore. The sole M28 logical hash retains the
field's presence and owner but clears its value, as for every `Sealable`.

Only an opaque random credential reaches the HttpOnly, Secure, SameSite=Lax
host-only session cookie. Sessions live only in private daemon memory, expire
no later than their verified ID token or one hour, and die on restart/logout.
Cookies are hostname-scoped, not port-scoped: deployment requires a dedicated
trusted admin hostname. The gateway strips the two reserved administrator
cookies before guest input/WAL admission and filters guest Set-Cookie attempts
for those names, without removing ordinary app cookies or Authorization.
This does not isolate unrelated untrusted services sharing the admin hostname.

Credential routing uses the complete canonical 32-byte base64url session
shape, not its `kronik_ui_` prefix: a valid 50-byte ordinary bearer can share
that prefix, while a genuine session is 53 bytes. An absent, revoked or invalid
session matching that whole shape is denied, never retried as an ordinary
token. A bearer placed in a session cookie does not acquire session authority.

Cookie-authenticated writes require both an exact configured Origin and the
session-specific `X-Kronik-CSRF` token. Explicit bearer callers keep existing
CLI behavior and do not inherit browser CSRF checks. Credentials and live
scopes are checked again after body I/O. Queued operations use the common
ordinary operation/job authority lease: logout/session expiry and token revoke
fence final admission; they do not retroactively undo admitted effects.

Native startup binds the ordinary TokenStore to the Node's exact physical
publication domain and original Log-issued execution capability before creating
authentication issuers or exposing listeners. An unbound or stopped execution
cannot issue or admit bearer, Unix, or browser authority. Session checks are
pure under that one domain; they never reacquire its publication mutex.

The callback captures the original ordinary token binding and creates only a
private unpublished session capability, not an active browser entry. Native
`record_oidc_login` prepares actual local key custody under owned admission and
returns its durable source with the same opaque prepared plan on that callback
stack. No native receipt-to-version ledger, latest-key lookup or restart
continuation is introduced. The actual held key protects the original pair;
the KS mutex and IMMEDIATE transaction authenticate its floor/envelope outside
publication, then remain held through crypto and one original admission's pure
bounded session insertion. Publication ends before transaction rollback/drop.
No KS transaction spans the login log ACK. The bounded insertion rejects a
closed pending-session latch under the same state mutex; cancellation publishes
no cookie and cleans the pending entry.
Preparation, final KS verification, crypto and post-admission guard checks run
through the existing `Env::blocking` worker, not on Tokio async workers or as
disk I/O inside the publication fence.

An authenticated session-info request captures its ordinary binding before body
I/O without inventing a Read grant. Its protected identity comes from that same
capture, never a fresh post-body caller lookup. Native response admission uses
the existing owned `Node::authorized_effect` queue with the original full
authority and the complete immutable body, headers and cookies. Callback
cleanup remains armed through this final candidate acknowledgement; only then
may it release the private pending session. The exact already-admitted logout
completion is separate because its own durable revocation closes its session.

AuditEvent operation 9 is history only: `auth.oidc.login`, empty target/details,
opaque bound origin and the original principal/configuration/token fields.
It stores neither a key version nor issuer boot/session authority. The current
original capability supplies those guards; a source is only a snapshot cut.
This native callback contract requires the actual coupled Root holder cohort;
older compiled-byte evidence does not prove it.

The physical member uses its metadata receipt producer and the existing
authenticated peer router's private `ForwardApi` field 10,
`OidcLoginMetadata { Audit = 1 }`.
Ordinary method/path/body/query are empty, with no shard or ordinary identity.
The receiver resolves the actual original OIDC proof, current metadata image
and original peer execution context; the host derives operation 9 and returns
the actual metadata receipt even on a control-only member with zero shards.
No callback code, cookie, issuer/subject payload or public endpoint is added.

The original token row/hash and member context are captured before identity
sealing/provider-adjacent waits, never resolved anew afterward. A native-to-member
transition retires the native browser authenticator under the same publication
domain. A fresh member browser uses the actual `for_member` TokenStore and
shared loaded Sealer; the admin host resolves the current browser per request.
An inactive provider leaves ordinary authorized administration available, not
the retired native session or a metadata-to-native fallback.

Audit kind 40 uses the shared `AuditEvent.operation` oneof: fields 5/6 belong
to FleetState/InstallationIdentity and field 7 is AuthConfig. Its versioned,
bounded public profile records issuer, client ID, callback URI, trust-root
fingerprints, fixed flow/session limits, and ordinary token-name bindings
identified by protected keyed issuer/subject hashes. Raw subjects, person
claims, tokens, credentials and whole JSON are not control metadata. The
digest is BLAKE3 of canonical typed protobuf with digest/prior digest cleared;
the prior digest is absent only for an actually absent bootstrap record.
Existing Sealer protected hashing supplies binding identities; no new root-key
purpose is created and an unavailable key fails closed.

Normal configuration changes need ordinary admin authority, reason/dry run,
and final authorized enqueue; session denial and that enqueue share the one
token publication fence, without revoking the invoking lease before enqueue.
Local authority uses Actor SourcePos; cluster authority uses the committed
metadata index via ControlAudit metadata tag 26, not a public log kind or a
maximum per-shard LSN. Never upgrade an old queued lease. Typed projection,
live publication and actual cluster evidence remain required for acceptance.

Startup reads, but never auto-admits or replaces, durable configuration.
An unreachable provider, exclusive-CA failure or valid startup-profile mismatch
leaves OIDC inactive with a sanitized 503/status reason; ordinary bearer and
verified Unix administration remain available. The existing reason/dry-run
admin configuration endpoint admits a corrected profile or explicitly
reinitializes an unchanged one. Provider I/O is outside the publication fence;
exact committed source, original admission ticket and runtime generation
prevent an old callback or completion from acquiring a new epoch. Corrupt
durable authority, missing required master keys and invalid global
configuration remain fatal as appropriate.

Self logout uses typed `AuditEvent.operation` field 8, `AuthSessionRevoked`,
not a single-current configuration family. The host derives its cookie hash,
principal binding, profile digest and source only from the original private
session capture. Native sessions die with their process; member revocation
uses the existing MetaGroup's durable internal tag 27 and its one publication
fence. This is not public record kind 27 or a SessionCreated ledger. Generic
configuration dispatch and ordinary native administrators cannot submit an
arbitrary session hash. Member acceptance requires actual tombstone-acknowledgment
and final-enqueue evidence, not local cookie deletion alone.

## Alternatives

- Unsigned/decoded identity headers or guest JWT-subject extraction: not OIDC
  authentication and cannot identify an approver.
- Browser-held bearer/ID tokens or localStorage: unnecessary credential exposure.
- Independent UI mutation logic: bypasses the public policy/audit boundary.
- A second crypto stack, RSA 0.9 advisory ignores, AWS-LC or hand-written JOSE:
  unnecessary dependency/security surface. The approved adapter only invokes
  maintained ring primitives; jsonwebtoken owns JOSE decoding and validation.

## Consequences

A public PKCE client needs no new stored client secret or signing key. Operators
provision scoped ordinary tokens and explicit issuer/subject bindings. Ordinary
token revocation also revokes corresponding sessions. Provider availability is
required for discovery/login, not for unrelated token-authenticated requests.
A separately owned local TLS issuer fixture exercises real authorization codes,
JWT signatures and JWKS; its dummy principals and automated browser clicks are
not evidence of an actual human review or an external security audit.
