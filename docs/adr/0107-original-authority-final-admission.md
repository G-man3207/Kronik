# 0107. Retain original authority through final mutation enqueue

- **Status:** Accepted
- **Date:** 2026-10-31

## Context

Authentication before an awaited body, certificate reply, bounded queue or leader
forward is not final authorization. Revocation must fence the final enqueue, not
merely cancel an HTTP waiter. Independent token/session/fleet/leader admission
locks would introduce a check-then-enqueue race or deadlock.

## Decision

Use the existing narrow `kronik_core::authority::Authority` and `AuthLease` for
one already-authenticated operation. The issuer captures its exact ordinary
principal, scope and configuration/projection identity. A lease is ephemeral;
it is not serialized into Audit, restored from history, refreshed to a newer
principal or inferred from routing metadata. Jobs retain the original lease.

`check()` and sticky `cancelled()` support early denial and bounded waits.
`admit(effect)` rechecks the original authority and invokes `effect` exactly once
on success, never on denial, under **the same physical publication fence** used
by token, session, fleet, configuration and metadata revocation. The callback may
only perform bounded synchronous final enqueue. It must not wait, do I/O or
acquire another authentication fence. Capacity/ReadIndex/body/secret waits occur
outside that fence and retain sticky cancellation.

The publication fence of the secret snapshot is the secret cache's mutex.
`SecretSnapshotPublication::with_current_publication` takes it with a small
constant number of attempts (about a millisecond) before it denies the
publication for contention. That is not a wait in the sense above: it does
not wait for a certificate, for I/O or for another authority. Every holder of
the mutex runs a short synchronous section that takes no authentication fence,
does no I/O and keeps the guard across no await, so it lets go without waiting
for the publication. A single attempt denied the publication whenever another
thread happened to hold the mutex, and a fork replay with a model configured
answered a spurious 503 `SECRET_UNAVAILABLE` under load. A certificate that is
no longer current is still denied at once.

TokenStore binds its publication domain and original physical execution before
any issuer starts; binding is not an optional production default. Lock order is
publication, bounded live/session/fleet projection data, final enqueue. Native
token storage may retain its database lock while publishing a completed storage
mutation, but admission never takes that database lock and never performs SQL
under publication. A caller composing session or role guards enters only the
outer shared fence and calls inner `check`, not nested `admit`. Every publisher
of the corresponding revocation must use that same domain. Raft publication must
not invert its group mutex with this domain; asynchronous ReadIndex precedes
admission, then exact durable principal/epoch is rechecked before final enqueue.

For local audit mutations, `Node::record_audit_event_authorized` carries the
original lease to the real Log's final bounded enqueue. The permit wait is
outside the fence. Storage and authorization failures stay distinct. The old
unrestricted user-facing audit path is removed. Actual internal SystemAudit
entrypoints have fixed trusted categories; `audit.token_id`, action strings or
free detail maps do not confer system authority.

A stopped native writer/execution publishes conservative denial through the
same domain. Physical execution is held by the actual registered job/runtime,
not a cloned Node or a replacement lease. The owned completion holds necessary
serialization through actual durable apply after the enqueueing waiter leaves.
Enrollment and webhook HTTP use the same canonical `Net::http_authorized`.
Connection/pool/sender-ready waits precede final admission of the exact prepared
request through Hyper's synchronous `try_send_request`, not a lazy client future.
A bounded owned Env completion keeps the original operation through response or
timeout; spawning that task is not an authorization grant.

Fleet enrollment retains the original ordinary operator authority across its
own Pending/Requested continuation and controller certificate body wait. An
exact pending request receipt is an additional guard, not a replacement admin
principal. Other revocation or supersession cancels that original operation;
it cannot refresh to a new token or fleet epoch. Only exact already-admitted
self-revoke cleanup may finish from its durable Revoked receipt. A late old
controller reply cannot reactivate a superseded or revoked installation.

Forwarded requests carry only the stable original principal/version context.
The receiver looks up actual durable authority, rather than trusting serialized
scopes or converting an old lease into a current one. An unrelated newer
metadata index may satisfy a lower-bound ReadIndex barrier, but exact token,
auth-config, session, managed-fleet, peer-boot and role guards still apply.
Unmanaged-token absence of fleet provenance is a typed durable fact; a zero
fleet revision is not an escape for a managed token.

A member's stale follower-local publication fence is not global admission.
Prepare the full bounded immutable command/frame, destination, payload binding
and correlation outside the current metadata leader's original fence. A bounded
owned producer retains that same captured leader term/boot and performs a new,
unique SafeReadIndex after the actual handoff; it waits for the durable
authorization projection to reach that exact new index, then checks the full
original principal/config/fleet/session and command-specific custody, erasure
and source guards before the first external effect. Role/read failure produces
no effect and no background retarget/retry. An older read barrier is insufficient.

Fleet enrollment's required `PreparedEnrollment::dispatch_with_admission`
callback runs inside the already-owned, bounded 30-second HTTP job. That job
already holds the entire immutable request, destination, scoped TLS/pin,
payload binding, original authority and single capacity permit. The actual
Meta-fenced sealed-command handoff followed by the new ReadIndex and full
original guards logically admits **that exact owned job**. Only then does the
same job perform canonical HTTP connection/readiness, synchronous enqueue and
bounded response-body EOF. Those later waits complete already-admitted work;
they do not authorize a different job or a newly chosen credential or payload.
The required `FnOnce` callback cannot return permission to another caller. Its
returned hold owns resources only and remains inside the job through EOF or
timeout. Spawning the job alone grants nothing. No additional origin-specific
Core-ready transport framework is required for this ownership boundary.

Opening a fleet WSS channel is also an external operation, not a free prelude
to command authorization. `PreparedControl::dispatch_with_admission` has no
default dispatcher. Its required factory runs inside the bounded owned job
holding the exact request, destination, scoped TLS/key version, hashes, original
authority, epoch guard and opening permit. Native dispatch first records the
ordinary durable `fleet.control.open` intent with that original operation; the
intent is not authority. Final `original.admit` rechecks the live guard and moves
the whole non-cloneable command into a private ready carrier. Only that carrier
may perform TLS/WebSocket I/O outside the fence. The final synchronous admission
callback neither allocates a replacement command nor waits, performs I/O or takes
another admission fence; the awaited audit factory runs before that callback.
Member dispatch additionally requires the exact sealed handoff and subsequent
unique ReadIndex described above; a native intent is not a Member substitute.
Opening capacity ends when the attempt completes, not when a long-lived channel
closes. A late admitted connection may finish once but cannot serve after its
original authority is cancelled. No opening grants permission to future unknown
commands: each ordinary API request retains its own captured authority.

The Member history-only Meta26 cause reuses the actual ordinary Record40
`fleet.control.open`: configured installation target, empty details, no operation
or native-origin payload, and the original bounded Audit. It does not repeat
epoch, request or pin fields in a free map, advance Fleet state/revision, or grant
authority. The named producer validates those bindings from the immutable
`PreparedControl` and current durable Active state at `propose_authorized`, then
awaits the real cause receipt before the existing owned handoff/ReadIndex flow.
`validate_fleet_control_open_event` validates data only. The shared
`fleet_control_tls_version` retains the existing length-framed SHA-256 version;
it neither validates certificate trust nor creates a new key purpose or root.

This uses the existing authenticated ForwardApi/PeerNet continuation, not a new
service, serialized lease or user-selectable bypass flag. Private enrollment
credentials and keys remain origin-owned. A stream does not pregrant unknown
future frames: each exact candidate needs its own current-leader producer check
after data awaits. Publishing Active state or a new token still requires fresh
admission of the same original operation. A known durable receipt completes
only its exact already-admitted mutation/self-revoke, not a new grant.

## Alternatives

- Check, await, mutate: revocation can occur between the check and enqueue.
- Nested token/session/fleet/leader admission: independent locks are neither an
  atomic authority check nor a safe lock order.
- Reauthenticate or infer system authority from Audit/history: upgrades a stale
  operation and treats spoofable data as a capability.
- Cancel the waiter and drop an admitted job: loses the real durability boundary
  and can report a denial despite an uncontrolled mutation still in flight.

## Consequences

After revocation publishes, no new mutation may be admitted under that old
context. Already-admitted effects can finish; this is not instantaneous global
rollback. ACK for revoke still requires the durable record and published
projection. A crash reconciles that exact durable operation, not a fresh grant.

Real local Log tests exercise a blocked permit followed by revoke and distinct
following records, and an already-admitted record completing after revoke.
A genuine native test couples a real TLS controller, ordinary TokenStore/API
revocation and the actual Node/WAL: capacity-held Requested sends no connection
after revoke ACK; a fresh authorized request succeeds; an already-received POST
may finish its admitted reply but creates no later Active record or usable
pending bearer, while a distinct following record remains. Actual HTTP tests
also cover revocation after MAC resolution and owned admitted completion.
These do not establish the full member final-Raft/leader-forwarding contract;
that requires its actual source and real member race acceptance, not a mocked
forwarder or a passing native-only producer.

Member race acceptance must distinguish real handoff milestones: revoke ACK
before the Meta-owned command handoff permits zero HTTP effects; the exact job
admitted before a later revoke may finish once, including TLS/body waits, but
must not publish Active authority; a stale origin starting a new job after the
other members acknowledge revocation must fail its new quorum proof with zero
HTTP effects. Native evidence is not evidence for these three-member races.
