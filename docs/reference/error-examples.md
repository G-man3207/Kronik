# Error scenario examples

The [generated catalog](../errors.md) defines each stable code, HTTP status,
meaning and detailed remediation. These are **illustrative fixture scenarios**,
not claims that every failure was induced. Commands assume an
owned installation, the stated precondition and the appropriate scoped token;
replace example ids with real fixture ids. Do not induce faults in production,
change shared host settings, or pass actual credentials in argv to reproduce an
example. A corrected prerequisite, not suppression of the error, is the fix.

## ACTOR_NOT_FOUND

Inspect an actor that has never run. Deploy the kind and send its first input,
or select an existing key from `actors list`.

```sh
kronik actors inspect counter/not-created
```

## APPROVAL_REQUIRED

Promote an evaluated fixture proposal whose policy requires approval but which
has no approval for its current diff. Have an authorized human review/approve
that diff before retrying; a request for approval is not approval itself.

```sh
kronik promote p-0123456789ab --reason "promote the reviewed fixture change"
```

## AUDIT_RANGE_GONE

Read an audit range older than the fixture's actual first retained LSN. Start
at the authoritative retained position named by the error; do not manufacture
missing history from a sink copy.

```sh
kronik audit show --from 1
```

## BAD_REQUEST

A management request with truncated JSON is malformed, independent of the
actor's business logic. Correct the JSON/field named in the response.

```http
PUT /v1/secrets/fixture-key HTTP/1.1
Host: fixture-management
Content-Type: application/json
Content-Length: 8

{"text":
```

## CAPABILITY_NOT_GRANTED

An actor calls an ungranted HTTP host or secret. Review the requested authority
and add only the needed fixture grant; the manifest's request grants nothing.

```sh
kronik grant counter secret:fixture-key --reason "allow the fixture HMAC key"
```

## DEAD_LETTER_ALREADY_RESENT

Attempt a second resend of a dead letter that already names its `resent_as`
turn. Inspect that turn instead of creating another duplicate operation.

```sh
kronik dead-letters resend main:42 --reason "retry the fixture after repair"
```

## DEAD_LETTER_NOT_FOUND

Resend a nonexistent fixture dead-letter id. Select the actual retained id
from the list rather than guessing a turn position.

```sh
kronik dead-letters list
```

## DEPLOYMENT_NOT_FOUND

Request rollback of an epoch absent from the installation. Read its actual
deployment history before selecting a rollback target.

```sh
kronik deployments list
```

## EFFECT_OUTCOME_UNKNOWN

An unsafe fixture effect was admitted before a crash, but no result was
recorded. Inspect its target's actual outcome before authorizing any resend;
absence of a receipt does not mean the effect did not happen.

```sh
kronik dead-letters list
```

## ENGINE_UPGRADE_DIVERGED

The candidate's replay changes a recorded response/effect/state. Keep the old
binary and inspect the saved diff; never rewrite historical engine identities.

```sh
kronik upgrade check --data-dir /owned/fixture/data --config /owned/fixture/kronik.toml --workers 2
```

## ENGINE_VERSION_MISMATCH

Start a different engine against existing fixture data without its exact
passing upgrade report. Run the candidate's real upgrade check first.

```sh
kronik serve --config /owned/fixture/kronik.toml
```

## EXPORT_NOT_CONFIGURED

Rewind an audit stream that is disabled in the owned configuration. Inspect
export status, then deliberately configure/restart the stream if required.

```sh
kronik export status
```

## FOREIGN_EXISTS

Add a fixture foreign name that is already declared. Inspect the existing
identity/configuration before deliberately removing or replacing it.

```sh
kronik foreign list
```

## FOREIGN_NOT_FOUND

Read logs for a name that is not declared. Use the actual name reported by the
foreign list; it is not necessarily the OCI image name.

```sh
kronik foreign logs not-declared --tail 20
```

## FOREIGN_UNAVAILABLE

A declared fixture process is in backoff or cannot be reached. Inspect its
actual runtime log and repair the fixture's application/image configuration.

```sh
kronik foreign logs echo --tail 20
```

## FORK_NOT_FOUND

Replay a deleted or unknown fixture fork. Create/select a current fork; forks
and proposal diffs are not restored merely by restoring the main log.

```sh
kronik fork list
```

## FUEL_EXHAUSTED

A fixture handler exceeds its turn fuel budget. Remove the excessive work or
explicitly review an appropriate per-kind limit; do not turn a failed turn
into a committed result.

```sh
kronik limits show --kind counter
```

## GATEWAY_TIMEOUT

An admitted fixture turn outlives the gateway's wait. The turn can still
commit; retry with the same ingress idempotency key and identical input.

```http
POST /counter/a/increment HTTP/1.1
Host: fixture
Idempotency-Key: fixture-retry-1
Content-Length: 0
```

## IDEMPOTENCY_IN_FLIGHT

Repeat a fixture idempotency key while its original turn remains in flight.
Wait for that actual outcome and retry the same input, not a fresh key.

```http
POST /counter/a/increment HTTP/1.1
Host: fixture
Idempotency-Key: fixture-in-flight-1
Content-Length: 0
```

## IDEMPOTENCY_KEY_REUSED

Reuse an accepted key for different input bytes. A distinct operation needs
its own key; changing the key is not permission to duplicate an uncertain one.

```http
POST /counter/a/increment HTTP/1.1
Host: fixture
Idempotency-Key: fixture-already-used-for-other-input
Content-Length: 7

changed
```

## IMAGE_INVALID

A fixture OCI archive has invalid metadata, content digest or paths. Rebuild
and validate the actual pinned image; do not disable archive checks.

```sh
kronik foreign add echo --image oci-layout:/owned/fixture/invalid.oci --port 8080 --reason "inspect the owned fixture image" --dry-run
```

## IMPORT_NOT_ALLOWED

A component requests an import outside the allowed actor/deterministic WASI
surface. Build for a supported interface; do not broaden the host allowlist
merely to accept arbitrary imports.

```sh
kronik deploy /owned/fixture/unsupported-import.wasm --reason "validate fixture imports" --dry-run
```

## INTERNAL

The fixture encounters an unexpected implementation failure rather than bad
input. Preserve its version, request and diagnostics, and report the defect;
repeatedly changing the input is not proof that the server was repaired.

```sh
kronik history counter/a --limit 10
```

## KEYSTORE_INCOMPLETE

A restored fixture has sealed values but lacks a required subject key. Supply
the correct shipped keystore/key authority; do not use a destructive missing-key
option as routine recovery.

```sh
kronik integrity
```

## KEY_PROTECTION_UNAVAILABLE

The OS refuses the configured key mapping's required memory protection. Repair
the owned service's supported resource/privilege prerequisites; do not silently
fall back to unprotected key buffers.

```sh
kronik serve --config /owned/fixture/kronik.toml
```

## KEY_SOURCE_UNAVAILABLE

The already configured fixture KMS cannot unwrap/rewrap within its deadline.
Restore actual provider availability/authority and retry; do not generate a
replacement seed over the existing encrypted stores.

```sh
kronik keys rewrap --reason "rewrap the owned fixture after provider repair"
```

## KVM_UNAVAILABLE

An owned foreign fixture explicitly requires KVM on a host without usable KVM.
Select an actually supported isolation backend; do not relabel systrap as KVM.

```sh
kronik doctor --config /owned/fixture/kvm-required.toml
```

## MASTER_KEY_MISMATCH

A fixture restore is supplied the wrong separate master-key material. Keep the
source/target intact and obtain the correct key; rewrap is not seed replacement.

```sh
kronik restore --from file:///owned/fixture/shipped --config /owned/fixture/recovery.toml --data-dir /owned/fixture/restored
```

## MASTER_KEY_MISSING

Existing encrypted fixture stores have no usable original key. Restore that
key through its approved source; never create a new master file over the stores.

```sh
kronik serve --config /owned/fixture/missing-key.toml
```

## NOTHING_TO_PROPOSE

Every submitted fixture component already runs at the relevant deployment
points. Keep using the current code or make an actual change before proposing.

```sh
kronik propose dist/counter.wasm --reason "evaluate the fixture change"
```

## NOT_IMPLEMENTED

An unsupported management route has no implementation in this binary. Consult
the running OpenAPI document instead of assuming a future milestone endpoint.

```http
GET /v1/unsupported-route HTTP/1.1
Host: kronik
```

## PAYLOAD_TOO_LARGE

The owned fixture sends a body beyond the configured ingress limit. Split or
reduce the legitimate input according to the actual interface; do not remove
the limit to conceal an invalid request.

```sh
curl --data-binary @/owned/fixture/over-limit.bin http://127.0.0.1:47813/counter/a/increment
```

## POLICY_DENIED

Promote a fixture proposal whose evaluated policy outcome is deny. Read/fix the
introduced behavior and propose again; an approval does not override deny.

```sh
kronik diff show p-0123456789ab --summary
```

## PREVIEW_FULL

A preview has consumed its allocated request/turn budget. Inspect its status
and create an intentionally budgeted replacement rather than bypassing limits.

```sh
kronik preview list
```

## PREVIEW_LIMIT

The fixture installation already has the allowed number of previews. Delete
an actual unneeded preview before allocating another.

```sh
kronik preview list
```

## PREVIEW_NOT_FOUND

Read a deleted/expired fixture preview id. Select a current one or create a
new preview from the actual proposal.

```sh
kronik preview list
```

## PROPOSAL_NOT_FOUND

Inspect a nonexistent or non-restored proposal. Select an actual proposal on
this installation; restoring main history does not restore proposal files.

```sh
kronik proposals list
```

## PROPOSAL_RUNNING

Read a final diff while a fixture's asynchronous proposal is still replaying.
Wait for that actual job to finish and inspect its final status.

```sh
kronik proposal wait p-0123456789ab --timeout 30s
```

## PROPOSAL_STALE

Main's relevant code/configuration changed after the fixture proposal was
made. Create a fresh proposal against the actual current history/code.

```sh
kronik propose dist/counter.wasm --reason "re-evaluate the fixture against current main"
```

## REASON_REQUIRED

Send a mutating API request without its required nonblank reason. Supply the
actual purpose, not a secret value, in the corrected request.

```http
POST /v1/snapshots HTTP/1.1
Host: fixture-management
Content-Type: application/json
Content-Length: 2

{}
```

## REPLAY_DIVERGED

A re-run requests an effect unlike its recorded request. Inspect the actual
recorded input/effect and code identity; never return a fake recorded success.

```sh
kronik history counter/a --limit 10
```

## ROLLBACK_SCHEMA_CHANGED

A fixture deployment changed state schema, so ordinary rollback cannot restore
its old state semantics. Evaluate an actual rollback-by-replay proposal.

```sh
kronik rollback 3 --by-replay --reason "evaluate the fixture schema rollback"
```

## ROUTE_CONFLICT

A new component declares a route already owned by another kind. Give it a
nonconflicting route or deliberately migrate the complete affected system.

```sh
kronik deploy /owned/fixture/conflicting-route.wasm --reason "validate fixture routes" --dry-run
```

## ROUTE_NOT_FOUND

Call a public actor path no deployed manifest serves. Check actual deployed
routes rather than treating the gateway as the management API.

```http
GET /not-a-deployed-route HTTP/1.1
Host: fixture
```

## RUNC_MISSING

An owned fixture selected the trusted/runc backend without its required runtime.
Install/provision the supported runtime through the operator's normal process;
this is not evidence that a different sandbox backend was exercised.

```sh
kronik doctor --config /owned/fixture/trusted-runtime.toml
```

## RUNSC_MISSING

The owned foreign fixture lacks the required usable runsc. Inspect the actual
runtime prerequisite rather than declaring the Wasm-only control sufficient.

```sh
kronik doctor --config /owned/fixture/kronik.toml
```

## SCOPE_MISSING

An agent's read/fork/propose token attempts a human-only operation. Hand the
reviewed command to a properly authorized person; do not broaden agent scopes
just to make the same request pass.

```sh
kronik promote p-0123456789ab --reason "promote the reviewed fixture proposal"
```

## SECRET_NOT_FOUND

A fixture effect names a secret that was never set or is no longer available
under that name/version. Provision the intended key through stdin, not argv.

```sh
printf '%s' 'fixture-only-value' | kronik secret set fixture-key --reason "provision the owned fixture key"
```

## SECRET_UNAVAILABLE

An operation cannot obtain the complete required retained-value inventory.
Restore that actual prerequisite; do not interpret an unavailable catalogue as
empty or substitute current values for historical references. After a
restart this includes a recorded version that the provider no longer serves,
until it serves the version again; that is a known defect (see the operations
guide). An effect that cannot get its secret fails with this code inside its
turn, and the guest decides what the turn does; the request is not answered
503.

```sh
kronik audit show --from 1
```

## STORAGE_CORRUPT

A fixture log/store fails its integrity checks. Preserve evidence and restore
from a verified recovery point; never edit committed log bytes to hide damage.

```sh
kronik integrity
```

## SUBJECT_ERASED

An operation needs a subject key already erased by the installation's policy.
Do not recreate that identity's old key or silently reintroduce erased data.

```sh
kronik privacy status
```

## TOKEN_NOT_FOUND

Revoke a name that was never created in this installation. Inspect the actual
names (not bearer bytes or token attribution strings) before choosing one.

```sh
kronik token list
```

## TURN_FAILED

A fixture handler returns a rejection/failure or traps. Inspect its actual
outcome and causal history; failed writes/messages must not be published.

```sh
kronik history counter/a --limit 10
```

## TURN_NOT_FOUND

Trace a validly formatted branch/LSN id absent from the fixture's retained log.
Select an actual id from history and respect retention boundaries.

```sh
kronik trace main:999999
```

## UNAUTHENTICATED

Send a protected management request without a valid bearer over TCP, or with a
revoked dummy bearer. Obtain the correct scoped token; local socket authority
is not permission to bypass remote authentication.

```http
GET /v1/actors HTTP/1.1
Host: fixture-management
Authorization: Bearer fixture-revoked-value
```

## UNAVAILABLE

The fixture node stopped admitting work after a storage/availability failure.
Repair the actual prerequisite before retrying with the original idempotency
key; an arbitrary sleep is not proof of recovery.

```sh
kronik doctor --config /owned/fixture/kronik.toml
```

## VERIFY_REQUIRED

Deploy code directly to a kind with history. Use proposal/replay/policy instead
of bypassing the existing application's verification path.

```sh
kronik propose dist/counter.wasm --reason "verify the change against fixture history"
```

## WATCH_NOT_FOUND

Inspect an unknown fixture watch id. Select an actual watch from this
installation rather than a deployment epoch or proposal id.

```sh
kronik watches list
```

## M23 source-contract additions

These six codes follow the current authoritative error catalog. They
are not claims that the `d9b946f2` proof binary or published v0.3.0 implements
the new source, nor that these failures were induced here. The M23 CLI
commands and backend setup require the integrated artifact described in the
[CLI](cli.md) and [API examples](api-examples.md). Final error-catalog
generation and actual help/remediation checks must use that artifact.

## KEY_HELPER_FAILED

An owned fixture's configured PKCS#11 helper cannot complete: inspect its
reported failure class, trusted module digest, private PIN credential and
enrolled token/key identity through the approved operator procedure.
Restore that exact prerequisite; never create a fallback master key or put
the PIN in argv, logs or an example report. `kronik keys enroll` re-verifies
the configured helper, module and possession probe offline, without loading
or changing the master seed; `kronik keys status` reports the loaded source.

```sh
kronik keys enroll --config /owned/fixture/pkcs11.toml
kronik keys status
```

## SECRET_BACKEND_UNKNOWN

A link names a backend ID absent from the local configuration. List the
actual configured IDs, then choose the intended one or have an administrator
configure it explicitly. A typed provider name is not implicit permission to
create a new source.

```sh
kronik --socket /owned/fixture/api.sock secret backends
```

## SECRET_EXTERNAL

A built-in value mutation targets a name linked to an external manager.
Change that provider's value through its separately approved procedure;
then preview a refresh of the actual existing fixture link. This preview
does not claim a committed rotation or alter historical version identities.

```sh
kronik --socket /owned/fixture/api.sock secret refresh demo-api-key \
  --reason "preview separately approved provider change" --dry-run
```

A foreign actor meets the same code when it needs a linked name: the
built-in store holds an older value of it or none, so `foreign add --secret`
refuses it, and so does the next start of an actor declared before the link.
Bind a name that Kronik stores itself.

```sh
kronik foreign add echo --image oci-layout:/owned/fixture/echo.oci --port 8080 --secret API_KEY=fixture-key --reason "bind a name that is stored in Kronik" --dry-run
```

## SECRET_REF_NOT_ALLOWED

A fixture link requests a reference outside the configured backend prefixes.
This request illustrates the rejected boundary, not a way around it. Use a
permitted reference or have an administrator deliberately review the source
configuration; do not broaden `allowed_refs` merely to hide a failure.

```http
PUT /v1/secrets/demo-api-key/link HTTP/1.1
Host: kronik
Content-Type: application/json

{"backend":"demo-env","ref":"UNAPPROVED_EXAMPLE","reason":"inspect owned fixture rejection","dry_run":true}
```

## SECRET_VERSION_EXHAUSTED

The durable version domain for this name has no next usable identity.
Inspect its real history and arrange a reviewed new logical name and binding.
Never reset, truncate or rewrite the existing version ledger, including its
wide-version representation.

```sh
kronik --socket /owned/fixture/api.sock secret history demo-api-key
```

## SECRET_VERSION_GONE

The exact recorded provider version is unavailable, for example after loss
of its immutable source version or a changed environment snapshot.
Restore access to the matching source, recorded identity and configuration;
the current provider value is not a substitute. History is diagnostic, not
permission to bypass this condition or proof that recovery succeeded.

```http
GET /v1/secrets/demo-api-key/history HTTP/1.1
Host: kronik
```

## HOST_REDACTION_FAILURE

The host cannot safely disclose recorded free effect data. A newly issued
external request may already have completed; the durable host-disclosure
failure is not a fabricated network error or an empty successful response.
Recovery consumes that failure rather than automatically issuing the request
again. A proven unsafe legacy receipt keeps its original identity; missing
keys or incomplete scrub inventory retain their normal prerequisite handling.

Inspect the failed turn and external system, then repair the reported
redaction resource or data boundary before considering a new attempt. Do not
disable matching, discard retained secret versions or resend a dead letter
without checking whether its external effect already happened.

```sh
kronik dead-letters list
```
