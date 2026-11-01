# API examples and coverage

[openapi.json](openapi.json) is the authoritative declared `/v1` operation,
parameter, request/response and error-schema inventory. The
[JSON reference](json.md) maps ordinary CLI commands to the exact API operation
they consume; each has an example in the [CLI reference](cli.md). This page
covers operations without a corresponding CLI command. It does not claim
that a documentation inventory exercises every endpoint's runtime behavior.

The request examples below are HTTP/1.1 request heads/bodies, not a shell
command to send a token to the public actor gateway. Send them to the actual
management API socket or its configured TLS port. Unix-socket access without
a bearer is full local authority; TCP requires a scoped bearer. For example:

```sh
curl --unix-socket /owned/fixture/api.sock http://kronik/v1/health
```

Use only an owned fixture in a drill, and never put a real bearer in argv,
history or committed documentation.

## GET /v1/health

Observe this installation's actual engine, applied LSN and advertised gateway
address before selecting an upgrade/recovery point. This is management health,
not proof that a proposed component or a lost cluster member is safe.

```http
GET /v1/health HTTP/1.1
Host: kronik
```

## GET /v1/openapi.json

Retrieve the schemas served by the running binary before constructing a client
request. A stale source copy is not evidence of a new binary's actual surface.

```http
GET /v1/openapi.json HTTP/1.1
Host: kronik
```

## GET /v1/turns/{id}

Read the actual turn identified by branch and LSN. The response follows
[turn.schema.json](turn.schema.json), including its input/outcome/effect
projection and the caller's data visibility; it is not a mutation.

```http
GET /v1/turns/main%3A42 HTTP/1.1
Host: kronik
```

## GET /v1/foreign/{name}

Read one configured foreign actor's metadata before investigating a deployment.
This is not permission to inspect another application's container or filesystem.

```http
GET /v1/foreign/payments HTTP/1.1
Host: kronik
```

## POST /v1/proposals/{id}/request-approval

An agent can record a pending request and hand the returned exact human command
to an approver. This does not itself approve/promote the proposal or bypass
policy. Inspect the real diff first and give the observed evidence in `reason`.
Replace the illustrative proposal id with one from the actual installation.

```http
POST /v1/proposals/p-7h3k2a9c1d0e/request-approval HTTP/1.1
Host: kronik
Content-Type: application/json

{"reason":"Please review the checkout response change and unchanged exact effects before promotion."}
```

## Required surface check

```sh
python3 scripts/check-doc-surface.py --binary target/debug/kronik
```

The checker inventories the actual binary's visible and hidden CLI leaf
commands using bounded `--help` calls, actual API method/path dispatch arms,
the generated OpenAPI operations, all current Kronik WIT functions, and the
authoritative error macro's code inventory. The real API source and declared
schema must agree in both directions; parameter names may differ, but their
path positions may not. Unsupported dispatch patterns fail explicitly rather
than silently reducing coverage.

It requires a syntactically valid CLI command example; an API schema plus a
documented CLI consumer or explicit HTTP example; a WIT usage example rather
than its declaration; and each error's typical cause/remediation example.
Empty/malformed inventories and missing coverage fail. The existing generated
document/schema checks remain required: this checker does not replace them or
exercise every endpoint's runtime behavior. Final feature-owner API/WIT
integration must rerun it against the actual integrated binary and source.

## Feature-owner API additions: source contract, not checkpoint availability

The following examples match the fleet maintainers' actual request types and
dispatch sources. They are **not available in the committed `0b84ab0f`
baseline or the published v0.3.0 binary**. They apply only after that feature
is integrated, its actual binary passes runtime proof, and its generated
OpenAPI agrees. These examples do not claim M29/M30 acceptance or independently
verify the controller, streaming authority or webhook delivery.

Use a configured owned fixture. A preview is not permission to send a real
one-time enrollment credential to an example URL. For shell request examples,
the surface check reads explicit `curl --request` and `--url` arguments; URLs
inside JSON payloads are not transport targets.

## GET /v1/fleet

Inspect durable local enrollment and derived admission before attempting a
change. `configured`, `admitting`, the durable phase and a recovery hint are
different facts; an unavailable admission source must not become `ready`.

```http
GET /v1/fleet HTTP/1.1
Host: kronik
```

## POST /v1/fleet/enroll

With the fixture's trusted controller CA, installation identity and scopes
already configured, preview the plan before real enrollment. The URL is the
owned fixture controller, not a replacement for its pinned trust configuration.
This request deliberately omits the optional one-time token and uses
`dry_run`; actual enrollment requires its approved private credential flow.

```sh
curl --fail --silent --show-error --unix-socket /owned/fixture/api.sock \
  --request POST --url http://kronik/v1/fleet/enroll \
  --header 'Content-Type: application/json' \
  --data-binary '{"url":"https://controller.example.test","reason":"preview owned fixture enrollment","dry_run":true}'
```

## POST /v1/fleet/revoke

Preview revocation of the owned fixture's fleet epoch. A preview result is
not evidence that active outbound authority was durably cancelled. Inspect
the actual subsequent status when performing a real authorized revocation.

```sh
curl --fail --silent --show-error --unix-socket /owned/fixture/api.sock \
  --request POST --url http://kronik/v1/fleet/revoke \
  --header 'Content-Type: application/json' \
  --data-binary '{"reason":"preview owned fixture fleet revocation","dry_run":true}'
```

## GET /v1/events

Read a bounded metadata-only operational page for an actual source. The
default source is `actor-native`, **not** member shard `actor-0`. Member actor
sources and the `metadata` source have separate coordinate namespaces; never
derive a global order by taking their maximum. Keep the returned `cursor`
unchanged with its installation and branch identity.

```http
GET /v1/events?source=actor-native&limit=100 HTTP/1.1
Host: kronik
```

An inventory/readiness failure is a failure, not an empty successful page.
Honor an explicit retention gap instead of claiming all earlier events remain.

## GET /v1/events/stream

Open the SSE transport without a request body. An SSE `id` is the next resume
cursor; an event's `data.id` is its replay-stable operational identity. Persist
the former for reconnect and use the latter for consumer deduplication.

```http
GET /v1/events/stream HTTP/1.1
Host: kronik
Accept: text/event-stream
Content-Length: 0
```

Resume with the actual saved cursor in `Last-Event-ID`; that standard header
takes precedence over the query cursor. Do not manufacture a cursor or treat
an already-open stream as permanent authority after revocation.

## GET /v1/events/ws

Use a real WebSocket client after a successful authenticated upgrade. This
request head uses the RFC example client nonce, not a bearer credential.
The stream carries explicit cursor/gap information and per-source ordering,
not a global total order.

```http
GET /v1/events/ws HTTP/1.1
Host: kronik
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Content-Length: 0
```

## GET /v1/events/schemas

Read the actual published registry before decoding operational event or cursor
frames. The current source identifiers are `kronik.event/v1` and
`kronik.events-cursor/v1`; a future incompatible format needs its own version.
The maintainers' `docs/reference/events.schema.json` is a separate publication
artifact, not a reason to regenerate historical event bytes.

```http
GET /v1/events/schemas HTTP/1.1
Host: kronik
```

## GET /v1/events/webhooks

Inspect the configured webhook's typed source cursor, enabled state, gap count
and stable failure code before considering replay. Successful local
inspection does not prove remote receipt or exactly-once application behavior.

```http
GET /v1/events/webhooks HTTP/1.1
Host: kronik
```

## POST /v1/events/webhooks/{name}/replay

For a configured `owned-native` fixture webhook whose actual source is
`actor-native`, obtain a real same-installation cursor and preview that
retained boundary. The page is bounded; this does not accumulate the entire
journal in memory. No delivery is asserted by this preview.

```bash
set -euo pipefail
curl --fail --silent --show-error --unix-socket /owned/fixture/api.sock \
  --request GET --url 'http://kronik/v1/events?source=actor-native&limit=1' |
  python3 -c 'import json,sys; page=json.load(sys.stdin); print(json.dumps({"cursor":page["cursor"],"reason":"preview owned retained webhook boundary","dry_run":True}))' |
  curl --fail --silent --show-error --unix-socket /owned/fixture/api.sock \
    --request POST --url http://kronik/v1/events/webhooks/owned-native/replay \
    --header 'Content-Type: application/json' --data-binary @-
```

For an earlier desired boundary, use its previously retained cursor from this
same installation/branch, not an invented actor LSN or metadata index. Validate
the actual preview, retention/gap status and authorization before choosing a
real durable rewind. Do not change event identity to hide duplicate delivery.


## M23 external-secret additions: source contract, not old-binary proof

These five examples follow the current M23 maintainers' actual API handlers and
request types. They are **not supported by the `0b84ab0f` proof binary or
published v0.3.0**. The integrated binary, regenerated OpenAPI and runtime
provider/recovery proofs must agree before these become an available contract.
Documentation parsing below is not evidence that an external provider works.

For an owned fixture only, the product configuration accepts this environment
backend definition:

```toml
[secrets.backends.demo-env]
type = "env"
allowed_refs = ["KRONIK_DEMO_API_KEY"]
```

Supply a dummy `KRONIK_DEMO_API_KEY` in that fixture daemon's environment
**before it starts**. The backend captures permitted environment values at
startup; changing a parent shell later does not update the running daemon's
snapshot. `allowed_refs` are prefixes, not an exact-name equality check.
Never use a production credential for this example.

## GET /v1/secrets/backends

Inspect actual backend IDs, kinds, bindings, `configured` and
`inventory_complete` before selecting a source. Configuration and complete
historical inventory are separate facts, not a provider health guarantee.

```http
GET /v1/secrets/backends HTTP/1.1
Host: kronik
```

## PUT /v1/secrets/{name}/link

Preview binding a logical fixture name to the explicitly configured source and
permitted reference. This admin operation requires a nonblank reason.
A successful preview does not commit a link or activate a secret version.

```http
PUT /v1/secrets/demo-api-key/link HTTP/1.1
Host: kronik
Content-Type: application/json

{"backend":"demo-env","ref":"KRONIK_DEMO_API_KEY","reason":"preview owned fixture binding","dry_run":true}
```

## POST /v1/secrets/{name}/refresh

For a separately approved, committed fixture link, preview resolving its
source. The preceding dry-run link request alone does not establish that
precondition. Inspect the actual response; a preview is not evidence that a
new version became active.

```http
POST /v1/secrets/demo-api-key/refresh HTTP/1.1
Host: kronik
Content-Type: application/json

{"reason":"preview owned fixture refresh","dry_run":true}
```

## GET /v1/secrets/{name}/history

Read recorded version identities, source identities, phase and deletion
markers. Neither a `reserved` nor a `failed` row proves an activated value.
Historical replay must retain the recorded identity rather than silently
substitute the backend's current version.

```http
GET /v1/secrets/demo-api-key/history HTTP/1.1
Host: kronik
```

## DELETE /v1/secrets/{name}/link

For an existing fixture link, preview returning the logical name to the
built-in source. This is an admin link mutation, not deletion of the remote
provider's value or proof that historical versions can be discarded.

```http
DELETE /v1/secrets/demo-api-key/link HTTP/1.1
Host: kronik
Content-Type: application/json

{"reason":"preview owned fixture unlink","dry_run":true}
```
