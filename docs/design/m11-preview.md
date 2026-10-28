# M11 preview forks

A preview lets a person try a proposal's code with new requests before it
is promoted: `kronik preview create <proposal>` gives a URL, and requests to
it run against the new code in a fork, without live effects (I7) but
`[fork] live_allowlist` GETs. A preview is a fork (no new concept, I13);
`kronik preview` is a command over forks and proposals. Decision record:
[ADR 0025](../adr/0025-preview-forks.md).

## 1. What a preview is

A plain fork named `v-<12 hex>`, with `status = "preview"` and a `preview`
object in its `branches/<id>/proposal.json`:

```json
"preview": {
  "proposal": "p-1a2b3c4d5e6f",
  "expires_ms": 1793188800000,
  "routes": [{"kind": "counter", "method": "POST", "pattern": "/counter/{key}/{op}"}]
}
```

- **Fork point**: main's HEAD when it is created. Its state is HEAD's
  state; it does not follow main afterwards.
- **Code**: the proposal's kinds, and the kinds the proposal pins as
  unchanged (M9), on top of main's code at the fork point. Its own fork,
  not the proposal's: the proposal's verified diff never sees a preview
  request.
- **Routes**: main's routes at the fork point, with the proposal's kinds'
  routes in place of theirs, kept in `proposal.json`.
- **Privacy**: `no_pii` when the proposal has it, when asked
  (`--no-pii`), or when the caller lacks `pii:read` (as for forks).
- **Stubs**: the proposal's. **Live allowlist**: `[fork] live_allowlist`.
- **Expiry**: wall time at creation plus `--ttl` or `[fork] preview_ttl`
  (24 h).

## 2. Requests

The gateway checks, at the top of `Gateway::serve` and only when a
`PreviewRouter` is set (by `kronik serve`; the simulator and the test host
set none), one of two things, depending on `[gateway] preview_domain`:

1. without it, the path `/__preview/<id>/<rest>`: preview `<id>`, path
   `/<rest>`;
2. with `preview_domain = "<domain>"`, only the `Host`: any host under
   `<domain>` (ASCII case ignored, port and one trailing dot stripped) is
   preview `<labels before the domain>`, the path unchanged. A host under
   the domain that names no live preview (`x.y.<domain>` included) answers
   `PREVIEW_NOT_FOUND`, never main. `/__preview/` is then an ordinary path
   of main.

Never both: with a preview domain, proposal code never answers on main's
origin. Through the prefix it does, so the gateway keeps only an allowlist
of the preview response's headers (content type, length, language and
disposition, cache control, expires, etag, last-modified, vary,
retry-after, the turn id; no `Set-Cookie`, HSTS, `Clear-Site-Data`,
NEL/Report-To or `Location`, which act on main's origin or redirect from
it) and adds `content-security-policy: sandbox`: the page runs in an
opaque origin and can neither read main's cookies nor send credentialed
same-origin requests to main, and runs no script or form (single-page
apps need a preview domain). The request's `Cookie` and `Authorization`
headers are dropped before the guest and the fork's log see them: on
main's origin they are main's credentials (the subject, when read from
them, is taken first). With a preview domain both reach the preview. The
config check refuses a `preview_domain` equal to or a parent of a `[tls] domains`
name (it would take main's traffic); the docs recommend a separate
registrable domain, since a sibling subdomain shares the production site's
cookies and SameSite boundary.

Preview requests are new input: the gateway refuses them like main's on a
fatal node or below `[log] disk_reserve` (`check_running`). It then asks
the router for the preview's routes (`PREVIEW_NOT_FOUND`, 404, for an
unknown or expired id), matches them with main's matching rules, builds
the `HttpInput` exactly as for main (actor key, subject from
`privacy.subject_from`, every value tagged with the subject) and hands it
to the router. The router (`impl PreviewRouter for Proposals`,
`kronik-fork/src/proposal/preview.rs`) runs it on its own task, so a client
that gives up does not cut a turn short between the fork's store and its
log; the gateway answers 504 after `[gateway] timeout`, as for main.

In the fork, the request is a new root input with causal root
`preview-<random>`, run by `Continuous::send_input` after everything the
fork ran before; its consequences run too. The turns go sealed to
`branches/<id>/log/` like any continuous turn (m3-fork §11), so `GET
/v1/turns/<id>:<lsn>` and `kronik trace` show them. The answer is the
root turn's outcome, concealed like `fork_send`'s (no real SQL rows from a
`--no-pii` preview) and scrubbed of every live secret value, then mapped
to HTTP exactly as main's (`turn_response`).

Each preview's serving state is a `Served` in a map of its own, not in the
proposals' `entries`: its expiry and routes, read under a short
`std::sync::Mutex` with no await, and its record and live state behind a
per-preview `tokio::sync::Mutex`. A request locks only its preview, for
the whole turn (including allowlisted live GETs and the log write); route
lookup, other previews and most operator commands (list, approve,
promote) never wait for it. `diff show <preview>` and `preview delete`
wait for the request in flight on that preview; `privacy erase` waits
for none. Delete and expiry mark the state gone under that
lock, so a request that was waiting answers `PREVIEW_NOT_FOUND` instead of
writing into a deleted directory.

Memory is bounded. Once a request's turns are logged they leave the
runner, except the first 20 root turns (`MAX_SAMPLES`), slimmed to what
`samples.preview` reads (causal key, method, route, outcome kind, status);
the others are only counted (`Live::preview_dropped`, added to
`summary.preview_inputs`). At most `MAX_PREVIEWS` = 16 previews live at
once; creating another answers `PREVIEW_LIMIT` (409), checked before the
replay and again under the `entries` lock where it is inserted. Each
preview state takes at most `MAX_PREVIEW_REQUESTS` = 10,000 requests, then
answers `PREVIEW_FULL` (409): every request leaves `turn_index` and
`trees` rows (and the guest's writes) in the fork's in-memory store, which
only main compacts. The count starts again when the state is rebuilt. The
gateway clears the idempotency key and request hash of preview inputs, so
the fork store keeps no `ingress_keys` row (with the response body) per
request. Measured (debug build, prefix preview, a route answering 1 MB, a
random `Idempotency-Key` per request): `kronik serve` VmRSS stayed at
262 MB from request 750 to 2,000; with the key kept it grew about 1 MB per
request (101 MB at start, 1,384 MB after 1,000).

Not done for previews: `Idempotency-Key` deduplication and parallel
requests to one preview (one request at a time per preview).

## 3. No live effects (I7)

A preview's effects go through the fork's effect gate (m3-fork §3.5): a
preview root never matches a production recording, so a fetch is answered
by a stub rule, goes out live only if it is a `GET` without secret headers
to a `[fork] live_allowlist` host, and is otherwise denied (`replay: no
recording`). Allowlisted GETs are the one thing a preview does in the
outside world. `secrets.reveal` answers the placeholder, as in every fork,
and a preview has no secret store at all (`ReplaySetup.secrets = None`):
`crypto.*` answers `no recording` instead of computing an HMAC or a
signature with a production key for whoever has the URL. Messages and
calls stay in the fork.

Timers do not fire in a preview. Its window is `(head, head]`, so a timer a
request sets has no root input to run before and is dropped, and so are
the timers pending at the fork point. Reviewers cannot preview
timer-driven behaviour; the upgrade, if they need it, is to queue a
preview's timers by due time after its current position.

The e2e test counts the requests a local server receives: zero for a
denied fetch, one for an allowlisted `GET`, none for an allowlisted
`POST`.

## 4. In the diff

`GET /v1/forks/<id>/diff` is the preview's diff (continuous mode). Preview
turns are lifted out of the comparison: `summary.preview_inputs` counts the
requests and `samples.preview` lists the first 20 as `{turn, method,
route, status, outcome}` (the others are counted, not kept, §2); they are
never divergent, never in `turns_fork`, effects, grounding or errors
(m3-fork §5.1, §5.10, §11). Their writes show in `state.continuous`. The
diff is rebuilt when it is read and requests came in since it was built,
not per request: building it loads production's state at the fork point.

## 5. Expiry and restarts

A daemon task (`preview::expire_loop`) runs at start and then every 60 s
on `env.clock`: it removes every preview whose `expires_ms` has passed, its
in-memory state and its directory. Lookups treat an expired preview as gone
at once (404, absent from `kronik preview list`), so the minute only delays
the directory's removal. Expiry is in `proposal.json`, so a preview that
expired while the daemon was down is removed at the next start.

`create_preview` replays first, in memory, then takes the `entries` lock
and, with no await in between, saves `proposal.json` and inserts the
preview; only then does it write the log and the diff. A create that stops
half-way leaves a preview that answers and expires. A `branches/v-*`
directory without `proposal.json` (a crash inside the save) is deleted at
start.

A preview's in-memory state does not survive a restart. The first request
after it starts the state again from the fork point, and writing its log
replaces the log of the requests before the restart (as for any fork,
m3-fork §11). Rebuilding the state from the log would mean running the old
requests again, with their effects; a preview is short-lived, so this is
left out. An erasure (`kronik privacy erase`) drops every preview's
in-memory state the same way: it holds the values revealed when it started,
and the next request reveals only what production still can. The erasure
only bumps a counter (`Proposals::erasures`) and waits for no preview; each
state records the count it was built at (read before its replay, so a
preview created during the erasure is caught too), and the next request,
or diff refresh, drops a state built before the latest erasure. A request
already running finishes on the old state.

A preview is not a fork to change: `deploy --fork`, `replay`, `send --fork`
(MCP `send_to_fork`) and `fork delete` refuse it with `BAD_REQUEST`, since
its code, options and log are its proposal's until it expires.

## 6. API and CLI

| Route | Scope | |
| --- | --- | --- |
| `POST /v1/previews` | `fork` | `{proposal, ttl_ms?, no_pii?, reason, dry_run?}` → `{dry_run, preview}` |
| `GET /v1/previews` | `read` | the previews that have not expired |
| `DELETE /v1/previews/{id}` | `fork` | `{reason, dry_run?}` → `{dry_run, deleted}` |

A preview gets the `fork` scope, not `propose`: it changes nothing on main
and makes no live effect but allowlisted GETs, like any fork; an agent
with the default scopes (`read,fork,propose`) can create one. Create is
refused below `[log] disk_reserve`. `preview` in the API answers is
`{id, proposal, url, fork_lsn, no_pii, expires_ms}`; `url` is
`<scheme>://<id>.<preview_domain>/` with the domain, else
`<scheme>://<host>/__preview/<id>/`, where `<host>` is the first `[tls]
domains` name, else the bound address with `0.0.0.0`/`::` as loopback,
with the port unless it is the scheme's default (`Config::public_host`).
The scheme is `https` when the gateway serves TLS, else `http`. The CLI:
`kronik preview create <proposal> [--ttl 2h] [--no-pii]`, `kronik preview
list`, `kronik preview delete <id>`, each with `--json` ([CLI
reference](../reference/cli.md)). There are no MCP tools for previews: an
agent creates one through the API or the CLI, and its URL is for people.

## 7. Configuration

- `[gateway] preview_domain`: lowercase domain, no scheme, port or leading
  dot; not equal to or a parent of a `[tls] domains` name. Needs a
  wildcard DNS record, and for HTTPS a certificate for `*.<preview_domain>`:
  with `mode = "acme"` only DNS-01 gets it, so ACME with a preview domain
  and no `[tls] dns01_hook` is refused at start (ADR 0026); with `mode =
  "files"` the operator's certificate must cover it. Without TLS the URLs
  are plain `http`.
- `[fork] preview_ttl`: default `"24h"`, more than zero.

## 8. Tests

- `crates/kronik/tests/preview.rs`:
  `a_preview_runs_new_requests_on_the_new_code_without_live_effects` (host
  routing in any case and with a trailing dot, the prefix as main's path
  when a domain is set, step2's answers on HEAD's state, main unchanged,
  the denied and allowlisted fetches counted at local servers, the preview
  inputs in the diff and its Markdown, `PREVIEW_NOT_FOUND` for unknown
  hosts, delete) and
  `previews_are_deleted_after_their_ttl_also_across_a_restart` (prefix).
- `crates/kronik-fork/tests/preview.rs`: bounded turns and
  `PREVIEW_LIMIT`, a held request blocking no operator command, fork
  commands refused, no production key, state dropped after an erasure.
- `crates/kronik/tests/ops.rs`: create and requests refused below the disk
  reserve. `crates/kronik/tests/schemas.rs`: a preview's diff and turn
  match their schemas.
- `kronik-gateway`: `preview_targets_from_the_prefix_or_the_host`,
  `a_prefix_response_sets_no_cookie_and_is_sandboxed` and
  `previews_answer_on_the_prefix_only_without_a_preview_domain`; `kronik`
  config: `preview_keys_parse_and_bad_values_are_errors`,
  `previews_get_valid_urls_or_the_configuration_is_refused`; `kronik-api`:
  `preview_urls_use_the_domain_else_the_public_host`.
