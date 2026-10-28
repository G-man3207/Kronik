# 0025. Preview forks

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

M11: "`kronik preview create <proposal>` gives a URL where new requests go
to the fork with the new code; the fork makes no live effects (I7).
Preview requests are their own root inputs and are marked as such in the
diff." Previews use `preview_domain` with a wildcard certificate, or the
path prefix `/__preview/<id>` without DNS-01, and are deleted after their
time to live (24 h by default). I13 allows no new concept.

A proposal's fork already runs the new code with no live effects, but its
diff is the evidence the policy and the approver judge. New requests in
that fork would count as new, divergent turns and could trip
`no-new-errors`. The gateway knows only main's node; forks live in
`kronik-fork`'s `Proposals`, in memory, behind one lock.

## Decision

- **A preview is its own plain fork** (`v-<12 hex>`, status `preview`) of
  main's HEAD with the proposal's code (changed and pinned kinds), the
  proposal's stubs and `no_pii`, and an expiry. The proposal and its diff
  are never touched. Forks commands (`fork list`, `diff show`, `trace`)
  work on it; `kronik preview` creates, lists and deletes them.
- **The gateway routes, the fork runs.** `kronik-gateway` defines a
  `PreviewRouter` trait (the preview's routes; run an `HttpInput` as a root
  input); `Proposals` implements it and `kronik serve` sets it. With
  `[gateway] preview_domain` the gateway intercepts any host under
  `<domain>` (`<id>.<domain>`), and only that; without it, the path
  `/__preview/<id>/...`. It matches the preview's routes with main's rules
  and builds the input exactly as for main (subject, tagging). The
  simulator and the test host set no router and are unchanged.
- **Never on main's origin when previews have their own.** Unapproved
  code needs only the `fork` scope to be served, so with a preview domain
  the prefix is main's path, and the config refuses a preview domain that
  is or contains a `[tls] domains` name. Through the prefix (no domain),
  the gateway keeps only an allowlist of the preview's response headers
  (no `Set-Cookie`, HSTS, `Clear-Site-Data`, NEL/Report-To or `Location`),
  adds `Content-Security-Policy: sandbox`, and drops the request's
  `Cookie` and `Authorization` before the guest sees them. The preview domain should be a
  separate registrable domain (`example-preview.com`), not a subdomain of
  the production site, whose cookies and SameSite boundary it would share.
  With `[tls] mode = "acme"` a preview domain needs `dns01_hook` (refused
  at start otherwise), so every URL handed out can get a certificate.
- **A request is a new continuous root input** of the fork
  (`Continuous::send_input`, generalized from `send`), written sealed to
  the fork's log, with causal root `preview-<random>`. The diff recognises
  preview turns by that prefix and lists them apart
  (`summary.preview_inputs`, `samples.preview`), never comparing them with
  production.
- **Effects are the fork's**: no recording matches a preview root, so a
  fetch is stubbed, denied, or (an allowlisted `GET`) live, as in every
  fork; allowlisted GETs are the one thing that reaches the outside world.
  A preview gets no secret store: `crypto.*` answers `no recording`, since
  anyone with the URL could otherwise have production keys sign their data.
- **Expiry** is wall time in `proposal.json`; a daemon task deletes
  expired previews at start and every minute, and lookups treat them as
  gone at once.
- **Scope `fork`** to create or delete one: it writes nothing on main.
- **Each preview has its own lock** (its serving state is outside the
  proposals' lock), and its memory and count are bounded: logged turns
  leave memory but the 20 the diff samples, a preview takes at most
  10,000 requests (`PREVIEW_FULL`) and stores no idempotency rows, and at
  most 16 previews live at once (`PREVIEW_LIMIT`).
- **No MCP tools** for previews: an agent creates one through the API or
  the CLI; the URL is for people.

## Consequences

- No change to the log format; the diff gains two optional fields
  (`kronik.diff/v1`, additive, absent for every other fork).
- A preview's state is in memory: after a restart it starts again from the
  fork point and its log is rewritten at the next request.
- Requests to one preview run one at a time; requests to other previews
  and most operator commands do not wait for them (`diff show` and
  `preview delete` of that preview do). Parallel turns on one
  preview's state are the upgrade if previews take real traffic.
- Timers that preview requests set never fire (the fork's window is
  `(head, head]`), nor do the timers pending at the fork point.
- The path prefix shadows actor routes under `/__preview/` when a router
  is set and no preview domain is.
- A preview URL is as public as the gateway. A preview with access to
  personal data serves the new code's answers on real data to whoever has
  the URL; `--no-pii` (or a token without `pii:read`) avoids it.
  An erasure drops every preview's in-memory state (it bumps a counter
  each preview checks before its next request, waiting for none), so the
  next request starts again from the fork point without the erased values.
- Through the prefix, the browser still sends main's cookies with each
  request; the gateway drops them (and `Authorization`, `Proxy-Authorization`) before the
  preview's code and log, and the sandbox keeps its pages from using
  main's origin, which also stops scripts and forms. A preview domain
  avoids both.
- The causal root prefix marks preview turns; a production root id never
  has it (they are hex).
