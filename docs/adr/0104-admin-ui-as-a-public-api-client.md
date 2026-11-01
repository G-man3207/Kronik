# 0104. The embedded admin UI is only a public API client

- **Status:** Accepted
- **Date:** 2026-10-30

## Context

M27 adds human review to the same verification loop used by CLI and MCP. I10
requires one binary; I12 requires ordinary scopes, reasons, dry runs and stable
errors. A second server-side business layer or frontend build chain would add
security and maintenance work without changing that loop. M27 also depends on
the M10 API and actual M16 cluster status, not invented browser fixture data.

## Decision

The `ui/` directory contains native HTML, CSS and JavaScript. The new
`kronik-ui` crate embeds their exact bytes at compilation, with explicit routes
for `/ui`, `/ui/`, `/ui/app.js`, `/ui/app.css` and `/ui/icon.svg`. There is no asset server,
frontend framework, CDN, runtime JavaScript dependency or extra application
port. Only the existing admin listener mounts the assets and same-origin `/v1`
transport. The application gateway and ordinary API listeners do not mount UI
assets. Their actual GET/HEAD operations and MIME types, alongside authentication
transport operations, are documented in OpenAPI as admin-listener-only. Browser
network coverage does not silently exclude assets from this public surface.

The browser calls ordinary published APIs for actors/history, turn detail and
causal trace, proposals/diffs, approve/promote, dead letters/resend, deployment
timeline and cluster status. Server-side policy and PII projection remain the
same as CLI/MCP. The UI shows responses, effects, state and per-target grounding
rather than an aggregate confidence alone. Missing cluster integration is an
actual API error, never a synthetic healthy status. Mutation forms require an
explicit reason, expose dry-run, and disable unavailable scopes with explanation;
the server remains the final authority.

Use native landmarks, headings, links, labels, buttons, details and tables.
Navigation moves focus to the view heading; loading/results/errors are announced.
Keyboard focus is visible, targets remain usable at narrow widths and contrast
meets AA. Every untrusted product value is inserted as text, not HTML. No product
value, credential or PII is written to URL parameters, localStorage,
sessionStorage, IndexedDB, service workers or offline caches. Displayed data is
cleared on logout/authentication failure and replaced on view navigation.

OIDC sessions follow ADR 0103. An optional ordinary bearer can be entered in a
password control and kept only in memory; it is sent only in Authorization,
with cookie credentials omitted. Discarding it in the UI does not revoke the
ordinary token. Cookie writes send session CSRF plus exact Origin. Responses
are `no-store`, with `nosniff`, no-referrer, same-origin isolation and a CSP
allowing only local scripts/styles/connections and no framing or HTML base URL.

Acceptance observes an actual Chromium browser, not only source strings or
copied operation lists. Collect the browser's real product/auth network
operations, match each against generated OpenAPI, and require all specified
view/mutation surfaces to have been observed. Run installed axe-core WCAG2A,
WCAG2AA, WCAG21AA and WCAG22AA rules on every required view, plus explicit
keyboard/focus checks and PII-denied principal checks. A real local TLS
OIDC-code issuer verifies protocol/identity behavior; it does not supply a real
human or integrated-cluster acceptance by assertion.

The API mutation table and real CLI audit consumers reuse the same owned
TLS/code/PKCE/JWT provider in `scripts/e2e-ui-oidc.py`. Prepare Python 3.11+ with
`scripts/requirements-oidc-tests.txt` (cryptography, PyJWT and their pinned
closure), following `CONTRIBUTING.md`; tests use `KRONIK_TEST_PYTHON` and never
download packages or rely on ambient imports. CI scopes that prepared runtime
to its existing Cargo test step, not unrelated SDK/action Python callers.
Their private, finite fixture uses genuine cookie sessions for logout and
ordinary administration for profile changes, retaining the exhaustive write
classification, reason/dry-run and exact audit checks without a mock identity
or a production test-only authenticator.

`e2e-ui-oidc.py --stream-auth-only` is a separately labelled, finite consumer
of the ordinary cookie-authenticated SSE/WebSocket endpoints. It reuses the
same provider, embedded UI login, browser and public OpenAPI/network
observation. Real ordinary token operations supply actual public event
identities: both streams receive the pre-logout event, but not a distinct
event appended after the self-logout ACK. Revoked-cookie reconnects and a
separate real read-only OIDC login must be denied before any feed. Older
already-admitted frames may finish; no graceful-close code, browser Ping API
or global rollback is assumed. Native uses the actual `actor-native` source;
an explicitly owned live fixture must provide the actual metadata source,
including a member with zero actors, never an invented actor or node zero.
This focus never deploys a guest, invokes a fork/model/body/kernel path, or
requires approval/key-fault/recovery capabilities. Its result always says
`full_acceptance: false`; it neither replaces the unchanged full M27 fixture
nor resumes any authoritatively stopped dependency work. Execute with the
prepared interpreter and existing isolated, resource-bounded browser runner;
source availability alone is not runtime evidence.

## Alternatives

- A frontend framework/bundler: no required interaction justifies it.
- A server-side UI business API: duplicates existing public behavior and risks
  weaker scopes, policy, grounding or PII enforcement.
- Serving on the application gateway: exposes an operator surface to app users
  and violates the specified admin-listener boundary.
- Static operation-list comparison alone: cannot prove which requests a browser
  actually makes or that the required views and transitions work.

## Consequences

The normal single-binary packaging includes the app without an asset install
step. An accessible native implementation is small enough to review directly.
Browser and accessibility packages are acceptance-only tools, not product
runtime dependencies. Human review, public M10 flow and actual integrated
cluster status must be recorded separately and cannot be fabricated by the
synthetic fixture or a green unit test.
