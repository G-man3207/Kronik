# 0010. OpenAPI from the API's types, with schemars

- **Status:** Accepted
- **Date:** 2026-10-25

## Context

The brief (SPEC.md, "Agent interface: API, CLI and MCP") wants OpenAPI
"generated, for example with `utoipa`, and published in the docs", and "all
commands have `--json` with published schemas". The JSON API's router is one
`match` on the method and the path segments (`kronik_api::Api::route`, plus
the M3 and M7 modules). Its bodies are serde structs in
`kronik_api::types` and `kronik_api::m7`, which the CLI shares. Every client
command prints the API's response body unchanged with `--json`, so a client
command's schema is its operation's response schema.

## Decision

- **schemars**, pinned exactly (`=1.2.3`). It is already in the dependency
  tree through rmcp, so this adds no crate. Every request and response type
  derives `JsonSchema`. Schemas follow JSON Schema 2020-12, which OpenAPI 3.1
  uses as is. They use the deserialize contract, so fields with serde
  defaults are optional, which also validates responses.
- **One table of operations**, `kronik_api::openapi::OPERATIONS`: method,
  path, summary, query parameters, request type and response type. The
  OpenAPI 3.1 document is built from the table. `x-kronik-scope` on each
  operation comes from `auth::required_scope`, the same table that
  authorizes requests.
- The daemon serves the document at `GET /v1/openapi.json`, and
  `docs/reference/openapi.json` is the committed copy. The book links to it.
- **CLI schemas.** `crates/kronik/src/cli/schemas.rs` maps every command to
  one of three things: the operation whose response it prints; a local
  schema for `explain`, `doctor`, `init` and `build`; or "no JSON" for
  `serve` and `mcp`. `docs/reference/json.md` is generated from the map.
- **Tests keep the four in step:**
  - the committed `openapi.json` equals the generated document;
  - every route arm that dispatches to a handler anywhere in
    `kronik-api/src` is in the table, and every table entry is routed (a
    scan of the sources);
  - every leaf command of the binary is in the CLI map, and each mapped
    operation exists;
  - the committed `json.md` equals the generated page.

## Alternatives

- **utoipa** (`ToSchema` derives and a `#[utoipa::path]` per handler). It
  would bring the utoipa crates into the tree as a second schema derive next
  to schemars. Its path macros annotate one function per operation, while
  our router is a single `match`. The annotations would repeat the table
  above, and nothing would check them against the `match`.
- **A hand-written document.** Nothing would keep it in step with the types
  and the router.

## Consequences

- A new route needs one table line, and `JsonSchema` on its types; the tests
  name what is missing. A new command needs one line in the CLI map.
- Upgrading schemars may change the generated document. It is a reviewed
  change: rerun the generator, and the diff shows what moved.
- Three bodies are not serde types of the API: the policy evaluation, the
  behavior diff and the turn JSON. The policy evaluation's schema is written
  in `openapi.rs`. The other two are covered by the amendment below.

## Amendment (2026-10-25): hand-written schemas for the diff and the turn

Before this, `GET /v1/turns/{id}` and the diff routes were described only
as objects. Typing them in the API would have meant changing the endpoints.
The diff is built by `kronik_fork::diff` with a canonical key order and
capped lists. The turn JSON renders the log's protobuf record.

- **Two JSON Schema 2020-12 files, written by hand:**
  - `docs/reference/diff-v1.schema.json` is `kronik.diff/v1`
    (docs/design/m3-fork.md §5, with what was added since: `live`, stub
    rules, the live allowlist, `no_pii` and `pii_masked`).
  - `docs/reference/turn.schema.json` is the turn JSON.
  - Both forbid unknown properties, so a new field fails the tests until
    the schema describes it.
- **One source.** `openapi.rs` includes both files. The root of each
  becomes a component (`Diff`, `Turn`), and so does every `$defs` entry,
  under names prefixed `Diff` or `Turn`. `DiffSummary`, used by the propose
  and replay responses, is the diff schema's own entry.
  `docs/reference/json.md` lists them as well and links the files.
- **Validated against real output.** `crates/kronik/tests/schemas.rs` runs
  a real `kronik serve` and checks every turn of main's log, fork turns of
  both replay modes, and diffs of an identity replay, a behavior change, approximate
  payments, a sample, stub rules, a new error and a `--no-pii` fork. The
  validator is [boon](https://crates.io/crates/boon) (`=0.6.1`, MIT OR
  Apache-2.0), a dev-dependency only: it implements 2020-12 in full, and
  cargo-deny passes.
- **Alternatives:**
  - *schemars derives on `kronik_fork::diff`'s types.* The schema would
    describe what the code emits rather than check it against the
    documented format. It would also leave the turn JSON, which has no
    type, as it was.
  - *A validator written here.* It would be more code to trust than the
    tests it serves.
