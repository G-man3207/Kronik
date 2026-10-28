# 0012. System proposals: inputs and the per-kind diff

- **Status:** Accepted
- **Date:** 2026-10-26

## Context

M9 asks that `kronik propose a.wasm b.wasm` or `kronik propose dist/` put
every new hash in one fork, skip components whose hash is unchanged, and
give one diff "where each actor kind is reported separately". The engine
already replayed several kinds in one fork, but the diff only had totals:
`causes` names a kind, `responses`, `effects`, `errors` and `state` do not
(or only inside an item list capped at 200). The diff is a published format
(`kronik.diff/v1`, `docs/reference/diff-v1.schema.json` with
`additionalProperties: false`) that the policy, MCP and CI scripts read and
that `branches/*/diff.json` keeps from before M9. CONTRIBUTING asks for a
version bump and a compatibility fixture when a format changes; v1 already
gained `live`, `stubs`, `live_allowlist`, `no_pii` and `pii_masked`
additively.

## Decision

- **Per-kind section.** The diff gets `kinds`, after `summary`: one entry
  per actor kind of the fork's code or of a replayed turn, sorted by kind,
  with `code` (`changed`, `unchanged`, `new`) and the counts of `summary`,
  `responses`, `effects`, `state` and `errors` restricted to that kind
  (`docs/design/m9-system-proposals.md` §3). Counts only: the item lists
  stay where they are, and their items keep their turn ids, whose actor
  names the kind.
- **Additive within v1.** `kinds` is in the schema but not required, and
  readers default it to `[]`. No `kronik.diff/v2`. The compatibility
  fixture is `docs/design/fixtures/diff-system-caller-alone.json`; the
  fixtures from before M9 (without `kinds`) keep passing the policy tests,
  and old `diff.json` files still load.
- **Unchanged components.** The daemon, not the CLI, decides. The fork
  runs every kind outside the set with its code at the fork point, so a
  component is skipped only when its code hash equals both the code main
  runs for its kind now and the code main ran at the fork point. Any other
  component stays in the set, even when main runs it now (promote then
  swaps that kind to the code it already runs, a no-op). Skipped components
  are listed in the proposal's `unchanged` with their full hash and are
  pinned: promote refuses with `PROPOSAL_STALE` when one of those kinds no
  longer runs that code (checked under the deploy lock, with the switch).
  If nothing is left, the proposal is refused with `BAD_REQUEST` and a
  hint that names the identity replay (`kronik fork create`, `kronik
  replay`). No new error code.
- **Directories.** `kronik propose <dir>` takes the `.wasm` files directly
  in the directory, in name order; not subdirectories, and a directory
  without one is `BAD_REQUEST`. A project with build variants (a
  TypeScript project's `dist/<name>.wasm` and `dist/<name>-<entry>.wasm`
  are often the same kind) cannot be proposed as a whole directory: two
  components for one kind are `BAD_REQUEST`, and the message names both
  files; name the components to propose instead.

## Alternatives

- **`kronik.diff/v2`.** Every reader would have to accept two schemas for
  one added array, and every stored diff would become "old". A v1 reader
  that ignores unknown fields loses nothing; the one that breaks is a
  strict validator of the published schema, which is updated in the same
  commit.
- **Split each list by kind** (`responses.by_kind`, a `kind` field on every
  item). Larger diffs and more churn for the same information; the counts
  per kind are what a reviewer and a policy rule need, and the turn ids in
  the items already identify the kind.
- **One diff per kind.** The brief asks for one diff; the kinds interact
  (a caller's change shows up as the callee's consequences), so separate
  diffs would double-count or hide that.
- **Skip unchanged components in the CLI.** An API or MCP client would not
  get it, and the CLI would need a second request for the running hashes.
- **An identity proposal when everything is unchanged.** Promoting it would
  write a `Deployment` that changes nothing; identity replay already exists
  as a fork replay.
- **A new error code for "nothing to propose".** The case is a malformed
  request for this operation; `BAD_REQUEST` with a hint is enough and
  keeps the catalog to the brief's codes.

## Consequences

- A diff's bytes, so its hash, now include `kinds`. A proposal created
  before M9 and promoted after it gets a new diff hash at catch-up; its
  approval still holds when the outcome is not stricter and the changed
  targets are the same (m3-fork §11).
- Policy rules can judge one kind: `diff.kinds.exists(k, k.kind ==
  'payments' && k.errors.introduced > 0)`. Against a diff from before M9
  such a rule errs, which counts as `require_approval`.
- A proposal of exactly the running code is no longer an "empty diff";
  tests and docs that relied on it use a fork replay.
- Revisit if reviewers need per-kind item lists, or if CI needs "nothing
  changed" to succeed instead of fail: then it gets its own code.

## Amendment (2026-10-26, M10): `NOTHING_TO_PROPOSE`

The "revisit" above happened. M10 adds a program that depends on telling
this case apart: the GitHub Action proposes on every pull request and every
push to main, and a pull request that changes no actor code, or a re-run
after the promote, must give a neutral check with a notice, not a failure.
Matching the message text is not a contract. So "nothing to propose" gets
its own stable code, `NOTHING_TO_PROPOSE` (409, milestone M10), with the
same message and hint; the request is well formed, there is just nothing
new in it. `BAD_REQUEST` stays for the other refusals of propose (no
components, two components for one kind, an empty directory, `at` after
HEAD).
