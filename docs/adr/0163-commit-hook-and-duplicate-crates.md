# 0163. A pre-commit hook, and duplicate crates fail cargo-deny

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Hosted CI starts only by hand
([ADR 0110](0110-manual-github-workflows.md)). Nothing on GitHub rejects a
commit that never ran `scripts/ci.sh`. Formatting, the determinism hygiene
and `cargo deny` are the cheap part of that suite: they do not build the
tests, the book or the release binary.

`deny.toml` warned on two versions of one crate and still exited 0. The
locked graph already contains such duplicates, held by dependencies the
workspace does not choose line by line (`ring` on an older `getrandom`,
`cranelift` on an older `sha2`, proc-macros split across `syn` 2 and `syn` 3,
and others). A warning does not make a new duplicate visible.

## Decision

Husky 9.1.7, pinned in the repository-root `package.json`, installs a
pre-commit hook. `npm ci` at the repository root runs the `prepare` script,
which points Git at `.husky/`. The hook runs `scripts/ci.sh fmt hygiene deny`
and nothing else. `git commit --no-verify` skips it. The hook is a local
gate: this ADR does not add a `pull_request` or `push` trigger to the hosted
workflows.

`multiple-versions` is `deny`. Each older version already in `Cargo.lock` is
an exact `skip` (`name@=version`) with a reason that names what still
resolves it. The newer version is not skipped, so another version of that
crate fails the check. The deny step passes `-D unmatched-skip` and
`-D unnecessary-skip`, so an entry whose version has left the graph, or
which now matches a crate with only one version, fails the step and has to
be removed in that change. A skip without an exact version and a reason
fails the step's own check of `deny.toml`.

The examples lockfile is checked with the same `deny.toml`, and
`unmatched-skip` and `unnecessary-skip` are allowed on that invocation. The
baseline describes the daemon graph. A new duplicate in the examples graph
still fails, because `multiple-versions` is `deny` there too.

## Alternatives

- **Restore a pull-request run of these three steps.** That spends hosted
  minutes on every pull request, which [ADR 0110](0110-manual-github-workflows.md)
  exists to avoid. Revisit it there if a required GitHub status is needed.
- **Leave duplicates as a warning.** A new pair does not fail the suite.
- **`skip-tree` on the parents.** That hides every transitive duplicate those
  parents pull in later, including ones that are new.

## Consequences

- A clone does not run the hook until `npm ci` (or `npm install`) at the
  repository root. Node.js 22.20 or later is already required for the `ts`
  and `ui` steps. `cargo-deny` must be on `PATH`, as `scripts/ci.sh deny`
  already requires.
- The hook can be skipped, and GitHub still does not run it. It narrows the
  gap; it does not close it.
- `fmt`, hygiene and `cargo deny` run on every commit that does not skip the
  hook. The deny step fetches the advisory database when its cache is cold.
- Dropping an old duplicate version, or moving it off the exact skipped
  release, fails `cargo deny` until `deny.toml` is updated in the same
  change.
