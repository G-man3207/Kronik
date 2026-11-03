# Agents

Kronik accepts contributions from people and from automated agents. Before you
change anything, read:

1. [The build brief](https://github.com/G-man3207/Kronik/wiki/Build-Brief): the
   English translation of the project's build brief, and the source of truth
   for scope, invariants and milestones.
2. The original build brief, in Swedish:
   [Build-Brief-Original-Swedish](https://github.com/G-man3207/Kronik/wiki/Build-Brief-Original-Swedish).
   It is authoritative if the two disagree, and the two pages are kept in sync.
3. [The project status](https://github.com/G-man3207/Kronik/wiki/Project-status):
   the current state of each milestone, the open questions and the known gaps.
4. `docs/adr/`: the decisions so far. Record new non-trivial decisions as ADRs
   based on `docs/adr/0000-template.md`.

The build brief also sets out the project's conventions: follow the milestone
order, verify changes against the tests and the demo scripts, and never change
an invariant without a maintainer decision. If a change would alter an
invariant or the scope of v0.1, open an issue for a maintainer decision before
proceeding.

## Conventions

The full list is in `CONTRIBUTING.md`. In short:

- Everything in the repository is in English.
- Small commits with descriptive messages; justify new dependencies in the
  commit message; update docs and the error catalog in the same commit as the
  behavior.
- No `unwrap` or `expect` in daemon code paths; `unsafe` only in allowlisted
  modules with a justification; `tracing`, not `println!`, in the daemon.
- `thiserror` in libraries, `anyhow` only in the `kronik` binary.
- Avoid C dependencies beyond bundled SQLite.
- Format changes need a version bump and a compatibility fixture.

## Running CI locally

```sh
scripts/ci.sh                # fmt, clippy, hygiene, test, docs, book, examples, ts, dst, deny, foreign, identity and action, as in CI
scripts/ci.sh clippy test    # selected steps
```

It needs rustup, which installs the toolchain pinned in `rust-toolchain.toml`,
`cargo-deny`, and Node.js 22.20 or later with npm for the `ts` step. The `book`
step downloads the pinned mdBook with `curl` on first use. The `foreign` step
needs root and `runsc` and is skipped with a message otherwise; without
libfaketime, `identity` skips `todo-ts` the same way. The `action` step skips
its YAML checks without PyYAML, and actionlint when it is not installed.
