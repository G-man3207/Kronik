# Agents

Kronik is built by a swarm of coding agents. Before you change anything, read:

1. `SPEC.md`: the English translation of the build brief.
2. `Kronik — Agent Build Brief.md`: the original brief, in Swedish. It is the
   source of truth and is authoritative if it and `SPEC.md` disagree. Never
   edit, move or rename it.
3. `STATUS.md`: the current milestone, what is done, next steps, open
   questions and known gaps. Update it at the end of every work session.
4. `docs/adr/`: the decisions so far. Record new non-trivial decisions as ADRs
   based on `docs/adr/0000-template.md`.

The brief also says how to work: follow the milestone order, verify
everything yourself, never change an invariant on your own, and when you are
stuck after three serious attempts, write the problem under open questions in
`STATUS.md` and continue with the next independent task.

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
scripts/ci.sh                # fmt, clippy, hygiene, test, docs, book, examples, ts, dst, deny, foreign and identity, as in CI
scripts/ci.sh clippy test    # selected steps
```

It needs rustup, which installs the toolchain pinned in `rust-toolchain.toml`,
`cargo-deny`, and Node.js 22.20 or later with npm for the `ts` step. The `book`
step downloads the pinned mdBook with `curl` on first use. The `foreign` step
needs root and `runsc` and is skipped with a message otherwise; without
libfaketime, `identity` skips `todo-ts` the same way.
