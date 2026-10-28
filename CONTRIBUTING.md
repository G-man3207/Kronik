# Contributing to Kronik

Kronik is pre-alpha. Before you change anything, read `STATUS.md` for the
current milestone and the decisions in `docs/adr/`. The product specification
is the build brief, `Kronik — Agent Build Brief.md` (in Swedish), with an
English translation coming in `SPEC.md`.

## Contributor License Agreement

External contributions require a signed Contributor License Agreement. Read
[`CLA.md`](CLA.md) and sign it as described there before your first pull
request can be merged.

## Build and test

You need [rustup](https://rustup.rs) and
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny)
(`cargo install --locked cargo-deny`). The Rust toolchain is pinned in
`rust-toolchain.toml`, and rustup installs it on first use.

Run the same checks as CI before you push:

```sh
scripts/ci.sh                # fmt, clippy, hygiene, test, docs, book, examples, ts, dst, deny, foreign and identity
scripts/ci.sh clippy test    # selected steps
```

`scripts/ci.sh` exits non-zero if any step fails. The `foreign` step needs
root and `runsc` and is skipped with a message otherwise; without
libfaketime, `identity` skips `todo-ts` the same way. Pull requests must
keep it green.

## Conventions

- **English only.** Code, comments, docs, commit messages, error messages and
  all user-facing text are in English.
- **Small commits** with descriptive messages.
- **Docs move with behavior.** Docs and the error catalog are updated in the
  same commit as the behavior they describe.
- **No panics in the daemon.** No `unwrap` or `expect` in daemon code paths; a
  panic is a bug. Clippy denies both outside tests.
- **`unsafe` only in allowlisted modules.** `unsafe_code` is denied in the
  whole workspace. A module that needs `unsafe` opts out explicitly with
  `#![allow(unsafe_code)]` and a comment that justifies it.
- **Errors.** `thiserror` in libraries, `anyhow` only in the `kronik` binary.
  Error codes are stable and live in `kronik-core`.
- **Logging.** Use `tracing` in the daemon, never `println!`.
- **Dependencies.** Justify every new dependency in the commit message. Avoid C
  dependencies beyond SQLite, which is bundled through `rusqlite`. Every
  dependency must pass `cargo deny check`; extend the license allowlist in
  `deny.toml` only when a new dependency needs it.
- **Formats are versioned.** A change to a format (the Protobuf log schema, the
  diff schema or CLI JSON) requires a version bump and a compatibility fixture.
- **Functional core, imperative shell.** tokio handles I/O in the shell. The
  core (scheduler, replay, matching, diff and policy) is synchronous and pure
  where possible, and all I/O sits behind traits with a real and a simulated
  implementation.
- **Decisions.** Non-trivial decisions are recorded as ADRs in `docs/adr/`,
  starting from `docs/adr/0000-template.md`.
- **Workspace settings.** Every crate inherits the workspace package metadata
  and lints (`[lints] workspace = true`). Rust is stable, edition 2024.
