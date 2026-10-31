# Contributing to Kronik

Kronik is pre-alpha. Before you change anything, read `STATUS.md` for the
current milestone and the decisions in `docs/adr/`. The product specification
is the build brief, `Kronik — Build Brief.md` (in Swedish), with an
English translation coming in `the build brief`.

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
scripts/ci.sh                # fmt, clippy, hygiene, test, docs, book, examples, ts, sdks, dst, deny, foreign, identity and action
scripts/ci.sh clippy test    # selected steps
```

`scripts/ci.sh` exits non-zero if any step fails. The `foreign` step needs
root and `runsc` and is skipped with a message otherwise; without
libfaketime, `identity` skips `todo-ts` the same way. The `action` step
installs checksum-verified actionlint 1.7.12 into `target/tools/` and lints
the actual workflows and composite action; a download or lint failure
fails the step. Its additional YAML structure checks need PyYAML.
The same step runs `scripts/e2e-release-signatures.py`: genuine public
Sigstore bundles through the actual source/standalone installer and Action,
including wrong-identity/artifact refusal and real authenticated EFBIG faults.
It needs HTTPS access for official fixed-hash verifier archives and maintained
TUF roots, but no account or GitHub token. Fixture identities are private SOURCE
copies, never production runtime trust overrides.
It also runs the bounded performance-comparator self-tests in `scripts/tests`.
Those synthetic reports check the strict greater-than-10% regression boundary
and input/workload/rig matching; they are not real benchmark results or
between-release performance acceptance, and fetch no baseline or target.
`hygiene` checks every argument of literal workflow `ci.sh` calls against
the default step inventory; missing, unknown, duplicate or reordered steps
fail. Pull requests must keep it green.
The opt-in cluster server keeps its runtime/server dependencies behind the
exact `server` feature; there is no whole-crate hygiene exemption. Vendored
third-party Rust is included in the unsafe scan and still needs a per-file
justification. Release packaging treats local third-party path dependencies
as third-party: an explicit, hash-checked upstream/ordered-patch/license origin
is required, rather than silently excluding every null Cargo `source`.

Release candidates from `scripts/release.sh` are unsigned. The manual exact-tag
workflow uses `scripts/reproduce-release.py` for two independent compiled builds
before keyless attestation. No compiled Kronik output is shared; pinned tools
and source inputs may be. Actual comparison evidence and a real signed
Kronik run are required before release claims. See
[ADR 0100](docs/adr/0100-signed-reproducible-releases.md).

Only `examples/github-flow/proof/change.json` is ignored by aggregate CI.
Kronik's separate three-job synthetic M10 workflow handles that exact path;
any other changed path still runs ordinary CI. Its real fixture smoke and
remaining public acceptance requirements are in `examples/github-flow/README.md`.

## Conventions

- **English only.** Code, comments, docs, commit messages, error messages and
  all user-facing text are in English.
- **Small commits** with descriptive messages.
- **Commit messages.** The subject is `area: summary` in the imperative, at
  most 72 characters and with no final period, for example
  `CI: run the foreign step as root with gVisor installed`. A squashed
  milestone or release is `Kronik M28: OpenTelemetry and audit export`.
  The body, wrapped at 72 columns, says why when the diff does not. A
  message describes the change, not how it came about: no people, agents
  or machines, and no reviews.
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
