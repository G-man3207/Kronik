# Contributing to Kronik

Kronik is pre-alpha. Before you change anything, read
[the build brief](https://github.com/G-man3207/Kronik/wiki/Build-Brief), the
English translation of the original
[Swedish build brief](https://github.com/G-man3207/Kronik/wiki/Build-Brief-Original-Swedish).
The [project status page](https://github.com/G-man3207/Kronik/wiki/Project-status)
has the current status, and `docs/adr/` records the decisions so far.

## Contributor License Agreement

External contributions require a signed Contributor License Agreement. Read
[`CLA.md`](CLA.md) and sign it as described there before your first pull
request can be merged.

## Build and test

You need [rustup](https://rustup.rs) and
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny)
(`cargo install --locked cargo-deny`). The Rust toolchain is pinned in
`rust-toolchain.toml`, and rustup installs it on first use.

Default Cargo API mutation and real CLI audit tests also run the existing
in-repo TLS/code/PKCE/JWT provider. Prepare Python 3.11+ with the pinned
test-only dependencies before `cargo test` or the `test` step; no target test
installs packages, skips missing dependencies, or substitutes a mock identity:

```sh
python3 -m venv target/oidc-test-python
target/oidc-test-python/bin/python3 -m pip install --only-binary=:all: \
    -r scripts/requirements-oidc-tests.txt
export KRONIK_TEST_PYTHON="$PWD/target/oidc-test-python/bin/python3"
```

On Debian/Ubuntu, creating that environment requires the `python3-venv` system
package. The fixture uses that exact interpreter in isolated mode and checks
the pinned packages, including PyJWT and cryptography. Do not globally activate
the environment or replace Python for unrelated action/PyYAML or SDK steps;
CI prepares its own private environment and scopes it to the existing test
step. These are development dependencies, not daemon/runtime requirements.

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
It also runs the pure-Python documentation-surface, frozen released-corpus,
corpus-promotion, performance-comparator and WASI 0.3 gate-watcher boundary
tests in `scripts/tests`. These are semantic checks of parsers, provenance,
tampering and regression enforcement, not real benchmark results or
between-release performance acceptance. The gate-watcher tests use canned
upstream inputs and make no request.
The `examples` step tests the dependency-free standalone `tools/loadgen`.
The `ts` step reuses its already-built binary for the CLI/API/WIT/error
documentation-surface gate and the frozen v0.1.0/v0.3.0/v0.4.0 log and genuine
tagged component consumers. A newly routed operation or error code requires the
regenerated reference and usage examples in the same change; results from an
earlier revision are not evidence for the integrated build. Compatibility
failures retain their fresh, printed fixture directory; success removes only
that step's temporary parent directory. See
[compatibility](docs/guides/compatibility.md) and [performance](docs/perf.md)
for the historical results and remaining physical gates.
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
Set `KRONIK_RELEASE_KEYHELPER=yes` for the separate default-off x86_64 GNU
PKCS#11 helper. Both real builds must compile and compare it, preserving actual
Cargo logs and compiled artifact identities. Its notices/SBOM select the helper
normal root; daemon musl/static checks and cryptoki-free closure are unchanged.
`KRONIK_INSTALL_KEYHELPER=yes` selects only a correctly attested helper through
the same strict standalone verification path. Source tests cover GNU loader/
dependency rejection, independent helper ELF/payload comparison and real
consumer signature/write-failure boundaries; tests are not release/HSM claims.

Only `examples/github-flow/proof/change.json` is ignored by aggregate CI.
Kronik's separate three-job synthetic M10 workflow handles that exact path;
any other changed path still runs ordinary CI. Its real fixture smoke and
remaining public acceptance requirements are in `examples/github-flow/README.md`.

## Conventions

- **English only.** Code, comments, docs, commit messages, error messages and
  all user-facing text are in English.
- **Public information only.** The repository is public and everything that is
  committed is permanent. Do not commit personal or environment-specific
  information: names, email addresses, usernames, hostnames, private network
  addresses, home-directory or absolute local paths, private repository or
  branch references, internal receipts, credentials, or other details about a
  development environment. This covers code, comments, docs, tests, fixtures,
  scripts, workflow files and commit messages. Use the project identity for
  commits and keep project-management documents on the wiki. If personal
  information does reach a commit, rewrite the history before publishing it.
- **Small commits** with descriptive messages.
- **Commit messages.** Commit as the project identity (`Kronik Maintainers
  <maintainers@users.noreply.github.com>`), never as an individual. The subject
  is `area: summary` in the imperative, at most 72 characters and with no
  final period, for example
  `CI: run the foreign step as root with gVisor installed`. A squashed
  milestone or release is `Kronik M28: OpenTelemetry and audit export`.
  The body, wrapped at 72 columns, says why when the diff does not. A
  message describes the change, not how it came about: no people, agents
  or machines, and no review rounds.
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
