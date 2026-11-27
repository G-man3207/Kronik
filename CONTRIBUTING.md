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
the pinned packages, including cryptography. Do not globally activate
the environment or replace Python for unrelated action/PyYAML or SDK steps;
CI prepares its own private environment and scopes it to the existing test
step. These are development dependencies, not daemon/runtime requirements.

Run the same checks as CI before you push:

```sh
scripts/ci.sh                # fmt, clippy, keyhelper, hygiene, test, docs, book, examples, ui, ts, sdks, dst, deny, musl, foreign, s3, identity and action
scripts/ci.sh clippy test    # selected steps
```

Formatting, the determinism hygiene and `cargo deny` also run before each
commit, once the hook is installed. From the repository root, with Node.js
22.20 or later:

```sh
npm ci
```

That installs the pinned Husky and points Git at `.husky/`. The pre-commit
hook runs `scripts/ci.sh fmt hygiene deny`. It needs `cargo-deny` on `PATH`,
as the deny step does. `git commit --no-verify` skips the hook. The hook is
local: GitHub still does not start CI on a pull request
([ADR 0110](docs/adr/0110-manual-github-workflows.md),
[ADR 0163](docs/adr/0163-commit-hook-and-duplicate-crates.md)).

`scripts/ci.sh` exits non-zero if any step fails. The M20 and M21 isolation
checks are explicit and are not CI steps: they need root, runsc, systemd 255
or newer and free numeric ids, the microVM ones also `/dev/kvm`, and the
wrapper expects an Ubuntu 24.04 host (the brief's install target). They change
their host, so they run only on a disposable one: the manual `isolation`
workflow runs them on GitHub-hosted runners and keeps their evidence
([ADR 0133](docs/adr/0133-isolation-proofs-on-hosted-runners.md);
`scripts/isolation-ci.py` is its driver, and refuses its host-changing steps
anywhere else).
`scripts/build-microvm-tools.sh` builds the pinned
microVM tool bundle, `scripts/proof-rootless.sh` (and the commands of
[ADR 0064](docs/adr/0064-foreign-isolation-conformance.md)) runs the
conformance harness and the escape probe. The two explicit drivers,
`rootless_boundary` and `isolation_fixture`, are built by name
(`cargo test -p kronik --no-run --test isolation_fixture`; ADR 0064 gives
their arguments) and are never run by `cargo test`. The `foreign` step
needs root and `runsc` and is skipped with a message otherwise; without
libfaketime, `identity` skips `todo-ts` the same way, unless
`KRONIK_TEST_FAKETIME=require`, as CI sets it. The `ui` step
syntax-checks `ui/app.js` and runs the admin UI's Node+Chrome test scripts
(`scripts/test-ui-session-retry.cjs` and
`scripts/test-ui-paging-focus.cjs`), which drive a real Chrome over CDP; it
needs Node.js 22.20 or later, and a Chrome at `/usr/bin/google-chrome`
unless `KRONIK_CHROME` names another binary. The `s3` step runs the
S3 variants of the shipping, restore, blob and audit-sink tests (every test
with `s3` in its name in `kronik-ship`'s `ship` and `blobs` and
`kronik-otel`'s `audit_export`) against moto's S3 server in Docker
(`scripts/s3.sh`). That covers multipart uploads, ranged reads, conditional
creates and listing by prefix, which the directory buckets of the `test`
step do not reach. Without Docker it is skipped with a message; under
`KRONIK_TEST_S3=require`, as in CI, a skip in the step or in a test fails, and
so does a binary in which no S3 test ran. Run as root, the
`foreign` step also runs, under `KRONIK_FOREIGN_TESTS=require`, the
rehearsals of the microVM launcher (`sys::tests` of `kronik-foreign`), the
installer's hand-over of a data directory to another user, a root
client's refusal of an API socket that another user swapped, the key
source's work in a tree that another user owns and `kronik restore` as root
into the nonroot service's directory (`--test restore_drop`, which really
gives up root), so that a host that cannot run them fails the step instead
of leaving them out. It also runs the conformance harness's own regressions
(`scripts/isolation-conformance-test.py`): one audits the owner of a separate
actor root, which needs root, so the suite fails without it and lives
outside `scripts/tests`. The trusted actor needs runc at `/usr/bin/runc` (CI
installs it); under require a missing binary fails the foreign test instead
of skipping. It also builds the hostile `foreign-probe` image and runs
M21's malicious actor, bounded for CI: root in its gVisor sandbox under the
root daemon, the probe tries the host's TCP, UDP, Unix and abstract-socket
listeners, its files, processes and devices, writes into its directories and a
neighbouring sandbox, and must fail at all of it while its own controls work
(about ten seconds). The full proof, under the installed nonroot service with
SysV, demo and microVM checks, is the manual `isolation` workflow. The
microVM level's refusal without KVM (`KVM_UNAVAILABLE` with the gVisor hint)
is tested on every host, including CI's runners, which have `/dev/kvm`, by
`crates/kronik/tests/microvm_admission.rs`: a debug build of the daemon
checks the device that `KRONIK_TEST_KVM_DEVICE` names instead of
`/dev/kvm`, and the test names one that does not exist. A release build
ignores the variable, and only the admission check reads it: the VMM's jail
binds `/dev/kvm` itself. The `action` step
installs checksum-verified actionlint 1.7.12 into `target/tools/` and lints
the actual workflows and composite action; a download or lint failure
fails the step. Its YAML structure checks of the workflows need PyYAML
(Debian and Ubuntu: `python3-yaml`), and the step fails without it.
The same step runs `scripts/e2e-release-signatures.py`: genuine public
Sigstore bundles through the actual source/standalone installer and Action,
including wrong-identity/artifact refusal and real authenticated EFBIG faults.
It needs HTTPS access for official fixed-hash verifier archives and maintained
TUF roots, but no account or GitHub token. Fixture identities are private SOURCE
copies, never production runtime trust overrides.
It also runs the pure-Python documentation-surface, frozen released-corpus,
corpus-promotion and performance-comparator boundary tests in `scripts/tests`.
These are semantic checks of parsers, provenance, tampering and regression
enforcement, not real benchmark results or between-release performance
acceptance.
It also runs the regressions of the microVM tool builder
(`scripts/tests/test_build_microvm_tools.py`), which run
`scripts/build-microvm-tools.sh` for its argument checks and for its
cancellation of the processes it owns, without fetching or building anything.
The `examples` step tests the dependency-free standalone `tools/loadgen`.
The `ts` step reuses its already-built binary for the CLI/API/WIT/error
documentation-surface gate and the frozen published log and genuine tagged
component consumers. A newly routed operation or error code requires the
regenerated reference and usage examples in the same change; results from an
earlier revision are not evidence for the integrated build. Compatibility
failures retain their fresh, printed fixture directory; success removes only
that step's temporary parent directory. The same step builds `loadgen` and
runs the M24 criteria 2 and 4 acceptance (`scripts/acceptance-m24.sh replay`,
then `restart`) against `chat-ts`; its default ports 47510 and 47511 must be
free, so two `ts` runs on one machine collide. See
[compatibility](https://github.com/G-man3207/Kronik/wiki/Compatibility) and [performance](docs/perf.md)
for the historical results and remaining physical gates.
`hygiene` checks every argument of literal workflow `ci.sh` calls against
the default step inventory; missing, unknown, duplicate or reordered steps
fail. A change must keep it green; GitHub does not start CI on the pull request.

The HTTP listeners in `kronik-api` and `kronik-gateway` keep their runtime
dependencies behind the `server` feature, which the `kronik` binary enables.
There is no cluster crate, and no whole-crate hygiene exemption. Vendored
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

A release moves every version site with `scripts/set-version.py`: `--from
0.5.0-dev --to 0.5.0` for the release commit, and `--from 0.5.0 --to
0.6.0-dev` on `main` after the tag. The sites are the workspace's and the
examples' manifests and lockfiles, the Rust and TypeScript SDKs' manifests and
npm lockfiles, the `/v1/health` example of `docs/design/m1-core.md` and
`info.version` of `docs/reference/openapi.json` (regenerate it afterwards; it
must not change). The script checks every site before it edits any, refuses
one at another version, and lists the tracked text that still names the old
version: the changelog, ADRs and the evidence in the guides keep the version
they were written with, as do binary fixtures. `--check` only checks that
every site is at the workspace's version; a test runs it on the repository.

CI (`.github/workflows/ci.yml`) and the long checks
(`.github/workflows/nightly.yml`) start only from `workflow_dispatch`. A push
or pull request does not spend hosted-runner minutes. Run `scripts/ci.sh`
locally, and start the GitHub workflow by hand when a hosted run is needed.
The Release workflow was already manual. See
[ADR 0110](docs/adr/0110-manual-github-workflows.md).

CI runs the steps of `scripts/ci.sh` in parallel jobs, each step once: fmt,
clippy, hygiene, docs, book and deny; test; dst; musl; foreign; s3; examples, ts,
sdks and identity, in one job because identity replays the examples the others
build; and action. The musl step links `kronik` for the static release target
(`x86_64-unknown-linux-musl`) with the release's pinned zig and cargo-zigbuild
(`scripts/install-zig.sh`, which `scripts/release.sh` uses too), in a debug
build: a libc function that zig's musl does not have, which compiles and works
on glibc, is an undefined symbol there and not first in the release. A job runs its steps in the script's order. The hygiene
step checks both with `scripts/check-ci-steps.py`, so a new default step in
`scripts/ci.sh` must also go into one of the jobs. It also checks that the
job running `foreign` or `s3` sets `KRONIK_FOREIGN_TESTS` or `KRONIK_TEST_S3`
to `require`, so that CI never passes by skipping them.

The synthetic M10 workflow (`.github/workflows/kronik.yml`) is not a general
build. It still starts only when `examples/github-flow/proof/change.json`
changes, and only on a real pull request or push, because a manual dispatch
cannot stand in for that proof. No such manifest is committed, so installing
the workflow does not start a run. Its real fixture smoke and remaining
public acceptance requirements are in `examples/github-flow/README.md`.

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
  dependency must pass `cargo deny --all-features check`; extend the license
  allowlist in `deny.toml` only when a new dependency needs it. A second
  version of a crate fails that check. An older version that is already
  duplicated is an exact `skip` with a reason
  ([ADR 0163](docs/adr/0163-commit-hook-and-duplicate-crates.md)); remove the
  skip in the change that drops the version.
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
