# Kronik

![Kronik: don't deploy code you hope works. See what it would have done with yesterday's traffic.](docs/media/kronik-banner.png)

Kronik is a source-available runtime in which a system is a deterministic
function of its history. Every input, every effect result and every state
change is written to an append-only log before a turn is applied, delivered or
answered. A proposed change can be replayed against that recorded traffic and
reviewed as a behavior diff before it goes live.

The runtime is one `kronik` binary. It runs actors: Wasm components with
key-value state and their own SQLite database, written in TypeScript, Rust,
Python or Go, or Linux programs from OCI images. The CLI, the JSON API and
the MCP server are the interfaces. The embedded admin UI is partial and
unreleased.

[Website](https://www.kronik.se/) ·
[Documentation](https://github.com/G-man3207/Kronik/wiki) ·
[Quickstart](https://github.com/G-man3207/Kronik/wiki/Quickstart) ·
[Project status](https://github.com/G-man3207/Kronik/wiki/Project-status) ·
[Build brief](https://github.com/G-man3207/Kronik/wiki/Build-Brief)

> **Status: pre-alpha.** Kronik is not ready for production, and interfaces
> may change between releases. See [Status](#status).

## Install

On Linux (x86_64 or aarch64), the latest release:

```sh
curl -fsSL https://github.com/G-man3207/Kronik/releases/download/v0.5.0/install.sh | sh
kronik doctor
```

To build current `main` from a trusted checkout, with the prerequisites in
[CONTRIBUTING.md](CONTRIBUTING.md):

```sh
cargo build --locked --release -p kronik
export PATH="$PWD/target/release:$PATH"
kronik doctor
```

`kronik serve` runs in the foreground. The
[quickstart](https://github.com/G-man3207/Kronik/wiki/Quickstart) goes from an
empty machine to a verified deploy, rollback and restore.
[Installing](https://github.com/G-man3207/Kronik/wiki/Installing) covers the
release contents and the SDK toolchains.

## Documentation

Guides, the introduction, the architecture page and the runbooks are on the
[wiki](https://github.com/G-man3207/Kronik/wiki). This repository keeps the
documents that have to move with the code:

| Path | Why it stays |
| --- | --- |
| [`docs/AGENT_GUIDE.md`](docs/AGENT_GUIDE.md) | Embedded in the binary (`kronik explain agent`) and served over MCP |
| [`docs/concepts/glossary.md`](docs/concepts/glossary.md), [`docs/errors.md`](docs/errors.md) | Generated from the code; CI checks they match |
| [`docs/reference/`](docs/reference/) | CLI, JSON, OpenAPI, WIT and examples, checked against the binary |
| [`docs/guides/operations.md`](docs/guides/operations.md), [`docs/guides/security.md`](docs/guides/security.md) | Checked by tests. `kronik serve --init` reads the operations guide |
| [`docs/perf.md`](docs/perf.md) | Measurements for this tree |
| [`docs/adr/`](docs/adr/), [`docs/design/`](docs/design/) | Decisions and design notes for this tree |

`docs/introduction.md`, `docs/concepts/architecture.md` and
`docs/guides/quickstart.md` are short pointers. Older links, including from
[kronik.se](https://www.kronik.se/), still use those paths. `scripts/ci.sh book`
builds an mdBook from `docs/`.

## Status

The latest release is **v0.5.0** (15 November 2026,
[release notes](https://github.com/G-man3207/Kronik/releases/tag/v0.5.0)):
WebSocket and SSE connections, streaming bodies and blob storage, external
secret backends, and the opt-in nonroot and microVM levels. Earlier attested
releases are **v0.4.1** and **v0.4.0**. The historical **v0.3.0** and
**v0.1.0** remain unsigned, and current consumers refuse their unsigned
artifacts. `v0.5.0` ships static musl binaries for x86_64 and aarch64 with
`install.sh`, checksums, CycloneDX SBOMs and two-build byte-equality
evidence.

`main` is the unreleased `0.6.0-dev` line. The [changelog](CHANGELOG.md)
lists what changed since `v0.5.0`. As of `v0.5.0`, 140 of the 196 criteria
in the [build brief](https://github.com/G-man3207/Kronik/wiki/Build-Brief)
are implemented. The
[compliance audit](https://github.com/G-man3207/Kronik/wiki/Compliance-audit)
maps each one, and the
[project status](https://github.com/G-man3207/Kronik/wiki/Project-status)
page tracks the milestones and the known gaps.

Kronik is single-node. The cluster (M16–M19) is not implemented. The WASI
0.3 remainder (M22), and the UI, fleet and hardening tracks (M27 and
M29–M34), are partial or absent. Some checks ran against pinned emulators
and disposable hosted runners, not production: ACME against Pebble, key and
secret backends against emulators, blob shipping against directory buckets
and a local S3 server, and the nonroot and microVM levels on GitHub-hosted
Ubuntu 24.04 runners. There has been no independent external security
review, production pilot or three-node soak.

## Development

Kronik builds with the Rust toolchain pinned in `rust-toolchain.toml`.

```sh
git clone https://github.com/G-man3207/Kronik.git
cd Kronik
cargo build -p kronik
scripts/ci.sh
```

`scripts/ci.sh` runs the same 18 checks as CI: fmt, clippy, keyhelper,
hygiene, test, docs, book, examples, ui, ts, sdks, dst, deny, musl, foreign,
s3, identity and action. `scripts/ci.sh clippy test` runs a subset.
[CONTRIBUTING.md](CONTRIBUTING.md) has the conventions and what each step
needs. `npm ci` at the repository root installs a pre-commit hook that runs
formatting, hygiene and `cargo deny`. [AGENTS.md](AGENTS.md) is the same list
for automated contributors.

CI, nightly, isolation and release workflows start only when someone runs
them (`workflow_dispatch`). Only the GitHub Action demo runs on push and
pull request. The nightly adds the 1,000-crash test, deterministic
simulation with 10,000 seeds and the release build.

## Security

Do not report vulnerabilities in public issues. See [`SECURITY.md`](SECURITY.md).

## License

Kronik is licensed under the [Elastic License 2.0](LICENSE). It is
source-available, not open source. External contributions require a signed
[Contributor License Agreement](CLA.md).
