# Kronik

> Don't deploy code you hope works. See what it would have done with
> yesterday's traffic.

https://github.com/user-attachments/assets/5c42b6b8-a40e-42d4-a994-31848284a324

<sub>The video shows the v1.0 target; see <a href="#status">Status</a> for what works today.</sub>

Kronik is a source-available runtime in which a system is a deterministic
function of its history. Every input, every effect result and every state
change is recorded in an append-only log, and a turn is applied, delivered and
answered only after its record is fsynced. A change can therefore be replayed
against real production traffic and reviewed as a behavior diff before it goes
live.

The runtime is a single `kronik` binary. It runs actors: Wasm components with
built-in key-value state and their own SQLite database. Actors are written in
TypeScript, Rust, Python or Go, or run as Linux programs from OCI images in
gVisor. The CLI, the JSON API and the MCP server are the primary surface; the
embedded admin UI (M27) is served on the admin listener and is partial and
unreleased.

## Status

Kronik is pre-alpha. It is not ready for production, and interfaces may still
change between releases.

| Release | Contents |
| --- | --- |
| [`v0.1.0`](https://github.com/G-man3207/Kronik/releases/tag/v0.1.0) | Durable turns, effects and capabilities, fork, replay and behavior diff with policy and approvals, proposals that span several actors, the TypeScript and Rust SDKs, the JSON API and MCP server, operations on a VPS, foreign actors in gVisor, privacy mode |
| [`v0.3.0`](https://github.com/G-man3207/Kronik/releases/tag/v0.3.0) | Python and Go SDKs, the CLI against a remote API, watch and preview forks, effect simulators, rollback via replay, foreign actors copied into forks |
| [`v0.4.0`](https://github.com/G-man3207/Kronik/releases/tag/v0.4.0) | Standard `fetch` through `wasi:http`, OpenTelemetry traces with a complete verifiable audit export, KMS-wrapped master key (OpenBao/AWS/GCP/Azure), Wasmtime 50.0.1, and crash-path hardening: atomic secret-catalogue publication, paced rate windows, restart-safe custody |
| [`v0.4.1`](https://github.com/G-man3207/Kronik/releases/tag/v0.4.1) | Patch release: `kronik restore` validates the manifest paths and the component names it takes from the snapshot bucket; restarts no longer grow with the log, nor stop on one whose retention compacted past an idle SQL actor; erasure no longer strands scrubbed reads at 503; the audit export and its followers recover at once from an overtaking configuration commit. Engine `kronik-0.4.1+wasmtime-50.0.1` |

`v0.4.1` is the latest release: a patch on the attested line `v0.4.0` opened.
The archives are static musl binaries for x86_64 and aarch64 with `install.sh`,
checksums, CycloneDX SBOMs and two-build byte-equality evidence
(`reproducibility.json`); `install.sh` verifies each archive's Sigstore
attestation and refuses unsigned ones. `v0.4.1` fixes a security issue in
`kronik restore` (the manifest paths and the component names it takes from the
snapshot bucket are now validated, see the
[advisory](https://github.com/G-man3207/Kronik/security/advisories/GHSA-f9xv-7cmm-95v6))
and the defects found since `v0.4.0` in restart, retention, secret handling and
the audit export; the engine is `kronik-0.4.1+wasmtime-50.0.1`. `v0.3.0` and
`v0.1.0` are the historical unsigned releases.

`main` is an unreleased `0.5.0-dev` work in progress; the
[changelog](CHANGELOG.md) lists what changed since `v0.4.1`. The external
secret backends (M23 B2–B6) are in the code and have run against pinned
services, emulators and SoftHSM2, not against a real cloud or a physical HSM;
they are not accepted yet. The designs of long-lived connections (M24),
streaming bodies (M25) and blob storage (M26) are accepted, and their
implementation has not landed. Major areas remain absent or partial: the
cluster (M16–M19), the WASI 0.3 remainder (M22), connections, streaming bodies
and blobs (M24–M26), and the UI, fleet and hardening tracks (M27 and M29–M34).
The microVM level (M20) and the nonroot daemon (M21) are in the tree as opt-in
work whose installed proofs have not been run on this revision:
`isolation = "microvm"` is experimental and has not booted a VM on a KVM host,
and the nonroot service of `kronik serve --init --rootless` has not passed its
installed proofs (ADR 0064), on Ubuntu 24.04 with AppArmor's restriction on
user namespaces (R1) or elsewhere. The manual `isolation` workflow runs those
proofs on disposable hosted runners and keeps their evidence. The nonroot
daemon's decisions, ADRs 0060–0065, were accepted on 2026-11-13; the microVM
level's, ADRs 0095 and 0096, await the maintainers.
See the [project status page](https://github.com/G-man3207/Kronik/wiki/Project-status)
for the state of each milestone, the open questions and the known gaps, and the
[compliance audit](https://github.com/G-man3207/Kronik/wiki/Compliance-audit)
for how the brief maps to the tree.

## What works today

- **Durable turns.** A turn's state writes, SQL changes and outgoing messages
  commit together or not at all, and nothing is applied or answered until the
  turn's record is fsynced. Recovery from the log is exercised by a crash
  test of 1,000 `kill -9` cycles (`scripts/chaos.sh`, also the manual nightly
  workflow).
- **Deterministic replay.** Time, randomness and SQL functions such as
  `random()` derive from values recorded with the turn, so running a turn again
  gives the same outcome. A deterministic simulation of the whole daemon, with
  injected crashes, runs in the CI checks (`scripts/ci.sh`).
- **Effects and capabilities.** Outgoing HTTP, actor-to-actor calls, timers and
  host-side cryptography with secret handles. Every effect is denied until the
  operator grants a capability, and each result is recorded and returned on
  re-execution.
- **Fork, replay and diff.** `kronik propose` forks history, replays recorded
  traffic through the new code and writes a behavior diff. Policy rules decide
  whether a change is allowed, needs an approval, or is denied; `promote` and
  `rollback` move code forward and back. Effect simulators stand in for
  external services during a replay, `watch` rolls a promotion back when a
  guard breaks, and preview forks take new requests on unproposed code.
- **Operations.** TLS from certificate files or ACME, a systemd unit,
  snapshots, shipping to object storage, `kronik restore`, `kronik upgrade
  check`, `kronik doctor`, `keys status|wrap|rewrap` and `/metrics`.
  Master-key custody supports file/env or OpenBao/AWS/GCP/Azure KMS,
  checked against free emulators, not production cloud IAM. ACME is tested
  against Pebble, not a public certificate authority.
- **Privacy mode.** Values with a subject can be sealed, erased and resealed,
  and forks replay without personal data unless a token carries `pii:read`.
- **Foreign actors.** Linux programs from OCI images run in gVisor behind the
  same recorded boundary, and can be copied into a fork from a checkpoint.
- **Agent interface.** The JSON API is described by OpenAPI, and `kronik mcp`
  serves the same operations as MCP tools with token scopes.
- **Observability.** Turns become OpenTelemetry traces over OTLP, metrics are
  served for Prometheus and sent over OTLP, and the audit export writes every
  mutation to files, object storage or a webhook; `kronik audit verify`
  checks a file or object-storage sink against the log.

## Getting started

The [installation guide](docs/guides/install.md) describes the signed-release
contract and standalone curl-pipe installer. `v0.4.1` and `v0.4.0` are
attested: the installer verifies each archive's Sigstore attestation, and
historical `v0.3.0` and `v0.1.0` remain unsigned, so current consumers
intentionally refuse their archives. To run the latest release:

```sh
curl -fsSL https://github.com/G-man3207/Kronik/releases/download/v0.4.1/install.sh | sh
kronik doctor
```

To build current `main` instead, from a trusted checkout with the
prerequisites in [CONTRIBUTING.md](CONTRIBUTING.md):

```sh
cargo build --locked --release -p kronik
export PATH="$PWD/target/release:$PATH"
kronik doctor
```

`kronik serve` runs in the foreground, so start it in its own terminal:

```sh
kronik serve \
  --data-dir /var/tmp/kronik \
  --http-listen 127.0.0.1:8080 \
  --api-socket /var/tmp/kronik/api.sock
```

In another terminal, point the CLI at that socket and deploy a first actor.
The TypeScript template needs Node.js 22.20 or later; Ubuntu 24.04 ships 18,
so take Node.js 24 from NodeSource first:

```sh
curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
apt-get install -y nodejs

export KRONIK_API_SOCKET=/var/tmp/kronik/api.sock

kronik init --lang ts billing
cd billing && npm install && npm test && kronik build
kronik deploy dist/billing.wasm --reason 'first deploy'
curl -s -X POST http://127.0.0.1:8080/billing/acme/increment
```

Change the actor, build it again, and propose it:

```sh
kronik propose dist/billing.wasm --window 1h --reason 'count in steps of 2'
kronik diff show <proposal> --md
```

`--lang rust`, `python` and `go` produce the same counter in the other SDKs;
Python and Go need the toolchains that `scripts/install-sdk-tools.sh` installs.
Foreign actors need gVisor's `runsc`, which `install.sh` offers.

[The quickstart](docs/guides/quickstart.md) walks the full path from an empty
machine to a verified deploy, rollback and restore, including what to do
without a public DNS name or an object store.
[Installing](docs/guides/install.md) covers the release contents and the SDK
toolchains.

## How it works

1. The gateway or the JSON API admits an input. The scheduler queues it in the
   actor's mailbox.
2. The runtime runs `handle` in a fresh Wasm instance, with fuel and memory
   limits, a host-provided clock and seed, and a host-side effect gate.
3. The turn's input, outcome, state writes and SQL changes are fsynced to the
   log as one record, and applied in LSN order. A turn that reaches the outside
   world first records what it is about to do, so a crash can rerun it with the
   recorded results.
4. A proposal forks the log at an LSN, replays the recorded inputs through the
   new component with the recorded effect results, and diffs the outcomes,
   writes and effects against what main actually did.

[Architecture](docs/concepts/architecture.md) describes the parts, the disk
layout and the decisions behind them.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/` | The daemon and its libraries: gateway, JSON API, scheduler, runtime, log, state, fork engine, MCP server, policy, privacy, shipping, admin UI, fleet API and OpenTelemetry/audit export |
| `ui/` | The dependency-free admin UI source embedded into the binary by `kronik-ui` |
| `sdk/` | The TypeScript, Rust, Python and Go SDKs; `kronik init` vendors one into a project |
| `examples/` | Example actors and apps in all four languages |
| `docs/` | The book: concepts, guides, reference, design notes and ADRs, indexed by `docs/SUMMARY.md` |
| `deploy/`, `action/` | The systemd unit and the GitHub Action |
| `scripts/`, `demo/` | `ci.sh`, release, acceptance, simulation and chaos scripts, and end-to-end demos |

## Documentation

- [Introduction](docs/introduction.md): what Kronik is and the five concepts it
  is built from.
- [Quickstart](docs/guides/quickstart.md): install to verified deploy.
- [Writing actors](docs/guides/actors.md): `kronik init`, the SDKs and the WIT
  interface.
- [CLI reference](docs/reference/cli.md) and [error codes](docs/errors.md).
- [Operating Kronik](docs/guides/operations.md) and the
  [security model](docs/guides/security.md).
- [Kronik for agents](docs/AGENT_GUIDE.md): the same text as `kronik explain agent`.
- [Performance](docs/perf.md) and the [ADRs](docs/adr).

The book is built from `docs/` with mdBook by `scripts/ci.sh book`.

## Development

Kronik builds with the Rust toolchain pinned in `rust-toolchain.toml`:

```sh
git clone https://github.com/G-man3207/Kronik.git
cd Kronik
cargo build -p kronik
scripts/ci.sh
```

`scripts/ci.sh` runs the same checks as CI: formatting, clippy, repository
hygiene, tests, docs, the book, the examples, the SDK tests, deterministic
simulation, dependency policy, foreign and identity tests, and the GitHub
Action. It needs `cargo-deny`, Node.js 22.20 or later and the pinned Python
test runtime from [`CONTRIBUTING.md`](CONTRIBUTING.md); [`AGENTS.md`](AGENTS.md)
lists what each step needs. A missing tool fails its step, except that
`foreign` is skipped with a message without root and gVisor's `runsc`, and
`identity` skips one example without libfaketime. Pass step names to run a
subset, for example `scripts/ci.sh clippy test`.

The CI and nightly GitHub workflows start only when someone runs them
(`workflow_dispatch`). A push or pull request does not. The nightly workflow
adds what is too slow for an ordinary CI run: a crash test of 1,000 `kill -9`
cycles, deterministic simulation with 10,000 seeds over every workload and a
million-step run, and the release build. One manual run starts every one of
those jobs; the same commands run locally.

An informational job in that workflow, which never turns the run red, also
reports whether the upstream conditions for WASI 0.3 are met yet
(`scripts/check-wasi-p3-gate.py`, [ADR 0070](docs/adr/0070-wasi-http-outgoing-handler.md)).

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the conventions, and
[`AGENTS.md`](AGENTS.md) is the guide for automated and human contributors.

## Security

Do not report vulnerabilities in public issues. See
[`SECURITY.md`](SECURITY.md) for the private reporting process and the
security model.

## License

Kronik is licensed under the [Elastic License 2.0](LICENSE). It is
source-available, not open source. External contributions require a signed
[Contributor License Agreement](CLA.md).
