# Kronik

> Don't deploy code you hope works. See what it would have done with
> yesterday's traffic.

Kronik is a source-available runtime in which a system is a deterministic
function of its history. Every input, every effect result and every state
change is recorded in an append-only log, and a turn is applied, delivered and
answered only after its record is fsynced. A change can therefore be replayed
against real production traffic and reviewed as a behavior diff before it goes
live.

The runtime is a single `kronik` binary. It runs actors: Wasm components with
built-in key-value state and their own SQLite database. Actors are written in
TypeScript, Rust, Python or Go, or run as Linux programs from OCI images in
gVisor. There is no web interface: the CLI, the JSON API and the MCP server
are the surface.

## Status

Kronik is pre-alpha. It is not ready for production, and interfaces may still
change between releases.

| Release | Contents |
| --- | --- |
| [`v0.1.0`](https://github.com/G-man3207/Kronik/releases/tag/v0.1.0) | Durable turns, effects and capabilities, fork, replay and behavior diff with policy and approvals, proposals that span several actors, the TypeScript and Rust SDKs, the JSON API and MCP server, operations on a VPS, foreign actors in gVisor, privacy mode |
| [`v0.3.0`](https://github.com/G-man3207/Kronik/releases/tag/v0.3.0) | Python and Go SDKs, the CLI against a remote API, watch and preview forks, effect simulators, rollback via replay, foreign actors copied into forks |

`v0.3.0` is the latest release: static musl binaries for x86_64 and aarch64,
with `install.sh`, `SHA256SUMS` and a CycloneDX SBOM. Since that tag, `main`
has added OpenTelemetry traces and a verifiable audit export, and standard
`fetch` through `wasi:http`; both are unreleased.

Two criteria remain open:

- An example repository running the whole propose, approve and promote flow in
  GitHub Actions. The action itself is tested against a fake `kronik` and a
  fake GitHub API.
- WASI 0.3 components, blocked on Wasmtime shipping the preview 3 interfaces
  as stable.

The cluster, the rootless daemon, microVMs, connections and external secret
backends are designed or started on parked branches; none of them is on
`main`.

[`STATUS.md`](STATUS.md) records the evidence for each milestone, the open
questions and the known gaps.

## What works today

- **Durable turns.** A turn's state writes, SQL changes and outgoing messages
  commit together or not at all, and nothing is applied or answered until the
  turn's record is fsynced. Recovery from the log is exercised by a nightly
  crash test of 1,000 `kill -9` cycles.
- **Deterministic replay.** Time, randomness and SQL functions such as
  `random()` derive from values recorded with the turn, so running a turn again
  gives the same outcome. A deterministic simulation of the whole daemon, with
  injected crashes, runs in CI.
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
  check`, `kronik doctor` and `/metrics`. ACME is tested against Pebble, not a
  public certificate authority.
- **Privacy mode.** Values with a subject can be sealed, erased and resealed,
  and forks replay without personal data unless a token carries `pii:read`.
- **Foreign actors.** Linux programs from OCI images run in gVisor behind the
  same recorded boundary, and can be copied into a fork from a checkpoint.
- **Agent interface.** The JSON API is described by OpenAPI, and `kronik mcp`
  serves the same operations as MCP tools with token scopes.

## Getting started

On a fresh Ubuntu 24.04 host, as root:

```sh
curl -fsSL https://github.com/G-man3207/Kronik/releases/latest/download/install.sh | sh
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
| `crates/` | The daemon and its libraries: gateway, JSON API, scheduler, runtime, log, state, fork engine, MCP server, policy, privacy, shipping |
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
- [Kronik for agents](AGENT_GUIDE.md): the same text as `kronik explain agent`.
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
Action. It needs `cargo-deny` and Node.js 22.20 or later; a step whose tools
are missing is skipped with a message, for example `foreign` without root and
gVisor's `runsc`. Pass step names to run a subset, for example `scripts/ci.sh
clippy test`.

The nightly workflow adds what is too slow for every pull request: a crash
test of 1,000 `kill -9` cycles, deterministic simulation with 10,000 seeds
over every workload and a million-step run, and the release build.

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the conventions, and
[`AGENTS.md`](AGENTS.md) is the entry point for coding agents.

## Security

Do not report vulnerabilities in public issues. See
[`SECURITY.md`](SECURITY.md) for the private reporting process and the
security model.

## License

Kronik is licensed under the [Elastic License 2.0](LICENSE). It is
source-available, not open source. External contributions require a signed
[Contributor License Agreement](CLA.md).
