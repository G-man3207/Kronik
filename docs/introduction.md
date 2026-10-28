# Introduction

> Don't deploy code you hope works. Show what it would have done with
> yesterday's traffic.

Kronik is a source-available runtime in which a system is a deterministic
function of its history. The goal is that every change can be verified
against real production traffic before it goes live. The determinism covers
everything that runs as Wasm actors, including their SQL state.

Kronik is pre-alpha: it has no release and is not ready for production. This
book describes what the code in the repository does. `STATUS.md` in the
repository root shows how far the work has come, including what has not been
run on a VPS. The [quickstart](guides/quickstart.md) is the finished-product
journey with the commands that exist today.

## What Kronik is

Kronik is one binary, `kronik`, that runs actors: Wasm components with
built-in state. Every input that an actor handles runs as a turn, every turn
is recorded in an append-only log before anything else happens, and all
state is derived from that log.

What the code does today, on one node:

- **Actors and turns (M1).** An actor type, called a kind, is a Wasm
  component that exports `describe` and `handle` and imports only Kronik's
  interfaces (the [WIT reference](reference/wit.md)). An actor such as
  `billing/acme` is one instance of a kind, with its own key-value state and
  its own SQLite database. It handles one input at a time, each in a turn
  that runs in a fresh instance of the component, within limits on fuel and
  memory.
- **Durability (M1).** A turn's state writes, SQL changes and outgoing
  messages commit together or not at all, and nothing is applied, delivered
  or answered until the turn's record is fsynced in the log. After a crash,
  the state is brought up to date from the log.
- **Determinism (M1).** Time, randomness and SQL functions such as
  `random()` and `datetime('now')` come from the host and derive from values
  recorded with the turn, so running a turn again gives the same outcome. A
  deterministic simulation of the whole daemon, with injected crashes, runs
  in CI ([ADR 0004](adr/0004-deterministic-simulation.md)).
- **Interfaces (M1).** `kronik serve` runs the daemon: an HTTP gateway that
  routes requests to actors by the routes in their manifests, and a JSON API
  on a Unix socket. The CLI deploys components, sends messages, shows actors
  and their history, and resends dead letters. Every error has a stable code
  and a hint ([CLI reference](reference/cli.md), [error codes](errors.md)).
- **Effects (M2).** Guest code reaches the outside world only through
  recorded host calls: outgoing HTTP, `call` to other actors, timers, and
  host-side cryptography with secrets that the guest never sees. Every
  external effect is denied until the operator grants a capability. A crash
  in the middle of a turn is recovered by running the turn again with the
  recorded results; a request to a target that cannot take retries is not
  repeated, and the guest learns that its outcome is unknown.
- **Fork, replay and diff (M3).** `kronik propose` forks history, replays
  recorded traffic through new code and writes a behavior diff. `approve`,
  `promote` and `rollback` are the rest of that path. Policy rules decide
  whether a proposal may go through.
- **TypeScript (M4).** `kronik init` and `kronik build` produce a component.
  The Rust SDK is there too.
- **Policy, tokens and MCP (M5).** Tokens carry scopes. The JSON API is
  described by OpenAPI. `kronik mcp` serves the agent tools. Every mutation
  takes `--reason` and `--dry-run`, except `replay` and `send --fork`, which
  take a reason and have no dry run.
- **Operations (M6).** Snapshots, shipping, `kronik restore` and
  `kronik upgrade check` exist. TLS from certificate files works. ACME is
  tested against Pebble, not a public Let's Encrypt host. `kronik doctor`
  and `/metrics` exist. There is no cluster.
- **Foreign actors (M7).** Linux programs from OCI images run in gVisor.
  `microvm` is reserved and not implemented.
- **Privacy (M8).** Values with a subject can be sealed. `erase` deletes a
  subject's keys and SQL rows that have a `_subject` column; rows in tables
  without that column survive. `reseal` rewrites closed segments. A
  `--no-pii` fork replays with pseudonyms, but its SQL rows are not
  pseudonymized.

There is no web interface. The CLI, the JSON API and MCP are the surface.

## Who it is for

- Agents that write and change software at machine pace and need to prove
  that a change is safe.
- Humans who review the agents' work and do not have time to read all the
  code, but can read a behavior diff.
- Small teams that want safe deploys on a VPS without Kubernetes.

## What makes it different

Other platforms use logs to survive crashes. Kronik uses the history to
verify change, and the product is the behavior diff (M3). A feature that does
not make changes safer, easier to verify or easier to run on a VPS does not
belong in v0.1.

## Five concepts

Kronik introduces five concepts of its own. Familiar concepts such as HTTP,
SQL, state and timers do not count, and everything else is built from these
five: a proposal is a fork with a diff, and a deployment points to a hash.

| Concept | What it is | Milestone |
| --- | --- | --- |
| [Actor](concepts/glossary.md#actor) | An instance with its own state, identified by kind/key | M1 |
| [Message](concepts/glossary.md#message) | Data sent to an actor: name, content type and body | M1 |
| [Effect](concepts/glossary.md#effect) | A call from guest code to the outside world, via the host | M2 |
| [Hash](concepts/glossary.md#hash) | The BLAKE3 hash of a component: the identity of its code | M1 |
| [Fork](concepts/glossary.md#fork) | A branch of the system's history from an LSN | M3 |

[Concepts](concepts/glossary.md) defines these five and every internal term,
and [Architecture](concepts/architecture.md) shows how the parts fit
together.

## Roadmap

v0.1 consists of nine milestones. M0 to M3 come in order; M4 to M8 each build
on M3 and can be built in parallel, and release v0.1.0 needs all nine.

| Milestone | Content |
| --- | --- |
| M0 | Repository, CI, and five spikes with their ADRs |
| M1 | Durable turns on one node: log, state, SQL state, gateway, JSON API and CLI |
| M2 | Effects and capabilities: `http.fetch`, `call`, timers, secrets, grants and limits, and crash recovery of effects |
| M3 | Fork, replay and behavior diff: `propose`, `approve`, `promote` and `rollback`, with policy rules that decide whether a proposal goes through |
| M4 | TypeScript SDK, `kronik init` and `kronik build` |
| M5 | Policy and agent interface: tokens and scopes, the complete JSON API with OpenAPI, and an MCP server |
| M6 | Operations on a VPS: TLS with ACME, systemd, snapshots, shipping and restore, engine upgrades |
| M7 | Foreign actors: Linux binaries in gVisor behind a recorded boundary |
| M8 | Privacy mode: sealed values per subject, erasure and forks without personal data |

After v0.1, the road to v1.0 (milestones M9 to M34) makes Kronik a cluster,
with richer replay, CI integration, visibility, control from outside and a
compatibility promise that holds until v2. The brief, `SPEC.md` in the
repository root, describes it.

## Reading this book

- The [quickstart](guides/quickstart.md) is the install-to-verified-deploy
  journey, with the commands that exist today.
- [Concepts](concepts/glossary.md) and [Architecture](concepts/architecture.md)
  explain the model.
- The reference covers the [CLI](reference/cli.md), the
  [WIT interface](reference/wit.md) that guest code is written against, and
  the [error codes](errors.md).
- The [security model](guides/security.md) lists the threats Kronik is
  designed against and what protects against each of them today.
- The design documents and the architecture decision records (ADRs) at the
  end are the binding decisions behind the code.
