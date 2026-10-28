# Architecture

Kronik is one Rust binary with a thin imperative shell around a deterministic
core, and every turn passes through the log before anything else happens.
This page describes the parts that exist in the code, the path of a turn
through them, what lies on disk, and the decisions behind it all. Parts that
later milestones add are marked with their milestone.

## The parts

```text
HTTP clients ──▶ gateway ───┐
                            ├──▶ scheduler ──▶ turn executor ──▶ effect gate (M2) ──▶ external services
CLI ──▶ JSON API ───────────┘                        │
                                                     │  turn record; from M2 also TurnBegin and EffectResult
                                                     ▼
                                  log: segments, group commit, fsync
                                                     │  applied in LSN order
                                                     ▼
                                  state.db and one SQLite database per actor
```

| Part | What it does | Crate |
| --- | --- | --- |
| Gateway | HTTP on `http_listen`, or HTTPS with a certificate from files or by ACME (M6). Matches requests against the routes in the current deployments' manifests, admits root inputs, handles `Idempotency-Key` per actor, and answers only after commit. A turn that outlives the gateway timeout (30 s) gives 504 and still completes. | `kronik-gateway` |
| JSON API | `/v1` over a Unix socket and, with a bearer token, over TCP (M5): deploy, messages, actors, history, turns, dead letters, from M2 grants, limits, secrets, orphans and timers, from M3 forks, proposals and policy, and from M5 tokens. Every request is checked against the scope its route needs. The CLI and the MCP server are clients of it. | `kronik-api` |
| Scheduler | Activates actors and runs one turn at a time per actor, different actors in parallel. Owns the mailboxes, logical time, the turn pipeline, migrate turns, dead letters and startup recovery, and from M2 the timer wheel. | `kronik-sched` |
| Turn executor | Wasmtime configured for determinism, a code store per hash, the deploy-time import check, a fresh instance per turn, the host side of the WIT, and the fuel and memory limits. | `kronik-runtime` |
| Effect gate (M2) | Checks capabilities against the configuration of the turn's epoch, writes `TurnBegin` before the first external effect, inserts secrets, applies rate limits, records every result, and returns recorded results when a turn runs again. | `kronik-sched`, `kronik-effects` |
| Log | Append-only segment files of Protobuf records, each with a CRC and an LSN; a group-commit writer that acknowledges an append after fsync; recovery of a torn tail. | `kronik-log`, `kronik-proto` |
| State | `state.db` per branch and one SQLite database per actor, written only by the applier, in LSN order, from committed records. | `kronik-store` |
| Secret store (M2) | The master key and the encrypted secret store. | `kronik-privacy` |

M3 adds the fork engine with replay and the behavior diff, and policy and
approvals; M5 the MCP server for agents, which serves the JSON API's
operations as tools; later milestones add shipping and restore (M6) and
foreign actors in gVisor (M7).

## A turn, step by step

1. **Admission.** The gateway matches a route and admits a root input with a
   fresh root id. An operator message through the API is a root input too; a
   message from another actor is not. A repeat of a committed request with
   the same `Idempotency-Key` gets the saved response instead of a new turn.
2. **Scheduling.** The scheduler queues the input in the actor's mailbox.
   When the actor's turn comes, it gets an execution id, a 32-byte seed and
   its logical time, the largest of the host's clock, the largest time
   already handed out and the time of the input that started it
   ([ADR 0006](../adr/0006-logical-time.md)).
3. **Execution.** The runtime creates a fresh instance of the kind's current
   code hash and calls `handle`. The guest sees the actor's state at the
   start of the turn plus its own writes. The host buffers state writes, SQL
   changes (run in a savepoint and captured as changesets,
   [ADR 0005](../adr/0005-sql-state.md)), outgoing messages and timer
   operations.
4. **Effects (M2).** Before the turn's first external effect, first `call`
   or first use of a secret, the gate appends and fsyncs a `TurnBegin` record
   with everything needed to run the turn again (I14). Each effect's result
   is appended and fsynced as an `EffectResult` before the guest sees it.
5. **Commit.** The turn record carries the input, the outcome, the writes,
   the SQL changesets, the messages, the timer operations, the effects and
   the fuel used. Only after it is fsynced are the writes applied, the
   messages put in their receivers' mailboxes, the timers registered and the
   response sent. A failed turn writes a failed turn record and discards
   what it buffered; a failed message or timer becomes a dead letter.
6. **Recovery.** At startup, a torn tail of the active segment is truncated,
   a corrupt record anywhere else stops the startup with `STORAGE_CORRUPT`,
   and the applier catches up from the log. From M2, every turn that has a
   `TurnBegin` but no turn record runs again with its recorded effect
   results before the gateway and the API accept requests.

## Crates

| Crate | Responsibility | Code since |
| --- | --- | --- |
| `kronik` | The binary: the CLI and `kronik serve` | M1 |
| `kronik-core` | Ids, causal keys, logical time, error codes and `kronik explain` texts, and the I/O boundary `Env` | M1 |
| `kronik-proto` | The Protobuf schema of the log and the code generated from it | M1 |
| `kronik-log` | Segment format, group-commit writer, reader and recovery | M1 |
| `kronik-store` | `state.db`, the applier and the SQL state per actor | M1 |
| `kronik-runtime` | Wasmtime configuration, code store, import allowlist, host implementations of the WIT, limits | M1 |
| `kronik-sched` | The scheduler and the turn pipeline; from M2 also the effect gate, `call`, compensations, timers and re-runs | M1 |
| `kronik-gateway` | HTTP ingress, routing and idempotency at ingress | M1 |
| `kronik-api` | The JSON API over the Unix socket, and the request and response types the CLI shares | M1 |
| `kronik-sim` | Deterministic simulation testing of the whole daemon | M1 |
| `kronik-effects` | Capabilities, grants and limits per epoch, delivery classes, HTTP fingerprints, secret headers and scrubbing, host-side cryptography, rate limits | M2 |
| `kronik-privacy` | The master key and the secret store; sealed values, erasure, reseal and pseudonyms follow in M8 | M2 |
| `kronik-fork` | Branches, isolated and continuous replay, the diff engine, proposals | M3 |
| `kronik-policy` | CEL rules against behavior diffs, approvals and guards | M3 |
| `kronik-mcp` | The MCP server on top of the JSON API, at `/mcp` on the API socket and through `kronik mcp` | M5 |
| `kronik-ship` | Shipping to and restore from S3-compatible object storage | placeholder until M6 |
| `kronik-foreign` | Foreign actors: OCI images, bundles, `runsc` and the bridge into the sandbox | placeholder until M7 |

Later releases add `kronik-cluster` (v0.4), `kronik-blob` (v0.5),
`kronik-ui` and `kronik-otel` (v0.6) and `kronik-fleet` (v0.7).

**Functional core, imperative shell.** The daemon crates do all I/O through
`kronik_core::env::Env`: clock, task spawning, file system, network, entropy
and processes. `Env` has a real implementation on tokio and the standard
library and a simulated one in `kronik-sim`, which runs the same daemon code
on a seeded single-threaded executor with injected crashes
([ADR 0004](../adr/0004-deterministic-simulation.md)). Clippy's
`disallowed-methods` keeps direct calls to the clock, to thread and task
spawning, to sleeps and timeouts and to the OS random source out of daemon
code; the real `Env` implementations opt out per module.

## Data on disk

```text
<data>/code/<blake3-hex>.wasm                          components, by code hash
<data>/code/<blake3-hex>.<engine-version>.cwasm        precompiled code, a cache
<data>/branches/main/log/<start lsn, 20 digits>.seg    the log
<data>/branches/main/state.db                          materialized state
<data>/branches/main/sql/<2 hex>/<actor>-<8 hex>.db    SQL state, one file per actor
<data>/keys/master.key                                 the master key (M2)
<data>/keys/secrets.db                                 the secret store (M2)
```

The data directory is `/var/lib/kronik` unless `kronik serve --data-dir`
says otherwise. The log is the truth (I4): `state.db` and the SQL databases
are derived from it and are brought up to date from it at startup, and the
precompiled code is a cache for this machine only. The secret store is not
in the log; the log refers to a secret by its name and a keyed hash of its
version.

A segment starts with a header (magic `KRNK`, format version, start LSN,
branch name and a CRC) and holds entries of the form
`[u32 len][u32 crc32c][u64 lsn][u8 kind][protobuf]`. LSNs increase by one
across all record kinds and segments. A segment is closed at 64 MiB or after
60 seconds, and a closed segment is never changed again.

| Record | Written by |
| --- | --- |
| `TurnBegin` | a turn, before its first external effect or `call` (M2) |
| `EffectResult` | a turn, before the guest sees an effect's result (M2) |
| `TurnRecord` | every finished turn, committed or failed |
| `Deployment` | deploy; promote and rollback from M3 |
| `Grant` | grant and revoke (M2) |
| `Limits` | limits set (M2) |
| `Policy` | policy set (M3) |
| `Approval` | approve (M3) |
| `PrivacyMode` | privacy mode (M8) |
| `ForeignActor` | foreign add and remove (M7) |
| `BranchCreated` | fork create (M3) |
| `Erasure` | privacy erase (M8) |
| `EngineUpgrade` | upgrade (M6) |
| `SnapshotMarker` | snapshot (M6) |
| `SimulatorConfig` | stubs set: a target's effect simulators (M12) |
| `StateRebase` | rollback via replay: the replayed turns and the switch (M13) |
| `GuardTriggered` | a `kronik watch` guard that fired (M11) |

A record with an enum value of 0 or an unknown enum value is
`STORAGE_CORRUPT`; it is never read as a default.

## Decisions

The architecture decision records hold the choices that the brief left
open, with the alternatives and the measurements behind them:

- [ADR 0001](../adr/0001-wasmtime-determinism.md): Wasmtime pinned at an
  exact version and configured for determinism (NaN canonicalization,
  deterministic relaxed SIMD, no threads, fuel instead of epochs), a fresh
  instance per turn from a pre-linked component in a pooling allocator,
  deterministic WASI and the deploy-time import allowlist.
- [ADR 0002](../adr/0002-typescript-components.md): TypeScript components
  built with jco and ComponentizeJS, without the `http`, `fetch-event` and
  `stdio` features, so that they stay inside the allowlist (M4).
- [ADR 0003](../adr/0003-gvisor-bridge.md): foreign actors in gVisor with
  `runsc` on the `systrap` platform, which needs no KVM, in a network
  namespace with only loopback, reached through `runsc port-forward
  --stream` (M7).
- [ADR 0004](../adr/0004-deterministic-simulation.md): deterministic
  simulation testing on Kronik's own executor rather than madsim, and the
  `Env` trait set that the daemon does its I/O through.
- [ADR 0005](../adr/0005-sql-state.md): per-actor SQL state with SQLite
  sessions and changesets, one file per actor, deterministic time and
  randomness inside SQL, and the deny list.
- [ADR 0006](../adr/0006-logical-time.md): logical time adds 1 ms over the
  log's high-water mark only when a new process starts, not on every turn.
- [ADR 0007](../adr/0007-policy-cel.md): policy rules in CEL, evaluated by
  the `cel` crate against the behavior diff (M3).
- [ADR 0008](../adr/0008-mcp-server.md): the MCP server, built with the
  official Rust SDK (rmcp) over the in-process JSON API (M5).
- [ADR 0009](../adr/0009-acme-instant-acme.md): TLS in the gateway with
  rustls, and ACME with instant-acme (M6).
- [ADR 0010](../adr/0010-openapi-schemars.md): the OpenAPI description and
  the CLI's JSON schemas, generated from the API's types with schemars (M5).

The design documents fix the interfaces of a milestone before it is built:
[M1 core design](../design/m1-core.md) (crates, log format, ids, JSON API
and the guest SDK contract), [M2 effects design](../design/m2-effects.md)
(the effect pipeline, re-runs after a crash, `call` and compensations,
grants, limits, secrets and timers) and [M3 fork design](../design/m3-fork.md)
(forks, replay, the behavior diff, proposals, promote and rollback, and the
policy interface).
