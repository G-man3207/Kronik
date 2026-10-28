# M1 core design

Status: binding for M1 work. Owner of the daemon core: the core worker. This
document fixes the interfaces other workers build against: the crates' main
types, the v1 log format, the id formulas, the JSON API, and the guest SDK
contract. The ADRs it relies on: 0001 (Wasmtime), 0004 (Env and DST),
0005 (SQL state).

## 1. Crates and their main types

| Crate | Exposes |
| --- | --- |
| `kronik-core` | `env` (`Clock`, `Spawner`, `EntropySource`, `Fs`/`File`, `Net`, `ProcessRunner`, `Env`, `JoinHandle`, `Env::{spawn, blocking, timeout, random_bytes}`); `env::real` behind feature `real` (tokio/std implementations, ADR 0004); `ids` (`ActorRef`, `Lsn`, `TurnId`, `ExecutionId`, `CodeHash`, `RootId`); `causal` (`CausalKey`, `causal_id()`, `message_id()`, `idempotency_key()`); `time` (`LogicalClock`, I15); `error` (`ErrorCode`, `ApiError`; content owned by the docs/CLI worker). |
| `kronik-proto` | Generated prost types `kronik_proto::log::v1::*` from `proto/kronik/log/v1/*.proto` (built with `prost-build` + `protox`, no `protoc` needed); `Record` (enum over all record types) with `kind()`, `encode()`, `decode(kind, bytes)`; `validate()` that turns enum 0, unknown enum values and missing required oneofs into `Corrupt`. |
| `kronik-log` | Segment format and envelope; `Log` (group-commit writer: `append(Record) -> Lsn` resolves after fsync; committed records are streamed in LSN order to the applier); `scan_dir()`/`LogReader` (read from an LSN); recovery (torn-tail truncation of the active segment, `STORAGE_CORRUPT` otherwise); segment rolling at 64 MiB or 60 s. |
| `kronik-store` | `StateDb` (`state.db`, SQLite WAL) and the `Applier` (`apply(lsn, &Record)`, single writer, LSN order, `applied_lsn` + logical-time high-water mark in the same transaction); read queries for the API (actors, kv, history, dead letters, deployments, ingress keys); `sql::SqlActor` + `SqliteOpener` (`FileOpener`, `MemOpener`) + an LRU pool (ADR 0005). |
| `kronik-runtime` | Engine configuration (ADR 0001), `CodeStore` (`code/<hex>.wasm` + `code/<hex>.<engine>.cwasm`), `check_imports()` (`IMPORT_NOT_ALLOWED`), `Program` (pre-linked component per hash), `describe()`, `run_turn(TurnRequest, &dyn TurnHostEnv) -> TurnOutput`, deterministic WASI, fuel and memory limits. |
| `kronik-sched` | `Node`: actor activation and per-actor serialization, mailboxes, logical time, the turn pipeline (run → `TurnRecord` → durable → applied → deliver → respond), migrate turns, dead letters, startup recovery, `submit(RootInput) -> TurnResult`; `Probe` for DST observations. |
| `kronik-gateway` | `Gateway::handle(HttpRequest) -> HttpResponse`: route table from deployments, root inputs, ingress idempotency, the 30 s turn timeout (504, turn continues); `serve()` binds it to hyper on TCP (no TLS in M1). |
| `kronik-api` | `Api::handle(ApiRequest) -> ApiResponse` (section 4) and `serve_unix()` (hyper over the Unix socket, mode 0660); request/response types shared with the CLI client (`kronik_api::types`). |
| `kronik-sim` | The deterministic executor, simulated `Env`, crash models and the DST scenarios; custom test harness (`cargo test -p kronik-sim -- --seed N`). |
| `kronik` | `kronik serve` (daemon wiring) and the CLI client subcommands. |

Daemon crates (`kronik-log`, `kronik-store`, `kronik-runtime`,
`kronik-sched`, `kronik-gateway::service`, `kronik-api::service`) use only
`Env` and executor-agnostic `tokio::sync`; see ADR 0004 section 3 for the
enforcement in CI.

## 2. Log format v1

### Files

```text
<data>/code/<blake3-hex>.wasm
<data>/code/<blake3-hex>.<engine-version>.cwasm
<data>/branches/main/log/<start-lsn, 20 digits>.seg
<data>/branches/main/state.db
<data>/branches/main/sql/<2 hex of blake3(actor)>/<actor>-<8 hex>.db
```

### Segment

- Header (28 bytes + branch): magic `KRNK`, `u32` format version (1),
  `u64` start LSN, `u32` branch name length, branch name bytes, `u32`
  crc32c of everything before it. All integers little endian.
- Entries: `[u32 len][u32 crc32c][u64 lsn][u8 kind][protobuf]`. `len` is
  the protobuf length, and the crc covers `lsn`, `kind` and the protobuf.
  LSNs are strictly increasing by 1 across all record kinds and segments.
- Rolling: a new segment starts at 64 MiB or 60 s; a segment is closed
  (immutable) once the next one is fsynced. The reserved kind 255 is now
  written then: a footer index from actor to offset (ADR 0011). Readers
  skip it, and a segment with no footer still reads.
- Recovery: in the active (last) segment, everything from the first entry
  that fails its length, CRC or LSN-continuity check is a torn tail and is
  truncated (and fsynced). A failure in a closed segment, or an entry that
  passes its CRC but does not decode or validate, is `STORAGE_CORRUPT`.

### Record kinds (envelope `kind` byte)

| Kind | Message | Written by |
| --- | --- | --- |
| 1 | `TurnBegin` | the turn, before its first external effect or call (M2) |
| 2 | `EffectResult` | the turn, before the guest sees an effect result (M2) |
| 3 | `TurnRecord` | every finished turn, committed or failed |
| 4 | `Deployment` | deploy, promote, rollback |
| 5 | `Grant` | grant, revoke (M2) |
| 6 | `Limits` | limits set |
| 7 | `Policy` | policy set (M5) |
| 8 | `Approval` | approve (M5) |
| 9 | `PrivacyMode` | privacy mode (M8) |
| 10 | `ForeignActor` | foreign add/remove (M7) |
| 11 | `BranchCreated` | fork create (M3) |
| 12 | `Erasure` | privacy erase (M8) |
| 13 | `EngineUpgrade` | upgrade (M6) |
| 14 | `SnapshotMarker` | snapshot (M6) |
| 17 | `GuardTriggered` | a `kronik watch` guard that fired (M11) |

0 and any other value (15 and 16 are reserved) are `STORAGE_CORRUPT`, except kind 255, the footer readers skip. The messages are in
`proto/kronik/log/v1/` (`common`, `input`, `turn`, `config`, `branch`).
Decisions beyond the brief:

- `TurnRecord` adds `config_epoch` (20), `memory_peak_bytes` (21) and
  `schema_version` (22); `TurnBegin` adds `config_epoch` (9).
- `EffectRecord` keeps the brief's string `kind` and `delivery` and adds the
  enums `status` (9) and `grounding` (10).
- `Outcome` is `{kind, error_code, message, reply | http}`; neither output
  set means `output::none`. Failed turns keep their effects and
  compensations but have no writes, messages, timers or SQL changes.
- `Input` is a oneof of `HttpInput` (with route, params, ingress
  `idempotency_key` and `request_hash`), `MessageInput` (with `source`,
  `message_id`, `sent_logical_time_ms`, `resend_of`, `audit`), `TimerInput`
  and `MigrateInput {from, to}`.
- All configuration records carry `epoch` and `Audit {token_id, reason,
  wall_time_ms}`; `Deployment` records each kind's `Manifest` so routes are
  history.
- Every user-data field is `Sealable` (message bodies, header values, state
  values, SQL changesets, effect requests and responses). In M1 every
  `Sealable` is `plain` with its subject tag.

### Materialized state (`state.db`)

Derived from the log (I4); one SQLite file per branch, WAL,
`synchronous=NORMAL`.

| Table | Content |
| --- | --- |
| `meta` | `applied_lsn`, `time_hwm`, `config_epoch` |
| `actors` | `kind, key, schema_version, first_lsn, last_lsn, turns, sql` |
| `kv` | `kind, key, k, value, subject, lsn` |
| `turn_index` | `lsn → kind, key, segment, offset, outcome` for `history` (details are read from the log) |
| `mailbox` | messages committed by a sender and not yet consumed: `message_id, to_kind, to_key, lsn, ordinal, input, causal` (the receiver's input and causal key) |
| `deliveries` | `message_id → lsn` of the consuming turn (dedup; saved `call` responses from M2) |
| `ingress_keys` | `kind, key, idem_key → request_hash, lsn, logical_time_ms, outcome` |
| `dead_letters` | `lsn → kind, key, input, error_code, message, resent_as` |
| `deployments`, `kinds` | every `Deployment`; each kind's current `KindVersion` |

`kv_versions` (M3), `grants`, `limits` (M2), `policies` (M5) and
`orphans` (M2) are created by the milestones that write them.

Per-actor SQL databases live next to it (ADR 0005), each with its own
`applied_lsn`. `state.db` and the actor databases commit independently
(`synchronous=NORMAL`), so recovery replays the log from the lowest applied
LSN of all of them and each target skips records it already has.

## 3. Ids and formulas

All hashes are BLAKE3. Hex is lowercase.

| Id | Formula |
| --- | --- |
| Code hash | `blake3(component bytes)`; shown as `b3:` + 12 hex characters |
| Engine version | `kronik-<semver>+wasmtime-<semver>` |
| Root id | 16 bytes from `EntropySource`, 32 hex characters; assigned when a root input is admitted, then read from the log in replay |
| Causal key encoding | `"kronik.causal.v1\0" + root + for each step: kind + "\0" + key + "\0" + u32_le(ordinal)` |
| Causal key of a root turn | `{root, []}` |
| Causal key of a child | parent key + step `{actor: producing actor, ordinal: producing turn's op ordinal}` |
| Causal key of a migrate turn | the triggering input's key + step `{actor: self, ordinal: 4294967295}` |
| `causal-id` (guest-visible) | 32 hex characters of `blake3(causal key encoding)` |
| Op ordinal | one counter per turn, starting at 0, incremented by `send`, `call`, `timers.schedule` and every external effect |
| Message id | 32 hex characters of `blake3(causal key encoding + u32_le(ordinal))` of the producing turn; for root inputs the root id |
| Idempotency key (outgoing effect) | `hex(blake3(causal key encoding + u32_le(ordinal)))` (64 hex characters) |
| Execution id | 16 bytes from `EntropySource`, 32 hex characters; never guest-visible; a re-run after a crash keeps its `TurnBegin`'s id |
| Turn id | `<branch>:<lsn>` of the `TurnRecord` |
| Turn seed | 32 bytes from `EntropySource` |
| Logical time | `max(clock.wall_ms(), hwm, parent)` where `parent` is the message's `sent_logical_time_ms` or the timer's `due_ms`, and `hwm` is the largest logical time handed out; at startup `hwm` is the largest logical time in the log plus 1 ms (kept as `meta.time_hwm`, the maximum over all `TurnBegin` and `TurnRecord` times). Within one run several turns may share a millisecond: adding 1 ms per turn would drift ahead of the wall clock above 1000 turns per second (ADR 0006) |

## 4. JSON API (`/v1` over the Unix socket)

HTTP/1.1 over `<api_socket>` (default `/run/kronik/api.sock`, mode 0660,
group `kronik`). Bodies are JSON. Until M5 the token id is
`unix:uid=<peer uid>`.

Every mutation body has `"reason": string` (required, non-empty, else
`REASON_REQUIRED`) and `"dry_run": bool` (default false; a dry run returns
the same response shape with `"dry_run": true` and the plan, and writes
nothing).

Errors always look like this, with the HTTP status from the error catalog:

```json
{ "error": { "code": "ACTOR_NOT_FOUND", "message": "...", "hint": "...", "docs": "kronik explain ACTOR_NOT_FOUND" } }
```

Byte payloads are given either as `"text"` (UTF-8) or `"base64"`; responses
carry both `"text"` (when the bytes are valid UTF-8) and `"base64"`.

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /v1/health` | | `{"status":"ok","version":"0.1.0-dev","engine":"kronik-…+wasmtime-…","applied_lsn":N,"branch":"main","http_listen":"127.0.0.1:8080"}` |
| `POST /v1/deployments` | `{"wasm_base64":"…","reason":"…","dry_run":false}` | `{"dry_run":false,"deployment":{"epoch":N,"lsn":N,"kind":"counter","code_hash":"b3:…","schema_version":1,"routes":[{"method":"POST","pattern":"/counter/{key}/increment"}],"capabilities":[…]},"warnings":["capability http:x is not granted; run: kronik grant counter http:x --reason '…'"]}`. Errors: `IMPORT_NOT_ALLOWED` (lists imports), `VERIFY_REQUIRED` (kind has history), `ROUTE_CONFLICT`, `TURN_FAILED` (describe trapped). |
| `GET /v1/deployments` | | `{"deployments":[{"epoch","lsn","cause","kinds":[{"kind","code_hash","schema_version"}],"reason"}]}` |
| `POST /v1/actors/{kind}/{key}/messages` | `{"name":"…","content_type":"…","text"|"base64":…,"subject":null,"reason":"…","dry_run":false}` | `{"dry_run":false,"turn_id":"main:N","outcome":{"kind":"committed","error_code":null,"message":null},"reply":{"name","content_type","text","base64"}}`. The call waits for the turn and answers 200 with its outcome also when it did not commit: `outcome.kind` is then `rejected`, `failed`, `trap`, `fuel_exhausted`, … with `error_code` (`TURN_FAILED`, `FUEL_EXHAUSTED`, …) and `message`, and `reply` is null; `kronik send` exits 1 for any outcome but `committed`. Errors: `ACTOR_NOT_FOUND` (unknown kind). |
| `GET /v1/actors?kind=&after=&limit=` | | `{"actors":[{"kind","key","schema_version","turns","last_turn_id","sql":bool}],"next":"kind/key"|null}` |
| `GET /v1/actors/{kind}/{key}` | | `{"actor":{…},"state":[{"key","text","base64","subject","lsn"}],"sql":{"tables":[{"name","rows":N}]}}` |
| `GET /v1/actors/{kind}/{key}/history?before=&limit=` | | `{"turns":[{"turn_id","lsn","logical_time_ms","code_hash","input":{"type":"http"|"message"|"timer"|"migrate","summary":"…"},"outcome":{…},"writes":[{"op","key","subject"}],"messages":[{"to","name"}],"sql_changes":N,"fuel_used":N}],"next":lsn|null}` |
| `GET /v1/turns/{turn_id}` | | the full turn record as JSON (bodies as text/base64) |
| `GET /v1/dead-letters?after=&limit=` | | `{"dead_letters":[{"id":"main:N","actor":"kind/key","input":{…},"error_code","message","resent_as":"main:M"|null}]}` |
| `POST /v1/dead-letters/{id}/resend` | `{"reason":"…","dry_run":false}` | like the messages response. Errors: `DEAD_LETTER_NOT_FOUND`, `DEAD_LETTER_ALREADY_RESENT`. |

The CLI maps these one-to-one: `kronik deploy`, `send`, `actors list`,
`actors inspect`, `history`, `dead-letters list`, `dead-letters resend`;
`--json` prints the response body unchanged.

### Gateway (HTTP on `http_listen`, no TLS in M1)

- Routes come from the current deployments' manifests. A pattern segment
  `{name}` matches one path segment; `{key}` names the actor key (a route
  without `{key}` targets the actor `kind/_`). A request matching no route
  gets 404 `ROUTE_NOT_FOUND`; two kinds with the same method and pattern are
  `ROUTE_CONFLICT` at deploy time.
- The response is the guest's `output::http` (an `output::reply` becomes 200
  with the message body and content type; `output::none` becomes 204). A
  failed turn gives 500 `TURN_FAILED` with `"turn_id"` in the error message
  and header `Kronik-Turn-Id`. Every response carries `Kronik-Turn-Id`.
- `Idempotency-Key` (per actor): a repeat after commit gets the saved
  response; a repeat while the original runs waits for it until the
  gateway timeout, then gets 409 `IDEMPOTENCY_IN_FLIGHT`; the same key with
  a different request is 422 `IDEMPOTENCY_KEY_REUSED`.
- A turn that outlives the gateway timeout (30 s) gives 504
  `GATEWAY_TIMEOUT` and still completes.

### Error codes needed by M1 (for the catalog in `kronik-core::error`)

Brief codes used: `IMPORT_NOT_ALLOWED`, `ACTOR_NOT_FOUND`, `ROUTE_CONFLICT`,
`VERIFY_REQUIRED`, `TURN_FAILED`, `FUEL_EXHAUSTED`,
`IDEMPOTENCY_KEY_REUSED`, `IDEMPOTENCY_IN_FLIGHT`, `STORAGE_CORRUPT`,
`ENGINE_VERSION_MISMATCH`, `NOT_IMPLEMENTED`, `REASON_REQUIRED`. Added by
M1: `ROUTE_NOT_FOUND` (404), `GATEWAY_TIMEOUT` (504), `BAD_REQUEST` (400,
malformed API input), `PAYLOAD_TOO_LARGE` (413, message or body over the
limit), `DEAD_LETTER_NOT_FOUND` (404), `DEAD_LETTER_ALREADY_RESENT` (409),
`TURN_NOT_FOUND` (404), `UNAVAILABLE` (503, daemon starting or shutting
down), `INTERNAL` (500, a bug).

## 5. Guest SDK contract

The SDK (`sdk/rust`, `kronik-sdk`) is a thin layer over the WIT; the host
guarantees the behavior below.

| SDK operation | WIT |
| --- | --- |
| `ctx.state().get/set/delete/keys`, `get_json/set_json` | `state.get/set/delete/keys` (JSON is SDK-side) |
| `ctx.state().set_for(subject, key, value)` | `state.set-for` (**added in M1**) |
| `ctx.subject(s)` / `ctx.current_subject()` | `privacy.set-subject` / `privacy.current-subject` (**added in M1**) |
| `ctx.sql().query/execute` | `sql.query/execute`; `kronik_subject()` is available inside SQL |
| `ctx.send(to, msg)` | `messaging.send` |
| `ctx.call(to, msg, compensate)` | `messaging.call` (M2) |
| `ctx.http().fetch(req)` | `http-client.fetch` (M2; `denied` in M1) |
| `ctx.crypto()`, `ctx.secret(name)` | `crypto.*`, `http-client.secret-template` (M2) |
| `ctx.timers()` | `timers.schedule/cancel` (M2) |
| `ctx.now()`, `ctx.random()`, `ctx.causal_id()`, `ctx.self_ref()` | `context.*` |
| `ctx.log()` | `log.emit` |

Host behavior the SDK can rely on:

- `describe` runs at deploy in an isolated turn without state and effects:
  any import other than `log` traps there.
- A new actor of a kind with `schema_version > 0` first runs `migrate(0)`.
  After a deployment with a higher schema version, an existing actor first
  runs `migrate(old)`. DDL is allowed only there, before its first DML.
- Message bodies and state values are at most 1 MiB (`PAYLOAD_TOO_LARGE`
  at the API, a trap inside a turn). SQL values are at most 1 MiB
  (`sql-error::too-large`).
- The guest's default subject starts as the HTTP request's subject (from
  M8's `subject_from`) or the sending turn's default subject, else none.
- `causal-id` is stable between production and replay; the execution id is
  never visible.
- `wasi:clocks` and `wasi:random` are deterministic (ADR 0001); stdout and
  stderr become log events.

The WIT stays `package kronik:actor@0.1.0`; M1 added `state.set-for` and
`privacy.current-subject` (additive: components built against the earlier
draft still link). The WIT is frozen for v0.1 from here.

## 6. Deferred inside M1 and to later milestones

- `TurnBegin`, `EffectResult` and the re-run of unfinished turns exist in
  the format, but nothing writes them before M2 (no external effects or
  `call` in M1); the re-run on recovery is built with them.
- Segment footer index: M3. Grants, limits records: M2.
- `secret`, `crypto`, `http.fetch`, `timers`, `call`: the M1 host returns
  `denied` or traps with `NOT_IMPLEMENTED`.

## 7. Implementation decisions recorded in M1

- **Unrunnable inputs are recorded.** A message to a kind without a
  deployment, or an input whose actor's migration failed, gets a failed
  `TurnRecord` (`ACTOR_NOT_FOUND`, `TURN_FAILED`) without running code, so it
  leaves the mailbox and becomes a dead letter.
- **`Deployment.effective_lsn = 0`** means "effective at this record's own
  LSN" (a deploy cannot know its LSN before the append).
- **Live SQL apply uses the per-subject changesets** from the record (one
  `apply_v2` per subject), the same path as a rebuild; ADR 0005's unsplit
  live apply is an optimization left for later.
- **Torn tail.** In the active segment everything from the first invalid
  entry is truncated (ADR 0004): a torn batch can leave valid but
  unacknowledged entries after an invalid one. The brief's "a broken entry in
  the middle of a segment is `STORAGE_CORRUPT`" applies to closed segments.
- **The code store** writes `code/` with `std::fs` (write, fsync, rename,
  fsync dir) rather than `Env::fs`; the simulator keeps code in memory, as a
  code directory that survives crashes.
- **HTTP failures** (`rejected` and `failed` handler errors, traps, fuel)
  are 500 `TURN_FAILED` with the turn id; a guest that wants a 4xx returns it
  as `output::http`.
