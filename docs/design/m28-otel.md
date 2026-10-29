# M28: OpenTelemetry and audit export (design)

Status: design, revised after the design review (reviewer-designs: H1–H4,
M1–M9, L1–L6; each fix names its finding). Delivered in 9d1f65b. The
decisions are in ADRs 0080–0084.

B2 (trace and metrics export) is in, with these refinements:
- The open-turn set (§3.1) also decides links into other traces: a link
  names the cause's trace from the set while the cause is open or kept,
  else from its key (the root's, its open caller's, or the trace it
  started).
- A first start of the trace export, without a cursor, starts at the
  applied LSN: history is not replayed into a new backend. That cursor is
  saved before the first batch (code review Low), so a refused first batch
  is resent after a restart.
- `[otel] batch_spans` caps the log records read per request (each turn
  record gives its turn span plus one per effect).
- The cursor file is `{"traces": {"lsn": N, "state": …}, "audit": …}`:
  the trace stream's state is its open-turn set, `{"open": […], "kept":
  […]}` (an older plain list of open pairs still loads).

Code review fixes, export follower and traces (M28 code review):
- **M2:** a failed `audit.gap` record keeps the cursor before the gap: the
  follower counts it as an error (`last_error` is the sink's code), backs
  off and records the gap again; the gap is counted once it is recorded.
- **M3:** a batch also stops at 4 MiB of encoded records (`BATCH_BYTES`,
  for both streams); a larger record goes alone.
- **M7:** a committed callee that joined its caller's trace stays in the
  open-turn set ("kept") until its messages and timers have arrived, and,
  while its caller has not committed or failed with a compensation for it,
  so links from them name its span in the caller's trace. Kept turns are
  capped like open ones (100,000), dropping the oldest (a cancelled timer
  never arrives).
- **M8:** `kronik export rewind traces` rebuilds the open-turn set at the
  rewind point by replaying the retained log's beginnings and commits from
  an empty set, so a re-export sends the same spans. Chosen over refusing a
  rewind past open turns, which would refuse almost every rewind of a busy
  node. Limit: a turn begun before the first retained record and still
  open or kept there is unknown.
- **M9:** a malformed `headers_env` pair is reported by the variable and
  its position, a rejected `[otel] endpoint` by scheme and host, and S3
  failures (audit sink log and status, `audit verify`) by a classified code
  (`s3_forbidden`, `s3_not_found`, …), never by their text.
- **Lows:** a callee whose call timed out joins its caller's trace (the
  caller is kept until it arrives); a migrate turn's ids include its target
  schema version, and its link names the trace its input will join; the
  lag gauge is set on every failed delivery; an idle, caught-up follower
  refreshes the audit hold's time each interval, so `max_hold` measures
  lag, not idleness; the trace exporter runs under a supervisor that
  restarts it from its saved cursor after a panic (`last_error = "panic"`).
  The audit export is not supervised: its sink is not rebuilt from saved
  state, and a dead audit export keeps its hold, which `kronik doctor`
  reports as a stall once older than `[retention] history`, until the
  daemon is restarted. Clamping stays per batch (§3.3, documented).

B3 (audit export) is in, with these refinements:
- The audit cursor of a first start is the record before the first
  retained one (not 0), and the hold lags the cursor by one batch, so it
  never depends on a cursor not yet saved.
- `kronik audit verify` reads a directory sink's files by modification
  time, then name (LSNs repeat after a restore), and an S3 sink's objects
  by name, which starts with the wall time the batch was prepared (§4.4),
  so both are in write order after a restore too. It deduplicates on every
  compared field.
- `audit.config` is recorded after the stream's start cursor (so `from =
  "now"` exports it too), and not on a node that never had `[otel]` or
  `[audit]` on. The hash is over the settings in force, overrides included.
- `GET /v1/export` has `stalled_ms` (time since the last delivery while
  there is lag); `kronik doctor`'s `export` check reads it from a running
  daemon. For the audit stream it is the hold's age.
- The completeness test drives foreign add and remove as failures (no
  sandbox in CI), which must export nothing, as `mutations.rs` does.

Code review fixes (M28 code review):
- H-A: the first start after `kronik restore` clamps every stream in
  `export.json` to the restored log, and drops the trace stream's state
  when it clamps it, before it removes the marker, with export on or off
  (§4.2).
- H-B: no sink overwrites earlier lines when LSNs repeat: new files never
  reuse a name, object names start with the batch's preparation time, and
  the webhook's `idempotency-key` includes a hash of the body (§4.4).
- M1: a rewind's retention floor holds until the follower resends from it;
  a batch in flight does not raise it (§5).
- M4: free disk is measured for `hold_release` with `[log] disk_reserve`
  at 0 too (§5).
- M5: reasons, `AuditEvent` targets and details and approval commands are
  scrubbed when they are written (§4.3).
- M6: an erasure's `record_hash` covers its subject's keyed label, not the
  subject (§4.3).

## The brief

> **M28 OpenTelemetry och audit-export.** Kronik passar in i befintlig
> övervakning. Berör en ny crate `kronik-otel`.
>
> - Varje turn blir ett span. Meddelanden och anrop blir länkar, och
>   effekter blir underspan.
> - Mätvärden exporteras via OpenTelemetry och Prometheus.
> - Audit-loggen över alla mutationer exporteras löpande som JSON-rader till
>   fil, webhook eller objektlagring.
>
> * [ ] Ett anrop genom tre aktörer syns som en sammanhängande trace i en
>   vanlig OpenTelemetry-backend.
> * [ ] Den exporterade audit-loggen är fullständig jämfört med loggens
>   poster, och ett test jämför dem.

M28 builds on v0.1 and needs no other v0.2+ milestone. It can use M11's
`TurnRecord.duration_us` (field 23) if M11 is merged first (§3.3).

## 1. What exists today (main 07bdeae)

- **Log.** Every turn commits one `TurnRecord` (kind 3), with its `CausalKey
  {root, path}`, `logical_time_ms`, input, effects (`EffectRecord`, with
  `ordinal`, `kind`, `target`, `status`, `grounding` and `duration_us`) and
  outcome. Turns with live effects also write `TurnBegin` (1) and
  `EffectResult` (2) first. Callees commit before their callers.
- **Causal tree.** `CausalKey.root` is 32 lowercase hex characters (16
  random bytes), the size of a W3C trace id. A turn's parent key is its path
  minus the last step. That step names the actor that produced it and its
  operation ordinal, which is the call effect's ordinal for a call. `GET
  /v1/turns/{id}/trace` builds the tree this way.
- **Message sources.** `MessageInput.source` is ACTOR (a send), CALL,
  OPERATOR, DEAD_LETTER_RESEND or COMPENSATION. `TimerInput.scheduled_by`
  names the scheduling turn.
- **Time.** `logical_time_ms` is set when a turn starts: `max(wall, high
  water mark, parent)`, so it is close to the wall clock. There is no
  turn-level duration on main (M11 adds field 23). `EffectRecord.duration_us`
  is set only for live `http.fetch` and `foreign.http`, and no effect
  records a start time.
- **Metrics.** `kronik-metrics` has no dependencies. It keeps 12 metrics
  (counters, gauges, histograms) in a registry and `render()` writes the
  Prometheus text format. The admin listener serves it as `GET /metrics`.
  There is no API to read values back.
- **Audit.** `pb::Audit {token_id, reason, wall_time_ms}` is on these
  records:
  - Deployment (4), Grant (5), Limits (6), Policy (7), Approval (8),
    PrivacyMode (9), ForeignActor (10), Erasure (12), EngineUpgrade (13);
  - operator sends and resends (`MessageInput.audit` in the `TurnRecord`).

  `BranchCreated` (11) carries one only in fork logs. Twelve mutating
  routes write no audited record to main's log (§4.2), and six of them drop
  their `reason`.
- **Object storage.** `kronik-ship` uses `object_store` 0.14 (S3 and
  `file://`, ring, `AWS_*` from the environment).
- **Outgoing HTTP.** `Env::net().http(..)` uses hyper with rustls (ring) and
  native roots. `NetError::Connect` means "not sent"; `Io` means "maybe
  delivered".
- **Following the log.** `node.reader().read(from, upto, f)` plus
  `node.store().applied.wait(lsn)` follow the committed log in LSN order,
  with no scheduler change (reseal already does this). Retention (`Node::
  compact`) deletes closed segments without regard to any reader.
- **Not present:**
  - no OpenTelemetry, Prometheus or tonic crate in `Cargo.lock`;
  - no `tracing` span anywhere;
  - the gateway stores every incoming header (so a `traceparent` too) but
    does nothing with it.

## 2. Shape

A new crate, `kronik-otel`, with two exporters. Both follow the committed log
from a durable cursor and run as `env.spawn` tasks of `kronik serve`. Neither
runs in the turn path.

| Exporter | Reads | Sends | Delivery |
|---|---|---|---|
| traces | `TurnRecord` (kind 3) | OTLP/HTTP protobuf, `POST <endpoint>/v1/traces` | at least once, in LSN order; best effort past retention (§5) |
| metrics | the `kronik-metrics` registry, every `metrics_interval` | OTLP/HTTP protobuf, `POST <endpoint>/v1/metrics`, cumulative | each push replaces the last |
| audit | every audited record (§4.1) | JSON lines to a file directory, a webhook, or object storage | at least once, in LSN order, never past retention (§5) |

Prometheus stays as it is (`GET /metrics` on the admin listener). Together
with the OTLP push, that is what "mätvärden exporteras via OpenTelemetry och
Prometheus" asks for.

The crate depends on `kronik-core` (Env), `kronik-log`, `kronik-proto`,
`kronik-store` (applied LSN), `kronik-metrics`, `kronik-privacy` (keyed
hashes) and `object_store`. To respect the hygiene rule, it uses no tokio
runtime features of its own: it gets the clock, spawning and network from
`Env`.

## 3. Traces (ADR 0080, ADR 0081)

### 3.1 Spans and ids

- **Trace id:** `causal_key.root`, decoded from 32 hex characters. A root
  that is not 32 hex characters (only tests make those) maps to the first 16
  bytes of `blake3("kronik trace v1" ‖ root)`.
  - An incoming W3C `traceparent` never sets the trace id (review H1): a
    callee computes its trace id from its own record, and a CALL input
    carries no trace context, so an adopted trace id would split the trace.
    Instead the root span gets a **link** to the incoming span
    (`kronik.link = "traceparent"`), with only its two ids after a strict
    format check (version 00, non-zero ids). Backends show the link.
  - The header is read from the recorded input. A sealed one (privacy mode
    with a subject) is opened with the node's sealer; once its subject is
    erased, the link is left out, which is the only way a re-export can
    differ.
  - **A trace is one root and its synchronous calls.** Timers and sends
    start a new trace (review M1), linked to their cause: a timer's or a
    message's causal key is a child of the turn that caused it, so a
    self-rescheduling timer, or two actors messaging each other, would
    otherwise make one trace for their whole life, and backends cap trace
    size. This is also the brief's "meddelanden … blir länkar". The new
    trace's id is the first 16 bytes of `blake3_keyed(id key, "kronik trace
    v1" ‖ encode(key))` of the turn's own key.
  - **A callee's trace** is its caller's. The causal key does not say
    whether an ancestor started a trace (a timer's key looks like a send's),
    so the exporter keeps the trace id of every begun, uncommitted turn,
    read from `TurnBegin`. A call is synchronous, so its caller is always
    open when the callee's record arrives: the set is bounded by the turns
    in flight, and is saved with the cursor. A committed callee that
    joined its caller's trace is kept while its messages, timers or
    compensation are still to come, and a caller while the callee of a
    timed-out call has not run (code review M7). A turn whose parent is
    neither open nor kept for it (a compensation, which never joins a
    committed callee) starts its own trace, linked.
- **Turn span id:** the first 8 bytes of `blake3_keyed(id key, "kronik span
  v1" ‖ causal::encode(key))`. A migrate turn also hashes
  `u32_le(to_schema_version)`, in its span, effect span and trace ids: one
  input migrates twice under one key when a code switch lands during the
  first migration.
- **Effect span id:** the first 8 bytes of `blake3_keyed(id key, "kronik
  effect span v1" ‖ encode(key) ‖ ordinal)`.
- **The id key** (perf review P1): `causal::encode` holds every step's actor
  kind and key in plain, so an unkeyed id would let a backend confirm a
  guessed actor key (an e-mail, say) against an exported id, whatever
  `actor_keys` says. Every id but a root's trace id (16 random bytes) is
  therefore keyed, with `Sealer::keyed_hash("kronik otel ids v1", [])` from
  the master key, or on a node without one the same construction with the
  node-local key of §3.5.
- **Only deterministic functions of the record and the id key.** Any
  exporter with the key (a restarted one, a rewound one, another node with
  the same master key) computes the same ids, so a span sent twice is the
  same span. A callee can name its caller's call-effect span without any
  lookup.

### 3.2 Parents and links

"Meddelanden och anrop blir länkar" alone would not give one connected
trace: in a backend, spans without a parent in the trace show as separate
roots. So every turn has both a parent, inside the root's trace, and a link
that says how it was caused:

| The turn's input | Parent span | Link |
|---|---|---|
| HTTP root, operator send, resend | none (root span) | to the incoming `traceparent`'s span, if any, `kronik.link = "traceparent"` |
| `CALL` from turn T, effect ordinal n | T's `actor.call` effect span (n) | to that span, `kronik.link = "call"` |
| `ACTOR` (a send) from turn T | none: a new trace (§3.1) | to T's turn span, `kronik.link = "message"` |
| timer scheduled by T | none: a new trace (§3.1) | to T's turn span, `kronik.link = "timer"` |
| `COMPENSATION` | the turn its key path names, `child(child(key, caller, n), callee, COMP)`, if it is still open; else none (a new trace) | to the caller's turn span, `kronik.link = "compensation"` |
| migrate | none: the input turn runs after it | to the input turn's span, `kronik.link = "migrate"` |

- **Resends:** a resend has a new root, so it is a new trace. It gets a
  link to the dead-lettered turn's span (`kronik.link = "resend"`), whose
  trace id comes from that turn's record.
- **Span kinds:** HTTP root = SERVER, a call callee = SERVER, its caller's
  effect span = CLIENT, a send's receiver = CONSUMER, other effect spans =
  CLIENT, everything else = INTERNAL.
- **A link that is also the parent** (a call, a compensation while its
  callee is open) carries `opentracing.ref_type = "child_of"`. Jaeger's
  model merges a link to the parent into the parent reference and types it
  FOLLOWS_FROM otherwise, which showed every callee as asynchronous (found
  by `demo/vps-otel.sh`).

### 3.3 Times

- **Turn span start:** `logical_time_ms` (milliseconds).
- **Turn span end:** start + `duration_us` when the record has it (M11's
  field 23, from the start of the turn to its record). Records without it
  (before M11, or recomputed by a fork) end when their last child effect
  span ends, else 1 µs after the start.
- **Effect span start:** a new `EffectRecord.offset_us` (field 80), the
  effect's start as an offset from the turn's start (the same monotonic
  clock as M11's duration). Records without it start at the turn's start.
- **Effect span end:** start + `duration_us`.
- **Phase B work:** set `duration_us` for `actor.call`, crypto and reveal
  effects too; today only fetch sets it.
- **Children inside parents** (review M9): `logical_time_ms` has
  millisecond resolution and can run ahead of the wall clock, so an effect
  span is clamped into its turn span, and a callee's turn span into its
  caller's `actor.call` span when the exporter has the caller's record in
  the same batch. Otherwise the callee keeps its own time; backends handle
  the skew (Jaeger 2.22's default configuration does not adjust it). So a
  callee's times depend on where a batch was cut: a re-export cut
  differently can send the same span with other times. A wall-clock start
  in µs in the record would remove this and is a follow-up.
- **Clocks:** the times are what the record says. They are never the
  exporter's clock, so a re-export or a late export gives the same span.

### 3.4 Attributes (ADR 0082: what leaves the node)

**Resource:**
- `service.name` (`[otel] service_name`, default `kronik`);
- `service.version`;
- `kronik.node` (the branch, `main`);
- `kronik.engine`.

**Turn span:**
- name: `<kind> <input>`, e.g. `counter POST /counter/{key}/{op}` (the route
  pattern, never the path), `counter message increment`, `counter timer
  tick`;
- `kronik.turn_id` (`main:<lsn>`), `kronik.actor.kind`, `kronik.actor.key`
  (§3.5);
- `kronik.input` (http, message, timer or migrate), `kronik.message.name`,
  `kronik.message.source`;
- `http.request.method`, `http.route`, `http.response.status_code`;
- `kronik.outcome` (committed, rejected, failed, trap, fuel_exhausted,
  memory_limit, effect_outcome_unknown), `kronik.error_code`;
- `kronik.code_hash`, `kronik.config_epoch`, `kronik.fuel_used`;
- span status ERROR for every outcome except committed.

**Effect span:**
- name: the effect kind, e.g. `http.fetch`;
- `kronik.effect.kind`, `kronik.effect.ordinal`, `kronik.effect.status`,
  `kronik.effect.grounding`, `kronik.effect.delivery`;
- the target as its kind plus `server.address` for `http:<host>`, the actor
  kind for `actor:<kind>/<key>`, and the secret name for `secret:<name>`;
- span status ERROR for failed, timed-out and outcome-unknown effects.

**Never exported:**
- any `Sealable` value (bodies, headers, paths and queries of requests with
  a subject, message bodies, effect requests and responses, replies, writes);
- `Outcome.message` and `EffectRecord.error` (free text that guest code
  writes, which can hold a value read from state);
- query strings and paths (only the route pattern);
- subject ids.

Secrets never reach the log in plain, and a revealed value is scrubbed when
recorded (I8). Since none of the free-text fields above is exported, no
secret can leave this way.

### 3.5 Actor keys

Kronik's model treats actor keys as identities that are plain everywhere
(privacy guide). A key can still be an e-mail address
(`counter/carol@example.com`), and a third-party backend is outside the
node. So:
- `[otel] actor_keys = "hashed"` is the default. It exports
  `kronik.actor.key = "kh:" + 12 hex` of `Sealer::keyed_hash("kronik otel
  key v1", [kind, key])`: stable for correlation, and not reversible without
  the master key. A node without a master key (review M5) hashes with a
  node-local key, 32 random bytes in `<data>/otel.key` (0600), created at
  first use: still stable on that node and not reversible.
- `"plain"` exports the key as it is.
- `"none"` leaves it out.

The same rule applies to the target of an `actor.call` effect. Span and
trace ids hide actor keys in every mode: they are keyed with the same key
under their own purpose (§3.1).

### 3.6 Transport (ADR 0081)

- **OTLP over HTTP with protobuf**, the OTLP 1.x wire format: `POST
  /v1/traces` and `POST /v1/metrics`, `content-type:
  application/x-protobuf`.
- **Messages:** compiled from the `.proto` files of
  `open-telemetry/opentelemetry-proto` (Apache-2.0), vendored in
  `proto/opentelemetry/` and compiled with the workspace's protox +
  prost-build, as `kronik-proto` is. The exporter sends through `Env::net()`.
- **No OpenTelemetry crate and no gRPC** (ADR 0081 explains why).
- **Batching and retries:** up to `[otel] batch_spans` spans (default 512),
  4 MiB of encoded log records (code review M3; a larger record goes
  alone) or `[otel] interval` (default 5 s). A failed POST is retried with
  backoff (1 s doubling to 60 s, from `env.clock`).
- **HTTP answers:**
  - 2xx advances the cursor.
  - 400 (the collector refused the batch) is logged and skipped, with
    `kronik_export_dropped_total{stream="traces"}`.
  - 429 and 5xx are retried, honouring `Retry-After`.
- **Settings:**
  - `[otel] headers_env` names an environment variable that holds extra
    headers (`key=value,…`, as `OTEL_EXPORTER_OTLP_HEADERS`). Credentials
    stay out of the config file.
  - `https://` endpoints use the native roots.
  - `http://` to a host that is not loopback is refused at config check when
    `headers_env` is set (review L4): the headers usually carry credentials.

### 3.7 Metrics over OTLP

- **Read-back API:** `kronik-metrics` gets one public function,
  `snapshot() -> Vec<Sample>`, returning the registry's current values.
  Labels, counters, gauges and histograms (14 fixed bounds) are as
  `render()` writes them.
- **Export:** every `[otel] metrics_interval` (default 60 s), the exporter
  converts the snapshot to OTLP:
  - counters → monotonic cumulative `Sum`;
  - gauges → `Gauge`;
  - histograms → cumulative `Histogram` with explicit bounds;
  - `start_time` is the daemon's start.
- The scrape-time gauges (`kronik_applied_lsn`, disk) are set before each
  push as the admin endpoint sets them.

## 4. The audit export (ADR 0083)

### 4.1 What is exported: the audited records of main's log

The audit log is the log. The exporter writes one JSON line per **audited
record** of main's log, in LSN order. An audited record is:
- a record of kind 4–10, 12, 13, 15 (`SimulatorConfig`, M12), 17
  (`GuardTriggered`, M11), 16 when it is a rebase's switch (`StateRebase`,
  M13; its rebased turns are the fork's, not operator actions), or 40 (the
  new `AuditEvent`, §4.2);
- a `TurnRecord` whose input is a message with source `OPERATOR` or
  `DEAD_LETTER_RESEND`, which carries `MessageInput.audit`;
- each `secret.reveal` effect of any `TurnRecord` (review H3: the brief says
  a reveal "syns i audit"). One line per reveal effect, keyed by the turn's
  LSN and the effect's ordinal, naming the actor (per §3.5) and the secret,
  never the value.

The classifier is one function in `kronik-otel`. A unit test walks every
record message of `kronik-proto` and fails when one with an `Audit` field
is not classified (review M4), so a new audited kind cannot be missed.

Not exported:
- `TurnBegin` copies of that audit, because `TurnRecord` is the
  authoritative one;
- `SnapshotMarker` (no audit; snapshots made by request now get an
  `AuditEvent`);
- `BranchCreated`, which only fork logs have.

### 4.2 Mutations outside the log become log records

"Alla mutationer" is wider than the log today. The mutating routes in the
first table below change state outside main's log, or nothing durable, and
six of them drop their `reason`.

Phase B adds record kind **40, `AuditEvent`** (`config.proto`), as follows:

```proto
// A mutation whose effect is not a log record of its own (secrets, tokens,
// forks and proposals, snapshots, reseal): written after it succeeded, so
// that the log is the complete audit trail (M28, ADR 0083). Applying it
// changes no state.
message AuditEvent {
  string action = 1;   // e.g. "secret.set", "token.create", "fork.delete"
  string target = 2;   // the secret's or token's name, the fork or proposal id
  map<string, string> details = 3;  // plain, non-secret facts: scopes, version
  Audit audit = 4;
}
```

It is written by:

| Route | `action` | `target` | `details` |
|---|---|---|---|
| PUT `/v1/secrets/{name}` | `secret.set` | name | (none: written before the change) |
| DELETE `/v1/secrets/{name}` | `secret.delete` | name | (none: written before the change) |
| POST `/v1/tokens` | `token.create` | name | `scopes`, `token_id` (never the token) |
| POST `/v1/tokens/{name}/revoke` | `token.revoke` | name | `token_id` |
| POST `/v1/forks` | `fork.create` | fork | `at`, `no_pii` |
| DELETE `/v1/forks/{name}` | `fork.delete` | fork | |
| POST `/v1/forks/{name}/deployments` | `fork.deploy` | fork | `kinds` with code hashes |
| POST `/v1/forks/{name}/replay` | `fork.replay` | fork | `mode` |
| POST `/v1/forks/{name}/actors/{kind}/{key}/messages` | `fork.send` | fork | `actor` (per §3.5), `message` |
| POST `/v1/proposals` | `proposal.create` | proposal id | `kinds` with code hashes, `fork_lsn` |
| POST `/v1/privacy/reseal` | `privacy.reseal` | | `segments`, `values_sealed`, `tombstones` |
| POST `/v1/snapshots` | `snapshot.create` | snapshot id | `lsn` |
| POST `/v1/deployments/{epoch}/watch` | `watch.start` | watch id | `epoch`, `for_ms` |
| POST `/v1/deployments/{epoch}/rebase` | `rebase.create` | rebase id (`r-…`) | `rolled_back_epoch`, `base_lsn` |
| POST `/v1/watches/{id}/stop` | `watch.stop` | watch id | |
| POST `/v1/previews` | `preview.create` | preview id | `proposal`, `no_pii` |
| DELETE `/v1/previews/{id}` | `preview.delete` | preview id | |

Rules for `AuditEvent`:
- **Ordering, security-relevant routes** (review M3): secret set, secret
  delete, token create and token revoke append their `AuditEvent` *before*
  the change, as the intent. If the change then fails, a second event with
  the action plus `.failed` and the error code follows. A crash in between
  leaves an intent without a change, which over-reports: the safe side.
  Token create picks the token id before the append so the intent names it.
- **Ordering, the other routes:** the `AuditEvent` follows the change. A
  crash, or a dropped request, after the change and before the event's
  commit returns loses the event while the fork directory, proposal,
  rebase or snapshot remains; the window is the event's append (one
  group commit) after the change's own writes. The two routes that wait
  for a job write their event before waiting (perf review P3): `watch.start`
  is appended before the watch is saved and starts, so it precedes any
  guard record or rollback the watch writes, and a crash in between
  over-reports; `proposal.create` is appended once the job is started
  and before the request waits for its replay, so a client that times out
  or disconnects while waiting does not lose it.
- **The append is not refused by the disk reserve:** it uses the
  `check_alive` path, as incident records do, so an action that ran is
  recorded.
- **Dry runs write none.** Other failed actions write none.
- **System events** (`token_id = "system"`), written by the node itself:
  - `restore`, on the first start after `kronik restore` (review H4), with
    `through_lsn`: `restore` leaves a marker file, written durably as part
    of the staged install before its commit step, with the last LSN of the
    staged log (the snapshot's when no segment follows it), so restored
    state never comes without it (perf review R4). The start records the
    event unless the log after `through_lsn` holds it already (a crash
    after the event), then clamps every stream in `export.json` to
    `through_lsn` (the trace stream also loses its open-turn state, which
    describes the lost tail), durably, whether or not an export is on, and
    only then removes the marker (review H-A). A later start with
    `[audit]` on therefore exports the `restore` line and what follows;
    `restore --force` keeps an old `export.json`, and this is why;
  - `audit.gap`, for a range retention deleted before export (§5);
  - `audit.config`, at a start where `[audit]` or `[otel]` differ from the
    last recorded one (review L2), with the settings' hash and the sink's
    scheme and host.
- **Tests:** the existing `crates/kronik-api/tests/mutations.rs` lists
  every mutating route. It gains a column: the record each route writes,
  configuration record or `AuditEvent`. A new route without one fails the
  test.

### 4.3 The JSON line (`kronik.audit/v1`)

One object per line, UTF-8, `\n`-terminated, keys in this order:

```json
{"schema":"kronik.audit/v1","lsn":1234,"kind":"deployment","action":"promote",
 "at_wall_ms":1761500000123,"token_id":"token:ci-promote","reason":"PR #12",
 "branch":"main","epoch":7,
 "details":{"proposal_id":"p-…","kinds":[{"kind":"counter","code_hash":"b3:…","schema_version":0}]},
 "record_hash":"b3:<64 hex>"}
```

- **The dedup key is (`lsn`, `effect`, `record_hash`)** (review H4).
  Delivery is at least once. `effect` is the ordinal on reveal lines and
  absent otherwise. The LSN alone is not unique: after `kronik restore` from
  an older ship point, new records reuse the LSNs of the lost tail. The
  `restore` event marks the point, and `kronik audit verify` reports lines
  that share an LSN but conflict.
- **`record_hash`** is blake3 of a canonical form of the record: its
  encoding with every `Sealable` payload replaced by its subject tag (review
  M2). It reveals no value, and a reseal, which rewrites sealed payloads,
  leaves it unchanged. Anyone holding the log can check a line against it.
  An erasure's subject, the one field its line leaves out, is replaced by
  its keyed `s:` label (in the reason too), so a backend cannot test
  guessed subjects against the hash; `audit verify` reads the master key
  to compute it (code review M6). The same holds for the actor key in a
  `fork.send` event's `details.actor`, which the line hides: the hash
  covers `kind/` plus its keyed label (perf review R1).
- **`action` and `details` per kind:**

| Kind | `action` | `details` |
|---|---|---|
| Deployment | `deploy`, `promote` or `rollback` | `epoch`, `kinds`, `proposal_id`, `rollback_of_epoch` |
| Grant | `grant` or `revoke` | `kind`, `capability`, `delivery`, `rate` |
| Limits | `limits` | the limits |
| Policy | `policy` | `rules_hash` (b3 of the rules text) and the rule names |
| Approval | `approve` or `request_approval` | `proposal_id`, `diff_hash`, `verified_through_lsn`, `command` |
| PrivacyMode | `privacy.mode` | `mode` |
| ForeignActor | `foreign.add` or `foreign.remove` | `name`, `image` (the digest only: an `oci-layout:` reference is a local path), `port`, secret names |
| Erasure | `privacy.erase` | `subject` as `s:` + 12 hex (the diff's keyed subject hash), `key_version` |
| EngineUpgrade | `engine.upgrade` | `from`, `to` |
| SimulatorConfig | `simulators.set` | `target`, `stubs` (a count), `contract` (a flag: whether one is set), `neighbor`, `model` |
| GuardTriggered | `watch.guard` | `watch_id`, `guard`, `action`, `outcome`, `deployment_epoch`, `rollback_epoch` |
| StateRebase (switch) | `rollback.rebase` | `rebase_id`, `rolled_back_epoch`, `base_lsn`, `turns`, `diff_hash`, `irreversible_effects` |
| AuditEvent | its `action` | `target` and `details` |
| operator send / resend | `send` or `resend` | `actor` (per §3.5), `message` (the name; never the body), `resend_of` |
| `secret.reveal` effect | `secret.reveal` | `effect` (ordinal), `actor` (per §3.5), `secret` (the name), `version`, `status` |

- **Privacy (ADR 0082):**
  - No sealable value appears in a line, and no subject id.
  - `reason`, `command` and the AuditEvent's `target` and `details` are
    free text or names. They are scrubbed for every stored version of
    every secret (`kronik_effects::http::scrub_str` with
    `Node::secret_values()`), as the API does: once when the record is
    written (the API's `Audit`, `AuditEvent` and `Node::record_approval`;
    a `secret.set` also scrubs its new value from its reason), so a
    secret deleted before the export reads the record stays out of the
    log (code review M5), and again at export.
  - `reason` is capped at 4 KiB (a `"reason_truncated":true` key marks a
    cut). Phase B also caps it at the API: a `reason` over 4 KiB is
    `BAD_REQUEST`.
  - Reasons are exported as written, apart from the secret scrub. The one
    known exception (review M8): an Erasure's reason usually names the
    subject, so its subject id is replaced by the `s:` hash in the reason
    too. The operations guide says reasons leave the node.
- **Fixed fields:** `token_id` is the caller's token id (`token:<name>`,
  `unix:uid=<n>`, `kronik`, `system`), as the history shows it today.
  `at_wall_ms` is the audit's own `wall_time_ms`.

### 4.4 Sinks

`[audit] sink` is one URL:

- **Directory:** `file:///var/log/kronik/audit/`. Lines are appended to
  `audit-<first lsn:020>.jsonl` (mode 0640) and fsynced before the cursor
  moves. A new file starts at `[audit] file_max_bytes` (default 64 MiB),
  under a name no file has: `audit-<first lsn:020>.<n>.jsonl` when LSNs
  repeat after a restore or a rewind. An existing file is never opened at
  offset 0 (code review H-B). Newly created directories are fsynced into
  their parents.
  - **Torn lines** (review M7): at start, the newest file is truncated to
    its last `\n`, so a crash mid-append leaves no partial line for the next
    batch to continue.
  - Kronik never deletes a file; rotation is the operator's (logrotate or
    a copy to cold storage), and the operations guide says so (review L3).
    The sink starts a new file when the newest one is gone, replaced (another
    inode, as logrotate's `create` leaves it) or shorter than written (its
    `copytruncate`), never writing at a stale offset (perf review R5).
    The systemd unit gets `LogsDirectory=kronik`, so the default path is
    writable under `ProtectSystem=strict`.
- **Webhook:** `https://…`. One POST per batch of up to `[audit]
  batch_records` (default 500) lines, `content-type: application/x-ndjson`,
  with `kronik-audit-range: <first>-<last>` and `idempotency-key:
  <first>-<last>-<32 hex of the body's blake3>` headers: after a restore
  the same range carries other lines, which a receiver honouring the key
  must not answer from its cache (code review H-B).
  - 2xx is delivered.
  - 4xx other than 408 and 429 stops the export with
    `kronik_export_errors_total{stream="audit"}` and a warning. It retries
    with backoff, because dropping audit lines is never automatic.
  - Credentials come from `[audit] headers_env`, as for OTLP.
  - `http://` is allowed only to a loopback address.
- **Object storage:** `s3://bucket/prefix` with `[audit] endpoint`, using
  `kronik-ship`'s `Remote`: `put` becomes `pub`, with the same `AWS_*`
  credentials and ring provider. One object per batch,
  `<prefix>/audit/<prepared wall ms:020>-<first:020>-<last:020>.jsonl`. A
  retried batch overwrites itself; a batch over reused LSNs gets a name of
  its own, and names sort in write order for `audit verify` (code review
  H-B).

The sink is shown and refused like `[ship] url`: an unknown scheme is a
configuration error at start.

### 4.5 "Complete compared to the log's records"

The definition, which the test checks:

> For a log range (F, L], the set of exported lines, deduplicated by
> (`lsn`, `effect`, `record_hash`), equals the set of audited items of §4.1
> in (F, L]: audited records, and reveal effects. They are equal on (`lsn`,
> `effect`, `kind`, `action`, `token_id`, `at_wall_ms`, `record_hash`).
> There are no extra lines and no missing ones, and no two lines share
> (`lsn`, `effect`) with different hashes. The lines are in increasing
> `lsn` order, apart from retried batches that repeat earlier lines.

Here F is the cursor's start (0 on a new data directory). L is a point where
the export cursor equals the applied LSN.

**The tests:**
- **Completeness:** `crates/kronik/tests/audit.rs`, a real `kronik serve`
  with a file sink. It drives every mutating route from the
  `mutations.rs` table, sends and resends included (each once, plus a dry
  run of each, which must export nothing), and restarts the daemon once in
  between, so the cursor survives a restart. It waits for `kronik export
  status` to show the audit cursor at the applied LSN.
  - **Its expectations come from what it drove** (review M4), not from the
    exporter's classifier: the test keeps its own list of (route, action,
    reason, token) and requires exactly one line for each, plus one for a
    test actor's `secret.reveal`, plus the `restore` event after a restore
    step.
  - It then runs `kronik audit verify` (§6) over the sink, which reads the
    whole log with `LogReader` and must report complete.
  - Separate tests: export, reseal, verify still passes (review M2); a
    partial line injected before a restart is truncated (review M7); export,
    restore from an older ship point, mutate, verify passes and the reused
    LSNs are told apart by hash (review H4).
- **Privacy:** the same run uses a secret value, a subject id, a message
  body and a token secret as needles. The test checks that none of them
  appears in any exported line, while the reason of a mutation and the
  secret's name do appear.
- **Unit tests in `kronik-otel`:** one per record kind, checking the line
  (golden JSON).

### 4.6 Delivery and order

- **Batches:** the exporter reads from its cursor, builds a batch, delivers
  it to the sink, then advances the cursor.
- **Cursor:** `<data>/export.json`, `{"traces": <lsn>, "audit": <lsn>}`.
  It is written to a temp file, fsynced, renamed, and the directory
  fsynced (the `snapshots.rs` `write_synced` pattern).
- **Order:** in LSN order, at least once. A crash after delivery and before
  the cursor write re-sends that batch, so consumers dedup by (`lsn`, `effect`, `record_hash`).
- **Duplicates and gaps:** the only duplicates are such re-sent batches. The
  only gaps are the ones §5 makes visible, which never happen for audit
  while the hold is on.

## 5. Retention and reseal (ADR 0084)

Retention deletes closed segments once a snapshot covers them and they are
older than `[retention] history`. A slow sink would otherwise lose records.

- **Audit holds retention, but never production** (review H2). `Node::compact`
  takes a floor: it keeps every segment with records past the audit cursor.
  The floor is exposed as a `RetentionHold` that the exporter updates.
  - **Released before the disk reserve:** when free disk falls below
    `[audit] hold_release` (default 2 × `[log] disk_reserve`), compaction
    ignores the hold, deletes what retention allows, and the export records
    a gap. Below `disk_reserve` new root inputs are refused, so a sink that
    is down for days (or answers 401) would otherwise stop all turns: the
    core must not depend on an outside service (I10).
    Free disk is measured whenever retention runs, also with
    `disk_reserve = 0`, which would otherwise leave only `max_hold` to
    protect the disk (code review M4). Once the hold has given way, the
    once-a-second disk check runs retention itself, at most once a minute,
    so the release does not wait for the next snapshot pass (perf review
    R2). A configuration whose `hold_release` is at or below
    `disk_reserve` (`"0B"` with `"2x"`, or `"1x"`) and has no `max_hold`
    is refused, after the flags too: that hold could never give way
    before the reserve refuses work (perf review R3).
  - `[audit] max_hold` (default 0 = no time cap) can also cap the hold.
  - **A rewind holds at once** (`RetentionHold::rewind`): the floor drops
    to its point and stays there, under the same lock, until the follower
    delivers (or records a gap) from there; a batch in flight when the
    rewind came does not raise it (code review M1).
  - A gap is an `AuditEvent` `audit.gap` with the lost range, appended
    through the `check_alive` path (never refused by the reserve), and
    `kronik_export_gaps_total{stream="audit"}` counts it. The node keeps
    serving.
  - A sink that stays down shows in the export status,
    `kronik_export_lag_records{stream="audit"}`, and `kronik doctor`, which
    warns once the hold is older than `[retention] history`.
  - Test: a sink that answers 503, a disk budget near the reserve: compaction
    releases the hold, the gap record appears, root inputs are still
    admitted, and the gap metric counts it.
- **Traces do not hold retention.** Past retention, the trace export skips
  to the first segment and counts a gap.
- **Reseal** rewrites sealables only. Audit lines and spans export no
  sealable value, and `record_hash` is over the canonical form with each
  sealable replaced by its subject tag (§4.3), so a reseal changes nothing
  either exports.
- **Enabling export on an existing data directory.** The cursor starts at
  `[audit] from`: `"start"` (default; the first retained record) or
  `"now"` (the applied LSN at enable). The first line's `lsn` shows where
  it started.

## 6. Configuration, CLI and API

### 6.1 Configuration

Two new sections. `[telemetry]` is already the unknown-section example in
the config tests, so the names are `[otel]` and `[audit]`.

```toml
[otel]
endpoint = "http://127.0.0.1:4318"   # none: off
traces = true
metrics = true
service_name = "kronik"
actor_keys = "hashed"                # hashed | plain | none
interval = "5s"
metrics_interval = "60s"
batch_spans = 512
headers_env = "KRONIK_OTEL_HEADERS"  # the variable holding extra headers

[audit]
sink = "file:///var/log/kronik/audit/"   # none: off; file://, https://, s3://
endpoint = "http://127.0.0.1:3900"       # s3:// only, as [ship] endpoint
batch_records = 500
interval = "1s"
file_max_bytes = "64MiB"
headers_env = "KRONIK_AUDIT_HEADERS"
from = "start"                            # start | now
max_hold = "0s"                           # 0: no time cap on the hold
hold_release = "2x"                       # release below 2 x [log] disk_reserve
```

Environment overrides: `KRONIK_OTEL_ENDPOINT` and `KRONIK_AUDIT_SINK`.
`Config::check` refuses:
- an unknown scheme;
- `http://` to a non-loopback address for the webhook (OTLP may use plain
  HTTP to a local collector, the usual deployment, but not with
  `headers_env` set);
- `s3://` without a bucket;
- `endpoint` without `s3://`.

### 6.2 CLI and API

Every command has `--json`.

| CLI | API | Scope | What |
|---|---|---|---|
| `kronik export status` | GET `/v1/export` | read | per stream: enabled, the sink's or endpoint's scheme and host only (review M6: webhook URLs often carry credentials in the path), cursor, applied LSN, lag, last success, last error code (not its text, which can contain the URL), gaps |
| `kronik audit show [--from LSN] [--limit N]` | GET `/v1/audit?from=&limit=` | admin | the audit lines, as the sink receives them, from the log (also when the export is off) |
| `kronik audit verify [--sink URL] [--from LSN] [--to LSN]` | (local; no API) | — | compares a sink's lines with the log, by §4.5's definition. `--sink` is a `file://` or `s3://` URL (default: `[audit] sink`; a webhook cannot be read back, review L1). Prints the missing, extra and conflicting lines, and exits 1 if there are any. The completeness test runs it. |
| `kronik export rewind <stream> --to LSN --reason R [--dry-run]` | POST `/v1/export/{stream}/rewind` | operate | moves a cursor back to re-send (after a sink lost data). A mutation, so it has a reason and a dry run, and writes an `AuditEvent` `export.rewind`. |

`kronik audit show` uses scope `admin` because the lines name tokens and
callers, as `token list` does.

**Error codes:**
- `EXPORT_NOT_CONFIGURED` (409): `export rewind` for a stream that is off.
- `AUDIT_RANGE_GONE` (410): `audit show --from` or `rewind --to` before the
  first retained record. The hint names the first retained LSN.
- Bad LSNs reuse `BAD_REQUEST`.

**Metrics** (added to the catalog, so in `/metrics` and OTLP):
- `kronik_export_records_total{stream}`;
- `kronik_export_lag_records{stream}`;
- `kronik_export_errors_total{stream}`;
- `kronik_export_dropped_total{stream}`;
- `kronik_export_gaps_total{stream}`.

`kronik doctor` warns when a stream's last success is older than 10 ×
interval.

## 7. Dependencies

| Need | Choice | New crate? |
|---|---|---|
| OTLP messages | vendored `opentelemetry-proto` `.proto` files (v1.x, Apache-2.0) compiled with protox + prost-build | no (protox, prost and prost-build are in the tree) |
| HTTP client (OTLP, webhook) | `Env::net()` (hyper, hyper-rustls with ring, native roots) | no |
| Object storage | `object_store` through `kronik-ship`'s `Remote` | no |
| JSON | `serde_json` | no |
| Hashes | `blake3`, `Sealer::keyed_hash` | no |

**New third-party crates: none.**

Considered and rejected (ADR 0081):
- `opentelemetry` / `opentelemetry_sdk` / `opentelemetry-otlp` 0.33.1:
  - the SDK records live spans with the wall clock (we export recorded
    turns);
  - the batch processor needs its own runtime or thread (hygiene);
  - it is a 0.x API with frequent breaking releases;
  - `reqwest/rustls` and `opentelemetry-otlp/reqwest-rustls` pull in
    aws-lc-rs.
- `opentelemetry-proto` alone with `gen-tonic-messages` would be acceptable
  (prost only). It still couples us to its release train for a few stable
  files. If the vendored protos ever drift from the spec, it is the
  fallback.
- `tonic` (OTLP/gRPC): adds tonic, tower and the gRPC stack, and every
  common backend and collector accepts OTLP/HTTP.
- `tracing-opentelemetry`: Kronik has no `tracing` spans, and the spans come
  from the log.
- `opentelemetry-prometheus` / `prometheus`: `/metrics` exists.

**Licensing:** NOTICE gains the opentelemetry-proto attribution (Apache-2.0,
already allowed in `deny.toml`). No C code is added; the only C in the tree
remains SQLite (bundled), zstd, blake3, ring and wasmtime's, unchanged.

## 8. Proving the acceptance on the testbench

**"Ett anrop genom tre aktörer syns som en sammanhängande trace i en vanlig
OpenTelemetry-backend":**

- **The backend.** Jaeger v2 (`jaegertracing/jaeger`, pinned by digest) is
  an ordinary OpenTelemetry backend. It receives OTLP/HTTP on 4318 and
  serves its query API on 16686.
- **Where it runs:** in docker on `travelfiesta`, under the VPS lock
  (`flock /var/tmp/kronik-vps.lock`), as the install suites already use
  docker there. The batch row is `suite otel 'with_garage scripts/jaeger.sh
  demo/vps-otel.sh' 5` in a row `M28`.
- **`demo/vps-otel.sh`**, in the shape of `demo/vps-restore.sh`:
  1. Start Jaeger with `--rm` on free loopback ports (`scripts/jaeger.sh`,
     Jaeger 2.22.0 pinned by digest).
  2. Start `kronik serve` with `[otel] endpoint` set to it and
     `actor_keys = "plain"` (test data only).
  3. Deploy the test-actor counter. `POST /counter/a/call` with body
     `counter/b call`: counter/a calls counter/b, which calls counter/x.
     That is three actors in one root.
  4. Read the root's trace id from `kronik --json turn <id>` (the causal
     root).
  5. Wait for `kronik export status` to show the trace cursor past the
     turn's LSN.
  6. Poll `GET <query>/api/traces/<trace id>` (the UI's model: references
     and warnings) until it has the five spans (Jaeger's ingestion is
     asynchronous; 30 s limit), then read `/api/v3/traces/<trace id>` (OTLP
     JSON: links with their attributes, which the UI's model drops).
  7. Check in python3:
     - one trace;
     - three turn spans, of `counter/a`, `counter/b` and `counter/x`;
     - two `actor.call` effect spans;
     - every span except the root has its parent in the trace (Jaeger
       reports no "orphan" warnings);
     - each callee has a `call` link to its caller's effect span.
  8. Print `PASS`. Stop Jaeger and the daemon.
- **On a developer machine:** `scripts/jaeger.sh demo/vps-otel.sh`, like
  `scripts/minio.sh`.
- **In CI, without docker:** `crates/kronik/tests/otel.rs` starts an
  in-process OTLP receiver (a small hyper server that decodes
  `ExportTraceServiceRequest` with the vendored types). It makes the same
  three-actor call and the same connectivity checks, plus: the same call
  with a `traceparent` header keeps one trace and links it (review H1),
  and every child lies within its parent (review M9). The Jaeger run then
  proves that a real backend accepts and joins the spans.
- **Independent decode** (the review's caveat: the receiver test decodes
  with our own types): a golden `ExportTraceServiceRequest` produced by a
  reference implementation (the Collector's `telemetrygen`, captured once on
  the testbench) is checked in, and a CI test decodes it with the vendored
  types. Until it is captured, a hand-encoded request built from the
  spec's field numbers (not with prost) stands in.

**"Den exporterade audit-loggen är fullständig jämfört med loggens poster,
och ett test jämför dem":** `crates/kronik/tests/audit.rs` (§4.5), in the
normal test suite. On the testbench, the same `kronik audit verify` runs on
the `with_garage` S3 sink in `demo/vps-otel.sh`'s second half
(`kronik audit verify --sink s3://…`).

## 9. Determinism and invariants

- **Off the turn path:** both exporters read committed records only. They
  never run in the turn path and never affect what a turn sees (I1, I4).
  DST does not run them; the export unit tests drive them with the
  simulated `Env`.
- **I5:** the log is the audit trail, now including every mutation (§4.2).
  `AuditEvent` is additive: a new kind with compat fixtures (I16), and
  older binaries refuse to read it (unknown record kind), as for every new
  kind.
- **I7:** forks and previews export nothing (they have their own logs and
  no exporter).
- **I8:** no secret value leaves (§3.4, §4.3).
- **M8 privacy:** no sealable value and no subject id leaves; actor keys
  are hashed by default.

## 10. Numbering

- **ADRs:** 0080 spans from the log, 0081 OTLP transport and dependencies,
  0082 what leaves the node, 0083 the audit export, 0084 export cursors and
  retention.
- **Record kinds:** 40 `AuditEvent`. 41–44 are not used.
- **Proto fields:** `EffectRecord.offset_us = 80`. 81–89 are not used.
  `TurnRecord.duration_us` is M11's field 23. If M28 lands first, it takes
  that commit rather than adding a second field.
- **Error codes:** `EXPORT_NOT_CONFIGURED`, `AUDIT_RANGE_GONE` (milestone
  "M28").

## 11. Phase B plan

Each slice comes with its tests (failing before the change) and its docs.
Each runs the gates through `kronik-slot`.

1. **B1 `kronik-otel` core**
   - vendored OTLP protos and their build;
   - the span mapping (ids, parents, links, times, attributes, key hashing)
     as pure functions over `TurnRecord`s;
   - `EffectRecord.offset_us` and effect durations in the scheduler;
   - unit and golden tests, including the privacy needles.
2. **B2 trace and metrics export**
   - the exporter loop over `Env` (cursor file, batching, retries,
     `Retry-After`), and `kronik-metrics::snapshot`;
   - the OTLP metrics push and the new `[otel]` config;
   - `kronik export status`, GET `/v1/export`, the export metrics;
   - `crates/kronik/tests/otel.rs` with the in-process receiver;
   - `traceparent` as a link on HTTP roots;
   - the node-local hash key when there is no master key.
3. **B3 audit export**
   - B3a, in: record kind 40 `AuditEvent` with its compat fixture; the
     twelve routes writing it (intent first for secrets and tokens, with
     `<action>.failed` and `code` on failure; `kinds` is `kind=b3:<hex>`
     joined by commas); every `AuditEvent` written with `check_alive` only;
     the `mutations.rs` column and its real-run test; the `restore` event
     (`kronik restore` leaves `branches/<b>/restored.json`, the next `serve`
     writes the event with `through_lsn`, then deletes the marker); the
     `reason` cap;
   - B3b, the rest:
     - the line mapping for every kind, and the file, webhook and S3 sinks;
     - `[audit]` config, the retention hold and gap records;
     - `audit show`, `audit verify`, `export rewind`, the error codes;
     - `crates/kronik/tests/audit.rs`.
4. **B4 proof and docs**
   - `demo/vps-otel.sh`, `scripts/jaeger.sh` and the batch row;
   - an operations guide section (OTLP to a collector, Jaeger, Grafana
     Tempo; the audit sinks), privacy guide lines (§3.4, §4.3), `cli.md`,
     `json.md`, `openapi.json`, `errors.md`;
   - STATUS.

Before B2, a spike via `kronik-slot`:
- check that the vendored protos compile with protox 0.10 and prost 0.14;
- check that a recorded batch is accepted by Jaeger and by the OpenTelemetry
  Collector `otlphttp` receiver. That needs the docker images, and network
  once for the image pull.

## 12. Open questions for the owner

- The default for actor keys: `hashed` (proposed) or `plain`, which matches
  Kronik's "keys are identities" model.
- The audit hold's release point: below 2 × `disk_reserve` (proposed, after
  review H2), with no time cap by default.
- Whether outgoing `http.fetch` requests should carry a `traceparent`, so
  that services Kronik calls join the trace. This is not in the brief and
  is not proposed. It would add a header on the wire only (not in the
  recorded request), as `idempotency-key` is added.
