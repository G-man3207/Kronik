# WIT reference

Guest code is a WebAssembly component for the package `kronik:actor@0.1.1`,
defined in `wit/kronik-actor.wit` in the repository. Most actors use the
world `actor`: they export `handler` and may import Kronik's interfaces and a
deterministic part of WASI, nothing else. An actor that holds WebSocket or
SSE connections (M24) uses the world `actor-connections`, which adds the
`connections` import and the `connection-handler` export.

The package grows on the 0.1 track by additions only
([ADR 0113](../adr/0113-v05-actor-abi.md)): existing interfaces, types,
functions and worlds never change, new functionality comes as new
interfaces that are complete when they first appear, and a new export is
optional. Components built for `kronik:actor@0.1.0` link and run unchanged
([M1 core design](../design/m1-core.md), §5). The brief's single entry
point holds for the log, the scheduler and replay, where a connection event
is one more kind of input; in the WIT, a component that holds connections
has a second export.

This page covers every interface and function, what the host guarantees
about each, the determinism rules, the limits, and what v0.1 does not offer.
The [complete WIT](#the-complete-wit) is at the end.

| Interface | What it gives | Milestone |
| --- | --- | --- |
| [`handler`](#handler) (export) | `describe` and `handle` | M1 |
| [`types`](#types) | Shared records and variants | M1 |
| [`state`](#state) | The actor's key-value state | M1 |
| [`sql`](#sql) | The actor's SQLite database | M1 |
| [`context`](#context) | The actor's id, the causal id, logical time and randomness | M1 |
| [`messaging`](#messaging) | `send` (M1) and `call` (M2) | M1 |
| [`timers`](#timers) | Timers that fire as turns | M2 |
| [`http-client`](#http-client) | Outgoing HTTP, with secret headers | M2 |
| [`crypto`](#crypto) | HMAC and signatures with secrets the guest never sees | M2 |
| [`secrets`](#secrets) | Raw secret values, by exception | M2 |
| [`log`](#log) | Log events | M1 |
| [`privacy`](#privacy) | The subject that written values belong to | M1 |
| [`connections`](#connections) | Frames to WebSocket and SSE clients, and closing their connections | M24 |
| [`connection-handler`](#connection-handler) (export) | `open`, `frame` and `close` of a connection | M24 |

A turn is one call of `handle`, or of one `connection-handler` function. Everything it writes or sends is buffered by
the host and committed together with the turn record, or discarded if the
turn fails. A trap ends the turn as failed; so does a host function that
traps because a rule on this page is broken, with the rule in the turn's
error message.

## handler

```wit
interface handler {
  use types.{input, output, handler-error, manifest};
  describe: func() -> manifest;
  handle: func(input: input) -> result<output, handler-error>;
}
```

**`describe`** runs at deploy, in an isolated turn without state and without
effects, and returns the manifest:

- `kind`: the actor type that the component implements.
- `schema-version`: the version of the actor's state schema. A new actor of
  a kind whose schema version is above 0 first runs `migrate(0)`. After a
  deployment with a higher schema version, each existing actor first runs
  `migrate(old)` under the new code.
- `routes`: the HTTP routes, each a method and a pattern such as
  `/counter/{key}/increment`. A `{name}` segment matches one path segment
  and arrives in `http-request.params`; `{key}` names the actor's key, and a
  route without `{key}` goes to the actor `<kind>/_`. The method is `GET`,
  `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or `OPTIONS`, or from M24 the
  pseudo-method `WEBSOCKET` or `SSE` of a [connection](#connections) route;
  a kind with a connection route must export `connection-handler`, or
  deploy and propose refuse it with `BAD_REQUEST`. Two kinds with the same
  method and pattern are `ROUTE_CONFLICT` at deploy. So are an `SSE` and a
  `GET` route on the same pattern, also within one manifest, because both
  answer a plain GET; a `WEBSOCKET` and a `GET` route may share a pattern
  (one URL serves the page and its socket).
- `capabilities`: the capabilities the kind asks for. Asking grants nothing:
  deploy answers with a warning and the `kronik grant` command for each
  requested capability, and only the operator's grants count (M2).

Only `log` may be used inside `describe`; state, SQL, messaging, timers,
effects and `privacy.set-subject` trap there. A trap in `describe` fails the
deploy with `TURN_FAILED`.

**`handle`** runs once per turn, in a fresh instance of the component, so
nothing in guest memory survives to the next turn (I3). The input:

| Input | When |
| --- | --- |
| `http(http-request)` | The gateway matched one of the kind's routes. |
| `message(incoming)` | Another actor sent a message (`sender` is that actor), or the operator did through the API or `kronik send` (`sender` is none). From M2 also a `call` from another actor, and a compensation. |
| `timer(timer-fired)` | A timer that this actor scheduled fell due (M2). |
| `migrate(from)` | The first turn under code with a higher schema version; `from` is the old version. DDL is allowed only here. |

The output:

- For an HTTP input, `http(http-response)` is the response;
  `reply(message)` becomes 200 with the message's body and content type
  (`application/octet-stream` if empty); `none` becomes 204.
- For an operator message, `reply` is returned to the API caller. For a
  `call` (M2), `reply` is the callee's answer and `none` answers with no
  message.
- `err(handler-error)` fails the turn, like a trap: `rejected(reason)` for an
  input the actor refuses, `failed(reason)` for an error. An HTTP client
  gets 500 `TURN_FAILED` with the turn id; a guest that wants a 4xx returns
  it as `http(http-response)`. For a `call`, the two become
  `call-error::rejected` and `call-error::failed`.

A failed turn writes a failed turn record and discards its writes, SQL
changes, messages and timers; there is no automatic retry. A failed message
or timer input becomes a dead letter.

## types

```wit
record actor-ref { kind: string, key: string }
record blob-ref { hash: string, size: u64 }
record message { name: string, content-type: string, body: list<u8>, blobs: list<blob-ref> }
variant http-body { inline(list<u8>), blob(blob-ref) }
record header { name: string, value: string }
record incoming { sender: option<actor-ref>, msg: message }
record http-request {
  method: string, path: string, query: string,
  params: list<tuple<string, string>>, headers: list<header>, body: http-body,
}
record http-response { status: u16, headers: list<header>, body: http-body }
record timer-fired { id: u64, msg: message }
variant input { http(http-request), message(incoming), timer(timer-fired), migrate(u32) }
variant output { none, reply(message), http(http-response) }
variant handler-error { rejected(string), failed(string) }
record route { method: string, pattern: string }
record manifest { kind: string, schema-version: u32, routes: list<route>, capabilities: list<string> }
```

- An `actor-ref` is `kind/key`, for example `billing/acme`; an invalid one
  traps where it is used.
- Blobs are not available in v0.1. `message.blobs` must be empty and
  `http-body` must be `inline`; a blob traps with `NOT_IMPLEMENTED`. Blob
  references arrive with M25 and messages with blobs with M26, without a
  breaking change to the WIT.

## state

```wit
interface state {
  get: func(key: string) -> option<list<u8>>;
  set: func(key: string, value: list<u8>);
  set-for: func(subject: option<string>, key: string, value: list<u8>);
  delete: func(key: string);
  keys: func(prefix: string) -> list<string>;
}
```

The actor's key-value state. Reads see the state at the start of the turn
plus the turn's own writes; no other turn changes the actor's state in the
meantime, because an actor runs one turn at a time.

- `get` returns the value, or none.
- `set` buffers a write, tagged with the current default subject (see
  [`privacy`](#privacy)). A value over the kind's state value limit (1 MiB by
  default) traps.
- `set-for` buffers a write tagged with an explicit subject, whatever the
  default is; none means no subject.
- `delete` buffers a deletion.
- `keys` returns the keys that start with `prefix` in ascending order,
  including the turn's own writes and without its deletions.

## sql

```wit
interface sql {
  variant sql-value { null, integer(s64), real(f64), text(string), blob(list<u8>) }
  record rows { columns: list<string>, values: list<list<sql-value>> }
  variant sql-error { syntax(string), constraint(string), denied(string), too-large }
  query: func(statement: string, params: list<sql-value>) -> result<rows, sql-error>;
  execute: func(statement: string, params: list<sql-value>) -> result<u64, sql-error>;
}
```

Each actor has its own SQLite database, owned by the host
([ADR 0005](../adr/0005-sql-state.md)). `query` returns the result rows;
`execute` returns the number of changed rows. Parameters bind to `?`
placeholders in order.

- **Recorded as changesets.** A turn's statements run in a savepoint and
  are captured as changesets in the turn record, so production, recovery
  and a rebuild from the log build the same database. A failed turn changes
  nothing.
- **Schema.** DDL is allowed only in a `migrate` turn, before its first DML
  statement; elsewhere it is `denied`. Tables without a `PRIMARY KEY` are
  allowed.
- **Subjects.** A row's subject is its `_subject` column; rows of tables
  without one take the turn's default subject. The SQL function
  `kronik_subject()` returns the current default subject, for example
  `_subject TEXT DEFAULT (kronik_subject())`. `UPDATE ... SET _subject` is
  denied, and a turn that moves a row to another subject fails.
- **Denied** with `denied(reason)`: `load_extension()`, `ATTACH` and
  `DETACH`, `VACUUM`, `ANALYZE`, a standalone `REINDEX`, transaction control
  (`BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE`), TEMP tables,
  views, triggers and indexes, virtual tables, `CREATE TABLE ... AS`,
  `changes()` and `total_changes()`, the `dbstat` table, tables named
  `_kronik*`, and every pragma except a read-only allowlist (`table_info`,
  `table_xinfo`, `table_list`, `index_list`, `index_info`, `index_xinfo`,
  `foreign_key_list`, `foreign_key_check`, `collation_list`,
  `function_list`, `pragma_list` and `compile_options`, plus reading
  `user_version`, `schema_version`, `application_id` and `encoding`).
- **Deterministic.** `'now'` in every date and time function and
  `CURRENT_TIMESTAMP` give the turn's logical time; `localtime` is UTC;
  `random()` and `randomblob()` draw from the turn's seed;
  `last_insert_rowid()` starts over in every turn.
- **Limits.** A value over 1 MiB, or a database over the kind's SQL size
  limit (1 GiB per actor by default), gives `too-large`. SQL runs in the
  host, outside Wasm fuel: a turn's statements may run at most as many
  SQLite VM steps as the kind's fuel limit, after which the turn fails with
  `FUEL_EXHAUSTED`. Foreign keys are enforced.

## context

```wit
interface context {
  self-ref: func() -> actor-ref;
  causal-id: func() -> string;
  now-ms: func() -> u64;
  random-bytes: func(len: u32) -> list<u8>;
}
```

- `self-ref` returns the actor's own `kind/key`.
- `causal-id` returns 32 hex characters derived from the turn's causal key.
  It is the same in production and replay, so it is the id to use for
  correlation. The host's execution id is never visible to the guest.
- `now-ms` returns the turn's logical time in milliseconds since the Unix
  epoch. It is constant within the turn, never goes backwards, and is never
  lower than the time of the message or timer that started the turn
  ([ADR 0006](../adr/0006-logical-time.md)). Several turns may share a
  millisecond, so it is not an id.
- `random-bytes` returns bytes from a ChaCha20 stream seeded with the turn's
  recorded 32-byte seed. A request for more than 1 MiB traps.

## messaging

```wit
interface messaging {
  variant call-error { not-found, rejected(string), failed(string), reentrant, timeout }
  send: func(to: actor-ref, msg: message);
  call: func(to: actor-ref, msg: message, compensate: option<message>) -> result<option<message>, call-error>;
}
```

**`send`** buffers a message. It is delivered exactly once, and only if the
sending turn commits; the receiver handles it as `input::message` with this
actor as `sender`. Its body is tagged with the current default subject, and
the receiver's turn starts with that subject as its default. A body over the
kind's message limit (1 MiB by default) traps. A message to a kind without a
deployment gets a failed turn record with `ACTOR_NOT_FOUND` and becomes a
dead letter.

**`call`** (M2) happens now: the callee runs and commits a turn of its own,
and its `reply` comes back as `ok(some(message))`, or `ok(none)` for an
`output::none`. The result is recorded in the caller's turn as an effect
(`actor.call`) before the caller sees it. Errors:

- `not-found`: the callee's kind has no deployment.
- `rejected(reason)` and `failed(reason)`: the callee returned that
  `handler-error`; a trap or fuel exhaustion in the callee is `failed`.
  Failed call turns are not dead letters, because the caller got the error.
- `reentrant`: the callee is already waiting in a `call` on this causal
  chain, or is the caller itself.
- `timeout`: no answer within the kind's effect timeout (10 s by default).

`call` is not atomic with the caller's turn. If the caller fails afterwards,
the callee's turn stands. When the call carried `compensate`, that message
is delivered exactly once to the callee, as a message from the caller; a
compensation that fails becomes a dead letter. Until a compensation
succeeds, the callee's change is an orphaned change, listed by
`kronik history --orphans`. After a crash, a `call` whose callee already committed
gets the saved answer, and the callee does not run again. Use `send` for
changes and `call` for queries.

## timers

```wit
interface timers {
  schedule: func(delay-ms: u64, msg: message) -> u64;
  cancel: func(id: u64) -> bool;
}
```

Timers (M2) are internal and need no capability.

- `schedule` buffers a timer that is registered when the turn commits, due
  at the turn's `now-ms` plus `delay-ms`, and returns its id. The id derives
  from the turn's causal key, so it is the same in a re-run. When the timer
  falls due, it fires as a turn of this actor with `input::timer`, at a
  logical time no lower than the due time. A failed timer turn becomes a
  dead letter.
- `cancel` buffers the cancellation of a timer and returns whether it was
  pending: committed and not yet fired, or scheduled earlier in this turn
  and not cancelled since. It takes effect when the turn commits.

`kronik actors timers <kind/key>` lists an actor's pending timers.

## http-client

```wit
interface http-client {
  record secret-template { name: string, template: string }
  variant header-value { text(string), secret(secret-template) }
  record request-header { name: string, value: header-value }
  record request { method: string, url: string, headers: list<request-header>, body: http-body }
  record response { status: u16, headers: list<tuple<string, string>>, body: http-body }
  variant fetch-error { denied(string), network(string), timeout, too-large, outcome-unknown }
  fetch: func(req: request) -> result<response, fetch-error>;
}
```

`fetch` (M2) sends an HTTP request from the host
([M2 effects design](../design/m2-effects.md), §3):

- **URL.** `https://` (TLS with the system's root certificates) or
  `http://`. `foreign://<name>/...` reaches a foreign actor from M7 and is
  denied until then.
- **Capability.** The kind needs a grant of `http:<host>`, or of a wildcard
  `http:*.<suffix>`; the most specific wildcard wins, and a wildcard never
  matches the bare suffix. Without one the guest gets
  `denied("CAPABILITY_NOT_GRANTED: http:<host>")`, and the denied effect is
  recorded in the turn.
- **Secret headers.** A `secret(secret-template)` value names a secret and
  a template such as `Bearer {}`; the host puts the secret's current value
  in place of `{}` on the wire. It needs the capability `secret:<name>`. The
  value never enters guest memory or the log, which records the secret's
  name and version hash.
- **Idempotency key.** Every request carries `Idempotency-Key:
  hex(blake3(causal key + ordinal))`, the same when the turn runs again; a
  guest's own `Idempotency-Key` header is replaced.
- **Rate.** A grant with a rate (`N/s`, `N/m` or `N/h`) makes the call wait
  for a free slot.
- **Errors.** `network(message)` when the connection fails or breaks,
  `timeout` after the kind's effect timeout (10 s by default), `too-large`
  for a response over the kind's effect response limit (10 MiB by default).
  A request body over the message limit traps.
- **Response.** Exact occurrences of the inserted secret values are
  replaced by `[secret:<name>]` before the guest sees the response.
- **Recording.** Before the turn's first external effect, `call` or secret
  use, the host fsyncs a `TurnBegin` (I14); each result is fsynced as an
  `EffectResult` before the guest sees it. A turn that runs again after a
  crash gets the recorded results; a request that differs from the
  recorded one traps with `REPLAY_DIVERGED`.
- **Uncertain outcomes.** If the daemon crashed after sending a request but
  before recording its result, the request is sent again with the same
  idempotency key when the target's delivery class is `replay-safe` or
  `idempotency-keyed`. For an `unsafe` target it is not sent again, and the
  guest gets `outcome-unknown` (I17); a turn that then fails fails with
  `EFFECT_OUTCOME_UNKNOWN`. The delivery class comes from the grant, and
  defaults to `replay-safe` for GET, HEAD and OPTIONS and `unsafe`
  otherwise.

## crypto

```wit
interface crypto {
  variant crypto-error { denied(string), unsupported(string) }
  hmac-sha256: func(secret: string, data: list<u8>) -> result<list<u8>, crypto-error>;
  sign-ed25519: func(secret: string, data: list<u8>) -> result<list<u8>, crypto-error>;
}
```

Host-side cryptography (M2) with a secret named by `secret`; the value never
enters guest memory.

- `hmac-sha256` returns the 32-byte HMAC-SHA256 of `data` under the secret.
- `sign-ed25519` returns the 64-byte Ed25519 signature of `data`. The
  secret must be a 32-byte seed, raw or as 64 hex characters; anything else
  gives `unsupported(reason)`.
- Both need the capability `secret:<name>`, else
  `denied("CAPABILITY_NOT_GRANTED: secret:<name>")`; an unknown secret gives
  `denied("SECRET_NOT_FOUND: <name>")`. They use the secret's current
  version and are recorded as effects with the secret's name and version
  hash and a hash of `data`.

## secrets

```wit
interface secrets {
  reveal: func(name: string) -> result<string, string>;
}
```

`reveal` (M2) returns a secret's raw value, as an exception for code that
cannot use a header template or `crypto`. It needs its own capability,
`secret-reveal:<name>`; without it the error is
`CAPABILITY_NOT_GRANTED: secret-reveal:<name>`, and an unknown secret gives
`SECRET_NOT_FOUND: <name>`. The log records only the secret's name and
version hash. Exact occurrences of a value that the turn used or revealed
are replaced by `[secret:<name>]` before anything from the turn is written,
but code that has seen a value can always leak it (I8). In a fork, `reveal`
returns `[secret:<name>]` itself, never the value. `crypto` returns a
matching recording, or else follows the grant's in-forks mode: `recorded`
denies the call and `compute` signs on the host. The key never leaves the
host. See the [security model](../guides/security.md#secrets).

## log

```wit
interface log {
  enum level { trace, debug, info, warn, error }
  emit: func(lvl: level, message: string, fields: list<tuple<string, string>>);
}
```

`emit` produces a log event in the daemon's log, with the actor, the causal
id and the execution id added by the host and with secret values that the
turn used replaced by `[secret:<name>]`. Log events are not part of the
turn record. Writes to WASI stdout become `info` events and writes to
stderr `warn` events.

## privacy

```wit
interface privacy {
  set-subject: func(subject: option<string>);
  current-subject: func() -> option<string>;
}
```

A subject is the person that a value belongs to, such as `user:123`.

- `set-subject` sets the default subject for the values that the turn
  writes from then on: state values written with `set`, the bodies of
  messages and timers, and SQL rows of tables without a `_subject` column.
- `current-subject` returns the current default subject. A turn starts with
  the subject of the message or timer that started it (for an operator
  message, the subject given in the API request), else none. From M8 the
  gateway can also take it from an HTTP header or a JWT claim
  (`privacy.subject_from`).

In v0.1 every value carries its subject tag in the log, but values are
stored in plaintext until privacy mode seals them under the subject's key
(M8).

## connections

```wit
interface connections {
  type connection-id = string;
  enum protocol { websocket, sse }
  record sse-event { event: string, id: string, data: string }
  variant frame { text(string), binary(list<u8>), event(sse-event) }
  record open-request { connection: connection-id, protocol: protocol, request: http-request, subprotocols: list<string> }
  record incoming-frame { connection: connection-id, seq: u64, frame: frame }
  enum close-initiator { client, actor, host }
  record close-info { initiator: close-initiator, code: u16, reason: string }
  record closed { connection: connection-id, info: close-info }
  record accept { subprotocol: option<string>, headers: list<header>, subject: option<string> }
  variant open-reply { accept(accept), refuse(http-response) }
  variant send-error { closed, outcome-unknown, denied(string) }
  send: func(conn: connection-id, frame: frame);
  broadcast: func(conns: list<connection-id>, frame: frame);
  close: func(conn: connection-id, code: u16, reason: string);
  send-now: func(conn: connection-id, frame: frame) -> result<_, send-error>;
}
```

Long-lived connections (M24,
[the design](../design/m24-connections.md)): the gateway holds every
WebSocket and server-sent-events (SSE) connection, and the actor that
accepted it, its **owner**, sends on it and closes it
([ADR 0114](../adr/0114-only-the-accepting-actor-sends.md)). The open,
every incoming frame and the close are inputs of the owner, delivered to
[`connection-handler`](#connection-handler).

- **Connection ids** are `c-` and 32 lowercase hex characters, assigned
  when the connection opens, recorded and the same in replay. An id is
  data, not a capability: storing it or sending it in a message grants
  nothing.
- **Frames.** On a WebSocket, `text` and `event` (its data) are text frames
  and `binary` is a binary frame. On SSE, `event` is an event, `text` is an
  event with only data, and `binary` traps. An event's `event` and `id`
  must not contain CR, LF or NUL; they are recorded in plain text, so keep
  personal data out of them.
- **Ownership.** A turn may use the connection its `open` input names and
  the live connections its actor accepted earlier. Another actor's live
  connection traps with `CONNECTION_NOT_HELD`, and a malformed id traps.
  An id that no live connection has (it closed, or none was ever accepted)
  is recorded as dropped: its frames are never delivered, `close` does
  nothing and `send-now` answers `closed`. Ids are 128 random bits, so
  they cannot be guessed.
- **`send`, `broadcast` and `close` are buffered**, like `messaging.send`:
  they are recorded in the turn record in call order and handed to the
  connections after the turn commits, before its response or reply goes
  out. A failed turn sends nothing. `broadcast` records one frame for many
  connections; duplicate ids are ignored. `close` closes the connection
  after the frames before it, with `code` (1000, 1001, 1003, 1007, 1008,
  1009, 1011, or 3000 to 4999) and `reason` (at most 123 bytes); an SSE
  stream just ends. Frames after a close are never written.
- **`send-now`** sends during the turn, as an effect with the delivery class
  `unsafe` that needs a grant of `connection:send-now` (else
  `denied("CAPABILITY_NOT_GRANTED: connection:send-now")`). Its `TurnBegin`
  is fsynced first (I14) and its result before the guest sees it. `ok`
  means the frame was handed to the connection in order, not that the
  client received it; `closed` means it was not sent: the connection is
  closed or closing, or the client did not read for the kind's effect
  timeout, which also closes the connection as a slow consumer. After a crash, a
  re-run never sends it again: the guest gets `outcome-unknown`, and a turn
  that then fails fails with `EFFECT_OUTCOME_UNKNOWN` (I17). It cannot be
  used on the connection that the current turn opens. Use it for
  intermediate results, such as the tokens of a streamed answer, and `send`
  for final notices, such as "payment complete": a stream can reach the
  client before its turn fails.
- **Order.** A connection's frames go out in one order: within a turn its
  `send-now` frames first, then its buffered ones; and a turn's frames
  before the next turn's.
- **Delivery.** An acknowledged turn means that its frames are recorded and
  were handed to their connections, or dropped because a connection was
  closed; not that a client received them. Frames to a closed connection
  are recorded and dropped, and history shows each frame as written,
  dropped, queued or unknown. Apps that need confirmation number their
  messages.
- **Limits** per turn: 10,000 `send`, `broadcast` and `close` calls, 100,000
  frame targets, 16 MiB of buffered frame payload; one frame's payload is
  at most the kind's message limit (1 MiB by default). Breaking one traps.
- **Subjects.** Frame data and close reasons are tagged with the turn's
  default subject at the call, like message bodies.

## connection-handler

```wit
interface connection-handler {
  use types.{handler-error};
  use connections.{open-request, open-reply, incoming-frame, closed};
  open: func(request: open-request) -> result<open-reply, handler-error>;
  frame: func(event: incoming-frame) -> result<_, handler-error>;
  close: func(event: closed) -> result<_, handler-error>;
}
```

The export of the world `actor-connections`. Each call is one turn of the
connection's owner, the actor that the `WEBSOCKET` or `SSE` route names. A
component without the export runs exactly as before, but a kind with a
connection route needs it.

- **`open`**: a client asks to open a connection. `accept` may select one of
  the offered subprotocols (WebSocket only), add response headers, and set
  the subject of the connection's later inputs (none: the request's).
  `refuse` answers with an HTTP response; refusing an SSE request with 204
  tells the browser's EventSource to stop reconnecting. The client gets
  `101 Switching Protocols` or the `200` event stream only after the open
  turn's record is durable; frames that `open` sends follow it. A failed
  open answers 500 `TURN_FAILED`, as for HTTP, and is not a dead letter.
- **`frame`**: one incoming WebSocket message, with its incoming `seq` (0, 1,
  2, ... in the order the client sent them). SSE has no incoming frames.
- **`close`**: the connection ended, by the client, the actor (a committed
  `connections.close`) or the host. Every accepted connection gets exactly
  one, after its frames, also after a crash. The host's reasons are
  `restart` (code 1012, after any restart), `ping-timeout`, `too-large`,
  `slow-consumer`, `protocol`, `operator`, `rebase`, `abandoned` and
  `unavailable`.
- A failed `frame` or `close` turn is a dead letter, and `kronik
  dead-letters resend` runs it again.

## Determinism

Every source of non-determinism reaches the guest through the host, and the
host either records it or derives it from what it recorded (I1, I2):

- **Time** is the turn's logical time: `context.now-ms`, WASI's wall clock
  and monotonic clock, and SQL's `'now'`. It does not move during a turn,
  and a WASI sleep returns at once.
- **Randomness** comes from the turn's recorded 32-byte seed, in separate
  ChaCha20 streams for `context.random-bytes`, `wasi:random/random`,
  `wasi:random/insecure`, `wasi:random/insecure-seed` and SQL's `random()`,
  so a language runtime that draws randomness at startup does not shift the
  bytes the actor gets.
- **The outside world** answers through recorded effects (M2); a turn that
  runs again gets the recorded answers.
- **The engine.** Wasmtime is pinned at an exact version and configured
  with NaN canonicalization, deterministic relaxed SIMD, no threads, and
  fuel instead of wall-clock interruption
  ([ADR 0001](../adr/0001-wasmtime-determinism.md)). The engine version,
  Kronik's plus Wasmtime's, is recorded with every turn.
- **No memory between turns.** Every turn starts from a fresh instance, so
  globals and caches in guest memory start over.

## Limits

| Limit | Default | When exceeded |
| --- | --- | --- |
| Fuel per turn | 50,000,000 | The turn fails with `FUEL_EXHAUSTED` |
| Memory per instance (all linear memories together) | 64 MiB, at most 1 GiB | `memory.grow` returns -1; a trap that follows fails the turn with `TURN_FAILED` |
| Message body | 1 MiB | Traps in a turn; `PAYLOAD_TOO_LARGE` at the API and the gateway |
| State value | 1 MiB | Traps |
| `random-bytes` request | 1 MiB | Traps |
| SQL value | 1 MiB | `too-large` |
| SQL database per actor | 1 GiB | `too-large`, and the turn changes nothing |
| SQL work per turn | the fuel limit, in SQLite VM steps | The turn fails with `FUEL_EXHAUSTED` |
| Effect timeout (M2) | 10 s | `timeout` |
| Effect response (M2) | 10 MiB | `too-large` |
| Everything one turn records: its input, effects and their results, state writes, messages, timers, SQL changes and output | 128 MiB, one log record; not a setting | A new effect that no longer fits does not happen and the turn fails with `TURN_TOO_LARGE`; a response larger than what is left is `too-large`; a turn whose writes, messages, SQL changes or output do not fit fails with `TURN_TOO_LARGE` |
| Table elements | 1,000,000 | `table.grow` returns -1 |

Fuel, memory, message and state value size, SQL size per actor, effect
timeout and effect response size can be set per kind from M2
(`kronik limits set`); a turn uses the limits of its configuration epoch.
Fuel is charged for bulk memory instructions in proportion to their length,
so with the defaults a turn runs out of fuel before it can touch all of its
memory. The gateway accepts request bodies up to 1 MiB and answers 504
`GATEWAY_TIMEOUT` after 30 s, while the turn still completes.

## WASI and the import allowlist

Toolchains import parts of WASI even for code that never uses them. Deploy
reads the component's imports before compiling it and accepts only these:

| Package | Interfaces | Version | Host implementation |
| --- | --- | --- | --- |
| `kronik:actor` | `types`, `state`, `sql`, `context`, `messaging`, `timers`, `http-client`, `crypto`, `secrets`, `log`, `privacy`, `connections` | `0.1.x` | Kronik |
| `wasi:io` | `error`, `poll`, `streams` | `0.2.x` | Wasmtime's; `poll`, `pollable.block` and the blocking stream calls first run the turn's outgoing `wasi:http` requests, and a wait that could never end traps |
| `wasi:clocks` | `wall-clock`, `monotonic-clock` | `0.2.x` | Logical time, 1 ms resolution; sleeps return at once |
| `wasi:random` | `random`, `insecure`, `insecure-seed` | `0.2.x` | ChaCha20 from the turn's seed |
| `wasi:cli` | `environment`, `exit`, `stdin`, `stdout`, `stderr`, `terminal-input`, `terminal-output`, `terminal-stdin`, `terminal-stdout`, `terminal-stderr` | `0.2.x` | Empty environment, no arguments, empty stdin; stdout and stderr become log events; `exit` traps |
| `wasi:http` | `types`, `outgoing-handler` | `0.2.x` | Each request is an [`http.fetch` effect](#standard-fetch-wasihttp) (M22) |

Everything else is rejected, including `wasi:filesystem`, `wasi:sockets`,
`wasi:http/incoming-handler`, `wasi:clocks/timezone`, WASI 0.3, other
packages, unversioned names and bare function imports. Deploy then fails with
[`IMPORT_NOT_ALLOWED`](../errors.md#import_not_allowed), and the message
lists the offending imports in this form:

```text
IMPORT_NOT_ALLOWED: the component imports <import>, <import>, ...
```

Only the outer component's imports count; imports between its nested
modules are satisfied inside it. The engine links only the allowed
interfaces, so a component that got past the check still could not
instantiate. A Rust component built for `wasm32-wasip2` stays inside the
allowlist ([ADR 0001](../adr/0001-wasmtime-determinism.md), §9), and so does
a TypeScript component built with jco and ComponentizeJS without the
`fetch-event` and `stdio` features
([ADR 0002](../adr/0002-typescript-components.md), M4). Its standard `fetch`
imports `wasi:http/types` and `wasi:http/outgoing-handler`, which are allowed
since M22: each request is an `http.fetch` effect
([ADR 0070](../adr/0070-wasi-http-outgoing-handler.md)).

## Standard fetch (wasi:http)

Since M22 a component may send HTTP requests through
`wasi:http/outgoing-handler`, which is what a TypeScript `fetch` does
([ADR 0070](../adr/0070-wasi-http-outgoing-handler.md)). Each request is an
`http.fetch` effect, as with [`http-client`](#http-client): the same
capability (`http:<host>`), delivery class, rate limit, recording, replay,
fork matching and simulators.

- A request runs when the guest waits (`wasi:io/poll`, `pollable.block` or a
  blocking stream call) and its body is complete. Requests run one at a
  time, in the order they were started among those whose bodies are
  complete; each takes the turn's next operation ordinal when it runs.
- A header value with one `{{secret:NAME}}` is a secret header: the host
  inserts the secret, with the rest of the value as its template (`Bearer
  {{secret:api-key}}` is the template `Bearer {}`). It needs `secret:NAME`;
  the guest never holds the value, and responses are scrubbed of it. Two
  placeholders in one value, or a literal `{}` beside one, are not sent.
- The request body counts against `message_bytes`, like `http-client`'s;
  responses are read whole within the effect limits. Trailers are not
  supported, and `request-options` timeouts are ignored (the effect timeout
  applies). A turn may have 32 requests that it has not waited for.
- Errors arrive as `wasi:http` error codes: denied (a missing capability
  or secret) is `HTTP-request-denied`, a timeout
  `HTTP-response-timeout`, an answer over the limit
  `HTTP-response-body-size`, a network error or an unknown outcome
  `internal-error` with the reason (`outcome-unknown`). In TypeScript every
  one of them is a `TypeError` from `fetch`; use `ctx.http.fetch` when the
  kind of error matters.
- A request whose future the guest drops before it waits is never sent,
  and so is one still unwaited when the turn ends; the turn's log then has
  a warning (`wasi:http: N request(s) the turn never waited for were not
  sent`). A clock pollable is ready at once (time does not move during a
  turn), so a timeout raced against a request, such as `AbortSignal.timeout`
  in TypeScript, does not bound it; the effect timeout does. A
  wait that could never end, such as one for the response to a request
  whose body was never finished, fails the turn at once.

## Not in v0.1

- Blobs: `blob-ref` and `http-body::blob` trap until M25, and
  `message.blobs` must stay empty until M26.
- `wasi:filesystem`, `wasi:sockets` and `wasi:http/incoming-handler`: no
  files or sockets, and no inbound HTTP but the gateway's. Outgoing HTTP is
  `http-client` or, since M22, `wasi:http/outgoing-handler` (both the
  `http.fetch` effect). WASI 0.3 waits for Wasmtime to support it stably
  ([ADR 0070](../adr/0070-wasi-http-outgoing-handler.md) §5).
- Threads and shared memory.
- `foreign://` URLs before M7.

## The complete WIT

```wit
{{#include ../../wit/kronik-actor.wit}}
```
