# M24 long-lived connections (WebSocket and SSE)

Status: design for M24, accepted on 2026-11-13. Nothing in it is built yet. It builds on
[m1-core](m1-core.md), [m2-effects](m2-effects.md), [m3-fork](m3-fork.md),
[m8-privacy](m8-privacy.md) and [m11-preview](m11-preview.md), and on these
sections of the build brief: "Turn semantics", "Effects and capabilities",
"Forks, replay and behavior diff" and M24.

The decisions, with their alternatives, are four ADRs:

- [ADR 0113](../adr/0113-v05-actor-abi.md): the actor ABI;
- [ADR 0114](../adr/0114-only-the-accepting-actor-sends.md): ownership;
- [ADR 0115](../adr/0115-connection-turn-semantics.md): turn semantics;
- [ADR 0116](../adr/0116-connections-in-replay-and-diff.md): replay and
  the diff.

M25 and M26 (streaming bodies and blob storage) are designed at the same
time, in ADRs 0117 to 0122. §2.1, §5.1 and §6.6 record what the two
designs share.

How this design upholds the invariants it touches:

| Invariant | How |
| --- | --- |
| I1, I2 | Everything a connection turn sees is recorded or derived from recorded state: connection ids, frames, close facts and `send-now` results. |
| I3 | A connection is not guest memory: the gateway holds it, and the actor keeps only its id. |
| I4 | Connection state is a table derived from the log. |
| I6 | An actor can use only the connections it accepted, and `send-now` needs a grant. |
| I7 | No fork writes to a live connection. |
| I13 | Connections and frames are familiar concepts, not new Kronik concepts. |
| I14 | `TurnBegin` is fsynced before a `send-now`. |
| I16 | The format changes are additive. |
| I17 | A `send-now` is never sent again after an uncertain outcome. |

## 1. Overview

```text
client ──WebSocket or SSE──▶ gateway ──root inputs: open, frame, close──▶ owner's queue
   ▲                           │                                              │ turn
   │                           ▼                                              ▼
   └── frames ◀── connection hub ◀── after commit: send, broadcast, close ◀── turn record
                     ▲
                     └── during the turn: send-now (an unsafe effect)
```

- A request to a WebSocket or SSE route opens a connection. The route names
  one actor, the connection's **owner**. The open, every incoming frame and
  the close are root inputs of the owner.
- The owner answers the open with **accept** or **refuse**. Only after the
  open turn's record is fsynced does the client get `101 Switching
  Protocols` (WebSocket) or a `200` event stream (SSE).
- The owner sends with `connections.send` and `connections.broadcast`
  (buffered, sent after the turn commits) or `connections.send-now` (an
  effect with delivery class `unsafe`, sent during the turn). It closes
  with `connections.close`.
- Every accepted connection ends with exactly one close input, also after a
  crash.
- In replay, incoming events are root inputs, and outgoing frames are
  compared as responses.

The terms:

| Term | Meaning |
| --- | --- |
| Connection id | The handle: `c-` and 32 lowercase hex characters. It is the open input's root id with a prefix, recorded, and identical in replay. It is data, not a capability. |
| Frame | One unit on a connection: a WebSocket text or binary message, or an SSE event. |
| Owner | The actor that accepted the connection (ADR 0114). |
| Outgoing `seq` | 0, 1, 2, ... per connection, in the order frames go out (§4.5). |
| Incoming `seq` | 0, 1, 2, ... per connection, in the order the client sent them. |

## 2. The actor ABI (WIT 0.1.1)

### 2.1 Versioning

ADR 0113 has the reasoning. v0.5 is `package kronik:actor@0.1.1`, and
there is no 0.2.0. The 0.1 track grows only by new interfaces and by one
optional export. Existing interfaces, types, functions and worlds never
change, and every new interface is complete when it first appears. M25 and
M26 add the import interface `blobs` under the same rule and the same
version. Whichever milestone's first slice lands first bumps the package,
and no release ships in between.

### 2.2 The `connections` interface

```wit
/// Long-lived connections (M24): WebSocket and server-sent events. The
/// gateway holds the connection; the actor that accepted it (its owner)
/// sends on it and closes it.
@since(version = 0.1.1)
interface connections {
  use types.{header, http-request, http-response};

  /// "c-" and 32 lowercase hex characters: assigned when the connection
  /// opens, recorded, and the same in replay. Data, not a capability.
  type connection-id = string;

  enum protocol { websocket, sse }

  /// An SSE event. `event` and `id` must not contain CR, LF or NUL.
  record sse-event {
    /// the `event:` field; empty: none (the browser's default, "message")
    event: string,
    /// the `id:` field; empty: none. A reconnecting EventSource sends the
    /// last one back as the `Last-Event-ID` header.
    id: string,
    data: string,
  }

  /// One frame. On a WebSocket, `text` and `event` (its data) are text
  /// frames and `binary` is a binary frame. On SSE, `event` is an event,
  /// `text` is an event with only data, and `binary` traps.
  variant frame { text(string), binary(list<u8>), event(sse-event) }

  record open-request {
    connection: connection-id,
    protocol: protocol,
    /// the upgrade request (WebSocket) or the GET (SSE); the body is empty
    request: http-request,
    /// the subprotocols the client offered (Sec-WebSocket-Protocol), in order
    subprotocols: list<string>,
  }

  record incoming-frame {
    connection: connection-id,
    /// 0, 1, 2, ... per connection, in the order the client sent them
    seq: u64,
    frame: frame,
  }

  enum close-initiator { client, actor, host }

  record close-info {
    initiator: close-initiator,
    /// the WebSocket close code (1000 normal, 1006 gone without a close
    /// frame, 1012 a restart, ...)
    code: u16,
    /// the client's or the actor's reason; for the host one of "restart",
    /// "ping-timeout", "too-large", "slow-consumer", "protocol",
    /// "operator", "rebase", "abandoned", "unavailable"
    reason: string,
  }

  record closed { connection: connection-id, info: close-info }

  record accept {
    /// one of the offered subprotocols (WebSocket only)
    subprotocol: option<string>,
    /// extra response headers
    headers: list<header>,
    /// the subject of the connection's later inputs; none: the request's
    subject: option<string>,
  }

  variant open-reply { accept(accept), refuse(http-response) }

  variant send-error {
    /// the connection is closed or closing, or the client could not keep
    /// up: the frame was not sent
    closed,
    /// after a crash: the frame may or may not have been sent (I17)
    outcome-unknown,
    /// no grant of connection:send-now
    denied(string),
  }

  /// Buffered: sent after this turn commits, in call order; nothing if the
  /// turn fails. Traps on a connection this actor does not hold.
  send: func(conn: connection-id, frame: frame);
  /// `send` to each of `conns`, recorded once.
  broadcast: func(conns: list<connection-id>, frame: frame);
  /// Buffered like `send`: after the frames before it, the connection
  /// closes with `code` and `reason` (WebSocket) or its stream ends (SSE).
  close: func(conn: connection-id, code: u16, reason: string);
  /// Sends now, before the turn commits: an effect with delivery class
  /// unsafe that needs the capability connection:send-now. `ok` means
  /// handed to the connection in order, not received. Never sent again
  /// after a crash: the re-run gets `outcome-unknown`.
  send-now: func(conn: connection-id, frame: frame) -> result<_, send-error>;
}
```

Frames are their own variant, not `message`. There is no `blobs` field to
refuse, and incoming frames are never blobs in v0.5 (agreed with M25/M26).

### 2.3 The `connection-handler` export and the world

```wit
/// The export of an actor that holds connections (M24). Each call is one
/// turn.
@since(version = 0.1.1)
interface connection-handler {
  use types.{handler-error};
  use connections.{open-request, open-reply, incoming-frame, closed};
  /// A client asks to open a connection: accept or refuse it.
  open: func(request: open-request) -> result<open-reply, handler-error>;
  /// One incoming frame (WebSocket only).
  frame: func(event: incoming-frame) -> result<_, handler-error>;
  /// The connection closed; always its last input.
  close: func(event: closed) -> result<_, handler-error>;
}

@since(version = 0.1.1)
world actor-connections {
  include actor;
  import connections;
  export connection-handler;
}
```

The world `actor` keeps its 0.1.0 shape (plus M25/M26's `blobs` import).
Components built for 0.1.0 export only `handler` and run unchanged. The WIT
above parses with `wasm-tools` 1.262, and bindings generated from it
instantiate a 0.1.0 component (ADR 0113, Consequences).

**The host** (`crates/kronik-runtime`):

- `bindings` stays the `bindgen!` of the world `actor`. A second
  `bindgen!` for `actor-connections` reuses the `actor` modules with
  `with:` and adds `connections::Host` and the export glue.
- `Program` keeps `ActorPre` and an `Option` of the connections
  pre-instance. The pre-instance is present when the component exports
  `kronik:actor/connection-handler@0.1.x`
  (`Component::get_export_index`).
- `Program::run` calls `handle` for HTTP, message, timer and migrate
  inputs, and `connection-handler.{open, frame, close}` for
  `Input.connection`. A connection input for a component without the
  export fails the turn with `TURN_FAILED` ("the kind's code does not
  handle connections").

### 2.4 Host rules per function

| Function | Rules (a broken rule traps, and the turn fails) |
| --- | --- |
| `send(conn, frame)` | `conn` is a well-formed id (`c-` and 32 lowercase hex characters), else the turn traps. If it names a live connection (§6.5), the turn's actor owns it, or it is the connection this turn opens; else `CONNECTION_NOT_HELD`. If no live connection has it (it closed, or none was ever accepted), the frame is recorded as dropped and never delivered (§4.7; ADR 0114, amended). The frame's payload (text bytes, binary bytes, or event data + event + id) is at most the kind's `message_bytes`. `binary` to an SSE connection traps. `event.event` and `event.id` must not contain CR, LF or NUL. The per-turn caps of §4.11 apply. Recorded in `TurnRecord.connection_ops` with the payload tagged with the turn's default subject. Not allowed in `describe`. |
| `broadcast(conns, frame)` | `send`'s rules for every id: dropped ids are recorded as such. Duplicate ids are ignored (the first occurrence keeps its place). An empty list does nothing. One recorded operation with all targets. |
| `close(conn, code, reason)` | `send`'s rules for `conn`: a close of an id without a live connection is recorded as dropped and does nothing. `code` is 1000, 1001, 1003, 1007, 1008, 1009 or 1011, or 3000 to 4999. `reason` is at most 123 bytes of UTF-8. On SSE, the code and reason are recorded, and the stream ends. |
| `send-now(conn, frame)` | `send`'s rules. `conn` must not be the connection that the current turn opens (it opens at commit). An id without a live connection answers `closed`, recorded with the status `CLOSED` without a `TurnBegin`: the answer follows from the state. Without a grant of `connection:send-now`: `denied("CAPABILITY_NOT_GRANTED: connection:send-now")`, recorded as status `DENIED`. Otherwise: `TurnBegin` (I14), the frame goes to the hub (§5.2), and the `EffectResult` is fsynced before the guest sees the result (§4.4). |

Each turn has a set of held connections: the connection that its `open`
input names, plus every live connection (a `connections` row, §6.5) whose
owner is the turn's actor, as of the turn's start. The rows come from the
state view, which gets `connection(id) -> Option<ConnectionView {
owner_is_self, protocol, next_seq, closing }>` over live rows only: `None`
means no live connection has the id.

### 2.5 Routes in the manifest

A WebSocket or SSE route is an ordinary manifest route with a pseudo-method:

```text
{ method: "WEBSOCKET", pattern: "/chat/{key}/ws" }
{ method: "SSE",       pattern: "/chat/{key}/events" }
```

- `kronik_sched::METHODS` gains `WEBSOCKET` and `SSE`. Patterns and `{key}`
  work as for HTTP routes.
- **Conflicts.** A `WEBSOCKET` route conflicts with another `WEBSOCKET`
  route on the same normalized pattern. An `SSE` route conflicts with an
  `SSE` or a `GET` route on the same pattern, because both answer plain
  GETs. Both kinds of conflict give `ROUTE_CONFLICT`, between kinds and
  within one manifest. A `WEBSOCKET` and a `GET` route may share a pattern
  (one URL serves the page and its socket).
- Older hosts refuse the new methods ("route method ... is not supported"),
  so a manifest with connection routes cannot deploy there by accident.

### 2.6 Deploy checks and the import allowlist

- `allowlist.rs`: `KRONIK_INTERFACES` gains `connections` (an import, at
  `0.1.x`). M25 adds `blobs`. Unknown interfaces stay refused.
- A manifest with a `WEBSOCKET` or `SSE` route needs the
  `connection-handler` export. Otherwise deploy and propose refuse with
  `BAD_REQUEST`: "kind chat declares WebSocket or SSE routes but its
  component does not export kronik:actor/connection-handler; build it with
  an SDK from v0.5".
- A deploy or promote whose new code lacks the export, while the kind
  still has open connections, warns: "kind chat has N open connections; the
  new code does not handle connections, so their frames will fail". A
  proposal shows the same thing as introduced errors.

## 3. Ownership

ADR 0114 has the reasoning:

- The owner is the actor whose open turn accepted the connection, which is
  the actor the route named. It never changes.
- Only the owner's turns may `send`, `broadcast`, `close` or `send-now` on
  a live connection. Another actor's use traps with `CONNECTION_NOT_HELD`.
  An operation on an id without a live connection (it closed, or none was
  ever accepted) is recorded as dropped, as the brief says of frames to a
  closed connection (ADR 0114, amended 2026-11-13).
- Connection ids are the open's root id: 128 random bits from the node's
  entropy source. So an actor cannot find another actor's live connection
  by guessing ids and telling a trap from a dropped frame.
- The gateway delivers a connection's frames and its close only to the
  owner.
- Fan-out goes through ownership (a room actor owns its members'
  connections and broadcasts to them) or through messages (session actors
  own their connections and forward what others send them).
- Sharing edges like M26's reference graph are a possible later interface
  on the 0.1 track, not part of M24.

## 4. Turn semantics

ADR 0115 has the reasoning. This section is the contract.

### 4.1 Connection inputs

Every input of a connection is a root input of its owner, with
`Input.connection` (§6.1):

| Event | When it is admitted | The turn |
| --- | --- | --- |
| `open` | A request matched a `WEBSOCKET` or `SSE` route (§5.3, §5.4). | `connection-handler.open` |
| `frame` | A WebSocket text or binary message arrived on an accepted connection (§5.5). SSE has none. | `connection-handler.frame` |
| `close` | The connection ended, by the client, the actor or the host, exactly once (§4.8). | `connection-handler.close` |

- Each input has its own causal root `{root: <fresh root id>, path: []}`.
  The connection id is `c-` and the open input's root id.
- The logical time is that of any root input
  ([ADR 0006](../adr/0006-logical-time.md)).
- Turns that the connection's inputs cause (messages, calls, timers) are
  ordinary children.
- The actor's queue is FIFO, and the gateway admits a connection's inputs
  in order: the open, then its frames by incoming `seq`, then the close. So
  the owner sees them in that order.

### 4.2 The open turn

- The guest answers `ok(accept(..))` or `ok(refuse(http-response))`. The
  host checks an accept before the turn is recorded:
  - `subprotocol` must be one of those the client offered (none for SSE);
    the record keeps only its position in the offered list (the first, if
    the client offered it twice), never the value (§6.1);
  - header names and values must be valid;
  - `subject` must be a valid subject (m8-privacy §1).

  A failed check fails the turn with `TURN_FAILED` ("the open's accept
  ..."). The gateway drops these response headers from an accept:
  hop-by-hop headers, `sec-websocket-*`, `upgrade`, `connection`,
  `content-length`, `transfer-encoding`, `kronik-turn-id`, and
  `content-type` for SSE. A refusal is checked like an HTTP response (a
  status from 200 to 599). Refusing an SSE request with 204 tells
  EventSource to stop reconnecting.
- The record: an accept is `Outcome.output.accept` (§6.2), and a refusal is
  `Outcome.output.http`.
- **The handshake follows the record.** When the open turn's record is
  fsynced and applied, the gateway sends `101` (WebSocket) or the `200`
  event-stream head (SSE), with the actor's headers and `kronik-turn-id`.
  Then come the frames that the open turn itself queued (a welcome). A
  refusal is sent as the actor's response. A failed open turn answers 500
  `TURN_FAILED` with the turn id, or `EFFECT_OUTCOME_UNKNOWN`.
- Failed opens are not dead letters: the client got the error, as with
  HTTP.
- Opens have no ingress deduplication. `Idempotency-Key` does not apply.
- An open turn that outlives `[gateway] timeout` (30 s) answers 504
  `GATEWAY_TIMEOUT`, and the turn still completes. If it accepts, the
  connection is closed at once with the host reason `abandoned` (§4.8).
  The same happens when the client went away before the handshake.

### 4.3 Buffered frames and close

- `send`, `broadcast` and `close` add operations to the turn's ordered list
  `connection_ops` (§6.2). They take **no** operation ordinal. A frame that
  new code adds must not shift the message ids and causal keys of the
  messages after it.
- When the turn record is fsynced and applied, `run_turn` hands the
  operations to the hub (§5.2) in order. This happens before it delivers
  messages, registers timers and returns the turn's result. The gateway
  therefore answers an HTTP turn only after its frames are queued.
- A failed turn records no operations and sends nothing. Its compensations
  are delivered as before.
- After a committed `close`, the connection is **closing**. Frames recorded
  after the close (in the same turn or later) are never written.

### 4.4 `send-now`

An external effect, as the brief requires:

- **Kind** `connection.send-now`. **Target** `connection:<id>`, recorded in
  plain text: an id is not personal data, and the applier counts by it.
  **Capability** `connection:send-now`, as a grant per kind. **Delivery
  class** always `unsafe`: a grant of `connection:send-now` with
  `--delivery` other than `unsafe`, or with `--rate`, is refused with
  `BAD_REQUEST`.
- It takes the turn's next operation ordinal, like every effect.
- The order of steps:
  1. the capability check (a denial is recorded in the turn, without an
     fsync, as for every denied effect; its hint names `kronik grant <kind>
     connection:send-now`, the capability, not the target);
  2. `TurnBegin` appended and fsynced (I14);
  3. the frame goes to the hub, which waits up to the kind's effect timeout
     (10 s by default) for room in the connection's outgoing queue;
  4. the `EffectRecord` is appended in an `EffectResult` and fsynced;
  5. the result returns to the guest.

  The request in the record is `ConnectionSendRequest` (§6.2): the
  connection, the frame and its `seq`.
- **Results:**

  | Status | Guest sees | Meaning |
  | --- | --- | --- |
  | `OK` | `ok` | Handed to the connection's writer, after every earlier frame of the connection. Not "received". |
  | `CLOSED` (new, 12) | `closed` | The connection is closed or closing, or not live on this node. Not sent. |
  | `TIMEOUT` | `closed` | The outgoing queue stayed full for the effect timeout. Not sent. The gateway closes the connection with the host reason `slow-consumer`. |
  | `DENIED` | `denied(..)` | No grant. |
  | `OUTCOME_UNKNOWN` | `outcome-unknown` | A re-run found no recorded result (below). |

- **Re-execution after a crash.** As for every `unsafe` effect
  ([m2-effects](m2-effects.md) §4), a re-run returns recorded results in
  order. A `send-now` with no recorded result is **not performed**. Its
  record gets status `OUTCOME_UNKNOWN` with the request, the guest gets
  `outcome-unknown`, and a turn that then fails fails with
  `EFFECT_OUTCOME_UNKNOWN`. A frame input then becomes a dead letter that
  holds the frame. After a restart no connection of the old process is
  live, so an unhandled `outcome-unknown` is the usual end of such a turn.
- `send-now` on the connection that the current turn opens traps ("use
  send: the connection opens when this turn commits").
- **Docs** (brief): use `send-now` for intermediate results, such as the
  tokens of a streamed model answer. Use `send` for final notices, such as
  "payment complete". A stream can reach the client before its turn fails:
  that is the price of streaming.

### 4.5 Order on a connection

- Every outgoing frame has a per-connection `seq`, starting at 0. The host
  assigns it in the turn:
  - a `send-now` frame takes `next_seq` + the number of earlier `OK`
    `send-now` frames to the same connection in this turn;
  - at the end of the turn, the buffered frames take the following seqs,
    target by target, in operation order;
  - `next_seq` is the `connections` row as of the turn's start (§6.5), and
    0 for the connection that the turn opens.
- One owner runs one turn at a time, and its next turn starts only after
  the previous record is applied. So a connection's frames are handed to
  its writer in `seq` order: within a turn, `send-now` frames before
  buffered ones; and a turn's frames before the next turn's. The writer
  writes in `seq` order.
- A `send-now` call and a later `send` in the same turn: the `send-now`
  frame goes first, whatever the call order. The docs say so.
- The applier advances `next_seq` by every `OK` `connection.send-now`
  effect of any turn record (failed turns keep their effects), and by every
  buffered target of committed records.
- Diffs ignore `seq` (ADR 0116).

### 4.6 What an acknowledged turn means

When a turn is acknowledged (its HTTP response, an API reply, or its record
committed for a message or connection input), these hold:

- the frames it sent are in the fsynced turn record;
- each was handed to its connection's writer in `seq` order, or dropped
  because the connection was gone or closing;
- this happened before the acknowledgement.

It does **not** mean that the client received them. The socket can fail
before the kernel sends them, and the node can crash before the writer
writes them. Apps that need delivery confirmation number their messages.
The chat example uses a room sequence, and clients resynchronize with
`GET /chat/{room}/messages?after=<seq>`.

### 4.7 Frames to closed connections

Frames to a connection that is closed, closing or not live are recorded
and never written.

- **An id without a live connection** (its close input was applied, or no
  connection was ever accepted with it): the turn records the target in
  `ConnectionOp.dropped` (§6.1), with no seq, and nothing reaches the hub.
  `send-now` answers `closed`.
- **A closing connection** (its owner's close committed, its close input
  not yet applied): it is still live, so its frames get seqs like any
  other and the hub drops them.

Every close input carries `frames_written` (§6.1):
frames with a lower `seq` were written, and the rest were dropped. `history`
shows every outgoing frame's **fate**:

| Fate | When |
| --- | --- |
| `written` | `seq < frames_written`, or the connection is live and its writer has written it. |
| `queued` | The connection is live and the frame waits in its queue. |
| `dropped` | `seq >= frames_written`. Or the connection was closed by a restart and the frame's record has an LSN above that close's `restart_after_lsn`. Or the target is in its operation's `dropped` list: no live connection had the id. |
| `unknown` | The connection was closed by a restart (the count died with the process) and the frame's record has an LSN at or below `restart_after_lsn`. |

`kronik_connection_frames_dropped_total` counts dropped frames (§11).

### 4.8 Exactly one close per accepted connection

The gateway admits **exactly one** close input for every accepted
connection. It comes after the connection's admitted frames:

| Who ends it | When | Close input (initiator, code, reason) |
| --- | --- | --- |
| Client | A close frame, an EOF, a reset, or a failed write to an SSE stream | `client`, the client's code (1006 without a close frame; SSE always 1006), the client's reason |
| Actor | A committed `close`. The gateway sends the close frame after the queued frames, waits up to `close_timeout` (5 s) for the client's, then drops TCP. | `actor`, the actor's code and reason |
| Host | A limit, a dead peer, an operator, a restart, a rebase, a failed handshake or an unavailable node (§5.8) | `host`, the code sent (§5.8), the fixed reason |

- The connection's state follows the close input, whatever its turn's
  outcome: a close input whose turn fails still closes the connection in
  `state.db`. The failed turn is a dead letter (§4.9).
- **After a restart:**
  - `Node::start` admits a host close (reason `restart`, code 1012,
    `frames_written` unknown, `restart_after_lsn` = the log's last LSN at
    start) for every connection still open in `state.db`.
  - These come after the re-runs and the mailbox, and before the gateway
    accepts traffic. In each actor, the old connections therefore close
    before new ones open.
  - An open turn that a re-run accepts (it had a `TurnBegin`) has no client
    any more. The hub closes it with the reason `restart` as soon as it
    commits: an accept for a connection that the hub did not open in this
    process is a restart.
- After a crash, the clients saw an abnormal closure (1006). After a
  graceful stop they got the close code 1012 (§5.9).

### 4.9 Failures, dead letters and resend

- A failed `frame` or `close` turn is a dead letter, as for messages and
  timers. `kronik dead-letters resend` admits it again as a new root input:
  the same connection, the same incoming `seq` and frame, `resend_of` and
  the audit. If the connection is closed by then, its frames are dropped as
  in §4.7.
- A resent close runs the close handler again (to clean up after a bug was
  fixed). It changes nothing in the `connections` table.
- A failed `open` is not a dead letter (§4.2).
- A connection input whose kind has no deployment, or whose code lacks the
  export, gets a failed record without running (as m1-core §7 does for
  messages). It becomes a dead letter for frames and closes.

### 4.10 Subjects

- The open's request is tagged like an HTTP request: with the subject from
  `privacy.subject_from` (header or JWT claim, trusted proxies only),
  m8-privacy §11.
- The **connection's subject** is the accept's `subject` when it is set,
  and otherwise the request's subject.
- Every later input of the connection is tagged with it: frame data, the
  close reason (empty for a host close, but tagged). The turn's default
  subject is the connection's subject, derived from the recorded input,
  so a re-run and a replay get the same one.
- Browsers cannot set headers on a WebSocket. Behind a trusted proxy that
  adds the subject header, `subject_from` works. Otherwise the actor checks
  a token (in the query or a cookie) in `open` and sets the subject in its
  accept.
- Outgoing frames are tagged with the sending turn's default subject at
  the call, as message bodies are.

### 4.11 Limits inside a turn

These are constants in v0.5. They are deterministic, and breaking one
traps:

| Limit | Value |
| --- | --- |
| Connection operations (`send`, `broadcast`, `close` calls) per turn | 10,000 |
| Frame targets per turn (the sum of every `broadcast`'s connections) | 100,000 |
| Buffered frame payload bytes per turn (counted once per operation) | 16 MiB |
| One frame's payload | the kind's `message_bytes` (1 MiB by default) |

With connection ids, a full turn records about 20 MiB. That is well below
`MAX_RECORD` (128 MiB). The per-record budget that the fix of issue #26
adds counts `connection_ops` like the turn's other outputs.

## 5. Gateway

### 5.1 Request classification

`Gateway::serve` decides, before reading any body:

1. **A preview target** (m11-preview §2). A WebSocket upgrade, or a GET
   that matches an `SSE` route of the preview, answers `501
   NOT_IMPLEMENTED` ("previews do not take WebSocket or SSE connections",
   §5.12).
2. **A WebSocket upgrade** (`GET`, `Upgrade` containing the token
   `websocket`, `Connection` containing `upgrade`) is matched against
   `WEBSOCKET` routes only. If none matches: 404 `ROUTE_NOT_FOUND`.
3. **A `GET`** is matched against `GET` and `SSE` routes together. They
   cannot overlap (§2.5). An `SSE` match takes the SSE path.
4. **Everything else** takes the HTTP path, where M25's body phase reads or
   spools the body.

An upgrade or SSE request with a body (`Content-Length` above 0, or
`Transfer-Encoding`) answers 400 `BAD_REQUEST`. Agreed with M25/M26:
`kronik-gateway/src/body.rs` and its `RequestBody`/`ResponseBody` enums
belong to M25. M24 adds the variant `ResponseBody::Events` for SSE. If
M24's SSE slice lands first, it creates `body.rs` with `ResponseBody {
Inline, Events }` and the single `http_body::Body` implementation, and M25
adds the rest.

### 5.2 The connection hub

The live registry, `kronik_sched::connections::Hub`, sits next to the node
in `kronik-sched`. It uses only `Env` and `tokio::sync`
([ADR 0004](../adr/0004-deterministic-simulation.md)), so `kronik-sim`
drives it as production does. `NodeParts` gets the hub, so re-runs at
startup already go through it. What it holds:

- **Per live connection:** the owner, protocol, route and subject; a
  bounded outgoing queue of `(seq, frame)`; `frames_written` and
  `frames_received`; the in-flight window (a semaphore of `inflight_frames`
  permits); the state (`opening`, `open`, `closing`); and a `Transport`
  handle.
- **The open operations it started in this process**, so that it can tell
  an abandoned open from a restart (§4.8).
- **Counts** per actor and per client address, for the caps (§5.11).

What the node calls:

- `deliver(ops)` after a commit (§4.3);
- `send_now(conn, seq, frame, timeout)` from the effect gate (§4.4);
- `connection_open`, `connection_frame` and `connection_closed`, to admit
  inputs;
- `shutdown(grace)` on SIGTERM.

What the shell implements: `trait Transport { fn wake(&self); fn close(&self,
code: u16, reason: &str); }`. Its writer pulls from the queue, and its
reader calls back into the hub. `kronik-gateway` implements it for
tokio-tungstenite and for the SSE body stream, and `kronik-sim` for its
simulated clients.

### 5.3 Opening a WebSocket

1. **Validate the handshake:** GET, `Sec-WebSocket-Version: 13`, and a
   `Sec-WebSocket-Key` of 16 base64-encoded bytes
   (`tungstenite::handshake::server::create_response`). A bad one: 400
   `BAD_REQUEST`. Extensions (`permessage-deflate`) are never negotiated.
2. **Check the caps:** reserve a slot for the owner and the client address
   (§5.11), or answer 503 `CONNECTION_LIMIT` with `retry-after: 5`. A
   refusal, a failure or a timeout gives the slot back. Check that the node
   runs (`check_running`), or answer 503 `UNAVAILABLE`.
3. **Admit the open:**
   - Build the `HttpInput` exactly as for HTTP (`Gateway::input`): the
     subject, admin cookies stripped, every value tagged. The body is
     empty, and the idempotency key and request hash are cleared.
   - Record no copy of the subprotocols: the runtime derives
     `open-request.subprotocols` from the request's recorded
     `Sec-WebSocket-Protocol` header, which is sealed like every header
     (§8). Browsers cannot set `Authorization` on a WebSocket, so bearer
     tokens travel in that header.
   - `node.connection_open(actor, input, subject)` returns the connection
     id and a waiter.
4. **Wait** for the turn, at most `[gateway] timeout`. On a timeout: 504,
   and the hub closes an eventual accept as `abandoned`.
5. **Answer:** a refusal or a failure as in §4.2. An accept: `101` with
   `Sec-WebSocket-Accept`, the selected subprotocol (the value at the
   recorded position in the request's offered list), the actor's headers
   and `kronik-turn-id`. The HTTP connection must be served `.with_upgrades()`.
6. **Upgrade** on a task: wait at most 10 s for `hyper::upgrade::on(req)`
   (a failure closes the connection as `abandoned`), then
   `WebSocketStream::from_raw_socket(.., Role::Server, config)` with:

   | Setting | Value |
   | --- | --- |
   | `read_buffer_size` | 4 KiB (tungstenite's 128 KiB default is allocated eagerly per connection) |
   | `write_buffer_size` | 0 |
   | `max_write_buffer_size` | `outbound_queue_bytes` + the largest frame |
   | `max_message_size`, `max_frame_size` | the smaller of `[connections] max_frame_bytes` and the kind's `message_bytes` |

   This follows the API's event stream (`kronik-api/src/event_stream.rs`).
7. **Attach** the transport to the hub (`attach(conn)`). The writer starts
   with the frames that the open turn queued.

The HTTP connection slot (`[gateway]`'s connection cap, `server.rs`
`Slots`) is released when hyper hands over the upgraded I/O. From then on
the connection counts against `[connections]`.

### 5.4 Opening an SSE stream

The same steps without the handshake and the upgrade. On an accept, the
gateway answers `200` with these headers: `content-type:
text/event-stream`, `cache-control: no-store`, `x-accel-buffering: no`,
the actor's headers and `kronik-turn-id`. The body is
`ResponseBody::Events`, which streams the hub's queue:

- **An event** is written as `id: <id>` (when not empty), `event: <event>`
  (when not empty), and one `data: <line>` per line of the data (CRLF and
  CR become LF), then an empty line. A `text` frame is an event with only
  data.
- **The heartbeat** is a comment, `: keep-alive`, every `sse_heartbeat`
  (15 s). A failed write ends the stream as a client close.
- A reconnecting EventSource sends `Last-Event-ID`. It is a header of the
  open request, and the actor resumes from it (the chat example does).
- SSE has no incoming frames: the open and the close are its only inputs.

### 5.5 Incoming frames and backpressure

The reader task, per connection, for each message:

- **Text or binary:** `frames_received += 1`. If the connection is closing
  (closed by the actor or the host), the message is discarded. Otherwise
  the reader takes an in-flight permit and an `inbound_rate` token, then
  admits the frame with `node.connection_frame(conn, seq, frame)`. The
  permit is returned when the frame's turn finishes.
  - While `inflight_frames` frames wait or run, and while the rate is
    exceeded, the reader stops reading. TCP then pushes back on the client.
    Slow actors and fast clients cost bounded memory: at most
    `inflight_frames` × `max_frame_bytes` per connection.
  - If admission fails (the node stopped, or `[log] disk_reserve` was
    reached), the host closes the connection with the reason `unavailable`
    (1013). Nothing is lost silently: `frames_received` shows how many
    frames were read.
- **Ping:** tungstenite answers with a pong. **Pong:** marks the peer
  alive.
- **Close frame:** answered, then a client close.
- **A frame over the size limit:** a `too-large` close (1009). **Invalid
  UTF-8 or a protocol error:** a `protocol` close (1007 or 1002).
- **EOF or an I/O error:** a client close with 1006.

A crash loses the frames that were admitted but not committed. They are
not acknowledged (brief): the client learns this from the app's own
numbering.

### 5.6 Outgoing frames and slow consumers

- The hub's queue per connection holds encoded frames in `seq` order. The
  writer pops, writes and flushes each, then sets `frames_written = seq +
  1`.
- A committed frame never waits: it is queued at once. If the queue would
  then hold more than `outbound_queue_bytes` (1 MiB), the connection is a
  slow consumer: it is marked closing, its queue is dropped, and a close
  frame 1008 (`slow-consumer`) is attempted within `close_timeout`. Then
  TCP is closed, and the close input records `frames_written`.
- A `send-now` instead waits up to the effect timeout for room (§4.4).
- **No write waits for ever** (review S1, S2). A frame or a ping that the
  client does not take within `ping_timeout` closes the connection: as a
  slow consumer for a frame, with `ping-timeout` for a ping. A close frame,
  the flush after the client's close and the final close each get
  `close_timeout`. The SSE driver's wait for room in the response body is
  bounded the same way and notices a host close meanwhile. Under all of
  them, the server fails any write to a client socket that makes no
  progress for `ping_timeout` (`server.rs` `StallGuard`), which also frees
  the socket of an SSE stream or an HTTP response that hyper is writing.
  However a driver ends, it reports the end to the hub exactly once
  (`FinishGuard`).
- **No accepted connection without a transport** (review S3). An open
  whose client leaves while its turn runs is abandoned when the gateway's
  answering future is dropped. An accept that gets no transport within
  `attach_timeout` (10 s, the upgrade's limit, not a `kronik.toml` key) is
  abandoned by the hub; a close its actor buffered meanwhile is recorded.

### 5.7 Keepalive

- A WebSocket gets a ping every `ping_interval` (30 s). If nothing arrives
  (pong or frame) within `ping_timeout` (30 s) after the ping, the host
  closes with `ping-timeout` (1001) and drops TCP.
- SSE uses the heartbeat comment (§5.4).
- There is no idle timeout. An app that wants one closes idle connections
  itself with a timer.
- Pings, pongs and heartbeats are never inputs and never recorded.

### 5.8 Close codes and host reasons

| Reason (`close-info.reason` for the host) | Code sent | When |
| --- | --- | --- |
| `restart` | 1012 Service Restart | Graceful stop. Also the close input after any restart. |
| `ping-timeout` | 1001 | No answer to a ping (§5.7). |
| `too-large` | 1009 | An incoming message over the limit. |
| `slow-consumer` | 1008 | The outgoing queue overflowed (§5.6). |
| `protocol` | 1002, or 1007 for invalid UTF-8 | A protocol error from the client. |
| `operator` | the operator's code (default 1008) | `kronik connections close` (§12). |
| `rebase` | 1012 | A rollback via replay switched the owner's kind (§7.7). |
| `abandoned` | 1001 (rarely delivered) | The accepted connection had no client: an open that outlived the gateway timeout, a client that left before the handshake, or a failed upgrade. |
| `unavailable` | 1013 Try Again Later | The node could not admit a frame (§5.5). |

The WebSocket codes are the common vocabulary for SSE too. An SSE stream
that the client ends is recorded with 1006, and one that the actor or host
ends with the code that applies.

### 5.9 Restarts and the dedicated close reason

- **A graceful stop** (SIGTERM, `systemctl restart`, Ctrl-C), before the
  shutdown snapshot in `serve.rs`, calls `hub.shutdown(shutdown_grace)`
  (2 s):
  1. stop admitting opens and frames;
  2. send every WebSocket a close frame with **code 1012 and the reason
     `kronik: restart`**, and every SSE stream `retry: 5000` before its end;
  3. wait up to the grace for the writers.
- **After any restart, graceful or not,** the close inputs come from
  `Node::start` (§4.8). The dedicated reason is the same in history and in
  the actor's close handler: initiator `host`, reason `restart`, code 1012.
- **Clients reconnect.** The gateway starts after recovery, the restart
  closes are queued first, and new opens are ordinary. The docs and the
  chat client reconnect with jittered backoff (from 0.5 s, doubling, at
  most 30 s), and the chat client then resynchronizes by its room sequence.

### 5.10 Actors that sleep

A connection lives in the hub, not in the actor. An actor has no resident
instance (I3). Its worker task ends when its queue is empty, and its SQL
database can leave the LRU pool. Nothing about a connection depends on
that: a frame for a sleeping actor queues a turn like any root input, and
the turn's frames go to the hub. A test checks this (§19, slice 5): a frame
after the actor's worker has ended and its database has been evicted, and
an idle connection kept alive by pings for several ping intervals.

### 5.11 Configuration: `[connections]`

Server settings, like `[gateway]`. They are admission and transport
settings: replay never reads them, because it reads the recorded inputs.

```toml
[connections]
max_open = 4096              # live connections in total, besides [gateway]'s HTTP connections
max_per_actor = 2048         # per owner
max_per_client = 256         # per client address; [gateway] trusted_proxies are exempt
max_frame_bytes = 65536      # largest incoming message; never above the kind's message_bytes
inflight_frames = 16         # incoming frames per connection admitted and not yet finished
inbound_rate = "50/s"        # reads per connection are paced to this (a token bucket of that size)
outbound_queue_bytes = 1048576   # queued outgoing bytes per connection before a slow-consumer close
ping_interval = "30s"
ping_timeout = "30s"
sse_heartbeat = "15s"
close_timeout = "5s"
shutdown_grace = "2s"
```

- The cap that applies is the smaller of `max_open` and what the open-file
  limit leaves after `serve.rs`'s `connection_caps` reserves (node, HTTP
  gateway, TCP API). The shipped unit has `LimitNOFILE=65536`, which leaves
  about 63,000.
- `kronik doctor` and the startup log warn when the effective cap is below
  `max_open`.
- `kronik serve --init` writes the section commented out, with its
  defaults.

### 5.12 Previews

Preview forks do not take connections in M24 (§5.1: 501). §21 Q4 has the
reasoning and the later approach: the preview owns the connections it
accepts, its frames go only to them, its roots are `preview-`, and they
close when the preview expires.

### 5.13 Security notes

- **Cross-site WebSocket hijacking.** Browsers send cookies and an `Origin`
  header on a WebSocket handshake, and the gateway does not check `Origin`.
  An actor that authenticates by cookie must check `Origin` in `open`. The
  SDKs offer `request.origin()`, the chat example checks it, and the
  security guide says so.
- **Admin cookies.** `__Host-kronik-session` and `__Host-kronik-login` are
  stripped from upgrade requests as from HTTP (`strip_admin_cookies`).
- **Tokens in subprotocols.** Browsers cannot set `Authorization` on a
  WebSocket, so apps pass bearer tokens in `Sec-WebSocket-Protocol`. The
  header is recorded only as a sealable header of the open request, sealed
  like `Authorization` when the request has a subject, and the accept
  records only the selected value's position in it. The API redacts the
  header like `Authorization` (§8).
- **Subjects.** Only trusted proxies may set them (§4.10).
- **Caps.** Per client, per actor and in total (§5.11).
- Memory per idle connection is bounded (§5.3 buffers). Incoming memory is
  bounded by the window and the frame limit, and outgoing memory by the
  queue limit.

## 6. Log format

All changes are additive to v1 (I16). New enums follow the rules of
`common.proto`: 0 is `<NAME>_UNSPECIFIED`, and 0 or an unknown value is
`STORAGE_CORRUPT` when a record is applied.

### 6.1 New messages, in the existing files

No new file: `input.proto` would have to import a new file that imports
`input.proto` (for `HttpInput`), and protobuf forbids import cycles. The
shared types go into `common.proto`, the input types into `input.proto`, and
the output types into `turn.proto`.

**`common.proto`** gains:

```proto
enum ConnectionProtocol {
  CONNECTION_PROTOCOL_UNSPECIFIED = 0;
  CONNECTION_PROTOCOL_WEBSOCKET = 1;
  CONNECTION_PROTOCOL_SSE = 2;
}

// One frame of a long-lived connection (M24), in either direction.
message Frame {
  enum Kind {
    KIND_UNSPECIFIED = 0;
    TEXT = 1;
    BINARY = 2;
    EVENT = 3;
  }
  Kind kind = 1;
  // TEXT: UTF-8 text; BINARY: bytes; EVENT: the event's data. Tagged with
  // its subject (I9).
  Sealable data = 2;
  // EVENT only: the SSE `event:` and `id:` fields (application constants
  // and cursors, never personal data; the docs say so).
  string event = 3;
  string id = 4;
}
```

**`input.proto`** gains the case `ConnectionInput connection = 5;` in
`Input.kind`, and:

```proto
// A root input of a long-lived connection (M24). Exactly one event is set.
message ConnectionInput {
  // "c-" + the open input's root id: the same in every input.
  string connection = 1;
  ConnectionProtocol protocol = 2;
  // The matched route pattern, e.g. "/chat/{key}/ws".
  string route = 3;
  oneof event {
    ConnectionOpen open = 4;
    ConnectionFrame frame = 5;
    ConnectionClose close = 6;
  }
  // Resends of a dead letter: the failed turn ("<branch>:<lsn>").
  string resend_of = 7;
  // Who resent the input, or who closed the connection (operator closes).
  Audit audit = 8;
  // The gateway node that holds the socket; empty on a single node.
  // Reserved for the cluster (section 17).
  string gateway = 9;
}

message ConnectionOpen {
  // The upgrade request or the GET, as an HTTP input: method, path, query,
  // params, headers and route, sealed fields when it has a subject; the
  // body empty; idempotency_key and request_hash empty.
  HttpInput request = 1;
  // Was a plain copy of the offered subprotocols. Bearer tokens travel in
  // Sec-WebSocket-Protocol, so the list is derived from the request's
  // sealable header instead (I9).
  reserved 2;
}

message ConnectionFrame {
  // Per connection from 0, in the order the client sent them.
  uint64 seq = 1;
  Frame frame = 2;
}

enum CloseCause {
  CLOSE_CAUSE_UNSPECIFIED = 0;
  CLOSE_CAUSE_CLIENT = 1;
  CLOSE_CAUSE_ACTOR = 2;
  CLOSE_CAUSE_RESTART = 3;
  CLOSE_CAUSE_PING_TIMEOUT = 4;
  CLOSE_CAUSE_TOO_LARGE = 5;
  CLOSE_CAUSE_SLOW_CONSUMER = 6;
  CLOSE_CAUSE_PROTOCOL = 7;
  CLOSE_CAUSE_OPERATOR = 8;
  CLOSE_CAUSE_REBASE = 9;
  CLOSE_CAUSE_ABANDONED = 10;
  CLOSE_CAUSE_UNAVAILABLE = 11;
}

message ConnectionClose {
  // CLIENT, ACTOR, or one of the host's causes.
  CloseCause cause = 1;
  // The WebSocket close code received (client) or sent (actor, host).
  uint32 code = 2;
  // The client's or the actor's reason, tagged with the connection's
  // subject; empty for host causes, but tagged too, so the close turn's
  // default subject is the connection's.
  Sealable reason = 3;
  // Outgoing frames written to the socket: seq < frames_written were
  // written, the rest dropped. Unknown (false) after a restart.
  uint64 frames_written = 4;
  bool frames_written_known = 5;
  // Incoming messages read, admitted or not.
  uint64 frames_received = 6;
  // RESTART only: the last LSN of the log when the node started; frames
  // in later records were never written.
  uint64 restart_after_lsn = 7;
}
```

**`turn.proto`** gains `repeated ConnectionOp connection_ops = 30;` in
`TurnRecord` (31 to 34 stay free for M24 follow-ups), the case
`ConnectionAccept accept = 6;` in `Outcome.output`, the value
`EFFECT_STATUS_CLOSED = 12;` in `EffectStatus`, `connection.send-now` in the
comment on `EffectRecord.kind`, and:

```proto
// A buffered connection operation of a turn (M24), in call order.
message ConnectionOp {
  // SEND: the live targets (`broadcast` has several), each with its seq at
  // the same index. CLOSE: at most one, no seqs.
  repeated string connections = 1;
  repeated uint64 seqs = 2;
  oneof op {
    Frame send = 3;
    ConnectionCloseRequest close = 4;
  }
  // The targets no live connection had (ADR 0114, amended): recorded,
  // never delivered. A SEND's targets are `connections` and `dropped`; a
  // CLOSE has exactly one target in either list.
  repeated string dropped = 5;
}

message ConnectionCloseRequest {
  uint32 code = 1;
  // Tagged with the turn's default subject at the call.
  Sealable reason = 2;
}

// The open turn's accept (Outcome.output.accept).
message ConnectionAccept {
  // Was the selected subprotocol as a string. Bearer tokens travel in
  // Sec-WebSocket-Protocol, so only its position is recorded (field 4).
  reserved 1;
  repeated Header headers = 2;
  // The connection's subject from now on; unset: the request's.
  optional string subject = 3;
  // The selected subprotocol: its position, from 0, among the request's
  // Sec-WebSocket-Protocol values in the order offered; unset: none.
  optional uint32 subprotocol_index = 4;
}
```

### 6.2 The `send-now` effect record

**`effects.proto`** gains the plaintext inside the `send-now`
`EffectRecord.request` (a `Sealable` tagged with the turn's default
subject). There is no response payload: the status is the result.

```proto
// connection.send-now request (M24).
message ConnectionSendRequest {
  string connection = 1;
  // The frame's outgoing seq; 0 unless the status is OK.
  uint64 seq = 2;
  Frame.Kind kind = 3;
  bytes data = 4;
  string event = 5;
  string id = 6;
}
```

- **Fingerprint** of a `send-now`: BLAKE3 over the domain string
  `kronik.fingerprint.connection.v1` and the length-prefixed connection,
  kind, data, event and id, without `seq`. Keyed per subject like every
  fingerprint ([m8-privacy](m8-privacy.md) §4).
- **The target:** `connection:<id>`.
- **The simulator label** `connection` joins the values that
  `EffectRecord.simulator` documents (and `turn.schema.json` enumerates),
  for a fork's modeled answer (§7.3).

### 6.3 Validation (`kronik-proto` `Record::validate`)

- `ConnectionInput`:
  - `connection` matches `c-[0-9a-f]{32}`;
  - `protocol` and the `event` oneof are set;
  - `open.request` is set;
  - `frame.frame.kind` is valid, and an SSE connection has no frame
    events;
  - `close.cause` is valid.
- `ConnectionOp`:
  - `op` is set;
  - every id in `connections` and `dropped` is well formed, and no id is in
    both or twice;
  - for SEND, `connections` and `dropped` together are non-empty, and
    `seqs` has the length of `connections`;
  - for CLOSE, there is exactly one id in the two lists together, and no
    seqs;
  - `Frame.kind` is valid.
- `EffectRecord` of kind `connection.send-now`: the target starts with
  `connection:`.
- `ConnectionAccept` (an open turn's accept): an SSE open's accept has no
  `subprotocol_index`. Whether the index lies within the offered list is
  checked by the runtime before the turn is recorded; `validate` cannot,
  since the request's header may be sealed.
- A record that breaks one of these is `STORAGE_CORRUPT` when applied, as
  for every record.

### 6.4 Sealables

`kronik_proto::sealables` is the single list of every `Sealable` (sealing,
reseal, erasure, `--no-pii`). It gains:

- in `input_mut`: a connection open's request (as `Kind::Http`), a frame's
  `data`, and a close's `reason`;
- in `outcome_mut`: the accept's header values;
- in `turn_mut`: every `ConnectionOp`'s frame `data` and close `reason`.

`send-now` requests are already covered as `EffectRecord.request`.

### 6.5 Materialized state: `connections` and `connection_history` in `state.db`

Two tables with the same columns. `connections` holds the live
connections, the only rows a turn reads. `connection_history` holds the
closed ones, for the API and `kronik history` (ADR 0114, amended
2026-11-13).

```sql
CREATE TABLE IF NOT EXISTS connections (
  id TEXT PRIMARY KEY,             -- c-<32 hex>
  kind TEXT NOT NULL, key TEXT NOT NULL,   -- the owner
  protocol INTEGER NOT NULL,       -- ConnectionProtocol
  route TEXT NOT NULL,
  subject TEXT,                    -- the connection's subject tag
  opened_lsn INTEGER NOT NULL,     -- the accepting open turn
  closing_lsn INTEGER,             -- the first committed close operation
  closed_lsn INTEGER,              -- the close input's turn
  cause INTEGER, code INTEGER,     -- from the close input
  frames_in INTEGER NOT NULL DEFAULT 0,   -- frame inputs recorded
  next_seq INTEGER NOT NULL DEFAULT 0,    -- outgoing frames handed over
  frames_written INTEGER,          -- from the close input, when known
  restart_after_lsn INTEGER
);
CREATE INDEX IF NOT EXISTS connections_owner ON connections(kind, key);
-- The same columns; rows move here when their close input is applied.
CREATE TABLE IF NOT EXISTS connection_history ( ... );
CREATE INDEX IF NOT EXISTS connection_history_owner ON connection_history(kind, key, closed_lsn);
CREATE INDEX IF NOT EXISTS connection_history_closed ON connection_history(closed_lsn);
```

In `connections`, `closed_lsn`, `cause`, `code`, `frames_written` and
`restart_after_lsn` are always null.

The applier applies, per turn record, in this order:

1. An open input with a committed `Outcome.output.accept` inserts the row.
2. Every `OK` `connection.send-now` effect advances `next_seq` of its
   target, also in failed turns.
3. Every SEND target of a committed record advances `next_seq`, and a
   committed CLOSE sets `closing_lsn` if it is still unset.
4. A frame input increments `frames_in`, unless it is a resend.
5. A close input sets `closed_lsn`, `cause`, `code`, `frames_written` and
   `restart_after_lsn` on the live row and moves it, in the same
   transaction, to `connection_history`. This does not depend on the
   turn's outcome.

Operations on ids without a live row are ignored: a refused open's own
frames, and the targets in `ConnectionOp.dropped`. Every row change
names the owner as well as the id, so a record that names another actor's
connection changes nothing.

- **Other uses of the tables.**
  - `connections` is in `snapshot.rs`'s `HASHED_TABLES`, so recovery and
    rebuild checks cover it. `connection_history` is not, like
    `turn_index`.
  - Both are rebuilt from the log like every table (I4), and travel in
    snapshots and restores.
  - Retention's index compaction deletes the history rows with `closed_lsn`
    below the first retained LSN, in the same pass that deletes
    `turn_index` and `trees` rows below it. It works at the retention
    base, never by wall time, and never touches `connections`.
  - What a turn reads therefore changes only when a record of the log is
    applied (I1). A turn that sends to a connection closed long ago gets
    the same dropped frame whether or not compaction ran.
  - Every frame record of a connection precedes its close, so compaction
    never removes a history row that a retained record's fate needs.
  - The M13 switch copies both tables' rows of the rebased actors from the
    shadow.
- **Replay.** Isolated replay's production cursor holds the table as of
  each root input's LSN, and the overlay applies the fork's turns to it.
  Continuous replay's fork store evolves its own table.

### 6.6 Field numbers shared with M25 and M26

Agreed with the M25/M26 design, so that the two never collide:

| Field | M24 | M25/M26 |
| --- | --- | --- |
| `Input.kind` | 5 (`connection`) | none |
| `TurnRecord` | 30 (`connection_ops`); 31 to 34 spare | 24 to 29 |
| `Outcome.output` | 6 (`accept`) | none |
| `EffectStatus` | 12 (`CLOSED`) | none |
| `EffectRecord` | none | 14 |
| `BlobRef` (`common.proto`) | none | 3, 4 |
| `HttpEffectRequest` / `HttpEffectResponse` | none | 6 / 4 |
| `Limits` | none (16 on if ever) | 11 to 15 |
| Envelope kinds | none (18 if ever) | 19 reserved |

### 6.7 Compatibility fixtures

- The connection-open golden fixture has no `subprotocols` (field 2 is
  reserved, §6.1), and its accept records `subprotocol_index` (field 1 is
  reserved).
- `crates/kronik-proto` golden round-trip tests for every new message, and
  validation tests (an enum 0 or unknown value gives `STORAGE_CORRUPT`; a
  missing oneof is refused).
- A new fixture log, `tests/compatibility/m24-connections/`, holds a short
  recorded session (an open, frames, a `send-now`, an actor close, a
  restart close), written by a test binary of this version. The test
  reads, applies and rebuilds it, and checks the `connections` table and
  the history fates.
- The existing fixtures (`v0.1.0` to `v0.4.1`) still read and replay
  unchanged. When v0.5.0 is released, a chat session enters the frozen
  release corpus like the earlier releases' logs.
- `docs/reference/turn.schema.json` gains `input.connection`,
  `connection_ops` and `output.accept`. Turn-JSON fixtures are validated
  against it.

## 7. Replay, forks, diff and proposals

ADR 0116 has the reasoning.

### 7.1 Root inputs and labels

- A connection input with an empty causal path is a root input like an
  HTTP request (m3-fork §3.1).
- Its label (`kronik_fork::index::input_label`, the sampling stratum and
  the `causes` group) is `connection open WEBSOCKET /chat/{key}/ws`,
  `connection frame ...` or `connection close ...`. It is never the
  connection id or data.
- `RootInput.subject` is the frame data's or the open request's subject.

### 7.2 Connections in isolated and continuous replay

- **Isolated replay** runs every connection input against production's
  state at its LSN, including the `connections` table. A frame input's
  connection is therefore held, and its seqs equal production's.
- **Continuous replay** evolves the fork's table under the fork's code. A
  frame or close input whose connection is not a live connection of the
  fork's actor (the fork refused the open) is **not run**. It counts in
  `frames.skipped`, and its production turn is missing in the fork.
- An open that production refused and the fork accepts stays open in the
  fork. No frames ever arrive for it, and the diff shows the changed open.

### 7.3 `send-now` in forks (I7)

A fork, a replay, catch-up and `send_to_fork` have **no hub**. Nothing is
written to any socket. The fork's effect gate (`kronik-fork` `replay.rs`)
answers `connection.send-now` as follows:

1. **Same causal key, ordinal and kind, the same connection and an
   identical frame** (the fingerprint): the recorded result
   (`GROUNDING_EXACT`). That includes `OUTCOME_UNKNOWN`, `TIMEOUT` and
   `CLOSED`.
2. **The same, but a different frame:** the recorded result
   (`GROUNDING_APPROXIMATE`). The frame difference goes to `frames`.
3. **Otherwise, the connection model:** `OK` when the connection is a
   live connection of the turn's actor and not closing in the fork's state
   at that turn, and `CLOSED` otherwise (`GROUNDING_SYNTHETIC`, simulator
   `connection`). As in production, an id without a live connection
   answers `CLOSED`, and another actor's live connection traps (§2.4).

These effects are excluded from `grounding` and `summary.confidence`
(`kronik-fork` `diff.rs` `external()` does not list the kind).
`fork.live_allowlist` never applies to them.

### 7.4 Comparison

The fork design's turn comparison (§4, `TurnView` in `diff.rs`) gains two
parts:

- `connection_ops`: per operation, the targets, then the frame (kind, data
  normalized like a body with `ignore_json_paths`, event, id) or the close
  (code, reason). Never `seq`.
- The open answer: `accept` (the subprotocol's position, headers,
  subject) against
  `http` (status, headers, body), next to the existing `reply` and `http`
  outputs.

A difference in either makes the turn divergent. An origin is a differing
turn with the same input as production's, as before, so a changed message
format is one origin per frame input that sent a changed frame.

### 7.5 Diff format additions (`kronik.diff/v1`, all optional)

The schema `docs/reference/diff-v1.schema.json` gains:

- **`frames`**, after `responses`. It is absent when the window has no
  connection input and no turn sent a frame:

  ```json
  "frames": {
    "inputs": {"open": 12, "frame": 240, "close": 11},
    "unchanged": 251,
    "changed": 12,
    "skipped": 0,
    "sent": {"prod": 4800, "fork": 4800},
    "send_now": {"recorded": 30, "modeled": 0},
    "items": [{
      "root_lsn": 1302,
      "input": "connection frame WEBSOCKET /chat/{key}/ws",
      "turn_prod": "main:1302",
      "turn_fork": "p-7h3k2a9c1d0e:r1302.0",
      "open": null,
      "frames": [{
        "index": 0,
        "change": "changed",
        "targets": 20,
        "connections": ["c-1f0c…", "c-23aa…"],
        "kind": {"prod": "text", "fork": "text"},
        "event": null,
        "data": [
          {"op": "remove", "path": "/text", "prod": "hi", "fork": null},
          {"op": "add", "path": "/body", "prod": null, "fork": "hi"}
        ]
      }]
    }]
  }
  ```

  The fields:

  | Field | Meaning |
  | --- | --- |
  | `inputs` | The connection root inputs of the window, by event. |
  | `unchanged`, `changed` | The isolated-replay root inputs (connection inputs, or any input whose tree sent frames) whose operations are identical or differ. |
  | `skipped` | §7.2. |
  | `sent` | Outgoing frame targets. |
  | `send_now` | Recorded and modeled answers (§7.3). |
  | `items` | The changed inputs, in root LSN order, at most 200. |
  | `items[].open` | `{prod, fork}`, each `"accept"` or `"refuse <status>"`, when the open answer changed; else `null`. |
  | `items[].frames` | The changed operations, at most 20 per item: `index` is the operation's position in the tree, `change` is `added`, `removed` or `changed`, and `connections` has the first 5 targets. |
  | `items[].frames[].data` | JSON pointer operations when both payloads are JSON; otherwise one `replace` at `""`. Values with a subject are redacted as `{redacted, subject, hash}` (`DiffValue`). |

- **`summary.frames_changed`** (absent when 0), **`kinds[].frames`**
  (`{unchanged, changed}`, absent for kinds without connections), and
  **`samples.frames_changed`** (absent when empty).
- **Markdown:** a "Frames" section after "Responses" ("12 of 263
  connection inputs send changed frames"), with the changed items. The
  `--summary` (M10, [ADR 0023](../adr/0023-diff-summary.md)) shows the
  counts only, never frame data, and a test checks it with frames of a
  subject.
- **Fixture:** `docs/design/fixtures/diff-connections.json` (a formatting
  change, expected policy `allow` under the defaults). The schema tests
  validate it and real diffs.

### 7.6 Identity replay of a recorded session

Identity replay (the same code) is empty because every input of a
connection turn is recorded or derived from recorded state:

- connection ids, incoming frames and seqs, close facts;
- outgoing seqs from the `connections` row as of the turn;
- `send-now` results from the recording (exact);
- the subject from the inputs' tags;
- time and seed from the record.

The acceptance (§18, criterion 2) checks both modes, and byte-identical
diffs with 1, 4 and 16 workers.

### 7.7 Proposals, catch-up, promote, upgrade check, rebase

- **Proposals and catch-up** replay connection inputs like any root input.
- **Promote** switches code at `effective_lsn`. Live connections stay
  open, and their later inputs run the new code. A kind whose new code
  lacks the export shows failing frame turns in the diff before promote
  (`no-new-errors` denies), and promote warns (§2.6).
- **`kronik upgrade check`** replays connection turns like all others.
  `fuel_used` is not compared across engines.
- **Rollback via replay** (M13): the switch closes the live connections of
  the rebased kinds (reason `rebase`, 1012). After the switch, every
  connection that the rebased state holds open gets a host close with the
  reason `rebase`, through the restart path of §4.8. A live connection
  that the rebased history never accepted is closed on the wire without
  any input, because in that history it never existed.
- **`kronik watch` guards** count failed connection turns in the error
  rate like other turns.

## 8. Privacy

| Value | Subject | Sealed in `on` mode |
| --- | --- | --- |
| The open's request (path, query, params, headers) | the request's subject | yes, as HTTP |
| The offered subprotocols (`Sec-WebSocket-Protocol`) | the request's subject | yes, as a header of the request; no other copy is recorded, and the accept keeps only the selected value's position |
| Incoming frame data, a client's close reason | the connection's subject (§4.10) | yes |
| Outgoing frame data, an actor's close reason | the turn's default subject at the call | yes |
| A `send-now` request | the turn's default subject | yes (`EffectRecord.request`) |
| The accept's header values | the turn's default subject | yes |
| Connection ids, routes, codes, causes, counts, SSE `event`/`id` | none | never (not personal data; the docs tell authors to keep personal data out of event names and ids) |

- **Erasure** makes a subject's frames unreadable everywhere (they are
  `Sealable`s). Live connections are not closed by an erasure. Later
  inputs of the same subject id are sealed under its new key
  (m8-privacy §2).
- **`--no-pii` forks** see pseudonyms in frame data like in every value,
  and a divergent turn that read one is marked `pii-masked`.
- **API redaction:**
  - history shows frame sizes and kinds, never data;
  - `GET /v1/turns/{id}` renders data with `render_sealable`: `[sealed]`
    without `pii:read`, `[erased]` after an erasure;
  - diffs redact as `DiffValue`;
  - the `connections` API shows `subject` only with `pii:read`;
  - `Sec-WebSocket-Protocol` is a credential header
    (`kronik_core::http::credential_header`), so the turn JSON, history and
    MCP show it only with `pii:read`. The accept records the selected
    subprotocol only as its position in that list (§6.1), so the record
    holds no copy of the header's values outside the header itself, which
    is sealed like every header. The turn JSON shows the position, and with
    `pii:read` also the value, resolved from the open's request in the
    same record.
- The `connections` table holds no personal data beyond the subject id,
  which `kv.subject` and the SQL `_subject` column hold already.

## 9. Capabilities and policy

- **No grant** is needed to declare connection routes, to accept, or to
  `send`, `broadcast` and `close` on the connections an actor accepted. The
  routes are the kind's interface, like HTTP routes, and buffered frames
  are its answer, like an HTTP response, which is the reading of I6 that
  HTTP routes already rely on.
- **`send-now`** needs `kronik grant <kind> connection:send-now --reason
  ...`. Deploy warns about a requested but ungranted capability with the
  exact command, as for every capability. `--delivery` other than
  `unsafe` and `--rate` are refused for it with `BAD_REQUEST` ("send-now is
  always unsafe; its pace is the connection's").
- **Policy:**
  - Rules can read `diff.frames.*`, for example `when =
    "diff.frames.changed > 0"`, `action = "require_approval"`.
  - The default rules do not change. `no-new-errors` already stops code
    whose connection turns fail.
  - `send-now` effects are outside `grounding`, so the confidence rules do
    not see them (ADR 0116).

## 10. Limits

| Limit | Default | Where | When exceeded |
| --- | --- | --- | --- |
| Live connections | 4,096 | `[connections] max_open` and the open-file limit | 503 `CONNECTION_LIMIT` |
| Per owner | 2,048 | `max_per_actor` | 503 `CONNECTION_LIMIT` |
| Per client address | 256 | `max_per_client` (trusted proxies exempt) | 503 `CONNECTION_LIMIT` |
| Incoming message | 64 KiB, and the kind's `message_bytes` | `max_frame_bytes` | close `too-large` (1009) |
| Incoming frames admitted per connection | 16 | `inflight_frames` | reading pauses |
| Incoming pace per connection | 50/s | `inbound_rate` | reading pauses |
| Outgoing queue per connection | 1 MiB | `outbound_queue_bytes` | close `slow-consumer`; a `send-now` waits up to the effect timeout |
| Outgoing frame | the kind's `message_bytes` (1 MiB) | `kronik limits set --message-size` | trap |
| Per turn: operations, targets, bytes | 10,000; 100,000; 16 MiB | constants (§4.11) | trap |
| Open turn | 30 s | `[gateway] timeout` | 504, then `abandoned` |
| Ping | 30 s, then 30 s | `ping_interval`, `ping_timeout` | close `ping-timeout` |

## 11. Metrics and logs

On the admin listener's `/metrics`, next to the existing `kronik_*`
metrics (`docs/guides/operations.md` lists them):

| Metric | Type | Labels |
| --- | --- | --- |
| `kronik_connections_open` | gauge | `kind`, `protocol` |
| `kronik_connections_opened_total` | counter | `kind`, `protocol`, `result` = `accepted`, `refused`, `failed` or `limit` |
| `kronik_connections_closed_total` | counter | `kind`, `protocol`, `cause` |
| `kronik_connection_frames_total` | counter | `kind`, `protocol`, `direction` = `in` or `out` |
| `kronik_connection_frame_bytes_total` | counter | `kind`, `protocol`, `direction` |
| `kronik_connection_frames_dropped_total` | counter | `kind`, `protocol` (outgoing frames never written) |
| `kronik_connection_send_now_total` | counter | `kind`, `result` = `ok`, `closed`, `timeout`, `denied` or `outcome_unknown` |
| `kronik_connection_queued_bytes` | gauge | (all outgoing queues together) |

`kronik_effects_total` counts `connection.send-now` like other effects.

The `tracing` events are:

- `debug` for an open and a close (connection id, owner, cause);
- `info` for a slow-consumer, ping-timeout or too-large close;
- `info` for a refusal over a cap;
- `warn` when the shutdown grace runs out.

None carries frame data.

## 12. API, CLI and MCP

The JSON API (`/v1`, m1-core §4 conventions; OpenAPI regenerated):

| Method and path | Scope | Request | Response |
| --- | --- | --- | --- |
| `GET /v1/connections?actor=&kind=&state=open\|closed\|all&after=&limit=` | `read` | | `{"connections": [Connection], "next": "<id>"\|null}`, open ones by default |
| `GET /v1/connections/{id}` | `read` | | `Connection` with `opened` and `closed` turn ids and counts; `CONNECTION_NOT_FOUND` |
| `POST /v1/connections/{id}/close` | `operate` | `{"code": 1008, "message": "...", "reason": "...", "dry_run": false}` | `{"dry_run", "connection": Connection}`; `CONNECTION_NOT_FOUND` when not live |

Closed connections come from `connection_history` (§6.5): the API lists
them until the retention base passes their close, and after that answers
`CONNECTION_NOT_FOUND` for them, as for their turns.

`Connection`:

```json
{
  "id": "c-…",
  "actor": "chat/lobby",
  "protocol": "websocket",
  "route": "/chat/{key}/ws",
  "state": "open|closing|closed",
  "opened": {"turn_id": "main:…", "logical_time_ms": 0},
  "closed": {"turn_id": "main:…", "initiator": "client|actor|host", "cause": "client|actor|restart|…", "code": 1000} | null,
  "frames": {"in": 0, "out": 0, "written": 0, "dropped": 0, "queued": 0, "unknown": 0},
  "live": {"queued_bytes": 0, "last_pong_ms_ago": 0} | null,
  "subject": "user:1" | null
}
```

- `subject` is shown only with `pii:read`.
- The operator's close is a mutation: `reason` is the operator's reason
  (I12), recorded in the close input's `audit`, and `message` is the
  close frame's reason.
- `dry_run` answers what would be closed.

Changes to existing endpoints:

- **History.** `TurnSummary.input.type` can be `connection`, with a summary
  such as `open c-1f0c… WEBSOCKET /chat/{key}/ws`, `frame c-1f0c… #12 text
  42 B` or `close c-1f0c… client 1000`.
- `TurnSummary` gains `connection_ops`: `[{"op": "send"|"close",
  "targets": N, "connections": [first 20], "kind": "text"|"binary"|"event",
  "bytes": N, "code": N|null, "fates": {"written", "dropped", "queued",
  "unknown"}}]` (§4.7).
- `GET /v1/actors/{kind}/{key}/history?connection=<id>` filters to that
  connection's inputs and the turns that sent to it.
- **The turn JSON** (`GET /v1/turns/{id}`, `turn.schema.json`) shows
  `input.connection`, `connection_ops` with data (redacted as §8),
  `output.accept`, and `send-now` effects (kind, target, status, request).
- **Dead letters** list connection inputs, and `resend` admits them (§4.9).

The CLI (`kronik <noun> <verb>`, `--json` everywhere):

- `kronik connections list [--actor kind/key] [--kind K] [--state
  open|closed|all]`;
- `kronik connections inspect <id>`;
- `kronik connections close <id> [--code N] [--message TEXT] --reason R
  [--dry-run]`;
- `kronik history <kind/key> [--connection <id>]`.

The JSON reference and the CLI reference are regenerated.

MCP: a tool `list_connections` (scope `read`), the same as `GET
/v1/connections`, with an `id` argument for one connection.
`query_history` and `trace_turn` show connection inputs and operations
without change. Closing stays a CLI and API operation for operators.

`kronik explain` topics: `connections` (the model, send against
`send-now`, ownership, the close guarantee) and `send-now`.

## 13. Error codes and explain topics

New in `kronik-core::error`, and from there in `docs/errors.md` (generated):

| Code | HTTP | Title | Hint |
| --- | --- | --- | --- |
| `CONNECTION_NOT_FOUND` | 404 | No such connection, or it is not open | List connections with `kronik connections list`. |
| `CONNECTION_NOT_HELD` | 403 | The actor used a connection it did not accept | Only the actor that accepted a connection can send on it or close it; send that actor a message instead (`kronik explain connections`). |
| `CONNECTION_LIMIT` | 503 | The gateway holds as many connections as it may | Try again later; operators raise `[connections] max_open`, `max_per_actor` or `max_per_client`. |

- A trap whose message starts with `CONNECTION_NOT_HELD:` gets that code as
  the turn's error code, as `NOT_IMPLEMENTED` and `REPLAY_DIVERGED` do in
  `turn.rs` `classify_error`. An HTTP client still sees `TURN_FAILED`, as
  for every failed turn.
- These codes are used as they are: `ROUTE_NOT_FOUND`, `ROUTE_CONFLICT`,
  `BAD_REQUEST`, `GATEWAY_TIMEOUT`, `UNAVAILABLE`, `NOT_IMPLEMENTED`,
  `TURN_FAILED`, `EFFECT_OUTCOME_UNKNOWN`, `CAPABILITY_NOT_GRANTED`,
  `PAYLOAD_TOO_LARGE` (an operator message only) and `STORAGE_CORRUPT`.
- The glossary (generated from `kronik-core`) gains "Connection" and
  "Frame", as familiar concepts (I13).

## 14. Deterministic simulation (`kronik-sim`)

**Model.** A new workload `connections`, `ScenarioConfig::connections_for_seed`,
part of `--scenario all`:

- **The guest:** `tests/guests/room.wasm`, from its own crate
  `tests/guests/room` (like `tests/guests/leaky`, so that the
  `test-actor` builds keep their bytes), built for the world
  `actor-connections`; its feature `fmt2` builds `room-fmt2.wasm` and
  `bare` builds `room-bare.wasm` (the same routes without the export, for
  the deploy check). It is the room of §16 in Rust: members in
  state, a room sequence, `say`, `stream <n>` (n `send-now` tokens, then a
  buffered `done`; an unhandled `outcome-unknown` fails the turn),
  `stream-safe <n>` (the same, but it handles `outcome-unknown` and records
  it in state), `kick <conn>`, `bye`, a refusal for `deny=1`, and an open
  that makes a `call` for `call=1` (to get a `TurnBegin`). The sim deploys
  it with `connection:send-now` granted.
- **Clients:** K = 2 to 6 simulated clients per seed. Each opens a
  connection to one of R = 1 to 3 rooms (WebSocket, sometimes SSE) through
  `Gateway`'s connection path and the hub, with a `SimTransport` in place of
  tungstenite. The transport has a bounded "kernel buffer" and a receive
  log.
- **What clients do:** send M frames each; sometimes vanish without a
  close, close cleanly, stop reading (a slow consumer) or reconnect.
- **Faults:** the existing ones (crashes at random points with lost or torn
  unsynced writes, fsync errors, clock jumps, lost `state.db`), plus
  graceful stops.

**Properties**, checked continuously and at the end:

| | Property |
| --- | --- |
| C1 | Every accepted connection gets exactly one gateway-admitted close input. At the end (clients gone, node restarted), no connection is open in `state.db`. |
| C2 | A connection's committed frame inputs have incoming seqs 0..n−1 exactly (a crash can only cut a suffix), and n is at most what the client sent. |
| C3 | A client never receives a buffered frame before the record that holds it is durable on the simulated disk, and never one of a failed turn. |
| C4 | A client receives its connection's frames in strictly increasing outgoing `seq`, without duplicates. When `frames_written` is known, the client received exactly the seqs below it. |
| C5 | `send-now`: none before its `TurnBegin` is durable (I14); none performed twice for one execution id and ordinal; none performed by a re-run without a recorded result (`OUTCOME_UNKNOWN` recorded instead) (I17). |
| C6 | A client receives frames only from its connection's owner. |
| C7 | The `connections` table after recovery equals a rebuild from the log (in the `rebuild` scenario's recovery check). |
| C8 | Identity replay of the run's log is empty in both modes (every 10th seed in CI, every seed nightly). |
| C9 | The run is a deterministic function of the seed (trace hash). |

**CI.** `scripts/ci.sh dst` runs 200 seeds per scenario as today, now with
`connections`. Nightly runs 10,000 seeds and the long run with
`connections` in the mix. A deliberate mutation
(`--mutation deliver-before-fsync`) must make C3 fail for some seeds, as
`ack-before-fsync` does for the counter.

## 15. SDKs

The same API in four languages, in the style of the M15 table
([m15-sdks](m15-sdks.md) §2):

| Concept | TypeScript | Rust | Python | Go |
| --- | --- | --- | --- | --- |
| Routes | `{ method: 'WEBSOCKET', pattern }`, `{ method: 'SSE', pattern }` | `Route::websocket(p)`, `Route::sse(p)` | `Route.websocket(p)`, `Route.sse(p)` | `kronik.WebSocket(p)`, `kronik.SSE(p)` |
| Handlers | `connections: { open(req, ctx), frame(frame, ctx), close(closed, ctx) }` | `fn connection_open / connection_frame / connection_close` on `Actor` | `connections=kronik.Connections(open=…, frame=…, close=…)` | `Connections: &kronik.Connections{Open, Frame, Close}` |
| Accept, refuse | `return ctx.accept({ subprotocol, headers, subject })`; any HTTP output (`ctx.status(403)`) refuses | `Ok(OpenReply::accept(..))`, `Ok(OpenReply::refuse(Output::status(403)))` | `return ctx.accept(...)`, `return ctx.status(403)` | `return ctx.Accept(...)`, `ctx.Status(403)` |
| Frames | `Frame.text(s)`, `Frame.json(v)`, `Frame.binary(b)`, `Frame.event({event, id, data})`; a string or a `Uint8Array` is taken as text or binary | `Frame::text/json/binary/event` | `Frame.text/json/binary/event` | `kronik.TextFrame/JSONFrame/BinaryFrame/EventFrame` |
| Send, broadcast, close | `ctx.connections.send(conn, frame)`, `.broadcast(conns, frame)`, `.close(conn, code = 1000, reason = '')` | `ctx.connections().send / broadcast / close` | `ctx.connections.send / broadcast / close` | `ctx.Connections.Send / Broadcast / Close` |
| Send now | `ctx.connections.sendNow(conn, frame): boolean` | `send_now(&conn, frame) -> Result<bool, ConnectionError>` | `send_now(conn, frame) -> bool` | `SendNow(conn, frame) (bool, error)` |
| Request helpers | `req.connection`, `req.protocol`, `req.subprotocols`, `req.origin()`, `req.lastEventId()` | same, in snake case | same | same, in Go case |
| Incoming frame | `frame.connection`, `frame.seq`, `frame.kind`, `frame.text()`, `frame.bytes()`, `frame.json()` | same | same | same |
| Close info | `closed.connection`, `closed.initiator`, `closed.code`, `closed.reason` | same | same | same |

- `sendNow` returns `true` when the frame was handed over and `false` when
  the connection is closed (including a slow client).
- It throws (raises, returns an error) `OutcomeUnknown` for
  `outcome-unknown`, which the guest may catch: uncaught, the turn fails
  with `EFFECT_OUTCOME_UNKNOWN`. It throws the SDK's host error with
  `CAPABILITY_NOT_GRANTED` for `denied`.
- Error messages end with `see: kronik explain connections`.

**Build.** `kronik build` targets `actor-connections` for all four
languages (ADR 0113):

- TypeScript: `--world-name actor-connections`, and the generated shim
  exports `handler` and `connectionHandler` from the actor's default
  export;
- Rust: `kronik_sdk::export!` exports both;
- Python and Go: their world files include `actor-connections`, and the Go
  bindings are regenerated with the pinned wit-bindgen-go.

The SDKs' own WIT copies (`sdk/python/wit`, `sdk/go/wit/deps`) are
regenerated from `wit/kronik-actor.wit`. An actor without `connections`
handlers gets defaults that refuse opens with 404 and reject frames and
closes, as the other unhandled inputs are rejected.

**Test kits.** Each SDK's test kit gains `openConnection(actor,
request)`, which returns `{connection, accepted, response}`, plus
`sendFrame(conn, frame)`, `closeConnection(conn, initiator, code, reason)`
and `framesSent(conn)`. They run the handlers against the in-memory host,
which records frames and closes, and `send-now` with a stubbed outcome.

## 16. The example app `chat-ts`

`examples/chat-ts/` (TypeScript, built by `scripts/build-examples-ts.sh`,
run by `scripts/identity-examples.py` and the M24 acceptance):

| Route | What |
| --- | --- |
| `GET /chat/{key}` | A small HTML page with a WebSocket client, for trying it by hand. |
| `WEBSOCKET /chat/{key}/ws?user=<id>` | Join room `{key}` as `user:<id>` (`[a-z0-9_-]{1,32}`); the accept sets the subject. `Origin` is checked against the request's `Host`. |
| `SSE /chat/{key}/events` | Read-only followers: one `message` event per message, `id` = room seq. `Last-Event-ID` resumes with the missed messages (at most 100). |
| `GET /chat/{key}/messages?after=<seq>` | Resynchronization after a reconnect. |
| `POST /chat/{key}/messages` | Post over HTTP: stored and broadcast to the room's connections (frames from an HTTP turn). |
| `GET /chat/{key}/members` | The members, for tests. |

- **State.** SQL table `messages(seq INTEGER PRIMARY KEY, user TEXT, text
  TEXT, ts INTEGER, _subject TEXT DEFAULT (kronik_subject()))`. KV keys
  `member/<conn>` = `{user, protocol}`.
- **Incoming frames** (JSON): `{"type": "say", "text", "id"}` stores the
  message and broadcasts it. `{"type": "bot", "prompt"}` streams a
  deterministic "answer" token by token with `sendNow`, then broadcasts
  the whole answer with `broadcast`. That needs `kronik grant chat
  connection:send-now`; without the grant the bot answers in one buffered
  frame.
- **Outgoing frames** (JSON): `welcome {connection, members, last}`,
  `joined {user}`, `message {seq, user, text, ts, id}` (one `broadcast` per
  message, including the sender: its acknowledgement), `token {ref, text}`
  and `left {user}`. SSE followers get the same `message` as events.
- **Close** removes the member and broadcasts `left`.
- **Trust.** The example takes the user id from the query, which is fine
  for a demo. A real app checks a token in `open` before it sets the
  subject (§4.10, §5.13).
- **`src/step2.ts`** changes only how messages are formatted: `message`
  carries `body` instead of `text`. Criterion 2's formatting change.
- **Tests** (the TS test kit): join, broadcast to members, ownership
  (sending to another room's connection traps), refusal of a bad user id,
  SSE resume from `Last-Event-ID`, the bot's stream with and without the
  grant.

The core of the handlers, as the SDK of §15 would read:

```ts
export default actor({
  kind: 'chat',
  schemaVersion: 1,
  routes: [
    // and GET /chat/{key}, GET /chat/{key}/members
    { method: 'WEBSOCKET', pattern: '/chat/{key}/ws' },
    { method: 'SSE', pattern: '/chat/{key}/events' },
    { method: 'GET', pattern: '/chat/{key}/messages' },
    { method: 'POST', pattern: '/chat/{key}/messages' },
  ],
  capabilities: ['connection:send-now'],
  migrate(_from, ctx) {
    ctx.sql.execute('CREATE TABLE messages (seq INTEGER PRIMARY KEY, user TEXT, text TEXT, ts INTEGER, _subject TEXT DEFAULT (kronik_subject()))');
  },
  connections: {
    open(req, ctx) {
      const user = req.query('user');
      if (!user || !/^[a-z0-9_-]{1,32}$/.test(user)) return ctx.status(400);
      if (req.protocol === 'websocket' && !sameOrigin(req)) return ctx.status(403);
      ctx.subject(`user:${user}`);
      ctx.state.setJson(`member/${req.connection}`, { user, protocol: req.protocol });
      if (req.protocol === 'sse') resume(ctx, req.connection, Number(req.lastEventId() ?? 0));
      else ctx.connections.send(req.connection, Frame.json({ type: 'welcome', connection: req.connection, members: members(ctx), last: lastSeq(ctx) }));
      broadcast(ctx, { type: 'joined', user }, req.connection);
      return ctx.accept({ subject: `user:${user}` });
    },
    frame(frame, ctx) {
      const m = frame.json<{ type: string; text?: string; id?: string }>();
      if (m.type === 'say') say(ctx, memberOf(ctx, frame.connection).user, m.text ?? '', m.id);
    },
    close(closed, ctx) {
      const member = memberOf(ctx, closed.connection);
      ctx.state.delete(`member/${closed.connection}`);
      if (member) broadcast(ctx, { type: 'left', user: member.user });
    },
  },
});
```

## 17. Cluster forward compatibility

This is not a cluster design. It records what M24 keeps open for M16 to
M18:

- **The connection lives on the gateway node.** The hub is per node.
  `ConnectionInput.gateway` (empty on a single node) records which node
  holds the socket, so the owner's shard leader knows where to send
  committed frames.
- **Frames are routed to the owner's shard leader.** Incoming frames carry
  their `seq`. If the leadership moves, the gateway node resends the frames
  that are not committed in order, and the shard deduplicates them by
  (connection, `seq`), as messages between shards are by message id.
- **Outgoing frames go back from the leader to the gateway node** with
  their seqs. The gateway node writes in `seq` order and ignores seqs below
  its count, so a resent delivery is idempotent. Ownership (ADR 0114) means
  that one shard writes to each connection.
- **`send-now` across nodes** is an RPC from the leader to the gateway
  node. A lost answer is an uncertain outcome, which gives
  `outcome-unknown` (I17).
- **A gateway node dies:** its connections are closed. The leaders of the
  owners' shards admit host closes (a new cause, `CLOSE_CAUSE_GATEWAY_LOST`;
  enums grow additively), and incoming frames that were not committed are
  not acknowledged (brief).
- **A shard leader changes:** connections survive. `restart_after_lsn`
  becomes per gateway node's incarnation.
- **The caps** (`[connections]`) stay per gateway node.

## 18. Acceptance plan

The four M24 criteria, each with its proof. Everything except criterion 1
runs in CI (`test` and `ts` steps) and locally. Criterion 1 runs on the
test VPS: 2 vCPUs, about 4 GiB of RAM, no KVM.

### Criterion 1: `chat-ts` handles 1,000 concurrent WebSocket clients on the test VPS

**Tool.** `tools/loadgen` gets a `chat` mode. It stays without
dependencies: a minimal RFC 6455 client (handshake with the
`Sec-WebSocket-Accept` check, masked text frames, ping replies, close), a
thread per client with a 64 KiB stack, and JSON output like the HTTP
modes.

```text
loadgen chat --addr 127.0.0.1:<port> --clients 1000 --rooms 50 \
        --ramp 20 --interval 10 --seconds 600 \
        --sources 127.0.0.1-127.0.0.4 --json
```

`--sources` binds the clients to four loopback source addresses, so the
per-client cap (§5.11) is not what is measured.

**Workload:**

- 1,000 clients in 50 rooms of 20, connecting over 20 s.
- Then 10 minutes in which every client sends a `say` every 10 s, with
  ±20 % jitter. That is about 100 incoming frames/s and about 2,000
  outgoing frames/s.
- Then every client closes.
- Each message carries the client's id and send time. Recipients measure
  end-to-end latency (one host, one clock). Every client checks that the
  room sequences it receives form one gap-free, duplicate-free range from
  its welcome to its close.

**The script.** `scripts/acceptance-m24.sh load`:

- builds `chat-ts` and the release `kronik` and `loadgen`;
- starts `kronik serve` on a fresh data directory, with `[connections]
  max_open = 4096` and `max_per_client = 512`;
- deploys `chat-ts` and runs the load;
- samples the daemon's `VmRSS`, `VmHWM` and CPU every 10 s from `/proc`;
- writes one JSON report.

**Pass when all hold:**

1. all 1,000 connections are accepted, with no refusal and no unexpected
   close;
2. gaps = 0, duplicates = 0, and deliveries received = deliveries expected;
3. end-to-end latency p50 ≤ 50 ms and p99 ≤ 250 ms;
4. the daemon's `VmHWM` ≤ 1.5 GiB, and `VmRSS` grows less than 10 % over
   the steady 10 minutes;
5. during the steady phase, `kronik connections list --state open --json`
   counts 1,000, and after the close phase 0;
6. no dead letters;
7. `kronik history chat/<room>` shows 20 opens and 20 closes for a sample
   room.

The results (and the idle cost of 1,000 connections, VmRSS with and
without them) go into `docs/perf.md` under "M24" and into the wiki's
performance evidence.

**The estimate behind it** (from `docs/perf.md`): a TypeScript counter
turn costs about 4.5 ms of CPU on the VPS (436 to 458 turns/s on two
vCPUs). A chat frame turn (JSON, one SQL insert, one broadcast) is
expected at 6 to 9 ms, so 100 frames/s need 0.6 to 0.9 of a vCPU. Each
room gets 2 frames/s, far below the about 200 turns/s one actor can
commit. Memory: about 600 MiB for the TypeScript engine pool, and under
20 KiB per idle connection (4 KiB read buffer, queues, task). §21 Q3 asks
the maintainers to confirm this workload as the meaning of "handles".

### Criterion 2: identity replay of a recorded WebSocket session is empty, and a changed message format shows as changed outgoing frames

**In `cargo test`,** without the TypeScript toolchain:
`crates/kronik-fork/tests/connections.rs` uses the Rust room guest
(`tests/guests/room.wasm` and `room-fmt2.wasm`).

1. Record a session on a test node through the hub with fake transports:
   - 3 WebSocket clients and 1 SSE follower;
   - 30 `say` frames and one `stream 3` (send-now);
   - one client vanishes, one is kicked (an actor close), one says `bye`;
   - an HTTP `say`;
   - a restart, which gives a restart close.
2. Fork before the session and replay with the same code:
   - `summary.changed == false`, and no `frames` items;
   - `frames.changed == 0`, `send_now.modeled == 0`;
   - in both isolated and continuous mode;
   - byte-identical diffs with 1, 4 and 16 workers.
3. Propose `room-fmt2.wasm`:
   - `frames.changed` equals the number of frame inputs that sent a
     message, and each item's operations are the format change;
   - `responses.changed == 0`, `state` and `cumulative` are empty,
     `errors.introduced == 0`;
   - the origins are the frame inputs;
   - the diff validates against the schema.

**End to end,** in the `ts` step: `scripts/acceptance-m24.sh replay`
drives `chat-ts` on a real daemon with real WebSocket and SSE clients.
These are Python's standard library plus a minimal client in
`scripts/m24_ws.py`. Then:

- `kronik fork create --at <before> --reason ...`, then `kronik replay
  <fork> --mode both --json`: an empty diff;
- `kronik propose examples/dist/chat-ts-step2.wasm --at <before> --reason
  ...`: `frames.changed > 0`, and every changed item is a `message` frame
  whose operations are `remove /text` and `add /body`.

`chat-ts` also joins `scripts/identity-examples.py`, so the Definition of
done's "identity replay empty for all example apps" covers it.

### Criterion 3: a crash after `send-now` but before a recorded result does not resend the frame, and the guest gets `outcome-unknown`

**`crates/kronik/tests/kill_connections.rs`** (the M2 SIGKILL pattern of
`tests/kill.rs`) runs the real `kronik serve` as a child process, with the
hidden flag `--test-hold-after-send-now`. That flag parks the turn after
the hub wrote the frame to the socket and before the `EffectResult` is
appended.

1. A raw WebSocket client opens a connection to the room guest and sends
   `stream 3`.
2. The client receives `tok 0`, which marks the hold point. The harness
   SIGKILLs the daemon and restarts it on the same data directory.
3. Then:
   - the log has the `TurnBegin` before the frame (I14);
   - the re-run's record has the `send-now` at that ordinal with status
     `OUTCOME_UNKNOWN` and the frame in the request;
   - `tok 0` was received exactly once over the whole run (the old
     connection's transcript), and no later connection of any client
     received it;
   - the variant without handling fails with `EFFECT_OUTCOME_UNKNOWN`,
     and `kronik dead-letters list` shows the frame input;
   - the variant that handles it (`stream-safe 3`) commits and records
     `unknown=1` in state;
   - the connection got its restart close (§4.8).

**In-process,** `crates/kronik-sched/tests/connections.rs` drops the
daemon's runtime at the same point, as `tests/effects.rs` does for fetch.
DST property C5 covers it under random crashes.

### Criterion 4: connections broken by a restart are closed with a dedicated reason, and the clients can reconnect

**`crates/kronik/tests/connections_restart.rs`** (a real daemon, real
sockets), with 20 WebSocket clients and 5 SSE followers on the room guest:

1. **SIGTERM:**
   - every WebSocket client receives a close frame with code 1012 and the
     reason `kronik: restart`;
   - every SSE stream receives `retry:` and ends.
2. **Restart:**
   - every old connection has a close input (cause `RESTART`, initiator
     host, code 1012, reason `restart`), recorded before the first new
     open of its actor;
   - `kronik connections list --state open` is empty before the clients
     return;
   - the clients reconnect with backoff, every reconnect is accepted, and
     `GET /room/<key>/members` equals the reconnected set (no stale
     member).
3. **SIGKILL:** the same, except that the clients see an abnormal closure
   (1006) instead of 1012, and the restart closes have
   `frames_written_known = false` and `restart_after_lsn` set.
4. **A crash inside an open turn:** the client opens with `?call=1`, so
   the open turn makes a `call` and has a `TurnBegin`. `serve
   --test-hold-after-call` (the M2 hold) parks it after the callee commits,
   and the harness SIGKILLs the daemon. After the restart, the re-run
   accepts, the hub closes the connection with the reason `restart`, and
   the client, which never got its 101, reconnects.

**End to end:** `scripts/acceptance-m24.sh restart` runs `loadgen chat
--clients 200 --reconnect` against `chat-ts`. It restarts the daemon once
gracefully and once with SIGKILL. All 200 clients must be connected again
within 30 s, the room sequences must stay gap-free after each client's
resynchronization (`GET /chat/{key}/messages?after=`), and there must be
no dead letters.

## 19. Implementation plan

Fourteen slices, in this order. Each keeps `scripts/ci.sh fmt clippy
hygiene` and the touched crates' tests green, and leaves earlier behavior
unchanged. "M25" below means the M25/M26 work (ADRs 0117 to 0122).

| # | Slice | Touches | Proven by | Parallel with M25/M26? |
| --- | --- | --- | --- | --- |
| 1 | **WIT 0.1.1 and the export.** The whole `connections` interface and `connection-handler` (every function traps `NOT_IMPLEMENTED`); the package bump; `actor-connections`; the second `bindgen!` with `with:`; `Program` detects the export; the allowlist; `WEBSOCKET`/`SSE` in `METHODS` and conflicts; the deploy check; `docs/reference/wit.md`; the SDK WIT copies regenerated. | `wit/`, `kronik-runtime` (`host.rs`, `turn.rs`, `allowlist.rs`), `kronik-sched` (`validate_manifest`, `check_routes_of`), `docs/reference/wit.md`, `sdk/python/wit`, `sdk/go/wit` | Corpus components (`tests/compatibility`) link and replay under 0.1.1; a guest with the export links; allowlist tests; route conflict and deploy-check tests | **Conflicts** with M25's WIT slice (same files). Land one, rebase the other; the first bumps the version. |
| 2 | **The log format.** The messages of §6.1 and §6.2 in `common.proto`, `input.proto`, `turn.proto` and `effects.proto`; `Input` 5; `TurnRecord` 30; `Outcome` 6; `EffectStatus` 12; validation; `sealables`; turn JSON and `turn.schema.json`; golden tests. | `proto/`, `kronik-proto`, `kronik-api` (turn JSON), `docs/reference/turn.schema.json` | Round-trip and validation tests; sealables visit every new field (seal/unseal test); old fixtures read | **Textual conflicts only** (`common.proto`, `turn.proto`, `effects.proto`, schemas). Parallel with care. |
| 3 | **The `connections` table.** The applier rules of §6.5; `HASHED_TABLES`; queries; retention compaction; `StateView::connection`. | `kronik-store`, `kronik-sched` (`KvView`) | Apply against rebuild equality; state hash; retention test | Parallel (M26's `blob_refs` table is a textual neighbor in `db.rs`). |
| 4 | **Turn path for buffered operations.** The host's `send`, `broadcast` and `close` (ownership, limits, seqs); the `connection-handler` calls; checking the open reply; `TurnOutput.connection_ops`; `run_turn` records field 30 and `accept`; failed turns drop them; dead-letter resend of connection inputs; the test guest `room` (Rust). | `kronik-runtime` (new `host/connections.rs`), `kronik-sched` (`node.rs`), `tests/guests/room` (its own crate), `scripts/build-test-guests.sh` | `kronik-sched` tests through `Node::connection_*` with fake transports: accept, refuse, failure; order; `CONNECTION_NOT_HELD`; broadcast; close; dead letters and resend | Parallel. Textual conflicts in `run_turn` with M26's blob-ref buffering. |
| 5 | **The hub.** Registry, queues, in-flight window, `deliver`, exactly one close, abandoned opens, restart closes in `Node::start`, `shutdown`, metrics. | `kronik-sched` (new `connections.rs`), `NodeParts` | Hub tests: seq order, `frames_written`, slow consumer, restart closes after a store reopen, an actor that sleeps (§5.10) | Parallel. |
| 6 | **Gateway WebSocket.** Classification; the handshake; caps and the `[connections]` config; 101 after commit; tungstenite tasks; ping and pong; close codes; the graceful 1012; `server.rs` `.with_upgrades()`; `serve.rs` wiring and caps; `kronik doctor`. | `kronik-gateway` (new `connections/`), `kronik/src/serve.rs`, `config` | `kronik-gateway` tests; `crates/kronik/tests/connections.rs` (a real daemon and client): open, frames, every close cause, limits | **Conflicts** with M25's gateway body slice in `server.rs` and `lib.rs`. Serialize these two. |
| 7 | **Gateway SSE.** The SSE route path; `ResponseBody::Events`; the encoder; heartbeat; disconnect detection; `Last-Event-ID`. | `kronik-gateway` (`connections/sse.rs`, `body.rs`) | Encoder unit tests (multi-line data, CR/LF refusal); a real EventSource-style client test; resume test | **Conflicts** with M25's `body.rs` (the agreed either-order rebase). |
| 8 | **`send-now`.** `EffectGate::send_now`; the grant rules of `connection:send-now`; I14; the `EffectResult`; the re-run's `outcome-unknown`; the hub's wait; the open-turn trap; `--test-hold-after-send-now`. | `kronik-runtime`, `kronik-sched` (`effects.rs`, `gate.rs`), `kronik-effects` (capability), `kronik` (hidden flag) | Criterion 3's tests (SIGKILL and in-process); grant refusal tests | Parallel. |
| 9 | **Replay and the diff.** Labels; isolated and continuous connection replay; skipping connections the fork does not hold; the replay gate's `send_now` (recorded or the connection model); the `TurnView` additions; the `frames` section, summary, kinds, samples, Markdown, `--summary`; the schema and fixture. | `kronik-fork` (`index.rs`, `replay.rs`, `diff.rs`, `markdown.rs`), `docs/reference/diff-v1.schema.json`, `docs/design/fixtures/` | Criterion 2's `cargo test` part; schema validation; worker-count byte identity | Parallel. Textual conflicts if M25 adds diff fields. |
| 10 | **API, CLI, MCP and errors.** `/v1/connections`, the operator close, history fields and fates, the `?connection=` filter, the dead-letter views; `kronik connections ...`; `list_connections`; the three error codes; explain topics; glossary; OpenAPI, CLI and JSON references regenerated; `AGENT_GUIDE.md`. | `kronik-api`, `kronik` (cli), `kronik-mcp`, `kronik-core` (error, explain), `docs/` generated files | API tests; schema tests; `scripts/ci.sh docs`; the doc-surface check | **Conflicts** on generated files (`openapi.json`, `errors.md`, `cli.md`, `json.md`). Regenerate after rebase, never hand-merge. |
| 11 | **DST.** The `connections` workload, `SimTransport`, C1 to C9, the mutation, CI wiring. | `kronik-sim`, `scripts/ci.sh` (dst seeds) | 200 seeds green; the mutation is caught; nightly 10,000 | Parallel. |
| 12 | **SDKs.** TypeScript (API, `kronik build` world and shim, test kit, `.d.ts` regenerated), Rust, Python, Go (bindings regenerated); `docs/guides/actors.md`. | `sdk/*`, `crates/kronik/src/project/build.rs` | The SDKs' unit tests; `scripts/ci.sh ts sdks`; the import check (`IMPORT_NOT_ALLOWED` test of components) | **Conflicts** with M26's SDK slice (the same files). Serialize. |
| 13 | **`chat-ts` and acceptance.** The example, `step2`, tests; `loadgen chat`; `scripts/acceptance-m24.sh` (load, replay, restart); `scripts/m24_ws.py`; identity-examples entry; `docs/guides/connections.md`; operations and security guide sections; the VPS run and `docs/perf.md`. | `examples/chat-ts`, `tools/loadgen`, `scripts/`, `docs/` | Criteria 1, 2 (end to end) and 4 (end to end) | Parallel. |
| 14 | **Rebase and the release corpus.** The M13 switch closes connections (§7.7); the `m24-connections` compatibility fixture; the release-corpus entry at v0.5.0. | `kronik-sched` (`rebase.rs`), `tests/compatibility/` | The rebase test with live connections; the corpus test | Parallel. |

Slices 4 to 11 can be split among people once 1 to 3 have landed. The
dependencies: 5 needs 4; 6, 7 and 8 need 5; 9 needs 4; 11 needs 5 and 8;
13 needs 6, 7, 8 and 12; 14 needs 5.

## 20. Risks

1. **Per-actor throughput.** One actor commits about 200 turns/s
   ([ADR 0111](../adr/0111-cross-actor-throughput.md)), and a TypeScript
   actor fewer. A busy room is a hot actor. Mitigation: the docs and the
   example shard by room; session actors for cross-room fan-out; the
   measured numbers in `docs/perf.md`. Pipelining an actor's turns would
   help, and would move seq assignment (ADR 0115).
2. **Log volume.** Every outgoing frame is recorded, because the diff
   needs it. The chat workload of §18 writes roughly 150 KB/s with
   `broadcast`, and roughly 400 KB/s with one `send` per member. Mitigation:
   `broadcast` records a payload once, and the operations guide gives
   retention and disk sizing for chat-like apps. Content-addressed frame
   payloads (M25's blob store) are a later option.
3. **Restart storms.** 1,000 connections give 1,000 close turns and then
   about 1,000 open turns. On the VPS that settles in about 5 s.
   Mitigation: jittered client backoff, and per-client caps.
4. **Ordering and accounting bugs** in `seq`, `frames_written` and the
   window. Mitigation: hub unit tests, DST C2 to C5, and a debug assertion
   that the writer receives seqs in order.
5. **The second export** goes against the brief's "one entry point" in the
   WIT. Mitigation: one input in the log, and revisit at the next breaking
   generation (ADR 0113).
6. **tungstenite limits.** No `permessage-deflate` and no WebSocket over
   HTTP/2. Neither is needed by the criteria, and both are documented.
7. **Record size** with very large broadcasts. Mitigation: the per-turn
   caps of §4.11, and the record budget of the issue #26 fix.
8. **Shutdown under systemd.** The 2 s grace must fit `TimeoutStopSec`
   (the shipped unit's default 90 s is enough). The SIGKILL path is covered
   anyway.

## 21. Open questions for the maintainers

Decided on 2026-11-13: the maintainers accepted all four recommendations
below, and ADRs 0113–0116 are Accepted.

1. **Q1. The ABI (project status).** A new minor ABI (0.2.0), or additions
   within 0.1 with a second, optional export? **Recommendation:** additive
   0.1.1 with the optional `connection-handler` export (ADR 0113), agreed
   with the M25/M26 design. Left to a later breaking generation: moving
   connection events into `input`.
2. **Q2. Who may send (project status).** Only the actor that accepted the
   connection, or any actor that knows its handle? **Recommendation:** only
   the accepting actor (ADR 0114). Sharing edges remain possible later as
   an additive interface.
3. **Q3. What "handles 1,000 concurrent clients" means.** The criterion
   names no load. **Recommendation:** the workload and thresholds of §18:
   50 rooms of 20; one message per client every 10 s; 10 minutes; no loss
   or duplicate; p99 ≤ 250 ms; `VmHWM` ≤ 1.5 GiB on the 2-vCPU VPS. A
   measured shortfall goes to `docs/perf.md` and an ADR, as for the other
   performance targets.
4. **Q4. Connections in preview forks.** M11 previews take new HTTP
   requests, and M24 does not extend that to WebSocket and SSE (they answer
   501). **Recommendation:** defer it to after M24. It needs the preview
   router to own its connections, and close them at expiry and restart, and
   no M24 criterion needs it. The approach is in §5.12 and ADR 0116.
