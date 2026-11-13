# 0119. Blob references: borrowed and held, and the reference graph as the authorization graph

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13

## Context

The build brief, M25 and M26:

- A `BlobRef` is identity, not authorization. The host's reference graph is
  also the authorization graph: an actor can only access a blob that it
  already holds, or that it has received through an edge the host tracks:
  HTTP bodies, `message.blobs` in messages, timers and compensations,
  responses to `call`, messages resent from dead letters, and responses from
  `fetch`. A self-constructed reference gives `BLOB_NOT_HELD`, even if the
  hash is correct.
- A reference from an HTTP body or an effect result is borrowed: it gives
  read access during the turn. `blobs.retain` takes ownership (M26),
  `blobs.release` lets go of the actor's own reference, and `put` gives a
  reference the actor holds.
- The turn record writes the changes as `BlobRefOp` `RETAIN` or `RELEASE` in
  `TurnRecord.blob_refs`, where `put` counts as `RETAIN`; they are buffered
  and committed with the turn. If the turn crashes before commit, no
  reference changes. A hash that only sits as bytes in state, SQL or a
  message body is neither a reference nor an authorization.
- A `BlobRef` travels in the message's `blobs` field, never hidden in the
  body: for `send`, `call`, timers and compensations.

The WIT has carried `blob-ref`, `message.blobs` and `http-body.blob` since
v0.1, and the host refuses them today (`NOT_IMPLEMENTED`). Components built
before v0.5 do not know blobs: their SDKs read only inline bodies.

ADR 0113 (M24's design: the v0.5 actor ABI) keeps v0.5 on the
`kronik:actor` 0.1 track: version 0.1.1 adds new interfaces and one optional
export, never new functions in existing interfaces or changed types. The
`blobs` interface is one such new interface
([ADR 0121](0121-blob-interface-and-wasi-0-3.md)).

## Decision

### 1. Opt-in by import

A component *reads blobs* when it imports `kronik:actor/blobs` (any 0.1.x).
The runtime knows this from the component's imports when it loads the
program, so it is a function of the code hash. Only for such a component
does the host produce a `blob` body: an HTTP request body or an effect
response above the threshold (ADR 0117 §7), and the bodies of standard
`fetch`. Every other component keeps the v0.4 behaviour byte for byte: 413
above `[gateway] max_body`, inline effect responses up to
`effect_response_bytes`. Every SDK built for v0.5 imports the interface.

### 2. The turn's references

During a turn of actor `a`, the turn may use exactly the references in its
set `T`:

- every blob `a` holds when the turn starts;
- the references in the turn's input: the HTTP request body; the
  `msg.blobs` of a message, a call (callee side), a timer, a compensation or
  a dead-letter resend;
- every reference the turn obtained: `writer.finish` and `put` results,
  `blob` bodies of `fetch` responses, `msg.blobs` of `call` replies.

`T` is determined by the turn's recorded inputs and its own calls, so it is
the same in re-runs and replays. It only grows during the turn: a released
blob stays readable until the turn ends.

A reference is the pair (identity, size); the host completes it with its
metadata ([ADR 0118](0118-sealed-blob-identity.md) §3) when it writes a
record.

### 3. Every use is checked

| Use of a reference not in `T` | Result |
| --- | --- |
| `blobs.get`, `blobs.retain`, `blobs.release` | `blob-error::not-held` |
| request body of `http-client.fetch` | the effect is denied: an `EffectRecord` with status `DENIED`, error `BLOB_NOT_HELD`, no fsync (deterministic, like a missing capability) |
| `msg.blobs` in `send`, `call`, `timers.schedule`, a compensation; the body of `output::http`; `msg.blobs` of `output::reply` | the turn traps with outcome code `BLOB_NOT_HELD`; nothing it buffered commits |

The same checks run in re-runs and replays. A hash that sits in state, SQL
or a body is bytes; turning it into a `blob-ref` does not put it into `T`.

### 4. Borrowed and held

- A reference in `T` that `a` does not hold is *borrowed*: usable in this
  turn only.
- `retain(r)` (and `put`) makes `a` hold `r` once the turn commits.
  Retaining a held blob changes nothing.
- `release(r)` ends `a`'s own hold once the turn commits; `not-held` if `a`
  does not hold `r`. It never affects another actor's hold, a queued message,
  a timer or any other root.
- Holding is a set per actor, not a count.

### 5. Buffered net operations

The turn record carries the net change of the actor's holds: `RETAIN` for
every blob held at commit and not at turn start, `RELEASE` for every blob
held at turn start and not at commit, sorted by identity. A failed turn
carries none, so a crash or a failure before commit changes no reference.
Applying is idempotent (insert or delete one row per actor and blob). Kind
0 or an unknown kind is `STORAGE_CORRUPT`.

### 6. The edges

| Edge | From | To |
| --- | --- | --- |
| HTTP request body | the gateway (an upload) | the root turn |
| `fetch` response body | the effect | the calling turn |
| `message.blobs` of `send` | the sender's committed turn | the receiver's turn |
| `message.blobs` of `call` | the caller | the callee's turn |
| `call` reply `msg.blobs` | the callee's turn | the caller |
| timer `msg.blobs` | the scheduling committed turn | the timer's turn |
| compensation `msg.blobs` | the failed caller's turn | the compensation turn |
| dead-letter resend | the dead letter | the resend's turn (the same blobs) |

A sender can only put references from its own `T` on an edge. Operator
messages (`kronik send`) carry no blobs in v0.5.

### 7. Bounds

At most 256 references per message and 1 024 blob operations per turn;
`blobs.get`, `put` and writer `write` move at most 1 MiB per call
([ADR 0121](0121-blob-interface-and-wasi-0-3.md)).

## Alternatives

- **Unforgeable handles** (random tokens per reference, as capabilities).
  More state, and a handle could not be stored in state and sent on as the
  same identity; content addressing would stop being the identity. The
  reference graph already gives unforgeability where it matters, at use.
- **An access-control list per blob.** A second graph beside the reference
  graph, kept in sync by hand.
- **References found in body bytes.** The brief forbids it: a hash in bytes
  is data.
- **Counting holds per actor.** No behaviour needs a count, and a count
  invites drift between `retain` and `release` pairs.
- **Recording every call instead of net changes.** Longer records for the
  same applied result.
- **Blob bodies for every component.** v0.4 components cannot read them; a
  large request would fail inside the turn instead of with 413.

## Consequences

- Authorization is a property of the history: a re-run, a replay and a fork
  see the same `T` and give the same `BLOB_NOT_HELD`.
- The materialized table `blob_refs` (actor → blob) is part of the state hash.
- The M26 acceptance test of authorization (actor B learns the hash but not
  the reference) follows from §2 and §3.
- Revisit if references must ever cross a branch (a fork never sends to
  main), or if operator messages need blobs.
