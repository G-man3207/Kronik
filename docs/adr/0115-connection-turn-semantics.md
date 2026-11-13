# 0115. Connection inputs, buffered frames, send-now and closes

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13

## Context

The brief's M24 fixes the outline:

- opening, each incoming frame and closing are root inputs, with the
  connection's handle in the input;
- `connections.send` and `connections.close` are buffered and take effect
  at commit, like `send`;
- `connections.send-now` is an effect with the delivery class `unsafe`; it
  is never sent again after an uncertain outcome, and the guest gets
  `outcome-unknown` on re-execution;
- an acknowledged turn means that Kronik committed the frames and tried to
  deliver them; frames to a closed connection are dropped and show in
  `history`;
- connections broken by a restart are closed with a dedicated reason.

The invariants that bear on it:

- I14: no external effect before `TurnBegin`.
- I17: an uncertain outcome against an `unsafe` target is shown, never
  redone.
- I1/I2: everything a turn sees is recorded or derived from what is.
- I3: guest memory is never state.

Turns already have these properties (`crates/kronik-sched/src/node.rs`):

- An actor runs one turn at a time. Its next turn starts only after the
  previous turn record is fsynced and applied.
- A re-run after a crash answers every `unsafe` effect without a recorded
  result with `outcome-unknown` (`effects.rs`).
- Root inputs are not persisted before their turn: a crash loses the queue.
- HTTP opens with the response after commit, and failed HTTP turns are not
  dead letters.

## Decision

1. **Connection inputs.** Open, frame and close are root inputs of the
   connection's owner (ADR 0114), recorded as `Input.connection`. Each has
   its own causal root. The connection id is `c-` followed by the open
   input's root id, so it is recorded with the open and identical in
   replay. Inbound frames carry `seq` = 0, 1, 2, ... per connection.
2. **The open turn answers.** It answers either accept (an optional
   subprotocol, extra headers and the connection's subject) or refuse (an
   HTTP response). The client gets `101 Switching Protocols` or the `200`
   event stream only after the open turn's record is fsynced. A refusal is
   sent as the actor's response. A failed open turn answers 500
   `TURN_FAILED`. Failed opens are not dead letters: the client got the
   error, as with HTTP.
3. **Buffered frames and close.** `send`, `broadcast` and `close` are
   recorded in the turn record's `connection_ops`, in call order. After the
   record is fsynced and applied, they are handed to the gateway, before the
   turn's result returns. A failed turn records none, and nothing is sent.
   They take no operation ordinal: a frame added in new code must not shift
   the message ids and causal keys of the messages after it.
4. **`send-now`** is an external effect of kind `connection.send-now`.
   - It needs the grant `connection:send-now`. The delivery class is always
     `unsafe`: a grant that names another class, or a rate, is refused.
   - Its `TurnBegin` is fsynced first (I14), and its `EffectResult` is
     fsynced before the guest sees the result. It takes an operation
     ordinal like every effect.
   - `ok` means the frame was handed to the connection's writer in order.
     It does not mean the client received it.
   - `closed` means it was not sent: the connection was closed or closing,
     or the client did not drain within the effect timeout (recorded as
     `TIMEOUT`, after which the gateway closes the connection as a slow
     consumer).
   - A re-run never performs a `send-now` that has no recorded result. The
     guest gets `outcome-unknown`, and if the turn then fails, it fails with
     `EFFECT_OUTCOME_UNKNOWN` (I17).
   - `send-now` on the connection whose open is the current turn traps.
     That connection opens only when the turn commits.
5. **Order on a connection.** Outgoing frames have a per-connection `seq`.
   A turn's `send-now` frames take the next seqs as they are sent; its
   buffered frames take the seqs after them, at the end of the turn. Since
   one owner runs one turn at a time, the order on the wire is the `seq`
   order: within a turn, its `send-now` frames come before its buffered
   ones, and a turn's frames come before the next turn's.
6. **What an acknowledged turn means.** The frames are in the fsynced turn
   record, and each was handed to its connection's writer, or dropped
   because the connection was gone, before the turn's response or reply was
   sent. It does not mean the client received them.
7. **Frames to a closed connection** are recorded and never written. Every
   close carries `frames_written`: frames with a lower `seq` were written,
   the rest were dropped. History shows each outgoing frame as `written`,
   `dropped`, `queued` or `unknown` (unknown after a restart, when the count
   was lost with the process).
8. **Exactly one close per accepted connection.** Whoever ends the
   connection (the client, the actor with `close`, or the host on a limit,
   a ping timeout, an operator close or a slow client), the gateway admits
   exactly one close input. The close comes after the connection's
   admitted frames. After a restart, every connection still open in state
   gets a host close with the reason `restart` and code 1012 (Service
   Restart). This happens before the gateway accepts traffic, so in each
   actor the old connections close before new ones open. On a graceful
   stop, clients get a close frame with code 1012, and SSE streams end
   after a `retry:` hint. The dedicated reason is the same `restart` in
   both cases.
9. **Incoming frames** are admitted in order, with a bounded in-flight
   window per connection. A frame that was read but whose turn never
   committed (a crash) is not acknowledged. After the actor's or the host's
   close, incoming frames are discarded.
10. **Failures.** A failed frame turn or close turn is a dead letter, and
    `kronik dead-letters resend` runs it again as a new root input for the
    same connection. The connection's lifecycle in state does not depend on
    turn outcomes: a close input closes the connection even if its turn
    fails.
11. **Subject.** A connection's inputs are tagged with the subject from
    `privacy.subject_from` at the open, or with the subject the accept sets.

## Alternatives

- **Sending 101 before the open turn and delivering the open afterwards.**
  The handshake would be faster. But the actor could not refuse with an
  HTTP status, and a crash could leave a client with a connection that no
  turn ever accepted. Rejected.
- **`send-now` as a buffered send flushed early, without an effect
  record.** A client could see output that history does not explain, and a
  re-run could send it twice. That breaks I14 and I17. Rejected.
- **No close input when the actor closed the connection itself.** It saves
  one turn, but the actor's clean-up would then live in two places, and the
  "one open, frames, one close" property would have exceptions. Rejected.
- **Committing close inputs during a graceful shutdown.** That is a second
  path next to the crash path, and it runs turns during shutdown. The
  startup path covers both. Rejected.
- **`send` returning whether the connection is open.** The guest's control
  flow would then depend on socket timing. The close input is the signal.
  Rejected.
- **A retry or acknowledgement protocol for frames.** It is not the brief's
  model ("not that the client has received them"). Apps that need it
  number their messages, as the chat example does with a room sequence.

## Consequences

- Identity replay can reproduce every connection turn: ids, seqs,
  `send-now` results and close facts are recorded (ADR 0116).
- A burst of closes after a restart (one turn per connection) is followed
  by reconnects. Clients should reconnect with jitter, as the 1012 code
  advises. The docs and the chat example do.
- Pipelining an actor's next turn before the previous commit
  (`docs/perf.md` lists it as an unmeasured option) would move seq
  assignment to commit time. This ADR then has to be revisited.
- Verified by the M24 acceptance tests: the restart close, the SIGKILL
  after `send-now` before its result, and identity replay. DST checks
  exactly one close, seq order, the prefix property of `frames_written`, no
  `send-now` before its durable `TurnBegin`, and none performed twice.
