# 0114. Only the actor that accepted a connection sends on it or closes it

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13
- **Amended:** 2026-11-13: live connections and a retention bound (see
  [the amendment](#amended-2026-11-13-live-connections-and-a-retention-bound))

## Context

In M24 the gateway holds every WebSocket and SSE connection. The connection
is opened by a request to a route, and that route names one actor
(`kind/key`). The brief says that the connection's open, its frames and its
close "become root inputs to an actor, with a connection handle in the
input", and that "the actor sends with `connections.send(handle, msg)`".
The project status leaves one question open: may only the actor that
accepted a connection send on it, or may any actor that knows the handle?

What bears on the answer:

- **I6, default deny.** An actor can do nothing beyond its own state, its
  messages and its timers until the operator grants a capability. A handle
  is a string. It ends up in state, in message bodies, in logs and in diffs.
  M26 met the same problem for blobs, and decided there that a `BlobRef` is
  identity, not authorization.
- **Order.** Frames on one connection need one total order. The design
  numbers them with a per-connection `seq`, and records how many were
  written (`frames_written`), which makes the written frames a prefix and
  every later frame a drop (`docs/design/m24-connections.md` §4.5). Each
  actor's turns run one at a time, and the next starts only after the
  previous turn record is fsynced and applied. One writer per connection
  therefore gets a total order for free. Several writers do not: with
  several actors, and from v0.4 several shards, nothing orders them.
- **Replay and the diff.** Outgoing frames are compared as responses. If
  only the owner writes, a connection's frames come from one actor's turns,
  whose order replay reproduces.
- **The cluster.** The connection lives on the gateway node, and frames are
  routed to the leader of the shard. With one owner, one shard writes to a
  connection.
- **Fan-out is the main use.** A chat room sends one message to many
  members.

## Decision

1. **A connection has one owner for its whole life:** the actor whose open
   turn accepted it, which is the actor the route named. The owner is
   recorded with the open input and kept in the `connections` table. It
   never changes.
2. **Only the owner's turns may use a connection.** That means
   `connections.send`, `broadcast`, `close` and `send-now`. Any other actor
   using the id, and the owner using an id it never accepted, traps with
   `CONNECTION_NOT_HELD`, which fails the turn. The check reads only
   recorded, immutable facts, so it is deterministic. (Amended 2026-11-13:
   this holds for live connections; an id without a live connection is
   recorded as dropped. Amended 2026-11-14: any id that is not a live
   connection of the turn's own actor is recorded as dropped; nothing traps
   but a malformed id. See the amendments below.)
3. **Handles are data, not capabilities.** Storing an id, logging it or
   sending it in a message grants nothing.
4. **Inputs go to the owner only.** The gateway delivers a connection's
   frames and its close to its owner, and to no one else.
5. **Fan-out goes through ownership or messages.** A room actor that owns
   its members' connections broadcasts to them in one call
   (`connections.broadcast`, recorded once). When the connections belong to
   other actors (say, one session actor per user), the sender sends those
   actors a message, and each forwards it on its own connection: one turn
   per recipient.

## Alternatives

- **Bearer handles: any actor that knows the id may send.** Fan-out is the
  simplest. But ids leak through state, logs and messages, so any actor
  could write to any client, which breaks I6. Frames from several actors,
  and later from several shards, would interleave in no defined order. The
  per-connection `seq` would need a cross-actor counter. And a change to
  one kind could change the frames on connections owned by another.
  Rejected.
- **Recorded sharing edges, like M26's reference graph:**
  `connections.share(conn, to)` would give another actor send rights
  through an edge the host records. Fan-out would then need no extra hop.
  But it brings a second authorization graph with revocation, and order
  across actors and shards. No acceptance criterion needs it. It can be
  added later as a new interface on the 0.1 track (ADR 0113) without
  breaking anything: going from strict to permissive is additive, and the
  reverse is not. Deferred.
- **Kind-wide ownership:** any actor of the owner's kind may send. Order
  across the actors of a kind is still undefined. Rejected.

## Consequences

- Each connection's order is its owner's commit order. `seq` and
  `frames_written` stay simple, and history can show for every frame
  whether it was written, dropped or is still queued.
- An actor runs one turn at a time, which is about 180 to 210 turns/s for
  the Rust counter on the test VPS (`docs/perf.md`). So a room that owns
  1,000 connections handles its incoming frames at that rate at most. Apps
  split rooms, or put connections on session actors. The design and the
  chat example say so.
- Forks and previews can address only connections that their own actors
  accepted. Replay never touches a live socket (I7).
- In a cluster, frames for a connection come from one shard leader.
- Verified by a runtime test (a foreign id traps with
  `CONNECTION_NOT_HELD`), a deploy-free scheduler test with two actors, and
  the DST property that a client receives frames only from its connection's
  owner.
- Revisit if a production app needs cross-actor fan-out that the hop cannot
  carry. Shared edges are the planned extension.

## Amended 2026-11-13: live connections and a retention bound

### Context

Decision 2's check also covers ids that no live connection has: a
connection the actor closed long ago, or an id it never accepted. To answer
it, the state kept every connection's row forever, closed ones included.
Deleting a closed row at a time the log does not record would make a turn's
outcome depend on when the deletion ran, in production and in replay (I1).
So the `connections` table grew without bound, and it is hashed into every
state hash and copied into every snapshot. A reconnect-heavy app (1,000
mobile users reconnecting 20 times a day) would add about 20,000 rows a
day, roughly 2 GB a year.

The brief already answers the case that needs the old rows: "frames to a
closed connection are dropped and show up in history". It does not ask for
a trap.

### Decision

1. **Ownership is checked against live connections.** A connection is live
   from the open turn that accepts it until its close input is applied. The
   rows that turns read hold live connections only.
2. **What a turn's `send`, `broadcast`, `close` or `send-now` does depends
   on its id:**
   - **A live connection of the turn's actor**, or the one the turn's own
     open accepts: as before.
   - **A live connection of another actor:** it traps with
     `CONNECTION_NOT_HELD`, as before. Owner-only sending holds for every
     live connection. (Superseded on 2026-11-14: it is recorded as dropped,
     see below.)
   - **No live connection has the id** (it closed, or none was ever
     accepted): the operation is recorded as dropped and never handed to a
     connection, and the turn goes on. `send-now` answers `closed`.
     History shows the frame as dropped.
   - **A malformed id** (not `c-` and 32 lowercase hex characters): it
     traps, as a guest bug.
3. **Connection ids are unguessable.** A connection's id is `c-` and its
   open input's root id: 16 bytes (128 bits) that the node draws from the
   operating system's random source when it admits the open. Nothing about
   an id is sequential or derived from other data. So an actor cannot tell
   another actor's live connection from a dead id by guessing ids and
   watching for the trap. It learns a live id only when one is handed to
   it, and handles are data (decision 3). This must stay so: a change to
   how ids are drawn needs a new decision.
4. **Closed rows leave the table that turns read, at a logged point.**
   Applying a connection's close input moves its row, in the same
   transaction, to a history table that turns never read. Only the API and
   `kronik history` read it, and it is not part of the state hash. History
   rows are deleted only by retention's index compaction, at the retention
   base: the pass that deletes `turn_index` rows below the first retained
   LSN also deletes the history rows that closed below it. Never by wall
   time. Every change to what a turn can read is applied from a record of
   the log, so I1 and I4 hold.

### Consequences

- **Bounded tables.** The live table is bounded by the connection caps.
  After a restart, every live connection gets its host close, which moves
  its row. History is bounded by the retention window. A frame record that
  could ask for a connection's fate is never older than its close, so no
  history row is deleted while a retained record still needs it.
- **What is lost.** Before, an id the actor never accepted trapped; now it
  is a dropped frame unless another actor's live connection has it. A typo
  in an id therefore shows up as dropped frames in history and in
  `kronik_connection_frames_dropped_total`, not as a failed turn.
- **The API.** `GET /v1/connections` lists closed connections until the
  retention base passes their close. After that they answer
  `CONNECTION_NOT_FOUND`, like their turns.
- **Replay.** Isolated replay reads production's live rows at each input.
  Continuous replay evolves its own. Both drop and trap on the same
  conditions as production, and history rows play no part.
- **The format.** `ConnectionOp` gains `repeated string dropped = 5`, the
  ids of the operation's targets that no live connection had. `connections`
  and `seqs` keep only the live targets, so a send's or close's targets are
  the union of the two lists. A `send-now` that finds no live connection is
  recorded with the status `CLOSED`. Like a denied effect, it needs no
  `TurnBegin`: its answer follows from the recorded state.
- **Verification:**
  - runtime tests: an id without a live connection is recorded as dropped
    and the turn commits; another actor's live connection traps; a
    malformed id traps;
  - store tests: the close input moves the row; compaction removes only
    history rows below the first retained LSN and changes neither the live
    table nor the state hash; a rebuild from a snapshot and the log gives
    the same live table;
  - an I1 test: one input sequence gives byte-identical turn records
    whether or not compaction ran in between.

## Amended 2026-11-14: a turn decides from its own actor's rows

### Context

The deterministic simulation's identity replay (C8) found that the trap
for another actor's live connection broke I1. Whether another actor's
connection is live depends on when that actor's close input was applied,
and the log does not order that against a turn of a different actor: in
production a frame turn of `room/r0` read the state before `room/r2`'s
close (LSN 46) was applied and trapped at LSN 47, while identity replay
applied LSN 46 first, found no live row, and dropped instead. The diff
showed a fixed error that production never fixed. About one connections
seed in 500 hit it.

A turn's own actor's rows have no such race: they change only through
that actor's own turns, which run one at a time, so a turn reads them as
its earlier turns left them, in production and in replay.

### Decision

1. **A turn decides only from its own actor's rows.** A `send`,
   `broadcast` target, `close` or `send-now` to the connection the turn's
   open accepts, or to a live connection of the turn's actor, works as
   before. Any other well-formed id, whether it closed, was never accepted
   or is another actor's live connection, is recorded as dropped and never
   handed to a connection; the turn goes on, and `send-now` answers
   `closed`. A malformed id still traps.
2. **The security property is unchanged.** Only the owner's turns ever put
   a frame on a connection or close it: a frame to another actor's
   connection is recorded, with its fate `dropped`, and never delivered.
   The trap only made such a mistake loud.
3. **Connection ids stay unguessable** (decision 3 of the first amendment:
   128 random bits). With no trap, a turn cannot even tell another actor's
   live connection from a dead id, so ids cannot be probed.
4. **`CONNECTION_NOT_HELD` goes.** No path raises it any more, and M24 is
   not released, so the error code leaves the catalog rather than staying
   reserved.

### Consequences

- **Determinism.** The outcome of every connection operation follows from
  the turn's own actor's rows and the log: identity replay of the race above
  gives an empty diff.
- **What is lost.** Passing the wrong actor a connection id no longer fails
  its turn. The mistake shows up as dropped frames in history (`kronik
  history --connection`), in `kronik_connection_frames_dropped_total`, and
  as a warning in the daemon's log that names the actor and the connection
  (not recorded, so replay is not affected).
- **Verification:** a runtime test (another actor's live connection is
  dropped and the turn commits), a scheduler test (a frame turn's send,
  close and `send-now` to another room's live connection: dropped, `closed`,
  nothing reaches that connection's client), an identity replay of such a
  session with an empty diff, and the deterministic simulation's C8 on the
  seeds that found it.
