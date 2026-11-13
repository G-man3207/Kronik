# 0114. Only the actor that accepted a connection sends on it or closes it

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13

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
   recorded, immutable facts, so it is deterministic.
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
