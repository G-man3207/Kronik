# WebSocket and SSE connections

An actor type can hold long-lived connections to clients: WebSocket, in both
directions, and server-sent events (SSE), from the actor to the client. The
gateway holds the connection; the actor only knows its id. Each thing that
happens on a connection is a turn of the actor that accepted it, recorded
like every other input, so replay, forks and proposals cover connections
too. The design is [M24](../design/m24-connections.md), with
[ADR 0113](../adr/0113-v05-actor-abi.md) to
[ADR 0116](../adr/0116-connections-in-replay-and-diff.md).

`examples/chat-ts` is a complete chat app: rooms over WebSocket, followers
over SSE, a bot that streams its answers, and the reconnect pattern below.

## Routes and the three inputs

A kind declares `WEBSOCKET` and `SSE` routes next to its HTTP routes. A
WebSocket upgrade request, or a GET for an SSE route, opens a connection
with the actor that the route names. Its key is `{key}`, as for HTTP. The
connection then gives its actor three kinds of input, each its own turn:

| Input | When | The actor |
| --- | --- | --- |
| open | A client asks to open a connection. | Accepts, or refuses with an HTTP response. The client gets `101 Switching Protocols` or the event stream only after the open turn is recorded. |
| frame | A WebSocket client sent a text or binary message. SSE has no frames. | Handles it. |
| close | The connection ended: the client left, the actor closed it, or the host did (a restart, a limit, an operator). | Cleans up. Every accepted connection gets exactly one close, also after a crash. |

Only the actor that accepted a connection sends on it or closes it. A frame
to any other id, a connection that closed, one that was never accepted or
one that another actor holds, is dropped and shows in `kronik history`. That
is no error: a connection can close between the turn that learned its id
and the turn that sends to it, and a turn decides only from its own actor's
connections, so it replays the same. Connection ids are 128 random bits, so
they cannot be guessed. To reach clients connected to other actors, send
those actors a message.

## The API

The same API in the four SDKs:

| | TypeScript | Rust | Python | Go |
| --- | --- | --- | --- | --- |
| Routes | `{ method: 'WEBSOCKET', pattern }`, `{ method: 'SSE', pattern }` | `Route::websocket(p)`, `Route::sse(p)` | `Route.websocket(p)`, `Route.sse(p)` | `kronik.WebSocket(p)`, `kronik.SSE(p)` |
| Handlers | `connections: { open, frame, close }` in `actor({...})` | `Actor::connection_open`, `connection_frame`, `connection_close` | `actor(connections=Connections(open=..., frame=..., close=...))` | `Connections: &kronik.Connections{Open, Frame, Close}` |
| Accept | `return ctx.accept({ subprotocol, headers, subject })` | `Ok(OpenReply::accept(Accept::new().with_subject(..)))` | `return ctx.accept(subprotocol=..., headers=..., subject=...)` | `return ctx.Accept(kronik.AcceptOptions{...})` |
| Refuse | return an HTTP output: `ctx.status(403)`, `ctx.json(400, ...)` | `Ok(OpenReply::refuse(Output::status(403)))` | return `ctx.status(403)` | `return ctx.Refuse(ctx.Status(403))` |
| Frames | `Frame.text/json/binary/event(...)`; a string or bytes also works | `Frame::text/json/binary/event` | `Frame.text/json/binary/event`; a str or bytes also works | `kronik.TextFrame/JSONFrame/BinaryFrame/EventFrame` |
| Send after commit | `ctx.connections.send(conn, frame)`, `.broadcast(conns, frame)` | `ctx.connections().send / broadcast` | `ctx.connections.send / broadcast` | `ctx.Connections.Send / Broadcast` |
| Close | `ctx.connections.close(conn, code, reason)` | `ctx.connections().close(..)` | `ctx.connections.close(...)` | `ctx.Connections.Close(...)` |
| Send now | `ctx.connections.sendNow(conn, frame)`: `boolean` | `send_now(..) -> Result<bool, Error>` | `send_now(...)`: `bool` | `SendNow(...) (bool, error)` |
| The open request | `req.connection`, `req.protocol`, `req.subprotocols`, `req.origin()`, `req.lastEventId()`, and the HTTP request's helpers | the same in snake case | the same | the same in Go case |
| A frame | `frame.connection`, `frame.seq`, `frame.kind`, `frame.text()`, `frame.bytes()`, `frame.json()` | the same | the same | the same |
| The close | `closed.connection`, `closed.initiator`, `closed.code`, `closed.reason` | `closed.info.*` | the same | the same |

Without handlers, an actor type refuses opens with 404 and rejects frames,
which become dead letters; a close without a handler does nothing.

In TypeScript:

```ts
import { actor, Frame } from "@kronik/sdk";

export default actor({
  kind: "room",
  schemaVersion: 0,
  routes: [{ method: "WEBSOCKET", pattern: "/room/{key}/ws" }],
  connections: {
    open(req, ctx) {
      if (req.origin() !== undefined && new URL(req.origin()!).host !== req.header("host")) return ctx.status(403);
      ctx.state.set(`member/${req.connection}`, "");
      ctx.connections.send(req.connection, Frame.json({ type: "welcome" }));
      return ctx.accept();
    },
    frame(frame, ctx) {
      const members = ctx.state.keys("member/").map((k) => k.slice("member/".length));
      ctx.connections.broadcast(members, Frame.text(frame.text()));
    },
    close(closed, ctx) {
      ctx.state.delete(`member/${closed.connection}`);
    },
  },
});
```

## Sending: after commit, or now

`send`, `broadcast` and `close` are buffered like `send` to an actor:
nothing leaves if the turn fails, and the frames go out in call order after
the turn is recorded. That is what a final notice needs, such as "your
payment went through".

`sendNow` sends during the turn. It is for intermediate results, such as the
tokens of a streamed model answer, and it is an effect:

- It needs the grant `kronik grant <kind> connection:send-now`. Its delivery
  class is always `unsafe`.
- It returns true when the frame was handed to the connection, and false
  when the connection is closed or its client does not keep up.
- After a crash, a turn that had already sent a frame now is run again, and
  that frame is never sent twice: the call throws `OutcomeUnknown` (Rust:
  `Error::SendNow(SendError::OutcomeUnknown)`, Go: `kronik.IsOutcomeUnknown`).
  The turn may catch it. Uncaught, the turn fails with
  `EFFECT_OUTCOME_UNKNOWN`.
- A stream can reach the client before its turn fails. That is the price
  of streaming: send the final result with `send`.

Within a turn, the frames sent now go out before the buffered ones.

## What a client can rely on

- A committed turn's frames were handed to their connections in order, or
  dropped because the connection was gone. Kronik does not wait for the
  client to receive them. A frame to a closed connection is dropped and
  shows in `kronik history` as dropped.
- A frame from a client is acknowledged only by the turn it causes. If the
  node crashes before that turn is recorded, the frame is lost.
- A restart closes every connection: on a graceful stop the clients get the
  close code 1012 and the reason `kronik: restart`, and an SSE stream gets
  a `retry:` hint. Every connection's close input then has the initiator
  `host` and the reason `restart`.

So a client that must not miss anything numbers what it receives and
fetches the gap after a reconnect. `chat-ts` does this:

1. Every message gets the room's next sequence number.
2. A client remembers the last number it saw.
3. On reconnect, the `welcome` frame carries the room's last number, and
   the client fetches what it missed with
   `GET /chat/{key}/messages?after=<last seen>`.
4. It reconnects with jittered backoff, from 0.5 s doubling to 30 s, so a
   restart does not bring every client back at once.

An SSE client gets this for free: the actor sends each event with an `id`,
and a reconnecting EventSource sends the last one back as `Last-Event-ID`
(`req.lastEventId()`).

## Security

- Browsers send cookies with a WebSocket handshake, from any site. An actor
  that authenticates by cookie must check `req.origin()` in `open`,
  or a hostile page can open connections as its visitors.
- The open request's subject comes from `privacy.subject_from` as for HTTP.
  A browser cannot set headers on a WebSocket, so an actor that knows the
  user after checking a token sets the connection's subject with
  `ctx.accept({ subject })`. The frames and the close are then tagged with
  it.
- `[connections]` in the configuration caps the connections in total, per
  actor and per client address, the incoming frame size and rate, and the
  outgoing queue of a slow client.

## Testing

The testkits play the client
([Writing actors](actors.md#testing) lists the methods per language). A
test opens a connection through the test host's gateway, sends frames,
closes it as the client or as the host, and reads what the actor sent:

```ts
import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

test("members chat", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  const ada = await host.openConnection("/chat/lobby/ws?user=ada");
  assert.ok(ada.accepted);
  await host.framesSent(ada, { clear: true }); // the welcome
  await host.sendFrame(ada, JSON.stringify({ type: "say", text: "hi" }));
  const { frames } = await host.framesSent(ada, { clear: true });
  assert.equal(frames[0].json<{ text: string }>().text, "hi");
  await host.closeConnection(ada, { initiator: "host", cause: "restart" });
  assert.deepEqual((await host.framesSent(ada)).closed, { code: 1012, reason: "restart" });
});
```

Each call returns once the turns it caused have finished, so the frames
they sent are there. `examples/chat-ts/test/connections.test.ts` has more.
