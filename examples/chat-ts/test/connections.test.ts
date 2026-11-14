import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost, type TestConnection } from "@kronik/sdk/testkit";

interface Frame {
  type: string;
  [field: string]: unknown;
}

/** The frames the actor sent on `conn` since the last call, as JSON. */
async function received(host: TestHost, conn: TestConnection): Promise<Frame[]> {
  const { frames } = await host.framesSent(conn, { clear: true });
  return frames.map((f) => f.json<Frame>());
}

async function join(host: TestHost, user: string, room = "lobby"): Promise<TestConnection> {
  const conn = await host.openConnection(`/chat/${room}/ws?user=${user}`);
  assert.equal(conn.response.status, 101, `${user}: ${conn.response.text()}`);
  assert.ok(conn.accepted);
  return conn;
}

test("members join, chat and leave over WebSocket", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  const ada = await join(host, "ada");
  assert.deepEqual(await received(host, ada), [{ type: "welcome", connection: ada.connection, members: [], last: 0 }]);

  const bob = await join(host, "bob");
  assert.deepEqual(await received(host, bob), [{ type: "welcome", connection: bob.connection, members: ["ada"], last: 0 }]);
  assert.deepEqual(await received(host, ada), [{ type: "joined", user: "bob" }]);

  await host.sendFrame(ada, JSON.stringify({ type: "say", text: "hi bob", id: "a1" }));
  for (const member of [ada, bob]) {
    const [m, ...rest] = await received(host, member);
    assert.deepEqual(rest, []);
    assert.deepEqual({ ...m, ts: 0 }, { type: "message", seq: 1, user: "ada", text: "hi bob", id: "a1", ts: 0 });
  }
  const page = (await host.http("GET", "/chat/lobby/messages")).json<{ messages: Frame[]; last: number }>();
  assert.equal(page.last, 1);
  assert.deepEqual(
    page.messages.map((m) => [m.seq, m.user, m.text]),
    [[1, "ada", "hi bob"]],
  );

  await host.closeConnection(bob);
  assert.deepEqual(await received(host, ada), [{ type: "left", user: "bob" }]);
  assert.deepEqual((await host.http("GET", "/chat/lobby/members")).json(), { members: ["ada"], followers: 0 });
});

test("opens are refused for a bad user or another site", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  for (const query of ["", "?user=", "?user=Ada!", `?user=${"a".repeat(33)}`]) {
    const conn = await host.openConnection(`/chat/lobby/ws${query}`);
    assert.equal(conn.accepted, false, query);
    assert.equal(conn.response.status, 400, query);
  }
  const hijack = await host.openConnection("/chat/lobby/ws?user=ada", { headers: { host: "chat.example", origin: "https://evil.example" } });
  assert.equal(hijack.response.status, 403);
  assert.deepEqual(hijack.response.json(), { error: "cross-origin WebSocket refused" });
  const same = await host.openConnection("/chat/lobby/ws?user=ada", { headers: { host: "chat.example", origin: "https://chat.example" } });
  assert.ok(same.accepted);
  assert.deepEqual((await host.http("GET", "/chat/lobby/members")).json(), { members: ["ada"], followers: 0 });
});

test("frames that are no chat get an error frame and change nothing", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  const ada = await join(host, "ada");
  await received(host, ada);
  await host.sendFrame(ada, "not json");
  await host.sendFrame(ada, JSON.stringify({ type: "say", text: "  ", id: "a2" }));
  await host.sendFrame(ada, JSON.stringify({ type: "dance", id: "a3" }));
  assert.deepEqual(await received(host, ada), [
    { type: "error", error: "frames must be JSON" },
    { type: "error", error: "text must be a non-empty string", id: "a2" },
    { type: "error", error: "unknown frame type", id: "a3" },
  ]);
  assert.equal((await host.http("GET", "/chat/lobby/messages")).json<{ last: number }>().last, 0);
});

test("a restart closes every member, and the room forgets them", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  const ada = await join(host, "ada");
  const bob = await join(host, "bob");
  await host.closeConnection(ada, { initiator: "host", cause: "restart" });
  await host.closeConnection(bob, { initiator: "host", cause: "restart" });
  for (const member of [ada, bob]) {
    assert.deepEqual((await host.framesSent(member)).closed, { code: 1012, reason: "restart" });
  }
  assert.deepEqual((await host.http("GET", "/chat/lobby/members")).json(), { members: [], followers: 0 });
  // A client that reconnects catches up from the room's sequence.
  const again = await join(host, "ada");
  assert.deepEqual(await received(host, again), [{ type: "welcome", connection: again.connection, members: [], last: 0 }]);
});

test("followers read over SSE, resuming after a sequence number", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  for (const text of ["one", "two", "three"]) {
    assert.equal((await host.http("POST", "/chat/lobby/messages", { body: { user: "dee", text } })).status, 201);
  }
  const follower = await host.openConnection("/chat/lobby/events?after=1", { protocol: "sse" });
  assert.equal(follower.response.status, 200, follower.response.text());
  let { frames } = await host.framesSent(follower, { clear: true });
  assert.deepEqual(
    frames.map((f) => [f.kind, f.event, f.id, f.json<Frame>().text]),
    [
      ["event", "message", "2", "two"],
      ["event", "message", "3", "three"],
    ],
  );
  const resumed = await host.openConnection("/chat/lobby/events", { protocol: "sse", headers: { "last-event-id": "2" } });
  assert.deepEqual(
    (await host.framesSent(resumed, { clear: true })).frames.map((f) => f.id),
    ["3"],
  );

  const ada = await join(host, "ada");
  await host.sendFrame(ada, JSON.stringify({ type: "say", text: "four" }));
  ({ frames } = await host.framesSent(follower, { clear: true }));
  assert.deepEqual(
    frames.map((f) => [f.id, f.json<Frame>().text]),
    [["4", "four"]],
  );
  assert.deepEqual((await host.http("GET", "/chat/lobby/members")).json(), { members: ["ada"], followers: 2 });
});

test("step2 changes only the message format", async (t) => {
  const host = await TestHost.start({ entries: ["src/step2.ts"] });
  t.after(() => host.close());
  const ada = await join(host, "ada");
  await received(host, ada);
  await host.sendFrame(ada, JSON.stringify({ type: "say", text: "hi", id: "a1" }));
  const [m] = await received(host, ada);
  assert.deepEqual({ ...m, ts: 0 }, { type: "message", seq: 1, user: "ada", body: "hi", id: "a1", ts: 0 });
});
