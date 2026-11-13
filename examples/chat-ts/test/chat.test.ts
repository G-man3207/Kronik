import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

interface ChatMessage {
  type: string;
  seq: number;
  user: string;
  text: string;
  ts: number;
  id: string;
}

test("messages posted over HTTP are numbered and read back after a sequence number", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  const first = await host.http("POST", "/chat/lobby/messages", { body: { user: "ada", text: "hello", id: "a1" } });
  assert.equal(first.status, 201);
  const m = first.json<ChatMessage>();
  assert.deepEqual([m.type, m.seq, m.user, m.text, m.id], ["message", 1, "ada", "hello", "a1"]);
  assert.equal((await host.http("POST", "/chat/lobby/messages", { body: { user: "bob", text: "hi ada" } })).status, 201);

  const all = (await host.http("GET", "/chat/lobby/messages")).json<{ messages: ChatMessage[]; last: number }>();
  assert.equal(all.last, 2);
  assert.deepEqual(all.messages.map((x) => [x.seq, x.user, x.text, x.id]), [
    [1, "ada", "hello", "a1"],
    [2, "bob", "hi ada", ""],
  ]);
  const after = (await host.http("GET", "/chat/lobby/messages?after=1&limit=10")).json<{ messages: ChatMessage[]; last: number }>();
  assert.deepEqual(after.messages.map((x) => x.seq), [2]);
  // Rooms are separate actors.
  assert.deepEqual((await host.http("GET", "/chat/other/messages")).json(), { messages: [], last: 0 });
});

test("bad posts and pages are refused", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  for (const body of ["not json", { text: "x" }, { user: "Ada!", text: "x" }, { user: "ada", text: "  " }, { user: "ada", text: "x".repeat(2001) }]) {
    assert.equal((await host.http("POST", "/chat/lobby/messages", { body })).status, 400, JSON.stringify(body).slice(0, 40));
  }
  for (const query of ["after=x", "after=-1", "limit=0", "limit=1001", "limit=abc"]) {
    assert.equal((await host.http("GET", `/chat/lobby/messages?${query}`)).status, 400, query);
  }
});

test("an empty room has no members, and its page is a WebSocket client", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  assert.deepEqual((await host.http("GET", "/chat/lobby/members")).json(), { members: [], followers: 0 });
  const page = await host.http("GET", "/chat/lobby");
  assert.equal(page.status, 200);
  assert.equal(page.header("content-type"), "text/html; charset=utf-8");
  assert.match(page.text(), /new WebSocket\(/);
  assert.doesNotMatch(page.text(), /innerHTML/);
});
