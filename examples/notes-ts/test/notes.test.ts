import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

interface Note {
  id: number;
  title: string;
  body: string;
  created: string;
  token: string;
}

test("notes are created, listed a page at a time, and deleted", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  const created = await host.http("POST", "/notes/alice", { body: { title: " first ", body: "hello" } });
  assert.equal(created.status, 201);
  const first = created.json<Note>();
  assert.deepEqual([first.id, first.title, first.body], [1, "first", "hello"]);
  assert.match(first.token, /^[0-9a-f]{16}$/);
  for (const title of ["second", "third"]) {
    assert.equal((await host.http("POST", "/notes/alice", { body: { title } })).status, 201);
  }

  const page = (await host.http("GET", "/notes/alice?limit=2")).json<{ notes: Note[]; next: number | null }>();
  assert.deepEqual(page.notes.map((n) => n.title), ["first", "second"]);
  assert.equal(page.next, 2);
  const last = (await host.http("GET", `/notes/alice?after=${page.next}&limit=2`)).json<{ notes: Note[]; next: number | null }>();
  assert.deepEqual(last.notes.map((n) => n.title), ["third"]);
  assert.equal(last.next, null);

  assert.equal((await host.http("DELETE", "/notes/alice/2")).status, 204);
  assert.equal((await host.http("GET", "/notes/alice/2")).status, 404);
  assert.equal((await host.http("DELETE", "/notes/alice/2")).status, 404);
  assert.deepEqual((await host.http("GET", "/notes/alice/3")).json<Note>().title, "third");
});

test("invalid notes and pages are refused", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  assert.equal((await host.http("POST", "/notes/bob", { body: "not json" })).status, 400);
  assert.equal((await host.http("POST", "/notes/bob", { body: { title: "" } })).status, 400);
  assert.equal((await host.http("POST", "/notes/bob", { body: { title: "x", body: 5 } })).status, 400);
  assert.equal((await host.http("GET", "/notes/bob?limit=0")).status, 400);
  assert.equal((await host.http("GET", "/notes/bob?after=x")).status, 400);
  assert.equal((await host.http("GET", "/notes/bob/abc")).status, 404);
  // Notes belong to their actor's user: bob has none of alice's.
  assert.deepEqual((await host.http("GET", "/notes/bob")).json(), { notes: [], next: null });
});
