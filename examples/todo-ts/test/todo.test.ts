import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

const DAY_MS = 24 * 60 * 60 * 1000;

test("items are added, changed and removed", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  const milk = await host.http("POST", "/todo/home", { body: { title: " milk " } });
  assert.equal(milk.status, 201);
  assert.deepEqual(milk.json(), { id: 1, title: "milk", done: false, created_ms: await host.advance(0), done_ms: null });
  await host.http("POST", "/todo/home", { body: { title: "bread" } });
  assert.equal((await host.http("POST", "/todo/home", { body: { title: "" } })).status, 400);
  assert.equal((await host.http("POST", "/todo/home", { body: "not json" })).status, 400);

  const renamed = await host.http("PATCH", "/todo/home/1", { body: { title: "oat milk" } });
  assert.equal(renamed.json<{ title: string }>().title, "oat milk");
  assert.equal((await host.http("DELETE", "/todo/home/2")).status, 204);
  assert.equal((await host.http("GET", "/todo/home/2")).status, 404);
  const list = await host.http("GET", "/todo/home");
  assert.deepEqual(
    list.json<{ items: Array<{ id: number }> }>().items.map((item) => item.id),
    [1],
  );
  // Lists are separate actors.
  assert.deepEqual((await host.http("GET", "/todo/work")).json(), { items: [] });
});

test("done items are removed a day after they were done", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  await host.http("POST", "/todo/home", { body: { title: "milk" } });
  await host.http("POST", "/todo/home", { body: { title: "bread" } });
  const done = await host.http("PATCH", "/todo/home/1", { body: { done: true } });
  assert.equal(done.json<{ done: boolean }>().done, true);

  await host.advance(DAY_MS - 1);
  assert.equal((await host.http("GET", "/todo/home/1")).status, 200, "kept for a day");
  await host.advance(1);
  assert.equal((await host.http("GET", "/todo/home/1")).status, 404, "swept");
  assert.equal((await host.http("GET", "/todo/home/2")).status, 200, "not done, kept");

  // An item done and then not done again stays.
  await host.http("PATCH", "/todo/home/2", { body: { done: true } });
  await host.http("PATCH", "/todo/home/2", { body: { done: false } });
  await host.advance(2 * DAY_MS);
  assert.equal((await host.http("GET", "/todo/home/2")).status, 200);
});
