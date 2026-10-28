import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

test("each counter counts its increments", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  for (const n of [1, 2, 3]) {
    assert.deepEqual((await host.http("POST", "/counter/alice/increment")).json(), { n });
  }
  assert.deepEqual((await host.http("GET", "/counter/alice")).json(), { n: 3 });
  assert.deepEqual((await host.http("GET", "/counter/bob")).json(), { n: 0 });

  // A message increments too and replies with the count.
  const sent = (await host.send("counter/alice", "increment")) as { reply: { text: string } };
  assert.deepEqual(JSON.parse(sent.reply.text), { n: 4 });
  assert.equal(await host.stateJson("counter/alice", "n"), 4);
});
