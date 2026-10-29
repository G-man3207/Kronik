// uptime-ts in a test host: standard fetch through the effect layer, with
// the targets stubbed.

import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

const UP = "https://up.example.com/health";
const DOWN = "https://down.example.com/health";
const TOKEN = "tok-uptime-5f2a";

interface Check {
  at: number;
  results: Array<{ url: string; status?: number; error?: string }>;
}

async function uptimeHost(): Promise<TestHost> {
  const host = await TestHost.start();
  await host.grant("uptime", "http:up.example.com");
  await host.grant("uptime", "http:down.example.com");
  await host.stub({ url: UP, status: 200, body: "ok" });
  await host.stub({ url: DOWN, status: 503, body: "maintenance" });
  return host;
}

test("every target is fetched at once and the check is stored", async (t) => {
  const host = await uptimeHost();
  t.after(() => host.close());
  await host.send("uptime/shop", "configure", JSON.stringify({ targets: [UP, DOWN] }));

  const res = await host.http("POST", "/uptime/shop/check");
  assert.equal(res.status, 200);
  const check = res.json<Check>();
  assert.deepEqual(check.results, [
    { url: UP, status: 200 },
    { url: DOWN, status: 503 },
  ]);
  assert.deepEqual((await host.http("GET", "/uptime/shop")).json<Check>(), check);
  const sent = (await host.requests()).map((r) => `${r.method} ${r.url}`).sort();
  assert.deepEqual(sent, [`GET ${DOWN}`, `GET ${UP}`]);
});

test("the token is inserted by the host and never reaches the actor", async (t) => {
  const host = await uptimeHost();
  t.after(() => host.close());
  await host.secret("uptime-token", TOKEN);
  await host.grant("uptime", "secret:uptime-token");
  await host.send("uptime/shop", "configure", JSON.stringify({ targets: [UP], token_secret: "uptime-token" }));

  assert.equal((await host.http("POST", "/uptime/shop/check")).status, 200);
  const [req] = await host.requests();
  assert.equal(req.headers.find(([n]) => n === "authorization")?.[1], `Bearer ${TOKEN}`);
  for (const value of (await host.state("uptime/shop")).values()) {
    assert.ok(!new TextDecoder().decode(value).includes(TOKEN));
  }
});

test("a target without a grant fails as a TypeError, the others still answer", async (t) => {
  const host = await uptimeHost();
  t.after(() => host.close());
  const other = "https://other.example.com/";
  await host.send("uptime/shop", "configure", JSON.stringify({ targets: [UP, other] }));

  const check = (await host.http("POST", "/uptime/shop/check")).json<Check>();
  assert.deepEqual(check.results[0], { url: UP, status: 200 });
  assert.equal(check.results[1].url, other);
  assert.match(check.results[1].error ?? "", /^TypeError/);
  assert.equal((await host.requests()).length, 1);
});

test("configure rejects what is not a list of http(s) URLs", async (t) => {
  const host = await uptimeHost();
  t.after(() => host.close());
  const configured = (await host.send("uptime/shop", "configure", JSON.stringify({ targets: ["ftp://x"] }))) as {
    outcome: { kind: string; message: string };
  };
  assert.equal(configured.outcome.kind, "rejected");
  assert.match(configured.outcome.message, /http/);
});
