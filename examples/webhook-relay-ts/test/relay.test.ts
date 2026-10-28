import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

const TARGET = "https://webhooks.example.com/relay";
const SIGNING_KEY = "test-signing-key";

interface Delivery {
  id: string;
  status: string;
  attempts: number;
  target_status: number | null;
  error: string | null;
  next_retry_ms: number | null;
}

/** A host with the relay's grants and secrets, as an operator sets them up. */
async function relayHost(): Promise<TestHost> {
  const host = await TestHost.start();
  await host.secret("relay-signing-key", SIGNING_KEY);
  await host.secret("relay-auth", "tok-123");
  await host.grant("webhook-relay", "secret:relay-signing-key");
  await host.grant("webhook-relay", "secret:relay-auth");
  await host.grant("webhook-relay", "http:webhooks.example.com", "idempotency-keyed");
  return host;
}

test("a webhook is forwarded signed, with the secret inserted by the host", async (t) => {
  const host = await relayHost();
  t.after(() => host.close());
  await host.send("webhook-relay/acme", "configure", JSON.stringify({ auth_secret: "relay-auth" }));
  await host.stub({ url: TARGET, status: 202 });

  const res = await host.http("POST", "/hooks/acme", { body: { event: "paid", amount: 42 } });
  assert.equal(res.status, 200);
  const delivery = res.json<Delivery>();
  assert.equal(delivery.status, "delivered");
  assert.equal(delivery.target_status, 202);

  const [sent] = await host.requests();
  const header = (name: string) => sent.headers.find(([n]) => n === name)?.[1];
  assert.equal(sent.url, TARGET);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(sent.body)), {
    webhook: delivery.id,
    source: "acme",
    payload: { event: "paid", amount: 42 },
  });
  assert.equal(header("x-webhook-id"), delivery.id);
  assert.equal(header("x-signature"), `sha256=${createHmac("sha256", SIGNING_KEY).update(sent.body).digest("hex")}`);
  assert.equal(header("authorization"), "Bearer tok-123");
  assert.equal(header("idempotency-key")?.length, 64);

  // The record stays readable.
  assert.equal((await host.http("GET", `/hooks/acme/${delivery.id}`)).json<Delivery>().status, "delivered");
  assert.equal((await host.http("GET", "/hooks/acme/nope")).status, 404);
});

test("a failure that may go away is retried by a timer", async (t) => {
  const host = await relayHost();
  t.after(() => host.close());
  await host.stub({ url: TARGET, status: 200 });
  await host.stub({ url: TARGET, status: 503, times: 1 });

  const first = await host.http("POST", "/hooks/acme", { body: "plain text" });
  assert.equal(first.status, 502);
  const delivery = first.json<Delivery>();
  assert.deepEqual([delivery.status, delivery.attempts, delivery.target_status], ["retrying", 1, 503]);
  const now = await host.advance(0);
  assert.equal(delivery.next_retry_ms, now + 1000);

  await host.advance(999);
  assert.equal((await host.requests()).length, 1, "not before the retry is due");
  await host.advance(1);
  const retried = (await host.http("GET", `/hooks/acme/${delivery.id}`)).json<Delivery>();
  assert.deepEqual([retried.status, retried.attempts], ["delivered", 2]);
  const sent = await host.requests();
  assert.equal(sent.length, 2);
  assert.deepEqual(sent[0].body, sent[1].body, "the same request both times");
});

test("a target outside the grants fails at once", async (t) => {
  const host = await relayHost();
  t.after(() => host.close());
  await host.send("webhook-relay/acme", "configure", JSON.stringify({ target: "https://elsewhere.example.com/x" }));
  const res = await host.http("POST", "/hooks/acme", { body: {} });
  assert.equal(res.status, 502);
  const delivery = res.json<Delivery>();
  assert.equal(delivery.status, "failed");
  assert.match(delivery.error ?? "", /CAPABILITY_NOT_GRANTED/);
  assert.equal((await host.requests()).length, 0, "nothing was sent");
});
