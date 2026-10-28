// billing-ts against `https://payments.internal` stubbed in the test host:
// the same API as the fake-payments foreign actor, without gVisor.

import assert from "node:assert/strict";
import { test, type TestContext } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

const CHARGES = "https://payments.internal/v1/charges";
const LINES = [{ description: "Consulting", quantity: 4, unit_price: 2500 }];

interface Invoice {
  status: string;
  net: number;
  vat_rule: string | null;
  vat_rate_bp: number | null;
  vat: number | null;
  total: number | null;
  charge: string | null;
  ledger_entry: number | null;
}

interface Ledger {
  balance: Record<string, number>;
  entries: Array<{ kind: string; amount: number }>;
}

/** A host with billing (default: the deployed build) and the ledger, charging through stubs. */
async function billingHost(t: TestContext, billing = "src/actor.ts"): Promise<TestHost> {
  const host = await TestHost.start({ entries: [billing, "src/ledger.ts"] });
  t.after(() => host.close());
  await host.grant("billing", "http:payments.internal", "idempotency-keyed");
  await host.stub({ url: CHARGES, method: "POST", status: 201, body: { id: "ch_1", status: "succeeded" } });
  return host;
}

/** Sets up `billing/<key>` with a profile, charging through https://payments.internal. */
async function customer(host: TestHost, key: string, country: string, vat_id: string | null = null): Promise<void> {
  await host.send(`billing/${key}`, "configure", JSON.stringify({ payments: "https://payments.internal" }));
  const res = await host.http("PUT", `/billing/${key}`, { body: { name: key, country, vat_id } });
  assert.equal(res.status, 200);
}

/** Drafts and finalizes an invoice of 100.00 net; returns the finalize response. */
async function invoice(host: TestHost, key: string, id: string) {
  const draft = await host.http("POST", `/billing/${key}/invoices/${id}`, { body: { currency: "EUR", lines: LINES } });
  assert.equal(draft.status, 201);
  assert.equal(draft.json<Invoice>().net, 10000);
  return host.http("POST", `/billing/${key}/invoices/${id}/finalize`);
}

test("the domestic rate on every invoice; the total is posted, then charged", async (t) => {
  const host = await billingHost(t);
  await customer(host, "acme", "DE");
  const res = await invoice(host, "acme", "inv-1");
  assert.equal(res.status, 200);
  const paid = res.json<Invoice>();
  assert.deepEqual(
    [paid.status, paid.vat_rule, paid.vat_rate_bp, paid.vat, paid.total, paid.charge, paid.ledger_entry],
    ["paid", "domestic SE", 2500, 2500, 12500, "ch_1", 1],
  );

  const [charge] = await host.requests();
  assert.equal(charge.url, CHARGES);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(charge.body)), {
    customer: "acme",
    invoice: "inv-1",
    amount: 12500,
    currency: "EUR",
  });
  assert.equal(charge.headers.find(([n]) => n === "idempotency-key")?.[1].length, 64);
  const ledger = (await host.http("GET", "/ledger/acme")).json<Ledger>();
  assert.deepEqual(ledger.balance, { EUR: 12500 });

  // A paid invoice stays as it is.
  assert.equal((await host.http("POST", "/billing/acme/invoices/inv-1/finalize")).status, 409);
  assert.equal((await host.http("POST", "/billing/acme/invoices/inv-1", { body: { lines: LINES } })).status, 409);
  assert.deepEqual((await host.http("GET", "/billing/acme")).json<{ invoices: unknown[] }>().invoices, [
    { id: "inv-1", status: "paid", total: 12500, currency: "EUR" },
  ]);
});

test("a declined charge fails the turn, and the compensation reverses the posting", async (t) => {
  const host = await billingHost(t);
  await host.stub({ url: CHARGES, status: 402, body: { error: { code: "card_declined" } } });
  await customer(host, "declined-co", "SE");
  const res = await invoice(host, "declined-co", "inv-9");
  assert.equal(res.status, 500);
  assert.match(res.text(), /TURN_FAILED.*not charged.*402: card_declined/);

  assert.equal((await host.http("GET", "/billing/declined-co/invoices/inv-9")).json<Invoice>().status, "draft");
  const ledger = (await host.http("GET", "/ledger/declined-co")).json<Ledger>();
  assert.deepEqual(
    ledger.entries.map((e) => [e.kind, e.amount]),
    [
      ["post", 12500],
      ["reverse", -12500],
    ],
  );
  assert.deepEqual(ledger.balance, { EUR: 0 });
});

test("Apply EU VAT: the customer's rate in the EU, reverse charge for businesses, none outside", async (t) => {
  const host = await billingHost(t, "src/eu-vat.ts");
  const cases: Array<[string, string, string | null, string, number]> = [
    ["se", "SE", null, "domestic SE", 12500],
    ["de", "DE", null, "OSS DE", 11900],
    ["fi", "FI", null, "OSS FI", 12550],
    ["de-gmbh", "DE", "DE123456789", "reverse charge", 10000],
    ["us", "US", null, "export", 10000],
  ];
  for (const [key, country, vatId, rule, total] of cases) {
    await customer(host, key, country, vatId);
    const paid = (await invoice(host, key, "inv-1")).json<Invoice>();
    assert.deepEqual([paid.vat_rule, paid.total], [rule, total], key);
  }
  const amounts = (await host.requests()).map((r) => JSON.parse(new TextDecoder().decode(r.body)).amount);
  assert.deepEqual(amounts, [12500, 11900, 12550, 10000, 10000]);
});

test("invalid input is refused", async (t) => {
  const host = await billingHost(t);
  assert.equal((await host.http("PUT", "/billing/x", { body: { name: "x", country: "Germany" } })).status, 400);
  assert.equal((await host.http("PUT", "/billing/x", { body: { name: "x", country: "DE", vat_id: "123" } })).status, 400);
  const draft = (body: unknown) => host.http("POST", "/billing/x/invoices/a", { body });
  assert.equal((await draft({ lines: [] })).status, 400);
  assert.equal((await draft({ lines: [{ description: "x", quantity: 0, unit_price: 1 }] })).status, 400);
  assert.equal((await draft({ lines: [{ description: "x", quantity: 1, unit_price: 1.5 }] })).status, 400);
  assert.equal((await draft({ currency: "euro", lines: LINES })).status, 400);
  assert.equal((await draft({ lines: LINES })).status, 201);
  // Finalizing needs the customer's country.
  assert.match((await host.http("POST", "/billing/x/invoices/a/finalize")).text(), /set the customer first/);
  assert.equal((await host.http("GET", "/billing/x/invoices/nope")).status, 404);
  const configured = (await host.send("billing/x", "configure", JSON.stringify({ payments: "ftp://x" }))) as {
    outcome: { kind: string };
  };
  assert.equal(configured.outcome.kind, "rejected");
});
