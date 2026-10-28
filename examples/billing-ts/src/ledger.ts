// ledger: what each customer owes, for billing-ts. Built from this project
// with `kronik build --entry src/ledger.ts` (dist/billing-ledger.wasm).
//
// Every actor `ledger/<customer>` keeps its entries and balances in one
// state value, `ledger`.
//
// - The message `post` with `{"invoice", "amount", "currency"}` books an
//   invoice and replies `{"entry", "balance"}`. Booking an invoice that is
//   already booked replies with the earlier entry.
// - The message `reverse` with `{"invoice"}` books the opposite of an
//   invoice's posting; billing sends it as the compensation of its `call`,
//   so a posting whose charge failed is undone. Reversing what is not
//   booked changes nothing.
// - `GET /ledger/{key}` returns `{"balance": {"EUR": n}, "entries": [...]}`.

import { actor, Rejected } from "@kronik/sdk";

interface Entry {
  entry: number;
  kind: "post" | "reverse";
  invoice: string;
  amount: number;
  currency: string;
  at_ms: number;
}

interface Ledger {
  entries: Entry[];
  balance: Record<string, number>;
}

export default actor({
  kind: "ledger",
  schemaVersion: 0,
  routes: [{ method: "GET", pattern: "/ledger/{key}" }],

  http(_req, ctx) {
    return ctx.json(200, ctx.state.getJson<Ledger>("ledger") ?? { entries: [], balance: {} });
  },

  message(msg, ctx) {
    const ledger = ctx.state.getJson<Ledger>("ledger") ?? { entries: [], balance: {} };
    const body = msg.json<{ invoice?: unknown; amount?: unknown; currency?: unknown }>();
    if (typeof body.invoice !== "string") throw new Rejected(`${msg.name} needs an invoice id`);
    // The invoice's latest entry: a posting in force, or its reversal.
    let posted: Entry | undefined;
    for (const e of ledger.entries) if (e.invoice === body.invoice) posted = e;
    const book = (kind: Entry["kind"], amount: number, currency: string): Entry => {
      const entry = { entry: ledger.entries.length + 1, kind, invoice: String(body.invoice), amount, currency, at_ms: ctx.now() };
      ledger.entries.push(entry);
      ledger.balance[currency] = (ledger.balance[currency] ?? 0) + amount;
      ctx.state.setJson("ledger", ledger);
      return entry;
    };
    switch (msg.name) {
      case "post": {
        if (posted?.kind === "post") return ctx.reply({ name: "posted", body: { entry: posted.entry, balance: ledger.balance } });
        if (typeof body.amount !== "number" || !Number.isInteger(body.amount) || typeof body.currency !== "string") {
          throw new Rejected("post needs a whole amount and a currency");
        }
        const entry = book("post", body.amount, body.currency);
        return ctx.reply({ name: "posted", body: { entry: entry.entry, balance: ledger.balance } });
      }
      case "reverse":
        if (posted?.kind === "post") book("reverse", -posted.amount, posted.currency);
        return ctx.none();
      default:
        throw new Rejected(`unknown message ${JSON.stringify(msg.name)}: ledger takes post and reverse`);
    }
  },
});
