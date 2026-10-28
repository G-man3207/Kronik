// billing-ts: invoices with VAT, posted to a ledger and charged through a
// payments service.
//
// Every actor `billing/<customer>` keeps one customer's profile (`customer`)
// and invoices (`invoice/<id>`) in its state. Amounts are integers in minor
// units (cents).
//
// - `PUT /billing/{key}` with `{"name", "country": "DE", "vat_id": null}`
//   sets the customer.
// - `GET /billing/{key}` returns the customer and a summary of the invoices.
// - `POST /billing/{key}/invoices/{id}` with `{"currency": "EUR", "lines":
//   [{"description", "quantity", "unit_price"}]}` creates or replaces a
//   draft: `201`, `200`, or `409` once it is paid.
// - `GET /billing/{key}/invoices/{id}` returns an invoice, or `404`.
// - `POST /billing/{key}/invoices/{id}/finalize` applies VAT, posts the total
//   to `ledger/<customer>` with `call` (and a `reverse` message as its
//   compensation), charges it with `POST <payments>/v1/charges`, and returns
//   the paid invoice. A charge that fails fails the turn: the invoice stays
//   a draft, the client gets `500 TURN_FAILED` with the reason, and the
//   ledger gets the compensation, which reverses the posting.
// - The message `configure` with `{"payments": "<base URL>",
//   "api_key_secret": "<secret name>"}` (both optional) sets where charges
//   go (default `foreign://payments.internal`, the fake-payments foreign
//   actor) and the secret sent as `authorization: Bearer <secret>`.
//
// The payments target's host is `payments.internal` both as a foreign actor
// and as `https://payments.internal`, so the default policy rule
// `payments-must-be-exact` applies to a proposal that changes the charges.
// Grants: `foreign:payments.internal` (or `http:payments.internal`) with
// `--delivery idempotency-keyed`, and `secret:<name>` for an API key.

import { actor, type Ctx, type Handler, Rejected, type Request, type Output } from "@kronik/sdk";
import { type Vat, type VatCustomer, type VatRule, vatOf } from "./vat.ts";

const DEFAULT_PAYMENTS = "foreign://payments.internal";
const MAX_LINES = 100;
const MAX_QUANTITY = 10_000;
const MAX_UNIT_PRICE = 100_000_000;
/** An invoice's net at most, so VAT stays exact in a double. */
const MAX_NET = 100_000_000_000;

interface Customer extends VatCustomer {
  name: string;
}

interface Line {
  description: string;
  quantity: number;
  unit_price: number;
}

interface Invoice {
  id: string;
  customer: string;
  currency: string;
  lines: Line[];
  status: "draft" | "paid";
  net: number;
  vat_rate_bp: number | null;
  vat_rule: string | null;
  vat: number | null;
  total: number | null;
  ledger_entry: number | null;
  charge: string | null;
  updated_ms: number;
}

interface Config {
  payments: string;
  api_key_secret: string | null;
}

/** Invalid input: answered with `400` and the message. */
class BadRequest extends Error {}

/** A request that does not fit the invoice's state: answered with `409`. */
class Conflict extends Error {}

function body(req: Request): Record<string, unknown> {
  let value: unknown;
  try {
    value = req.json();
  } catch {
    value = undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new BadRequest("the body must be a JSON object");
  }
  return value as Record<string, unknown>;
}

function wholeNumber(value: unknown, what: string, max: number, min = 0): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw new BadRequest(`${what} must be a whole number from ${min} to ${max}`);
  }
  return value;
}

function customer(req: Request): Customer {
  const b = body(req);
  if (typeof b.name !== "string" || b.name.trim() === "") throw new BadRequest("name must be a non-empty string");
  if (typeof b.country !== "string" || !/^[A-Z]{2}$/.test(b.country)) {
    throw new BadRequest("country must be an ISO 3166-1 alpha-2 code such as DE");
  }
  const vatId = b.vat_id ?? null;
  if (vatId !== null && (typeof vatId !== "string" || !/^[A-Z]{2}[0-9A-Z]{2,13}$/.test(vatId))) {
    throw new BadRequest("vat_id must be null or a VAT number such as DE123456789");
  }
  return { name: b.name.trim(), country: b.country, vat_id: vatId };
}

function lines(value: unknown): Line[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_LINES) {
    throw new BadRequest(`lines must be a list of 1 to ${MAX_LINES} lines`);
  }
  return value.map((line: unknown, i) => {
    if (typeof line !== "object" || line === null) throw new BadRequest(`line ${i + 1} must be an object`);
    const l = line as Record<string, unknown>;
    if (typeof l.description !== "string" || l.description.trim() === "") {
      throw new BadRequest(`line ${i + 1} needs a description`);
    }
    return {
      description: l.description.trim(),
      quantity: wholeNumber(l.quantity, `line ${i + 1}'s quantity`, MAX_QUANTITY, 1),
      unit_price: wholeNumber(l.unit_price, `line ${i + 1}'s unit_price`, MAX_UNIT_PRICE),
    };
  });
}

function config(ctx: Ctx): Config {
  return ctx.state.getJson<Config>("config") ?? { payments: DEFAULT_PAYMENTS, api_key_secret: null };
}

function draft(req: Request, ctx: Ctx, id: string): Output {
  const previous = ctx.state.getJson<Invoice>(`invoice/${id}`);
  if (previous?.status === "paid") throw new Conflict(`invoice ${id} is paid and cannot change`);
  const b = body(req);
  const currency = b.currency ?? "EUR";
  if (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency)) throw new BadRequest("currency must be a code such as EUR");
  const items = lines(b.lines);
  const net = items.reduce((sum, l) => sum + l.quantity * l.unit_price, 0);
  if (net > MAX_NET) throw new BadRequest(`the invoice's net must be at most ${MAX_NET}`);
  const invoice: Invoice = {
    id,
    customer: ctx.self().key,
    currency,
    lines: items,
    status: "draft",
    net,
    vat_rate_bp: null,
    vat_rule: null,
    vat: null,
    total: null,
    ledger_entry: null,
    charge: null,
    updated_ms: ctx.now(),
  };
  ctx.state.setJson(`invoice/${id}`, invoice);
  return ctx.json(previous === undefined ? 201 : 200, invoice);
}

function finalize(ctx: Ctx, id: string, vatRule: VatRule): Output {
  const invoice = ctx.state.getJson<Invoice>(`invoice/${id}`);
  if (invoice === undefined) return ctx.status(404);
  if (invoice.status !== "draft") throw new Conflict(`invoice ${id} is already ${invoice.status}`);
  const who = ctx.state.getJson<Customer>("customer");
  if (who === undefined) throw new Conflict(`set the customer first: PUT /billing/${invoice.customer}`);
  const vat: Vat = vatRule(who);
  invoice.vat_rate_bp = vat.rate_bp;
  invoice.vat_rule = vat.rule;
  invoice.vat = vatOf(invoice.net, vat.rate_bp);
  invoice.total = invoice.net + invoice.vat;

  // The ledger commits its posting now. If this turn fails later, for
  // instance because the charge is declined, it gets `reverse` instead.
  const posted = ctx.call(
    `ledger/${invoice.customer}`,
    { name: "post", body: { invoice: id, amount: invoice.total, currency: invoice.currency } },
    { name: "reverse", body: { invoice: id } },
  );
  invoice.ledger_entry = posted?.json<{ entry: number }>().entry ?? null;

  const cfg = config(ctx);
  const res = ctx.http.fetch({
    method: "POST",
    url: `${cfg.payments}/v1/charges`,
    headers: cfg.api_key_secret === null ? {} : { authorization: ctx.secret(cfg.api_key_secret).header("Bearer {}") },
    body: { customer: invoice.customer, invoice: id, amount: invoice.total, currency: invoice.currency },
  });
  if (!res.ok) {
    let reason = `the payments service answered ${res.status}`;
    try {
      reason += `: ${res.json<{ error?: { code?: string } }>().error?.code ?? "no error code"}`;
    } catch {
      // Not JSON; the status says enough.
    }
    throw new Rejected(`invoice ${id} was not charged: ${reason}`);
  }
  invoice.charge = res.json<{ id: string }>().id;
  invoice.status = "paid";
  invoice.updated_ms = ctx.now();
  ctx.state.setJson(`invoice/${id}`, invoice);
  return ctx.json(200, invoice);
}

function route(req: Request, ctx: Ctx, vatRule: VatRule): Output {
  const id = req.param("id");
  if (id === undefined) {
    if (req.method === "PUT") {
      const c = customer(req);
      ctx.state.setJson("customer", c);
      return ctx.json(200, c);
    }
    const invoices = ctx.state
      .keys("invoice/")
      .map((key) => ctx.state.getJson<Invoice>(key))
      .filter((invoice) => invoice !== undefined)
      .map((invoice) => ({ id: invoice.id, status: invoice.status, total: invoice.total, currency: invoice.currency }));
    return ctx.json(200, { customer: ctx.state.getJson<Customer>("customer") ?? null, invoices });
  }
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) return ctx.status(404);
  // /billing/{key}/invoices/{id}/finalize has one segment more than the
  // invoice itself (whose id may well be "finalize").
  if (req.path.split("/").length === 6) return finalize(ctx, id, vatRule);
  if (req.method === "POST") return draft(req, ctx, id);
  const invoice = ctx.state.getJson<Invoice>(`invoice/${id}`);
  return invoice === undefined ? ctx.status(404) : ctx.json(200, invoice);
}

/** The billing actor type, with `vatRule` choosing each invoice's VAT. */
export function billing(vatRule: VatRule): Handler {
  return actor({
    kind: "billing",
    schemaVersion: 0,
    routes: [
      { method: "PUT", pattern: "/billing/{key}" },
      { method: "GET", pattern: "/billing/{key}" },
      { method: "POST", pattern: "/billing/{key}/invoices/{id}" },
      { method: "GET", pattern: "/billing/{key}/invoices/{id}" },
      { method: "POST", pattern: "/billing/{key}/invoices/{id}/finalize" },
    ],
    capabilities: ["foreign:payments.internal"],

    http(req, ctx) {
      try {
        return route(req, ctx, vatRule);
      } catch (e) {
        if (e instanceof BadRequest) return ctx.json(400, { error: e.message });
        if (e instanceof Conflict) return ctx.json(409, { error: e.message });
        throw e;
      }
    },

    message(msg, ctx) {
      if (msg.name !== "configure") throw new Rejected(`unknown message ${JSON.stringify(msg.name)}: billing takes \`configure\``);
      const update = msg.json<{ payments?: unknown; api_key_secret?: unknown }>();
      const cfg = config(ctx);
      if (update.payments !== undefined) {
        if (typeof update.payments !== "string" || !/^(https?|foreign):\/\/[^/]+$/.test(update.payments)) {
          throw new Rejected("payments must be a base URL such as foreign://payments.internal, without a path");
        }
        cfg.payments = update.payments;
      }
      if (update.api_key_secret !== undefined) {
        if (update.api_key_secret !== null && typeof update.api_key_secret !== "string") {
          throw new Rejected("api_key_secret must be a secret's name or null");
        }
        cfg.api_key_secret = update.api_key_secret;
      }
      ctx.state.setJson("config", cfg);
      return ctx.reply({ name: "config", body: cfg });
    },
  });
}
