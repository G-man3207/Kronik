// webhook-relay-ts: relays webhooks to a target, signed, with retries. The
// TypeScript twin of webhook-relay-rs, with the same routes, messages,
// records and forwarded requests.
//
// An actor `webhook-relay/<key>` accepts webhooks for one source and
// forwards each one to its target with `ctx.http.fetch`, signed with
// `ctx.crypto.hmacSha256`. It records every delivery in its state and
// retries failures that may go away with a timer.
//
// - `POST /hooks/{key}` accepts a webhook (any body of at most 512 KiB) and
//   forwards it at once. The answer is the delivery record: `200` when the
//   target accepted it, else `502`.
// - `GET /hooks/{key}/{id}` returns the delivery record of one webhook.
// - The message `configure` with `{"target": "...", "auth_secret": "..."}`
//   (both optional) sets the target URL and the secret for an
//   `authorization: Bearer <secret>` header. The default target is
//   `https://webhooks.example.com/relay`.
//
// The forwarded request is `POST <target>` with
//
// - `content-type: application/json`;
// - `x-webhook-id: <id>`, the same in every attempt, so the target can drop
//   duplicates; `<id>` is the causal id of the turn that accepted it;
// - `x-signature: sha256=<hex>`, the HMAC-SHA256 of the body with the secret
//   `relay-signing-key`, computed by the host;
// - `authorization: Bearer <secret>` if `auth_secret` is set, inserted by the
//   host, so the value never reaches the actor;
// - the body `{"webhook": "<id>", "source": "<key>", "payload": <the webhook
//   body as JSON, or as a string if it is not JSON>}`.
//
// The host adds an `Idempotency-Key` and records the request and its
// response. Outcomes: a 2xx answer is `delivered`. A network error, a
// timeout, an unknown outcome (after a crash, for a target granted as
// `unsafe`), a 5xx or a 429 is `retrying`: a timer tries again after 1, 2, 4
// and 8 seconds, and after 5 attempts the webhook is `failed`. Anything else,
// such as a 4xx, a missing grant or a missing secret, is `failed` at once.
// The actor answers with the record either way, so its turn commits and the
// record and the retry timer are kept.
//
// The operator grants what the manifest asks for, plus `http:<host>` for a
// configured target and `secret:<name>` for an `auth_secret`:
//
//     kronik secret set relay-signing-key
//     kronik grant webhook-relay http:webhooks.example.com --delivery idempotency-keyed --reason '...'
//     kronik grant webhook-relay secret:relay-signing-key --reason '...'

import { actor, type Ctx, KronikError, type Output, Rejected, type Request } from "@kronik/sdk";

const DEFAULT_TARGET = "https://webhooks.example.com/relay";
const SIGNING_KEY = "relay-signing-key";
const MAX_PAYLOAD_BYTES = 512 * 1024;
const MAX_ATTEMPTS = 5;
const FIRST_RETRY_MS = 1000;
/** Fetch errors that may go away on a later attempt. */
const RETRYABLE = ["fetch.network", "fetch.timeout", "fetch.outcome-unknown"];

interface Config {
  target: string;
  auth_secret: string | null;
}

/** What happened to one webhook. Kept in state under `hook/<id>`. */
interface Delivery {
  id: string;
  status: "delivered" | "retrying" | "failed";
  attempts: number;
  target: string;
  target_status: number | null;
  error: string | null;
  received_ms: number;
  updated_ms: number;
  next_retry_ms: number | null;
}

type Attempt =
  | { outcome: "delivered"; code: number }
  | { outcome: "retry" | "fail"; error: string; code: number | null };

function config(ctx: Ctx): Config {
  return ctx.state.getJson<Config>("config") ?? { target: DEFAULT_TARGET, auth_secret: null };
}

/** Accepts a webhook and makes the first delivery attempt. */
function accept(req: Request, ctx: Ctx): Output {
  if (req.body.length > MAX_PAYLOAD_BYTES) {
    return ctx.json(413, { error: `the webhook body is over ${MAX_PAYLOAD_BYTES} bytes` });
  }
  let payload: unknown;
  try {
    payload = req.json();
  } catch {
    try {
      payload = req.text();
    } catch {
      return ctx.json(400, { error: "the webhook body is neither JSON nor UTF-8 text" });
    }
  }
  const id = ctx.causalId();
  const body = new TextEncoder().encode(JSON.stringify({ webhook: id, source: ctx.self().key, payload }));
  const now = ctx.now();
  const delivery: Delivery = {
    id,
    status: "retrying",
    attempts: 0,
    target: config(ctx).target,
    target_status: null,
    error: null,
    received_ms: now,
    updated_ms: now,
    next_retry_ms: null,
  };
  ctx.state.set(`hook/${id}/body`, body);
  deliver(ctx, delivery, body);
  return ctx.json(delivery.status === "delivered" ? 200 : 502, delivery);
}

/**
 * Makes one delivery attempt and records its outcome, scheduling the next
 * attempt when the failure may go away.
 */
function deliver(ctx: Ctx, delivery: Delivery, body: Uint8Array): void {
  const cfg = config(ctx);
  delivery.attempts += 1;
  delivery.updated_ms = ctx.now();
  delivery.target = cfg.target;
  delivery.next_retry_ms = null;
  const result = attempt(ctx, delivery.id, body, cfg);
  if (result.outcome === "delivered") {
    delivery.status = "delivered";
    delivery.error = null;
    delivery.target_status = result.code;
  } else if (result.outcome === "retry" && delivery.attempts < MAX_ATTEMPTS) {
    const delay = FIRST_RETRY_MS * 2 ** (delivery.attempts - 1);
    ctx.timers.schedule(delay, { name: "retry", body: { id: delivery.id } });
    delivery.next_retry_ms = ctx.now() + delay;
    delivery.status = "retrying";
    delivery.error = result.error;
    delivery.target_status = result.code;
  } else {
    delivery.status = "failed";
    delivery.error = result.error;
    delivery.target_status = result.code;
  }
  ctx.state.setJson(`hook/${delivery.id}`, delivery);
  if (delivery.status !== "retrying") ctx.state.delete(`hook/${delivery.id}/body`);
}

/** Signs and sends the forwarded body once. */
function attempt(ctx: Ctx, id: string, body: Uint8Array, cfg: Config): Attempt {
  try {
    const mac = ctx.crypto.hmacSha256(ctx.secret(SIGNING_KEY), body);
    const signature = Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("");
    const response = ctx.http.fetch({
      method: "POST",
      url: cfg.target,
      headers: {
        "content-type": "application/json",
        "x-webhook-id": id,
        "x-signature": `sha256=${signature}`,
        ...(cfg.auth_secret === null ? {} : { authorization: ctx.secret(cfg.auth_secret).header("Bearer {}") }),
      },
      body,
    });
    if (response.ok) return { outcome: "delivered", code: response.status };
    const error = `the target answered ${response.status}`;
    const retry = response.status === 429 || response.status >= 500;
    return { outcome: retry ? "retry" : "fail", error, code: response.status };
  } catch (e) {
    if (!(e instanceof KronikError)) throw e;
    return { outcome: RETRYABLE.includes(e.kind) ? "retry" : "fail", error: e.message, code: null };
  }
}

export default actor({
  kind: "webhook-relay",
  schemaVersion: 0,
  routes: [
    { method: "POST", pattern: "/hooks/{key}" },
    { method: "GET", pattern: "/hooks/{key}/{id}" },
  ],
  capabilities: ["http:webhooks.example.com", `secret:${SIGNING_KEY}`],

  http(req, ctx) {
    const id = req.param("id");
    if (req.method === "POST" && id === undefined) return accept(req, ctx);
    if (req.method === "GET" && id !== undefined) {
      const delivery = ctx.state.getJson<Delivery>(`hook/${id}`);
      return delivery === undefined ? ctx.status(404) : ctx.json(200, delivery);
    }
    return ctx.status(405);
  },

  message(msg, ctx) {
    if (msg.name !== "configure") {
      throw new Rejected(`unknown message ${JSON.stringify(msg.name)}: webhook-relay takes \`configure\``);
    }
    const update = msg.json<{ target?: string | null; auth_secret?: string | null }>();
    const cfg = config(ctx);
    if (typeof update.target === "string") {
      if (!["https://", "http://", "foreign://"].some((scheme) => update.target?.startsWith(scheme))) {
        throw new Rejected(`target ${JSON.stringify(update.target)} is not an https://, http:// or foreign:// URL`);
      }
      cfg.target = update.target;
    }
    if (typeof update.auth_secret === "string") cfg.auth_secret = update.auth_secret;
    ctx.state.setJson("config", cfg);
    return ctx.reply({ name: "config", body: cfg });
  },

  timer(timer, ctx) {
    const { id } = timer.message.json<{ id: string }>();
    const delivery = ctx.state.getJson<Delivery>(`hook/${id}`);
    const body = ctx.state.get(`hook/${id}/body`);
    if (delivery !== undefined && body !== undefined && delivery.status === "retrying") {
      deliver(ctx, delivery, body);
    }
    return ctx.none();
  },
});
