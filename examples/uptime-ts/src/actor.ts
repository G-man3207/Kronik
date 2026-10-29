// uptime-ts: checks a site's URLs in parallel with standard `fetch` (M22).
//
// Every actor `uptime/<site>` keeps its targets (`config`) and the last check
// (`last`) in its state.
//
// - The message `configure` with `{"targets": ["https://...", ...],
//   "token_secret": "<secret name>"}` (both optional) sets the URLs to check
//   (at most 20) and the secret sent as `authorization: Bearer <secret>`.
// - `POST /uptime/{key}/check` fetches every target at once
//   (`Promise.all`), stores the check and returns it: `{"at": <ms>,
//   "results": [{"url", "status"} or {"url", "error"}]}`.
// - `GET /uptime/{key}` returns the last check, or `404`.
//
// Each `fetch` is an `http.fetch` effect, as `ctx.http.fetch` is: recorded,
// matched in replay, answered by simulators in forks. The token is written
// as `Bearer {{secret:<name>}}` and inserted by the host, so the actor never
// holds its value. A failed fetch is a TypeError whatever went wrong (a
// missing grant, a network error, a timeout); `ctx.http.fetch` tells them
// apart. Grants: `http:<host>` for every target, `secret:<name>` for a token.

import { actor, type Ctx, type Output, Rejected } from "@kronik/sdk";

const MAX_TARGETS = 20;

interface Config {
  targets: string[];
  token_secret: string | null;
}

interface Result {
  url: string;
  status?: number;
  error?: string;
}

interface Check {
  at: number;
  results: Result[];
}

function config(ctx: Ctx): Config {
  return ctx.state.getJson<Config>("config") ?? { targets: [], token_secret: null };
}

async function probe(url: string, token: string | null): Promise<Result> {
  try {
    const res = await fetch(url, {
      headers: token === null ? {} : { authorization: `Bearer {{secret:${token}}}` },
    });
    await res.arrayBuffer();
    return { url, status: res.status };
  } catch (e) {
    return { url, error: e instanceof Error ? `${e.name}: ${e.message}` : String(e) };
  }
}

export default actor({
  kind: "uptime",
  schemaVersion: 0,
  routes: [
    { method: "POST", pattern: "/uptime/{key}/check" },
    { method: "GET", pattern: "/uptime/{key}" },
  ],

  async http(req, ctx): Promise<Output> {
    if (req.method === "GET") {
      const last = ctx.state.getJson<Check>("last");
      return last === undefined ? ctx.status(404) : ctx.json(200, last);
    }
    const cfg = config(ctx);
    const results = await Promise.all(cfg.targets.map((url) => probe(url, cfg.token_secret)));
    const check: Check = { at: ctx.now(), results };
    ctx.state.setJson("last", check);
    return ctx.json(200, check);
  },

  message(msg, ctx) {
    if (msg.name !== "configure") {
      throw new Rejected(`unknown message ${JSON.stringify(msg.name)}: uptime takes \`configure\``);
    }
    const update = msg.json<{ targets?: unknown; token_secret?: string | null }>();
    const cfg = config(ctx);
    if (update.targets !== undefined) {
      const targets = update.targets;
      if (
        !Array.isArray(targets) ||
        targets.length > MAX_TARGETS ||
        !targets.every((t) => typeof t === "string" && (t.startsWith("https://") || t.startsWith("http://")))
      ) {
        throw new Rejected(`targets must be at most ${MAX_TARGETS} http:// or https:// URLs`);
      }
      cfg.targets = targets;
    }
    if (update.token_secret !== undefined) cfg.token_secret = update.token_secret;
    ctx.state.setJson("config", cfg);
    return ctx.reply({ name: "config", body: cfg });
  },
});
