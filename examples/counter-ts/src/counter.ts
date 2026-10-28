// counter-ts: the brief's counter, the TypeScript twin of counter-rs.
//
// Every actor `counter/<key>` keeps a number `n` in its state.
//
// - `POST /counter/{key}/increment` adds `step` and returns `{"n": n}`.
// - `GET /counter/{key}` returns `{"n": n}` without changing it.
// - Any message, for example `kronik send counter/alice increment`, adds
//   `step` and replies `{"n": n}`.
//
// The kind has schema version 1, so a new actor first runs `migrate(0)`; the
// counter has no schema, so that turn changes nothing. src/actor.ts adds 1;
// src/step2.ts adds 2, a changed behavior for the M3 tests (`kronik build
// --entry src/step2.ts` builds it as counter-ts-step2.wasm).

import { actor, type Ctx, type Handler } from "@kronik/sdk";

export function counter(step: number): Handler {
  const increment = (ctx: Ctx): number => {
    const n = (ctx.state.getJson<number>("n") ?? 0) + step;
    ctx.state.setJson("n", n);
    return n;
  };
  return actor({
    kind: "counter",
    schemaVersion: 1,
    routes: [
      { method: "POST", pattern: "/counter/{key}/increment" },
      { method: "GET", pattern: "/counter/{key}" },
    ],
    http(req, ctx) {
      if (req.method === "GET") {
        return ctx.json(200, { n: ctx.state.getJson<number>("n") ?? 0 });
      }
      return ctx.json(200, { n: increment(ctx) });
    },
    message(_msg, ctx) {
      return ctx.reply({ name: "n", body: { n: increment(ctx) } });
    },
  });
}
