// todo-ts: to-do lists over HTTP, one actor per list.
//
// Every actor `todo/<key>` keeps one list, as one JSON value under `list` in
// its state: the items (`{"id", "title", "done", "created_ms", "done_ms"}`),
// the next item id and when the next sweep is due. A request reads and
// writes that one value: in a JavaScript actor every host call costs about
// 0.1 million of the 50 million fuel a turn may use, so a value per item
// would limit a list to a few hundred items.
//
// - `POST /todo/{key}` with `{"title": "..."}` adds an item: `201` and the
//   item. A list holds at most 500 items (`409` after that).
// - `GET /todo/{key}` returns `{"items": [...]}`, oldest first.
// - `GET /todo/{key}/{id}` returns one item, or `404`.
// - `PATCH /todo/{key}/{id}` with `{"title": "..."}` and/or `{"done": true}`
//   changes an item: `200` and the item, or `404`.
// - `DELETE /todo/{key}/{id}` removes an item: `204`, or `404`.
//
// Invalid input gets `400` and `{"error": "..."}`.
//
// Done items are removed a day after they were done, by a timer: marking an
// item done makes sure a `sweep` timer is pending, and every sweep removes
// the items done for a day or more and schedules the next sweep while done
// items remain.

import { actor, type Ctx, type Output, type Request } from "@kronik/sdk";

const MAX_TITLE_CHARS = 200;
const MAX_ITEMS = 500;
/** How long a done item stays on its list. */
const RETENTION_MS = 24 * 60 * 60 * 1000;

interface Item {
  id: number;
  title: string;
  done: boolean;
  created_ms: number;
  /** When it was done, or `null` while it is not. */
  done_ms: number | null;
}

interface List {
  items: Item[];
  next_id: number;
  /** When the pending sweep timer fires, or `null` if none is pending. */
  sweep_ms: number | null;
}

/** Invalid input: answered with `400` and the message. */
class BadRequest extends Error {}

/** The request body, which must be a JSON object. */
function object(req: Request): Record<string, unknown> {
  let body: unknown;
  try {
    body = req.json();
  } catch {
    body = undefined;
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new BadRequest("the body must be a JSON object");
  }
  return body as Record<string, unknown>;
}

/** A title, trimmed. */
function title(value: unknown): string {
  const t = typeof value === "string" ? value.trim() : "";
  if (t === "" || [...t].length > MAX_TITLE_CHARS) {
    throw new BadRequest(`the title must be a string of 1 to ${MAX_TITLE_CHARS} characters`);
  }
  return t;
}

/** Makes sure a sweep is pending for an item done at `doneMs`. */
function scheduleSweep(ctx: Ctx, list: List, doneMs: number): void {
  if (list.sweep_ms !== null) return;
  list.sweep_ms = doneMs + RETENTION_MS;
  ctx.timers.schedule(Math.max(0, list.sweep_ms - ctx.now()), { name: "sweep" });
}

function update(req: Request, ctx: Ctx, list: List, item: Item): void {
  const body = object(req);
  if (body.title !== undefined) item.title = title(body.title);
  if (body.done !== undefined) {
    if (typeof body.done !== "boolean") throw new BadRequest("done must be true or false");
    if (body.done && !item.done) {
      item.done_ms = ctx.now();
      scheduleSweep(ctx, list, item.done_ms);
    } else if (!body.done) {
      item.done_ms = null;
    }
    item.done = body.done;
  }
}

function route(req: Request, ctx: Ctx): Output {
  const list = ctx.state.getJson<List>("list") ?? { items: [], next_id: 1, sweep_ms: null };
  const id = req.param("id");
  if (id === undefined) {
    if (req.method === "GET") return ctx.json(200, { items: list.items });
    if (req.method !== "POST") return ctx.status(405);
    const t = title(object(req).title);
    if (list.items.length >= MAX_ITEMS) {
      return ctx.json(409, { error: `the list is full: it has ${MAX_ITEMS} items` });
    }
    const item: Item = { id: list.next_id, title: t, done: false, created_ms: ctx.now(), done_ms: null };
    list.next_id += 1;
    list.items.push(item);
    ctx.state.setJson("list", list);
    return ctx.json(201, item);
  }
  const index = list.items.findIndex((item) => String(item.id) === id);
  if (index < 0) return ctx.status(404);
  const item = list.items[index];
  switch (req.method) {
    case "GET":
      return ctx.json(200, item);
    case "PATCH":
      update(req, ctx, list, item);
      ctx.state.setJson("list", list);
      return ctx.json(200, item);
    case "DELETE":
      list.items.splice(index, 1);
      ctx.state.setJson("list", list);
      return ctx.none();
    default:
      return ctx.status(405);
  }
}

export default actor({
  kind: "todo",
  schemaVersion: 0,
  routes: [
    { method: "POST", pattern: "/todo/{key}" },
    { method: "GET", pattern: "/todo/{key}" },
    { method: "GET", pattern: "/todo/{key}/{id}" },
    { method: "PATCH", pattern: "/todo/{key}/{id}" },
    { method: "DELETE", pattern: "/todo/{key}/{id}" },
  ],

  http(req, ctx) {
    try {
      return route(req, ctx);
    } catch (e) {
      if (e instanceof BadRequest) return ctx.json(400, { error: e.message });
      throw e;
    }
  },

  timer(timer, ctx) {
    const list = ctx.state.getJson<List>("list");
    if (timer.message.name !== "sweep" || list === undefined) return ctx.none();
    const now = ctx.now();
    const kept = list.items.filter((item) => item.done_ms === null || item.done_ms + RETENTION_MS > now);
    if (kept.length < list.items.length) {
      console.log(`removed ${list.items.length - kept.length} items done for a day`);
    }
    list.items = kept;
    list.sweep_ms = null;
    const oldest = Math.min(...kept.map((item) => item.done_ms ?? Infinity));
    if (oldest !== Infinity) scheduleSweep(ctx, list, oldest);
    ctx.state.setJson("list", list);
    return ctx.none();
  },
});
