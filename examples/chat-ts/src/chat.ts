// chat-ts: chat rooms over WebSocket and server-sent events (M24).
//
// Every actor `chat/<key>` is one room. Its messages are rows in its SQL
// state, numbered by the room's sequence (`seq`); the connections it holds
// are keys in its state.
//
// - `WEBSOCKET /chat/{key}/ws?user=<id>` joins the room as `user:<id>`
//   (`[a-z0-9_-]{1,32}`), which becomes the connection's subject. A browser's
//   `Origin` must match the request's host. The first frame is
//   `{"type":"welcome","connection","members","last"}`, where `last` is the
//   room's last sequence number.
// - A member sends `{"type":"say","text","id"}`. Every member, the sender
//   included, receives `{"type":"message","seq","user","text","ts","id"}`:
//   the sender's copy is its acknowledgement. `{"type":"bot","prompt"}`
//   streams a deterministic answer word by word with `sendNow` (when the
//   kind has `connection:send-now`), then posts it to the room. Members
//   also see `joined` and `left`.
// - `SSE /chat/{key}/events` follows the room read-only: one `message`
//   event per message, with `id` the sequence number. A reconnecting
//   EventSource sends `Last-Event-ID` and gets what it missed (`?after=`
//   does the same for clients without one), at most 100 messages.
// - `GET /chat/{key}/messages?after=<seq>&limit=<n>` returns
//   `{"messages":[...],"last"}`: how a client resynchronizes after a
//   reconnect (`limit` at most 1000, default 100).
// - `POST /chat/{key}/messages` with `{"user","text","id"?}` posts over HTTP:
//   stored and sent to the room's connections from an HTTP turn.
// - `GET /chat/{key}/members` lists the members and counts the followers.
// - `GET /chat/{key}` is a small page with a WebSocket client.
//
// Frames are delivered when their turn commits and never retried: a client
// that reconnects compares the welcome's `last` with the last `seq` it saw
// and fetches the gap from `/messages` (see `kronik explain connections`).

import { Frame, type ActorSpec, type Closed, type Ctx, type IncomingFrame, type OpenReply, type OpenRequest, type Output, type Request } from "@kronik/sdk";
import { page } from "./page.ts";

/** A stored message, as the room's SQL returns it. */
export interface ChatMessage {
  seq: number;
  user: string;
  text: string;
  ts: number;
  id: string;
}

/**
 * The `message` frame for a stored message: what the room sends its members.
 * step2.ts changes only this.
 */
export type Format = (m: ChatMessage) => Record<string, unknown>;

export const format: Format = (m) => ({ type: "message", seq: m.seq, user: m.user, text: m.text, ts: m.ts, id: m.id });

const USER = /^[a-z0-9_-]{1,32}$/;
const MAX_TEXT = 2000;
const MAX_ID = 64;
const RESUME = 100;
const PAGE = 100;
const MAX_PAGE = 1000;

const WS = "ws/";
const SSE = "sse/";
const COLUMNS = "seq, user, text, ts, id";

function members(ctx: Ctx): string[] {
  return ctx.state.keys(WS).map((k) => k.slice(WS.length));
}

function followers(ctx: Ctx): string[] {
  return ctx.state.keys(SSE).map((k) => k.slice(SSE.length));
}

function lastSeq(ctx: Ctx): number {
  const row = ctx.sql.query("SELECT coalesce(max(seq), 0) AS last FROM messages").first();
  return Number(row?.last ?? 0);
}

/** The messages after `after`, oldest first, at most `limit`, as one JSON text built by SQLite. */
function since(ctx: Ctx, after: number, limit: number): string {
  // SQLite builds the JSON: a row's values cross from the host one at a time,
  // which costs a JavaScript actor fuel per value.
  const row = ctx.sql
    .query(
      `SELECT json_group_array(json_object('seq', seq, 'user', user, 'text', text, 'ts', ts, 'id', id) ORDER BY seq) AS list
       FROM (SELECT ${COLUMNS} FROM messages WHERE seq > ?1 ORDER BY seq LIMIT ?2)`,
      [after, limit],
    )
    .first();
  return String(row?.list ?? "[]");
}

/** A same-origin check against cross-site WebSocket hijacking: a browser sends `Origin`. */
function sameOrigin(req: OpenRequest): boolean {
  const origin = req.origin();
  if (origin === undefined) return true;
  try {
    return new URL(origin).host === req.header("host");
  } catch {
    return false;
  }
}

function sendToRoom(ctx: Ctx, fmt: Format, m: ChatMessage): void {
  const ws = members(ctx);
  if (ws.length > 0) ctx.connections.broadcast(ws, Frame.json(fmt(m)));
  const sse = followers(ctx);
  if (sse.length > 0) ctx.connections.broadcast(sse, Frame.event({ event: "message", id: m.seq, data: fmt(m) }));
}

/** Stores a message under the turn's default subject and sends it to the room. */
function post(ctx: Ctx, fmt: Format, user: string, text: string, id: string): ChatMessage {
  const row = ctx.sql
    .query(`INSERT INTO messages (user, text, ts, id) VALUES (?1, ?2, ?3, ?4) RETURNING ${COLUMNS}`, [user, text, ctx.now(), id])
    .first();
  if (row === undefined) throw new Error("INSERT ... RETURNING returned no row");
  const m = row as unknown as ChatMessage;
  sendToRoom(ctx, fmt, m);
  return m;
}

function textError(text: unknown): string | undefined {
  if (typeof text !== "string" || text.trim() === "") return "text must be a non-empty string";
  if ([...text].length > MAX_TEXT) return `text must have at most ${MAX_TEXT} characters`;
  return undefined;
}

function open(fmt: Format) {
  return (req: OpenRequest, ctx: Ctx): OpenReply | Output => {
    if (req.protocol === "sse") return follow(fmt, req, ctx);
    return join(req, ctx);
  };
}

/** An SSE follower: read-only, anonymous, resumed from `Last-Event-ID` or `?after=`. */
function follow(fmt: Format, req: OpenRequest, ctx: Ctx): OpenReply {
  const after = Number(req.lastEventId() ?? req.queryParam("after") ?? NaN);
  ctx.state.set(SSE + req.connection, "");
  if (Number.isSafeInteger(after) && after >= 0) {
    for (const m of JSON.parse(since(ctx, after, RESUME)) as ChatMessage[]) {
      ctx.connections.send(req.connection, Frame.event({ event: "message", id: m.seq, data: fmt(m) }));
    }
  }
  return ctx.accept();
}

/** A WebSocket member. */
function join(req: OpenRequest, ctx: Ctx): OpenReply | Output {
  const user = req.queryParam("user");
  if (user === undefined || !USER.test(user)) return ctx.json(400, { error: "user must match [a-z0-9_-]{1,32}" });
  if (!sameOrigin(req)) return ctx.json(403, { error: "cross-origin WebSocket refused" });
  const subject = `user:${user}`;
  ctx.subject(subject);
  const others = members(ctx);
  const names = others.map((c) => ctx.state.getJson<{ user: string }>(WS + c)?.user ?? "");
  ctx.state.setJson(WS + req.connection, { user });
  ctx.connections.send(req.connection, Frame.json({ type: "welcome", connection: req.connection, members: names, last: lastSeq(ctx) }));
  if (others.length > 0) ctx.connections.broadcast(others, Frame.json({ type: "joined", user }));
  return ctx.accept({ subject });
}

/** The answer of the room's bot: the prompt's words, reversed, deterministically. */
function botAnswer(prompt: string): string[] {
  const words = prompt.split(/\s+/).filter((w) => w !== "");
  return words.length === 0 ? ["…"] : words.reverse();
}

function frame(fmt: Format) {
  return (f: IncomingFrame, ctx: Ctx): void => {
    const member = ctx.state.getJson<{ user: string }>(WS + f.connection);
    if (member === undefined) return; // a frame after the member left
    let m: { type?: unknown; text?: unknown; id?: unknown; prompt?: unknown };
    try {
      m = f.json();
    } catch {
      ctx.connections.send(f.connection, Frame.json({ type: "error", error: "frames must be JSON" }));
      return;
    }
    const id = typeof m.id === "string" ? m.id.slice(0, MAX_ID) : "";
    if (m.type === "say") {
      const error = textError(m.text);
      if (error !== undefined) {
        ctx.connections.send(f.connection, Frame.json({ type: "error", error, id }));
        return;
      }
      post(ctx, fmt, member.user, m.text as string, id);
    } else if (m.type === "bot") {
      const prompt = typeof m.prompt === "string" ? m.prompt.slice(0, MAX_TEXT) : "";
      const tokens = botAnswer(prompt);
      // Intermediate results go out now; the final message is buffered, so
      // it is sent only if the turn commits.
      let streaming = true;
      for (const token of tokens) {
        if (!streaming) break;
        try {
          streaming = ctx.connections.sendNow(f.connection, Frame.json({ type: "token", ref: id, text: token }));
        } catch (e) {
          if ((e as { kind?: string }).kind !== "send-now.denied") throw e;
          streaming = false; // no connection:send-now grant: answer in one frame
        }
      }
      post(ctx, fmt, "bot", tokens.join(" "), id);
    } else {
      ctx.connections.send(f.connection, Frame.json({ type: "error", error: "unknown frame type", id }));
    }
  };
}

function close(c: Closed, ctx: Ctx): void {
  if (ctx.state.get(SSE + c.connection) !== undefined) {
    ctx.state.delete(SSE + c.connection);
    return;
  }
  const member = ctx.state.getJson<{ user: string }>(WS + c.connection);
  if (member === undefined) return;
  ctx.state.delete(WS + c.connection);
  const others = members(ctx);
  if (others.length > 0) ctx.connections.broadcast(others, Frame.json({ type: "left", user: member.user }));
}

function badRequest(ctx: Ctx, error: string): Output {
  return ctx.json(400, { error });
}

function messages(req: Request, ctx: Ctx): Output {
  const after = req.queryParam("after") ?? "0";
  if (!/^\d{1,15}$/.test(after)) return badRequest(ctx, "after must be a sequence number");
  const limitParam = req.queryParam("limit") ?? String(PAGE);
  const limit = /^\d{1,4}$/.test(limitParam) ? Number(limitParam) : 0;
  if (limit < 1 || limit > MAX_PAGE) return badRequest(ctx, `limit must be 1 to ${MAX_PAGE}`);
  const body = `{"messages":${since(ctx, Number(after), limit)},"last":${lastSeq(ctx)}}`;
  return { tag: "http", val: { status: 200, headers: [{ name: "content-type", value: "application/json" }], body: { tag: "inline", val: new TextEncoder().encode(body) } } };
}

function postMessage(fmt: Format, req: Request, ctx: Ctx): Output {
  let m: { user?: unknown; text?: unknown; id?: unknown };
  try {
    m = req.json();
  } catch (e) {
    return badRequest(ctx, (e as Error).message);
  }
  if (typeof m !== "object" || m === null || typeof m.user !== "string" || !USER.test(m.user)) {
    return badRequest(ctx, "user must match [a-z0-9_-]{1,32}");
  }
  const error = textError(m.text);
  if (error !== undefined) return badRequest(ctx, error);
  ctx.subject(`user:${m.user}`);
  const id = typeof m.id === "string" ? m.id.slice(0, MAX_ID) : "";
  // HTTP answers keep the first format; only the frames follow `fmt`.
  return ctx.json(201, format(post(ctx, fmt, m.user, m.text as string, id)));
}

/** The chat room actor type, sending messages in format `fmt`. */
export function chat(fmt: Format): ActorSpec {
  return {
    kind: "chat",
    schemaVersion: 1,
    routes: [
      { method: "GET", pattern: "/chat/{key}" },
      { method: "WEBSOCKET", pattern: "/chat/{key}/ws" },
      { method: "SSE", pattern: "/chat/{key}/events" },
      { method: "GET", pattern: "/chat/{key}/messages" },
      { method: "POST", pattern: "/chat/{key}/messages" },
      { method: "GET", pattern: "/chat/{key}/members" },
    ],
    capabilities: ["connection:send-now"],
    migrate(_from, ctx) {
      ctx.sql.execute(
        `CREATE TABLE messages (
           seq INTEGER PRIMARY KEY,
           user TEXT NOT NULL,
           text TEXT NOT NULL,
           ts INTEGER NOT NULL,
           id TEXT NOT NULL,
           _subject TEXT DEFAULT (kronik_subject())
         )`,
      );
    },
    http(req, ctx) {
      if (req.path.endsWith("/messages")) return req.method === "POST" ? postMessage(fmt, req, ctx) : messages(req, ctx);
      if (req.path.endsWith("/members")) {
        const names = members(ctx).map((c) => ctx.state.getJson<{ user: string }>(WS + c)?.user ?? "");
        return ctx.json(200, { members: names.sort(), followers: followers(ctx).length });
      }
      return html(ctx);
    },
    connections: { open: open(fmt), frame: frame(fmt), close },
  };
}

function html(ctx: Ctx): Output {
  const out = ctx.text(200, page);
  if (out.tag === "http") out.val.headers = [{ name: "content-type", value: "text/html; charset=utf-8" }];
  return out;
}

