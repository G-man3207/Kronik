// notes-ts: notes in SQL state per actor, the TypeScript twin of notes-rs.
//
// Every actor `notes/<key>` keeps one user's notes in its own SQLite
// database. Rows carry the subject `user:<key>` in their `_subject` column,
// so privacy mode can seal them and erasure can remove them.
//
// - `POST /notes/{key}` with `{"title": "...", "body": "..."}` creates a note
//   and returns it with `201`.
// - `GET /notes/{key}` lists the notes, oldest first, a page at a time:
//   `{"notes": [...], "next": id}`. `?limit=` sets the page size (default
//   100, at most 1000) and `?after=<next>` gets the following page; `next` is
//   `null` on the last page.
// - `GET /notes/{key}/{id}` returns one note, or `404`.
// - `DELETE /notes/{key}/{id}` deletes one note: `204`, or `404`.
//
// The schema is at version 2: version 1 created the table, version 2 added a
// random token per note. A new actor runs both steps in `migrate(0)`.
// `created` comes from `datetime('now')` and `token` from `randomblob()`;
// both are deterministic, so rebuilding the database from the log gives the
// same rows.

import { actor, type Ctx, type Output, type Request } from "@kronik/sdk";

const MAX_TITLE_CHARS = 200;

// Notes per page of `GET /notes/{key}`: the default and the most.
const PAGE = 100;
const MAX_PAGE = 1000;

const COLUMNS = "id, title, body, created, token";

function badRequest(ctx: Ctx, error: string): Output {
  return ctx.json(400, { error });
}

function create(req: Request, ctx: Ctx): Output {
  let note: { title?: unknown; body?: unknown };
  try {
    note = req.json();
  } catch (e) {
    return badRequest(ctx, (e as Error).message);
  }
  if (typeof note !== "object" || note === null || typeof note.title !== "string") {
    return badRequest(ctx, "the note must be an object with a string title");
  }
  const body = note.body ?? "";
  if (typeof body !== "string") {
    return badRequest(ctx, "the body must be a string");
  }
  const title = note.title.trim();
  if (title === "" || [...title].length > MAX_TITLE_CHARS) {
    return badRequest(ctx, `the title must have 1 to ${MAX_TITLE_CHARS} characters`);
  }
  const row = ctx.sql
    .query(
      `INSERT INTO notes (title, body, created, token)
       VALUES (?1, ?2, datetime('now'), lower(hex(randomblob(8))))
       RETURNING ${COLUMNS}`,
      [title, body],
    )
    .first();
  if (row === undefined) throw new Error("INSERT ... RETURNING returned no row");
  return ctx.json(201, row);
}

function list(req: Request, ctx: Ctx): Output {
  const after = req.queryParam("after") ?? "0";
  if (!/^-?\d{1,18}$/.test(after)) return badRequest(ctx, "after must be a note id");
  const limitParam = req.queryParam("limit") ?? String(PAGE);
  const limit = /^\d{1,4}$/.test(limitParam) ? Number(limitParam) : 0;
  if (limit < 1 || limit > MAX_PAGE) return badRequest(ctx, `limit must be 1 to ${MAX_PAGE}`);
  // SQLite builds the page as one JSON text: rows cross from the host one SQL
  // value at a time, at about 40 000 fuel per value in a JavaScript actor, so
  // a page of 1000 notes as rows would not fit in a turn's 50 million fuel.
  // One row more than the page shows whether there is a next page.
  const page = ctx.sql
    .query(
      `SELECT json_group_array(
         json_object('id', id, 'title', title, 'body', body, 'created', created, 'token', token) ORDER BY id
       ) AS notes
       FROM (SELECT ${COLUMNS} FROM notes WHERE id > ?1 ORDER BY id LIMIT ?2)`,
      [BigInt(after), limit + 1],
    )
    .first();
  const notes = JSON.parse(String(page?.notes ?? "[]")) as Array<{ id: number }>;
  let next = null;
  if (notes.length > limit) {
    notes.length = limit;
    next = notes[limit - 1].id;
  }
  return ctx.json(200, { notes, next });
}

export default actor({
  kind: "notes",
  schemaVersion: 2,
  routes: [
    { method: "POST", pattern: "/notes/{key}" },
    { method: "GET", pattern: "/notes/{key}" },
    { method: "GET", pattern: "/notes/{key}/{id}" },
    { method: "DELETE", pattern: "/notes/{key}/{id}" },
  ],

  migrate(from, ctx) {
    // Every step since `from`, in order. DDL is allowed only here, and only
    // before the first statement that changes data.
    if (from < 1) {
      ctx.sql.execute(`CREATE TABLE notes (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created TEXT NOT NULL,
        _subject TEXT DEFAULT (kronik_subject())
      )`);
    }
    if (from < 2) {
      ctx.sql.execute("ALTER TABLE notes ADD COLUMN token TEXT NOT NULL DEFAULT ''");
    }
  },

  http(req, ctx) {
    // Rows written in this turn belong to the actor's user.
    ctx.subject(`user:${ctx.self().key}`);
    const idParam = req.param("id");
    if (idParam === undefined) {
      if (req.method === "POST") return create(req, ctx);
      if (req.method === "GET") return list(req, ctx);
      return ctx.status(405);
    }
    if (!/^-?\d{1,18}$/.test(idParam)) return ctx.status(404);
    const id = BigInt(idParam);
    if (req.method === "GET") {
      const note = ctx.sql.query(`SELECT ${COLUMNS} FROM notes WHERE id = ?1`, [id]).first();
      return note === undefined ? ctx.status(404) : ctx.json(200, note);
    }
    if (req.method === "DELETE") {
      return ctx.sql.execute("DELETE FROM notes WHERE id = ?1", [id]) === 0 ? ctx.status(404) : ctx.none();
    }
    return ctx.status(405);
  },
});
