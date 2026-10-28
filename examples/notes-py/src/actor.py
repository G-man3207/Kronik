# notes-py: notes in SQL state per actor, the Python twin of notes-ts.
#
# Every actor `notes/<key>` keeps one user's notes in its own SQLite
# database. Rows carry the subject `user:<key>` in their `_subject` column,
# so privacy mode can seal them and erasure can remove them.
#
# - `POST /notes/{key}` with `{"title": "...", "body": "..."}` creates a note
#   and returns it with `201`.
# - `GET /notes/{key}` lists the notes, oldest first, a page at a time:
#   `{"notes": [...], "next": id}`. `?limit=` sets the page size (default
#   100, at most 1000) and `?after=<next>` gets the following page; `next` is
#   `null` on the last page.
# - `GET /notes/{key}/{id}` returns one note, or `404`.
# - `DELETE /notes/{key}/{id}` deletes one note: `204`, or `404`.
#
# The schema is at version 2: version 1 created the table, version 2 added a
# random token per note. A new actor runs both steps in `migrate(0)`.
# `created` comes from `datetime('now')` and `token` from `randomblob()`;
# both are deterministic, so rebuilding the database from the log gives the
# same rows.

import json
import re

from kronik import KronikError, actor

MAX_TITLE_CHARS = 200

# Notes per page of `GET /notes/{key}`: the default and the most.
PAGE = 100
MAX_PAGE = 1000

COLUMNS = "id, title, body, created, token"

NOTE_ID = re.compile(r"-?[0-9]{1,18}")
LIMIT = re.compile(r"[0-9]{1,4}")


def bad_request(ctx, error):
    return ctx.json(400, {"error": error})


def create(req, ctx):
    try:
        note = req.json()
    except KronikError as e:
        return bad_request(ctx, str(e))
    if not isinstance(note, dict) or not isinstance(note.get("title"), str):
        return bad_request(ctx, "the note must be an object with a string title")
    body = note.get("body")
    body = "" if body is None else body
    if not isinstance(body, str):
        return bad_request(ctx, "the body must be a string")
    title = note["title"].strip()
    if title == "" or len(title) > MAX_TITLE_CHARS:
        return bad_request(ctx, f"the title must have 1 to {MAX_TITLE_CHARS} characters")
    row = ctx.sql.query(
        f"""INSERT INTO notes (title, body, created, token)
       VALUES (?1, ?2, datetime('now'), lower(hex(randomblob(8))))
       RETURNING {COLUMNS}""",
        [title, body],
    ).first()
    if row is None:
        raise RuntimeError("INSERT ... RETURNING returned no row")
    return ctx.json(201, row)


def list_notes(req, ctx):
    after = req.query_param("after")
    after = "0" if after is None else after
    if not NOTE_ID.fullmatch(after):
        return bad_request(ctx, "after must be a note id")
    limit_param = req.query_param("limit")
    limit_param = str(PAGE) if limit_param is None else limit_param
    limit = int(limit_param) if LIMIT.fullmatch(limit_param) else 0
    if limit < 1 or limit > MAX_PAGE:
        return bad_request(ctx, f"limit must be 1 to {MAX_PAGE}")
    # SQLite builds the page as one JSON text: rows cross from the host one
    # SQL value at a time, so one value per page is cheapest. One row more
    # than the page shows whether there is a next page.
    page = ctx.sql.query(
        f"""SELECT json_group_array(
         json_object('id', id, 'title', title, 'body', body, 'created', created, 'token', token) ORDER BY id
       ) AS notes
       FROM (SELECT {COLUMNS} FROM notes WHERE id > ?1 ORDER BY id LIMIT ?2)""",
        [int(after), limit + 1],
    ).first()
    notes = json.loads(page["notes"] if page and page["notes"] is not None else "[]")
    next_id = None
    if len(notes) > limit:
        del notes[limit:]
        next_id = notes[limit - 1]["id"]
    return ctx.json(200, {"notes": notes, "next": next_id})


def migrate(from_version, ctx):
    # Every step since `from_version`, in order. DDL is allowed only here,
    # and only before the first statement that changes data.
    if from_version < 1:
        ctx.sql.execute("""CREATE TABLE notes (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created TEXT NOT NULL,
        _subject TEXT DEFAULT (kronik_subject())
      )""")
    if from_version < 2:
        ctx.sql.execute("ALTER TABLE notes ADD COLUMN token TEXT NOT NULL DEFAULT ''")


def http(req, ctx):
    # Rows written in this turn belong to the actor's user.
    ctx.subject(f"user:{ctx.self().key}")
    id_param = req.param("id")
    if id_param is None:
        if req.method == "POST":
            return create(req, ctx)
        if req.method == "GET":
            return list_notes(req, ctx)
        return ctx.status(405)
    if not NOTE_ID.fullmatch(id_param):
        return ctx.status(404)
    note_id = int(id_param)
    if req.method == "GET":
        note = ctx.sql.query(f"SELECT {COLUMNS} FROM notes WHERE id = ?1", [note_id]).first()
        return ctx.status(404) if note is None else ctx.json(200, note)
    if req.method == "DELETE":
        return ctx.status(404) if ctx.sql.execute("DELETE FROM notes WHERE id = ?1", [note_id]) == 0 else ctx.none()
    return ctx.status(405)


handler = actor(
    kind="notes",
    schema_version=2,
    routes=[
        {"method": "POST", "pattern": "/notes/{key}"},
        {"method": "GET", "pattern": "/notes/{key}"},
        {"method": "GET", "pattern": "/notes/{key}/{id}"},
        {"method": "DELETE", "pattern": "/notes/{key}/{id}"},
    ],
    migrate=migrate,
    http=http,
)
