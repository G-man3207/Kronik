//! notes-rs: notes in SQL state per actor.
//!
//! Every actor `notes/<key>` keeps one user's notes in its own SQLite
//! database. Rows carry the subject `user:<key>` in their `_subject` column,
//! so privacy mode can seal them and erasure can remove them.
//!
//! - `POST /notes/{key}` with `{"title": "...", "body": "..."}` creates a
//!   note and returns it with `201`.
//! - `GET /notes/{key}` lists the notes, oldest first, a page at a time:
//!   `{"notes": [...], "next": id}`. `?limit=` sets the page size (default
//!   100, at most 1000) and `?after=<next>` gets the following page; `next`
//!   is `null` on the last page.
//! - `GET /notes/{key}/{id}` returns one note, or `404`.
//! - `DELETE /notes/{key}/{id}` deletes one note: `204`, or `404`.
//!
//! The schema is at version 2: version 1 created the table, version 2 added
//! a random token per note. A new actor runs both steps in `migrate(0)`.
//! `created` comes from `datetime('now')` and `token` from `randomblob()`;
//! both are deterministic, so rebuilding the database from the log gives the
//! same rows.

use kronik_sdk::prelude::*;
use serde::{Deserialize, Serialize};

struct Notes;

/// The schema version that `migrate` brings an actor to.
const SCHEMA_VERSION: u32 = 2;

const MAX_TITLE_CHARS: usize = 200;

/// Notes per page of `GET /notes/{key}`: the default and the most. A page
/// of 1000 notes uses about 16 million fuel, a third of a turn's default.
const PAGE: u32 = 100;
const MAX_PAGE: u32 = 1000;

const COLUMNS: &str = "id, title, body, created, token";

#[derive(Deserialize)]
struct NewNote {
    title: String,
    #[serde(default)]
    body: String,
}

#[derive(Serialize)]
struct Note {
    id: i64,
    title: String,
    body: String,
    created: String,
    token: String,
}

impl Note {
    fn from_row(row: Row<'_>) -> Result<Self, Error> {
        Ok(Note {
            id: row.get("id")?,
            title: row.get("title")?,
            body: row.get("body")?,
            created: row.get("created")?,
            token: row.get("token")?,
        })
    }
}

impl Actor for Notes {
    fn describe() -> Manifest {
        Manifest::new("notes", SCHEMA_VERSION)
            .route(Route::post("/notes/{key}"))
            .route(Route::get("/notes/{key}"))
            .route(Route::get("/notes/{key}/{id}"))
            .route(Route::delete("/notes/{key}/{id}"))
    }

    fn migrate(ctx: &mut Ctx, from: u32) -> Result<(), HandlerError> {
        // Every step since `from`, in order. DDL is allowed only here, and
        // only before the first statement that changes data.
        if from < 1 {
            ctx.sql().execute(
                "CREATE TABLE notes (
                    id INTEGER PRIMARY KEY,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created TEXT NOT NULL,
                    _subject TEXT DEFAULT (kronik_subject())
                )",
                params![],
            )?;
        }
        if from < 2 {
            ctx.sql().execute(
                "ALTER TABLE notes ADD COLUMN token TEXT NOT NULL DEFAULT ''",
                params![],
            )?;
        }
        Ok(())
    }

    fn http(ctx: &mut Ctx, request: HttpRequest) -> Result<Output, HandlerError> {
        // Rows written in this turn belong to the actor's user.
        ctx.subject(format!("user:{}", ctx.self_ref().key).as_str());
        let id = request.param("id").map(str::parse::<i64>);
        match (request.method.as_str(), id) {
            ("POST", None) => create(ctx, &request),
            ("GET", None) => list(ctx, &request),
            ("GET", Some(Ok(id))) => get(ctx, id),
            ("DELETE", Some(Ok(id))) => delete(ctx, id),
            (_, Some(Err(_))) => Ok(Output::status(404)),
            _ => Ok(Output::status(405)),
        }
    }
}

fn create(ctx: &Ctx, request: &HttpRequest) -> Result<Output, HandlerError> {
    let note: NewNote = match request.json() {
        Ok(note) => note,
        Err(e) => return Ok(bad_request(&e.to_string())),
    };
    let title = note.title.trim();
    if title.is_empty() || title.chars().count() > MAX_TITLE_CHARS {
        return Ok(bad_request(&format!(
            "the title must have 1 to {MAX_TITLE_CHARS} characters"
        )));
    }
    let rows = ctx.sql().query(
        &format!(
            "INSERT INTO notes (title, body, created, token)
             VALUES (?1, ?2, datetime('now'), lower(hex(randomblob(8))))
             RETURNING {COLUMNS}"
        ),
        params![title, note.body],
    )?;
    match rows.first() {
        Some(row) => Ok(Output::json(201, &Note::from_row(row)?)),
        None => Err(HandlerError::failed("INSERT ... RETURNING returned no row")),
    }
}

fn list(ctx: &Ctx, request: &HttpRequest) -> Result<Output, HandlerError> {
    let after = match request.query_param("after").map(|v| v.parse::<i64>()) {
        None => 0,
        Some(Ok(after)) => after,
        Some(Err(_)) => return Ok(bad_request("after must be a note id")),
    };
    let limit = match request.query_param("limit").map(|v| v.parse::<u32>()) {
        None => PAGE,
        Some(Ok(limit)) if (1..=MAX_PAGE).contains(&limit) => limit,
        Some(_) => return Ok(bad_request(&format!("limit must be 1 to {MAX_PAGE}"))),
    };
    // One row more than the page shows whether there is a next page.
    let rows = ctx.sql().query(
        &format!("SELECT {COLUMNS} FROM notes WHERE id > ?1 ORDER BY id LIMIT ?2"),
        params![after, limit + 1],
    )?;
    let mut notes = rows
        .iter()
        .map(Note::from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let next = if notes.len() > limit as usize {
        notes.truncate(limit as usize);
        notes.last().map(|n| n.id)
    } else {
        None
    };
    Ok(Output::json(
        200,
        &serde_json::json!({ "notes": notes, "next": next }),
    ))
}

fn get(ctx: &Ctx, id: i64) -> Result<Output, HandlerError> {
    let rows = ctx.sql().query(
        &format!("SELECT {COLUMNS} FROM notes WHERE id = ?1"),
        params![id],
    )?;
    match rows.first() {
        Some(row) => Ok(Output::json(200, &Note::from_row(row)?)),
        None => Ok(Output::status(404)),
    }
}

fn delete(ctx: &Ctx, id: i64) -> Result<Output, HandlerError> {
    match ctx
        .sql()
        .execute("DELETE FROM notes WHERE id = ?1", params![id])?
    {
        0 => Ok(Output::status(404)),
        _ => Ok(Output::none()),
    }
}

fn bad_request(message: &str) -> Output {
    Output::json(400, &serde_json::json!({ "error": message }))
}

kronik_sdk::export!(Notes);
