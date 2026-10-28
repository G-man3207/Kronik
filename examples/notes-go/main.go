// notes-go: notes in SQL state per actor, the Go twin of notes-ts.
//
// Every actor notes/<key> keeps one user's notes in its own SQLite
// database. Rows carry the subject user:<key> in their _subject column, so
// privacy mode can seal them and erasure can remove them.
//
//   - POST /notes/{key} with {"title": "...", "body": "..."} creates a note
//     and returns it with 201.
//   - GET /notes/{key} lists the notes, oldest first, a page at a time:
//     {"notes": [...], "next": id}. ?limit= sets the page size (default
//     100, at most 1000) and ?after=<next> gets the following page; next is
//     null on the last page.
//   - GET /notes/{key}/{id} returns one note, or 404.
//   - DELETE /notes/{key}/{id} deletes one note: 204, or 404.
//
// The schema is at version 2: version 1 created the table, version 2 added
// a random token per note. A new actor runs both steps in Migrate(0).
// created comes from datetime('now') and token from randomblob(); both are
// deterministic, so rebuilding the database from the log gives the same
// rows.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"kronik.dev/sdk"
)

const maxTitleChars = 200

// Notes per page of GET /notes/{key}: the default and the most.
const (
	page    = 100
	maxPage = 1000
)

const columns = "id, title, body, created, token"

func badRequest(ctx *kronik.Ctx, msg string) (kronik.Output, error) {
	return ctx.JSON(400, map[string]string{"error": msg})
}

// digits reports whether s is 1 to max decimal digits, after a "-" if
// signed.
func digits(s string, max int, signed bool) bool {
	if signed {
		s = strings.TrimPrefix(s, "-")
	}
	if s == "" || len(s) > max {
		return false
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func create(req *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
	var value any
	if err := req.JSON(&value); err != nil {
		return badRequest(ctx, err.Error())
	}
	note, ok := value.(map[string]any)
	title, isText := note["title"].(string)
	if !ok || !isText {
		return badRequest(ctx, "the note must be an object with a string title")
	}
	body, isText := note["body"].(string)
	if !isText && note["body"] != nil {
		return badRequest(ctx, "the body must be a string")
	}
	title = strings.TrimSpace(title)
	if title == "" || utf8.RuneCountInString(title) > maxTitleChars {
		return badRequest(ctx, fmt.Sprintf("the title must have 1 to %d characters", maxTitleChars))
	}
	rows, err := ctx.SQL.Query(`INSERT INTO notes (title, body, created, token)
       VALUES (?1, ?2, datetime('now'), lower(hex(randomblob(8))))
       RETURNING `+columns, title, body)
	if err != nil {
		return kronik.Output{}, err
	}
	row, ok := rows.First()
	if !ok {
		return kronik.Output{}, errors.New("INSERT ... RETURNING returned no row")
	}
	return ctx.JSON(201, row)
}

func list(req *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
	after, ok := req.QueryParam("after")
	if !ok {
		after = "0"
	}
	if !digits(after, 18, true) {
		return badRequest(ctx, "after must be a note id")
	}
	limitParam, ok := req.QueryParam("limit")
	if !ok {
		limitParam = strconv.Itoa(page)
	}
	limit := 0
	if digits(limitParam, 4, false) {
		limit, _ = strconv.Atoi(limitParam)
	}
	if limit < 1 || limit > maxPage {
		return badRequest(ctx, fmt.Sprintf("limit must be 1 to %d", maxPage))
	}
	afterID, _ := strconv.ParseInt(after, 10, 64)
	// SQLite builds the whole answer as one JSON text, the page as in
	// notes-ts, so the rows cross from the host as one value and the text
	// goes out unparsed: a page of 1000 notes through encoding/json would not
	// fit in a turn's fuel. One row more than the page shows whether there is
	// a next page.
	rows, err := ctx.SQL.Query(`WITH page AS (
         SELECT `+columns+` FROM notes WHERE id > ?1 ORDER BY id LIMIT ?2
       )
       SELECT json_object(
         'notes', json((SELECT json_group_array(
           json_object('id', id, 'title', title, 'body', body, 'created', created, 'token', token) ORDER BY id
         ) FROM (SELECT * FROM page ORDER BY id LIMIT ?3))),
         'next', CASE WHEN (SELECT count(*) FROM page) > ?3
           THEN (SELECT id FROM page ORDER BY id LIMIT 1 OFFSET ?3 - 1) END
       ) AS answer`, afterID, limit+1, limit)
	if err != nil {
		return kronik.Output{}, err
	}
	row, ok := rows.First()
	if !ok {
		return kronik.Output{}, errors.New("the page query returned no row")
	}
	answer, _ := row.Get("answer")
	text, isText := answer.(string)
	if !isText {
		return kronik.Output{}, fmt.Errorf("the page query returned %T, not text", answer)
	}
	return ctx.JSON(200, json.RawMessage(text))
}

func init() {
	kronik.Export(kronik.Actor{
		Kind:          "notes",
		SchemaVersion: 2,
		Routes: []kronik.Route{
			{Method: "POST", Pattern: "/notes/{key}"},
			{Method: "GET", Pattern: "/notes/{key}"},
			{Method: "GET", Pattern: "/notes/{key}/{id}"},
			{Method: "DELETE", Pattern: "/notes/{key}/{id}"},
		},

		Migrate: func(from uint32, ctx *kronik.Ctx) error {
			// Every step since from, in order. DDL is allowed only here, and
			// only before the first statement that changes data.
			if from < 1 {
				if _, err := ctx.SQL.Execute(`CREATE TABLE notes (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created TEXT NOT NULL,
        _subject TEXT DEFAULT (kronik_subject())
      )`); err != nil {
					return err
				}
			}
			if from < 2 {
				if _, err := ctx.SQL.Execute("ALTER TABLE notes ADD COLUMN token TEXT NOT NULL DEFAULT ''"); err != nil {
					return err
				}
			}
			return nil
		},

		HTTP: func(req *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
			// Rows written in this turn belong to the actor's user.
			ctx.Subject("user:" + ctx.Self().Key)
			idParam, ok := req.Param("id")
			if !ok {
				switch req.Method {
				case "POST":
					return create(req, ctx)
				case "GET":
					return list(req, ctx)
				}
				return ctx.Status(405)
			}
			if !digits(idParam, 18, true) {
				return ctx.Status(404)
			}
			id, _ := strconv.ParseInt(idParam, 10, 64)
			switch req.Method {
			case "GET":
				rows, err := ctx.SQL.Query("SELECT "+columns+" FROM notes WHERE id = ?1", id)
				if err != nil {
					return kronik.Output{}, err
				}
				if note, ok := rows.First(); ok {
					return ctx.JSON(200, note)
				}
				return ctx.Status(404)
			case "DELETE":
				n, err := ctx.SQL.Execute("DELETE FROM notes WHERE id = ?1", id)
				if err != nil {
					return kronik.Output{}, err
				}
				if n > 0 {
					return ctx.None()
				}
				return ctx.Status(404)
			}
			return ctx.Status(405)
		},
	})
}

func main() {}
