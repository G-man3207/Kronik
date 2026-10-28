package test

import (
	"reflect"
	"regexp"
	"testing"

	"kronik.dev/sdk/testkit"
)

type note struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
	Token string `json:"token"`
}

type page struct {
	Notes []note `json:"notes"`
	Next  *int   `json:"next"`
}

func titles(p page) []string {
	out := []string{}
	for _, n := range p.Notes {
		out = append(out, n.Title)
	}
	return out
}

func TestNotesAreCreatedListedAPageAtATimeAndDeleted(t *testing.T) {
	host := testkit.Start(t, testkit.Options{Dir: ".."})
	created := host.HTTP("POST", "/notes/alice", map[string]any{"title": " first ", "body": "hello"})
	if created.Status != 201 {
		t.Fatalf("create: %d %s", created.Status, created.Text())
	}
	var first note
	created.JSON(&first)
	if first.ID != 1 || first.Title != "first" || first.Body != "hello" {
		t.Fatalf("first %+v", first)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(first.Token) {
		t.Fatalf("token %q", first.Token)
	}
	for _, title := range []string{"second", "third"} {
		if res := host.HTTP("POST", "/notes/alice", map[string]any{"title": title}); res.Status != 201 {
			t.Fatalf("create %s: %d", title, res.Status)
		}
	}

	var p page
	host.HTTP("GET", "/notes/alice?limit=2", nil).JSON(&p)
	if !reflect.DeepEqual(titles(p), []string{"first", "second"}) || p.Next == nil || *p.Next != 2 {
		t.Fatalf("page %+v", p)
	}
	var last page
	host.HTTP("GET", "/notes/alice?after=2&limit=2", nil).JSON(&last)
	if !reflect.DeepEqual(titles(last), []string{"third"}) || last.Next != nil {
		t.Fatalf("last page %+v", last)
	}

	for _, step := range []struct {
		method, path string
		status       int
	}{
		{"DELETE", "/notes/alice/2", 204},
		{"GET", "/notes/alice/2", 404},
		{"DELETE", "/notes/alice/2", 404},
	} {
		if res := host.HTTP(step.method, step.path, nil); res.Status != step.status {
			t.Fatalf("%s %s: %d, want %d", step.method, step.path, res.Status, step.status)
		}
	}
	var third note
	host.HTTP("GET", "/notes/alice/3", nil).JSON(&third)
	if third.Title != "third" {
		t.Fatalf("note 3 %+v", third)
	}
}

func TestInvalidNotesAndPagesAreRefused(t *testing.T) {
	host := testkit.Start(t, testkit.Options{Dir: ".."})
	for _, step := range []struct {
		method, path string
		body         any
		status       int
	}{
		{"POST", "/notes/bob", "not json", 400},
		{"POST", "/notes/bob", map[string]any{"title": ""}, 400},
		{"POST", "/notes/bob", map[string]any{"title": "x", "body": 5}, 400},
		{"GET", "/notes/bob?limit=0", nil, 400},
		{"GET", "/notes/bob?after=x", nil, 400},
		{"GET", "/notes/bob/abc", nil, 404},
	} {
		if res := host.HTTP(step.method, step.path, step.body); res.Status != step.status {
			t.Fatalf("%s %s: %d, want %d (%s)", step.method, step.path, res.Status, step.status, res.Text())
		}
	}
	// Notes belong to their actor's user: bob has none of alice's.
	if got := host.HTTP("GET", "/notes/bob", nil).Text(); got != `{"notes":[],"next":null}` {
		t.Fatalf("bob's notes %s", got)
	}
}
