// Unit tests for the parts of the SDK that make no host calls: go test .

package kronik

import (
	"reflect"
	"strings"
	"testing"

	"go.bytecodealliance.org/cm"
	httpclient "kronik.dev/sdk/internal/wit/kronik/actor/http-client"
	"kronik.dev/sdk/internal/wit/kronik/actor/sql"
	"kronik.dev/sdk/internal/wit/kronik/actor/types"
)

func TestExplainTopic(t *testing.T) {
	for msg, want := range map[string]string{
		"CAPABILITY_NOT_GRANTED: http:api.example.com": "CAPABILITY_NOT_GRANTED",
		"DDL is only allowed in migrate":               "fallback",
		"http: bad url":                                "fallback",
		"":                                             "fallback",
	} {
		if got := explainTopic(msg, "fallback"); got != want {
			t.Errorf("explainTopic(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestHostErrors(t *testing.T) {
	denied := hostError("fetch", "denied", "CAPABILITY_NOT_GRANTED: http:x.example", nil)
	if denied.Kind != "fetch.denied" || denied.Error() != "HTTP request denied: CAPABILITY_NOT_GRANTED: http:x.example (see `kronik explain CAPABILITY_NOT_GRANTED`)" {
		t.Errorf("denied: %q %q", denied.Kind, denied.Error())
	}
	e := sql.SQLErrorTooLarge()
	if got := sqlError(&e).Error(); got != "SQL value or database over its size limit (see `kronik explain sql-state`)" {
		t.Errorf("too-large: %q", got)
	}
	if got := hostError("call", "not-found", "", nil).Topic; got != "ACTOR_NOT_FOUND" {
		t.Errorf("not-found topic %q", got)
	}
	if got := revealError("CAPABILITY_NOT_GRANTED: secret-reveal:stripe").Error(); got != "revealing the secret failed: CAPABILITY_NOT_GRANTED: secret-reveal:stripe (see `kronik explain CAPABILITY_NOT_GRANTED`)" {
		t.Errorf("reveal: %q", got)
	}
	if got := hostError("crypto", "boom", "", nil).Error(); got != "crypto failed: boom (see `kronik explain effect`)" {
		t.Errorf("unknown: %q", got)
	}
	if !IsRejected(Rejected("no")) || IsRejected(denied) {
		t.Error("IsRejected")
	}
}

func TestSQLValues(t *testing.T) {
	params := []any{nil, true, 7, int64(-3), uint8(2), 2.5, "t", []byte{1}}
	want := []sql.SQLValue{
		sql.SQLValueNull(), sql.SQLValueInteger(1), sql.SQLValueInteger(7), sql.SQLValueInteger(-3),
		sql.SQLValueInteger(2), sql.SQLValueReal(2.5), sql.SQLValueText("t"), sql.SQLValueBlob(cm.ToList([]byte{1})),
	}
	for i, p := range params {
		got, err := toSQL(p)
		if err != nil || got.String() != want[i].String() || !reflect.DeepEqual(fromSQL(got), fromSQL(want[i])) {
			t.Errorf("toSQL(%#v) = %v, %v", p, got, err)
		}
	}
	for _, bad := range []any{struct{}{}, uint64(1) << 63} {
		if _, err := toSQL(bad); err == nil || !strings.Contains(err.Error(), "not a SQL parameter") || !strings.Contains(err.Error(), "kronik explain sql-state") {
			t.Errorf("toSQL(%#v): %v", bad, err)
		}
	}
	rows := &SQLRows{Columns: []string{"id", "title", "done"}, raw: []cm.List[sql.SQLValue]{
		cm.ToList([]sql.SQLValue{sql.SQLValueInteger(1), sql.SQLValueText("milk"), sql.SQLValueNull()}),
		cm.ToList([]sql.SQLValue{sql.SQLValueInteger(2), sql.SQLValueText("eggs"), sql.SQLValueInteger(1)}),
	}}
	if rows.Len() != 2 {
		t.Fatal("Len")
	}
	first, ok := rows.First()
	j, err := toJSON(first)
	if !ok || err != nil || string(j) != `{"id":1,"title":"milk","done":null}` {
		t.Errorf("first row %s %v", j, err)
	}
	if v, ok := rows.Rows()[1].Get("title"); !ok || v != "eggs" {
		t.Errorf("Get title = %v", v)
	}
}

func TestHasOrderBy(t *testing.T) {
	for _, s := range []string{"SELECT * FROM notes ORDER BY id", "select id from notes order\n by created desc", "SELECT id FROM t ORDER /* c */ BY id"} {
		if !hasOrderBy(s) {
			t.Errorf("no ORDER BY found in %q", s)
		}
	}
	for _, s := range []string{"SELECT * FROM notes", "SELECT * FROM notes WHERE title = 'order by'", `SELECT "order", by FROM t`,
		"SELECT x FROM t -- ORDER BY x", "SELECT x FROM t /* ORDER BY x */", "SELECT recorder, bypass FROM t", "SELECT [order] by"} {
		if hasOrderBy(s) {
			t.Errorf("ORDER BY found in %q", s)
		}
	}
}

func TestBodiesAndRequests(t *testing.T) {
	if _, ct, _ := encodeBody("hi"); ct != "text/plain; charset=utf-8" {
		t.Error(ct)
	}
	if b, ct, _ := encodeBody(map[string]string{"a": "<&>"}); ct != "application/json" || string(b) != `{"a":"<&>"}` {
		t.Error(ct, string(b))
	}
	var v any
	if err := decodeJSON([]byte("{"), &v, "the body", "message"); err == nil || !strings.Contains(err.Error(), "the body is not the expected JSON") || !strings.HasSuffix(err.Error(), "(see `kronik explain message`)") {
		t.Errorf("bad JSON: %v", err)
	}
	req := newRequest(&types.HTTPRequest{
		Method: "GET", Path: "/notes/alice", Query: "after=7&q=a+b%2Fc",
		Params:  cm.ToList([][2]string{{"key", "alice"}}),
		Headers: cm.ToList([]types.Header{{Name: "Content-Type", Value: "application/json"}}),
		Body:    types.HTTPBodyInline(cm.ToList([]byte(`{"x":1}`))),
	})
	if k, _ := req.Param("key"); k != "alice" {
		t.Error("param")
	}
	if a, _ := req.QueryParam("after"); a != "7" {
		t.Error("after")
	}
	if q, _ := req.QueryParam("q"); q != "a b/c" {
		t.Error("q", q)
	}
	if _, ok := req.QueryParam("nope"); ok {
		t.Error("nope")
	}
	if h, _ := req.Header("content-type"); h != "application/json" {
		t.Error("header")
	}
	var x struct{ X int }
	if err := req.JSON(&x); err != nil || x.X != 1 {
		t.Error("json", err)
	}
	out, err := (&FetchRequest{
		Method:  "POST",
		URL:     "https://api.example.com/charges",
		Headers: []FetchHeader{{Name: "authorization", Secret: Secret{"stripe"}.Header("")}},
		Body:    map[string]int{"amount": 100},
	}).wit()
	if err != nil {
		t.Fatal(err)
	}
	headers := out.Headers.Slice()
	if len(headers) != 2 || *headers[0].Value.Secret() != (httpclient.SecretTemplate{Name: "stripe", Template: "Bearer {}"}) ||
		headers[1].Name != "content-type" || *headers[1].Value.Text() != "application/json" {
		t.Errorf("headers %v", headers)
	}
	if string(out.Body.Inline().Slice()) != `{"amount":100}` {
		t.Error("body")
	}
}

func TestDescribe(t *testing.T) {
	a := &Actor{Kind: "counter", SchemaVersion: 1, Routes: []Route{{"GET", "/c/{key}"}}}
	m := a.describe()
	if m.Kind != "counter" || m.SchemaVersion != 1 || m.Routes.Len() != 1 || m.Routes.Slice()[0].Pattern != "/c/{key}" || m.Capabilities.Len() != 0 {
		t.Errorf("manifest %+v", m)
	}
}

func TestHandleErrors(t *testing.T) {
	a := &Actor{Kind: "x", Message: func(m *Message, ctx *Ctx) (Output, error) {
		switch m.Name {
		case "reject":
			return Output{}, Rejected("no")
		case "panic":
			var p map[string]int
			p["x"] = 1
		}
		return Output{}, newError("json", "bad", "", "message", nil)
	}}
	for name, want := range map[string]string{
		"reject": "rejected(no)",
		"panic":  "failed(panic: assignment to entry in nil map)",
		"fail":   "failed(bad (see `kronik explain message`))",
	} {
		res := a.handle(types.InputMessage(types.Incoming{Msg: types.Message{Name: name}}))
		e := res.Err()
		if e == nil {
			t.Fatalf("%s: no error", name)
		}
		got := e.String()
		if s := e.Rejected(); s != nil {
			got += "(" + *s + ")"
		} else {
			got += "(" + *e.Failed() + ")"
		}
		if got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
}

func TestUnhandledInputIsRejected(t *testing.T) {
	res := (&Actor{Kind: "x"}).handle(types.InputHTTP(types.HTTPRequest{}))
	if e := res.Err(); e == nil || e.Rejected() == nil || *e.Rejected() != "actor type x does not handle HTTP requests: give the kronik.Actor an HTTP func (see `kronik explain actor`)" {
		t.Errorf("unhandled: %v", res)
	}
}
