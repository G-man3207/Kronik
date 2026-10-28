// The turn's access to the host. Every method is a synchronous host call.

package kronik

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.bytecodealliance.org/cm"
	"kronik.dev/sdk/internal/wit/kronik/actor/context"
	"kronik.dev/sdk/internal/wit/kronik/actor/crypto"
	httpclient "kronik.dev/sdk/internal/wit/kronik/actor/http-client"
	"kronik.dev/sdk/internal/wit/kronik/actor/log"
	"kronik.dev/sdk/internal/wit/kronik/actor/messaging"
	"kronik.dev/sdk/internal/wit/kronik/actor/privacy"
	"kronik.dev/sdk/internal/wit/kronik/actor/secrets"
	"kronik.dev/sdk/internal/wit/kronik/actor/sql"
	"kronik.dev/sdk/internal/wit/kronik/actor/state"
	"kronik.dev/sdk/internal/wit/kronik/actor/timers"
	"kronik.dev/sdk/internal/wit/kronik/actor/types"
)

// Output is what a handler answers: build it with ctx.JSON, Text, Status,
// Reply or None.
type Output struct{ wit types.Output }

func parseActor(actor string) (types.ActorRef, error) {
	kind, key, ok := strings.Cut(actor, "/")
	if !ok || kind == "" || key == "" {
		return types.ActorRef{}, newError("actor", strconv.Quote(actor)+" is not an actor: expected kind/key", "", "actor", nil)
	}
	return types.ActorRef{Kind: kind, Key: key}, nil
}

func optional(s string) cm.Option[string] {
	if s == "" {
		return cm.None[string]()
	}
	return cm.Some(s)
}

// list is s as a cm.List, an empty one with a null pointer: TinyGo's pointer
// for an empty allocation need not be aligned for T, and the host checks.
func list[T any](s []T) cm.List[T] {
	if len(s) == 0 {
		return cm.List[T]{}
	}
	return cm.ToList(s)
}

// State is the actor's key-value state. Writes apply only if the turn commits.
type State struct{}

// Get returns the value of key.
func (State) Get(key string) ([]byte, bool) {
	v := state.Get(key)
	if v.None() {
		return nil, false
	}
	return v.Some().Slice(), true
}

// GetText returns the value of key as UTF-8 text.
func (s State) GetText(key string) (string, bool, error) {
	v, ok := s.Get(key)
	if !ok {
		return "", false, nil
	}
	text, err := decodeText(v, "state value "+strconv.Quote(key), "actor")
	return text, err == nil, err
}

// GetJSON parses the value of key as JSON into v; false if there is none.
func (s State) GetJSON(key string, v any) (bool, error) {
	b, ok := s.Get(key)
	if !ok {
		return false, nil
	}
	if err := decodeJSON(b, v, "state value "+strconv.Quote(key), "actor"); err != nil {
		return false, err
	}
	return true, nil
}

// Set sets key, tagged with the turn's default subject.
func (State) Set(key string, value []byte) { state.Set(key, cm.ToList(value)) }

// SetJSON sets key to v as JSON, tagged with the turn's default subject.
func (State) SetJSON(key string, v any) error {
	b, err := toJSON(v)
	if err == nil {
		state.Set(key, cm.ToList(b))
	}
	return err
}

// SetFor sets key tagged with subject ("" for no subject), whatever the
// turn's default subject is.
func (State) SetFor(subject, key string, value []byte) {
	state.SetFor(optional(subject), key, cm.ToList(value))
}

// Delete deletes key.
func (State) Delete(key string) { state.Delete(key) }

// Keys returns the keys that start with prefix.
func (State) Keys(prefix string) []string { return state.Keys(prefix).Slice() }

// SQL is the actor's own SQLite database (see `kronik explain sql-state`).
// DDL is allowed only in Migrate, before the first statement that changes
// data; datetime('now'), random() and randomblob() are deterministic, and
// kronik_subject() gives the turn's default subject.
type SQL struct{ log Log }

func sqlParams(params []any) (cm.List[sql.SQLValue], error) {
	values := make([]sql.SQLValue, len(params))
	for i, p := range params {
		v, err := toSQL(p)
		if err != nil {
			return cm.List[sql.SQLValue]{}, err
		}
		values[i] = v
	}
	return list(values), nil
}

func sqlError(e *sql.SQLError) *Error {
	detail := ""
	for _, s := range []*string{e.Syntax(), e.Constraint(), e.Denied()} {
		if s != nil {
			detail = *s
		}
	}
	return hostError("sql", e.String(), detail, *e)
}

// Query runs a query. A query without ORDER BY that returns several rows
// logs a warning: their order then depends on SQLite's plan.
func (s SQL) Query(statement string, params ...any) (*SQLRows, error) {
	values, err := sqlParams(params)
	if err != nil {
		return nil, err
	}
	res := sql.Query(statement, values)
	if res.IsErr() {
		return nil, sqlError(res.Err())
	}
	rows := res.OK()
	if rows.Values.Len() > 1 && !hasOrderBy(statement) {
		s.log.Warn("a query returned several rows without ORDER BY, so their order is not guaranteed (see `kronik explain sql-state`)",
			"rows", rows.Values.Len(), "statement", statement)
	}
	return &SQLRows{Columns: rows.Columns.Slice(), raw: rows.Values.Slice()}, nil
}

// Execute runs a statement that returns no rows and returns how many rows
// it changed.
func (SQL) Execute(statement string, params ...any) (uint64, error) {
	values, err := sqlParams(params)
	if err != nil {
		return 0, err
	}
	res := sql.Execute(statement, values)
	if res.IsErr() {
		return 0, sqlError(res.Err())
	}
	return *res.OK(), nil
}

// HTTP is outgoing HTTP, recorded as effects (see `kronik explain effect`).
// It needs the capability http:<host>.
type HTTP struct{}

// Fetch sends req and waits for the response.
func (HTTP) Fetch(req FetchRequest) (*FetchResponse, error) {
	wit, err := req.wit()
	if err != nil {
		return nil, err
	}
	res := httpclient.Fetch(wit)
	if res.IsErr() {
		e := res.Err()
		detail := ""
		for _, s := range []*string{e.Denied(), e.Network()} {
			if s != nil {
				detail = *s
			}
		}
		return nil, hostError("fetch", e.String(), detail, *e)
	}
	r := res.OK()
	return &FetchResponse{Status: int(r.Status), Headers: r.Headers.Slice(), Body: inline(r.Body)}, nil
}

// Crypto is crypto computed by the host with a secret's value; it needs the
// capability secret:<name>.
type Crypto struct{}

func cryptoResult(res cm.Result[crypto.CryptoErrorShape, cm.List[uint8], crypto.CryptoError]) ([]byte, error) {
	if res.IsErr() {
		e := res.Err()
		detail := ""
		for _, s := range []*string{e.Denied(), e.Unsupported()} {
			if s != nil {
				detail = *s
			}
		}
		return nil, hostError("crypto", e.String(), detail, *e)
	}
	return res.OK().Slice(), nil
}

// HMACSHA256 is the HMAC-SHA256 of data keyed with secret.
func (Crypto) HMACSHA256(secret Secret, data []byte) ([]byte, error) {
	return cryptoResult(crypto.HmacSha256(secret.Name, cm.ToList(data)))
}

// SignEd25519 is an Ed25519 signature of data with the private key secret.
func (Crypto) SignEd25519(secret Secret, data []byte) ([]byte, error) {
	return cryptoResult(crypto.SignEd25519(secret.Name, cm.ToList(data)))
}

// Secrets reveals secrets: the exception path, behind the capability
// secret-reveal:<name>.
type Secrets struct{}

// Reveal returns the value of secret inside the guest. Prefer secret
// headers and ctx.Crypto.
func (Secrets) Reveal(secret Secret) (string, error) {
	res := secrets.Reveal(secret.Name)
	if res.IsErr() {
		return "", revealError(*res.Err())
	}
	return *res.OK(), nil
}

// Timers deliver a message to this actor later. They are registered only if
// the turn commits.
type Timers struct{}

// Schedule schedules msg to arrive as a timer input after delay (whole
// milliseconds, at least 0) and returns the timer's id.
func (Timers) Schedule(delay time.Duration, msg OutgoingMessage) (uint64, error) {
	m, err := msg.wit()
	if err != nil {
		return 0, err
	}
	return timers.Schedule(uint64(max(0, delay.Milliseconds())), m), nil
}

// Cancel cancels the timer id and reports whether it was pending.
func (Timers) Cancel(id uint64) bool { return timers.Cancel(id) }

// Random is randomness from the turn's recorded seed: a replay gets the
// same values.
type Random struct{}

// Bytes returns n random bytes (at most 1 MiB).
func (Random) Bytes(n uint32) []byte { return context.RandomBytes(n).Slice() }

// U64 returns a random unsigned 64-bit integer.
func (Random) U64() uint64 { return binary.LittleEndian.Uint64(context.RandomBytes(8).Slice()) }

// Level is a log level.
type Level = log.Level

// The log levels.
const (
	LevelTrace = log.LevelTrace
	LevelDebug = log.LevelDebug
	LevelInfo  = log.LevelInfo
	LevelWarn  = log.LevelWarn
	LevelError = log.LevelError
)

// Log is the actor's log. The host adds the turn's ids to every event.
type Log struct{}

// Emit logs message at level with fields given as key-value pairs, as
// log/slog takes them: a string value as it is, any other as JSON.
func (Log) Emit(level Level, message string, fields ...any) {
	pairs := make([][2]string, 0, (len(fields)+1)/2)
	for i := 0; i < len(fields); i += 2 {
		key := fmt.Sprint(fields[i])
		value := "!MISSING"
		if i+1 < len(fields) {
			if s, ok := fields[i+1].(string); ok {
				value = s
			} else if j, err := toJSON(fields[i+1]); err == nil {
				value = string(j)
			} else {
				value = fmt.Sprint(fields[i+1])
			}
		}
		pairs = append(pairs, [2]string{key, value})
	}
	log.Emit(level, message, list(pairs))
}

// Trace logs at level trace; see [Log.Emit].
func (l Log) Trace(message string, fields ...any) { l.Emit(LevelTrace, message, fields...) }

// Debug logs at level debug; see [Log.Emit].
func (l Log) Debug(message string, fields ...any) { l.Emit(LevelDebug, message, fields...) }

// Info logs at level info; see [Log.Emit].
func (l Log) Info(message string, fields ...any) { l.Emit(LevelInfo, message, fields...) }

// Warn logs at level warn; see [Log.Emit].
func (l Log) Warn(message string, fields ...any) { l.Emit(LevelWarn, message, fields...) }

// Error logs at level error; see [Log.Emit].
func (l Log) Error(message string, fields ...any) { l.Emit(LevelError, message, fields...) }

// Ctx is a turn's access to the host: the names Kronik's SDKs share
// (State, SQL, Send, Call, HTTP.Fetch, Crypto, Timers, Now, Random,
// CausalID, Secret, Subject, Log) and helpers for outputs.
type Ctx struct {
	State   State
	SQL     SQL
	HTTP    HTTP
	Crypto  Crypto
	Secrets Secrets
	Timers  Timers
	Random  Random
	Log     Log
}

// Send sends msg to the actor to ("kind/key"): buffered, delivered exactly
// once, only if this turn commits.
func (*Ctx) Send(to string, msg OutgoingMessage) error {
	ref, err := parseActor(to)
	if err != nil {
		return err
	}
	m, err := msg.wit()
	if err != nil {
		return err
	}
	messaging.Send(ref, m)
	return nil
}

// Call calls the actor to ("kind/key") and waits for its reply (nil if it
// answered none). The callee commits its own turn now; if this turn fails
// afterwards, compensate (if not nil) is delivered to it once.
func (*Ctx) Call(to string, msg OutgoingMessage, compensate *OutgoingMessage) (*Message, error) {
	ref, err := parseActor(to)
	if err != nil {
		return nil, err
	}
	m, err := msg.wit()
	if err != nil {
		return nil, err
	}
	comp := cm.None[types.Message]()
	if compensate != nil {
		c, err := compensate.wit()
		if err != nil {
			return nil, err
		}
		comp = cm.Some(c)
	}
	res := messaging.Call(ref, m, comp)
	if res.IsErr() {
		e := res.Err()
		detail := ""
		for _, s := range []*string{e.Rejected(), e.Failed()} {
			if s != nil {
				detail = *s
			}
		}
		return nil, hostError("call", e.String(), detail, *e)
	}
	reply := res.OK().Some()
	if reply == nil {
		return nil, nil
	}
	return newMessage(reply, nil), nil
}

// Now is the turn's logical time: constant within the turn and recorded.
func (*Ctx) Now() time.Time { return time.UnixMilli(int64(context.NowMs())).UTC() }

// CausalID is the turn's correlation id, the same in production and in replay.
func (*Ctx) CausalID() string { return context.CausalID() }

// Self is this actor.
func (*Ctx) Self() ActorRef {
	r := context.SelfRef()
	return ActorRef{Kind: r.Kind, Key: r.Key}
}

// Secret is a handle to the secret name; its value never enters the guest.
func (*Ctx) Secret(name string) Secret { return Secret{Name: name} }

// Subject sets the default subject (such as "user:123") for values written
// from now on; "" for none.
func (*Ctx) Subject(subject string) { privacy.SetSubject(optional(subject)) }

// CurrentSubject is the current default subject, if there is one.
func (*Ctx) CurrentSubject() (string, bool) {
	s := privacy.CurrentSubject()
	if s.None() {
		return "", false
	}
	return *s.Some(), true
}

func httpOutput(status int, contentType string, body []byte) Output {
	var headers []types.Header
	if contentType != "" {
		headers = []types.Header{{Name: "content-type", Value: contentType}}
	}
	return Output{types.OutputHTTP(types.HTTPResponse{Status: uint16(status), Headers: list(headers), Body: types.HTTPBodyInline(cm.ToList(body))})}
}

// JSON is an HTTP response with v as a JSON body. A [json.RawMessage] is
// the body as it is, unchecked: JSON that SQLite built (json_object,
// json_group_array) reaches the client without a pass through
// encoding/json, which costs fuel for every byte.
func (*Ctx) JSON(status int, v any) (Output, error) {
	body, err := toJSON(v)
	if err != nil {
		return Output{}, err
	}
	return httpOutput(status, "application/json", body), nil
}

// Text is an HTTP response with a text body.
func (*Ctx) Text(status int, body string) (Output, error) {
	return httpOutput(status, "text/plain; charset=utf-8", []byte(body)), nil
}

// Status is an HTTP response with no body, such as 404.
func (*Ctx) Status(status int) (Output, error) { return httpOutput(status, "", nil), nil }

// Reply is a reply message (an HTTP request gets 200 with its body).
func (*Ctx) Reply(msg OutgoingMessage) (Output, error) {
	m, err := msg.wit()
	if err != nil {
		return Output{}, err
	}
	return Output{types.OutputReply(m)}, nil
}

// None is no output (an HTTP request gets 204).
func (*Ctx) None() (Output, error) { return Output{types.OutputNone()}, nil }
