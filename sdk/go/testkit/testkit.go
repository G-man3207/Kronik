// Package testkit tests Kronik actors with the host's `go test`. A
// [TestHost] runs the project's component in an in-memory Kronik node
// (`kronik test-host`): the real scheduler, runtime and effect gate, with a
// clock that moves only when the test advances it and outgoing HTTP
// answered by stubs and recorded.
//
//	func TestCounts(t *testing.T) {
//		host := testkit.Start(t, testkit.Options{Dir: ".."})
//		var got struct{ N int }
//		host.HTTP("POST", "/counter/alice/increment", nil).JSON(&got)
//		if got.N != 1 {
//			t.Fatalf("n = %d", got.N)
//		}
//	}
//
// Start builds the project as `kronik build` does, so tests run the code
// they see. The kronik binary comes from KRONIK_BIN or PATH. Every request
// waits until what it started has finished (messages delivered, timers that
// came due fired), so a test can check the outcome right after it. A failing
// request fails the test; the host stops when the test ends.
package testkit

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// Options say how to start a test host.
type Options struct {
	// Dir is the project to build and deploy; default the current directory.
	Dir string
	// NoDir deploys only Wasm, building no project.
	NoDir bool
	// Entries are the project's entries to build and deploy instead of the
	// default one: a second actor type, a variant (such as "./step2").
	Entries []string
	// Wasm are components that are already built, deployed as well.
	Wasm []string
	// Bin is the kronik binary; default KRONIK_BIN, else kronik on PATH.
	Bin string
	// Seed seeds the host's ids and guest randomness; default
	// KRONIK_TEST_SEED, else 0.
	Seed *uint64
}

// Header is an HTTP header as a name and a value.
type Header = [2]string

// Response is a response through the gateway.
type Response struct {
	Status  int
	Headers []Header
	Body    []byte
	// Turn is the id of the turn that answered, such as "main:5".
	Turn string
	t    testing.TB
}

// Header returns the first header called name, ignoring case.
func (r *Response) Header(name string) (string, bool) { return header(r.Headers, name) }

// Text returns the body as text.
func (r *Response) Text() string { return string(r.Body) }

// JSON parses the body as JSON into v; the test fails if it is not.
func (r *Response) JSON(v any) {
	r.t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		r.t.Fatalf("the response body is not the expected JSON (%v): %s", err, r.Body)
	}
}

// RecordedRequest is an outgoing request an actor made, as the target got
// it (with the secrets the host inserted).
type RecordedRequest struct {
	Method  string
	URL     string
	Headers []Header
	Body    []byte
}

// Header returns the first header called name, ignoring case.
func (r *RecordedRequest) Header(name string) (string, bool) { return header(r.Headers, name) }

// Stub answers the outgoing requests whose URL starts with URL. The newest
// stub that matches answers; a request no stub matches fails as if the
// connection were refused.
type Stub struct {
	URL string
	// Method limits the stub to requests with this method.
	Method string
	// Status defaults to 200.
	Status  int
	Headers []Header
	// Body is nil, []byte, a string as text, or any other value as JSON.
	Body any
	// Error fails instead: "connect" (not sent) or "io" (may have arrived;
	// outcome unknown).
	Error string
	// Times answers only this many requests (0: all of them).
	Times uint32
}

// APIAnswer is an answer of the daemon's API: the status and the JSON body.
type APIAnswer struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// TestHost is an in-memory node running the components under test.
type TestHost struct {
	t     testing.TB
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bufio.Reader
}

// Start builds the project (or takes built components), starts a test host
// with them deployed and stops it when the test ends.
func Start(t testing.TB, opts ...Options) *TestHost {
	t.Helper()
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	bin := o.Bin
	if bin == "" {
		bin = os.Getenv("KRONIK_BIN")
	}
	if bin == "" {
		bin = "kronik"
	}
	args := []string{"test-host"}
	if !o.NoDir {
		dir := o.Dir
		if dir == "" {
			dir = "."
		}
		args = append(args, "--dir", dir)
		for _, e := range o.Entries {
			args = append(args, "--entry", e)
		}
	}
	for _, w := range o.Wasm {
		args = append(args, "--wasm", w)
	}
	seed := os.Getenv("KRONIK_TEST_SEED")
	if o.Seed != nil {
		seed = strconv.FormatUint(*o.Seed, 10)
	}
	if seed != "" {
		args = append(args, "--seed", seed)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", bin, err)
	}
	h := &TestHost{t: t, cmd: cmd, stdin: stdin, out: bufio.NewReader(stdout)}
	t.Cleanup(h.Close)
	h.next(nil)
	return h
}

// next reads the next answer into v (if not nil); the test fails if it is
// not ok.
func (h *TestHost) next(v any) {
	h.t.Helper()
	line, err := h.out.ReadBytes('\n')
	if err != nil {
		h.t.Fatalf("the test host exited (%v); its errors are above, on stderr", err)
	}
	var status struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(line, &status); err != nil {
		h.t.Fatalf("the test host's answer is not JSON: %s", line)
	}
	if !status.OK {
		h.t.Fatalf("test host: %s", status.Error)
	}
	if v != nil {
		if err := json.Unmarshal(line, v); err != nil {
			h.t.Fatalf("the test host's answer is not the expected JSON (%v): %s", err, line)
		}
	}
}

func (h *TestHost) call(request map[string]any, v any) {
	h.t.Helper()
	line, err := json.Marshal(request)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.stdin.Write(append(line, '\n')); err != nil {
		h.t.Fatalf("writing to the test host: %v", err)
	}
	h.next(v)
}

// wireBody sets the wire fields for body: text if it is a string, base64
// for bytes, else JSON; it reports whether it is JSON.
func wireBody(h *TestHost, request map[string]any, body any) bool {
	switch b := body.(type) {
	case nil:
		return false
	case string:
		request["body"] = b
		return false
	case []byte:
		request["body_base64"] = base64.StdEncoding.EncodeToString(b)
		return false
	}
	j, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	request["body"] = string(j)
	return true
}

type wire struct {
	Body       *string `json:"body"`
	BodyBase64 *string `json:"body_base64"`
}

func (w wire) bytes(t testing.TB) []byte {
	if w.BodyBase64 != nil {
		b, err := base64.StdEncoding.DecodeString(*w.BodyBase64)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if w.Body != nil {
		return []byte(*w.Body)
	}
	return []byte{}
}

func withContentType(headers []Header, isJSON bool) []Header {
	out := append([]Header{}, headers...)
	if _, ok := header(out, "content-type"); isJSON && !ok {
		out = append(out, Header{"content-type", "application/json"})
	}
	return out
}

func header(headers []Header, name string) (string, bool) {
	for _, h := range headers {
		if strings.EqualFold(h[0], name) {
			return h[1], true
		}
	}
	return "", false
}

// HTTP sends an HTTP request through the gateway, as a client would. body is
// nil, []byte, a string as text, or any other value as JSON (with
// content-type application/json unless headers set one).
func (h *TestHost) HTTP(method, path string, body any, headers ...Header) *Response {
	h.t.Helper()
	request := map[string]any{"op": "http", "method": method, "path": path}
	request["headers"] = withContentType(headers, wireBody(h, request, body))
	var answer struct {
		wire
		Status  int      `json:"status"`
		Headers []Header `json:"headers"`
		Turn    *string  `json:"turn"`
	}
	h.call(request, &answer)
	res := &Response{Status: answer.Status, Headers: answer.Headers, Body: answer.bytes(h.t), t: h.t}
	if answer.Turn != nil {
		res.Turn = *answer.Turn
	}
	return res
}

// Send sends the message name with a text body to actor ("kind/key") as the
// operator and returns the API's answer (outcome, reply, turn_id).
func (h *TestHost) Send(actor, name, body string) json.RawMessage {
	h.t.Helper()
	return h.api("POST", "/v1/actors/"+actor+"/messages", map[string]any{"name": name, "text": body, "reason": "test"})
}

// SendReply sends like [TestHost.Send] and returns the reply's text.
func (h *TestHost) SendReply(actor, name, body string) string {
	h.t.Helper()
	var answer struct {
		Reply *struct {
			Text string `json:"text"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(h.Send(actor, name, body), &answer); err != nil || answer.Reply == nil {
		h.t.Fatalf("sending %s to %s gave no reply", name, actor)
	}
	return answer.Reply.Text
}

// Advance moves the clock forward by ms and runs the timers that came due;
// it returns the new time in ms since the Unix epoch.
func (h *TestHost) Advance(ms uint64) int64 {
	h.t.Helper()
	var answer struct {
		NowMs int64 `json:"now_ms"`
	}
	h.call(map[string]any{"op": "advance", "ms": ms}, &answer)
	return answer.NowMs
}

// Stub adds a stub for outgoing HTTP.
func (h *TestHost) Stub(s Stub) {
	h.t.Helper()
	request := map[string]any{"op": "stub", "url": s.URL, "status": 200}
	if s.Status != 0 {
		request["status"] = s.Status
	}
	request["headers"] = withContentType(s.Headers, wireBody(h, request, s.Body))
	if s.Method != "" {
		request["method"] = s.Method
	}
	if s.Error != "" {
		request["error"] = s.Error
	}
	if s.Times != 0 {
		request["times"] = s.Times
	}
	h.call(request, nil)
}

// Requests returns the outgoing requests the actors made so far, oldest
// first; clear forgets them.
func (h *TestHost) Requests(clear bool) []RecordedRequest {
	h.t.Helper()
	var answer struct {
		Requests []struct {
			wire
			Method  string   `json:"method"`
			URL     string   `json:"url"`
			Headers []Header `json:"headers"`
		} `json:"requests"`
	}
	h.call(map[string]any{"op": "requests", "clear": clear}, &answer)
	out := make([]RecordedRequest, len(answer.Requests))
	for i, r := range answer.Requests {
		out[i] = RecordedRequest{Method: r.Method, URL: r.URL, Headers: r.Headers, Body: r.bytes(h.t)}
	}
	return out
}

// Grant grants the actor type kind a capability, such as
// "http:api.example.com" or "secret:stripe". http: grants need a delivery:
// "idempotency-keyed", "at-most-once" or "unsafe"; "" for none.
func (h *TestHost) Grant(kind, capability, delivery string) {
	h.t.Helper()
	body := map[string]any{"kind": kind, "capability": capability, "reason": "test"}
	if delivery != "" {
		body["delivery"] = delivery
	}
	h.api("POST", "/v1/grants", body)
}

// Secret sets the secret name.
func (h *TestHost) Secret(name, value string) {
	h.t.Helper()
	h.api("PUT", "/v1/secrets/"+name, map[string]any{"text": value, "reason": "test"})
}

// State returns the key-value state of actor ("kind/key").
func (h *TestHost) State(actor string) map[string][]byte {
	h.t.Helper()
	var answer struct {
		State []struct {
			Key    string `json:"key"`
			Base64 string `json:"base64"`
		} `json:"state"`
	}
	if err := json.Unmarshal(h.api("GET", "/v1/actors/"+actor, nil), &answer); err != nil {
		h.t.Fatal(err)
	}
	state := make(map[string][]byte, len(answer.State))
	for _, e := range answer.State {
		b, err := base64.StdEncoding.DecodeString(e.Base64)
		if err != nil {
			h.t.Fatal(err)
		}
		state[e.Key] = b
	}
	return state
}

// StateJSON parses the state value key of actor as JSON into v and reports
// whether there is one.
func (h *TestHost) StateJSON(actor, key string, v any) bool {
	h.t.Helper()
	b, ok := h.State(actor)[key]
	if !ok {
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		h.t.Fatalf("state value %q of %s is not the expected JSON (%v): %s", key, actor, err, b)
	}
	return true
}

// API sends any request to the daemon's API, as kronik sends it over its
// socket (/v1/...); body (if not nil) is sent as JSON.
func (h *TestHost) API(method, path string, body any) APIAnswer {
	h.t.Helper()
	request := map[string]any{"op": "api", "method": method, "path": path}
	if body != nil {
		request["body"] = body
	}
	var answer APIAnswer
	h.call(request, &answer)
	return answer
}

func (h *TestHost) api(method, path string, body any) json.RawMessage {
	h.t.Helper()
	answer := h.API(method, path, body)
	if answer.Status != 200 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(answer.Body, &e)
		code, msg := e.Error.Code, e.Error.Message
		if code == "" {
			code = fmt.Sprintf("HTTP %d", answer.Status)
		}
		if msg == "" {
			msg = "the request failed"
		}
		h.t.Fatalf("%s %s: %s: %s", method, path, code, msg)
	}
	return answer.Body
}

// Close stops the test host; Start arranges it for the test's end.
func (h *TestHost) Close() {
	if h.stdin == nil {
		return
	}
	_ = h.stdin.Close()
	h.stdin = nil
	_ = h.cmd.Wait()
}
