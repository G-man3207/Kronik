// HTTP for actors: the incoming request, outgoing requests and their
// responses, messages and secret handles. No host calls here.

package kronik

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"unicode/utf8"

	"go.bytecodealliance.org/cm"
	httpclient "kronik.dev/sdk/internal/wit/kronik/actor/http-client"
	"kronik.dev/sdk/internal/wit/kronik/actor/types"
)

// ActorRef names an actor: its kind and its key.
type ActorRef struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

// String is the actor as "kind/key".
func (a ActorRef) String() string { return a.Kind + "/" + a.Key }

// toJSON is v as JSON text, without HTML escaping (as JSON.stringify and
// the other SDKs write it).
func toJSON(v any) ([]byte, error) {
	// JSON text made elsewhere (by SQLite, say) is written as it is: encoding
	// it again would cost a scan of every byte, in fuel.
	if raw, ok := v.(json.RawMessage); ok {
		return raw, nil
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, newError("json", "the value cannot be written as JSON", err.Error(), "message", nil)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}

// encodeBody encodes a body: nil as nothing, []byte as it is, a string as
// UTF-8 text, anything else as JSON; with the content type that follows.
func encodeBody(body any) ([]byte, string, error) {
	switch b := body.(type) {
	case nil:
		return nil, "", nil
	case []byte:
		return b, "application/octet-stream", nil
	case string:
		return []byte(b), "text/plain; charset=utf-8", nil
	}
	j, err := toJSON(body)
	return j, "application/json", err
}

func decodeText(b []byte, what, topic string) (string, error) {
	if !utf8.Valid(b) {
		return "", newError("utf8", what+" is not UTF-8", "", topic, nil)
	}
	return string(b), nil
}

func decodeJSON(b []byte, v any, what, topic string) error {
	if _, err := decodeText(b, what, topic); err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return newError("json", what+" is not the expected JSON", err.Error(), topic, nil)
	}
	return nil
}

func inline(body types.HTTPBody) []byte {
	if b := body.Inline(); b != nil {
		return b.Slice()
	}
	return nil
}

// Header is an HTTP header.
type Header struct {
	Name  string
	Value string
}

// Request is an HTTP request routed to the actor by one of its routes.
type Request struct {
	Method string
	Path   string
	// Query is the raw query string, without "?".
	Query string
	// Params are the route parameters, such as "key" for /notes/{key}.
	Params  map[string]string
	Headers []Header
	// Body is the body's bytes (inline; a blob body, from M25, is empty here).
	Body []byte
}

func newRequest(req *types.HTTPRequest) *Request {
	r := &Request{Method: req.Method, Path: req.Path, Query: req.Query, Params: map[string]string{}, Body: inline(req.Body)}
	for _, p := range req.Params.Slice() {
		r.Params[p[0]] = p[1]
	}
	for _, h := range req.Headers.Slice() {
		r.Headers = append(r.Headers, Header{Name: h.Name, Value: h.Value})
	}
	return r
}

// Param returns the route parameter name.
func (r *Request) Param(name string) (string, bool) {
	v, ok := r.Params[name]
	return v, ok
}

// QueryParam returns the first query parameter called name, decoded.
func (r *Request) QueryParam(name string) (string, bool) {
	values, err := url.ParseQuery(r.Query)
	if err != nil && values == nil {
		return "", false
	}
	v, ok := values[name]
	if !ok || len(v) == 0 {
		return "", false
	}
	return v[0], true
}

// Header returns the first header called name, ignoring case.
func (r *Request) Header(name string) (string, bool) {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

// Text returns the body as UTF-8 text.
func (r *Request) Text() (string, error) { return decodeText(r.Body, "the request body", "message") }

// JSON parses the body as JSON into v.
func (r *Request) JSON(v any) error { return decodeJSON(r.Body, v, "the request body", "message") }

// Message is a message from another actor or the operator.
type Message struct {
	Name        string
	ContentType string
	Body        []byte
	// Sender is the sending actor, if an actor sent it.
	Sender *ActorRef
}

func newMessage(msg *types.Message, sender *types.ActorRef) *Message {
	m := &Message{Name: msg.Name, ContentType: msg.ContentType, Body: msg.Body.Slice()}
	if sender != nil {
		m.Sender = &ActorRef{Kind: sender.Kind, Key: sender.Key}
	}
	return m
}

// Text returns the body as UTF-8 text.
func (m *Message) Text() (string, error) { return decodeText(m.Body, "the message body", "message") }

// JSON parses the body as JSON into v.
func (m *Message) JSON(v any) error { return decodeJSON(m.Body, v, "the message body", "message") }

// OutgoingMessage is a message to send: a name and a body (nil, []byte,
// a string as text, or any other value as JSON).
type OutgoingMessage struct {
	Name string
	Body any
	// ContentType overrides the content type that follows from the body.
	ContentType string
}

func (m OutgoingMessage) wit() (types.Message, error) {
	body, contentType, err := encodeBody(m.Body)
	if err != nil {
		return types.Message{}, err
	}
	if m.ContentType != "" {
		contentType = m.ContentType
	}
	return types.Message{Name: m.Name, ContentType: contentType, Body: cm.ToList(body)}, nil
}

// Secret is a handle to a secret: its name, never its value (see `kronik
// explain secret-handle`). The host inserts the value at the effect boundary.
type Secret struct{ Name string }

// Header is a header value the host makes from this secret: "{}" in
// template is replaced by the value; "" means "Bearer {}".
func (s Secret) Header(template string) *SecretHeader {
	if template == "" {
		template = "Bearer {}"
	}
	return &SecretHeader{Secret: s.Name, Template: template}
}

// SecretHeader is a header value made from a secret by the host; see
// [Secret.Header].
type SecretHeader struct {
	Secret   string
	Template string
}

// FetchHeader is a header of an outgoing request: Value, or the value the
// host makes from a secret if Secret is set.
type FetchHeader struct {
	Name   string
	Value  string
	Secret *SecretHeader
}

// FetchRequest is an outgoing request for ctx.HTTP.Fetch.
type FetchRequest struct {
	// Method defaults to GET.
	Method  string
	URL     string
	Headers []FetchHeader
	// Body is nil, []byte, a string as text, or a value sent as JSON (which
	// also sets content-type).
	Body any
}

func (req *FetchRequest) wit() (httpclient.Request, error) {
	var headers []httpclient.RequestHeader
	hasContentType := false
	for _, h := range req.Headers {
		hasContentType = hasContentType || strings.EqualFold(h.Name, "content-type")
		value := httpclient.HeaderValueText(h.Value)
		if h.Secret != nil {
			value = httpclient.HeaderValueSecret(httpclient.SecretTemplate{Name: h.Secret.Secret, Template: h.Secret.Template})
		}
		headers = append(headers, httpclient.RequestHeader{Name: h.Name, Value: value})
	}
	body, contentType, err := encodeBody(req.Body)
	if err != nil {
		return httpclient.Request{}, err
	}
	if req.Body != nil && !hasContentType {
		headers = append(headers, httpclient.RequestHeader{Name: "content-type", Value: httpclient.HeaderValueText(contentType)})
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	return httpclient.Request{Method: method, URL: req.URL, Headers: list(headers), Body: types.HTTPBodyInline(cm.ToList(body))}, nil
}

// FetchResponse is the response to ctx.HTTP.Fetch.
type FetchResponse struct {
	Status  int
	Headers [][2]string
	Body    []byte
}

// OK reports whether the status is 2xx.
func (r *FetchResponse) OK() bool { return r.Status >= 200 && r.Status < 300 }

// Header returns the first header called name, ignoring case.
func (r *FetchResponse) Header(name string) (string, bool) {
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1], true
		}
	}
	return "", false
}

// Text returns the body as UTF-8 text.
func (r *FetchResponse) Text() (string, error) {
	return decodeText(r.Body, "the response body", "effect")
}

// JSON parses the body as JSON into v.
func (r *FetchResponse) JSON(v any) error {
	return decodeJSON(r.Body, v, "the response body", "effect")
}
