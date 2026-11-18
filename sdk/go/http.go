// HTTP for actors: the incoming request, outgoing requests and their
// responses, messages and secret handles. No host calls here.

package kronik

import (
	"bytes"
	"encoding/json"
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

// BlobCallBytes is the most bytes one blob call moves: 1 MiB.
const BlobCallBytes = 1 << 20

// BlobFrameBytes is a blob's frame: the store reads and checks whole frames,
// and a read is charged for every frame it touches, so readers fetch whole
// frames.
const BlobFrameBytes = 1 << 16

// BlobRef is a blob: a large body kept outside the log and named by its
// hash (see `kronik explain blob`). A handler gets one from req.Blob() or
// res.Blob(), in a message's Blobs, or from ctx.Blobs.Writer().Finish() or
// ctx.Blobs.Put, and may use it in the turn that got it: read it
// (ctx.Blobs), answer with it (BlobResponse), send it
// (FetchRequest.BodyBlob, OutgoingMessage.Blobs), or hold it for later turns
// (ctx.Blobs.Retain).
type BlobRef struct {
	// Hash is "b3:<hex>", or "b3s:<hex>" for a data subject's blob.
	Hash string
	// Size is the blob's size in bytes.
	Size uint64
}

func (b BlobRef) wit() types.BlobRef { return types.BlobRef{Hash: b.Hash, Size: b.Size} }

// blobReader reads a whole blob: a lazy body.
type blobReader func(BlobRef) ([]byte, error)

// splitBody is an HTTP body's inline bytes, or its blob.
func splitBody(body types.HTTPBody) ([]byte, *BlobRef) {
	if b := body.Blob(); b != nil {
		return nil, &BlobRef{Hash: b.Hash, Size: b.Size}
	}
	if b := body.Inline(); b != nil {
		return b.Slice(), nil
	}
	return nil, nil
}

// lazyBody is a body that may be a blob, read on first use.
type lazyBody struct {
	bytes []byte
	blob  *BlobRef
	read  blobReader
	done  bool
}

func newLazyBody(body types.HTTPBody, read blobReader) lazyBody {
	bytes, blob := splitBody(body)
	return lazyBody{bytes: bytes, blob: blob, read: read, done: blob == nil}
}

func (b *lazyBody) get(what string) ([]byte, error) {
	if b.done {
		return b.bytes, nil
	}
	if b.read == nil {
		return nil, newError("blob", what+" is a blob that this value cannot read", "", "blob", nil)
	}
	bytes, err := b.read(*b.blob)
	if err != nil {
		return nil, err
	}
	b.bytes, b.done = bytes, true
	return bytes, nil
}

func (b *lazyBody) blobRef() (BlobRef, bool) {
	if b.blob == nil {
		return BlobRef{}, false
	}
	return *b.blob, true
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
	body    lazyBody
}

func newRequest(req *types.HTTPRequest, read blobReader) *Request {
	r := &Request{Method: req.Method, Path: req.Path, Query: req.Query, Params: map[string]string{}, body: newLazyBody(req.Body, read)}
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

// QueryParam returns the first query parameter called name, percent-decoded
// (`+` is a space). A malformed `%` stays as it is and `;` is data, not a
// separator. Missing if it is absent or not UTF-8 after decoding.
// Not net/url.ParseQuery: that splits on `;` and drops a malformed `%`.
func (r *Request) QueryParam(name string) (string, bool) {
	for _, pair := range strings.Split(r.Query, "&") {
		rawName, rawValue, _ := strings.Cut(pair, "=")
		decoded, ok := percentDecode(rawName)
		if !ok || decoded != name {
			continue
		}
		return percentDecode(rawValue)
	}
	return "", false
}

// percentDecode decodes `%XX` and `+` (a space) in one query component.
// A malformed `%` stays. ok is false when the result is not UTF-8.
func percentDecode(s string) (string, bool) {
	in := []byte(s)
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		switch in[i] {
		case '+':
			out = append(out, ' ')
		case '%':
			if i+2 < len(in) {
				hi, okHi := unhex(in[i+1])
				lo, okLo := unhex(in[i+2])
				if okHi && okLo {
					out = append(out, hi<<4|lo)
					i += 2
					continue
				}
			}
			out = append(out, '%')
		default:
			out = append(out, in[i])
		}
	}
	if !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

func unhex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
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
func (r *Request) Text() (string, error) {
	body, err := r.Body()
	if err != nil {
		return "", err
	}
	return decodeText(body, "the request body", "message")
}

// JSON parses the body as JSON into v.
func (r *Request) JSON(v any) error {
	body, err := r.Body()
	if err != nil {
		return err
	}
	return decodeJSON(body, v, "the request body", "message")
}

// Body returns the body's bytes. A blob body is read on first use, whole,
// within the guest's memory limit (64 MiB by default); read a larger one in
// parts with ctx.Blobs.Reader.
func (r *Request) Body() ([]byte, error) { return r.body.get("the request body") }

// Blob returns the body's blob, when the gateway stored a large body as one.
func (r *Request) Blob() (BlobRef, bool) { return r.body.blobRef() }

// Message is a message from another actor or the operator.
type Message struct {
	Name        string
	ContentType string
	Body        []byte
	// Sender is the sending actor, if an actor sent it.
	Sender *ActorRef
	// Blobs are the blobs the message carries (M26): the turn may read
	// them, and holds one only if it retains it ([Blobs.Retain]).
	Blobs []BlobRef
}

func newMessage(msg *types.Message, sender *types.ActorRef) *Message {
	m := &Message{Name: msg.Name, ContentType: msg.ContentType, Body: msg.Body.Slice()}
	if sender != nil {
		m.Sender = &ActorRef{Kind: sender.Kind, Key: sender.Key}
	}
	for _, b := range msg.Blobs.Slice() {
		m.Blobs = append(m.Blobs, BlobRef{Hash: b.Hash, Size: b.Size})
	}
	return m
}

// Text returns the body as UTF-8 text.
func (m *Message) Text() (string, error) { return decodeText(m.Body, "the message body", "message") }

// JSON parses the body as JSON into v.
func (m *Message) JSON(v any) error { return decodeJSON(m.Body, v, "the message body", "message") }

// OutgoingMessage is a message to send, schedule or reply with: a name and
// a body (nil, []byte, a string as text, or any other value as JSON), and
// the blobs it carries.
type OutgoingMessage struct {
	Name string
	Body any
	// ContentType overrides the content type that follows from the body.
	ContentType string
	// Blobs travel with the message (M26), at most 256, each one the turn
	// may use. The receiving turn may read them, and holds one only if it
	// retains it.
	Blobs []BlobRef
}

func (m OutgoingMessage) wit() (types.Message, error) {
	body, contentType, err := encodeBody(m.Body)
	if err != nil {
		return types.Message{}, err
	}
	if m.ContentType != "" {
		contentType = m.ContentType
	}
	// Without blobs the list stays nil. An empty slice from make may point
	// anywhere (TinyGo gives zero-size allocations one shared address), and
	// the canonical ABI traps on a list pointer that is not aligned to its
	// elements, 8 bytes for blob-ref, even for an empty list.
	var blobs []types.BlobRef
	for _, b := range m.Blobs {
		blobs = append(blobs, b.wit())
	}
	return types.Message{Name: m.Name, ContentType: contentType, Body: cm.ToList(body), Blobs: cm.ToList(blobs)}, nil
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
	// BodyBlob, instead of Body, sends a blob, streamed from the blob store
	// (content-type application/octet-stream unless Headers set one).
	BodyBlob *BlobRef
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
	method := req.Method
	if method == "" {
		method = "GET"
	}
	if req.BodyBlob != nil {
		if req.Body != nil {
			return httpclient.Request{}, newError("fetch.body", "a request has a Body or a BodyBlob, not both", "", "blob", nil)
		}
		if !hasContentType {
			headers = append(headers, httpclient.RequestHeader{Name: "content-type", Value: httpclient.HeaderValueText("application/octet-stream")})
		}
		return httpclient.Request{Method: method, URL: req.URL, Headers: list(headers), Body: types.HTTPBodyBlob(req.BodyBlob.wit())}, nil
	}
	body, contentType, err := encodeBody(req.Body)
	if err != nil {
		return httpclient.Request{}, err
	}
	if req.Body != nil && !hasContentType {
		headers = append(headers, httpclient.RequestHeader{Name: "content-type", Value: httpclient.HeaderValueText(contentType)})
	}
	return httpclient.Request{Method: method, URL: req.URL, Headers: list(headers), Body: types.HTTPBodyInline(cm.ToList(body))}, nil
}

// FetchResponse is the response to ctx.HTTP.Fetch.
type FetchResponse struct {
	Status  int
	Headers [][2]string
	body    lazyBody
}

func newFetchResponse(status int, headers [][2]string, body types.HTTPBody, read blobReader) *FetchResponse {
	return &FetchResponse{Status: status, Headers: headers, body: newLazyBody(body, read)}
}

// Body returns the body's bytes. A blob body is read on first use, whole,
// within the guest's memory limit; read a larger one with ctx.Blobs.Reader.
func (r *FetchResponse) Body() ([]byte, error) { return r.body.get("the response body") }

// Blob returns the body's blob, when the host stored a large response as one.
func (r *FetchResponse) Blob() (BlobRef, bool) { return r.body.blobRef() }

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
	body, err := r.Body()
	if err != nil {
		return "", err
	}
	return decodeText(body, "the response body", "effect")
}

// JSON parses the body as JSON into v.
func (r *FetchResponse) JSON(v any) error {
	body, err := r.Body()
	if err != nil {
		return err
	}
	return decodeJSON(body, v, "the response body", "effect")
}
