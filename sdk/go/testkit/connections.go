package testkit

import (
	"encoding/base64"
	"encoding/json"
)

// Connection is a WebSocket or SSE connection a test opened with
// [TestHost.OpenConnection]: the client's side.
//
//	conn := host.OpenConnection("/chat/lobby/ws?user=ada")
//	host.SendFrame(conn, `{"type":"say","text":"hi"}`)
//	frames := host.FramesSent(conn, true).Frames
type Connection struct {
	// ID is the connection's id (c- and 32 hex digits) when its actor
	// accepted it, else "".
	ID string
	// Response is the handshake's answer: 101 for an accepted WebSocket, 200
	// for an accepted event stream, else the refusal or the error.
	Response *Response
}

// Accepted reports whether the actor accepted the connection.
func (c *Connection) Accepted() bool { return c.ID != "" }

// ConnectionOptions say how [TestHost.OpenConnection] opens a connection.
type ConnectionOptions struct {
	// Protocol is "websocket" (the default) or "sse".
	Protocol string
	Headers  []Header
}

// Frame is a frame an actor sent on a connection, as [TestHost.FramesSent]
// returns it.
type Frame struct {
	// Seq is its outgoing seq on the connection, from 0.
	Seq uint64
	// Kind is "text", "binary" or "event".
	Kind string
	// Body is the text or binary data, or the event's data.
	Body []byte
	// Event and ID are an event's fields.
	Event string
	ID    string
	t     *TestHost
}

// Text returns the frame's data as text.
func (f *Frame) Text() string { return string(f.Body) }

// JSON parses the frame's data as JSON into v; the test fails if it is not.
func (f *Frame) JSON(v any) {
	f.t.t.Helper()
	if err := json.Unmarshal(f.Body, v); err != nil {
		f.t.t.Fatalf("the frame is not the expected JSON (%v): %s", err, f.Body)
	}
}

// Closed is the close a connection got, from its actor or from the host.
type Closed struct {
	Code   uint16
	Reason string
}

// FramesSent is what an actor sent on a connection.
type FramesSent struct {
	// Frames are the frames since the last clear, oldest first.
	Frames []Frame
	// Closed is the close the connection got, or nil.
	Closed *Closed
}

// Close says how [TestHost.CloseConnection] ends a connection.
type Close struct {
	// Initiator is "client" (the default) or "host".
	Initiator string
	// Code is the client's close code: 0 means 1000, and 1006 is a client
	// that goes away without a close frame.
	Code uint16
	// Reason is the client's close reason.
	Reason string
	// Cause is the host's: restart, ping-timeout, too-large, slow-consumer,
	// protocol, operator or unavailable.
	Cause string
}

func (h *TestHost) connectionID(conn *Connection) string {
	h.t.Helper()
	if conn.ID == "" {
		h.t.Fatalf("the connection was not accepted: HTTP %d %s", conn.Response.Status, conn.Response.Text())
	}
	return conn.ID
}

// OpenConnection opens a WebSocket (the default) or an event stream
// (Protocol "sse") at path through the gateway, as a client would. The open
// turn has run when it returns: Accepted tells whether the actor accepted,
// and [TestHost.FramesSent] has what its open turn sent.
func (h *TestHost) OpenConnection(path string, opts ...ConnectionOptions) *Connection {
	h.t.Helper()
	var o ConnectionOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.Protocol == "" {
		o.Protocol = "websocket"
	}
	headers := o.Headers
	if headers == nil {
		headers = []Header{}
	}
	var answer struct {
		wire
		Status     int      `json:"status"`
		Headers    []Header `json:"headers"`
		Turn       *string  `json:"turn"`
		Connection *string  `json:"connection"`
	}
	h.call(map[string]any{"op": "open-connection", "path": path, "protocol": o.Protocol, "headers": headers}, &answer)
	res := &Response{Status: answer.Status, Headers: answer.Headers, Body: answer.bytes(h.t), t: h.t}
	if answer.Turn != nil {
		res.Turn = *answer.Turn
	}
	conn := &Connection{Response: res}
	if answer.Connection != nil {
		conn.ID = *answer.Connection
	}
	return conn
}

// SendFrame sends a frame from the client: a text frame for a string, a
// binary frame for []byte. It returns once its turn, and what that started,
// have finished.
func (h *TestHost) SendFrame(conn *Connection, frame any) {
	h.t.Helper()
	request := map[string]any{"op": "send-frame", "connection": h.connectionID(conn)}
	switch f := frame.(type) {
	case string:
		request["body"] = f
	case []byte:
		request["body_base64"] = base64.StdEncoding.EncodeToString(f)
	default:
		h.t.Fatalf("a frame is a string (text) or []byte (binary), not %T", frame)
	}
	h.call(request, nil)
}

// CloseConnection ends a connection as c says; the zero Close is the
// client's close with 1000. It returns once the close turn, and what that
// started, have finished.
func (h *TestHost) CloseConnection(conn *Connection, c Close) {
	h.t.Helper()
	request := map[string]any{"op": "close-connection", "connection": h.connectionID(conn), "initiator": "client", "reason": c.Reason}
	if c.Initiator != "" {
		request["initiator"] = c.Initiator
	}
	if c.Code != 0 {
		request["code"] = c.Code
	}
	if c.Cause != "" {
		request["cause"] = c.Cause
	}
	h.call(request, nil)
}

// FramesSent returns what the actor sent on a connection since the last
// clear, and the close it got; clear forgets the frames returned.
func (h *TestHost) FramesSent(conn *Connection, clear bool) FramesSent {
	h.t.Helper()
	var answer struct {
		Frames []struct {
			wire
			Seq   uint64 `json:"seq"`
			Kind  string `json:"kind"`
			Event string `json:"event"`
			ID    string `json:"id"`
		} `json:"frames"`
		Closed *Closed `json:"closed"`
	}
	h.call(map[string]any{"op": "frames-sent", "connection": h.connectionID(conn), "clear": clear}, &answer)
	out := FramesSent{Frames: make([]Frame, 0, len(answer.Frames)), Closed: answer.Closed}
	for _, f := range answer.Frames {
		out.Frames = append(out.Frames, Frame{Seq: f.Seq, Kind: f.Kind, Body: f.bytes(h.t), Event: f.Event, ID: f.ID, t: h})
	}
	return out
}
