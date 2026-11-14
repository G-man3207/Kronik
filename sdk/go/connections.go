// Long-lived connections (M24): WebSocket and SSE. A kind declares
// WEBSOCKET and SSE routes ([WebSocket], [SSE]) and handles them with
// Actor.Connections. Each input of a connection is a turn of the actor that
// accepted it, and only that actor may send on it or close it
// (ctx.Connections).

package kronik

import (
	"fmt"

	"go.bytecodealliance.org/cm"
	connectionhandler "kronik.dev/sdk/internal/wit/kronik/actor/connection-handler"
	"kronik.dev/sdk/internal/wit/kronik/actor/connections"
	"kronik.dev/sdk/internal/wit/kronik/actor/types"
)

// WebSocket is a WebSocket route: an upgrade request opens a connection.
func WebSocket(pattern string) Route { return Route{Method: "WEBSOCKET", Pattern: pattern} }

// SSE is a server-sent events route: a GET opens an event stream.
func SSE(pattern string) Route { return Route{Method: "SSE", Pattern: pattern} }

// Connections handles an actor type's WebSocket and SSE connections, for
// its WEBSOCKET and SSE routes. Each handler runs as a turn of the actor
// that accepted the connection.
type Connections struct {
	// Open accepts a connection with ctx.Accept or refuses it with
	// ctx.Refuse(ctx.Status(403)). Frames sent here go out right after the
	// handshake. Without it, opens are refused with 404.
	Open func(req *OpenRequest, ctx *Ctx) (OpenReply, error)
	// Frame handles a frame from a client (WebSocket only). Without it,
	// frames are rejected and become dead letters.
	Frame func(frame *IncomingFrame, ctx *Ctx) error
	// Close runs when the connection ended: its last input, exactly once,
	// also after a restart (initiator "host", reason "restart"). Without
	// it, closes do nothing.
	Close func(closed Closed, ctx *Ctx) error
}

// Frame is a frame to send: one WebSocket message or one SSE event. Make
// one with [TextFrame], [JSONFrame], [BinaryFrame] or [EventFrame].
type Frame struct{ wit connections.Frame }

// TextFrame is a text frame; on an SSE stream, an event with only data.
func TextFrame(text string) Frame { return Frame{connections.FrameText(text)} }

// JSONFrame is v as JSON in a text frame.
func JSONFrame(v any) (Frame, error) {
	b, err := toJSON(v)
	if err != nil {
		return Frame{}, err
	}
	return TextFrame(string(b)), nil
}

// BinaryFrame is a binary frame (WebSocket only: sending one on an SSE
// stream traps).
func BinaryFrame(data []byte) Frame { return Frame{connections.FrameBinary(list(data))} }

// EventFrame is an SSE event with an event name and an id (both may be
// empty). A reconnecting EventSource sends the last id back
// (req.LastEventID). On a WebSocket, a text frame with the data.
func EventFrame(event, id, data string) Frame {
	return Frame{connections.FrameEvent(connections.SseEvent{Event: event, ID: id, Data: data})}
}

// OpenRequest is a client asking to open a connection: a WebSocket upgrade
// or an SSE GET. The body is empty.
type OpenRequest struct {
	*Request
	// Connection is the new connection's id ("c-..."): keep it to send to
	// the connection in later turns.
	Connection string
	// Protocol is "websocket" or "sse".
	Protocol string
	// Subprotocols are the WebSocket subprotocols the client offered.
	Subprotocols []string
}

func newOpenRequest(req *connections.OpenRequest) *OpenRequest {
	return &OpenRequest{
		Request:      newRequest(&req.Request),
		Connection:   string(req.Connection),
		Protocol:     req.Protocol.String(),
		Subprotocols: append([]string(nil), req.Subprotocols.Slice()...),
	}
}

// Origin is the Origin header. A browser sends it, with its cookies, on a
// WebSocket handshake: an actor that authenticates by cookie checks it (see
// `kronik explain connections`).
func (r *OpenRequest) Origin() (string, bool) { return r.Header("origin") }

// LastEventID is the last SSE event id a reconnecting EventSource saw
// (Last-Event-ID).
func (r *OpenRequest) LastEventID() (string, bool) { return r.Header("last-event-id") }

// IncomingFrame is one frame from a client (WebSocket only).
type IncomingFrame struct {
	// Connection is the connection it came on.
	Connection string
	// Seq is 0, 1, 2, ... per connection, in the order the client sent them.
	Seq uint64
	// Kind is "text", "binary" or "event".
	Kind string
	data []byte
}

func newIncomingFrame(event *connections.IncomingFrame) *IncomingFrame {
	f := &IncomingFrame{Connection: string(event.Connection), Seq: event.Seq}
	switch {
	case event.Frame.Text() != nil:
		f.Kind, f.data = "text", []byte(*event.Frame.Text())
	case event.Frame.Binary() != nil:
		f.Kind, f.data = "binary", append([]byte(nil), event.Frame.Binary().Slice()...)
	case event.Frame.Event() != nil:
		f.Kind, f.data = "event", []byte(event.Frame.Event().Data)
	}
	return f
}

// Bytes is the frame's bytes: a text frame's text as UTF-8.
func (f *IncomingFrame) Bytes() []byte { return f.data }

// Text is the frame's text: a binary frame's bytes decoded as UTF-8.
func (f *IncomingFrame) Text() (string, error) { return decodeText(f.data, "the frame", "connections") }

// JSON parses the frame as JSON into v.
func (f *IncomingFrame) JSON(v any) error { return decodeJSON(f.data, v, "the frame", "connections") }

// Closed is a connection that ended.
type Closed struct {
	Connection string
	// Initiator is who ended it: "client", "actor" (ctx.Connections.Close)
	// or "host" (a restart, a limit, an operator).
	Initiator string
	// Code is the WebSocket close code: 1000 normal, 1006 gone without a
	// close frame, 1012 a restart.
	Code uint16
	// Reason is the client's or the actor's reason, or the host's (such as
	// "restart").
	Reason string
}

func newClosed(event *connections.Closed) Closed {
	return Closed{
		Connection: string(event.Connection),
		Initiator:  event.Info.Initiator.String(),
		Code:       event.Info.Code,
		Reason:     event.Info.Reason,
	}
}

// AcceptOptions are how ctx.Accept accepts a connection.
type AcceptOptions struct {
	// Subprotocol is one of the subprotocols the client offered (WebSocket
	// only).
	Subprotocol string
	// Headers are extra response headers.
	Headers []Header
	// Subject is the subject of the connection's later inputs (its frames
	// and its close); empty: the request's.
	Subject string
}

// OpenReply is an open handler's answer: ctx.Accept or ctx.Refuse.
type OpenReply struct {
	accept *connections.Accept
	refuse *types.HTTPResponse
}

// wit is the reply as the export returns it. The variant is built only
// here: its storage is sized for wasm32, where an accept fits.
func (r OpenReply) wit() connections.OpenReply {
	if r.accept != nil {
		return connections.OpenReplyAccept(*r.accept)
	}
	return connections.OpenReplyRefuse(*r.refuse)
}

// Accept accepts the connection that the current open asks for: return it
// from Connections.Open.
func (*Ctx) Accept(o AcceptOptions) (OpenReply, error) {
	headers := make([]types.Header, len(o.Headers))
	for i, h := range o.Headers {
		headers[i] = types.Header{Name: h.Name, Value: h.Value}
	}
	accept := connections.Accept{Subprotocol: optional(o.Subprotocol), Headers: list(headers), Subject: optional(o.Subject)}
	return OpenReply{accept: &accept}, nil
}

// Refuse refuses the connection that the current open asks for with an
// HTTP response: return ctx.Refuse(ctx.Status(403)) from Connections.Open.
// A reply refuses with 200 and its body, None with 204.
func (*Ctx) Refuse(out Output, err error) (OpenReply, error) {
	if err != nil {
		return OpenReply{}, err
	}
	var r types.HTTPResponse
	switch {
	case out.wit.HTTP() != nil:
		r = *out.wit.HTTP()
	case out.wit.Reply() != nil:
		m := out.wit.Reply()
		h := []types.Header{{Name: "content-type", Value: m.ContentType}}
		r = types.HTTPResponse{Status: 200, Headers: list(h), Body: types.HTTPBodyInline(m.Body)}
	default:
		r = types.HTTPResponse{Status: 204, Body: types.HTTPBodyInline(cm.List[uint8]{})}
	}
	return OpenReply{refuse: &r}, nil
}

// ConnectionOps are the WebSocket and SSE connections this actor accepted:
// ctx.Connections (see `kronik explain connections`). Only the actor whose
// open accepted a connection sends on it or closes it. A frame to an id that
// is not a live connection of this actor (it closed, was never accepted, or
// another actor holds it) is recorded as dropped and never delivered, and
// shows in the history; closing it does nothing, and SendNow returns false.
// To reach another actor's clients, send that actor a message.
type ConnectionOps struct{}

// Send sends frame to connection when this turn commits, in call order;
// nothing if the turn fails.
func (ConnectionOps) Send(connection string, frame Frame) {
	connections.Send(connections.ConnectionID(connection), frame.wit)
}

// Broadcast is Send to each of conns, recorded once: the way to fan a
// message out.
func (ConnectionOps) Broadcast(conns []string, frame Frame) {
	ids := make([]connections.ConnectionID, len(conns))
	for i, c := range conns {
		ids[i] = connections.ConnectionID(c)
	}
	connections.Broadcast(list(ids), frame.wit)
}

// Close closes connection when this turn commits, after the frames sent
// before: a WebSocket with code and reason, an SSE stream by ending it. Its
// close input still follows.
func (ConnectionOps) Close(connection string, code uint16, reason string) {
	connections.Close(connections.ConnectionID(connection), code, reason)
}

// SendNow sends frame now, before this turn commits, for intermediate
// results such as the tokens of a streamed answer; use Send for final
// notices. An effect with delivery class unsafe that needs the capability
// connection:send-now. True when the frame was handed to the connection
// (not that the client received it), false when the connection is closed
// or its client does not keep up. An error for which [IsOutcomeUnknown] is
// true means a crash made the outcome unknown: a frame is never sent
// twice; returned from the turn, it fails with EFFECT_OUTCOME_UNKNOWN.
// Frames sent now go out before the turn's Send frames.
func (ConnectionOps) SendNow(connection string, frame Frame) (bool, error) {
	return sendNowResult(connections.SendNow(connections.ConnectionID(connection), frame.wit))
}

func sendNowResult(res cm.Result[connections.SendError, struct{}, connections.SendError]) (bool, error) {
	e := res.Err()
	switch {
	case e == nil:
		return true, nil
	case e.Closed():
		return false, nil
	case e.OutcomeUnknown():
		return false, newError("send-now.outcome-unknown", "the frame may or may not have reached the client", "", "EFFECT_OUTCOME_UNKNOWN", *e)
	case e.Denied() != nil:
		detail := *e.Denied()
		return false, newError("send-now.denied", "sending now denied", detail, explainTopic(detail, "capability"), *e)
	}
	return false, newError("send-now.unknown", "sending now failed", e.String(), "connections", *e)
}

// IsOutcomeUnknown reports whether err is SendNow's unknown outcome.
func IsOutcomeUnknown(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Kind == "send-now.outcome-unknown"
}

type openResult = cm.Result[connectionhandler.OpenReplyShape, connectionhandler.OpenReply, connectionhandler.HandlerError]
type eventResult = cm.Result[connectionhandler.HandlerError, struct{}, connectionhandler.HandlerError]

func unhandledConnections(ctx *Ctx, what, field string) string {
	return fmt.Sprintf("actor type %s does not handle %s: give the kronik.Actor Connections a %s func (see `kronik explain connections`)",
		ctx.Self().Kind, what, field)
}

func (a *Actor) open(req connectionhandler.OpenRequest) (result openResult) {
	defer func() {
		if r := recover(); r != nil {
			result = cm.Err[openResult](types.HandlerErrorFailed(fmt.Sprintf("panic: %v", r)))
		}
	}()
	reply, err := a.openReply(&req)
	if err != nil {
		return cm.Err[openResult](handlerError(err))
	}
	return cm.OK[openResult](reply.wit())
}

// openReply runs the open handler: its answer, or 404 without one.
func (a *Actor) openReply(req *connections.OpenRequest) (OpenReply, error) {
	ctx := &Ctx{}
	if a.Connections == nil || a.Connections.Open == nil {
		body := []byte(unhandledConnections(ctx, "connections", "an Open"))
		h := []types.Header{{Name: "content-type", Value: "text/plain; charset=utf-8"}}
		r := types.HTTPResponse{Status: 404, Headers: list(h), Body: types.HTTPBodyInline(list(body))}
		return OpenReply{refuse: &r}, nil
	}
	reply, err := a.Connections.Open(newOpenRequest(req), ctx)
	if err == nil && reply.accept == nil && reply.refuse == nil {
		err = newError("open", "an open handler must return ctx.Accept(...) or ctx.Refuse(...)", "", "connections", nil)
	}
	return reply, err
}

func (a *Actor) frame(event connectionhandler.IncomingFrame) (result eventResult) {
	defer func() {
		if r := recover(); r != nil {
			result = cm.Err[eventResult](types.HandlerErrorFailed(fmt.Sprintf("panic: %v", r)))
		}
	}()
	ctx := &Ctx{}
	if a.Connections == nil || a.Connections.Frame == nil {
		return cm.Err[eventResult](handlerError(Rejected(unhandledConnections(ctx, "connection frames", "a Frame"))))
	}
	if err := a.Connections.Frame(newIncomingFrame(&event), ctx); err != nil {
		return cm.Err[eventResult](handlerError(err))
	}
	return result
}

func (a *Actor) close(event connectionhandler.Closed) (result eventResult) {
	defer func() {
		if r := recover(); r != nil {
			result = cm.Err[eventResult](types.HandlerErrorFailed(fmt.Sprintf("panic: %v", r)))
		}
	}()
	if a.Connections == nil || a.Connections.Close == nil {
		return result
	}
	if err := a.Connections.Close(newClosed(&event), &Ctx{}); err != nil {
		return cm.Err[eventResult](handlerError(err))
	}
	return result
}
