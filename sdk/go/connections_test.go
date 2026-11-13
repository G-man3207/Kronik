// Unit tests for connections (M24); the only host call they reach is
// ctx.Self, defined in host_test.go.

package kronik

import (
	"strings"
	"testing"

	"go.bytecodealliance.org/cm"
	"kronik.dev/sdk/internal/wit/kronik/actor/connections"
	"kronik.dev/sdk/internal/wit/kronik/actor/types"
)

func openRequest(query string, headers ...types.Header) connections.OpenRequest {
	return connections.OpenRequest{
		Connection: "c-0123",
		Protocol:   connections.ProtocolWebsocket,
		Request: types.HTTPRequest{
			Method:  "GET",
			Path:    "/chat/lobby/ws",
			Query:   query,
			Params:  cm.ToList([][2]string{{"key", "lobby"}}),
			Headers: list(headers),
		},
		Subprotocols: cm.ToList([]string{"chat.v1"}),
	}
}

func TestFramesAndRoutes(t *testing.T) {
	if r := WebSocket("/chat/{key}/ws"); r.Method != "WEBSOCKET" || r.Pattern != "/chat/{key}/ws" {
		t.Errorf("websocket route %+v", r)
	}
	if r := SSE("/e"); r.Method != "SSE" {
		t.Errorf("sse route %+v", r)
	}
	if f := TextFrame("hi"); f.wit.Text() == nil || *f.wit.Text() != "hi" {
		t.Errorf("text frame %v", f.wit)
	}
	if f, err := JSONFrame(map[string]int{"n": 1}); err != nil || *f.wit.Text() != `{"n":1}` {
		t.Errorf("json frame %v %v", f.wit, err)
	}
	if f := BinaryFrame([]byte{1, 2}); f.wit.Binary() == nil || f.wit.Binary().Len() != 2 {
		t.Errorf("binary frame %v", f.wit)
	}
	if f := EventFrame("message", "7", "x"); f.wit.Event() == nil || *f.wit.Event() != (connections.SseEvent{Event: "message", ID: "7", Data: "x"}) {
		t.Errorf("event frame %v", f.wit)
	}
}

func TestOpenRequestFramesAndClose(t *testing.T) {
	wit := openRequest("user=ada", types.Header{Name: "Origin", Value: "https://chat.example"}, types.Header{Name: "Last-Event-ID", Value: "41"})
	req := newOpenRequest(&wit)
	if req.Connection != "c-0123" || req.Protocol != "websocket" || len(req.Subprotocols) != 1 {
		t.Errorf("request %+v", req)
	}
	if u, _ := req.QueryParam("user"); u != "ada" {
		t.Errorf("user %q", u)
	}
	if k, _ := req.Param("key"); k != "lobby" {
		t.Errorf("key %q", k)
	}
	if o, _ := req.Origin(); o != "https://chat.example" {
		t.Errorf("origin %q", o)
	}
	if id, _ := req.LastEventID(); id != "41" {
		t.Errorf("last event id %q", id)
	}
	text := newIncomingFrame(&connections.IncomingFrame{Connection: "c-0123", Seq: 3, Frame: connections.FrameText(`{"type":"say"}`)})
	var v struct{ Type string }
	if err := text.JSON(&v); err != nil || v.Type != "say" || text.Kind != "text" || text.Seq != 3 {
		t.Errorf("text frame %+v %v", text, err)
	}
	binary := newIncomingFrame(&connections.IncomingFrame{Frame: connections.FrameBinary(cm.ToList([]byte{0xff}))})
	if _, err := binary.Text(); err == nil || !strings.Contains(err.Error(), "the frame is not UTF-8") {
		t.Errorf("binary text: %v", err)
	}
	closed := newClosed(&connections.Closed{Connection: "c-0123", Info: connections.CloseInfo{Initiator: connections.CloseInitiatorHost, Code: 1012, Reason: "restart"}})
	if closed != (Closed{Connection: "c-0123", Initiator: "host", Code: 1012, Reason: "restart"}) {
		t.Errorf("closed %+v", closed)
	}
}

func TestOpenAcceptsRefusesAndDefaultsTo404(t *testing.T) {
	a := &Actor{Kind: "chat", Connections: &Connections{Open: func(req *OpenRequest, ctx *Ctx) (OpenReply, error) {
		switch u, _ := req.QueryParam("user"); u {
		case "mallory":
			return ctx.Refuse(ctx.Status(403))
		case "none":
			return OpenReply{}, nil
		}
		return ctx.Accept(AcceptOptions{Subject: "user:ada", Headers: []Header{{Name: "x-room", Value: "lobby"}}})
	}}}
	// An accept variant is sized for wasm32, so a 64-bit host test checks the
	// handler's answer before it becomes the variant.
	ada := openRequest("user=ada")
	reply, err := a.openReply(&ada)
	if err != nil || reply.accept == nil || reply.accept.Subject.Some() == nil || *reply.accept.Subject.Some() != "user:ada" || reply.accept.Headers.Len() != 1 {
		t.Errorf("accept %+v %v", reply, err)
	}
	refused := a.open(openRequest("user=mallory"))
	if r := refused.OK(); r == nil || r.Refuse() == nil || r.Refuse().Status != 403 {
		t.Errorf("refuse %v", refused)
	}
	none := a.open(openRequest("user=none"))
	if e := none.Err(); e == nil || e.Failed() == nil || !strings.Contains(*e.Failed(), "must return ctx.Accept") {
		t.Errorf("zero reply: %v", e)
	}
	bare := (&Actor{Kind: "chat"}).open(openRequest(""))
	if r := bare.OK(); r == nil || r.Refuse() == nil || r.Refuse().Status != 404 {
		t.Errorf("default open %v", bare)
	}
}

func TestFramesAreRejectedAndClosesIgnoredWithoutHandlers(t *testing.T) {
	bare := &Actor{Kind: "chat"}
	frame := connections.IncomingFrame{Connection: "c-0123", Frame: connections.FrameText("x")}
	closed := connections.Closed{Connection: "c-0123", Info: connections.CloseInfo{Code: 1000}}
	bareFrame, bareClose := bare.frame(frame), bare.close(closed)
	if e := bareFrame.Err(); e == nil || e.Rejected() == nil || !strings.Contains(*e.Rejected(), "does not handle connection frames") {
		t.Errorf("default frame: %v", e)
	}
	if e := bareClose.Err(); e != nil {
		t.Errorf("default close: %v", e)
	}
	var seen []Closed
	a := &Actor{Kind: "chat", Connections: &Connections{
		Frame: func(f *IncomingFrame, ctx *Ctx) error { return Rejected("bad frame") },
		Close: func(c Closed, ctx *Ctx) error { seen = append(seen, c); return nil },
	}}
	gotFrame := a.frame(frame)
	if e := gotFrame.Err(); e == nil || e.Rejected() == nil || *e.Rejected() != "bad frame" {
		t.Errorf("frame: %v", e)
	}
	gotClose := a.close(closed)
	if e := gotClose.Err(); e != nil || len(seen) != 1 || seen[0].Code != 1000 {
		t.Errorf("close: %v %v", e, seen)
	}
}

func TestSendNowResults(t *testing.T) {
	type result = cm.Result[connections.SendError, struct{}, connections.SendError]
	if sent, err := sendNowResult(cm.OK[result](struct{}{})); !sent || err != nil {
		t.Errorf("ok: %v %v", sent, err)
	}
	if sent, err := sendNowResult(cm.Err[result](connections.SendErrorClosed())); sent || err != nil {
		t.Errorf("closed: %v %v", sent, err)
	}
	_, err := sendNowResult(cm.Err[result](connections.SendErrorOutcomeUnknown()))
	if !IsOutcomeUnknown(err) || err.Error() != "the frame may or may not have reached the client (see `kronik explain EFFECT_OUTCOME_UNKNOWN`)" {
		t.Errorf("outcome unknown: %v", err)
	}
	_, err = sendNowResult(cm.Err[result](connections.SendErrorDenied("CAPABILITY_NOT_GRANTED: connection:send-now")))
	if e, ok := err.(*Error); !ok || e.Kind != "send-now.denied" || e.Topic != "CAPABILITY_NOT_GRANTED" || IsOutcomeUnknown(err) {
		t.Errorf("denied: %v", err)
	}
}
