// Package kronik writes Kronik actors in Go, built with TinyGo into a
// component of the kronik:actor world. See [Actor].
package kronik

import (
	"fmt"

	"go.bytecodealliance.org/cm"
	"kronik.dev/sdk/internal/wit/kronik/actor/handler"
	"kronik.dev/sdk/internal/wit/kronik/actor/types"
)

// Route is an HTTP route the gateway sends to an actor type. "{key}" in
// Pattern names the actor's key.
type Route struct {
	Method  string
	Pattern string
}

// Timer is a timer this actor scheduled, arriving as an input.
type Timer struct {
	ID      uint64
	Message *Message
}

// Actor is an actor type: its manifest and the handlers for the inputs it
// takes. Export it from the main package's init:
//
//	func init() {
//		kronik.Export(kronik.Actor{
//			Kind:          "counter",
//			SchemaVersion: 1,
//			Routes:        []kronik.Route{{Method: "POST", Pattern: "/counter/{key}/increment"}},
//			HTTP: func(req *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
//				var n int
//				if _, err := ctx.State.GetJSON("n", &n); err != nil {
//					return kronik.Output{}, err
//				}
//				n++
//				if err := ctx.State.SetJSON("n", n); err != nil {
//					return kronik.Output{}, err
//				}
//				return ctx.JSON(200, map[string]int{"n": n})
//			},
//		})
//	}
//
// Every input runs as one turn on a fresh instance: package variables do
// not survive it, and init runs again in every instance. A handler that
// returns an error fails the turn and its writes are discarded: [Rejected]
// gives handler-error::rejected, any other error handler-error::failed with
// the error's message. A panic is recovered into handler-error::failed.
type Actor struct {
	// Kind is the actor type's name, such as "counter".
	Kind string
	// SchemaVersion is raised when Migrate gains a step; above 0, a new
	// actor runs Migrate(0) first.
	SchemaVersion uint32
	// Routes are the HTTP routes the gateway sends to this actor type.
	Routes []Route
	// Capabilities the actor type asks for, such as "http:api.example.com".
	Capabilities []string
	// HTTP handles an HTTP request.
	HTTP func(req *Request, ctx *Ctx) (Output, error)
	// Message handles a message from another actor or the operator.
	Message func(msg *Message, ctx *Ctx) (Output, error)
	// Timer handles a timer this actor scheduled.
	Timer func(timer Timer, ctx *Ctx) (Output, error)
	// Migrate migrates the actor's state from schema version from; SQL DDL
	// is allowed only here.
	Migrate func(from uint32, ctx *Ctx) error
}

type handleResult = cm.Result[handler.OutputShape, types.Output, types.HandlerError]

// Export makes a the component's kronik:actor/handler export. Call it once,
// from init.
func Export(a Actor) {
	handler.Exports.Describe = a.describe
	handler.Exports.Handle = a.handle
}

func (a *Actor) describe() types.Manifest {
	routes := make([]types.Route, len(a.Routes))
	for i, r := range a.Routes {
		routes[i] = types.Route{Method: r.Method, Pattern: r.Pattern}
	}
	return types.Manifest{
		Kind:          a.Kind,
		SchemaVersion: a.SchemaVersion,
		Routes:        list(routes),
		Capabilities:  list(a.Capabilities),
	}
}

func (a *Actor) handle(input types.Input) (result handleResult) {
	defer func() {
		if r := recover(); r != nil {
			result = cm.Err[handleResult](types.HandlerErrorFailed(fmt.Sprintf("panic: %v", r)))
		}
	}()
	out, err := a.dispatch(&input, &Ctx{})
	if err != nil {
		if IsRejected(err) {
			return cm.Err[handleResult](types.HandlerErrorRejected(err.Error()))
		}
		return cm.Err[handleResult](types.HandlerErrorFailed(err.Error()))
	}
	return cm.OK[handleResult](out.wit)
}

func (a *Actor) dispatch(input *types.Input, ctx *Ctx) (Output, error) {
	switch {
	case input.HTTP() != nil:
		if a.HTTP == nil {
			return Output{}, unhandled(ctx, "HTTP requests", "an HTTP", "actor")
		}
		return a.HTTP(newRequest(input.HTTP()), ctx)
	case input.Message() != nil:
		if a.Message == nil {
			return Output{}, unhandled(ctx, "messages", "a Message", "message")
		}
		in := input.Message()
		return a.Message(newMessage(&in.Msg, in.Sender.Some()), ctx)
	case input.Timer() != nil:
		if a.Timer == nil {
			return Output{}, unhandled(ctx, "timers", "a Timer", "dead-letters")
		}
		t := input.Timer()
		return a.Timer(Timer{ID: t.ID, Message: newMessage(&t.Msg, nil)}, ctx)
	case input.Migrate() != nil:
		if a.Migrate != nil {
			if err := a.Migrate(*input.Migrate(), ctx); err != nil {
				return Output{}, err
			}
		}
		return ctx.None()
	}
	return Output{}, fmt.Errorf("unknown input %s", input.String())
}

func unhandled(ctx *Ctx, what, field, topic string) error {
	return Rejected(fmt.Sprintf("actor type %s does not handle %s: give the kronik.Actor %s func (see `kronik explain %s`)",
		ctx.Self().Kind, what, field, topic))
}
