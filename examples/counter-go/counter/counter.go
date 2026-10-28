// Package counter is the brief's counter, the Go twin of counter-ts.
//
// Every actor counter/<key> keeps a number n in its state.
//
//   - POST /counter/{key}/increment adds step and returns {"n": n}.
//   - GET /counter/{key} returns {"n": n} without changing it.
//   - Any message, for example `kronik send counter/alice increment`, adds
//     step and replies {"n": n}.
//
// The kind has schema version 1, so a new actor first runs Migrate(0); the
// counter has no schema, so that turn changes nothing. The main package adds
// 1; ./step2 adds 2, a changed behavior for the M3 tests (`kronik build
// --entry ./step2` builds it as counter-go-step2.wasm).
package counter

import "kronik.dev/sdk"

type count struct {
	N int64 `json:"n"`
}

// Actor is the counter actor type, adding step per increment.
func Actor(step int64) kronik.Actor {
	get := func(ctx *kronik.Ctx) (int64, error) {
		var n int64
		_, err := ctx.State.GetJSON("n", &n)
		return n, err
	}
	increment := func(ctx *kronik.Ctx) (int64, error) {
		n, err := get(ctx)
		if err != nil {
			return 0, err
		}
		n += step
		return n, ctx.State.SetJSON("n", n)
	}
	return kronik.Actor{
		Kind:          "counter",
		SchemaVersion: 1,
		Routes: []kronik.Route{
			{Method: "POST", Pattern: "/counter/{key}/increment"},
			{Method: "GET", Pattern: "/counter/{key}"},
		},
		HTTP: func(req *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
			n, err := get(ctx)
			if req.Method != "GET" {
				n, err = increment(ctx)
			}
			if err != nil {
				return kronik.Output{}, err
			}
			return ctx.JSON(200, count{n})
		},
		Message: func(_ *kronik.Message, ctx *kronik.Ctx) (kronik.Output, error) {
			n, err := increment(ctx)
			if err != nil {
				return kronik.Output{}, err
			}
			return ctx.Reply(kronik.OutgoingMessage{Name: "n", Body: count{n}})
		},
	}
}
