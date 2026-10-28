package main

import (
	"encoding/json"
	"math/rand"
	"time"

	"example.com/counter/gen/kronik/actor/context"
	"example.com/counter/gen/kronik/actor/handler"
	"example.com/counter/gen/kronik/actor/state"
	"example.com/counter/gen/kronik/actor/types"
	"go.bytecodealliance.org/cm"
)

func init() {
	handler.Exports.Describe = func() types.Manifest {
		return types.Manifest{
			Kind:          "counter",
			SchemaVersion: 1,
			Routes:        cm.ToList([]types.Route{{Method: "POST", Pattern: "/counter/{key}/increment"}}),
			Capabilities:  cm.ToList([]string{}),
		}
	}
	handler.Exports.Handle = func(input types.Input) cm.Result[handler.OutputShape, types.Output, types.HandlerError] {
		if input.HTTP() != nil {
			n := 0
			if v := state.Get("n"); v.Some() != nil {
				_ = json.Unmarshal(v.Some().Slice(), &n)
			}
			n++
			b, _ := json.Marshal(n)
			state.Set("n", cm.ToList(b))
			body, _ := json.Marshal(map[string]int{"n": n})
			return cm.OK[cm.Result[handler.OutputShape, types.Output, types.HandlerError]](types.OutputHTTP(types.HTTPResponse{
				Status:  200,
				Headers: cm.ToList([]types.Header{{Name: "content-type", Value: "application/json"}}),
				Body:    types.HTTPBodyInline(cm.ToList(body)),
			}))
		}
		if m := input.Message(); m != nil {
			switch m.Msg.Name {
			case "probe":
				out, _ := json.Marshal(map[string]any{
					"now":  context.NowMs(),
					"time": time.Now().UnixMilli(),
					"rand": rand.Int63(),
				})
				return cm.OK[cm.Result[handler.OutputShape, types.Output, types.HandlerError]](types.OutputReply(types.Message{Name: "probe", ContentType: "application/json", Body: cm.ToList(out)}))
			case "spin":
				for {
				}
			case "boom":
				panic("boom")
			case "fail":
				return cm.Err[cm.Result[handler.OutputShape, types.Output, types.HandlerError]](types.HandlerErrorFailed("nope"))
			}
		}
		return cm.OK[cm.Result[handler.OutputShape, types.Output, types.HandlerError]](types.OutputNone())
	}
}

func main() {}
