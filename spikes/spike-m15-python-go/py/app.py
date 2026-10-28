import json
import random
import time

import wit_world
from wit_world.exports import Handler as _H
from wit_world.imports import state, types, context, log
from componentize_py_types import Err


class Handler(_H):
    def describe(self) -> types.Manifest:
        return types.Manifest(
            kind="counter",
            schema_version=1,
            routes=[types.Route(method="POST", pattern="/counter/{key}/increment")],
            capabilities=[],
        )

    def handle(self, input: types.Input) -> types.Output:
        if isinstance(input, types.Input_Http):
            raw = state.get("n")
            n = (json.loads(raw) if raw is not None else 0) + 1
            state.set("n", json.dumps(n).encode())
            body = json.dumps({"n": n}).encode()
            return types.Output_Http(types.HttpResponse(
                status=200,
                headers=[types.Header("content-type", "application/json")],
                body=types.HttpBody_Inline(body),
            ))
        if isinstance(input, types.Input_Message):
            name = input.value.msg.name
            if name == "probe":
                out = {
                    "now": context.now_ms(),
                    "time": time.time(),
                    "rand": random.random(),
                    "rb": context.random_bytes(4).hex(),
                }
                return types.Output_Reply(types.Message("probe", "application/json", json.dumps(out).encode(), []))
            if name == "noop":
                return types.Output_None_()
            if name == "spin":
                i = 0
                while True:
                    i += 1
            if name == "fail":
                raise Err(types.HandlerError_Failed("nope"))
            if name == "boom":
                raise ValueError("boom")
        return types.Output_None_()
