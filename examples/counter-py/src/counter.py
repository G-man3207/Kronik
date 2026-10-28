# counter-py: the brief's counter, the Python twin of counter-ts.
#
# Every actor `counter/<key>` keeps a number `n` in its state.
#
# - `POST /counter/{key}/increment` adds `step` and returns `{"n": n}`.
# - `GET /counter/{key}` returns `{"n": n}` without changing it.
# - Any message, for example `kronik send counter/alice increment`, adds
#   `step` and replies `{"n": n}`.
#
# The kind has schema version 1, so a new actor first runs `migrate(0)`; the
# counter has no schema, so that turn changes nothing. src/actor.py adds 1;
# src/step2.py adds 2, a changed behavior for the M3 tests (`kronik build
# --entry step2` builds it as counter-py-step2.wasm).

from kronik import actor


def counter(step):
    def increment(ctx):
        n = (ctx.state.get_json("n") or 0) + step
        ctx.state.set_json("n", n)
        return n

    def http(req, ctx):
        if req.method == "GET":
            return ctx.json(200, {"n": ctx.state.get_json("n") or 0})
        return ctx.json(200, {"n": increment(ctx)})

    def message(msg, ctx):
        return ctx.reply({"name": "n", "body": {"n": increment(ctx)}})

    return actor(
        kind="counter",
        schema_version=1,
        routes=[
            {"method": "POST", "pattern": "/counter/{key}/increment"},
            {"method": "GET", "pattern": "/counter/{key}"},
        ],
        http=http,
        message=message,
    )
