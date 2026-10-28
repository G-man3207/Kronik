# The kronik:actor/handler export. `kronik build` writes
# `.kronik/kronik_entry.py` with `Handler = export(handler)`, which
# componentize-py exports. The bindings are imported in export(), so this
# module imports outside a component too (handle() takes them as `h`).

import sys

from .actor import unhandled
from .ctx import Ctx
from .errors import Rejected
from .http import Message, Request, Timer


def handle(spec, h, input):
    """Runs one input through `spec`'s handlers; raises `h.Err(handler-error)` when the turn fails."""
    t = h.types
    ctx = Ctx(h)
    try:
        if isinstance(input, t.Input_Http):
            if spec.http is None:
                raise Rejected(unhandled(ctx.self().kind, "HTTP requests", "http", "actor"))
            return spec.http(Request(input.value), ctx)
        if isinstance(input, t.Input_Message):
            if spec.message is None:
                raise Rejected(unhandled(ctx.self().kind, "messages", "message", "message"))
            return spec.message(Message(input.value.msg, input.value.sender), ctx)
        if isinstance(input, t.Input_Timer):
            if spec.timer is None:
                raise Rejected(unhandled(ctx.self().kind, "timers", "timer", "dead-letters"))
            return spec.timer(Timer(input.value.id, Message(input.value.msg)), ctx)
        if spec.migrate is not None:
            spec.migrate(input.value, ctx)
        return t.Output_None_()
    except Rejected as e:
        raise h.Err(t.HandlerError_Rejected(str(e))) from None
    except Exception as e:
        # Uncaught, it would trap the turn without a message.
        raise h.Err(t.HandlerError_Failed(f"{type(e).__name__}: {e}")) from None
    finally:
        # stdout is block-buffered and the instance ends with the turn: print() output goes out now.
        sys.stdout.flush()
        sys.stderr.flush()


def export(spec):
    """The class componentize-py exports as `kronik:actor/handler` for the actor type `spec`."""
    from wit_world import exports

    from . import _host

    t = _host.types
    kind, schema_version, routes, capabilities = spec.manifest()
    manifest = t.Manifest(kind, schema_version, [t.Route(m, p) for m, p in routes], capabilities)

    class Handler(exports.Handler):
        def describe(self):
            return manifest

        def handle(self, input):
            return handle(spec, _host, input)

    return Handler
