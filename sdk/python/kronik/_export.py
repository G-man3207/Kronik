# The kronik:actor/handler export. `kronik build` writes
# `.kronik/kronik_entry.py` with `Handler = export(handler)`, which
# componentize-py exports. The bindings are imported in export(), so this
# module imports outside a component too (handle() takes them as `h`).

import sys

from .actor import unhandled
from .connections import IncomingFrame, OpenRequest, closed_of
from .ctx import Ctx
from .errors import KronikError, Rejected
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


def _turn(h, run):
    """Runs `run(ctx)` as a turn's handler: its result, or `h.Err(handler-error)` when it fails."""
    t = h.types
    ctx = Ctx(h)
    try:
        return run(ctx)
    except Rejected as e:
        raise h.Err(t.HandlerError_Rejected(str(e))) from None
    except Exception as e:
        raise h.Err(t.HandlerError_Failed(f"{type(e).__name__}: {e}")) from None
    finally:
        sys.stdout.flush()
        sys.stderr.flush()


def _unhandled_connections(kind, what, handler):
    return (
        f"actor type {kind} does not handle {what}: give actor() "
        f"connections=Connections({handler}=...) (see `kronik explain connections`)"
    )


def open_reply(h, out):
    """What an open handler returned, as the export's answer: an accept stays one,
    and an HTTP output (ctx.status(403), ctx.json(...)) refuses with that response."""
    c, t = h.connections, h.types
    if isinstance(out, (c.OpenReply_Accept, c.OpenReply_Refuse)):
        return out
    if isinstance(out, t.Output_Http):
        return c.OpenReply_Refuse(out.value)
    raise KronikError(
        "open",
        "an open handler must return ctx.accept() or an HTTP response such as ctx.status(403)",
        f"it returned {type(out).__name__}",
        "connections",
    )


def open_connection(spec, h, request):
    """A connection's open: the handler's accept or refusal; 404 without a handler."""
    handlers = spec.connections

    def run(ctx):
        if handlers is None or handlers.open is None:
            c, t = h.connections, h.types
            message = _unhandled_connections(ctx.self().kind, "connections", "open")
            body = t.HttpBody_Inline(message.encode())
            return c.OpenReply_Refuse(t.HttpResponse(404, [t.Header("content-type", "text/plain; charset=utf-8")], body))
        return open_reply(h, handlers.open(OpenRequest(request), ctx))

    return _turn(h, run)


def connection_frame(spec, h, event):
    """A frame from a client; rejected without a handler."""
    handlers = spec.connections

    def run(ctx):
        if handlers is None or handlers.frame is None:
            raise Rejected(_unhandled_connections(ctx.self().kind, "connection frames", "frame"))
        handlers.frame(IncomingFrame(event), ctx)

    _turn(h, run)


def connection_closed(spec, h, event):
    """A connection ended; nothing happens without a handler."""
    handlers = spec.connections

    def run(ctx):
        if handlers is not None and handlers.close is not None:
            handlers.close(closed_of(event), ctx)

    _turn(h, run)


def export_connections(spec):
    """The class componentize-py exports as `kronik:actor/connection-handler` for the actor type `spec`."""
    from wit_world import exports

    from . import _host

    class ConnectionHandler(exports.ConnectionHandler):
        def open(self, request):
            return open_connection(spec, _host, request)

        def frame(self, event):
            connection_frame(spec, _host, event)

        def close(self, event):
            connection_closed(spec, _host, event)

    return ConnectionHandler


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
