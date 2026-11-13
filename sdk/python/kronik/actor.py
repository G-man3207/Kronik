# actor(): an actor type's spec, exported by `kronik build` through
# kronik/_export.py. No host calls here.


class ActorSpec:
    """An actor type: its manifest and the handlers for the inputs it takes. Made by actor()."""

    def __init__(self, kind, schema_version, routes, capabilities, http, message, timer, migrate, connections=None):
        self.kind = kind
        self.schema_version = schema_version
        self.routes = routes
        self.capabilities = capabilities
        self.http = http
        self.message = message
        self.timer = timer
        self.migrate = migrate
        self.connections = connections

    def manifest(self):
        """What `describe` returns: kind, schema_version, routes as (method, pattern), capabilities."""
        return self.kind, self.schema_version, [(r["method"], r["pattern"]) for r in self.routes], list(self.capabilities)


class Route:
    """Routes as actor() takes them: Route.post("/counter/{key}") is
    {"method": "POST", "pattern": "/counter/{key}"}. WEBSOCKET and SSE routes
    open connections, handled by actor(connections=...)."""

    @staticmethod
    def get(pattern):
        return {"method": "GET", "pattern": pattern}

    @staticmethod
    def post(pattern):
        return {"method": "POST", "pattern": pattern}

    @staticmethod
    def put(pattern):
        return {"method": "PUT", "pattern": pattern}

    @staticmethod
    def patch(pattern):
        return {"method": "PATCH", "pattern": pattern}

    @staticmethod
    def delete(pattern):
        return {"method": "DELETE", "pattern": pattern}

    @staticmethod
    def websocket(pattern):
        """A WebSocket route: an upgrade request opens a connection."""
        return {"method": "WEBSOCKET", "pattern": pattern}

    @staticmethod
    def sse(pattern):
        """A server-sent events route: a GET opens an event stream."""
        return {"method": "SSE", "pattern": pattern}


def actor(*, kind, schema_version, routes=(), capabilities=(), http=None, message=None, timer=None, migrate=None, connections=None):
    """Builds an actor type from its spec; the entry module binds it to `handler`:

        handler = actor(
            kind="counter",
            schema_version=1,
            routes=[{"method": "POST", "pattern": "/counter/{key}/increment"}],
            http=increment,  # def increment(req, ctx): ...
        )

    `routes` are the HTTP routes the gateway sends to this actor type (`{key}`
    names the actor's key), `capabilities` what it asks for (such as
    `http:api.example.com`). `http(req, ctx)`, `message(msg, ctx)` and
    `timer(timer, ctx)` return an output (`ctx.json(...)`, `ctx.reply(...)`,
    `ctx.none()`, ...); `migrate(from_version, ctx)` migrates the state from
    schema version `from_version`, and SQL DDL is allowed only there. Above
    schema version 0, a new actor runs `migrate(0)` first. `connections`
    (a Connections) handles the WebSocket and SSE connections of the
    actor type's WEBSOCKET and SSE routes.

    Every input runs as one turn on a fresh instance: module-level variables
    do not survive it, and module scope itself runs at build time. A handler
    that raises fails the turn and its writes are discarded: Rejected gives
    `handler-error::rejected`, any other exception `handler-error::failed`
    with its message.
    """
    if not isinstance(kind, str) or not kind:
        raise TypeError("actor(kind=...) must be a non-empty str (see `kronik explain actor`)")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or not 0 <= schema_version < 2**32:
        raise TypeError("actor(schema_version=...) must be an int from 0 to 2**32-1 (see `kronik explain actor`)")
    for r in routes:
        if not isinstance(r, dict) or not isinstance(r.get("method"), str) or not isinstance(r.get("pattern"), str):
            raise TypeError(f"route {r!r} must be a dict with str method and pattern (see `kronik explain actor`)")
    from .connections import Connections

    if connections is not None and not isinstance(connections, Connections):
        raise TypeError("actor(connections=...) must be a Connections(open=..., frame=..., close=...) (see `kronik explain connections`)")
    return ActorSpec(kind, schema_version, list(routes), list(capabilities), http, message, timer, migrate, connections)


def unhandled(kind, what, param, topic):
    """The rejection for an input the spec has no handler for."""
    return f"actor type {kind} does not handle {what}: give actor() a {param}= handler (see `kronik explain {topic}`)"
