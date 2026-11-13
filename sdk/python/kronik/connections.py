# Long-lived connections (M24): frames, the open request, incoming frames,
# the close, and the spec of an actor type's connection handlers. No host
# calls here: those are `ctx.connections` in kronik/ctx.py.

from dataclasses import dataclass

from .errors import KronikError, explain_topic, variant_tag
from .http import Request, parse_json, text, to_json

_BYTES = (bytes, bytearray, memoryview)


@dataclass(frozen=True)
class Frame:
    """A frame to send: one WebSocket message or one SSE event. Make one with
    Frame.text, Frame.json, Frame.binary or Frame.event; wherever a frame is
    taken, a str is a text frame and bytes a binary frame."""

    kind: str
    data: object
    event_name: str = ""
    event_id: str = ""

    @staticmethod
    def text(value):
        """A text frame; on an SSE stream, an event with only data."""
        return Frame("text", value)

    @staticmethod
    def json(value):
        """`value` as JSON in a text frame."""
        return Frame("text", to_json(value))

    @staticmethod
    def binary(data):
        """A binary frame (WebSocket only: sending one on an SSE stream traps)."""
        return Frame("binary", bytes(data))

    @staticmethod
    def event(data, event="", id=""):
        """An SSE event: `data` as text, or any other value as JSON, with an
        optional `event` name and `id`. A reconnecting EventSource sends the
        last id back (`req.last_event_id()`). On a WebSocket, a text frame
        with the data."""
        return Frame("event", data if isinstance(data, str) else to_json(data), event, "" if id is None else str(id))


def to_wit_frame(frame, c):
    """`frame` (a Frame, a str or bytes) as a WIT frame of `c`, the bindings' connections module."""
    if isinstance(frame, str):
        frame = Frame.text(frame)
    elif isinstance(frame, _BYTES):
        frame = Frame.binary(frame)
    if not isinstance(frame, Frame):
        raise KronikError("frame", "not a frame", "send a str, bytes, or Frame.text/json/binary/event(...)", "connections")
    if frame.kind == "text":
        return c.Frame_Text(frame.data)
    if frame.kind == "binary":
        return c.Frame_Binary(frame.data)
    return c.Frame_Event(c.SseEvent(frame.event_name, frame.event_id, frame.data))


def _enum_name(value):
    """A componentize-py enum value as the WIT case: Protocol.WEBSOCKET is "websocket"."""
    return value.name.lower().replace("_", "-")


class OpenRequest(Request):
    """A client asks to open a connection: a WebSocket upgrade or an SSE GET,
    routed by one of the actor type's WEBSOCKET or SSE routes. The body is
    empty. `connection` is the new connection's id (keep it to send to the
    connection in later turns), `protocol` "websocket" or "sse",
    `subprotocols` the WebSocket subprotocols the client offered."""

    def __init__(self, req):
        super().__init__(req.request)
        self.connection = req.connection
        self.protocol = _enum_name(req.protocol)
        self.subprotocols = list(req.subprotocols)

    def origin(self):
        """The Origin header. A browser sends it, with its cookies, on a
        WebSocket handshake: an actor that authenticates by cookie checks it
        (see `kronik explain connections`)."""
        return self.header("origin")

    def last_event_id(self):
        """The last SSE event id a reconnecting EventSource saw (Last-Event-ID)."""
        return self.header("last-event-id")


class IncomingFrame:
    """One frame from a client (WebSocket only): `connection` it came on,
    `seq` (0, 1, 2, ... per connection, in the order the client sent them)
    and `kind` ("text", "binary" or "event")."""

    def __init__(self, event):
        self.connection = event.connection
        self.seq = event.seq
        self.kind = variant_tag(event.frame)
        value = event.frame.value
        if self.kind == "binary":
            self._bytes = bytes(value)
        else:
            self._bytes = (value.data if self.kind == "event" else value).encode()

    def bytes(self):
        """The frame's bytes: a text frame's text as UTF-8."""
        return self._bytes

    def text(self):
        """The frame's text: a binary frame's bytes decoded as UTF-8."""
        return text(self._bytes, "the frame", "connections")

    def json(self):
        """The frame parsed as JSON."""
        return parse_json(self._bytes, "the frame", "connections")


@dataclass(frozen=True)
class Closed:
    """A connection ended: its last input, exactly once. `initiator` is
    "client", "actor" (ctx.connections.close) or "host" (a restart, a limit,
    an operator); `code` the WebSocket close code (1000 normal, 1006 gone
    without a close frame, 1012 a restart); `reason` the client's or the
    actor's reason, or the host's (such as "restart")."""

    connection: str
    initiator: str
    code: int
    reason: str


def closed_of(event):
    info = event.info
    return Closed(event.connection, _enum_name(info.initiator), info.code, info.reason)


class Connections:
    """The handlers of an actor type's WebSocket and SSE connections, for
    actor(connections=...), with the WEBSOCKET and SSE routes:

        connections=Connections(open=join, frame=say, close=leave)

    `open(req, ctx)` accepts with `ctx.accept(...)` or refuses with an HTTP
    response such as `ctx.status(403)`; without it, opens are refused with
    404. `frame(frame, ctx)` handles a frame from a client; without it,
    frames are rejected and become dead letters. `close(closed, ctx)` runs
    when the connection ends, also after a restart; without it, closes do
    nothing. Each runs as a turn of the actor that accepted the connection.
    """

    def __init__(self, *, open=None, frame=None, close=None):
        self.open = open
        self.frame = frame
        self.close = close


class OutcomeUnknown(KronikError):
    """Raised by send_now when the frame's outcome is unknown: the node
    stopped after it sent the frame and before it recorded that, and a frame
    is never sent twice. The turn may catch it; uncaught, the turn fails
    with EFFECT_OUTCOME_UNKNOWN."""

    def __init__(self, payload=None):
        super().__init__(
            "send-now.outcome-unknown", "the frame may or may not have reached the client", "", "EFFECT_OUTCOME_UNKNOWN", payload
        )


def send_now_failure(payload):
    """What a failing send-now host call's error (`Err.value`) means:
    False when the connection is closed (or its client does not keep up),
    else the error to raise."""
    tag = variant_tag(payload)
    if tag == "closed":
        return False
    if tag == "outcome-unknown":
        return OutcomeUnknown(payload)
    if tag == "denied":
        detail = getattr(payload, "value", "")
        detail = detail if isinstance(detail, str) else ""
        return KronikError("send-now.denied", "sending now denied", detail, explain_topic(detail, "capability"), payload)
    return KronikError("send-now.unknown", "sending now failed", repr(payload), "connections", payload)
