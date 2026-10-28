# HTTP for actors: the incoming request, messages, outgoing responses and
# secret handles, and body encoding. No host calls here.

import json as _json
from dataclasses import dataclass
from urllib.parse import parse_qsl

from .errors import KronikError

_BYTES = (bytes, bytearray, memoryview)


def to_json(value):
    """JSON text for `value`, as JavaScript's JSON.stringify writes it: no spaces, non-ASCII as is.
    NaN and infinities are an error (they are not JSON)."""
    return _json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def encode_body(body):
    """Encodes a body: bytes as they are, a str as UTF-8, anything else as JSON. Returns (bytes, content type)."""
    if isinstance(body, _BYTES):
        return bytes(body), "application/octet-stream"
    if isinstance(body, str):
        return body.encode(), "text/plain; charset=utf-8"
    return to_json(body).encode(), "application/json"


def text(data, what, topic):
    """`data` as UTF-8 text; raises a KronikError naming `what` if it is not."""
    try:
        return data.decode()
    except UnicodeDecodeError:
        raise KronikError("utf8", f"{what} is not UTF-8", "", topic) from None


def parse_json(data, what, topic):
    """`data` parsed as JSON; raises a KronikError naming `what` if it is not JSON."""
    source = text(data, what, topic)
    try:
        return _json.loads(source, parse_constant=_no_constant)
    except ValueError as e:
        raise KronikError("json", f"{what} is not the expected JSON", str(e), topic) from None


def _inline(body):
    # A blob body (from M25) is empty here.
    return body.value if isinstance(body.value, bytes) else b""


def _header(headers, name):
    lower = name.lower()
    return next((v for n, v in headers if n.lower() == lower), None)


class Request:
    """An HTTP request routed to the actor by one of its manifest's routes.

    `query` is the raw query string without `?`, `params` the route
    parameters (such as `key` for `/notes/{key}`), `headers` a list of
    `(name, value)`, `body` the body's bytes.
    """

    def __init__(self, req):
        self.method = req.method
        self.path = req.path
        self.query = req.query
        self.params = dict(req.params)
        self.headers = [(h.name, h.value) for h in req.headers]
        self.body = _inline(req.body)

    def param(self, name):
        """The route parameter `name`, or None."""
        return self.params.get(name)

    def query_param(self, name):
        """The first query parameter called `name`, decoded, or None."""
        return next((v for n, v in parse_qsl(self.query, keep_blank_values=True) if n == name), None)

    def header(self, name):
        """The first header called `name`, ignoring case, or None."""
        return _header(self.headers, name)

    def text(self):
        """The body as UTF-8 text."""
        return text(self.body, "the request body", "message")

    def json(self):
        """The body parsed as JSON."""
        return parse_json(self.body, "the request body", "message")


class Message:
    """A message from another actor or the operator; `sender` is the sending actor, if an actor sent it."""

    def __init__(self, msg, sender=None):
        self.name = msg.name
        self.content_type = msg.content_type
        self.body = msg.body
        self.sender = sender

    def text(self):
        """The body as UTF-8 text."""
        return text(self.body, "the message body", "message")

    def json(self):
        """The body parsed as JSON."""
        return parse_json(self.body, "the message body", "message")


@dataclass
class Timer:
    """A timer this actor scheduled, arriving as an input."""

    id: int
    message: Message


@dataclass(frozen=True)
class SecretHeader:
    """A header value made from a secret by the host; see Secret.header."""

    secret: str
    template: str


@dataclass(frozen=True)
class Secret:
    """A handle to a secret: its name, never its value (see `kronik explain
    secret-handle`). The host inserts the value at the effect boundary."""

    name: str

    def header(self, template="Bearer {}"):
        """A header value the host makes from this secret: `{}` in `template` is replaced by the value."""
        return SecretHeader(self.name, template)


class FetchResponse:
    """The response to `ctx.http.fetch`: `status`, `headers` as `(name, value)`, `body` bytes."""

    def __init__(self, res):
        self.status = res.status
        self.headers = list(res.headers)
        self.body = _inline(res.body)

    @property
    def ok(self):
        """Whether the status is 2xx."""
        return 200 <= self.status < 300

    def header(self, name):
        """The first header called `name`, ignoring case, or None."""
        return _header(self.headers, name)

    def text(self):
        """The body as UTF-8 text."""
        return text(self.body, "the response body", "effect")

    def json(self):
        """The body parsed as JSON."""
        return parse_json(self.body, "the response body", "effect")
