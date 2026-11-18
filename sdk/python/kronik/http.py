# HTTP for actors: the incoming request, messages, outgoing responses and
# secret handles, and body encoding. No host calls here.

import json as _json
from dataclasses import dataclass
from urllib.parse import unquote_plus

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


BLOB_CALL_BYTES = 1 << 20
"""The most bytes one blob call moves: 1 MiB."""

BLOB_FRAME_BYTES = 1 << 16
"""A blob's frame: the store reads and checks whole frames, and a read is
charged for every frame it touches, so readers fetch whole frames."""


@dataclass(frozen=True)
class BlobRef:
    """A blob: a large body kept outside the log and named by its hash (see
    `kronik explain blob`). A handler gets one as `req.blob` or `res.blob`, in
    a message's `blobs`, from `ctx.blobs.writer().finish()` or
    `ctx.blobs.put`, and may use it in the turn that got it: read it
    (`ctx.blobs`), answer with it (`ctx.blob`), send it
    (`ctx.http.fetch(url, body=blob)`, a message's "blobs"), or hold it for
    later turns (`ctx.blobs.retain`). `hash` is `b3:<hex>`, or `b3s:<hex>` for
    a data subject's blob; `size` its size in bytes."""

    hash: str
    size: int


def _split_body(body):
    """An HTTP body's (inline bytes, None) or (None, BlobRef)."""
    value = body.value
    if isinstance(value, _BYTES):
        return bytes(value), None
    return None, BlobRef(value.hash, value.size)


def _whole(blob, read, what):
    if read is None:
        raise KronikError("blob", f"{what} is a blob that this value cannot read", "", "blob")
    return read(blob)


def _header(headers, name):
    lower = name.lower()
    return next((v for n, v in headers if n.lower() == lower), None)


def _percent_decode(value):
    """`%XX` and `+` (a space). A malformed `%` stays. None if not UTF-8."""
    # parse_qsl replaces invalid UTF-8, and strict mode fails the whole query.
    try:
        return unquote_plus(value, errors="strict")
    except UnicodeDecodeError:
        return None


class Request:
    """An HTTP request routed to the actor by one of its manifest's routes.

    `query` is the raw query string without `?`, `params` the route
    parameters (such as `key` for `/notes/{key}`), `headers` a list of
    `(name, value)`, `body` the body's bytes, and `blob` the body's BlobRef
    when the gateway stored a large body as one (else None).
    """

    def __init__(self, req, read=None):
        self.method = req.method
        self.path = req.path
        self.query = req.query
        self.params = dict(req.params)
        self.headers = [(h.name, h.value) for h in req.headers]
        self._inline, self.blob = _split_body(req.body)
        self._read = read

    @property
    def body(self):
        """The body's bytes. A blob body is read on first use, whole, within the
        guest's memory limit (64 MiB by default); read a larger one in parts with
        `ctx.blobs.reader(req.blob)`."""
        if self._inline is None:
            self._inline = _whole(self.blob, self._read, "the request body")
        return self._inline

    def param(self, name):
        """The route parameter `name`, or None."""
        return self.params.get(name)

    def query_param(self, name):
        """The first query parameter called `name`, percent-decoded (`+` is a space), or None.

        A malformed `%` stays and `;` is data. None if it is missing or not UTF-8.
        """
        for pair in self.query.split("&"):
            raw_name, _, raw_value = pair.partition("=")
            if _percent_decode(raw_name) == name:
                return _percent_decode(raw_value)
        return None

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
    """A message from another actor or the operator; `sender` is the sending
    actor, if an actor sent it. `blobs` are the BlobRefs it carries (M26): the
    turn may read them, and holds one only if it retains it."""

    def __init__(self, msg, sender=None):
        self.name = msg.name
        self.content_type = msg.content_type
        self.body = msg.body
        self.sender = sender
        self.blobs = [BlobRef(blob.hash, blob.size) for blob in (getattr(msg, "blobs", None) or ())]

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
    """The response to `ctx.http.fetch`: `status`, `headers` as `(name, value)`,
    `body` bytes, and `blob` the body's BlobRef when the host stored a large
    response as one (else None)."""

    def __init__(self, res, read=None):
        self.status = res.status
        self.headers = list(res.headers)
        self._inline, self.blob = _split_body(res.body)
        self._read = read

    @property
    def body(self):
        """The body's bytes. A blob body is read on first use, whole, within the
        guest's memory limit; read a larger one with `ctx.blobs.reader(res.blob)`."""
        if self._inline is None:
            self._inline = _whole(self.blob, self._read, "the response body")
        return self._inline

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
