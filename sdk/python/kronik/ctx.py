# The turn's access to the host. Every method is a synchronous host call
# through `h`, the componentize-py bindings (kronik/_host.py), passed in so
# this module imports outside a component too.
#
# A message to send is a dict like TypeScript's: {"name": ..., "body": ...,
# "content_type": ...}; the body (bytes, str, or a value as JSON) and the
# content type (default: what follows from the body) are optional.

import io

from .connections import send_now_failure, to_wit_frame
from .errors import KronikError, host_error
from .http import BLOB_CALL_BYTES, BLOB_FRAME_BYTES, BlobRef, FetchResponse, Message, Secret, SecretHeader, encode_body, parse_json, text, to_json
from .sql import SqlRows, has_order_by, to_sql


def _utf8(value):
    """A str as UTF-8, bytes as they are. Anything else is an error: bytes(3)
    would be three NUL bytes."""
    if isinstance(value, str):
        return value.encode()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"expected str or bytes, not {type(value).__name__} (use set_json for other values)")


def _name(secret):
    return secret if isinstance(secret, str) else secret.name


def actor_ref(actor, types):
    """`actor` ("kind/key", or anything with `kind` and `key`) as a WIT actor-ref."""
    if not isinstance(actor, str):
        return types.ActorRef(actor.kind, actor.key)
    kind, slash, key = actor.partition("/")
    if not kind or not slash or not key:
        raise ValueError(f"{to_json(actor)} is not an actor: expected kind/key (see `kronik explain actor`)")
    return types.ActorRef(kind, key)


def wit_message(msg, types):
    """An outgoing message dict as a WIT message: `name`, and optionally
    `body`, `content_type` and `blobs` (BlobRefs that travel with it, M26)."""
    body, content_type = encode_body(msg["body"]) if "body" in msg else (b"", "")
    blobs = [types.BlobRef(blob.hash, blob.size) for blob in msg.get("blobs", ())]
    return types.Message(msg["name"], msg.get("content_type", content_type), body, blobs)


class State:
    """The actor's key-value state. Writes apply only if the turn commits."""

    def __init__(self, h):
        self._h = h

    def get(self, key):
        """The value of `key` as bytes, or None."""
        return self._h.state.get(key)

    def get_text(self, key):
        """The value of `key` as UTF-8 text, or None."""
        value = self._h.state.get(key)
        return None if value is None else text(value, f"state value {to_json(key)}", "actor")

    def get_json(self, key):
        """The value of `key` parsed as JSON, or None."""
        value = self._h.state.get(key)
        return None if value is None else parse_json(value, f"state value {to_json(key)}", "actor")

    def set(self, key, value):
        """Sets `key` (bytes, or str as UTF-8), tagged with the turn's default subject."""
        self._h.state.set(key, _utf8(value))

    def set_json(self, key, value):
        """Sets `key` to `value` as JSON, tagged with the turn's default subject."""
        self._h.state.set(key, to_json(value).encode())

    def set_for(self, subject, key, value):
        """Sets `key` tagged with `subject` (None: no subject), whatever the turn's default subject is."""
        self._h.state.set_for(subject, key, _utf8(value))

    def delete(self, key):
        """Deletes `key`."""
        self._h.state.delete(key)

    def keys(self, prefix=""):
        """The keys that start with `prefix`."""
        return self._h.state.keys(prefix)


class Sql:
    """The actor's own SQLite database (see `kronik explain sql-state`). DDL is
    allowed only in `migrate`, before the first statement that changes data;
    `datetime('now')`, `random()` and `randomblob()` are deterministic, and
    `kronik_subject()` gives the turn's default subject."""

    def __init__(self, h, log):
        self._h = h
        self._log = log

    def query(self, statement, params=()):
        """Runs a query and returns its SqlRows. A query without ORDER BY that
        returns several rows logs a warning: their order then depends on SQLite's plan."""
        sql = self._h.sql
        try:
            rows = sql.query(statement, [to_sql(p, sql) for p in params])
        except self._h.Err as e:
            raise host_error("sql", e.value) from None
        if len(rows.values) > 1 and not has_order_by(statement):
            self._log.warn(
                "a query returned several rows without ORDER BY, so their order is not guaranteed (see `kronik explain sql-state`)",
                {"rows": len(rows.values), "statement": statement},
            )
        return SqlRows(rows)

    def execute(self, statement, params=()):
        """Runs a statement that returns no rows and returns how many rows it changed."""
        sql = self._h.sql
        try:
            return sql.execute(statement, [to_sql(p, sql) for p in params])
        except self._h.Err as e:
            raise host_error("sql", e.value) from None


class Http:
    """Outgoing HTTP, recorded as effects (see `kronik explain effect`). Needs the capability `http:<host>`."""

    def __init__(self, h, blobs):
        self._h = h
        self._blobs = blobs

    def fetch(self, request, **fields):
        """Sends a request and waits for the FetchResponse.

        `request` is a dict, or the URL with the other fields as keywords
        (`fetch(url, method="POST", body=b)`): `url`, and optionally `method`
        (default GET), `headers` (name to str, or a SecretHeader from
        `ctx.secret(name).header()`) and `body` (bytes, str, a value sent as JSON,
        which also sets content-type, or a BlobRef, streamed from the blob store
        as `application/octet-stream` unless the headers say otherwise).
        """
        if isinstance(request, str):
            request = dict(fields, url=request)
        elif fields:
            raise TypeError("fetch takes a dict, or a URL and keywords, not both")
        hc = self._h.http_client
        types = self._h.types
        headers = []
        has_content_type = False
        for name, value in (request.get("headers") or {}).items():
            has_content_type = has_content_type or name.lower() == "content-type"
            if isinstance(value, SecretHeader):
                value = hc.HeaderValue_Secret(hc.SecretTemplate(value.secret, value.template))
            else:
                value = hc.HeaderValue_Text(value)
            headers.append(hc.RequestHeader(name, value))
        body = types.HttpBody_Inline(b"")
        if isinstance(request.get("body"), BlobRef):
            blob = request["body"]
            body = types.HttpBody_Blob(types.BlobRef(blob.hash, blob.size))
            if not has_content_type:
                headers.append(hc.RequestHeader("content-type", hc.HeaderValue_Text("application/octet-stream")))
        elif "body" in request:
            data, content_type = encode_body(request["body"])
            body = types.HttpBody_Inline(data)
            if not has_content_type:
                headers.append(hc.RequestHeader("content-type", hc.HeaderValue_Text(content_type)))
        req = hc.Request(request.get("method") or "GET", request["url"], headers, body)
        try:
            return FetchResponse(hc.fetch(req), self._blobs.read_all)
        except self._h.Err as e:
            raise host_error("fetch", e.value) from None


class Blobs:
    """The turn's blobs (see `kronik explain blob`): read the ones the turn may
    use (its request's or a fetch response's body, a message's blobs, the ones
    it wrote and the ones its actor holds), in ranges or with a reader, write
    new ones, and hold them across turns (`put`, `retain`, `release`, M26).
    The host checks every call (`BLOB_NOT_HELD`)."""

    def __init__(self, h):
        self._h = h

    def _get(self, blob, offset, n):
        try:
            return bytes(self._h.blobs.get(self._h.types.BlobRef(blob.hash, blob.size), offset, n))
        except self._h.Err as e:
            raise host_error("blob", e.value) from None

    def get(self, blob, offset, n):
        """Up to `n` bytes of `blob` from `offset`: fewer only at its end, none at
        or past it. One host call moves at most 1 MiB; this makes as many as `n`
        needs."""
        if offset < 0 or n < 0:
            raise KronikError("blob.range", f"no such range of a blob: offset {offset}, length {n}", "", "blob")
        end = min(blob.size, offset + n)
        parts = []
        at = offset
        while at < end:
            chunk = self._get(blob, at, min(BLOB_CALL_BYTES, end - at))
            if not chunk:
                break
            parts.append(chunk)
            at += len(chunk)
        return b"".join(parts)

    def read_all(self, blob):
        """The whole blob: a lazy body. It must fit in the guest's memory (64 MiB by default)."""
        return self.get(blob, 0, blob.size)

    def reader(self, blob):
        """A seekable binary file (`io.RawIOBase`) that reads `blob`; wrap it in
        `io.BufferedReader` to read lines."""
        return BlobReader(self, blob)

    def writer(self):
        """A writer of a new blob, tagged with the turn's default subject:
        `write()` its bytes, then `finish()` to get the BlobRef, which the turn
        may use as a response or fetch body."""
        return BlobWriter(self._h, self._h.blobs.Writer())

    def put(self, data):
        """Stores `data` (bytes, or a str as UTF-8) as a blob tagged with the
        turn's default subject; the actor holds it once the turn commits. One
        host call takes at most 1 MiB: a larger value is written in parts and
        then retained, which is the same. Returns its BlobRef."""
        data = data.encode() if isinstance(data, str) else bytes(data)
        if len(data) > BLOB_CALL_BYTES:
            writer = self.writer()
            writer.write(data)
            blob = writer.finish()
            self.retain(blob)
            return blob
        try:
            blob = self._h.blobs.put(data)
        except self._h.Err as e:
            raise host_error("blob", e.value) from None
        return BlobRef(blob.hash, blob.size)

    def put_for(self, subject, data):
        """`put` tagged with `subject` (None: none), whatever the turn's default
        subject is; the default is restored afterwards, also when the put
        fails."""
        before = self._h.privacy.current_subject()
        self._h.privacy.set_subject(subject)
        try:
            return self.put(data)
        finally:
            self._h.privacy.set_subject(before)

    def retain(self, blob):
        """Holds `blob` from the turn's commit on: one the turn may use, such as
        a request body, a fetch response or one that a message brought. A blob
        the actor already holds stays held."""
        try:
            self._h.blobs.retain(self._h.types.BlobRef(blob.hash, blob.size))
        except self._h.Err as e:
            raise host_error("blob", e.value) from None

    def release(self, blob):
        """Ends the actor's hold on `blob` at the turn's commit; the turn can
        still read it. Only a hold of this actor's own ends; a blob nothing
        holds any more is deleted later by collection."""
        try:
            self._h.blobs.release(self._h.types.BlobRef(blob.hash, blob.size))
        except self._h.Err as e:
            raise host_error("blob", e.value) from None


class BlobReader(io.RawIOBase):
    """Reads one blob as a seekable binary file; see Blobs.reader. It fetches
    whole 64 KiB frames (a read is charged for every frame it touches) and
    serves small reads from the last ones it fetched."""

    def __init__(self, blobs, blob):
        super().__init__()
        self._blobs = blobs
        self.blob = blob
        self._pos = 0
        self._block_at = 0
        self._block = b""

    def readable(self):
        return True

    def seekable(self):
        return True

    def readinto(self, b):
        view = memoryview(b).cast("B")
        if not view or self._pos >= self.blob.size:
            return 0
        rel = self._pos - self._block_at
        if not 0 <= rel < len(self._block):
            self._block_at = self._pos - self._pos % BLOB_FRAME_BYTES
            want = self._pos - self._block_at + len(view)
            want = min(BLOB_CALL_BYTES, -(-want // BLOB_FRAME_BYTES) * BLOB_FRAME_BYTES)
            self._block = self._blobs._get(self.blob, self._block_at, want)
            rel = self._pos - self._block_at
            if rel >= len(self._block):
                return 0
        n = min(len(view), len(self._block) - rel)
        view[:n] = self._block[rel : rel + n]
        self._pos += n
        return n

    def seek(self, offset, whence=io.SEEK_SET):
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: self.blob.size}[whence]
        if base + offset < 0:
            raise ValueError("negative seek position")
        self._pos = base + offset
        return self._pos

    def tell(self):
        return self._pos


class BlobWriter:
    """Writes one blob in parts; `finish()` ends it and returns its BlobRef.
    Bytes go to the host as whole 64 KiB frames (calls of at most 1 MiB);
    what is short of a frame waits for the next write or `finish()`."""

    def __init__(self, h, writer):
        self._h = h
        self._writer = writer
        self._pending = b""

    def _send(self, data):
        for at in range(0, len(data), BLOB_CALL_BYTES):
            try:
                self._writer.write(data[at : at + BLOB_CALL_BYTES])
            except self._h.Err as e:
                raise host_error("blob", e.value) from None

    def write(self, data):
        """Appends bytes, or a str as UTF-8, of any length; returns how many bytes."""
        data = data.encode() if isinstance(data, str) else bytes(data)
        n = len(data)
        if self._pending:
            data = self._pending + data
        whole = len(data) - len(data) % BLOB_FRAME_BYTES
        self._send(data[:whole])
        self._pending = data[whole:]
        return n

    def finish(self):
        """Ends the blob and returns its BlobRef; the writer takes no more bytes."""
        self._send(self._pending)
        self._pending = b""
        try:
            blob = self._writer.finish()
        except self._h.Err as e:
            raise host_error("blob", e.value) from None
        return BlobRef(blob.hash, blob.size)


class Crypto:
    """Crypto computed by the host with a secret's value; needs the capability `secret:<name>`."""

    def __init__(self, h):
        self._h = h

    def hmac_sha256(self, secret, data):
        """HMAC-SHA256 of `data` (bytes or str) keyed with `secret` (a Secret or its name)."""
        try:
            return self._h.crypto.hmac_sha256(_name(secret), _utf8(data))
        except self._h.Err as e:
            raise host_error("crypto", e.value) from None

    def sign_ed25519(self, secret, data):
        """An Ed25519 signature of `data` with the private key `secret`."""
        try:
            return self._h.crypto.sign_ed25519(_name(secret), _utf8(data))
        except self._h.Err as e:
            raise host_error("crypto", e.value) from None


class Secrets:
    """Revealing secrets: the exception path, behind the capability `secret-reveal:<name>`."""

    def __init__(self, h):
        self._h = h

    def reveal(self, secret):
        """The value of `secret` inside the guest. Prefer secret headers and `ctx.crypto`."""
        try:
            return self._h.secrets.reveal(_name(secret))
        except self._h.Err as e:
            raise host_error("reveal", e.value) from None


class Timers:
    """Timers that deliver a message to this actor later. Registered only if the turn commits."""

    def __init__(self, h):
        self._h = h

    def schedule(self, delay_ms, msg):
        """Schedules `msg` to arrive as a timer input after `delay_ms`; returns the timer's id."""
        return self._h.timers.schedule(max(0, int(delay_ms)), wit_message(msg, self._h.types))

    def cancel(self, id):
        """Cancels the timer `id`; returns whether it was pending."""
        return self._h.timers.cancel(id)


class ConnectionOps:
    """The WebSocket and SSE connections this actor accepted: `ctx.connections`
    (see `kronik explain connections`). Only the actor whose open accepted a
    connection sends on it or closes it. A frame to an id that is not a live
    connection of this actor (it closed, was never accepted, or another actor
    holds it) is recorded as dropped and never delivered, and shows in the
    history; closing it does nothing, and send_now returns False. To reach
    another actor's clients, send that actor a message. A frame is a Frame,
    a str (text) or bytes (binary)."""

    def __init__(self, h):
        self._h = h

    def send(self, connection, frame):
        """Sends `frame` to `connection` when this turn commits, in call order; nothing if the turn fails."""
        c = self._h.connections
        c.send(connection, to_wit_frame(frame, c))

    def broadcast(self, connections, frame):
        """send() to each of `connections`, recorded once: the way to fan a message out."""
        c = self._h.connections
        c.broadcast(list(connections), to_wit_frame(frame, c))

    def close(self, connection, code=1000, reason=""):
        """Closes `connection` when this turn commits, after the frames sent before:
        a WebSocket with `code` and `reason`, an SSE stream by ending it. Its close input still follows."""
        self._h.connections.close(connection, code, reason)

    def send_now(self, connection, frame):
        """Sends `frame` now, before this turn commits, for intermediate results
        such as the tokens of a streamed answer; use send() for final notices.
        An effect with delivery class `unsafe` that needs the capability
        `connection:send-now`. True when the frame was handed to the connection
        (not that the client received it), False when the connection is closed
        or its client does not keep up. Raises OutcomeUnknown when a crash made
        the outcome unknown: a frame is never sent twice. Frames sent now go out
        before the turn's send() frames."""
        c = self._h.connections
        try:
            c.send_now(connection, to_wit_frame(frame, c))
            return True
        except self._h.Err as e:
            failure = send_now_failure(e.value)
            if failure is False:
                return False
            raise failure from None


class Random:
    """Randomness from the turn's recorded seed: a replay gets the same values."""

    def __init__(self, h):
        self._h = h

    def bytes(self, length):
        """`length` random bytes (at most 1 MiB)."""
        return self._h.context.random_bytes(length)

    def u64(self):
        """A random unsigned 64-bit integer."""
        return int.from_bytes(self._h.context.random_bytes(8), "little")


class Log:
    """The actor's log. The host adds the turn's ids to every event."""

    def __init__(self, h):
        self._h = h

    def emit(self, level, message, fields=None):
        """Logs `message` at `level` ("trace" to "error") with `fields` (values that are not str as JSON)."""
        log = self._h.log
        pairs = [(k, v if isinstance(v, str) else to_json(v)) for k, v in (fields or {}).items()]
        log.emit(log.Level[level.upper()], message, pairs)

    def trace(self, message, fields=None):
        self.emit("trace", message, fields)

    def debug(self, message, fields=None):
        self.emit("debug", message, fields)

    def info(self, message, fields=None):
        self.emit("info", message, fields)

    def warn(self, message, fields=None):
        self.emit("warn", message, fields)

    def error(self, message, fields=None):
        self.emit("error", message, fields)


class Ctx:
    """A turn's access to the host: the names Kronik's SDKs share (`state`,
    `sql`, `send`, `call`, `http.fetch`, `crypto`, `timers`, `now`, `random`,
    `causal_id`, `secret`, `subject`, `log`, `blobs`) and helpers for outputs."""

    def __init__(self, h):
        self._h = h
        self.state = State(h)
        self.log = Log(h)
        self.sql = Sql(h, self.log)
        self.blobs = Blobs(h)
        self.http = Http(h, self.blobs)
        self.crypto = Crypto(h)
        self.secrets = Secrets(h)
        self.timers = Timers(h)
        self.random = Random(h)
        self.connections = ConnectionOps(h)

    def send(self, to, msg):
        """Sends a message to `to`: buffered, delivered exactly once, only if this turn commits."""
        types = self._h.types
        self._h.messaging.send(actor_ref(to, types), wit_message(msg, types))

    def call(self, to, msg, compensate=None):
        """Calls `to` and returns its reply Message (or None). The callee commits
        its own turn now; if this turn fails afterwards, `compensate` is delivered to it once."""
        types = self._h.types
        comp = None if compensate is None else wit_message(compensate, types)
        try:
            reply = self._h.messaging.call(actor_ref(to, types), wit_message(msg, types), comp)
        except self._h.Err as e:
            raise host_error("call", e.value) from None
        return None if reply is None else Message(reply)

    def now(self):
        """The turn's logical time in milliseconds since the Unix epoch: constant within the turn and recorded."""
        return self._h.context.now_ms()

    def causal_id(self):
        """The turn's correlation id, the same in production and in replay."""
        return self._h.context.causal_id()

    def self(self):
        """This actor, with `kind` and `key`."""
        return self._h.context.self_ref()

    def secret(self, name):
        """A handle to the secret `name`; its value never enters the guest."""
        return Secret(name)

    def subject(self, subject):
        """Sets the default subject (such as "user:123") for values written from now on; None: none."""
        self._h.privacy.set_subject(subject)

    def current_subject(self):
        """The current default subject, or None."""
        return self._h.privacy.current_subject()

    def accept(self, subprotocol=None, headers=None, subject=None):
        """Accepts the connection the current open asks for: return it from the
        open handler. `subprotocol` is one the client offered (WebSocket only),
        `headers` a dict of extra response headers, `subject` the subject of the
        connection's later inputs (by default the request's). Returning an HTTP
        response instead (`ctx.status(403)`) refuses the connection."""
        c, t = self._h.connections, self._h.types
        return c.OpenReply_Accept(c.Accept(subprotocol, [t.Header(n, v) for n, v in (headers or {}).items()], subject))

    def _http(self, status, content_type, body):
        t = self._h.types
        headers = [t.Header("content-type", content_type)] if content_type else []
        return t.Output_Http(t.HttpResponse(status, headers, t.HttpBody_Inline(body)))

    def json(self, status, value):
        """An HTTP response with `value` as a JSON body."""
        return self._http(status, "application/json", to_json(value).encode())

    def text(self, status, body):
        """An HTTP response with a text body."""
        return self._http(status, "text/plain; charset=utf-8", body.encode())

    def blob(self, status, blob, content_type="application/octet-stream"):
        """An HTTP response whose body is `blob` (one the turn got or wrote): the
        gateway streams it from the blob store."""
        t = self._h.types
        body = t.HttpBody_Blob(t.BlobRef(blob.hash, blob.size))
        return t.Output_Http(t.HttpResponse(status, [t.Header("content-type", content_type)], body))

    def status(self, status):
        """An HTTP response with no body, such as 404."""
        return self._http(status, None, b"")

    def reply(self, msg):
        """A reply message (an HTTP request gets 200 with its body)."""
        return self._h.types.Output_Reply(wit_message(msg, self._h.types))

    def none(self):
        """No output (an HTTP request gets 204)."""
        return self._h.types.Output_None_()
