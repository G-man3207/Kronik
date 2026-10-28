# The turn's access to the host. Every method is a synchronous host call
# through `h`, the componentize-py bindings (kronik/_host.py), passed in so
# this module imports outside a component too.
#
# A message to send is a dict like TypeScript's: {"name": ..., "body": ...,
# "content_type": ...}; the body (bytes, str, or a value as JSON) and the
# content type (default: what follows from the body) are optional.

from .errors import host_error
from .http import FetchResponse, Message, Secret, SecretHeader, encode_body, parse_json, text, to_json
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
    """An outgoing message dict as a WIT message."""
    body, content_type = encode_body(msg["body"]) if "body" in msg else (b"", "")
    return types.Message(msg["name"], msg.get("content_type", content_type), body, [])


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

    def __init__(self, h):
        self._h = h

    def fetch(self, request):
        """Sends `request` and waits for the FetchResponse.

        `request` is a dict: `url`, and optionally `method` (default GET),
        `headers` (name to str, or a SecretHeader from `ctx.secret(name).header()`)
        and `body` (bytes, str, or a value sent as JSON, which also sets content-type).
        """
        hc = self._h.http_client
        headers = []
        has_content_type = False
        for name, value in (request.get("headers") or {}).items():
            has_content_type = has_content_type or name.lower() == "content-type"
            if isinstance(value, SecretHeader):
                value = hc.HeaderValue_Secret(hc.SecretTemplate(value.secret, value.template))
            else:
                value = hc.HeaderValue_Text(value)
            headers.append(hc.RequestHeader(name, value))
        body = b""
        if "body" in request:
            body, content_type = encode_body(request["body"])
            if not has_content_type:
                headers.append(hc.RequestHeader("content-type", hc.HeaderValue_Text(content_type)))
        req = hc.Request(request.get("method") or "GET", request["url"], headers, self._h.types.HttpBody_Inline(body))
        try:
            return FetchResponse(hc.fetch(req))
        except self._h.Err as e:
            raise host_error("fetch", e.value) from None


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
    `causal_id`, `secret`, `subject`, `log`) and helpers for outputs."""

    def __init__(self, h):
        self._h = h
        self.state = State(h)
        self.log = Log(h)
        self.sql = Sql(h, self.log)
        self.http = Http(h)
        self.crypto = Crypto(h)
        self.secrets = Secrets(h)
        self.timers = Timers(h)
        self.random = Random(h)

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

    def status(self, status):
        """An HTTP response with no body, such as 404."""
        return self._http(status, None, b"")

    def reply(self, msg):
        """A reply message (an HTTP request gets 200 with its body)."""
        return self._h.types.Output_Reply(wit_message(msg, self._h.types))

    def none(self):
        """No output (an HTTP request gets 204)."""
        return self._h.types.Output_None_()
