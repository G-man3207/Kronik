# Host-side tests of the SDK's pure parts, with fakes for the componentize-py bindings.

import pathlib
import sys
import unittest
from dataclasses import dataclass
from types import SimpleNamespace

SDK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SDK))

from enum import Enum  # noqa: E402

from kronik import Connections, Frame, KronikError, OutcomeUnknown, Rejected, Route, actor  # noqa: E402
from kronik._export import connection_closed, connection_frame, handle, open_connection  # noqa: E402
from kronik.connections import IncomingFrame, OpenRequest, closed_of, send_now_failure, to_wit_frame  # noqa: E402
from kronik.ctx import actor_ref, wit_message  # noqa: E402
from kronik.errors import explain_topic, host_error, variant_tag  # noqa: E402
from kronik.http import Request, encode_body, parse_json, to_json  # noqa: E402
from kronik.sql import SqlRows, from_sql, has_order_by, to_sql  # noqa: E402


def _variant(name, *fields):
    return dataclass(type(name, (), {"__annotations__": {f: object for f in fields}}))


class Err(Exception):
    def __init__(self, value):
        self.value = value


FetchError_OutcomeUnknown = _variant("FetchError_OutcomeUnknown")
FetchError_Denied = _variant("FetchError_Denied", "value")
SqlError_TooLarge = _variant("SqlError_TooLarge")
CallError_NotFound = _variant("CallError_NotFound")

types = SimpleNamespace(
    **{n: _variant(n, "value") for n in ["Input_Http", "Input_Message", "Input_Timer", "Input_Migrate", "Output_Reply", "Output_Http", "HandlerError_Rejected", "HandlerError_Failed"]},
    Output_None_=_variant("Output_None_"),
    ActorRef=_variant("ActorRef", "kind", "key"),
    Message=_variant("Message", "name", "content_type", "body", "blobs"),
    Header=_variant("Header", "name", "value"),
    HttpResponse=_variant("HttpResponse", "status", "headers", "body"),
    HttpBody_Inline=_variant("HttpBody_Inline", "value"),
    HttpRequest=_variant("HttpRequest", "method", "path", "query", "params", "headers", "body"),
    Incoming=_variant("Incoming", "sender", "msg"),
)
sql = SimpleNamespace(**{n: _variant(n, "value") for n in ["SqlValue_Integer", "SqlValue_Real", "SqlValue_Text", "SqlValue_Blob"]}, SqlValue_Null=_variant("SqlValue_Null"))


def fake_host(writes):
    return SimpleNamespace(
        types=types,
        Err=Err,
        state=SimpleNamespace(get=lambda k: None, set=lambda k, v: writes.append((k, v))),
        context=SimpleNamespace(self_ref=lambda: types.ActorRef("counter", "alice")),
    )


def http_input(method="POST", query="", body=b""):
    req = types.HttpRequest(method, "/x", query, [("key", "alice")], [types.Header("Content-Type", "text/plain")], types.HttpBody_Inline(body))
    return types.Input_Http(req)


class Protocol(Enum):
    WEBSOCKET = 0
    SSE = 1


class CloseInitiator(Enum):
    CLIENT = 0
    ACTOR = 1
    HOST = 2


conn = SimpleNamespace(
    **{n: _variant(n, "value") for n in ["Frame_Text", "Frame_Binary", "Frame_Event", "OpenReply_Accept", "OpenReply_Refuse", "SendError_Denied"]},
    SendError_Closed=_variant("SendError_Closed"),
    SendError_OutcomeUnknown=_variant("SendError_OutcomeUnknown"),
    SseEvent=_variant("SseEvent", "event", "id", "data"),
    Accept=_variant("Accept", "subprotocol", "headers", "subject"),
    OpenRequest=_variant("OpenRequest", "connection", "protocol", "request", "subprotocols"),
    IncomingFrame=_variant("IncomingFrame", "connection", "seq", "frame"),
    CloseInfo=_variant("CloseInfo", "initiator", "code", "reason"),
    Closed=_variant("Closed", "connection", "info"),
    Protocol=Protocol,
    CloseInitiator=CloseInitiator,
)


def connection_host(calls, send_now_error=None):
    """A fake host whose connections functions record their calls."""

    def send_now(c, frame):
        calls.append(("send_now", c, frame))
        if send_now_error is not None:
            raise Err(send_now_error)

    h = fake_host([])
    h.connections = SimpleNamespace(
        **vars(conn),
        send=lambda c, frame: calls.append(("send", c, frame)),
        broadcast=lambda cs, frame: calls.append(("broadcast", cs, frame)),
        close=lambda c, code, reason: calls.append(("close", c, code, reason)),
        send_now=send_now,
    )
    return h


def open_request(query="user=ada", headers=()):
    req = types.HttpRequest("GET", "/chat/lobby/ws", query, [("key", "lobby")], [types.Header(n, v) for n, v in headers], types.HttpBody_Inline(b""))
    return conn.OpenRequest("c-0123", Protocol.WEBSOCKET, req, ["chat.v1"])


class ErrorsTest(unittest.TestCase):
    def test_explain_topic_takes_a_leading_error_code(self):
        self.assertEqual(explain_topic("CAPABILITY_NOT_GRANTED: http:x", "capability"), "CAPABILITY_NOT_GRANTED")
        self.assertEqual(explain_topic("near SELEC: syntax error", "sql-state"), "sql-state")
        self.assertEqual(explain_topic("NO_COLON", "effect"), "effect")

    def test_variant_tag_is_the_wit_case(self):
        self.assertEqual(variant_tag(FetchError_OutcomeUnknown()), "outcome-unknown")
        self.assertEqual(variant_tag(CallError_NotFound()), "not-found")
        self.assertEqual(variant_tag(SqlError_TooLarge()), "too-large")

    def test_host_errors_point_at_kronik_explain(self):
        e = host_error("fetch", FetchError_Denied("CAPABILITY_NOT_GRANTED: http:x.example.com"))
        self.assertEqual(e.kind, "fetch.denied")
        self.assertEqual(str(e), "HTTP request denied: CAPABILITY_NOT_GRANTED: http:x.example.com (see `kronik explain CAPABILITY_NOT_GRANTED`)")
        e = host_error("fetch", FetchError_OutcomeUnknown())
        self.assertEqual(str(e), "the HTTP request may or may not have reached its target (see `kronik explain EFFECT_OUTCOME_UNKNOWN`)")
        self.assertEqual(host_error("call", CallError_NotFound()).topic, "ACTOR_NOT_FOUND")
        self.assertEqual(host_error("reveal", "SECRET_NOT_FOUND: x").topic, "SECRET_NOT_FOUND")
        self.assertEqual(host_error("sql", object()).kind, "sql.unknown")


class BodyTest(unittest.TestCase):
    def test_to_json_writes_like_json_stringify(self):
        self.assertEqual(to_json({"n": 1, "s": "å", "l": [None, True]}), '{"n":1,"s":"å","l":[null,true]}')

    def test_json_has_no_nan_or_infinity(self):
        # Review M15 N5: NaN and infinities are not JSON, either way.
        for value in [float("nan"), float("inf"), {"x": float("-inf")}]:
            with self.assertRaises(ValueError):
                to_json(value)
        for data in [b"NaN", b'{"payload": Infinity}', b"-Infinity"]:
            with self.assertRaises(KronikError):
                parse_json(data, "the body", "json")

    def test_state_and_crypto_values_are_text_or_bytes(self):
        # Review M15 N3: an int is no value (bytes(3) would be three NULs).
        from kronik.ctx import _utf8

        self.assertEqual(_utf8("é"), "é".encode())
        self.assertEqual(_utf8(bytearray(b"ab")), b"ab")
        for bad in [3, 5.0, None, ["x"]]:
            with self.assertRaises(TypeError):
                _utf8(bad)

    def test_encode_body(self):
        self.assertEqual(encode_body(b"\x00"), (b"\x00", "application/octet-stream"))
        self.assertEqual(encode_body("hi"), (b"hi", "text/plain; charset=utf-8"))
        self.assertEqual(encode_body({"a": 1}), (b'{"a":1}', "application/json"))

    def test_bad_bodies_raise_kronik_errors(self):
        with self.assertRaisesRegex(KronikError, r"^the request body is not UTF-8 \(see `kronik explain message`\)$"):
            parse_json(b"\xff", "the request body", "message")
        with self.assertRaisesRegex(KronikError, r"^x is not the expected JSON: .*\(see `kronik explain message`\)$") as cm:
            parse_json(b"not json", "x", "message")
        self.assertEqual(cm.exception.kind, "json")

    def test_request_helpers(self):
        req = Request(http_input(query="a=1&b=x+y&a=2&e=", body=b'{"k": [1]}').value)
        self.assertEqual(req.param("key"), "alice")
        self.assertEqual(req.query_param("a"), "1")
        self.assertEqual(req.query_param("b"), "x y")
        self.assertEqual(req.query_param("e"), "")
        self.assertIsNone(req.query_param("z"))
        self.assertEqual(req.header("content-type"), "text/plain")
        self.assertEqual(req.json(), {"k": [1]})

    def test_messages_and_actor_refs(self):
        self.assertEqual(wit_message({"name": "n"}, types), types.Message("n", "", b"", []))
        self.assertEqual(wit_message({"name": "n", "body": {"n": 1}}, types), types.Message("n", "application/json", b'{"n":1}', []))
        self.assertEqual(wit_message({"name": "n", "body": "x", "content_type": "text/csv"}, types).content_type, "text/csv")
        self.assertEqual(actor_ref("billing/acme/1", types), types.ActorRef("billing", "acme/1"))
        for bad in ["billing", "/acme", "billing/"]:
            with self.assertRaisesRegex(ValueError, "kronik explain actor"):
                actor_ref(bad, types)


class SqlTest(unittest.TestCase):
    def test_params_and_values(self):
        self.assertEqual(to_sql(None, sql), sql.SqlValue_Null())
        self.assertEqual(to_sql(True, sql), sql.SqlValue_Integer(1))
        self.assertEqual(to_sql(2**62, sql), sql.SqlValue_Integer(2**62))
        self.assertEqual(to_sql(1.5, sql), sql.SqlValue_Real(1.5))
        self.assertEqual(to_sql("t", sql), sql.SqlValue_Text("t"))
        self.assertEqual(to_sql(b"b", sql), sql.SqlValue_Blob(b"b"))
        with self.assertRaisesRegex(KronikError, "kronik explain sql-state"):
            to_sql({}, sql)
        self.assertIsNone(from_sql(sql.SqlValue_Null()))
        self.assertEqual(from_sql(sql.SqlValue_Text("t")), "t")

    def test_rows(self):
        rows = SqlRows(SimpleNamespace(columns=["id", "t"], values=[[sql.SqlValue_Integer(1), sql.SqlValue_Null()]]))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows.rows(), [{"id": 1, "t": None}])
        self.assertEqual(rows.first(), {"id": 1, "t": None})
        self.assertIsNone(SqlRows(SimpleNamespace(columns=[], values=[])).first())

    def test_has_order_by(self):
        self.assertTrue(has_order_by("SELECT * FROM t ORDER  BY id"))
        self.assertTrue(has_order_by("select * from t order\nby id"))
        self.assertFalse(has_order_by("SELECT 'ORDER BY' FROM t"))
        self.assertFalse(has_order_by('SELECT "order" by FROM t'))
        self.assertFalse(has_order_by("SELECT 1 -- ORDER BY id"))
        self.assertFalse(has_order_by("SELECT 1 /* ORDER BY */"))
        self.assertFalse(has_order_by("SELECT border BY FROM t"))


class ActorTest(unittest.TestCase):
    def test_manifest(self):
        spec = actor(kind="counter", schema_version=1, routes=[{"method": "GET", "pattern": "/c/{key}"}], capabilities=["http:x"])
        self.assertEqual(spec.manifest(), ("counter", 1, [("GET", "/c/{key}")], ["http:x"]))
        self.assertEqual(actor(kind="k", schema_version=0).manifest(), ("k", 0, [], []))

    def test_invalid_specs_are_refused(self):
        for kwargs in [{"kind": "", "schema_version": 0}, {"kind": "k", "schema_version": -1}, {"kind": "k", "schema_version": True}, {"kind": "k", "schema_version": 0, "routes": [{"method": "GET"}]}]:
            with self.assertRaisesRegex(TypeError, "kronik explain actor"):
                actor(**kwargs)

    def test_handle_dispatches_and_maps_errors(self):
        writes = []

        def http(req, ctx):
            if req.method == "DELETE":
                raise Rejected("no")
            if req.method == "PUT":
                raise ValueError("boom")
            ctx.state.set_json("n", 1)
            return ctx.json(200, {"n": 1})

        spec = actor(kind="counter", schema_version=1, http=http)
        out = handle(spec, fake_host(writes), http_input())
        self.assertEqual(out, types.Output_Http(types.HttpResponse(200, [types.Header("content-type", "application/json")], types.HttpBody_Inline(b'{"n":1}'))))
        self.assertEqual(writes, [("n", b"1")])
        with self.assertRaises(Err) as cm:
            handle(spec, fake_host(writes), http_input("DELETE"))
        self.assertEqual(cm.exception.value, types.HandlerError_Rejected("no"))
        with self.assertRaises(Err) as cm:
            handle(spec, fake_host(writes), http_input("PUT"))
        self.assertEqual(cm.exception.value, types.HandlerError_Failed("ValueError: boom"))
        with self.assertRaises(Err) as cm:
            handle(spec, fake_host(writes), types.Input_Message(types.Incoming(None, types.Message("m", "", b"", []))))
        self.assertEqual(
            cm.exception.value,
            types.HandlerError_Rejected("actor type counter does not handle messages: give actor() a message= handler (see `kronik explain message`)"),
        )
        self.assertEqual(handle(spec, fake_host(writes), types.Input_Migrate(0)), types.Output_None_())


class ConnectionsTest(unittest.TestCase):
    def test_frames(self):
        self.assertEqual(Frame.text("hi"), Frame("text", "hi"))
        self.assertEqual(Frame.json({"n": 1}), Frame("text", '{"n":1}'))
        self.assertEqual(Frame.binary(bytearray(b"ab")), Frame("binary", b"ab"))
        self.assertEqual(Frame.event({"seq": 7}, id=7), Frame("event", '{"seq":7}', "", "7"))
        self.assertEqual(to_wit_frame("hi", conn), conn.Frame_Text("hi"))
        self.assertEqual(to_wit_frame(b"\x01", conn), conn.Frame_Binary(b"\x01"))
        self.assertEqual(to_wit_frame(Frame.event("x", event="message"), conn), conn.Frame_Event(conn.SseEvent("message", "", "x")))
        with self.assertRaisesRegex(KronikError, "not a frame.*kronik explain connections"):
            to_wit_frame({"type": "say"}, conn)

    def test_routes(self):
        self.assertEqual(Route.websocket("/chat/{key}/ws"), {"method": "WEBSOCKET", "pattern": "/chat/{key}/ws"})
        self.assertEqual(Route.sse("/e"), {"method": "SSE", "pattern": "/e"})
        self.assertEqual(Route.post("/p"), {"method": "POST", "pattern": "/p"})

    def test_the_open_request_incoming_frames_and_the_close(self):
        req = OpenRequest(open_request(headers=[("Origin", "https://chat.example"), ("Last-Event-ID", "41")]))
        self.assertEqual((req.connection, req.protocol, req.subprotocols), ("c-0123", "websocket", ["chat.v1"]))
        self.assertEqual(req.param("key"), "lobby")
        self.assertEqual(req.query_param("user"), "ada")
        self.assertEqual(req.origin(), "https://chat.example")
        self.assertEqual(req.last_event_id(), "41")
        frame = IncomingFrame(conn.IncomingFrame("c-0123", 3, conn.Frame_Text('{"type":"say"}')))
        self.assertEqual((frame.connection, frame.seq, frame.kind), ("c-0123", 3, "text"))
        self.assertEqual(frame.json(), {"type": "say"})
        binary = IncomingFrame(conn.IncomingFrame("c-0123", 4, conn.Frame_Binary(b"\xff")))
        self.assertEqual(binary.bytes(), b"\xff")
        with self.assertRaisesRegex(KronikError, "the frame is not UTF-8"):
            binary.text()
        closed = closed_of(conn.Closed("c-0123", conn.CloseInfo(CloseInitiator.HOST, 1012, "restart")))
        self.assertEqual((closed.initiator, closed.code, closed.reason), ("host", 1012, "restart"))

    def test_open_accepts_refuses_and_defaults_to_404(self):
        calls = []
        h = connection_host(calls)

        def join(req, ctx):
            if req.query_param("user") == "mallory":
                return ctx.status(403)
            if req.query_param("user") == "none":
                return ctx.none()
            ctx.connections.send(req.connection, Frame.json({"type": "welcome"}))
            return ctx.accept(subject="user:ada", headers={"x-room": "lobby"})

        spec = actor(kind="chat", schema_version=0, connections=Connections(open=join))
        out = open_connection(spec, h, open_request())
        self.assertEqual(out, conn.OpenReply_Accept(conn.Accept(None, [types.Header("x-room", "lobby")], "user:ada")))
        self.assertEqual(calls, [("send", "c-0123", conn.Frame_Text('{"type":"welcome"}'))])
        out = open_connection(spec, h, open_request("user=mallory"))
        self.assertEqual(out, conn.OpenReply_Refuse(types.HttpResponse(403, [], types.HttpBody_Inline(b""))))
        with self.assertRaises(Err) as cm:
            open_connection(spec, h, open_request("user=none"))
        self.assertIn("must return ctx.accept()", cm.exception.value.value)
        bare = actor(kind="chat", schema_version=0)
        out = open_connection(bare, h, open_request())
        self.assertEqual(out.value.status, 404)
        self.assertIn(b"does not handle connections", out.value.body.value)
        with self.assertRaisesRegex(TypeError, "kronik explain connections"):
            actor(kind="chat", schema_version=0, connections={"open": join})

    def test_frames_are_rejected_and_closes_ignored_without_handlers(self):
        h = connection_host([])
        frame = conn.IncomingFrame("c-0123", 0, conn.Frame_Text("x"))
        closed = conn.Closed("c-0123", conn.CloseInfo(CloseInitiator.CLIENT, 1000, ""))
        bare = actor(kind="chat", schema_version=0)
        with self.assertRaises(Err) as cm:
            connection_frame(bare, h, frame)
        self.assertEqual(
            cm.exception.value,
            types.HandlerError_Rejected(
                "actor type counter does not handle connection frames: give actor() connections=Connections(frame=...) (see `kronik explain connections`)"
            ),
        )
        self.assertIsNone(connection_closed(bare, h, closed))
        seen = []

        def boom(f, ctx):
            raise ValueError("bad frame")

        spec = actor(kind="chat", schema_version=0, connections=Connections(frame=boom, close=lambda c, ctx: seen.append(c)))
        with self.assertRaises(Err) as cm:
            connection_frame(spec, h, frame)
        self.assertEqual(cm.exception.value, types.HandlerError_Failed("ValueError: bad frame"))
        connection_closed(spec, h, closed)
        self.assertEqual(seen[0].code, 1000)

    def test_ctx_connections(self):
        from kronik.ctx import Ctx

        calls = []
        ctx = Ctx(connection_host(calls))
        ctx.connections.send("c-1", "hi")
        ctx.connections.broadcast(("c-1", "c-2"), Frame.binary(b"x"))
        ctx.connections.close("c-1", 4000, "bye")
        self.assertTrue(ctx.connections.send_now("c-1", "tok"))
        self.assertEqual(
            calls,
            [
                ("send", "c-1", conn.Frame_Text("hi")),
                ("broadcast", ["c-1", "c-2"], conn.Frame_Binary(b"x")),
                ("close", "c-1", 4000, "bye"),
                ("send_now", "c-1", conn.Frame_Text("tok")),
            ],
        )
        self.assertFalse(Ctx(connection_host([], conn.SendError_Closed())).connections.send_now("c-1", "x"))
        with self.assertRaises(OutcomeUnknown) as cm:
            Ctx(connection_host([], conn.SendError_OutcomeUnknown())).connections.send_now("c-1", "x")
        self.assertEqual(cm.exception.topic, "EFFECT_OUTCOME_UNKNOWN")
        with self.assertRaisesRegex(KronikError, r"sending now denied: CAPABILITY_NOT_GRANTED: connection:send-now \(see `kronik explain CAPABILITY_NOT_GRANTED`\)"):
            Ctx(connection_host([], conn.SendError_Denied("CAPABILITY_NOT_GRANTED: connection:send-now"))).connections.send_now("c-1", "x")
        self.assertEqual(send_now_failure(object()).kind, "send-now.unknown")


class WitTest(unittest.TestCase):
    def test_wit_is_the_repository_copy(self):
        repo_wit = SDK.parents[1] / "wit" / "kronik-actor.wit"
        if not repo_wit.is_file():
            self.skipTest("not in the Kronik repository (a vendored SDK)")
        self.assertEqual((SDK / "wit" / "kronik-actor.wit").read_bytes(), repo_wit.read_bytes())


if __name__ == "__main__":
    unittest.main()
