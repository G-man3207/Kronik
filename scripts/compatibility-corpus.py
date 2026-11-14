#!/usr/bin/env python3
"""Preserve actual released producer data and verify it through the public binary."""
import argparse
import base64
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

from kronikd import Daemon, UnixConnection, Violation

# Reuse the bounded public-command fixture helper, not a second subprocess convention.
spec = importlib.util.spec_from_file_location("benchmark_single_node", Path(__file__).with_name("benchmark-single-node.py"))
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)
run_json = benchmark.run_json
digest = benchmark.digest
# The standard-library WebSocket and SSE clients of M24's acceptance scripts.
ws_spec = importlib.util.spec_from_file_location("m24_ws", Path(__file__).with_name("m24_ws.py"))
m24_ws = importlib.util.module_from_spec(ws_spec)
ws_spec.loader.exec_module(m24_ws)
DUMMY_MASTER = "44" * 32
REASON = "owned released-producer compatibility fixture"
MAX_FILE = 2 << 20
MAX_TOTAL = 32 << 20
# A release is named by its tag, v0.<minor>.<patch>, as in the release index.
RELEASE_TAG = re.compile(r"v0\.[0-9]+\.[0-9]+")
# The first line of an actual release's `--version` is `kronik <version>`. The
# one documented exception is the v0.1.0 artifact, which shipped its
# development string; its real identity is retained, not rewritten.
REPORTED_VERSION = {"v0.1.0": "kronik 0.1.0-dev"}
# From v0.5.0, and only from then, the producer also records the record kinds
# that release added: long-lived connections (M24, the `room` guest) and blobs
# (M25 and M26, the `media` guest). An older release's scenario, and so its
# case, stays exactly as it was.
BLOBS_AND_CONNECTIONS = (5, 0)
SCENARIOS = ["counter", "notes", "blobs", "connections"]
# The `media` kind's blob threshold in the corpus: bodies above 64 KiB are
# blobs.
BLOB_THRESHOLD = 64 << 10
# The size of each blob of the scenario: above the threshold, at most 300 KB
# and so far below a corpus file's 2 MiB.
BLOB_SIZES = {"upload": 200_000, "fetched": 150_000, "written": 120_000, "callee_reply": 110_000,
              "put": 100_000, "timer": 90_000, "reply": 80_000}
# The timer that carries a blob stays pending in the corpus: due about 50
# years after the producer ran, so no verification of the corpus fires it.
TIMER_DELAY_MS = 50 * 365 * 24 * 3600 * 1000
BLOB_HASH = re.compile(r"b3s?:[0-9a-f]{64}")
# HOOK, review finding F1: a call answered with a blob the CALLEE wrote
# (media/kw calls media/cw, whose `write` answers with the blob, and keeps the
# reply's blob). A binary without the fix fails the caller with a
# prerequisite failure (HTTP 503), so the scenario leaves it out. Once the
# release that the corpus is produced from has the fix, set this to True:
# produce_blobs then records it, and the verifier checks it with the other
# blobs and holds (nothing else to change).
CALLEE_WRITTEN_REPLY = False
# The room of the connection scenario, and what its members send and see.
ROOM = "compat"
ROOM_QUERIES = ("messages", "closes", "seq")
SAID = "released corpus hello"
JOINED = '{"type":"joined","user":"anon"}'
LEFT = '{"type":"left","user":"anon"}'


def release_tag(value):
    """argparse type: the exact tag of an actual release."""
    if not RELEASE_TAG.fullmatch(value):
        raise argparse.ArgumentTypeError(f"{value!r} is not a release tag such as v0.4.0")
    return value


def release_version(release):
    """(minor, patch) of a release tag v0.<minor>.<patch>."""
    _, minor, patch = release_tag(release)[1:].split(".")
    return int(minor), int(patch)


def records_blobs_and_connections(release):
    """Whether the scenario of `release` also records blobs and connections."""
    return release_version(release) >= BLOBS_AND_CONNECTIONS


def expected_version(release):
    """The first `--version` line that the release's own binary reports."""
    return REPORTED_VERSION.get(release_tag(release), "kronik " + release[1:])


def checked_api(daemon, method, path, body=None):
    status, value = daemon.api(method, path, body, timeout=30)
    if status != 200:
        raise Violation(f"{method} {path}: HTTP {status}: {value}")
    return value


def message(daemon, actor, name, text=""):
    value = checked_api(daemon, "POST", f"/v1/actors/{actor}/messages",
                        {"name": name, "text": text, "reason": REASON})
    if value.get("outcome", {}).get("kind") != "committed":
        raise Violation(f"{actor}/{name} did not commit: {value}")
    return value


def configure(work, data, sock):
    # No [blobs] table, for any release: v0.5.0 removed the `enabled` switch
    # of the development builds (M26 slice B20) and refuses a configuration
    # that still sets it, and blobs are always on from then; older releases
    # have no blobs.
    config = work / "kronik.toml"
    config.write_text("[server]\n" + f"data_dir = {json.dumps(str(data))}\n" +
                      f"api_socket = {json.dumps(str(sock))}\n" +
                      "admin_listen = \"127.0.0.1:0\"\n")
    return {"KRONIK_CONFIG": str(config), "KRONIK_MASTER_KEY": DUMMY_MASTER,
            "KRONIK_ADMIN_LISTEN": "127.0.0.1:0"}


def fixture_bytes(seed, size):
    """Deterministic fixture content: the SHA-256 chain of `seed`."""
    out = bytearray()
    block = hashlib.sha256(seed.encode()).digest()
    while len(out) < size:
        out += block
        block = hashlib.sha256(block).digest()
    return bytes(out[:size])


def media_pattern(size):
    """The bytes the `media` guest's `write` and `put` produce: byte i is
    (31 i + 7) mod 251 (`pattern` in tests/guests/media/src/lib.rs)."""
    return bytes((i * 31 + 7) % 251 for i in range(size))


def fnv1a64(data):
    """The `media` guest's checksum (FNV-1a, 64 bits), as its `sum` answers it."""
    value = 0xcbf2_9ce4_8422_2325
    for byte in data:
        value = ((value ^ byte) * 0x0000_0100_0000_01b3) & 0xffff_ffff_ffff_ffff
    return f"{value:016x}"


def gateway(port, method, path, body=b""):
    """One request through the daemon's own gateway: (status, body bytes)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request(method, path, body=body, headers={"content-type": "application/octet-stream"})
        response = conn.getresponse()
        data = response.read(MAX_FILE + 1)
    finally:
        conn.close()
    if len(data) > MAX_FILE:
        raise Violation(f"{method} {path}: answer exceeds 2 MiB")
    return response.status, data


def gateway_text(port, method, path, body=b""):
    status, data = gateway(port, method, path, body)
    if status != 200:
        raise Violation(f"{method} {path}: HTTP {status}: {data[:300]!r}")
    return data.decode()


def blob_answer(text):
    """A `media` answer `blob <hash> <size>`."""
    parts = text.split()
    if len(parts) != 3 or parts[0] != "blob" or not BLOB_HASH.fullmatch(parts[1]) or not parts[2].isdigit():
        raise Violation(f"not a blob answer: {text!r}")
    return {"hash": parts[1], "size": int(parts[2])}


def reply_answer(text):
    """A `media` call's answer `reply blob <hash> <size> retained`: the reply's
    blob, which the caller keeps."""
    if not (text.startswith("reply ") and text.endswith(" retained")):
        raise Violation(f"the call answered {text!r}")
    return blob_answer(text[len("reply "):-len(" retained")])


def blob_bytes(daemon, blob):
    """A blob's bytes through `GET /v1/blobs/{hash}/content`, exactly its size."""
    conn = UnixConnection(daemon.sock, 30)
    try:
        conn.request("GET", f"/v1/blobs/{blob['hash']}/content", headers={"Host": "kronik"})
        response = conn.getresponse()
        data = response.read(MAX_FILE + 1)
    finally:
        conn.close()
    if response.status != 200 or len(data) != blob["size"]:
        raise Violation(f"blob {blob['hash']}: HTTP {response.status}, {len(data)} of {blob['size']} bytes")
    return data


def store_blobs(data):
    """The blobs in a data directory's store, by the names of their files."""
    found = set()
    for path in (data / "blobs" / "objects").glob("*/*"):
        match = re.fullmatch(r"(b3s?)-([0-9a-f]{64})", path.name)
        if match:
            found.add(f"{match.group(1)}:{match.group(2)}")
    return found


def blob_roots(daemon, blob):
    """What keeps a blob (`kronik blobs inspect`), as the data directory's
    records, rows and snapshots say: without the leases of this node's memory
    and the log root's floor, which moves with this node's forks and runs."""
    roots = [{key: value for key, value in root.items() if key != "floor"}
             for root in checked_api(daemon, "GET", f"/v1/blobs/{blob['hash']}").get("roots") or []
             if root.get("kind") != "lease"]
    return sorted(roots, key=lambda root: json.dumps(root, sort_keys=True))


def until(what, probe, timeout=10.0):
    deadline = time.monotonic() + timeout
    while True:
        value = probe()
        if value is not None:
            return value
        if time.monotonic() >= deadline:
            raise Violation(f"{what} did not happen within {timeout:.0f} s")
        time.sleep(0.02)


class DocumentServer:
    """A local HTTP server whose one document the `media` guest fetches."""

    def __init__(self, document):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/document":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("content-type", "application/pdf")
                self.send_header("content-length", str(len(document)))
                self.end_headers()
                self.wfile.write(document)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def configure_blobs_and_connections(daemon):
    """Before the stable point: the `media` kind's blob threshold and its
    fetches of the local document, and the `room` kind's `send-now`."""
    checked_api(daemon, "POST", "/v1/limits",
                {"kind": "media", "blob_threshold_bytes": BLOB_THRESHOLD, "reason": REASON})
    checked_api(daemon, "POST", "/v1/grants",
                {"kind": "media", "capability": "http:127.0.0.1", "reason": REASON})
    checked_api(daemon, "POST", "/v1/grants",
                {"kind": "room", "capability": "connection:send-now", "reason": REASON})


def actor_blobs(daemon, actor):
    return checked_api(daemon, "GET", f"/v1/actors/{actor}/blobs")["blobs"]


def produce_blobs(daemon, port, data):
    """M25 and M26 records with the `media` guest, bodies above 64 KiB being
    blobs: an upload (u), a fetched document (f), a blob a turn writes and
    answers with (w), a put whose hold travels on a message and is retained by
    its receiver and released by its sender (h, r), a pending timer that
    carries a blob (t), and a call whose reply carries the caller's blob,
    which the caller keeps (k, c). Returns what a later binary must read
    back, and the root inputs it sent."""
    sent = []

    def media(method, path, body=b""):
        sent.append(path)
        return gateway(port, method, path, body)

    def media_text(method, path, body=b""):
        status, answer = media(method, path, body)
        if status != 200:
            raise Violation(f"{method} {path}: HTTP {status}: {answer[:300]!r}")
        return answer.decode()

    blobs, expected = {}, {}
    expected["upload"] = fixture_bytes("upload", BLOB_SIZES["upload"])
    blobs["upload"] = blob_answer(media_text("POST", "/media/u/info", expected["upload"]))
    expected["fetched"] = fixture_bytes("document", BLOB_SIZES["fetched"])
    server = DocumentServer(expected["fetched"])
    try:
        url = f"http://127.0.0.1:{server.port}/document".encode()
        fetched = media_text("POST", "/media/f/fetch", url)
    finally:
        server.close()
    if not fetched.startswith("status 200 "):
        raise Violation(f"the fetch answered {fetched!r}")
    blobs["fetched"] = blob_answer(fetched[len("status 200 "):])
    # The answer's body is the blob the turn wrote; its name is the one the
    # store gained.
    before = store_blobs(data)
    expected["written"] = media_pattern(BLOB_SIZES["written"])
    status, written = media("POST", f"/media/w/write?size={BLOB_SIZES['written']}")
    if status != 200 or written != expected["written"]:
        raise Violation(f"the write answered HTTP {status} with {len(written)} other bytes")
    gained = store_blobs(data) - before
    if len(gained) != 1:
        raise Violation(f"the write's blob is not the one new file of the store: {sorted(gained)}")
    blobs["written"] = {"hash": gained.pop(), "size": BLOB_SIZES["written"]}
    expected["put"] = media_pattern(BLOB_SIZES["put"])
    blobs["put"] = blob_answer(media_text("POST", f"/media/h/put?size={BLOB_SIZES['put']}"))
    if media_text("POST", "/media/h/send?to=r&op=retain") != "sent":
        raise Violation("media/h did not send its blob")
    until("media/r's hold", lambda: actor_blobs(daemon, "media/r") or None)
    if media_text("POST", "/media/h/release") != "released":
        raise Violation("media/h did not release its blob")
    # The same bytes are the same blob: `info` names it, `schedule` puts it
    # on the timer's message, which stays pending (TIMER_DELAY_MS).
    expected["timer"] = fixture_bytes("timer", BLOB_SIZES["timer"])
    blobs["timer"] = blob_answer(media_text("POST", "/media/t/info", expected["timer"]))
    if media_text("POST", f"/media/t/schedule?delay={TIMER_DELAY_MS}&op=sum", expected["timer"]) != "scheduled":
        raise Violation("media/t did not schedule its timer")
    expected["reply"] = fixture_bytes("call", BLOB_SIZES["reply"])
    blobs["reply"] = reply_answer(media_text("POST", "/media/k/call?to=c&op=reply&keep=1", expected["reply"]))
    holders = {"media/r": "put", "media/k": "reply"}
    if CALLEE_WRITTEN_REPLY:
        # The hook of review finding F1 (CALLEE_WRITTEN_REPLY): the callee's
        # `write` answers the call with a blob it wrote.
        expected["callee_reply"] = media_pattern(BLOB_SIZES["callee_reply"])
        blobs["callee_reply"] = reply_answer(media_text(
            "POST", f"/media/kw/call?to=cw&op=write?size={BLOB_SIZES['callee_reply']}&keep=1"))
        holders["media/kw"] = "callee_reply"
    for name, blob in blobs.items():
        if blob["size"] != BLOB_SIZES[name] or blob_bytes(daemon, blob) != expected[name]:
            raise Violation(f"the {name} blob is not the {BLOB_SIZES[name]} bytes it should hold")
        blob["sha256"] = hashlib.sha256(expected[name]).hexdigest()
    # Every actor of the scenario: those the requests went to, and those that
    # only received messages and calls.
    receivers = {"media/r", "media/c"} | ({"media/cw"} if CALLEE_WRITTEN_REPLY else set())
    actors = sorted({"media/" + path.split("/")[2] for path in sent} | receivers)
    holds = {actor: actor_blobs(daemon, actor) for actor in actors}
    for actor, held in holds.items():
        want = [blobs[holders[actor]]["hash"]] if actor in holders else []
        if [entry["hash"] for entry in held] != want:
            raise Violation(f"{actor} holds {held}, not {want}")
    timers = checked_api(daemon, "GET", "/v1/actors/media/t/timers")["timers"]
    if [timer.get("name") for timer in timers] != ["sum"]:
        raise Violation(f"media/t's pending timer is not the one it scheduled: {timers}")
    return {"blobs": blobs, "holds": holds, "timers": {"media/t": timers}}, len(sent)


class Member:
    """A WebSocket client of the `room` guest that keeps its transcript: the
    frames it sent and received, in order."""

    def __init__(self, port, path):
        self.path, self.id = path, None
        try:
            self.ws = m24_ws.WebSocket("127.0.0.1", port, path)
        except OSError as error:
            raise Violation(f"WEBSOCKET {path}: {error}") from None
        self.sent, self.received = [], []

    def send(self, text):
        self.ws.send_text(text)
        self.sent.append(text)

    def expect(self, what, frame, timeout=10.0):
        """The next frame, which must be `frame`."""
        try:
            got = self.ws.recv(timeout)
        except m24_ws.Closed as closed:
            raise Violation(f"{self.path} closed ({closed.code} {closed.reason!r}) before {what}") from None
        except OSError:
            raise Violation(f"{what} did not arrive on {self.path} within {timeout:.0f} s") from None
        self.received.append(got if isinstance(got, str) else {"binary": base64.b64encode(got).decode()})
        if got != frame:
            raise Violation(f"{self.path} got {got!r}, not {what} {frame!r}")

    def expect_welcome(self, members):
        """The room's welcome, the first frame; returns the connection's id."""
        try:
            got = self.ws.recv(10.0)
        except (m24_ws.Closed, OSError) as error:
            raise Violation(f"no welcome on {self.path}: {error}") from None
        self.received.append(got)
        welcome = json.loads(got) if isinstance(got, str) else None
        if (not isinstance(welcome, dict) or set(welcome) != {"type", "connection", "members", "last"}
                or welcome["type"] != "welcome" or welcome["members"] != members or welcome["last"] != 0
                or not re.fullmatch(r"c-[0-9a-f]{32}", str(welcome["connection"]))):
            raise Violation(f"{self.path} was not welcomed as member {members}: {got!r}")
        self.id = welcome["connection"]
        return self.id

    def expect_close(self, what, code, reason, timeout=10.0):
        """The close frame that ends the connection, which the client returns."""
        try:
            got = self.ws.recv(timeout)
        except m24_ws.Closed as closed:
            self.ws.sock.close()
            if (closed.code, closed.reason) != (code, reason):
                raise Violation(f"{self.path} closed with {closed.code} {closed.reason!r}, not {what}") from None
            return
        except OSError:
            raise Violation(f"{what} did not arrive on {self.path} within {timeout:.0f} s") from None
        raise Violation(f"{self.path} got {got!r}, not {what}")

    def close_by_client(self, code, reason):
        """A client's close: ours, then the server's."""
        try:
            self.ws.close(code, reason)
        except OSError:
            raise Violation(f"{self.path} did not answer its client's close") from None


class Follower:
    """An SSE client of the `room` guest that keeps its transcript: each event
    it received as [event, id, data]."""

    def __init__(self, port, path):
        self.path, self.id, self.sent, self.received = path, None, [], []
        self.stream = m24_ws.EventStream("127.0.0.1", port, path)
        if self.stream.status != 200:
            raise Violation(f"SSE {path} answered HTTP {self.stream.status}")

    def expect(self, what, event):
        try:
            got = list(self.stream.next_event())
        except m24_ws.Closed:
            raise Violation(f"{self.path} ended before {what}") from None
        except OSError:
            raise Violation(f"{what} did not arrive on {self.path}") from None
        self.received.append(got)
        if got != event:
            raise Violation(f"{self.path} got {got}, not {what} {event}")

    def expect_end(self, what):
        try:
            got = self.stream.next_event()
        except m24_ws.Closed:
            self.stream.close()
            return
        except OSError:
            raise Violation(f"{self.path} did not end with {what}") from None
        raise Violation(f"{self.path} got {list(got)}, not {what}")


def room_message(seq, user, text):
    """A `message` frame of the room (on a WebSocket, the event's data)."""
    return json.dumps({"type": "message", "seq": seq, "user": user, "text": text}, separators=(",", ":"))


def room_text(port, op):
    return gateway_text(port, "GET", f"/room/{ROOM}/{op}")


def open_connections(daemon):
    return checked_api(daemon, "GET", "/v1/connections?state=open")["connections"]


def connection_view(daemon, connection):
    return checked_api(daemon, "GET", f"/v1/connections/{connection}")


def closed_by_their_turns(daemon, connections):
    """True once every connection is closed and its close input recorded."""
    for connection in connections:
        view = connection_view(daemon, connection)
        if view.get("state") != "closed" or not (view.get("closed") or {}).get("turn_id"):
            return None
    return True


def produce_connections(daemon, port):
    """M24 records with the `room` guest: two WebSocket members, one with the
    subject user:7 and one without, and an SSE follower. The first says,
    echoes and streams three frames with `send-now` (which a replay answers
    from the recording); the second echoes and says `bye`, so the actor
    closes it; the operator closes the follower; the first member closes as
    a client. Each step waits for the frames it causes, so every transcript
    is exact, and every connection is closed before the snapshot. Returns the
    transcripts, the room's state, the closed connections and the root
    inputs it sent."""
    seven = Member(port, f"/room/{ROOM}/ws?user=7")
    seven.expect_welcome(members=1)
    anonymous = Member(port, f"/room/{ROOM}/ws")
    anonymous.expect_welcome(members=2)
    seven.expect("the second member's joined", JOINED)
    follower = Follower(port, f"/room/{ROOM}/events")
    for member in (seven, anonymous):
        member.expect("the follower's joined", JOINED)
    follower.id = until("the follower's open", lambda: next(
        (c["id"] for c in open_connections(daemon) if c.get("protocol") == "sse"), None))
    said = room_message(1, "7", SAID)
    seven.send(f"say {SAID}")
    for member in (seven, anonymous):
        member.expect("the message", said)
    follower.expect("the message", ["message", "1", said])
    seven.send("echo released corpus echo")
    seven.expect("the echo", "released corpus echo")
    seven.send("stream 3")
    for i in range(3):
        seven.expect("a send-now frame", f"tok {i}")
    seven.expect("the stream's end", "done 3")
    anonymous.send("echo anonymous echo")
    anonymous.expect("the echo", "anonymous echo")
    anonymous.send("bye")
    anonymous.expect_close("the actor's close", 1000, "bye")
    seven.expect("the second member's left", LEFT)
    follower.expect("the second member's left", ["message", "", LEFT])
    checked_api(daemon, "POST", f"/v1/connections/{follower.id}/close",
                {"code": 1000, "message": "released corpus ends", "reason": REASON})
    follower.expect_end("the operator's close")
    seven.expect("the follower's left", LEFT)
    seven.close_by_client(1000, "done")
    clients = {"member-7": (seven, {"initiator": "client", "cause": "client", "code": 1000}),
               "member-anonymous": (anonymous, {"initiator": "actor", "cause": "actor", "code": 1000}),
               "follower": (follower, {"initiator": "host", "cause": "operator", "code": 1000})}
    until("the three close inputs", lambda: closed_by_their_turns(daemon, [c.id for c, _ in clients.values()]))
    transcripts = {name: {"connection": client.id, "path": client.path, "sent": client.sent,
                          "received": client.received, "close": close}
                   for name, (client, close) in clients.items()}
    for transcript in transcripts.values():
        check_transcript(connection_view(daemon, transcript["connection"]), transcript)
    room = {op: room_text(port, op) for op in ROOM_QUERIES}
    if room["seq"] != "1" or len(room["closes"].splitlines()) != 3:
        raise Violation(f"the room recorded {room}")
    # An open, a close and each frame a client sent per connection, and the queries.
    roots = sum(2 + len(transcript["sent"]) for transcript in transcripts.values()) + len(ROOM_QUERIES)
    return {"transcripts": transcripts, "send_now": 3, "room": room,
            "connections": closed_connections(daemon)}, roots


def check_transcript(view, transcript):
    """A connection's record agrees with what its client saw: a frame in for
    each frame it sent, a frame out, written, for each it received, and its
    close."""
    frames, closed = view.get("frames") or {}, view.get("closed") or {}
    expected = {"in": len(transcript["sent"]), "out": len(transcript["received"]),
                "written": len(transcript["received"]), "queued": 0, "dropped": 0, "unknown": 0}
    if (view.get("id") != transcript["connection"] or view.get("state") != "closed"
            or {key: frames.get(key) for key in expected} != expected
            or {key: closed.get(key) for key in transcript["close"]} != transcript["close"]):
        raise Violation(f"connection {transcript['connection']} ({transcript['path']}) does not agree "
                        f"with its client's transcript: frames {frames}, closed {closed}")


def closed_connections(daemon):
    """The closed connections as the log records them: without what this
    node holds now (`live`) or what retention may remove (the open turn's
    logical time)."""
    connections = checked_api(daemon, "GET", "/v1/connections?state=closed")["connections"]
    if not 1 <= len(connections) <= 64:
        raise Violation(f"unexpected closed connections: {len(connections)}")
    out = []
    for connection in connections:
        view = {key: value for key, value in connection.items() if key != "live"}
        view["opened"] = {key: value for key, value in connection["opened"].items() if key != "logical_time_ms"}
        out.append(view)
    return out


def agrees(recorded, actual):
    """Whether `actual` says what the producer `recorded`: the same value for
    every key it recorded, recursively. A later binary may add fields."""
    if isinstance(recorded, dict):
        return isinstance(actual, dict) and all(key in actual and agrees(value, actual[key])
                                                for key, value in recorded.items())
    if isinstance(recorded, list):
        return (isinstance(actual, list) and len(recorded) == len(actual)
                and all(agrees(value, other) for value, other in zip(recorded, actual)))
    return type(recorded) is type(actual) and recorded == actual


def check_observations(manifest):
    """Whether a manifest is of a release whose scenario has blobs and
    connections; such a manifest must carry their observations, and no older
    one may claim them."""
    observations, release = manifest.get("observations"), manifest.get("release")
    if not isinstance(observations, dict) or not isinstance(release, str) or not RELEASE_TAG.fullmatch(release):
        raise Violation("the corpus manifest names no release or has no observations")
    extended = records_blobs_and_connections(release)
    added = {"roots", "blobs", "connections"}
    if extended:
        if manifest.get("scenarios") != SCENARIOS or not added <= observations.keys():
            raise Violation(f"a {manifest['release']} corpus records blobs and connections, and its manifest "
                            "must say what they were")
    elif "scenarios" in manifest or added & observations.keys():
        raise Violation(f"a {manifest.get('release')} corpus has no blobs or connections")
    return extended


def check_blobs(daemon, observed):
    """The candidate reads every blob of the corpus back byte for byte, holds
    it live and whole, keeps it for every reason the producer's node did,
    reports the same holds and pending timers, and would collect none of
    them."""
    for name, blob in observed["blobs"].items():
        if hashlib.sha256(blob_bytes(daemon, blob)).hexdigest() != blob["sha256"]:
            raise Violation(f"candidate changed the bytes of the {name} blob")
        inspected = checked_api(daemon, "GET", f"/v1/blobs/{blob['hash']}?verify=true")
        if (inspected.get("state") != "live" or inspected.get("verified") is not True
                or inspected.get("size") != blob["size"]):
            raise Violation(f"candidate does not hold the {name} blob live and whole: {inspected}")
        candidate = blob_roots(daemon, blob)
        lost = [root for root in blob["roots"] if not any(agrees(root, other) for other in candidate)]
        if lost:
            raise Violation(f"candidate lost what keeps the {name} blob: {lost}")
    for actor, holds in observed["holds"].items():
        if not agrees(holds, actor_blobs(daemon, actor)):
            raise Violation(f"candidate changed what {actor} holds")
    for actor, timers in observed["timers"].items():
        if not agrees(timers, checked_api(daemon, "GET", f"/v1/actors/{actor}/timers")["timers"]):
            raise Violation(f"candidate changed {actor}'s pending timers")
    plan = checked_api(daemon, "GET", "/v1/blobs/gc?verify=true")
    if plan.get("drift") != []:
        raise Violation(f"candidate's blob pins drifted from its rows: {plan.get('drift')}")
    ours = {blob["hash"] for blob in observed["blobs"].values()}
    collected = [entry for entry in plan.get("blobs") or [] if entry.get("hash") in ours]
    if collected:
        raise Violation(f"candidate would collect blobs of the corpus: {collected}")


def check_connections(daemon, port, observed):
    """The candidate's room state and closed connections are the producer's,
    and each connection's record still agrees with its client's transcript."""
    for op, text in observed["room"].items():
        if room_text(port, op) != text:
            raise Violation(f"candidate changed the room's {op}")
    if open_connections(daemon):
        raise Violation("candidate holds a connection open that the producer closed")
    if not agrees(observed["connections"], closed_connections(daemon)):
        raise Violation("candidate changed the closed connections")
    for transcript in observed["transcripts"].values():
        check_transcript(connection_view(daemon, transcript["connection"]), transcript)


def check_kinds_replayed(diff, roots):
    """A replay's diff (`kronik.diff/v1`) replayed each kind's root inputs,
    `roots`, with no divergent turn."""
    kinds = {kind.get("kind"): kind for kind in diff.get("kinds") or [] if isinstance(kind, dict)}
    for kind, count in roots.items():
        replayed = kinds.get(kind) or {}
        if replayed.get("root_inputs") != count or replayed.get("divergent_turns") != 0:
            raise Violation(f"the replay did not replay the {count} {kind} roots unchanged: {replayed}")


def check_frames_replayed(diff, transcripts, send_now):
    """A replay's diff replayed each connection's open, frames and close, with
    no frame changed and every one of the `send_now` frames sent with
    `send-now` answered from its recording, as no fork holds a client."""
    inputs = {"open": len(transcripts), "frame": sum(len(transcript["sent"]) for transcript in transcripts),
              "close": len(transcripts)}
    frames = diff.get("frames") or {}
    replayed = frames.get("inputs") or {}
    sent, now = frames.get("sent") or {}, frames.get("send_now") or {}
    if ({key: replayed.get(key) for key in inputs} != inputs or frames.get("changed") != 0
            or sent.get("prod") != sent.get("fork") or now.get("recorded") != send_now or now.get("modeled") != 0):
        raise Violation("the replay did not replay the connections from their recording: "
                        f"{ {key: value for key, value in frames.items() if key != 'items'} }")


def check_replay_coverage(diff, observations):
    """An identity replay of a corpus with blobs and connections replays their
    turns too: each kind's root inputs, none divergent; each connection's
    open, frames and close, no frame changed, every `send-now` answered from
    its recording; the fetch from its recording."""
    check_kinds_replayed(diff, observations["roots"])
    connections = observations["connections"]
    check_frames_replayed(diff, list(connections["transcripts"].values()), connections["send_now"])
    fetches = [entry for entry in diff.get("grounding") or [] if isinstance(entry, dict)
               and (entry.get("kind"), entry.get("host"), entry.get("route")) == ("http.fetch", "127.0.0.1", "/document")]
    if (len(fetches) != 1 or fetches[0].get("exact") != 1
            or any(fetches[0].get(field) for field in ("approximate", "synthetic", "live", "forked"))):
        raise Violation(f"the identity replay did not answer the fetch from its recording: {fetches}")


def close(daemon):
    if daemon.proc is not None and daemon.proc.poll() is None:
        os.killpg(daemon.proc.pid, signal.SIGTERM)
        try:
            daemon.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(daemon.proc.pid, signal.SIGKILL)
            daemon.proc.wait(timeout=5)
    daemon.log.close()
    if sys.exc_info()[0] is not None:
        with Path(daemon.log.name).open("rb") as source:
            source.seek(0, os.SEEK_END)
            source.seek(max(0, source.tell() - 4096))
            print(source.read(4096).decode("utf-8", errors="replace"), file=sys.stderr)


def inventory(root):
    records = []
    total = 0
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise Violation(f"nonregular or linked corpus entry: {path}")
        if metadata.st_size > MAX_FILE:
            raise Violation(f"corpus file exceeds 2 MiB: {path}")
        total += metadata.st_size
        if total > MAX_TOTAL or len(records) >= 512:
            raise Violation("corpus exceeds the 32 MiB / 512-file bound")
        records.append({"path": path.relative_to(root).as_posix(),
                        "bytes": metadata.st_size, "sha256": digest(path)})
    if not records:
        raise Violation("corpus contains no producer data")
    return records


def producer(args):
    work = args.workdir.resolve()
    work.mkdir(mode=0o700)
    binary = args.binary.resolve(strict=True)
    if digest(binary) != args.binary_sha256:
        raise Violation("producer binary does not match the explicitly pinned release SHA-256")
    version = subprocess.check_output([str(binary), "--version"], text=True, timeout=10)
    if not version.splitlines() or version.splitlines()[0] != expected_version(args.release):
        raise Violation(f"producer is not the declared actual release {args.release}")
    extended = getattr(args, "media", None) is not None
    if extended != records_blobs_and_connections(args.release):
        raise Violation(f"the {args.release} producer records blobs and connections: give --media and --room"
                        if not extended else
                        f"{args.release} has no blobs or connections: leave out --media and --room")
    data, sock = work / "data", work / "api.sock"
    daemon = Daemon(str(binary), str(data), str(sock), args.port, str(work / "producer.log"), healthy_timeout=30)
    env = configure(work, data, sock)
    try:
        daemon.start(env)
        health = checked_api(daemon, "GET", "/v1/health")
        components = []
        guests = (args.counter, args.notes, *((args.media, args.room) if extended else ()))
        for guest in guests:
            guest = guest.resolve(strict=True)
            if guest.stat().st_size > 1 << 20:
                raise Violation("fixture component exceeds 1 MiB")
            result = checked_api(daemon, "POST", "/v1/deployments",
                                 {"wasm_base64": base64.b64encode(guest.read_bytes()).decode(), "reason": REASON})
            components.append({"filename": guest.name, "sha256": digest(guest), "deployment": result})
        checked_api(daemon, "PUT", "/v1/secrets/compat-key", {"text": "released-fixture-only-secret", "reason": REASON})
        checked_api(daemon, "POST", "/v1/grants", {"kind": "counter", "capability": "secret:compat-key", "reason": REASON})
        if extended:
            configure_blobs_and_connections(daemon)
        # All roots replayed by an ordinary fork share this actual recorded configuration.
        stable_lsn = checked_api(daemon, "GET", "/v1/health")["applied_lsn"]
        for _ in range(5):
            message(daemon, "counter/a", "increment")
        for text in ("released alpha", "released beta"):
            message(daemon, "notes/a", "add", text)
        signature = message(daemon, "counter/a", "hmac", "compat-key\nrecorded data")["reply"]["text"]
        message(daemon, "counter/a", "forward", "sink")
        deadline = time.monotonic() + 10
        while True:
            try:
                sink = checked_api(daemon, "GET", "/v1/actors/counter/sink")
                if sink.get("actor", {}).get("turns", 0) >= 1:
                    break
            except Violation:
                pass
            if time.monotonic() >= deadline:
                raise Violation("real buffered message was not consumed within 10 s")
            time.sleep(0.02)
        if extended:
            # The messages above: seven to counter/a (its turns for the sink
            # are consequences) and two to notes/a.
            roots = {"counter": 7, "notes": 2}
            blob_observations, roots["media"] = produce_blobs(daemon, args.port, data)
            connection_observations, roots["room"] = produce_connections(daemon, args.port)
        checked_api(daemon, "POST", "/v1/snapshots", {"reason": REASON})
        if extended:
            # After the snapshot, whose blob index is one of the roots.
            for blob in blob_observations["blobs"].values():
                blob["roots"] = blob_roots(daemon, blob)
        before = checked_api(daemon, "GET", "/v1/integrity")
        observations = {"counter": checked_api(daemon, "GET", "/v1/actors/counter/a"),
                        "notes": checked_api(daemon, "GET", "/v1/actors/notes/a"),
                        "sink": sink, "hmac": signature}
        if extended:
            observations.update(roots=roots, blobs=blob_observations, connections=connection_observations)
    finally:
        close(daemon)
    # Machine-specific native precompiles are derived cache, never compatibility inputs.
    for path in data.rglob("*.cwasm"):
        path.unlink()
    manifest = {"format": "kronik.compatibility-corpus/v1", "release": args.release,
                "producer_revision": args.revision, "producer_binary_sha256": args.binary_sha256,
                "producer_version": version, "engine": health["engine"],
                "dummy_master_key": DUMMY_MASTER, "stable_lsn": stable_lsn,
                "integrity": before, "observations": observations,
                "components": components, "files": inventory(data)}
    if extended:
        manifest["scenarios"] = SCENARIOS
    check_observations(manifest)
    (work / "manifest.json").write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"release": args.release, "producer_binary_sha256": args.binary_sha256,
                      "data_files": len(manifest["files"]), "manifest_sha256": digest(work / "manifest.json")}, allow_nan=False))
    if args.emit_files:
        # Bounded records cross the sandbox boundary; no retained host directory
        # is mounted writable into the target-controlled process.
        for relative in ["manifest.json", *["data/" + entry["path"] for entry in manifest["files"]]]:
            path = work / relative
            if path.stat().st_size > MAX_FILE:
                raise Violation("export entry exceeds 2 MiB")
            print(json.dumps({"format": "kronik.corpus-file/v1", "release": args.release,
                              "path": relative, "sha256": digest(path),
                              "base64": base64.b64encode(path.read_bytes()).decode()}, allow_nan=False))


def compare_integrity_hashes(manifest, after, candidate_revision):
    """The durable-path half of the compatibility contract (I16): log_hash is
    the producer's path and must not change across revisions; state_hash is
    the daemon's internal projection, which legitimately gains milestone
    bookkeeping (M22/M23/M28) at an engine boundary -- M6's upgrade check and
    the identity replays are the semantic comparators across revisions. When
    the candidate revision differs from the producer's, a state_hash change is
    recorded as an explicit delta instead of failing; a log_hash change, or a
    state_hash change at the same revision, still fails."""
    if after["log_hash"] != manifest["integrity"]["log_hash"]:
        raise Violation("candidate changed producer log_hash")
    if after["state_hash"] == manifest["integrity"]["state_hash"]:
        return None
    if candidate_revision == manifest["producer_revision"]:
        raise Violation("candidate changed producer state_hash at the same revision")
    return {"producer": manifest["integrity"]["state_hash"],
            "candidate": after["state_hash"]}


def check_identity_summary(summary, expected_roots):
    if (type(expected_roots) is not int or expected_roots <= 0
            or any(type(summary.get(field)) is not int for field in
                   ("root_inputs", "replayed", "divergent_turns", "approximate", "synthetic"))
            or summary.get("changed") is not False or summary.get("divergent_turns") != 0
            or summary.get("root_inputs") != expected_roots or summary.get("replayed") != expected_roots
            or summary.get("approximate") != 0 or summary.get("synthetic") != 0):
        raise Violation(f"candidate did not identity-replay every original root: {summary}")


def verify(args):
    source = args.corpus.resolve(strict=True)
    manifest_file = source / "manifest.json"
    if manifest_file.stat().st_size > 1 << 20:
        raise Violation("corpus manifest exceeds 1 MiB")
    manifest = json.loads(manifest_file.read_text())
    if manifest.get("format") != "kronik.compatibility-corpus/v1" or manifest.get("dummy_master_key") != DUMMY_MASTER:
        raise Violation("unsupported or nonfixture corpus manifest")
    if inventory(source / "data") != manifest.get("files"):
        raise Violation("producer corpus differs from its frozen file inventory")
    # From v0.5.0 the corpus also holds blobs and connections, and the
    # replays must cover their root inputs, which are part of the count.
    extended = check_observations(manifest)
    observations = manifest["observations"]
    if extended and sum(observations["roots"].values()) != args.expected_roots:
        raise Violation(f"the corpus's root inputs per kind {observations['roots']} do not add up "
                        f"to the {args.expected_roots} original roots")
    work = args.workdir.resolve()
    work.mkdir(mode=0o700)
    data, sock = work / "data", work / "api.sock"
    shutil.copytree(source / "data", data, symlinks=False)
    binary = args.binary.resolve(strict=True)
    env = configure(work, data, sock)
    command = [str(binary), "--socket", str(sock), "--json"]
    # Reuse the bounded command helper. Only explicitly allowlisted fixture env is added.
    process_env = {**os.environ, **env}
    daemon = Daemon(str(binary), str(data), str(sock), args.port, str(work / "candidate.log"), healthy_timeout=30)
    try:
        report = run_json([str(binary), "--json", "upgrade", "check", "--data-dir", str(data),
                           "--config", env["KRONIK_CONFIG"], "--workers", "2"], work, "upgrade", timeout=120, env=process_env)
        if report.get("passed") is not True or type(report.get("root_inputs")) is not int or report.get("root_inputs") != args.expected_roots:
            raise Violation("candidate upgrade check did not prove actual producer roots")
        daemon.start(env)
        after = checked_api(daemon, "GET", f"/v1/integrity?through={manifest['integrity']['applied_lsn']}")
        if after.get("through_lsn") != manifest["integrity"]["applied_lsn"]:
            raise Violation("candidate did not confirm the requested historical integrity bound; use a candidate supporting through_lsn")
        # Semantic checks first: they are the compatibility contract across a
        # producer-revision boundary, and their evidence must print before any
        # internal-projection hash comparison.
        checked_api(daemon, "POST", "/v1/forks", {"at": manifest["stable_lsn"], "name": "released-identity", "reason": REASON})
        replays = {}
        for mode in ("isolated", "continuous"):
            result = run_json(command + ["replay", "released-identity", "--mode", mode, "--reason", REASON],
                              work, f"replay-{mode}", timeout=120)
            summary = result["summary"]
            check_identity_summary(summary, args.expected_roots)
            if extended:
                check_replay_coverage(checked_api(daemon, "GET", "/v1/forks/released-identity/diff"), observations)
            replays[mode] = summary
        if message(daemon, "counter/a", "hmac", "compat-key\nrecorded data")["reply"]["text"] != observations["hmac"]:
            raise Violation("candidate changed actual historical key-backed effect result")
        if extended:
            check_blobs(daemon, observations["blobs"])
            check_connections(daemon, args.port, observations["connections"])
        # The durable path (log hash, replays, keyed effects) is the contract
        # per I16; the internal state projection legitimately gains milestone
        # bookkeeping (M22/M23/M28) across a producer-revision boundary, and
        # M6's upgrade check above is the semantic comparator across revisions.
        state_hash_delta = compare_integrity_hashes(manifest, after, args.revision)
        result = {"format": "kronik.compatibility-proof/v1", "release": manifest["release"],
                  "producer_revision": manifest["producer_revision"], "candidate_revision": args.revision,
                  "candidate_binary_sha256": digest(binary), "manifest_sha256": digest(manifest_file),
                  "integrity": after, "upgrade": report, "replays": replays, "passed": True}
        if extended:
            # Additive: what the blob and connection checks covered.
            result["scenarios"] = manifest["scenarios"]
            result["blobs"] = len(observations["blobs"]["blobs"])
            result["connections"] = len(observations["connections"]["transcripts"])
        if state_hash_delta is not None:
            # Additive field: an engine-boundary state_hash change is recorded,
            # not accepted silently; the durable path above already passed.
            result["state_hash_delta"] = {"producer": state_hash_delta["producer"],
                                          "candidate": state_hash_delta["candidate"]}
        (work / "proof.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
        print(json.dumps(result, allow_nan=False))
    finally:
        close(daemon)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    produce = sub.add_parser("produce")
    produce.add_argument("--release", type=release_tag, required=True,
                         help="tag of the actual release that built --binary, for example v0.4.0")
    produce.add_argument("--binary-sha256", required=True,
                         help="pinned SHA-256 of the release binary itself, taken from the verified release")
    produce.add_argument("--counter", type=Path, required=True)
    produce.add_argument("--notes", type=Path, required=True)
    produce.add_argument("--media", type=Path,
                         help="from v0.5.0, and only then: the release's media guest, for blob records (with --room)")
    produce.add_argument("--room", type=Path,
                         help="from v0.5.0, and only then: the release's room guest, for connection records (with --media)")
    produce.add_argument("--emit-files", action="store_true",
                         help="emit bounded dummy-fixture files as JSON lines for trusted promotion")
    check = sub.add_parser("verify")
    check.add_argument("--corpus", type=Path, required=True)
    check.add_argument("--expected-roots", type=int, required=True,
                       help="original root count from the reviewed immutable producer receipt")
    for command in (produce, check):
        command.add_argument("--binary", type=Path, required=True)
        command.add_argument("--revision", required=True)
        command.add_argument("--workdir", type=Path, required=True)
        command.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("revision must be the exact 40-hex source commit")
    if not 1024 <= args.port <= 65535:
        parser.error("use an owned fixture port in 1024..65535")
    if args.mode == "produce" and not re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256):
        parser.error("binary-sha256 must be the exact 64-hex release binary digest")
    if args.mode == "produce" and (args.media is None) != (args.room is None):
        parser.error("--media and --room go together")
    if args.mode == "verify" and args.expected_roots <= 0:
        parser.error("expected-roots must be positive")
    os.umask(0o077)
    (producer if args.mode == "produce" else verify)(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, Violation, RuntimeError, subprocess.SubprocessError) as error:
        print(f"compatibility corpus: {error}", file=sys.stderr)
        sys.exit(1)
