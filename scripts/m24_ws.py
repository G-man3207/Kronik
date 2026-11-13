#!/usr/bin/env python3
"""A WebSocket and SSE client with the standard library only, for M24's
acceptance scripts (docs/design/m24-connections.md, section 18): enough
RFC 6455 for a test (the handshake with the accept check, masked text
frames, ping replies, close) and an SSE reader. No extensions.

As a program it records a chat-ts session for criterion 2:

    m24_ws.py session --gateway 127.0.0.1:47510 --room lobby

Three WebSocket members and one SSE follower join, the members chat, ask
the bot, post over HTTP, one member vanishes without a close and the others
leave cleanly. It prints a JSON summary and exits 1 if a client saw
something it should not have.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import struct
import sys
import time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Closed(Exception):
    """The server closed the connection: its code and reason."""

    def __init__(self, code, reason):
        super().__init__(f"closed {code} {reason}")
        self.code = code
        self.reason = reason


class WebSocket:
    """One client connection. `recv` answers pings and returns text or bytes."""

    def __init__(self, host, port, path, origin=None, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            f"GET {path} HTTP/1.1",
            f"host: {host}:{port}",
            "upgrade: websocket",
            "connection: Upgrade",
            f"sec-websocket-key: {key}",
            "sec-websocket-version: 13",
        ]
        if origin:
            lines.append(f"origin: {origin}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed during the handshake")
            self.buf += chunk
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        status_line, *header_lines = head.decode("latin-1").split("\r\n")
        self.status = int(status_line.split()[1])
        self.headers = {k.strip().lower(): v.strip() for k, v in (h.split(":", 1) for h in header_lines if ":" in h)}
        if self.status != 101:
            raise ConnectionError(f"handshake answered HTTP {self.status}")
        want = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        if self.headers.get("sec-websocket-accept") != want:
            raise ConnectionError("wrong Sec-WebSocket-Accept")

    def _send(self, opcode, payload):
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            head = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
        elif n <= 0xFFFF:
            head = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
        else:
            head = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def send_text(self, text):
        self._send(1, text.encode())

    def send_json(self, value):
        self.send_text(json.dumps(value, separators=(",", ":")))

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise Closed(1006, "connection closed without a close frame")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self, timeout=10.0):
        """The next text (str) or binary (bytes) message; raises Closed or socket.timeout."""
        self.sock.settimeout(timeout)
        message, opcode = b"", None
        while True:
            b0, b1 = self._read(2)
            fin, op, n = b0 & 0x80, b0 & 0x0F, b1 & 0x7F
            if b1 & 0x80:
                raise ConnectionError("masked frame from the server")
            if n == 126:
                (n,) = struct.unpack("!H", self._read(2))
            elif n == 127:
                (n,) = struct.unpack("!Q", self._read(8))
            payload = self._read(n)
            if op == 9:
                self._send(10, payload)
            elif op == 10:
                continue
            elif op == 8:
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                raise Closed(code, payload[2:].decode("utf-8", "replace"))
            else:
                if op != 0:
                    opcode = op
                message += payload
                if fin:
                    return message.decode() if opcode == 1 else message

    def recv_json(self, timeout=10.0):
        return json.loads(self.recv(timeout))

    def close(self, code=1000, reason=""):
        """A clean close: send ours, wait for the server's."""
        self._send(8, struct.pack("!H", code) + reason.encode())
        try:
            while True:
                self.recv(5.0)
        except Closed:
            pass
        finally:
            self.sock.close()

    def vanish(self):
        """Drop the TCP connection without a close frame (the server records 1006)."""
        self.sock.close()


class EventStream:
    """An SSE GET: yields (event, id, data) per event."""

    def __init__(self, host, port, path, last_event_id=None, timeout=10.0):
        self.conn = http.client.HTTPConnection(host, port, timeout=timeout)
        headers = {"accept": "text/event-stream"}
        if last_event_id is not None:
            headers["last-event-id"] = str(last_event_id)
        self.conn.request("GET", path, headers=headers)
        self.response = self.conn.getresponse()
        self.status = self.response.status

    def next_event(self):
        event, ident, data = "", "", []
        while True:
            line = self.response.fp.readline()
            if not line:
                raise Closed(1006, "the stream ended")
            line = line.decode().rstrip("\r\n")
            if line == "":
                if data or event or ident:
                    return event or "message", ident, "\n".join(data)
                continue
            if line.startswith(":"):
                continue
            field, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
            if field == "event":
                event = value
            elif field == "id":
                ident = value
            elif field == "data":
                data.append(value)

    def close(self):
        self.conn.close()


def http_json(host, port, method, path, body=None):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    data = None if body is None else json.dumps(body).encode()
    conn.request(method, path, body=data, headers={"content-type": "application/json"} if data else {})
    res = conn.getresponse()
    raw = res.read()
    conn.close()
    return res.status, (json.loads(raw) if raw else None)


def until(ws, predicate, what, timeout=10.0):
    """Reads frames until one satisfies `predicate`; returns it."""
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(f"no {what} within {timeout} s")
        frame = ws.recv_json(left)
        if predicate(frame):
            return frame


def session(args):
    """Records a chat-ts session: what criterion 2 replays."""
    host, port = args.gateway.rsplit(":", 1)
    port = int(port)
    room = args.room
    origin = f"http://{host}:{port}"
    problems = []
    members = {}
    for user in ("ada", "bob", "cy"):
        ws = WebSocket(host, port, f"/chat/{room}/ws?user={user}", origin=origin)
        welcome = until(ws, lambda f: f["type"] == "welcome", "welcome")
        members[user] = (ws, welcome)
    follower = EventStream(host, port, f"/chat/{room}/events")
    if follower.status != 200:
        problems.append(f"SSE answered {follower.status}")
    refused = None
    try:
        WebSocket(host, port, f"/chat/{room}/ws?user=Bad!", origin=origin)
    except ConnectionError as e:
        refused = str(e)
    if refused != "handshake answered HTTP 400":
        problems.append(f"a bad user was not refused with 400: {refused}")
    seqs = []
    for i in range(args.messages):
        user = ("ada", "bob", "cy")[i % 3]
        ws = members[user][0]
        ws.send_json({"type": "say", "text": f"message {i} from {user}", "id": f"{user}-{i}"})
        echo = until(ws, lambda f: f["type"] == "message" and f.get("id") == f"{user}-{i}", "echo")
        seqs.append(echo["seq"])
    members["ada"][0].send_json({"type": "bot", "prompt": "replay me deterministically", "id": "ada-bot"})
    until(members["ada"][0], lambda f: f["type"] == "message" and f.get("user") == "bot", "bot answer")
    status, posted = http_json(host, port, "POST", f"/chat/{room}/messages", {"user": "dee", "text": "over HTTP", "id": "dee-1"})
    if status != 201:
        problems.append(f"POST answered {status}")
    else:
        seqs.append(posted["seq"])
    events = []
    while len(events) < len(seqs):
        events.append(follower.next_event())
    if [e[0] for e in events] != ["message"] * len(events):
        problems.append(f"follower events {events[:3]}...")
    members["cy"][0].vanish()
    until(members["ada"][0], lambda f: f["type"] == "left" and f["user"] == "cy", "cy's left")
    members["bob"][0].close(1000, "bye")
    until(members["ada"][0], lambda f: f["type"] == "left" and f["user"] == "bob", "bob's left")
    members["ada"][0].close(1000, "bye")
    follower.close()
    status, page = http_json(host, port, "GET", f"/chat/{room}/messages?after=0&limit=1000")
    stored = [m["seq"] for m in page["messages"]] if status == 200 else []
    if stored != sorted(stored) or len(stored) < len(seqs):
        problems.append(f"stored messages {stored}")
    summary = {"room": room, "messages": len(stored), "sse_events": len(events), "problems": problems}
    print(json.dumps(summary))
    return 1 if problems else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("session", help="record a chat-ts session")
    s.add_argument("--gateway", required=True, help="host:port of the gateway")
    s.add_argument("--room", default="lobby")
    s.add_argument("--messages", type=int, default=30)
    args = parser.parse_args()
    return session(args)


if __name__ == "__main__":
    sys.exit(main())
