#!/usr/bin/env python3
"""Finite loopback receiver for real `kronik serve` webhook/restart/replay proofs.

Run with a dummy --secret-file, --journal, --requests and optionally --expected-id.
--fail-first 1 returns 503 after durable receipt; --lose-ack-first 1 closes the
connection after durable receipt. A restarted receiver reads its journal and
requires every duplicate identity to carry identical canonical bytes. The parent
proof drives the actual binary, restarts it, and uses ordinary audited rewind.
--hold-first-success-until FILE flushes 200 headers, writes FILE.ready, and
withholds its two-byte body until the owned driver creates FILE or time expires.
No secret, signature, URL, event body or reason is written to the evidence file.
"""

import argparse
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import socket
import time

MAX_BODY = 1 << 20
ID = re.compile(r"ke1\.[0-9a-f]+\.(?:[0-9a-f]+\.actor\.(?:native|0|[1-9][0-9]*)|metadata)\.[1-9][0-9]*\.(0|[1-9][0-9]*)\.[0-9a-f]{64}\Z")


def signing_input(timestamp, event_id, body):
    return f"kronik.webhook/v1\n{timestamp}\n{event_id}\n".encode("ascii") + body


def verify(key, headers, body, expected_ids, previous_keys=()):
    def header(name):
        values = headers.get_all(name, [])
        if len(values) != 1:
            raise ValueError("missing_or_duplicate_header")
        return values[0]

    if header("kronik-signature-version") != "v1":
        raise ValueError("version")
    event_id = header("kronik-event-id")
    if not ID.fullmatch(event_id):
        raise ValueError("identity")
    if expected_ids and event_id not in expected_ids:
        raise ValueError("unexpected_identity")
    if header("idempotency-key") != event_id:
        raise ValueError("idempotency_identity")
    timestamp = header("kronik-timestamp-ms")
    if not re.fullmatch(r"0|[1-9][0-9]*", timestamp) or int(timestamp) > (1 << 64) - 1:
        raise ValueError("timestamp")
    signature = header("kronik-signature")
    message = signing_input(timestamp, event_id, body)
    key_slot = None
    for slot, candidate in enumerate((key, *previous_keys)):
        expected = "v1=" + hmac.new(candidate, message, hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature, expected):
            key_slot = slot
    if key_slot is None:
        raise ValueError("mac")
    event = json.loads(body)
    required = {"schema", "id", "installation", "source", "subindex", "record_kind", "data"}
    if not isinstance(event, dict) or not required.issubset(event):
        raise ValueError("event_shape")
    if event["schema"] != "kronik.event/v1" or event["id"] != event_id:
        raise ValueError("body_identity")
    installation = event["installation"]
    if not isinstance(installation, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", installation):
        raise ValueError("body_identity")
    source = event["source"]
    if not isinstance(source, dict):
        raise ValueError("source_shape")
    if source.get("kind") == "actor":
        if set(source) != {"kind", "shard", "lsn"} or set(event) != required | {"branch"}:
            raise ValueError("actor_shape")
        shard = source["shard"]
        if shard is not None and (type(shard) is not int or not 0 <= shard < 4096):
            raise ValueError("actor_shard")
        branch = event["branch"]
        if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", branch):
            raise ValueError("actor_branch")
        position = source["lsn"]
        suffix = f"{branch.encode().hex()}.actor.{'native' if shard is None else shard}.{position}"
    elif source.get("kind") == "metadata":
        if set(source) != {"kind", "index"} or set(event) != required:
            raise ValueError("metadata_source_shape")
        position = source["index"]
        suffix = f"metadata.{position}"
    else:
        raise ValueError("source_kind")
    if type(position) is not int or not 1 <= position <= (1 << 64) - 1:
        raise ValueError("source_position")
    if type(event["subindex"]) is not int or not 0 <= event["subindex"] <= (1 << 32) - 1:
        raise ValueError("body_subindex")
    if type(event["record_kind"]) is not int or not 1 <= event["record_kind"] <= 255:
        raise ValueError("record_kind")
    derived = f"ke1.{installation.encode().hex()}.{suffix}.{event['subindex']}"
    data = event.get("data", {})
    if not isinstance(data, dict):
        raise ValueError("metadata_shape")
    if data.get("schema") not in ("kronik.audit/v3", "kronik.operation/v1"):
        raise ValueError("projection_version")
    if data.get("schema") == "kronik.operation/v1" and (data.get("kind"), data.get("action")) != ("deadletter", "created"):
        raise ValueError("projection_version")
    if set(data) - {"schema", "kind", "action", "at_wall_ms", "epoch", "effect", "phase", "adoption", "record_hash"}:
        raise ValueError("unsafe_metadata_fields")
    if not {"schema", "kind", "action", "at_wall_ms", "record_hash"}.issubset(data):
        raise ValueError("metadata_shape")
    if not all(isinstance(data[name], str) and data[name] for name in ("kind", "action", "record_hash")):
        raise ValueError("metadata_shape")
    if not re.fullmatch(r"b3k:v3:[0-9a-f]{64}", data["record_hash"]):
        raise ValueError("record_hash")
    derived += "." + data["record_hash"][7:]
    if derived != event_id:
        raise ValueError("body_position")
    for name in ("at_wall_ms", "epoch", "effect"):
        if name in data and (type(data[name]) is not int or not 0 <= data[name] <= (
                (1 << 32) - 1 if name == "effect" else (1 << 64) - 1)):
            raise ValueError("metadata_number")
    if (data["kind"], data["action"]) == ("audit_event", "fleet.state"):
        if (event["record_kind"] != 40 or "epoch" not in data
                or data.get("phase") not in ("pending", "requested", "active", "revoked")):
            raise ValueError("fleet_phase")
    elif "phase" in data:
        raise ValueError("unexpected_phase")
    if "adoption" in data:
        adoption = data["adoption"]
        if (source["kind"] != "metadata" or data["schema"] != "kronik.audit/v3"
                or not isinstance(adoption, dict) or set(adoption) != {"current_projection"}
                or type(adoption["current_projection"]) is not bool):
            raise ValueError("native_adoption")
    if header("content-type").split(";", 1)[0] != "application/json":
        raise ValueError("content_type")
    return event_id, hashlib.sha256(body).hexdigest(), timestamp, key_slot


def self_check():
    from email.message import Message
    key = b"dummy-receiver-proof-key"
    event_id = "ke1.69.6d.actor.native.9.0." + "0" * 64
    event = {"schema": "kronik.event/v1", "id": event_id, "installation": "i", "branch": "m",
             "source": {"kind": "actor", "shard": None, "lsn": 9}, "subindex": 0, "record_kind": 40,
             "data": {"schema": "kronik.audit/v3", "kind": "audit_event", "action": "proposal.create",
                      "at_wall_ms": 123, "record_hash": "b3k:v3:" + "0" * 64}}
    body = json.dumps(event, separators=(",", ":")).encode()

    def headers():
        result = Message()
        for name, value in {"kronik-signature-version": "v1", "kronik-event-id": event_id,
                            "idempotency-key": event_id, "kronik-timestamp-ms": "123",
                            "content-type": "application/json", "kronik-signature": "v1=" + hmac.new(
                                key, signing_input("123", event_id, body), hashlib.sha256).hexdigest()}.items():
            result[name] = value
        return result

    assert verify(key, headers(), body, {event_id})[0] == event_id
    assert verify(key, headers(), body, {event_id})[3] == 0
    assert verify(b"next-dummy-key", headers(), body, {event_id}, (key,))[3] == 1
    cases = [(key, headers(), body + b" ", {event_id}),
             (b"wrong", headers(), body, {event_id}),
             (key, headers(), body, {"ke1.69.6d.actor.native.10.0." + "0" * 64})]
    for name, value in (("kronik-event-id", "ke1.69.6d.actor.native.10.0." + "0" * 64),
                        ("kronik-signature-version", "v2"), ("kronik-timestamp-ms", "124")):
        altered = headers()
        altered.replace_header(name, value)
        cases.append((key, altered, body, {event_id}))
    duplicate = headers()
    duplicate["kronik-event-id"] = event_id
    cases.append((key, duplicate, body, {event_id}))
    for args in cases:
        try:
            verify(*args)
        except ValueError:
            continue
        raise AssertionError("negative webhook verification accepted")
    # Framing/closed-shape fixtures only: these are not producer or Raft proof.
    event_id = "ke1.69.metadata.53.0." + "0" * 64
    event = {"schema": "kronik.event/v1", "id": event_id, "installation": "i",
             "source": {"kind": "metadata", "index": 53}, "subindex": 0, "record_kind": 40,
             "data": {"schema": "kronik.audit/v3", "kind": "audit_event",
                      "action": "installation.identity", "at_wall_ms": 0,
                      "record_hash": "b3k:v3:" + "0" * 64}}
    for current in (False, True):
        event["data"]["adoption"] = {"current_projection": current}
        body = json.dumps(event, separators=(",", ":")).encode()
        assert verify(key, headers(), body, {event_id})[0] == event_id
    event["record_kind"] = 45
    event["data"].update(kind="secret_version", action="secret.version", at_wall_ms=1)
    for current in (False, True):
        event["data"]["adoption"] = {"current_projection": current}
        body = json.dumps(event, separators=(",", ":")).encode()
        assert verify(key, headers(), body, {event_id})[0] == event_id
    invalid_adoptions = (None, {}, {"current_projection": 1}, {"current_projection": "false"},
                         {"current_projection": False, "issuer": "private-NEEDLE"})
    for adoption in invalid_adoptions:
        event["data"]["adoption"] = adoption
        body = json.dumps(event, separators=(",", ":")).encode()
        try:
            verify(key, headers(), body, {event_id})
        except ValueError:
            continue
        raise AssertionError("unsafe native adoption metadata accepted")
    print(json.dumps({"self_check": "passed",
                      "scope": "HMAC framing and closed event shape only, not committed-record projection",
                      "negative_cases": len(cases) + len(invalid_adoptions)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--previous-secret-file", type=Path,
                        help="one retiring receiver key during a configured signing-version rotation")
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--requests", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--idle-timeout", type=float, help="finish after verified delivery becomes idle; requests stays a hard cap")
    parser.add_argument("--expected-id", action="append", default=[])
    parser.add_argument("--fault-id", help="fault only this actual committed event; other sources remain independent")
    parser.add_argument("--fail-first", type=int, default=0)
    parser.add_argument("--lose-ack-first", type=int, default=0)
    parser.add_argument("--hold-first-success-until", type=Path)
    parser.add_argument("--min-duplicates", type=int, default=0)
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    if not args.secret_file or not args.journal or args.requests < 1 or args.timeout <= 0:
        parser.error("finite receive requires --secret-file, --journal, positive requests/timeout")
    if args.idle_timeout is not None and args.idle_timeout <= 0:
        parser.error("--idle-timeout must be positive")
    key = args.secret_file.read_bytes()
    if not key:
        parser.error("empty key file")
    previous_keys = () if args.previous_secret_file is None else (args.previous_secret_file.read_bytes(),)
    if any(not candidate for candidate in previous_keys):
        parser.error("empty previous key file")
    seen = {}
    if args.journal.exists():
        for line in args.journal.read_text().splitlines():
            record = json.loads(line)
            if record["status"] in (200, 503, "lost_ack"):
                previous = seen.setdefault(record["id"], record["digest"])
                if previous != record["digest"]:
                    parser.error("inconsistent durable identity")
    counts = {"requests": 0, "accepted": 0, "rejected": 0, "duplicates": 0}
    expected_ids = set(args.expected_id)
    remaining_failures = args.fail_first
    remaining_lost_acks = args.lose_ack_first
    remaining_hold = args.hold_first_success_until is not None
    last_activity = [time.monotonic()]

    def journal(record):
        with args.journal.open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, sort_keys=True) + "\n")
            output.flush()
            os.fsync(output.fileno())
        directory = os.open(args.journal.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def setup(self):
            self.request.settimeout(3)
            super().setup()

        def log_message(self, *_):
            pass

        def do_POST(self):
            nonlocal remaining_failures, remaining_lost_acks, remaining_hold
            counts["requests"] += 1
            last_activity[0] = time.monotonic()
            self.connection.settimeout(3)
            try:
                lengths = self.headers.get_all("content-length", [])
                if self.headers.get("transfer-encoding") or len(lengths) != 1:
                    raise ValueError("framing")
                length = int(lengths[0])
                if not 0 < length <= MAX_BODY:
                    raise ValueError("size")
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError("truncated")
                event_id, digest, timestamp, key_slot = verify(key, self.headers, body, expected_ids, previous_keys)
                previous = seen.get(event_id)
                if previous and previous != digest:
                    raise ValueError("duplicate_body_changed")
                counts["duplicates"] += previous is not None
                counts["accepted"] += 1
                seen[event_id] = digest
                status = 200
                selected_fault = args.fault_id is None or event_id == args.fault_id
                if selected_fault and remaining_failures > 0:
                    remaining_failures -= 1
                    status = 503
                elif selected_fault and remaining_lost_acks > 0:
                    remaining_lost_acks -= 1
                    status = "lost_ack"
                journal({"id": event_id, "digest": digest, "timestamp_ms": timestamp,
                         "status": status, "duplicate": previous is not None, "key_slot": key_slot,
                         "received_wall_ms": time.time_ns() // 1_000_000})
                if status == "lost_ack":
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                self.send_response(status)
                if status == 503:
                    self.send_header("retry-after", "1")
                hold = selected_fault and status == 200 and remaining_hold
                if hold:
                    remaining_hold = False
                self.send_header("content-length", "2" if hold else "0")
                self.end_headers()
                if hold:
                    self.wfile.flush()
                    release = args.hold_first_success_until
                    ready = release.with_name(release.name + ".ready")
                    ready.write_text(event_id, encoding="ascii")
                    ready.chmod(0o600)
                    while not release.exists():
                        if time.monotonic() >= deadline:
                            self.close_connection = True
                            return
                        time.sleep(0.01)
                    self.wfile.write(b"ok")
                    self.wfile.flush()
            except (ValueError, KeyError, TypeError, UnicodeError, OSError):
                counts["rejected"] += 1
                journal({"status": 400})
                self.send_response(400)
                self.send_header("content-length", "0")
                self.end_headers()

    with http.server.HTTPServer(("127.0.0.1", args.port), Handler) as server:
        server.timeout = 0.2
        print(json.dumps({"ready": True, "port": server.server_port}), flush=True)
        deadline = time.monotonic() + args.timeout
        while counts["requests"] < args.requests and time.monotonic() < deadline:
            server.handle_request()
            if args.idle_timeout is not None and counts["accepted"] > 0 \
                    and counts["duplicates"] >= args.min_duplicates and expected_ids.issubset(seen) \
                    and time.monotonic() - last_activity[0] >= args.idle_timeout:
                break
    print(json.dumps(counts, sort_keys=True), flush=True)
    complete = counts["requests"] == args.requests if args.idle_timeout is None else (
        counts["requests"] < args.requests and counts["accepted"] > 0
        and time.monotonic() - last_activity[0] >= args.idle_timeout)
    if not complete or counts["duplicates"] < args.min_duplicates:
        raise SystemExit(1)
    if not expected_ids.issubset(seen):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
