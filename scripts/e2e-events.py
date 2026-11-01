#!/usr/bin/env python3
"""Finite M30 proof against a supplied real binary; no build or external service.

The launcher uses an already-installed pinned Debian Docker image with network
none, read-only root/toolchain/binary/scripts, dropped capabilities, resource
limits and private size-capped tmpfs. Only bounded non-secret JSON evidence is
retained in a fresh 0700 --scratch. No pulls, installs or host-execution fallback.
"""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import resource
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import unittest
from unittest import mock
from contextlib import closing
import urllib.parse

MAX = 1 << 20
KEY = b"m30-disposable-webhook-key-only"
NEXT_KEY = b"m30-disposable-webhook-next-key-only"
REASON = "M30 owned finite proof"
ENV = {"PATH": "/usr/bin:/usr/sbin:/bin", "HOME": "/work/home", "TMPDIR": "/work/tmp", "LANG": "C.UTF-8",
       "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"}
RUNTIME = "debian@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4"


def failure_summary(stderr, exit_code):
    text = stderr[-65536:].decode("utf-8", errors="replace")
    frames = [int(match) for match in re.findall(r'File "/tools/e2e-events\.py", line ([0-9]{1,5}), in ', text)]
    result = {"code": "ISOLATED_EVENT_SCENARIO_FAILED", "exit_code": exit_code, "source_lines": frames[-8:]}
    status = re.search(r"^ApiFailure: \(([1-5][0-9]{2}), '(SECRET_UNAVAILABLE|UNEXPECTED_API_STATUS)'\)$",
                       text, re.MULTILINE)
    if status:
        result["http_status"] = int(status.group(1))
        result["api_code"] = status.group(2)
    cursor = re.search(r"^AssertionError: \('CURSOR_STALL', ([0-9]{1,20}), ([0-9]{1,20}), ([0-9]{1,20}), ([0-9]{1,20}), '([A-Za-z_0-9]{1,32})'\)$",
                       text, re.MULTILINE)
    if cursor:
        code = cursor.group(5)
        result["cursor"] = dict(zip(("expected", "reported", "durable", "pending"),
                                   (int(cursor.group(index)) for index in range(1, 5))))
        result["cursor"]["error_code"] = code if code in (
            "NONE", "http_400", "http_503", "SECRET_UNAVAILABLE", "cursor_save", "webhook_checkpoint",
            "webhook_state", "webhook_source", "webhook_config_audit", "log_read", "execution_revoked",
            "UNAUTHENTICATED", "UNAVAILABLE") else "OTHER"
    return result


class DiagnosticTests(unittest.TestCase):
    def test_failure_metadata_does_not_reflect_private_stderr(self):
        summary = failure_summary(b'private-secret\nFile "/tools/e2e-events.py", line 69, in api\n'
                                  b"ApiFailure: (503, 'SECRET_UNAVAILABLE')\n", 1)
        self.assertEqual(summary, {"code": "ISOLATED_EVENT_SCENARIO_FAILED", "exit_code": 1,
                                   "source_lines": [69], "http_status": 503, "api_code": "SECRET_UNAVAILABLE"})
        self.assertNotIn("private-secret", json.dumps(summary))

    def test_failure_metadata_is_bounded_and_does_not_invent_a_status(self):
        summary = failure_summary(b"x" * 70000 + b"\nTimeoutError: private-secret\n", 1)
        self.assertEqual(summary, {"code": "ISOLATED_EVENT_SCENARIO_FAILED", "exit_code": 1,
                                   "source_lines": []})

    def test_cursor_evidence_exposes_only_coordinates_and_known_error_codes(self):
        summary = failure_summary(b"private-secret\nAssertionError: ('CURSOR_STALL', 17, 15, 15, 16, 'http_400')\n", 1)
        self.assertEqual(summary["cursor"], {"expected": 17, "reported": 15, "durable": 15,
                                            "pending": 16, "error_code": "http_400"})
        private = failure_summary(b"AssertionError: ('CURSOR_STALL', 17, 15, 15, 16, 'private_secret')\n", 1)
        self.assertEqual(private["cursor"]["error_code"], "OTHER")
        self.assertNotIn("private_secret", json.dumps(private))

    def test_readiness_waits_only_for_the_coded_inventory_hold(self):
        for status, code, hold in [(503, "SECRET_UNAVAILABLE", True),
                                   (503, "UNEXPECTED_API_STATUS", False), (403, "UNEXPECTED_API_STATUS", False)]:
            with mock.patch.dict(readable_events.__globals__, {"api": mock.Mock(side_effect=ApiFailure(status, code))}):
                if hold:
                    self.assertIsNone(readable_events("/owned.sock"))
                else:
                    with self.assertRaises(ApiFailure):
                        readable_events("/owned.sock")


def wait_for(description, predicate, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("timeout: " + description)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=5)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(5)
        self.sock.connect(self.path)


class ApiFailure(AssertionError):
    def __init__(self, status, code):
        super().__init__(status, code)
        self.status, self.code = status, code


def api(path, route, body=None, method=None, expected=200):
    with closing(UnixHTTP(path)) as connection:
        encoded = None if body is None else json.dumps(body).encode()
        connection.request(method or ("POST" if body is not None else "GET"), route, encoded,
                           {"content-type": "application/json"})
        response = connection.getresponse()
        raw = response.read(MAX + 1)
        assert len(raw) <= MAX, "API response exceeds the fixture bound"
        payload = json.loads(raw) if raw else {}
        if response.status != expected:
            inventory_hold = (isinstance(payload, dict) and isinstance(payload.get("error"), dict)
                              and payload["error"].get("code") == "SECRET_UNAVAILABLE")
            raise ApiFailure(response.status, "SECRET_UNAVAILABLE" if inventory_hold else "UNEXPECTED_API_STATUS")
        return payload


def readable_events(path):
    try:
        return api(path, "/v1/events?source=actor-native&limit=256")
    except ApiFailure as error:
        if error.status == 503 and error.code == "SECRET_UNAVAILABLE":
            return None
        raise


def records(path):
    if not path.exists():
        return []
    # A receiver may be between write and fsync; inspect complete JSONL only.
    return [json.loads(line) for line in path.read_text().splitlines() if line.endswith("}")]


def stop(process, hard=False):
    if process and process.poll() is None:
        process.send_signal(signal.SIGKILL if hard else signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def sse_first(port, token, resume=None):
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as connection:
        headers = {"authorization": "Bearer " + token}
        if resume is not None:
            headers["last-event-id"] = json.dumps(resume, separators=(",", ":"))
        connection.request("GET", "/v1/events/stream?source=actor-native", headers=headers)
        response = connection.getresponse()
        assert response.status == 200 and response.getheader("content-type") == "text/event-stream"
        fields = {}
        total = 0
        for _ in range(100):
            line = response.readline(MAX + 1)
            total += len(line)
            assert line and total <= MAX
            if line == b"\n":
                if fields.get("event") == "operational":
                    event = json.loads(fields["data"])
                    cursor = json.loads(fields["id"])
                    assert cursor["streams"][source_domain(event["source"])] == {
                        "source": event["source"], "subindex": event["subindex"] + 1}
                    return event, cursor
                fields = {}
            elif b":" in line and not line.startswith(b":"):
                name, value = line.decode().rstrip("\r\n").split(":", 1)
                fields[name] = value.lstrip(" ")
        raise AssertionError("no finite SSE event")


def source_domain(source):
    if source["kind"] == "metadata":
        assert set(source) == {"kind", "index"}
        return "metadata"
    assert source["kind"] == "actor" and set(source) == {"kind", "shard", "lsn"}
    return "actor-native" if source["shard"] is None else f"actor-{source['shard']}"


def native_coordinate(source):
    assert source_domain(source) == "actor-native"
    return source["lsn"]


def exact(reader, length):
    value = reader.read(length)
    assert len(value) == length, "truncated WebSocket frame"
    return value


def websocket_first(port, token, source="actor-native", expected_status=101):
    nonce = base64.b64encode(os.urandom(16)).decode()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        reader = connection.makefile("rb")
        request = (f"GET /v1/events/ws?source={source} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                   f"Authorization: Bearer {token}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {nonce}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        connection.sendall(request.encode())
        assert f" {expected_status} ".encode() in reader.readline(4096)
        if expected_status != 101:
            return None
        headers = {}
        for _ in range(100):
            line = reader.readline(4096)
            assert line
            if line == b"\r\n":
                break
            name, value = line.decode().split(":", 1)
            headers[name.lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1((nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        assert headers.get("sec-websocket-accept") == expected
        for _ in range(20):
            first, second = exact(reader, 2)
            assert first & 0x80 and not second & 0x80
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", exact(reader, 2))[0]
            elif length == 127:
                length = struct.unpack("!Q", exact(reader, 8))[0]
            assert length <= MAX
            payload = exact(reader, length)
            if first & 15 == 1:
                event = json.loads(payload)
                if event.get("schema") == "kronik.event/v1":
                    return event
        raise AssertionError("no finite WS event")


def negative_requests(port, event):
    body = json.dumps(event, separators=(",", ":")).encode()
    event_id = event["id"]
    timestamp = "123"
    def headers(identity=event_id, payload=body):
        signed = f"kronik.webhook/v1\n{timestamp}\n{identity}\n".encode() + payload
        return {"content-type": "application/json", "kronik-event-id": identity,
                "idempotency-key": identity, "kronik-timestamp-ms": timestamp,
                "kronik-signature-version": "v1", "kronik-signature": "v1=" + hmac.new(KEY, signed, hashlib.sha256).hexdigest()}
    bad_mac = headers()
    bad_mac["kronik-signature"] = "v1=" + "0" * 64
    wrong = event_id.rsplit(".", 1)[0] + "." + ("f" * 64 if not event_id.endswith("f" * 64) else "0" * 64)
    for payload, metadata in [(body, bad_mac), (body + b" ", headers()), (body, headers(wrong))]:
        with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as connection:
            connection.request("POST", "/events", payload, metadata)
            response = connection.getresponse()
            assert response.status == 400
            response.read(MAX)


def inside(binary):
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    # Wasmtime reserves sparse virtual pools; Docker's memory cgroup caps actual RAM.
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 << 20, 128 << 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = Path("/work")
    for name in ("home", "tmp", "data"):
        (root / name).mkdir(mode=0o700)
    config = root / "kronik.toml"
    api_socket = root / "api.sock"
    journal = root / "receiver.jsonl"
    key_file = root / "receiver.key"
    key_file.write_bytes(KEY)
    key_file.chmod(0o600)
    previous_key_file = root / "receiver-previous.key"
    previous_key_file.write_bytes(KEY)
    previous_key_file.chmod(0o600)
    api_port, gateway_port, admin_port, receiver_port = (free_port() for _ in range(4))
    daemon = receiver = None
    handles = []
    env = {**ENV, "KRONIK_MASTER_KEY": "17" * 32}

    def configuration(webhook=False, version=1):
        text = (f'[server]\ndata_dir = "/work/data"\napi_socket = "/work/api.sock"\n'
                f'http_listen = "127.0.0.1:{gateway_port}"\nadmin_listen = "127.0.0.1:{admin_port}"\n'
                f'api_listen = "127.0.0.1:{api_port}"\n[log]\ndisk_reserve = "0B"\n'
                '[foreign]\nrun_dir = "/work/foreign-run"\n[secrets]\nrefresh = "1s"\n')
        if webhook:
            text += (f'[[events.webhook]]\nname = "proof"\nurl = "http://127.0.0.1:{receiver_port}/events"\n'
                     f'secret = "webhook-key"\nversion = {version}\n')
        config.write_text(text)
        config.chmod(0o600)

    def launch():
        log = (root / "daemon.log").open("ab")
        handles.append(log)
        process = subprocess.Popen([binary, "serve", "--config", str(config)], stdout=log, stderr=log, env=env)
        def ready():
            if process.poll() is not None:
                raise AssertionError("supplied daemon exited during startup")
            try:
                return readable_events(api_socket)
            except (OSError, http.client.HTTPException):
                return None
        wait_for("actual daemon API", ready, 30)
        return process

    def receiver_launch(fail=0, lose=0, duplicates=0, expected_ids=(), previous=False, hold_body=None):
        output = (root / "receiver.log").open("ab")
        handles.append(output)
        command = [sys.executable, "/tools/events-receiver.py", "--port", str(receiver_port),
                   "--secret-file", str(key_file), "--journal", str(journal), "--requests", "512",
                   "--timeout", "40", "--idle-timeout", "2", "--fail-first", str(fail), "--lose-ack-first", str(lose),
                   "--min-duplicates", str(duplicates)]
        if previous:
            command += ["--previous-secret-file", str(previous_key_file)]
        if hold_body is not None:
            command += ["--hold-first-success-until", str(hold_body)]
        for identity in expected_ids:
            command += ["--expected-id", identity]
        process = subprocess.Popen(command, stdout=output, stderr=output, env=ENV)
        def ready():
            if process.poll() is not None:
                raise AssertionError("finite receiver exited before binding")
            try:
                with socket.create_connection(("127.0.0.1", receiver_port), timeout=0.2):
                    return True
            except OSError:
                return False
        wait_for("owned receiver", ready)
        return process

    try:
        configuration()
        daemon = launch()
        created = api(api_socket, "/v1/secrets/webhook-key", {"text": KEY.decode(), "reason": REASON}, "PUT")
        version = created["secret"]["version"]
        rotated = api(api_socket, "/v1/secrets/webhook-key", {"text": NEXT_KEY.decode(), "reason": REASON}, "PUT")
        next_version = rotated["secret"]["version"]
        assert next_version != version
        token = api(api_socket, "/v1/tokens", {"name": "event-proof-admin", "scopes": ["admin"], "reason": REASON})["secret"]
        page = wait_for("certified inventory after secret setup", lambda: readable_events(api_socket), 30)
        assert not page["more"] and page["events"]
        events = page["events"]
        first = events[0]
        expected_ids = {event["id"] for event in events}
        streamed, resume = sse_first(api_port, token)
        assert streamed["id"] == first["id"]
        assert len(events) > 1
        reconnected, _next_resume = sse_first(api_port, token, resume)
        assert reconnected["id"] == events[1]["id"]
        assert reconnected["id"] != streamed["id"]
        assert websocket_first(api_port, token)["id"] == first["id"]
        for unavailable in ("actor-0", "metadata"):
            try:
                api(api_socket, f"/v1/events/stream?source={unavailable}")
            except ApiFailure as error:
                assert error.status == 400
            else:
                raise AssertionError("unavailable SSE source was accepted")
            assert websocket_first(api_port, token, unavailable, 400) is None
        cli = subprocess.run([binary, "--socket", str(api_socket), "--json", "events", "tail",
                              "--source", "actor-native", "--limit", "1"],
                             check=True, capture_output=True, timeout=10, env=ENV)
        assert json.loads(cli.stdout.splitlines()[0])["id"] == first["id"]
        stop(daemon)
        configuration(True, version)
        # This generation cannot ACK before the driver kills and restarts it.
        receiver = receiver_launch(fail=512, duplicates=2, expected_ids=expected_ids)
        daemon = launch()
        failed = wait_for("real signed 503 receipt", lambda: next((r for r in records(journal) if r["status"] == 503), None))
        stop(daemon, hard=True)
        before = json.loads((root / "data/export.json").read_text())["events-proof:actor-native"]
        assert before["state"]["pending"] is not None
        assert native_coordinate(before["state"]["source"]) == before["lsn"]
        assert before["lsn"] < native_coordinate(before["state"]["pending"]["source"])
        assert before["state"]["pending"]["schema"] == "kronik.webhook-batch/v1"
        assert before["state"]["pending"]["pin"]["version"] == version
        stop(receiver)
        configuration(True, next_version)
        key_file.write_bytes(NEXT_KEY)
        body_release = root / "webhook-body-release"
        body_ready = body_release.with_name(body_release.name + ".ready")
        receiver = receiver_launch(lose=1, duplicates=2, previous=True, hold_body=body_release)
        daemon = launch()
        held_id = wait_for("actual successful response headers before its body",
                           lambda: body_ready.read_text() if body_ready.exists() else None)
        assert held_id == failed["id"]
        end = time.monotonic() + 1
        while time.monotonic() < end:
            progress = api(api_socket, "/v1/events/webhooks")["webhooks"][0]
            saved = json.loads((root / "data/export.json").read_text())["events-proof:actor-native"]
            assert native_coordinate(progress["cursor"]) == before["lsn"], "headers advanced the API cursor before EOF"
            assert saved["lsn"] == before["lsn"], "headers advanced the durable cursor before EOF"
            assert saved["state"]["pending"] == before["state"]["pending"], "headers changed the immutable pending delivery"
            time.sleep(0.02)
        body_release.write_bytes(b"release\n")
        body_release.chmod(0o600)
        receiver.wait(timeout=35)
        assert receiver.returncode == 0
        delivered = records(journal)
        retries = [record for record in delivered if record.get("id") == failed["id"]]
        assert len(retries) >= 3
        assert {record["digest"] for record in retries} == {failed["digest"]}
        assert {record["timestamp_ms"] for record in retries} == {failed["timestamp_ms"]}
        assert any(record["status"] == "lost_ack" for record in retries)
        lost = next(record for record in retries if record["status"] == "lost_ack")
        acknowledged = next(record for record in retries if record["status"] == 200)
        assert acknowledged["received_wall_ms"] - lost["received_wall_ms"] >= 800
        assert lost["key_slot"] == acknowledged["key_slot"] == 1
        assert any(record["status"] == 200 and record["key_slot"] == 0 and record["id"] != failed["id"]
                   for record in delivered)
        rotated_state = json.loads((root / "data/export.json").read_text())["events-proof:actor-native"]["state"]
        assert rotated_state["secret"]["version"] == next_version
        try:
            status = wait_for("durable webhook acknowledgement", lambda: (
                value if native_coordinate((value := api(api_socket, "/v1/events/webhooks"))["webhooks"][0]["cursor"])
                >= native_coordinate(page["applied"]) else None))
        except AssertionError:
            progress = api(api_socket, "/v1/events/webhooks")["webhooks"][0]
            saved = json.loads((root / "data/export.json").read_text())["events-proof:actor-native"]
            pending = saved["state"]["pending"]
            code = progress["last_error"]
            code = code if code in ("http_400", "http_503", "SECRET_UNAVAILABLE", "cursor_save",
                                    "webhook_checkpoint", "webhook_state", "webhook_source", "webhook_config_audit",
                                    "log_read", "execution_revoked", "UNAUTHENTICATED", "UNAVAILABLE") else (
                                        "NONE" if code is None else "OTHER")
            raise AssertionError("CURSOR_STALL", native_coordinate(page["applied"]), native_coordinate(progress["cursor"]),
                                 saved["lsn"], native_coordinate(pending["source"]) if pending else 0, code) from None
        assert status["webhooks"][0]["name"] == "proof:actor-native"
        rewind = {"schema": "kronik.events-cursor/v1", "identity": page["cursor"]["identity"],
                  "streams": {"actor-native": {"source": first["source"], "subindex": 0}}}
        request = {"cursor": rewind, "reason": REASON, "dry_run": True}
        route = "/v1/events/webhooks/proof%3Aactor-native/replay"
        before_dry_run = api(api_socket, "/v1/events/webhooks")["webhooks"][0]["cursor"]
        assert api(api_socket, route, request)["dry_run"]
        assert api(api_socket, "/v1/events/webhooks")["webhooks"][0]["cursor"] == before_dry_run
        # An intent may be delivered once before rewind and again during replay.
        receiver = receiver_launch(duplicates=len(events), previous=True)
        negative_requests(receiver_port, first)
        request["dry_run"] = False
        api(api_socket, route, request)
        receiver.wait(timeout=35)
        assert receiver.returncode == 0
        replayed = records(journal)[len(delivered):]
        assert sum(record["status"] == 400 for record in replayed) == 3
        repeated_ids = {record.get("id") for record in replayed if record.get("duplicate")}
        assert expected_ids.issubset(repeated_ids)
        assert all(record["key_slot"] == 0 for record in replayed if record["status"] == 200)
        final_applied = api(api_socket, "/v1/events")["applied"]
        wait_for("replay durable acknowledgement", lambda:
            native_coordinate(api(api_socket, "/v1/events/webhooks")["webhooks"][0]["cursor"])
            >= native_coordinate(final_applied))
        manifest = json.loads((root / "data/export.json").read_text())
        state = json.dumps(manifest).encode()
        assert KEY not in state and NEXT_KEY not in state
        for event in events:
            assert not set(event["data"]) & {"reason", "token_id", "details"}
        result = {"binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                  "checks": ["real_committed_page", "real_SSE_resume", "real_WS", "real_CLI_tail",
                             "selected_source_SSE_WS_CLI", "unavailable_source_rejected_before_stream", "HMAC",
                             "bad_mac", "body_tamper", "wrong_event", "503_backoff", "lost_ACK_duplicates",
                             "durable_restart_same_body_timestamp_id", "cursor_ack_only",
                             "success_headers_do_not_commit_cursor_before_body_EOF", "dry_run_no_advance", "audited_replay_same_ids",
                             "pending_old_pin_after_config_rotation", "next_and_replay_new_key_same_event_identity"],
                  "initial_event_count": len(events), "retry_event_id": failed["id"],
                  "from_key_version": version, "next_key_version": next_version,
                  "retry_timestamp_ms": failed["timestamp_ms"], "replayed_ids": sorted(expected_ids),
                  "final_cursor": manifest["events-proof:actor-native"]["state"]["source"], "receiver_journal": records(journal)}
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))
    finally:
        stop(daemon)
        stop(receiver)
        for handle in handles:
            handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        if os.environ.get("KRONIK_EVENTS_SANDBOX") != "1":
            parser.error("internal mode requires the isolated launcher")
        inside(str(args.binary))
        return
    if not args.scratch or args.scratch.exists():
        parser.error("--scratch must name a new owned directory")
    docker = shutil.which("docker")
    if not docker:
        parser.error("Docker and the preinstalled pinned runtime are required; host execution is never a fallback")
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--binary must be an existing executable")
    system_ca = Path("/etc/ssl/certs/ca-certificates.crt")
    if not system_ca.is_file():
        parser.error("the existing public system CA bundle is required by the real transport fixture")
    scratch = args.scratch.absolute()
    scratch.mkdir(mode=0o700)
    tools = Path(__file__).resolve().parent
    docker_env = {"PATH": ENV["PATH"], "HOME": str(scratch)}
    subprocess.run([docker, "image", "inspect", RUNTIME], check=True, capture_output=True,
                   timeout=10, env=docker_env)
    name = f"kronik-m30-events-{os.getpid()}-{time.time_ns()}"
    command = [docker, "create", "--pull=never", "--name", name, "--network", "none",
               "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", "64", "--memory", "6g", "--memory-swap", "6g", "--cpus", "1",
               "--ulimit", "core=0:0", "--ulimit", "nofile=256:256",
               "--ulimit", "fsize=134217728:134217728", "--ulimit", "cpu=120:120",
               "--tmpfs", "/work:rw,nosuid,nodev,size=512m,mode=0700",
               "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
               "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
               "--mount", "type=bind,source=/usr,target=/usr,readonly",
               "--mount", f"type=bind,source={system_ca},target=/etc/ssl/certs/ca-certificates.crt,readonly",
               "--mount", f"type=bind,source={binary},target=/target/kronik,readonly",
               "--mount", f"type=bind,source={Path(__file__).resolve()},target=/tools/e2e-events.py,readonly",
               "--mount", f"type=bind,source={tools / 'events-receiver.py'},target=/tools/events-receiver.py,readonly"]
    for library in ("/lib", "/lib64"):
        if Path(library).exists():
            command += ["--mount", f"type=bind,source={Path(library).resolve()},target={library},readonly"]
    command += ["--entrypoint", "/usr/bin/env", RUNTIME, "-i",
                *(f"{key}={value}" for key, value in ENV.items()), "KRONIK_EVENTS_SANDBOX=1",
                sys.executable, "/tools/e2e-events.py", "--inside", "--binary", "/target/kronik"]
    created = False
    try:
        subprocess.run(command, check=True, timeout=15, env=docker_env, capture_output=True)
        created = True
        try:
            result = subprocess.run([docker, "start", "--attach", name], check=True, timeout=150,
                                    env=docker_env, capture_output=True)
        except subprocess.CalledProcessError as error:
            print(json.dumps({"m30_failure_diagnostic": failure_summary(error.stderr, error.returncode)},
                             sort_keys=True), flush=True)
            raise RuntimeError("isolated event scenario failed; see bounded diagnostic") from None
        state = subprocess.run([docker, "inspect", "--format", "{{json .State}}", name],
                               check=True, timeout=10, env=docker_env, capture_output=True)
        assert json.loads(state.stdout)["ExitCode"] == 0, "isolated proof failed"
    finally:
        if created:
            subprocess.run([docker, "rm", "--force", "--volumes", name], check=True,
                           timeout=15, env=docker_env, capture_output=True)
    if len(result.stdout) > MAX:
        raise RuntimeError("proof evidence exceeds its bound")
    evidence = json.loads(result.stdout)
    (scratch / "result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
