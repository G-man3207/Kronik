"""events-receiver.py: verify accepts a correctly signed event and refuses tampered ones."""
from email.message import Message
import hashlib
import hmac
import json
from pathlib import Path
import runpy
import unittest

RECEIVER = runpy.run_path(str(Path(__file__).resolve().parents[1] / "events-receiver.py"))
verify = RECEIVER["verify"]
signing_input = RECEIVER["signing_input"]


class Verify(unittest.TestCase):
    def test_signed_events_pass_and_tampered_ones_fail(self):
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
