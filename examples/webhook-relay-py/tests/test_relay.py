import hashlib
import hmac
import json
import pathlib
import sys
import tomllib
import unittest

# The SDK is [tool.kronik] sdk in pyproject.toml.
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["kronik"]["sdk"]))

from kronik.testkit import TestHost  # noqa: E402

TARGET = "https://webhooks.example.com/relay"
SIGNING_KEY = "test-signing-key"


class RelayTest(unittest.TestCase):
    def relay_host(self):
        """A host with the relay's grants and secrets, as an operator sets them up."""
        host = TestHost.start(ROOT)
        self.addCleanup(host.close)
        host.secret("relay-signing-key", SIGNING_KEY)
        host.secret("relay-auth", "tok-123")
        host.grant("webhook-relay", "secret:relay-signing-key")
        host.grant("webhook-relay", "secret:relay-auth")
        host.grant("webhook-relay", "http:webhooks.example.com", "idempotency-keyed")
        return host

    def test_a_webhook_is_forwarded_signed_with_the_secret_inserted_by_the_host(self):
        host = self.relay_host()
        host.send("webhook-relay/acme", "configure", json.dumps({"auth_secret": "relay-auth"}))
        host.stub(TARGET, status=202)

        res = host.http("POST", "/hooks/acme", body={"event": "paid", "amount": 42})
        self.assertEqual(res.status, 200)
        delivery = res.json()
        self.assertEqual(delivery["status"], "delivered")
        self.assertEqual(delivery["target_status"], 202)

        [sent] = host.requests()
        header = dict(sent.headers).get
        self.assertEqual(sent.url, TARGET)
        self.assertEqual(
            json.loads(sent.body),
            {"webhook": delivery["id"], "source": "acme", "payload": {"event": "paid", "amount": 42}},
        )
        self.assertEqual(header("x-webhook-id"), delivery["id"])
        self.assertEqual(header("x-signature"), "sha256=" + hmac.new(SIGNING_KEY.encode(), sent.body, hashlib.sha256).hexdigest())
        self.assertEqual(header("authorization"), "Bearer tok-123")
        self.assertEqual(len(header("idempotency-key")), 64)

        # The record stays readable.
        self.assertEqual(host.http("GET", f"/hooks/acme/{delivery['id']}").json()["status"], "delivered")
        self.assertEqual(host.http("GET", "/hooks/acme/nope").status, 404)

    def test_a_failure_that_may_go_away_is_retried_by_a_timer(self):
        host = self.relay_host()
        host.stub(TARGET, status=200)
        host.stub(TARGET, status=503, times=1)

        first = host.http("POST", "/hooks/acme", body="plain text")
        self.assertEqual(first.status, 502)
        delivery = first.json()
        self.assertEqual([delivery["status"], delivery["attempts"], delivery["target_status"]], ["retrying", 1, 503])
        now = host.advance(0)
        self.assertEqual(delivery["next_retry_ms"], now + 1000)

        host.advance(999)
        self.assertEqual(len(host.requests()), 1, "not before the retry is due")
        host.advance(1)
        retried = host.http("GET", f"/hooks/acme/{delivery['id']}").json()
        self.assertEqual([retried["status"], retried["attempts"]], ["delivered", 2])
        sent = host.requests()
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0].body, sent[1].body, "the same request both times")

    def test_a_target_outside_the_grants_fails_at_once(self):
        host = self.relay_host()
        host.send("webhook-relay/acme", "configure", json.dumps({"target": "https://elsewhere.example.com/x"}))
        res = host.http("POST", "/hooks/acme", body={})
        self.assertEqual(res.status, 502)
        delivery = res.json()
        self.assertEqual(delivery["status"], "failed")
        self.assertIn("CAPABILITY_NOT_GRANTED", delivery["error"] or "")
        self.assertEqual(len(host.requests()), 0, "nothing was sent")


if __name__ == "__main__":
    unittest.main()
