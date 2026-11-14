"""The testkit's connections against a real test host (`kronik test-host`)
and the room guest (tests/guests/room). They need a kronik binary in
KRONIK_BIN: scripts/ci.sh sdks runs them after it builds one."""

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from kronik.testkit import TestHost, TestHostError  # noqa: E402

ROOM = ROOT / "tests" / "guests" / "room.wasm"


class ConnectionsTest(unittest.TestCase):
    def setUp(self):
        self.host = TestHost.start(dir=None, wasm=[ROOM])
        self.addCleanup(self.host.close)

    def test_a_test_plays_the_client(self):
        host = self.host
        ada = host.open_connection("/room/lobby/ws?user=ada")
        self.assertTrue(ada.accepted)
        self.assertEqual(ada.response.status, 101)
        [welcome] = host.frames_sent(ada, clear=True).frames
        self.assertEqual((welcome.seq, welcome.kind, welcome.json()["type"]), (0, "text", "welcome"))

        host.send_frame(ada, "echo hi")
        host.send_frame(ada, b"binary raw")
        sent = host.frames_sent(ada, clear=True)
        self.assertEqual([(f.kind, f.body) for f in sent.frames], [("text", b"hi"), ("binary", b"raw")])
        self.assertIsNone(sent.closed)

        host.send_frame(ada, "say hello")
        [message] = host.frames_sent(ada, clear=True).frames
        self.assertEqual((message.kind, message.event, message.id), ("event", "message", "1"))
        self.assertEqual(message.json(), {"type": "message", "seq": 1, "user": "ada", "text": "hello"})

        host.close_connection(ada, initiator="host", cause="restart")
        self.assertEqual(host.frames_sent(ada).closed, (1012, "restart"))
        with self.assertRaises(TestHostError):
            host.send_frame(ada, "say late")
        self.assertIn(f"{ada.connection} host 1012 restart", host.http("GET", "/room/lobby/closes").text())

    def test_refusals_and_client_closes(self):
        host = self.host
        refused = host.open_connection("/room/lobby/ws?user=ada&deny=1")
        self.assertFalse(refused.accepted)
        self.assertEqual(refused.response.status, 403)
        with self.assertRaises(TestHostError):
            host.send_frame(refused, "say hi")
        bob = host.open_connection("/room/lobby/ws?user=bob")
        host.close_connection(bob, code=4001, reason="done")
        cy = host.open_connection("/room/lobby/ws?user=cy")
        host.close_connection(cy, code=1006)
        closes = host.http("GET", "/room/lobby/closes").text().splitlines()
        self.assertIn(f"{bob.connection} client 4001 done", closes)
        self.assertIn(f"{cy.connection} client 1006 ", closes)

    def test_an_event_stream_resumes(self):
        host = self.host
        ada = host.open_connection("/room/lobby/ws?user=ada")
        for text in ("one", "two"):
            host.send_frame(ada, f"say {text}")
        stream = host.open_connection("/room/lobby/events", protocol="sse", headers={"last-event-id": "1"})
        self.assertEqual(stream.response.status, 200)
        self.assertEqual([f.id for f in host.frames_sent(stream).frames], ["2"])


if __name__ == "__main__":
    unittest.main()
