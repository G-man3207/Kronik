"""e2e-events.py: its failure diagnostic is bounded and never echoes private stderr."""
import json
from pathlib import Path
import runpy
import sys
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))  # e2e-events.py imports kronikd
EVENTS = runpy.run_path(str(SCRIPTS / "e2e-events.py"))
failure_summary = EVENTS["failure_summary"]
readable_events = EVENTS["readable_events"]
ApiFailure = EVENTS["ApiFailure"]


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
