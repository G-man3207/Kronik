"""Synthetic comparator fixtures only: these are not benchmark evidence."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-performance.py"


def synthetic_report():
    return {
        "format": "kronik.benchmark/v1",
        "profile": "synthetic-comparator-test",
        "rig": {"hardware": {"vcpus": 4, "memory_bytes": 8192},
                "topology": ["one", "two", "three"], "workload": {"requests": 100}},
        "measurements": [
            {"name": "throughput", "unit": "turns/s", "direction": "higher",
             "value": 100, "errors": 0},
            {"name": "latency", "unit": "ms", "direction": "lower",
             "value": 100, "errors": 0},
        ],
        "source": {"revision": "a" * 40, "binary_sha256": "b" * 64,
                   "guest_sha256": "c" * 64},
    }


class PerformanceComparatorTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.baseline = synthetic_report()
        self.candidate = copy.deepcopy(self.baseline)
        self.old = Path(self.directory.name) / "baseline.json"
        self.new = Path(self.directory.name) / "candidate.json"

    def invoke(self, old_bytes=None, new_bytes=None):
        self.old.write_bytes(json.dumps(self.baseline).encode() if old_bytes is None else old_bytes)
        self.new.write_bytes(json.dumps(self.candidate).encode() if new_bytes is None else new_bytes)
        before = (self.old.read_bytes(), self.new.read_bytes())
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.old), str(self.new)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(before, (self.old.read_bytes(), self.new.read_bytes()))
        return result

    def assert_status(self, expected, **kwargs):
        result = self.invoke(**kwargs)
        self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
        return result

    def test_equal_reports_print_every_scenario_deterministically(self):
        result = self.assert_status(0)
        self.assertEqual("", result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(2, len(lines))
        self.assertTrue(lines[0].startswith("latency: old=100 new=100 ms change="))
        self.assertTrue(lines[1].startswith("throughput: old=100 new=100 turns/s change="))
        self.assertIn("PASS", lines[0])
        self.assertIn("errors=0/0", lines[1])
        self.candidate["measurements"].reverse()
        self.candidate["rig"] = dict(reversed(list(self.candidate["rig"].items())))
        self.assertEqual(result.stdout, self.assert_status(0).stdout)

    def test_exact_ten_percent_boundaries_pass(self):
        self.candidate["measurements"][0]["value"] = 90
        self.candidate["measurements"][1]["value"] = 110
        self.assert_status(0)

    def test_decimal_ten_percent_boundary_passes(self):
        self.baseline["measurements"][0]["value"] = 0.1
        self.baseline["measurements"][1]["value"] = 0.1
        self.candidate["measurements"][0]["value"] = 0.09
        self.candidate["measurements"][1]["value"] = 0.11
        self.assert_status(0)

    def test_just_over_boundary_regresses_in_both_directions(self):
        for index, value in ((0, 89.99999999999999), (1, 110.00000000000001)):
            with self.subTest(index=index):
                self.candidate = copy.deepcopy(self.baseline)
                self.candidate["measurements"][index]["value"] = value
                result = self.assert_status(1)
                self.assertIn("REGRESSION", result.stdout)
                self.assertEqual(2, len(result.stdout.splitlines()))

    def test_improvements_in_both_directions_pass(self):
        self.candidate["measurements"][0]["value"] = 1000
        self.candidate["measurements"][1]["value"] = 1
        self.assert_status(0)

    def test_revision_and_binary_changes_are_allowed(self):
        self.candidate["source"]["revision"] = "d" * 40
        self.candidate["source"]["binary_sha256"] = "e" * 64
        self.assert_status(0)

    def test_guest_digest_hex_case_is_not_a_workload_change(self):
        self.candidate["source"]["guest_sha256"] = "C" * 64
        self.assert_status(0)

    def test_report_identity_changes_refuse_comparison(self):
        for field, value in (("profile", "physical-three-node"),
                             ("rig", {"hardware": "different"})):
            with self.subTest(field=field):
                self.candidate = copy.deepcopy(self.baseline)
                self.candidate[field] = value
                result = self.assert_status(1)
                self.assertIn(f"{field} differs", result.stderr)
                self.assertEqual("", result.stdout)
        self.candidate = copy.deepcopy(self.baseline)
        self.candidate["source"]["guest_sha256"] = "d" * 64
        self.assertIn("guest_sha256 differs", self.assert_status(1).stderr)

    def test_rig_booleans_are_not_numeric_settings(self):
        self.baseline["rig"] = {"nodes": 1}
        self.candidate["rig"] = {"nodes": True}
        self.assert_status(1)

    def test_missing_and_unexpected_scenarios_fail(self):
        self.candidate["measurements"].pop()
        self.assertIn("missing candidate scenario: latency", self.assert_status(1).stderr)
        self.candidate = copy.deepcopy(self.baseline)
        self.candidate["measurements"][0]["name"] = "another-scenario"
        result = self.assert_status(1)
        self.assertIn("unexpected candidate scenario: another-scenario", result.stderr)
        self.assertIn("missing candidate scenario: throughput", result.stderr)
        self.assertEqual("", result.stdout)

    def test_unit_or_direction_changes_fail(self):
        for key, value in (("unit", "requests/s"), ("direction", "lower")):
            with self.subTest(key=key):
                self.candidate = copy.deepcopy(self.baseline)
                self.candidate["measurements"][0][key] = value
                self.assertIn(f"{key} differs", self.assert_status(1).stderr)

    def test_errors_in_either_report_fail_even_with_improvement(self):
        for side in ("baseline", "candidate"):
            with self.subTest(side=side):
                self.baseline = synthetic_report()
                self.candidate = copy.deepcopy(self.baseline)
                self.candidate["measurements"][0]["value"] = 1000
                getattr(self, side)["measurements"][0]["errors"] = 1
                self.assertIn("ERROR", self.assert_status(1).stdout)

    def test_all_supported_units_and_arbitrary_scenario_names(self):
        for unit in ("turns/s", "requests/s", "ms", "bytes", "ratio"):
            with self.subTest(unit=unit):
                for report in (self.baseline, self.candidate):
                    report["measurements"][0]["unit"] = unit
                    report["measurements"][0]["name"] = "measured scenario / custom"
                self.assert_status(0)

    def test_duplicate_scenario_names_are_invalid(self):
        self.candidate["measurements"].append(copy.deepcopy(self.candidate["measurements"][0]))
        self.assertIn("duplicate measurement name", self.assert_status(2).stderr)

    def test_duplicate_json_keys_at_every_schema_level_are_invalid(self):
        raw = json.dumps(self.candidate)
        for original, replacement in (
                ('"format":', '"format": "kronik.benchmark/v1", "format":'),
                ('"value": 100', '"value": 100, "value": 100'),
                ('"vcpus": 4', '"vcpus": 4, "vcpus": 4'),
                ('"revision":', '"revision": "' + "d" * 40 + '", "revision":')):
            with self.subTest(original=original):
                result = self.assert_status(2, new_bytes=raw.replace(original, replacement, 1).encode())
                self.assertIn("duplicate JSON key", result.stderr)

    def test_invalid_values_and_errors(self):
        for key, values in (
                ("value", (0, -1, True, False, None, "100", [], {})),
                ("errors", (-1, 0.0, 1.5, True, False, None, "0", [], {})),
                ("direction", ("up", "HIGHER", "", None, [], {})),
                ("unit", ("seconds", "bananas", "", None, [], {})),
                ("name", ("", " ", "line\nbreak", "x" * 129, None, 1))):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.candidate = copy.deepcopy(self.baseline)
                    self.candidate["measurements"][0][key] = value
                    self.assert_status(2)

    def test_nonfinite_and_unrepresentable_numbers_are_invalid(self):
        raw = json.dumps(self.candidate)
        for token in ("NaN", "Infinity", "-Infinity", "1e309", "1e-400", "-0.0"):
            with self.subTest(token=token):
                self.assert_status(2, new_bytes=raw.replace('"value": 100', '"value": ' + token, 1).encode())
        self.assert_status(2, new_bytes=raw.replace('"vcpus": 4', '"vcpus": NaN', 1).encode())

    def test_malformed_source_fields(self):
        for key, values in (("revision", ("a" * 64, "z" * 40, "a" * 39, None, 1)),
                            ("binary_sha256", ("b" * 40, "g" * 64, None, [])),
                            ("guest_sha256", ("c" * 63, "", None, {}))):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.candidate = copy.deepcopy(self.baseline)
                    self.candidate["source"][key] = value
                    self.assert_status(2)

    def test_exact_field_inventories_are_required(self):
        for container in ("report", "measurement", "source"):
            for mode in ("missing", "extra"):
                with self.subTest(container=container, mode=mode):
                    self.candidate = copy.deepcopy(self.baseline)
                    obj = (self.candidate if container == "report" else self.candidate["source"]
                           if container == "source" else self.candidate["measurements"][0])
                    if mode == "missing":
                        del obj[next(iter(obj))]
                    else:
                        obj["extra"] = "ignored fields must not be accepted"
                    self.assert_status(2)

    def test_wrong_top_level_field_types_and_empty_results_are_invalid(self):
        for key, values in (("format", ("v2", None, 1)),
                            ("profile", ("", " ", "x" * 129, None, 1)),
                            ("rig", ({}, [], None, "hardware")),
                            ("measurements", ([], {}, None, [None])),
                            ("source", (None, [], "hashes"))):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.candidate = copy.deepcopy(self.baseline)
                    self.candidate[key] = value
                    self.assert_status(2)
        self.assert_status(2, new_bytes=b"[]")

    def test_measurement_count_is_bounded(self):
        self.candidate["measurements"] = [dict(self.candidate["measurements"][0], name=f"metric-{i}")
                                          for i in range(129)]
        self.assertIn("128", self.assert_status(2).stderr)
        self.candidate["measurements"].pop()
        self.baseline = copy.deepcopy(self.candidate)
        self.assert_status(0)

    def test_file_byte_bound(self):
        raw = json.dumps(self.candidate).encode()
        self.assert_status(0, new_bytes=raw + b" " * (1024 * 1024 - len(raw)))
        self.assertIn("exceeds", self.assert_status(2, new_bytes=b" " * (1024 * 1024 + 1)).stderr)

    def test_numeric_token_and_rig_bounds(self):
        raw = json.dumps(self.candidate)
        self.assert_status(2, new_bytes=raw.replace('"value": 100', '"value": ' + "1" * 129, 1).encode())
        nested = {"leaf": 1}
        for _ in range(17):
            nested = {"nested": nested}
        for rig in (nested, {"list": list(range(129))}, {str(i): i for i in range(129)},
                    {"key": "x" * 1025}, {"bad\nkey": 1}):
            with self.subTest(rig_type=type(rig)):
                self.candidate["rig"] = rig
                self.assert_status(2)

    def test_bad_json_encoding_and_nesting_are_input_errors(self):
        for raw in (b"", b"{", b"{} trailing", b"\xff", b"[" * 1500 + b"]" * 1500):
            with self.subTest(raw=raw[:20]):
                result = self.assert_status(2, new_bytes=raw)
                self.assertNotIn("Traceback", result.stderr)
        self.assert_status(2, old_bytes=b"not json")

    def test_missing_file_and_usage_errors_exit_two(self):
        self.old.write_text(json.dumps(self.baseline))
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.old), str(self.new)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertNotIn("Traceback", result.stderr)
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=10)
        self.assertEqual(2, result.returncode)


if __name__ == "__main__":
    unittest.main()
