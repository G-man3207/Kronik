"""Frozen inventory boundary tests; public-binary replay is a separate exercised check."""
import copy
import json
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
VERIFY = runpy.run_path(str(SCRIPTS / "verify-compatibility.py"))
FIXTURES = SCRIPTS.parent / "tests/compatibility"


class CompatibilityIndexTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.index = json.loads((FIXTURES / "releases.json").read_text())
        for case in self.index["releases"]:
            relatives = [case["manifest"], *[item["path"] for item in case["components"]],
                         *[item["path"] for item in case["contracts"].values()]]
            for relative in relatives:
                destination = self.root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                # Keep source read-only; private mutation fixtures need writable copies.
                shutil.copyfile(FIXTURES / relative, destination)
        self.path = self.root / "releases.json"

    def load(self, index=None):
        self.path.write_text(json.dumps(self.index if index is None else index))
        return VERIFY["load_index"](self.path)

    def test_actual_frozen_source_and_payload_inventory_is_accepted(self):
        cases = self.load()
        self.assertTrue(cases)
        for case in cases:
            self.assertEqual({"counter", "notes"}, {item["role"] for item in case["components"]})

    def test_changed_manifest_bytes_require_new_explicit_provenance(self):
        manifest = self.root / self.index["releases"][0]["manifest"]
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        with self.assertRaisesRegex(VERIFY["Violation"], "manifest digest mismatch"):
            self.load()

    def test_changed_released_component_is_not_an_old_component(self):
        component = self.root / self.index["releases"][0]["components"][0]["path"]
        component.write_bytes(component.read_bytes() + b"changed")
        with self.assertRaisesRegex(VERIFY["Violation"], "payload differs"):
            self.load()

    def test_release_revision_cannot_disagree_with_actual_producer_manifest(self):
        self.index["releases"][0]["producer_revision"] = "f" * 40
        with self.assertRaisesRegex(VERIFY["Violation"], "producer provenance disagrees"):
            self.load()

    def test_duplicate_releases_do_not_hide_missing_coverage(self):
        self.index["releases"].append(copy.deepcopy(self.index["releases"][0]))
        with self.assertRaisesRegex(VERIFY["Violation"], "duplicate actual release"):
            self.load()

    def test_sql_component_cannot_be_replaced_by_another_counter(self):
        self.index["releases"][0]["components"][1] = copy.deepcopy(self.index["releases"][0]["components"][0])
        with self.assertRaisesRegex(VERIFY["Violation"], "SQL component"):
            self.load()

    def test_future_index_format_needs_a_deliberate_reader(self):
        self.index["format"] = "kronik.compatibility-index/v99"
        with self.assertRaisesRegex(VERIFY["Violation"], "unsupported"):
            self.load()

    def test_fixture_reference_must_be_normalized_relative_to_corpus(self):
        self.index["releases"][0]["components"][0]["path"] = "../outside.wasm"
        with self.assertRaisesRegex(VERIFY["Violation"], "normalized and relative"):
            self.load()

    def test_nonobject_index_is_a_clean_format_error(self):
        with self.assertRaisesRegex(VERIFY["Violation"], "must be an object"):
            self.load([])

    def test_omitting_a_published_release_cannot_make_the_matrix_green(self):
        self.index["releases"].pop()
        with self.assertRaises(VERIFY["Violation"]):
            self.load()

    def test_published_release_catalog_cannot_be_implicit(self):
        del self.index["published_releases"]
        with self.assertRaises(VERIFY["Violation"]):
            self.load()

    def test_original_root_count_is_not_a_truthy_flag(self):
        self.index["releases"][0]["root_inputs"] = True
        with self.assertRaises(VERIFY["Violation"]):
            self.load()

    def test_contract_bytes_are_from_the_pinned_tag_not_a_regeneration(self):
        contract = self.root / self.index["releases"][0]["contracts"]["api"]["path"]
        contract.write_bytes(contract.read_bytes() + b" ")
        with self.assertRaises(VERIFY["Violation"]):
            self.load()

    def test_contract_git_object_cannot_be_relabelled_without_bytes(self):
        self.index["releases"][0]["contracts"]["api"]["git_blob"] = "a" * 40
        with self.assertRaises(VERIFY["Violation"]):
            self.load()

    def test_contract_role_cannot_be_relabelled_as_another_source(self):
        self.index["releases"][0]["contracts"]["api"]["source_path"] = "docs/reference/json.md"
        with self.assertRaises(VERIFY["Violation"]):
            self.load()


class OriginalRootIdentityTest(unittest.TestCase):
    def summary(self, roots=9):
        return {"changed": False, "divergent_turns": 0, "root_inputs": roots,
                "replayed": roots, "approximate": 0, "synthetic": 0}

    def test_all_original_roots_are_required_not_just_one_successful_root(self):
        VERIFY["corpus"].check_identity_summary(self.summary(), 9)
        with self.assertRaises(VERIFY["Violation"]):
            VERIFY["corpus"].check_identity_summary(self.summary(8), 9)

    def test_recorded_effect_identity_cannot_be_approximate_or_synthetic(self):
        for field, value in (("changed", True), ("divergent_turns", 1), ("approximate", 1), ("synthetic", 1), ("replayed", 8)):
            with self.subTest(field=field), self.assertRaises(VERIFY["Violation"]):
                VERIFY["corpus"].check_identity_summary({**self.summary(), field: value}, 9)

    def test_json_counts_are_integers_not_float_or_boolean_lookalikes(self):
        for value in (9.0, True, "9"):
            with self.subTest(value=value), self.assertRaises(VERIFY["Violation"]):
                VERIFY["corpus"].check_identity_summary({**self.summary(), "root_inputs": value}, 9)


if __name__ == "__main__":
    unittest.main()
