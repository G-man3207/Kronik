"""Cross-revision state_hash handling in the compatibility corpus checker:
the durable path (log_hash) is strict; the internal state projection records
an explicit delta across a producer-revision boundary instead of failing, and
still fails at the same revision."""
import runpy
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
CORPUS = runpy.run_path(str(SCRIPTS / "compatibility-corpus.py"))
COMPARE = CORPUS["compare_integrity_hashes"]
REASON = CORPUS["Violation"]


def integrity(state_hash, log_hash):
    return {"state_hash": state_hash, "log_hash": log_hash}


class CompareIntegrityHashesTest(unittest.TestCase):
    MANIFEST = {"producer_revision": "a" * 40, "integrity": integrity("state-1", "log-1")}

    def test_log_hash_is_always_strict_even_across_revisions(self):
        after = integrity("state-1", "log-2")
        with self.assertRaises(REASON):
            COMPARE(self.MANIFEST, after, "b" * 40)

    def test_state_hash_change_at_the_same_revision_fails(self):
        after = integrity("state-2", "log-1")
        with self.assertRaises(REASON):
            COMPARE(self.MANIFEST, after, "a" * 40)

    def test_state_hash_change_across_revisions_records_an_explicit_delta(self):
        after = integrity("state-2", "log-1")
        delta = COMPARE(self.MANIFEST, after, "b" * 40)
        self.assertEqual(delta, {"producer": "state-1", "candidate": "state-2"})

    def test_matching_hashes_require_no_delta(self):
        self.assertIsNone(COMPARE(self.MANIFEST, integrity("state-1", "log-1"), "b" * 40))


if __name__ == "__main__":
    unittest.main()
