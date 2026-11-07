"""Cross-revision state_hash handling in the compatibility corpus checker:
the durable path (log_hash) is strict; the internal state projection records
an explicit delta across a producer-revision boundary instead of failing, and
still fails at the same revision. The producer also refuses a binary that is
not the pinned, declared release; these tests use synthetic stand-ins and
produce no corpus."""
import argparse
import runpy
import stat
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
CORPUS = runpy.run_path(str(SCRIPTS / "compatibility-corpus.py"))
COMPARE = CORPUS["compare_integrity_hashes"]
REASON = CORPUS["Violation"]
EXPECTED_VERSION = CORPUS["expected_version"]
RELEASE_TAG = CORPUS["release_tag"]
PRODUCE = CORPUS["producer"]
DIGEST = CORPUS["digest"]


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


class ReleaseIdentityTest(unittest.TestCase):
    def test_each_actual_release_reports_its_own_version_line(self):
        self.assertEqual("kronik 0.1.0-dev", EXPECTED_VERSION("v0.1.0"))
        self.assertEqual("kronik 0.3.0", EXPECTED_VERSION("v0.3.0"))
        self.assertEqual("kronik 0.4.0", EXPECTED_VERSION("v0.4.0"))

    def test_a_later_release_needs_no_script_edit_and_no_development_string(self):
        for release in ("v0.2.0", "v0.4.1", "v0.5.0", "v0.10.12"):
            with self.subTest(release=release):
                self.assertEqual("kronik " + release[1:], EXPECTED_VERSION(release))

    def test_a_release_is_an_exact_tag(self):
        for value in ("", "0.4.0", "v0.4", "v1.0.0", "v0.4.0-dev", "v0.4.0\n", " v0.4.0", "V0.4.0", "v0.4.x", "v0.4.0.1"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    RELEASE_TAG(value)
                with self.assertRaises(argparse.ArgumentTypeError):
                    EXPECTED_VERSION(value)


class ProducerBinaryTest(unittest.TestCase):
    """A stand-in that reports a fixed version; the checks run before any daemon starts."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "kronik"
        self.binary.write_text("#!/bin/sh\nprintf 'kronik 0.3.0\\nwasmtime 50.0.0\\n'\n")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)

    def produce(self, release, binary_sha256):
        return PRODUCE(argparse.Namespace(release=release, binary=self.binary, binary_sha256=binary_sha256,
                                          workdir=self.root / "work"))

    def test_a_binary_other_than_the_pinned_digest_is_refused(self):
        with self.assertRaisesRegex(REASON, "pinned release SHA-256"):
            self.produce("v0.3.0", "0" * 64)

    def test_a_pinned_binary_of_another_release_is_not_the_declared_release(self):
        with self.assertRaisesRegex(REASON, "not the declared actual release v0.4.0"):
            self.produce("v0.4.0", DIGEST(self.binary))


if __name__ == "__main__":
    unittest.main()
