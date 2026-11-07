"""Synthetic export records test promotion, not released logs or runtime compatibility."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest

PROMOTE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "promote-compatibility-corpus.py"))
RELEASE = "v0.1.0"
PRODUCER = "a" * 64


def record(path, payload, release=RELEASE):
    return {"format": "kronik.corpus-file/v1", "release": release, "path": path,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "base64": base64.b64encode(payload).decode()}


def records(release=RELEASE):
    payload = b"known synthetic fixture bytes"
    manifest = {"format": "kronik.compatibility-corpus/v1", "release": release,
                "producer_binary_sha256": PRODUCER, "dummy_master_key": "44" * 32,
                "files": [{"path": "log/0001", "bytes": len(payload),
                           "sha256": hashlib.sha256(payload).hexdigest()}]}
    return [record("manifest.json", json.dumps(manifest).encode(), release), record("data/log/0001", payload, release)]


def stream(items):
    return io.BytesIO(b"ordinary process diagnostic\n" + b"".join(json.dumps(item).encode() + b"\n" for item in items))


class PromotionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.destination = Path(self.temporary.name) / "promoted"

    def promote(self, items):
        return PROMOTE["promote"](stream(items), self.destination, RELEASE, PRODUCER)

    def test_exact_export_preserves_actual_bytes_and_private_modes(self):
        result = self.promote(records())
        self.assertTrue(result["promoted"])
        self.assertEqual(b"known synthetic fixture bytes", (self.destination / "data/log/0001").read_bytes())
        self.assertEqual(0o700, self.destination.stat().st_mode & 0o777)
        self.assertEqual(0o600, (self.destination / "data/log/0001").stat().st_mode & 0o777)

    def test_existing_destination_is_never_regenerated(self):
        self.promote(records())
        previous = (self.destination / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.promote(records())
        self.assertEqual(previous, (self.destination / "manifest.json").read_bytes())

    def test_digest_mismatch_is_refused_before_payload_publication(self):
        items = records()
        items[1]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.promote(items)
        self.assertFalse((self.destination / "data/log/0001").exists())

    def test_missing_payload_is_not_a_complete_corpus(self):
        with self.assertRaisesRegex(ValueError, "exactly match"):
            self.promote(records()[:1])

    def test_uninventoried_payload_is_not_silently_promoted(self):
        with self.assertRaisesRegex(ValueError, "exactly match"):
            self.promote(records() + [record("data/log/0002", b"unexpected")])

    def test_duplicate_file_is_not_silently_overwritten(self):
        items = records()
        with self.assertRaisesRegex(ValueError, "duplicate corpus file"):
            self.promote(items + items[1:])

    def test_other_producer_manifest_is_refused(self):
        items = records()
        manifest = json.loads(base64.b64decode(items[0]["base64"]))
        manifest["producer_binary_sha256"] = "b" * 64
        items[0] = record("manifest.json", json.dumps(manifest).encode())
        with self.assertRaisesRegex(ValueError, "pinned dummy producer"):
            self.promote(items)

    def test_unsupported_inventory_version_is_refused(self):
        items = records()
        manifest = json.loads(base64.b64decode(items[0]["base64"]))
        manifest["format"] = "kronik.compatibility-corpus/v2"
        items[0] = record("manifest.json", json.dumps(manifest).encode())
        with self.assertRaisesRegex(ValueError, "pinned dummy producer"):
            self.promote(items)

    def test_duplicate_json_keys_do_not_change_the_accepted_record(self):
        duplicate = b'{"format":"ignored","format":"kronik.corpus-file/v1"}\n'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            PROMOTE["promote"](io.BytesIO(duplicate), self.destination, RELEASE, PRODUCER)

    def test_nonfixture_output_path_is_refused(self):
        with self.assertRaisesRegex(ValueError, "only manifest.json and data/"):
            self.promote([record("notes.txt", b"not an exported fixture")])

    def test_invalid_base64_is_refused(self):
        items = records()
        items[1]["base64"] = "not base64!"
        with self.assertRaises(ValueError):
            self.promote(items)

    def test_oversized_stream_record_stops_at_its_bounded_read(self):
        with self.assertRaisesRegex(ValueError, "exceeds 3 MiB"):
            PROMOTE["promote"](io.BytesIO(b"x" * (PROMOTE["MAX_LINE"] + 1)), self.destination, RELEASE, PRODUCER)

    def test_a_later_actual_release_is_promoted_like_the_earlier_ones(self):
        result = PROMOTE["promote"](stream(records("v0.4.0")), self.destination, "v0.4.0", PRODUCER)
        self.assertTrue(result["promoted"])
        self.assertEqual("v0.4.0", json.loads((self.destination / "manifest.json").read_text())["release"])

    def test_records_of_another_release_are_not_promoted(self):
        with self.assertRaisesRegex(ValueError, "no producer manifest"):
            PROMOTE["promote"](stream(records("v0.3.0")), self.destination, "v0.4.0", PRODUCER)


class ReleaseTagTest(unittest.TestCase):
    def test_every_actual_release_tag_is_accepted(self):
        for tag in ("v0.1.0", "v0.3.0", "v0.4.0", "v0.10.12"):
            with self.subTest(tag=tag):
                self.assertEqual(tag, PROMOTE["release_tag"](tag))

    def test_a_release_is_an_exact_tag(self):
        for value in ("", "0.4.0", "v0.4", "v1.0.0", "v0.4.0-dev", "v0.4.0\n", " v0.4.0", "V0.4.0", "../v0.4.0"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                PROMOTE["release_tag"](value)


if __name__ == "__main__":
    unittest.main()
