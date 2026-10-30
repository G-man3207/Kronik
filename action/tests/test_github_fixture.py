"""Real-fixture trust-boundary tests; the driver smoke uses actual Kronik/TLS/Docker."""

import hashlib
import io
import json
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = runpy.run_path(str(ROOT / "scripts/e2e-github-flow.py"))


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for name, data, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(data) if kind == tarfile.REGTYPE else 0
            member.linkname = "../outside"
            tar.addfile(member, io.BytesIO(data) if member.size else None)
    output.seek(0)
    return output


class GithubFixtureTest(unittest.TestCase):
    def test_only_one_exact_manifest_path_bypasses_aggregate_ci(self):
        ci = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        flow = yaml.load((ROOT / ".github/workflows/kronik.yml").read_text(), Loader=yaml.BaseLoader)
        for trigger in ("push", "pull_request"):
            self.assertEqual(ci["on"][trigger]["paths-ignore"], ["examples/github-flow/proof/change.json"])
            self.assertEqual(flow["on"][trigger]["paths"], ["examples/github-flow/proof/change.json"])
        self.assertEqual(set(flow["jobs"]), {"propose", "verify", "promote"})
        self.assertIn("head.repo.full_name == github.repository", flow["jobs"]["propose"]["if"])
        self.assertEqual(flow["jobs"]["promote"]["environment"]["name"], "kronik-production")

    def test_manifest_accepts_only_two_real_pinned_components(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "change.json"
            for name in FIXTURE["COMPONENTS"]:
                path.write_text(json.dumps({"component": name, "reason": "actual component fixture"}))
                self.assertEqual(FIXTURE["change"](path)["component"], name)
            for value in ({"component": "../counter.wasm", "reason": "bad path"},
                          {"component": "https://example.invalid/a.wasm", "reason": "bad URL"},
                          {"component": "counter.wasm", "reason": "line\ninjection"},
                          {"component": "counter.wasm", "reason": "", "extra": 1},
                          {"component": [], "reason": "wrong type"}):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    FIXTURE["change"](path)

    def test_plaintext_bootstrap_bearer_master_and_private_keys_do_not_ship(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state.db").write_bytes(b"synthetic state")
            for name in ("admin.token", "bootstrap.token", "other.token", "master.key", "server.pem", "ca.key"):
                (root / name).write_bytes(b"kronik_" + b"A" * 43)
            self.assertEqual(set(FIXTURE["files"](root)), {"state.db"})
            (root / "unknown.bin").write_bytes(b"kronik_" + b"B" * 43)
            with self.assertRaisesRegex(ValueError, "plaintext credential"):
                FIXTURE["files"](root)
            (root / "unknown.bin").write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nprivate")
            with self.assertRaisesRegex(ValueError, "private key"):
                FIXTURE["files"](root)

    def test_restore_rejects_paths_links_duplicates_credentials_and_missing_files(self):
        data = b"synthetic data"
        expected = {"file": hashlib.sha256(data).hexdigest()}
        cases = [[("../outside", data, tarfile.REGTYPE)],
                 [("/absolute", data, tarfile.REGTYPE)],
                 [("file", b"", tarfile.SYMTYPE)],
                 [("file", b"", tarfile.LNKTYPE)],
                 [("file", data, tarfile.REGTYPE), ("./file", data, tarfile.REGTYPE)],
                 [("admin.token", data, tarfile.REGTYPE)],
                 [("file", b"changed", tarfile.REGTYPE)], []]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    FIXTURE["unpack"](archive(entries), Path(directory), expected)
        with tempfile.TemporaryDirectory() as directory:
            FIXTURE["unpack"](archive([("file", data, tarfile.REGTYPE)]), Path(directory), expected)
            self.assertEqual((Path(directory) / "file").read_bytes(), data)

    def test_artifact_identity_covers_metadata_and_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "proof.json").write_text('{"proposal_id":"p-111111111111"}')
            (root / "data.tar.gz").write_bytes(b"synthetic archive identity")
            original = FIXTURE["artifact_digest"](root)
            (root / "proof.json").write_text('{"proposal_id":"p-222222222222"}')
            self.assertNotEqual(FIXTURE["artifact_digest"](root), original)
            second = FIXTURE["artifact_digest"](root)
            (root / "data.tar.gz").write_bytes(b"changed archive identity")
            self.assertNotEqual(FIXTURE["artifact_digest"](root), second)

    def test_approval_record_decoder_fails_closed_on_truncation_and_duplicates(self):
        self.assertEqual(FIXTURE["wire_fields"](b"\x0a\x01x\x18\x01"), {1: b"x", 3: 1})
        for data in (b"\x0a\x05x", b"\x0a\x01x\x0a\x01y", b"\x09", b"\x00", b"\x80" * 11):
            with self.subTest(data=data), self.assertRaises(ValueError):
                FIXTURE["wire_fields"](data)


if __name__ == "__main__":
    unittest.main()
