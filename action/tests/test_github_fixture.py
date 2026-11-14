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
    def test_hosted_builds_start_only_by_hand_and_the_proof_path_stays_exact(self):
        # CI, nightly and release must not start from a push, pull request or
        # schedule. The proof workflow is not a general build: a dispatch
        # cannot stand in for its real events, so it still starts only for one
        # manifest path.
        automatic = {"push", "pull_request", "pull_request_target", "schedule", "workflow_run"}
        for name in ("ci.yml", "nightly.yml", "release.yml", "isolation.yml"):
            workflow = yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)
            self.assertIn("workflow_dispatch", workflow["on"], name)
            self.assertTrue(automatic.isdisjoint(workflow["on"]), name)
        flow = yaml.load((ROOT / ".github/workflows/kronik.yml").read_text(), Loader=yaml.BaseLoader)
        for trigger in ("push", "pull_request"):
            self.assertEqual(flow["on"][trigger]["paths"], ["examples/github-flow/proof/change.json"])
        self.assertNotIn("workflow_dispatch", flow["on"])
        self.assertNotIn("schedule", flow["on"])
        self.assertEqual(set(flow["jobs"]), {"propose", "verify", "promote"})
        self.assertIn("head.repo.full_name == github.repository", flow["jobs"]["propose"]["if"])
        self.assertEqual(flow["jobs"]["promote"]["environment"]["name"], "kronik-production")

    def test_the_isolation_proofs_keep_their_evidence_and_pin_every_action(self):
        # ADR 0133: the M21 job twice (R1 active and lifted), the microVM tool
        # bundle, then M20; every job keeps its evidence whatever happened and
        # fails unless every proof left a pass. Every action is pinned by commit.
        text = (ROOT / ".github/workflows/isolation.yml").read_text()
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow["jobs"]), {"m21", "microvm-tools", "m20"})
        self.assertEqual(workflow["jobs"]["m21"]["strategy"]["matrix"]["userns"], ["restricted", "lifted"])
        self.assertEqual(workflow["jobs"]["m20"]["needs"], "microvm-tools")
        for name, job in workflow["jobs"].items():
            uploads = [step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@")]
            self.assertEqual(len(uploads), 1, name)
            self.assertEqual(uploads[0]["if"], "always()", name)
            self.assertEqual(uploads[0]["with"]["if-no-files-found"], "error", name)
            if name != "microvm-tools":
                verify = [step for step in job["steps"] if "isolation-ci.py verify" in step.get("run", "")]
                self.assertEqual(len(verify), 1, name)
                self.assertEqual(verify[0]["if"], "always()", name)
            for step in job["steps"]:
                if "actions/checkout@" in step.get("uses", ""):
                    self.assertEqual(step["with"]["persist-credentials"], "false", name)
        for line in text.splitlines():
            if "uses:" in line:
                reference = line.split("uses:", 1)[1].split("#", 1)[0].strip()
                action, _, version = reference.partition("@")
                self.assertRegex(version, r"^[0-9a-f]{40}$", line)
                self.assertRegex(line, r"# v\d+\.\d+\.\d+$", line)

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

    def test_approval_binds_original_artifact_not_the_post_promote_hash(self):
        # Captured real v0.3.0 Approval from local product smoke, not GitHub approval.
        payload = bytes.fromhex(
            "0a0e702d34626531633165653934646612207d0294f84c407b295fcddc5a055847550b"
            "3e820a231fce43ea7e4203a47ddb87180522440a11746f6b656e3a6d31302d70726f"
            "6d6f746512286c6f63616c2070726f6475637420736d6f6b652c206e6f7420476974"
            "48756220617070726f76616c18fcf09aee9834")
        gated = {"proposal_id": "p-4be1c1ee94df", "verified_through_lsn": 5,
                 "diff_hash": "b3:7d0294f84c407b295fcddc5a055847550b3e820a231fce43ea7e4203a47ddb87"}
        record = FIXTURE["approval_record"](payload, 7, gated, github=False)
        self.assertEqual(record["diff_hash"], gated["diff_hash"])
        self.assertEqual(record["verified_through_lsn"], 5)
        self.assertEqual(record["reason"], "local product smoke, not GitHub approval")
        post_promote_hash = "b3:d4b04ff2124863ce86e42a90ae49ce0bf39202f7545d757f5fef9083c8f58109"
        for field, value in (("proposal_id", "p-000000000000"), ("diff_hash", post_promote_hash),
                             ("verified_through_lsn", 7)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "original gated"):
                FIXTURE["approval_record"](payload, 7, dict(gated, **{field: value}), github=False)
        with self.assertRaisesRegex(ValueError, "original gated"):
            FIXTURE["approval_record"](payload + b"\x28\x01", 7, gated, github=False)

    def test_approval_record_decoder_fails_closed_on_truncation_and_duplicates(self):
        self.assertEqual(FIXTURE["wire_fields"](b"\x0a\x01x\x18\x01"), {1: b"x", 3: 1})
        for data in (b"\x0a\x05x", b"\x0a\x01x\x0a\x01y", b"\x09", b"\x00", b"\x80" * 11):
            with self.subTest(data=data), self.assertRaises(ValueError):
                FIXTURE["wire_fields"](data)


if __name__ == "__main__":
    unittest.main()
