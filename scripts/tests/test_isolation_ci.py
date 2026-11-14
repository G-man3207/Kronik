"""The isolation workflow's driver: what it decides, without changing the host."""
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock

CI = runpy.run_path(str(Path(__file__).resolve().parents[1] / "isolation-ci.py"))
Refused = CI["Refused"]


class HostChanges(unittest.TestCase):
    def test_steps_that_change_the_host_refuse_anywhere_but_a_hosted_runner(self):
        for environment in ({}, {"GITHUB_ACTIONS": "true"}, {"RUNNER_ENVIRONMENT": "github-hosted"},
                            {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}):
            with mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(Refused, msg=str(environment)):
                    CI["hosted_only"]("a step")

    def test_the_user_namespace_restriction_is_recorded_as_it_was_and_as_the_job_set_it(self):
        plan = CI["userns_plan"]
        self.assertEqual(plan("1", "restricted")["changed_by_job"], False)
        self.assertTrue(plan("1", "restricted")["r1_exercised"])
        self.assertEqual(plan("0", "restricted")["changed_by_job"], True)
        self.assertTrue(plan("0", "restricted")["r1_exercised"])
        lifted = plan("1", "lifted")
        self.assertEqual((lifted["wanted"], lifted["changed_by_job"], lifted["r1_exercised"]), ("0", True, False))
        self.assertIn("NOT exercise R1", lifted["note"])
        # A kernel without the knob cannot exercise R1 at all: refused, never reported as exercised.
        for missing in (None, "", "2"):
            with self.assertRaises(Refused):
                plan(missing, "restricted")


class Identities(unittest.TestCase):
    def test_ids_and_the_range_avoid_everything_in_use(self):
        users, groups = {0, 1001, 61000, 61002}, {0, 1001, 61001}
        ranges = [(100000, 165536), (2_000_000_000, 2_000_065_536)]
        chosen = CI["choose_ids"](users, groups, ranges, known=lambda kind, n: n == 61003)
        # 61000 and 61002 are users, 61001 a group, 61003 known to the name service.
        self.assertEqual((chosen["uid"], chosen["gid"], chosen["operator"]), (61004, 61004, 61005))
        self.assertEqual(chosen["subid"], 2_000_065_536)
        clear = CI["choose_ids"](set(), set(), [])
        self.assertEqual(clear, {"uid": 61000, "gid": 61000, "operator": 61001, "subid": 2_000_000_000})

    def test_an_account_inside_the_range_moves_it(self):
        chosen = CI["choose_ids"]({2_000_000_005}, set(), [])
        self.assertEqual(chosen["subid"], 2_000_065_536)


class Build(unittest.TestCase):
    def test_the_drivers_are_found_in_cargos_messages(self):
        messages = "\n".join([
            "Compiling kronik",
            json.dumps({"reason": "compiler-artifact", "target": {"name": "kronik", "kind": ["bin"]},
                        "executable": "/t/release/kronik"}),
            json.dumps({"reason": "compiler-artifact", "target": {"name": "isolation_fixture"},
                        "executable": "/t/release/deps/isolation_fixture-abc"}),
            json.dumps({"reason": "compiler-artifact", "target": {"name": "rootless_boundary"},
                        "executable": "/t/release/deps/rootless_boundary-def"}),
            json.dumps({"reason": "build-finished", "success": True}),
        ])
        found = CI["executables_from"](messages, ["isolation_fixture", "rootless_boundary"])
        self.assertEqual(found, {"isolation_fixture": "/t/release/deps/isolation_fixture-abc",
                                 "rootless_boundary": "/t/release/deps/rootless_boundary-def"})
        with self.assertRaises(Refused):
            CI["executables_from"](messages, ["isolation_fixture", "absent"])


class ExplicitFixture(unittest.TestCase):
    """ADR 0064's commands for the run with the restriction lifted, without running them."""

    def sequence(self, isolation, init_status=0):
        calls = []
        def fake_run(args, log=None, env=None, timeout=None, check=True):
            calls.append([str(a) for a in args])
            status = init_status if "init" in args else 0
            return CI["subprocess"].CompletedProcess(args, status, "")
        created = CI["subprocess"].CompletedProcess([], 0, "retained\n/parent/kronik-proof-x\n")
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(CI["explicit_fixture"].__globals__, {"run": fake_run}), \
                mock.patch.object(CI["subprocess"], "run", return_value=created) as create:
            positional = ["/h", "/p", "/probe", "/pg", "/pay", "/parent", 61000, 61000, 2000000000, 61001]
            CI["explicit_fixture"](positional, isolation, "/tools", "3600", Path(directory) / "log")
            return [str(a) for a in create.call_args.args[0]], calls

    def test_create_takes_the_parent_first_and_cleanup_always_runs(self):
        create, calls = self.sequence("gvisor")
        self.assertEqual(create, ["/h", "create", "/parent", "/p", "/probe", "/pg", "/pay", "61000", "61000",
                                  "2000000000", "61001", "--max-runtime", "3600"])
        self.assertEqual(calls[0], ["/h", "init", "/parent/kronik-proof-x", "rootless"])
        self.assertEqual(calls[1][:2], ["bash", "scripts/conformance-rootless.sh"])
        self.assertIn("--program-proof", calls[1])
        self.assertEqual(calls[-1], ["/h", "cleanup", "/parent/kronik-proof-x"])
        create, calls = self.sequence("microvm")
        self.assertEqual(create[-3:], ["/tools", "--max-runtime", "3600"])
        self.assertIn("--microvm-proof", calls[1])
        # A failed init skips the harness, never the cleanup.
        _, calls = self.sequence("gvisor", init_status=1)
        self.assertEqual([call[1] for call in calls], ["init", "cleanup"])


class Evidence(unittest.TestCase):
    def test_a_path_an_artifact_refuses_is_renamed_and_others_kept(self):
        self.assertEqual(CI["artifact_path"](Path("logs/library-package-libblkid1:amd64.log")),
                         Path("logs/library-package-libblkid1_amd64.log"))
        self.assertEqual(CI["artifact_path"](Path('a"b/c<d>e|f*g?h')), Path("a_b/c_d_e_f_g_h"))
        self.assertEqual(CI["artifact_path"](Path("run/build.log")), Path("run/build.log"))
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "tree", Path(directory) / "evidence"
            (source / "logs").mkdir(parents=True)
            (source / "logs" / "package-libelf1:amd64.log").write_text("built\n")
            copied, _, _ = CI["copy_evidence"](source, destination, CI["MAX_TOTAL"])
            self.assertEqual(copied, 1)
            self.assertEqual((destination / "logs" / "package-libelf1_amd64.log").read_text(), "built\n")

    def test_only_text_leaves_and_no_key_image_disk_or_database(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "proof", Path(directory) / "evidence"
            files = {
                "serve.log": b"INFO started\n",
                "conformance-gvisor.json": b"[]\n",
                "data/foreign/actors/pg-1/output.log": b"[ 0.1] Linux version\n",
                "etc/kronik/kronik.toml": b"[server]\n",
                "etc/kronik/master.key": b"0" * 64,
                "data/keys/secrets.db": b"SQLite format 3\0",
                "data/layouts/probe.oci/index.json": b"{}",
                "data/foreign/actors/pg-1/data.ext4": b"\0" * 64,
                "data/foreign/actors/pg-1/bundle/rootfs/etc/passwd": b"root:x:0:0\n",
                "microvm/manifest.json": b"{}",
                "binary.out": b"\x7fELF\0\0\0",
            }
            for name, content in files.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            (source / "link.log").symlink_to(source / "serve.log")
            big = source / "big.log"
            big.write_bytes(b"x" * (CI["MAX_FILE"] + 1))
            copied, skipped, size = CI["copy_evidence"](source, destination, CI["MAX_TOTAL"])
            kept = sorted(str(p.relative_to(destination)) for p in destination.rglob("*") if p.is_file())
            self.assertEqual(kept, ["conformance-gvisor.json", "data/foreign/actors/pg-1/output.log",
                                    "etc/kronik/kronik.toml", "serve.log"])
            self.assertEqual(copied, 4)
            self.assertGreaterEqual(skipped, 4)
            # The budget is a total: what does not fit stays behind.
            copied, _, _ = CI["copy_evidence"](source, Path(directory) / "small", 20)
            self.assertLess(copied, 4)


def evidence_tree(root, job, userns="restricted", **changes):
    """A collected evidence tree in which every proof of `job` passed, with `changes` applied:
    a relative path mapped to None is removed, to bytes is rewritten."""
    files = {"run/host-facts.json": "{}",
             "run/userns.json": json.dumps({"mode": userns, "initial": "1", "r1_exercised": userns == "restricted",
                                            "note": "note"})}
    for _, pattern in CI["REQUIRED"][job]:
        name = pattern.replace("proof-*", "proof-kronik-proof-x").replace("*", "t0k3n")
        files.setdefault(name, "{}")
    for name in list(files):
        if name.endswith("result-conformance-gvisor.json") or name.endswith("result-conformance-microvm.json"):
            files[name] = json.dumps({"status": "PASS"})
        if name.endswith("host-listeners.json"):
            files[name] = "[]"
        if name == "run/boundary.json":
            files[name] = json.dumps({"passed": True})
    files.update(changes)
    for name, content in files.items():
        if content is None:
            continue
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


class Verdict(unittest.TestCase):
    def verdict(self, job, userns="restricted", **changes):
        with tempfile.TemporaryDirectory() as directory:
            evidence_tree(Path(directory), job, userns, **changes)
            return CI["verdict"](job, Path(directory), userns)

    def test_every_proof_present_and_passed_is_a_pass(self):
        for job in ("m21", "m20"):
            result = self.verdict(job)
            self.assertTrue(result["passed"], result)
            self.assertTrue(result["r1_exercised"])
        lifted = self.verdict("m21", "lifted")
        self.assertTrue(lifted["passed"])
        self.assertFalse(lifted["r1_exercised"])

    def test_a_missing_proof_is_a_failure_and_says_which(self):
        result = self.verdict("m20", **{"proof-kronik-proof-x/vm-stop-pg-t0k3n.json": None})
        self.assertFalse(result["passed"])
        failed = [row for row in result["proofs"] if not row["passed"]]
        self.assertEqual([row["proof"] for row in failed], ["graceful STOP, Postgres"])
        self.assertEqual(failed[0]["evidence"], "missing")

    def test_a_failed_result_receipts_or_a_failed_boundary_are_failures(self):
        for changes in ({"proof-kronik-proof-x/result-conformance-gvisor.json": json.dumps({"status": "FAIL"})},
                        {"proof-kronik-proof-x/host-listeners.json": json.dumps([[0, "accept"]])},
                        {"run/boundary.json": json.dumps({"passed": False})},
                        {"run/userns.json": None}):
            self.assertFalse(self.verdict("m21", **changes)["passed"], changes)

    def test_the_recorded_user_namespace_mode_must_be_the_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence_tree(Path(directory), "m21", "lifted")
            self.assertFalse(CI["verdict"]("m21", Path(directory), "restricted")["passed"])


if __name__ == "__main__":
    unittest.main()
