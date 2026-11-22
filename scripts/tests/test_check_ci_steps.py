"""The check that ci.yml runs every default step of scripts/ci.sh once, in order per job."""
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECK = runpy.run_path(str(ROOT / "scripts/check-ci-steps.py"))
SCRIPT = 'if [ "$#" -eq 0 ]; then\n    set -- fmt clippy test musl action\nfi\n'


def workflow(**jobs):
    """A workflow whose jobs run `scripts/ci.sh` with the given steps, one line each."""
    text = "name: CI\non:\n  workflow_dispatch:\njobs:\n"
    for name, runs in jobs.items():
        text += f"  {name}:\n    steps:\n"
        for steps in runs:
            text += f"      - run: scripts/ci.sh {steps}\n"
    return text


class CheckCiSteps(unittest.TestCase):
    def test_every_step_once_over_parallel_jobs_passes(self):
        CHECK["check"](SCRIPT, workflow(lint=["fmt", "clippy"], test=["test"], musl=["musl"],
                                        action=["action"]))

    def test_a_missing_step_a_repeated_one_and_an_unknown_one_fail(self):
        cases = {
            "missing": workflow(lint=["fmt clippy"], test=["test"], action=["action"]),
            "repeated": workflow(lint=["fmt clippy"], test=["test musl"], musl=["musl"], action=["action"]),
            "unknown": workflow(lint=["fmt clippy"], test=["test"], musl=["musl"], action=["action lint"]),
        }
        for case, text in cases.items():
            with self.assertRaises(ValueError, msg=case):
                CHECK["check"](SCRIPT, text)

    def test_a_job_runs_its_steps_in_the_scripts_order(self):
        with self.assertRaises(ValueError):
            CHECK["check"](SCRIPT, workflow(lint=["clippy fmt"], test=["test"], musl=["musl"],
                                            action=["action"]))

    def test_a_step_that_skips_needs_its_require_variable(self):
        script = 'if [ "$#" -eq 0 ]; then\n    set -- test s3 foreign\nfi\n'
        def text(s3_env, foreign_cmd):
            return ("name: CI\njobs:\n"
                    "  test:\n    steps:\n      - run: scripts/ci.sh test\n"
                    f"  s3:\n    steps:\n      - env:\n{s3_env}        run: scripts/ci.sh s3\n"
                    f"  foreign:\n    steps:\n      - run: {foreign_cmd}\n")
        CHECK["check"](script, text("          KRONIK_TEST_S3: require\n",
                                    "sudo -E env KRONIK_FOREIGN_TESTS=require scripts/ci.sh foreign"))
        for case, (s3_env, foreign_cmd) in {
            "s3 without require": ("          OTHER: 1\n",
                                   "KRONIK_FOREIGN_TESTS=require scripts/ci.sh foreign"),
            "s3 with another value": ("          KRONIK_TEST_S3: skip\n",
                                      "KRONIK_FOREIGN_TESTS=require scripts/ci.sh foreign"),
            "foreign without require": ("          KRONIK_TEST_S3: require\n",
                                        "scripts/ci.sh foreign"),
            "foreign's require only in a comment": (
                "          KRONIK_TEST_S3: require\n",
                "scripts/ci.sh foreign\n      # KRONIK_FOREIGN_TESTS=require fails a skip."),
        }.items():
            with self.assertRaises(ValueError, msg=case):
                CHECK["check"](script, text(s3_env, foreign_cmd))

    def test_identity_needs_libfaketime_required(self):
        # Without libfaketime the identity step skips todo-ts's replay.
        script = 'if [ "$#" -eq 0 ]; then\n    set -- test identity\nfi\n'
        def text(identity):
            return ("name: CI\njobs:\n"
                    "  test:\n    steps:\n      - run: scripts/ci.sh test\n"
                    f"  identity:\n    steps:\n{identity}")
        CHECK["check"](script, text("      - env:\n          KRONIK_TEST_FAKETIME: require\n"
                                    "        run: scripts/ci.sh identity\n"))
        with self.assertRaisesRegex(ValueError, "identity without KRONIK_TEST_FAKETIME=require"):
            CHECK["check"](script, text("      - run: scripts/ci.sh identity\n"))

    def test_the_repository_runs_every_step_and_musl_in_a_job_of_its_own(self):
        script = (ROOT / "scripts/ci.sh").read_text()
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        CHECK["check"](script, text)
        jobs = CHECK["jobs"](text)
        self.assertEqual(CHECK["calls"](jobs["musl"], []), ["musl"])
        self.assertEqual(CHECK["calls"](jobs["s3"], []), ["s3"])


if __name__ == "__main__":
    unittest.main()
