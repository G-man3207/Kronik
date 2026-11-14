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

    def test_the_repository_runs_every_step_and_musl_in_a_job_of_its_own(self):
        script = (ROOT / "scripts/ci.sh").read_text()
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        CHECK["check"](script, text)
        jobs = CHECK["jobs"](text)
        self.assertEqual(CHECK["calls"](jobs["musl"], []), ["musl"])


if __name__ == "__main__":
    unittest.main()
