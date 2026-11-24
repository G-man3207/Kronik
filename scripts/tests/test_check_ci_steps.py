"""The check that ci.yml runs every default step of scripts/ci.sh once, in order per job."""
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECK = runpy.run_path(str(ROOT / "scripts/check-ci-steps.py"))
SCRIPT = 'if [ "$#" -eq 0 ]; then\n    set -- fmt clippy test musl action\nfi\n'
SMALL = 'if [ "$#" -eq 0 ]; then\n    set -- fmt test action\nfi\n'


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

    def test_a_call_may_span_continued_lines_and_end_in_a_comment(self):
        CHECK["check"](SMALL, "run: scripts/ci.sh fmt test\\\n    action # selected checks\n")

    def test_a_sudo_call_and_a_shell_failure_handler_are_calls(self):
        CHECK["check"](SMALL, "run: scripts/ci.sh fmt test\n"
                              "  sudo -E env PATH=x scripts/ci.sh action || status=$?\n")

    def test_a_bare_call_runs_the_defaults_and_comment_lines_are_not_calls(self):
        CHECK["check"](SMALL, "# scripts/ci.sh unknown\nrun: scripts/ci.sh # all defaults\n")

    def test_hyphenated_step_names_are_whole_steps(self):
        script = "set -- foreign foreign-extra other-job\n"
        run = "run: KRONIK_FOREIGN_TESTS=require scripts/ci.sh "
        CHECK["check"](script, run + "foreign foreign-extra other-job\n")
        with self.assertRaisesRegex(ValueError, "missing"):
            CHECK["check"](script, run + "foreign other-job\n")
        with self.assertRaisesRegex(ValueError, "unknown"):
            CHECK["check"](script, run + "foreign foreign-extr other-job\n")

    def test_a_workflow_without_calls_misses_every_step(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            CHECK["check"](SMALL, "# no CI calls")

    def test_a_script_without_a_default_list_fails(self):
        with self.assertRaisesRegex(ValueError, "no default"):
            CHECK["check"]("# no defaults", "run: scripts/ci.sh fmt")

    def test_jobs_may_run_their_steps_in_any_job_order(self):
        CHECK["check"](SMALL, "on:\n  workflow_dispatch:\njobs:\n"
                              "  first:\n    steps:\n      - run: scripts/ci.sh action\n\n"
                              "  second:  # the other job\n    steps:\n"
                              "      - run: scripts/ci.sh fmt\n      - run: scripts/ci.sh test\n")

    def test_the_repository_runs_every_step_and_musl_in_a_job_of_its_own(self):
        script = (ROOT / "scripts/ci.sh").read_text()
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        CHECK["check"](script, text)
        jobs = CHECK["jobs"](text)
        self.assertEqual(CHECK["calls"](jobs["musl"], []), ["musl"])
        self.assertEqual(CHECK["calls"](jobs["s3"], []), ["s3"])


if __name__ == "__main__":
    unittest.main()
