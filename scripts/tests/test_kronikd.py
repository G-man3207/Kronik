"""kronikd: where a script finds the binary it runs by default."""
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1]
artifact = runpy.run_path(str(SCRIPTS / "kronikd.py"))["artifact"]


class Artifact(unittest.TestCase):
    def elsewhere(self):
        """Runs from a directory that is not the repository; restored afterwards."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(directory.name)

    def test_it_is_the_repositorys_build_wherever_the_script_runs(self):
        self.elsewhere()
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(artifact("KRONIK_BIN", "debug", "kronik"), SCRIPTS.parent / "target/debug/kronik")
            self.assertEqual(artifact("KRONIK_KEYHELPER", "debug", "kronik-keyhelper"),
                             SCRIPTS.parent / "target/debug/kronik-keyhelper")
            self.assertEqual(artifact("KRONIK_BIN", "x86_64-unknown-linux-musl", "release", "kronik"),
                             SCRIPTS.parent / "target/x86_64-unknown-linux-musl/release/kronik")

    def test_cargos_own_target_directory_replaces_target(self):
        with mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": "/elsewhere/target"}, clear=True):
            self.assertEqual(artifact("KRONIK_BIN", "release", "kronik"), Path("/elsewhere/target/release/kronik"))

    def test_the_named_variable_wins_and_stays_relative_to_the_caller(self):
        environment = {"KRONIK_BIN": "/opt/kronik/bin/kronik", "KRONIK_KEYHELPER": "build/kronik-keyhelper",
                       "CARGO_TARGET_DIR": "/elsewhere/target"}
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertEqual(artifact("KRONIK_BIN", "debug", "kronik"), Path("/opt/kronik/bin/kronik"))
            self.assertEqual(artifact("KRONIK_KEYHELPER", "debug", "kronik-keyhelper"),
                             Path("build/kronik-keyhelper"))


if __name__ == "__main__":
    unittest.main()
