"""benchmark-single-node.digest is SHA-256 of the file, and the UI fixture's
sleep is Node's timer promise."""
import hashlib
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))  # benchmark-single-node.py imports kronikd
BENCHMARK = runpy.run_path(str(SCRIPTS / "benchmark-single-node.py"))
UI_COMMON = ROOT / "scripts/test-ui-common.cjs"


class BenchmarkDigestTest(unittest.TestCase):
    def test_digest_matches_sha256_of_the_file(self):
        digest = BENCHMARK["digest"]
        sample = ROOT / "scripts/ci.sh"
        self.assertEqual(digest(sample), hashlib.sha256(sample.read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload"
            path.write_bytes(b"")
            self.assertEqual(digest(path), hashlib.sha256(b"").hexdigest())
            # Larger than the old 64 KiB read, so a short read cannot pass.
            path.write_bytes(b"kronik" * 20000)
            self.assertEqual(digest(path), hashlib.sha256(path.read_bytes()).hexdigest())

    def test_digest_uses_file_digest(self):
        source = (ROOT / "scripts/benchmark-single-node.py").read_text()
        self.assertIn('return hashlib.file_digest(source, "sha256").hexdigest()', source)
        self.assertNotIn("source.read(65536)", source)


class UiSleepTest(unittest.TestCase):
    def test_sleep_is_the_node_timer_and_stays_exported(self):
        source = UI_COMMON.read_text()
        self.assertIn("const { setTimeout: sleep } = require('node:timers/promises');", source)
        self.assertIn("module.exports = { chromeBin, sleep, connect, chromeArgs, serveUi };", source)
        self.assertNotIn("new Promise((resolve) => setTimeout(resolve, ms))", source)
        subprocess.run(["node", "--check", str(UI_COMMON)], check=True)
        result = subprocess.run(
            ["node", "-e", "require('./scripts/test-ui-common.cjs').sleep(10).then(() => console.log('ok'))"],
            cwd=ROOT, check=True, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stdout, "ok\n")
