#!/usr/bin/env python3
"""Exercise the actual builder's process ownership without fetching/building inputs."""
import ctypes
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("build-microvm-tools.sh").resolve()
REPO = SCRIPT.parent.parent

# Debugger instrumentation enters the real CLI's original run(), before its
# first fetch/compiler command. It does not replace that function or its signal setup.
SITE = '''import os, sys

def audit(event, args):
    if event in ("socket.connect", "urllib.Request"):
        raise RuntimeError("process-ownership regression must not fetch inputs")
sys.addaudithook(audit)

def trace(frame, event, arg):
    scope = frame.f_globals
    if frame.f_code.co_name == "which" and frame.f_back is not None:
        scope = frame.f_back.f_globals
    if (event == "call" and frame.f_code.co_name in ("run", "fetch", "which")
            and "commands" in scope and "run" in scope):
        sys.settrace(None)
        scope["run"]("owned-cancellation", [sys.executable,
            os.environ["KRONIK_CANCEL_WORKER"], os.environ["KRONIK_CANCEL_READY"]], timeout=15)
        raise RuntimeError("long worker unexpectedly completed without interruption")
    return trace
sys.settrace(trace)
'''
WORKER = '''import json, os, pathlib, signal, subprocess, sys, time
signal.alarm(10)
child = subprocess.Popen([sys.executable, "-c", "import signal,time; signal.alarm(10); time.sleep(30)"])
pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(), child.pid]))
time.sleep(30)
'''


class BuilderOwnership(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.libc = ctypes.CDLL(None, use_errno=True)
        cls.previous_subreaper = ctypes.c_int()
        if cls.libc.prctl(37, ctypes.byref(cls.previous_subreaper), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "reading own subreaper state")
        if cls.libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "setting own test subreaper")

    @classmethod
    def tearDownClass(cls):
        if cls.libc.prctl(36, cls.previous_subreaper.value, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "restoring own subreaper state")

    def cancellation(self, signum, outer_timeout=False):
        root = Path(tempfile.mkdtemp(prefix="kronik-builder-cancel-", dir="/var/tmp"))
        os.chmod(root, 0o700)
        (root / "sitecustomize.py").write_text(SITE)
        (root / "worker.py").write_text(WORKER)
        ready = root / "ready.json"
        env = dict(os.environ, PYTHONPATH=str(root), PYTHONDONTWRITEBYTECODE="1",
                   KRONIK_CANCEL_WORKER=str(root / "worker.py"), KRONIK_CANCEL_READY=str(ready))
        pids = []
        pidfds = []
        success = False
        with (root / "driver.log").open("xb") as log:
            command = ["bash", str(SCRIPT), "--execute", "--output", str(root / "tools")]
            if outer_timeout:
                command = ["timeout", "--signal=TERM", "--kill-after=3s", "3s"] + command
            driver = subprocess.Popen(command, cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline and driver.poll() is None:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), (root / "driver.log").read_text())
                pids = json.loads(ready.read_text())
                self.assertEqual(len(pids), 2)
                self.assertEqual(os.getpgid(pids[0]), pids[0])
                self.assertEqual(os.getpgid(pids[1]), pids[0])
                pidfds = [os.pidfd_open(pid) for pid in pids]
                self.assertTrue(all(not select.select([fd], [], [], 0)[0] for fd in pidfds))
                if not outer_timeout:
                    driver.send_signal(signum)
                code = driver.wait(timeout=6)
                for pid, fd in zip(pids, pidfds):
                    self.assertTrue(select.select([fd], [], [], 2)[0],
                                    f"owned descendant {pid} survived builder cancellation; evidence {root}")
                self.assertEqual(code, 124 if outer_timeout else 128 + signum, (root / "driver.log").read_text())
                success = True
            finally:
                if driver.poll() is None:
                    if outer_timeout and os.getpgid(driver.pid) == driver.pid:
                        os.killpg(driver.pid, signal.SIGKILL)
                    driver.kill()
                driver.wait(timeout=5)
                if pids:
                    for pid in pids:
                        try:
                            if os.getpgid(pid) == pids[0]:
                                os.killpg(pids[0], signal.SIGKILL)
                                break
                        except ProcessLookupError:
                            pass
                for fd in pidfds:
                    os.close(fd)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        pid, _ = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if pid == 0:
                        time.sleep(0.01)
                else:
                    raise AssertionError(f"owned descendants could not be reaped; evidence {root}")
                if success:
                    shutil.rmtree(root)
                else:
                    print(f"builder cancellation evidence retained: {root}", file=sys.stderr)

    def test_term_reaps_the_actual_worker_and_descendant(self):
        self.cancellation(signal.SIGTERM)

    def test_int_reaps_the_actual_worker_and_descendant(self):
        self.cancellation(signal.SIGINT)

    def test_outer_timeout_reaps_the_actual_worker_and_descendant(self):
        self.cancellation(signal.SIGTERM, outer_timeout=True)


class Arguments(unittest.TestCase):
    """The slow-machine arguments: their defaults are the recorded recipe, bad values stop at once."""

    def test_the_kernel_options_the_guest_needs_are_checked_before_the_long_build(self):
        import re
        source = SCRIPT.read_text()
        listed = re.search(r"^required = \[(.*?)\]\n", source, re.S | re.M)
        self.assertIsNotNone(listed)
        names = set(re.findall(r"'([A-Z0-9_]+)'", listed[1]))
        for needed in ("PROC_FS", "SYSFS", "UNIX98_PTYS", "NET", "INET", "UNIX", "BINFMT_ELF",
                       "CRYPTO_CRC32C", "TMPFS_XATTR", "EXT4_FS_POSIX_ACL", "SERIAL_8250_CONSOLE",
                       "VIRTIO_VSOCKETS", "SECCOMP", "EXT4_FS", "OVERLAY_FS"):
            self.assertIn(needed, names)
        # DEVPTS_FS and LIBCRC32C are not options of 6.18, so requiring them would stop every
        # build. CRC32 is =y but has no prompt: CRYPTO_CRC32C selects it, so it is left out.
        for absent in ("DEVPTS_FS", "LIBCRC32C", "CRC32"):
            self.assertNotIn(absent, names)
        self.assertIn("required.append('ACPI')", source)

    def run_script(self, *args):
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=REPO, capture_output=True, text=True, timeout=60,
        )

    def test_defaults_are_the_recorded_recipe(self):
        help_text = self.run_script("--help").stdout
        self.assertIn("(default 3600)", help_text)
        self.assertIn("(default 1, the", help_text)
        source = SCRIPT.read_text()
        self.assertIn("default=3600", source)
        self.assertIn("'-j' + str(a.kernel_jobs)", source)

    def test_values_outside_the_bounds_stop_before_anything_is_fetched(self):
        for flag, value in (("--command-timeout", "5"), ("--command-timeout", "99999999"),
                            ("--kernel-jobs", "0"), ("--kernel-jobs", "9999")):
            with tempfile.TemporaryDirectory(prefix="kronik-args-") as tmp:
                out = self.run_script("--execute", "--output", str(Path(tmp) / "tools"), flag, value)
                self.assertNotEqual(out.returncode, 0, (flag, value))
                self.assertIn(flag, out.stderr)
                self.assertEqual(list(Path(tmp).iterdir()), [], "nothing was created")


if __name__ == "__main__":
    unittest.main()
