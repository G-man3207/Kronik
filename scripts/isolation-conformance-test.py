#!/usr/bin/env python3
"""Small runtime regressions for the proof's oracles; no mocked syscalls/reports.
Run explicitly: python3 scripts/isolation-conformance-test.py
"""
import errno
import importlib.util
import os
from pathlib import Path
import resource
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).with_name("isolation-conformance.py")
spec = importlib.util.spec_from_file_location("isolation_conformance", SOURCE)
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class RuntimeOracles(unittest.TestCase):
    def test_wrong_actual_pid_and_root_expectation_are_refused(self):
        with self.assertRaises(proof.Violation):
            proof.validate_target_pid(os.getpid(), 0)
        with self.assertRaises(proof.Violation):
            proof.validate_target_pid(os.getpid(), os.getuid() + 1)

    def test_replaced_file_is_never_cleaned(self):
        with tempfile.TemporaryDirectory(prefix="kronik-cleanup-") as tmp:
            path = Path(tmp) / secrets.token_hex(16)
            path.write_text("created by this test")
            identity = path.lstat()
            retained = path.with_suffix(".retained")
            path.rename(retained)
            path.write_text("replacement must survive")
            with self.assertRaises(proof.Violation):
                proof.remove_owned(path, identity)
            self.assertEqual(path.read_text(), "replacement must survive")
            proof.remove_owned(retained, identity)
            self.assertFalse(retained.exists())

    def test_real_outside_write_is_observed_in_owned_tmp_fixture(self):
        with tempfile.TemporaryDirectory(prefix="kronik-outside-", dir="/tmp") as tmp:
            path = Path(tmp) / (".kronik-probe-" + secrets.token_hex(16))
            proof.assert_absent(path)
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, b"actual outside write")
            identity = os.fstat(fd)
            os.close(fd)
            with self.assertRaises(proof.Violation):
                proof.assert_absent(path)
            proof.remove_owned(path, identity)
            proof.assert_absent(path)

    def test_outside_write_oracle_retains_evidence_and_cleans_only_its_canary(self):
        with tempfile.TemporaryDirectory(prefix="kronik-write-oracle-",dir="/tmp") as tmp:
            root = Path(tmp)
            token = secrets.token_hex(16)
            path = root/f".kronik-probe-{token}"
            with path.open("xb") as stream:
                stream.write(token.encode())
            identity = path.lstat()
            with self.assertRaises(proof.Violation):
                proof.observe_outside_writes(root,[path],[root],token)
            proof.assert_absent(path)
            import json
            rows = json.loads((root/"outside-writes.json").read_text())
            self.assertEqual(rows[0]["identity"],[identity.st_dev,identity.st_ino])

    def test_actual_emfile_is_not_accepted_as_boundary_absence(self):
        # Exhaust only a bounded child, never the parent test runner's FD table.
        child = r'''
import errno, importlib.util, os, resource, sys
spec=importlib.util.spec_from_file_location("proof",sys.argv[1])
proof=importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)
resource.setrlimit(resource.RLIMIT_NOFILE,(32,32))
fds=[]
try:
    while True: fds.append(os.open("/dev/null",os.O_RDONLY))
except OSError as error:
    assert error.errno == errno.EMFILE
    try: proof.check_errno(error.errno,[errno.ENOENT,errno.EPERM,errno.EACCES])
    except proof.Violation: pass
    else: raise AssertionError("actual EMFILE was accepted")
finally:
    for fd in fds: os.close(fd)
'''
        result = subprocess.run([sys.executable, "-c", child, str(SOURCE)], timeout=10,
                                cwd=SOURCE.parent, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_plaintext_key_reopen_is_observed(self):
        with tempfile.TemporaryDirectory(prefix="kronik-key-reads-") as tmp:
            paths = [Path(tmp)/name for name in ["source", "credential"]]
            for path in paths:
                path.write_bytes(b"exclusive test key")
            fd = proof.watch_key_reads(paths)
            try:
                self.assertEqual(proof.key_accesses(fd), [])
                paths[0].rename(Path(tmp)/"retained")
                self.assertEqual(proof.key_accesses(fd), [])
                with paths[1].open("rb") as stream:
                    self.assertEqual(stream.read(), b"exclusive test key")
                self.assertTrue(proof.key_accesses(fd))
                self.assertEqual(proof.key_accesses(fd), [])
            finally:
                os.close(fd)

    def test_actual_listener_receipt_control_detects_weak_network(self):
        with tempfile.TemporaryDirectory(prefix="kronik-listener-") as tmp:
            observed = False
            with self.assertRaises(proof.Violation):
                with proof.HostControls(Path(tmp), secrets.token_hex(16)) as host:
                    self.assertEqual(host.receipts, [])
                    # Deliberately weakened fixture: a real client shares the host network.
                    with socket.create_connection(host.v4.getsockname(), timeout=1):
                        pass
                    deadline = time.monotonic() + 2
                    while not host.receipts and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(host.receipts, "listener oracle did not observe actual accepts")
                    observed = True
            self.assertTrue(observed,"required real listener control did not execute")

    def test_supported_separate_actor_root_is_not_skipped(self):
        if os.geteuid() != 0:
            self.fail("required ownership regression needs allocated root setup authority")
        with tempfile.TemporaryDirectory(prefix="kronik-owner-") as tmp:
            primary = Path(tmp) / "data"
            separate = Path(tmp) / "actor-data"
            actors = primary / "foreign" / "actors"
            actors.mkdir(parents=True)
            separate.mkdir()
            for directory in (primary, primary / "foreign", actors, separate):
                os.chown(directory, 62001, 62001)
            link = actors / "actor"
            link.symlink_to(separate, target_is_directory=True)
            os.lchown(link, 62001, 62001)
            canary = separate / "root-owned-exclusive-canary"
            canary.write_text("root-owned corruption must be detected")
            cfg = {"uid":62001,"gid":62001,"subid":1000000000,"data":str(primary)}
            with self.assertRaises(proof.Violation):
                proof.owner_tree([str(primary), str(separate)], cfg)
            os.chown(canary, 62001, 62001)
            proof.owner_tree([str(primary), str(separate)], cfg)


if __name__ == "__main__":
    unittest.main()
