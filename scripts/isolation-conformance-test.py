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


class VmProcesses(unittest.TestCase):
    """The two processes of a VM's cgroup, from a fake /proc with the lines the kernel prints.

    NSpid is read by a process in the initial namespace: the id in each PID namespace down to the
    process's own. The private manager is a PID namespace, and the VMM is init of one below it.
    """

    LAUNCHER, VMM = 4301, 4312

    def tree(self):
        status = {self.LAUNCHER: {"NSpid": "\t4301\t77", "PPid": "\t4290"},
                  self.VMM: {"NSpid": "\t4312\t88\t1", "PPid": "\t4301"}}
        args = {self.LAUNCHER: [b"/proc/self/exe", b"foreign", b"launch-microvm", b"/run/x/launch.json"],
                self.VMM: [b"/firecracker", b"--api-sock", b"/api.sock"]}
        return status, args

    def processes(self, members, status, args):
        return proof.vm_processes(members, status.__getitem__, args.__getitem__)

    def test_the_launcher_is_what_the_manager_translates_and_the_vmm_is_found_through_it(self):
        status, args = self.tree()
        for members in ([self.LAUNCHER, self.VMM], [self.VMM, self.LAUNCHER]):
            launcher, vmm, inside = self.processes(members, status, args)
            self.assertEqual((launcher, vmm), (self.LAUNCHER, self.VMM))
            # The id the helper must translate is the launcher's in the manager's namespace (77),
            # not the last NSpid entry of the VMM, which is 1: init of its own namespace.
            self.assertEqual(inside, 77)
            self.assertEqual(proof.nspid(status[self.VMM])[-1], 1)

    def test_one_process_or_three_is_not_a_vm_cgroup_any_more(self):
        status, args = self.tree()
        status[4400] = {"NSpid": "\t4400\t99", "PPid": "\t4301"}
        args[4400] = [b"/bin/sh"]
        for members in ([self.VMM], [self.LAUNCHER], [self.LAUNCHER, self.VMM, 4400], [], [self.VMM, self.VMM]):
            with self.assertRaises(proof.Violation, msg=str(members)):
                self.processes(members, status, args)

    def test_the_vmm_must_be_init_of_a_pid_namespace_of_its_own(self):
        status, args = self.tree()
        # No PID namespace of its own (both in the manager's): the same depth, not a VMM below a launcher.
        plain = {self.LAUNCHER: status[self.LAUNCHER], self.VMM: {"NSpid": "\t4312\t88", "PPid": "\t4301"}}
        with self.assertRaises(proof.Violation):
            self.processes([self.LAUNCHER, self.VMM], plain, args)
        # One level below but not init of it.
        not_init = {self.LAUNCHER: status[self.LAUNCHER], self.VMM: {"NSpid": "\t4312\t88\t5", "PPid": "\t4301"}}
        with self.assertRaises(proof.Violation):
            self.processes([self.LAUNCHER, self.VMM], not_init, args)

    def test_the_vmm_is_a_child_of_the_launcher_one_namespace_below_it(self):
        status, args = self.tree()
        orphan = {self.LAUNCHER: status[self.LAUNCHER], self.VMM: {"NSpid": "\t4312\t88\t1", "PPid": "\t1"}}
        with self.assertRaises(proof.Violation):
            self.processes([self.LAUNCHER, self.VMM], orphan, args)
        deeper = {self.LAUNCHER: status[self.LAUNCHER], self.VMM: {"NSpid": "\t4312\t88\t5\t1", "PPid": "\t4301"}}
        with self.assertRaises(proof.Violation):
            self.processes([self.LAUNCHER, self.VMM], deeper, args)

    def test_a_status_that_does_not_start_with_its_own_id_is_refused(self):
        status, args = self.tree()
        status[self.VMM] = {"NSpid": "\t9999\t88\t1", "PPid": "\t4301"}
        with self.assertRaises(proof.Violation):
            self.processes([self.LAUNCHER, self.VMM], status, args)

    def test_the_vmm_must_be_firecracker_and_the_launcher_the_launcher(self):
        status, args = self.tree()
        wrong_vmm = {**args, self.VMM: [b"/bin/sh", b"-c", b"/firecracker"]}
        with self.assertRaises(proof.Violation):
            self.processes([self.LAUNCHER, self.VMM], status, wrong_vmm)
        wrong_launcher = {**args, self.LAUNCHER: [b"/usr/bin/python3"]}
        with self.assertRaises(proof.Violation):
            self.processes([self.LAUNCHER, self.VMM], status, wrong_launcher)

    def test_the_readers_the_harness_hands_over_work_on_the_real_proc(self):
        # NSpid of a process in this namespace starts with its own id; its arguments are bytes.
        ids = proof.nspid(proof.status(os.getpid()))
        self.assertEqual(ids[0], os.getpid())
        args = proof.process_args(os.getpid())
        self.assertTrue(args and all(isinstance(a, bytes) for a in args) and args[0])


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


class CallerLimits(unittest.TestCase):
    """The caller's effect timeout: the guest's fill of its drive is one call."""

    class Daemon:
        def __init__(self, answer=None):
            self.calls = []
            self.answer = answer

        def api(self, method, path, body=None, timeout=0):
            self.calls.append((method, path, body))
            if self.answer is not None:
                return self.answer
            return 200, {"dry_run": False, "limits": {"kind": body["kind"],
                         "effect_timeout_ms": body["effect_timeout_ms"]}}

    def test_the_effect_timeout_is_raised_for_the_caller_kind_with_a_reason(self):
        daemon = self.Daemon()
        proof.raise_effect_timeout(daemon, "caller-kind")
        (method, path, body), = daemon.calls
        self.assertEqual((method, path), ("POST", "/v1/limits"))
        self.assertEqual(body["kind"], "caller-kind")
        self.assertEqual(body["effect_timeout_ms"], 300_000)
        self.assertGreater(proof.EFFECT_TIMEOUT_MS, 120_000, "more than the gateway's own timeout")
        self.assertTrue(body["reason"].strip())

    def test_an_answer_that_does_not_carry_the_new_limit_is_a_violation(self):
        for answer in [(200, {"limits": {"effect_timeout_ms": 10_000}}),
                       (409, {"error": {"code": "CONFLICT"}})]:
            with self.assertRaises(proof.Violation):
                proof.raise_effect_timeout(self.Daemon(answer), "caller-kind")


if __name__ == "__main__":
    unittest.main()
