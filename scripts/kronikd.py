"""A real `kronik serve` for the scripts that drive one: scripts/chaos.py and
scripts/identity-examples.py. Not a test framework: the daemon process, its
API over the Unix socket, and the CLI with --json."""

import http.client
import json
import os
import signal
import socket
import subprocess
import time


class Violation(Exception):
    """Something a script checks does not hold; the message says what."""


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("kronik", timeout=timeout)
        self.unix_path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.unix_path)
        self.sock = s


class Daemon:
    """`kronik serve` on a data directory, its output appended to `log`."""

    def __init__(self, bin, data, sock, port, log, healthy_timeout=60.0):
        self.bin, self.data, self.sock, self.port = bin, data, sock, port
        self.healthy_timeout = healthy_timeout
        self.log = open(log, "ab")
        self.proc = None

    def start(self, env=None):
        """Starts the daemon, with `env` added to its environment if given;
        returns (seconds until healthy, applied LSN then)."""
        started = time.time()
        self.proc = subprocess.Popen(
            [self.bin, "serve", "--data-dir", self.data, "--http-listen", f"127.0.0.1:{self.port}",
             "--api-socket", self.sock],
            stdout=self.log, stderr=self.log, start_new_session=True, env={**os.environ, **(env or {})})
        while time.time() - started < self.healthy_timeout:
            if self.proc.poll() is not None:
                raise Violation(f"the daemon exited with {self.proc.returncode} while starting")
            try:
                status, body = self.api("GET", "/v1/health", timeout=2)
                if status == 200 and body.get("status") == "ok":
                    return time.time() - started, body["applied_lsn"]
            except OSError:
                pass
            time.sleep(0.02)
        raise Violation(f"the daemon was not healthy within {self.healthy_timeout} s")

    def kill9(self):
        self.proc.send_signal(signal.SIGKILL)
        self.proc.wait()

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            raise Violation("the daemon did not stop within 60 s of SIGTERM") from None

    def api(self, method, path, body=None, timeout=60):
        conn = UnixConnection(self.sock, timeout)
        try:
            data = json.dumps(body).encode() if body is not None else None
            conn.request(method, path, body=data, headers={"content-type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
        finally:
            conn.close()

    def cli(self, *args):
        out = subprocess.run([self.bin, "--socket", self.sock, "--json", *args],
                             capture_output=True, text=True, timeout=7200)
        if out.returncode != 0:
            raise Violation(f"kronik {' '.join(args)} failed: {out.stderr.strip() or out.stdout.strip()}")
        return json.loads(out.stdout)
