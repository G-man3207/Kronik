"""A real `kronik serve` for the scripts that drive one: scripts/chaos.py,
scripts/identity-examples.py and scripts/acceptance_m24.py, plus the socket,
process and command helpers the e2e scripts share. Not a test framework: the
daemon process, its API over the Unix socket, and the CLI with --json."""

import contextlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent


class Violation(Exception):
    """Something a script checks does not hold; the message says what."""


def command(*args, timeout=120, check=True, data=None, env=None, pass_fds=()):
    """Runs a command with captured output; `check` turns a failure into an
    AssertionError that quotes the end of both streams."""
    r = subprocess.run([str(a) for a in args], input=data, capture_output=True,
                       timeout=timeout, env=env, pass_fds=pass_fds)
    if check and r.returncode:
        raise AssertionError(f"{[str(a) for a in args[:4]]} exited {r.returncode}: "
                             f"{r.stdout[-2000:].decode(errors='replace')}{r.stderr[-2000:].decode(errors='replace')}")
    return r


def write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text if isinstance(text, bytes) else text.encode())
    path.chmod(mode)


def wait_for(description, predicate, seconds=90, step=0.1, retry=()):
    """Waits until `predicate()` returns a truthy value, which it returns.
    Exceptions in `retry` mean not-yet; the last one is reported on timeout."""
    deadline = time.monotonic() + seconds
    failure = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
        except retry as error:
            failure = error
        else:
            failure = None
            if value:
                return value
        time.sleep(step)
    message = f"timed out: {description}"
    raise AssertionError(message + (f" ({failure})" if failure is not None else ""))


def free_port():
    """A loopback port for a fixture listener to bind."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def artifact(variable, *path):
    """The binary a script runs unless the caller names one: the value of the
    environment variable `variable` (KRONIK_BIN, KRONIK_KEYHELPER), else
    `path` under cargo's target directory ($CARGO_TARGET_DIR, or the
    repository's target/). A relative value is relative to the caller's
    current directory."""
    return Path(os.environ.get(variable) or Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target", *path))


def docker_image(ref, pull_timeout=240):
    """The `docker image inspect` info of `ref`, pulling the image if absent."""
    info = command("docker", "image", "inspect", ref, check=False)
    if info.returncode:
        command("docker", "pull", ref, timeout=pull_timeout)
        info = command("docker", "image", "inspect", ref)
    return json.loads(info.stdout)[0]


def stop_process(process, grace=60):
    """SIGTERM, then SIGKILL if the process outlives `grace`; None is gone."""
    if process and process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=60):
        super().__init__("kronik", timeout=timeout)
        self.unix_path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(str(self.unix_path))
        self.sock = s


def unix_api(sock, method, path, data=None, status=200, timeout=60, token=None):
    """One JSON request over the daemon's Unix socket; `status` is the one
    expected answer, or None for the (status, value) pair."""
    with contextlib.closing(UnixConnection(sock, timeout)) as conn:
        headers = {"Content-Type": "application/json", "Host": "localhost"}
        if token:
            headers["Authorization"] = "Bearer " + token
        conn.request(method, path, body=None if data is None else json.dumps(data), headers=headers)
        response = conn.getresponse()
        raw = response.read()
        value = json.loads(raw) if raw.strip() else {}
        if status is None:
            return response.status, value
        assert response.status == status, (method, path, response.status, value)
        return value


class Daemon:
    """`kronik serve` on a data directory, its output appended to `log`."""

    def __init__(self, bin, data, sock, port, log, healthy_timeout=60.0, config=None):
        """`config`, if given, is a configuration file for --config; the
        data directory, gateway address and API socket flags override it."""
        self.bin, self.data, self.sock, self.port = bin, data, sock, port
        self.config = config
        self.healthy_timeout = healthy_timeout
        self.log = open(log, "ab")
        self.proc = None

    def start(self, env=None):
        """Starts the daemon, with `env` added to its environment if given;
        returns (seconds until healthy, applied LSN then)."""
        started = time.time()
        args = [self.bin, "serve", "--data-dir", self.data, "--http-listen", f"127.0.0.1:{self.port}",
                "--api-socket", self.sock]
        if self.config:
            args += ["--config", self.config]
        self.proc = subprocess.Popen(
            args,
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
        return unix_api(self.sock, method, path, body, status=None, timeout=timeout)

    def cli(self, *args):
        out = subprocess.run([self.bin, "--socket", self.sock, "--json", *args],
                             capture_output=True, text=True, timeout=7200)
        if out.returncode != 0:
            raise Violation(f"kronik {' '.join(args)} failed: {out.stderr.strip() or out.stdout.strip()}")
        return json.loads(out.stdout)
