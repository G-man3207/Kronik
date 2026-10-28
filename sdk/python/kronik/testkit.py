# kronik.testkit: tests for actors, with unittest. TestHost runs the
# project's component in an in-memory Kronik node (`kronik test-host`): the
# real scheduler, runtime and effect gate, with a clock that moves only when
# the test advances it and outgoing HTTP answered by stubs and recorded.
#
#     class CounterTest(unittest.TestCase):
#         def test_counts(self):
#             host = TestHost.start()
#             self.addCleanup(host.close)
#             self.assertEqual(host.http("POST", "/counter/alice/increment").json(), {"n": 1})
#
# TestHost.start() builds the project as `kronik build` does, so tests run
# the code they see. The `kronik` binary comes from the KRONIK_BIN
# environment variable or PATH. Every request waits until what it started
# has finished (messages delivered, timers that came due fired), so a test
# can check the outcome right after it.

import base64
import json
import os
import subprocess
from dataclasses import dataclass


def _wire_body(body):
    """The wire fields for a body: text for a str, base64 for bytes, else JSON; and whether it is JSON."""
    if body is None:
        return {}, False
    if isinstance(body, str):
        return {"body": body}, False
    if isinstance(body, (bytes, bytearray, memoryview)):
        return {"body_base64": base64.b64encode(body).decode()}, False
    return {"body": json.dumps(body, separators=(",", ":"), ensure_ascii=False)}, True


def _bytes_of(wire):
    if wire.get("body_base64") is not None:
        return base64.b64decode(wire["body_base64"])
    return (wire.get("body") or "").encode()


def _header(headers, name):
    lower = name.lower()
    return next((v for n, v in headers if n.lower() == lower), None)


def _with_content_type(headers, is_json):
    if is_json and _header(headers, "content-type") is None:
        headers.append(["content-type", "application/json"])
    return headers


@dataclass
class TestResponse:
    """A response through the gateway; `turn` is the id of the turn that answered, such as `main:5`."""

    __test__ = False  # not a test case for test runners that collect Test* classes

    status: int
    headers: list
    body: bytes
    turn: str | None

    def header(self, name):
        """The first header called `name`, ignoring case, or None."""
        return _header(self.headers, name)

    def text(self):
        return self.body.decode()

    def json(self):
        return json.loads(self.text())


@dataclass
class RecordedRequest:
    """An outgoing request an actor made, as the target got it (with the secrets the host inserted)."""

    method: str
    url: str
    headers: list
    body: bytes


@dataclass
class ApiAnswer:
    """An answer of the daemon's API: the status and the JSON body."""

    status: int
    body: object


class TestHostError(Exception):
    """A request the test host refused, or the test host exited."""


class TestHost:
    """An in-memory node running the components under test."""

    __test__ = False

    def __init__(self, process):
        self._process = process

    @classmethod
    def start(cls, dir=".", entries=(), wasm=(), bin=None, seed=None):
        """Builds the project (or takes built components) and starts a test host with them deployed.

        `dir` is the project to build and deploy (None for none), `entries`
        the project's entries to build and deploy instead of pyproject.toml's
        `[tool.kronik] entry` (a second actor type, a variant), `wasm`
        components that are already built. `bin` defaults to KRONIK_BIN, else
        `kronik` on PATH; `seed` (the host's ids and guest randomness) to
        KRONIK_TEST_SEED, else 0.
        """
        args = [bin or os.environ.get("KRONIK_BIN", "kronik"), "test-host"]
        if dir is not None:
            args += ["--dir", str(dir)]
            for entry in entries:
                args += ["--entry", entry]
        for w in wasm:
            args += ["--wasm", str(w)]
        seed = seed if seed is not None else os.environ.get("KRONIK_TEST_SEED")
        if seed is not None:
            args += ["--seed", str(seed)]
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8")
        host = cls(process)
        try:
            host._next()
        except BaseException:
            host.close()
            raise
        return host

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _next(self):
        line = self._process.stdout.readline()
        if not line:
            code = self._process.wait()
            raise TestHostError(f"the test host exited (code {code}); its errors are above, on stderr")
        try:
            answer = json.loads(line)
        except ValueError:
            raise TestHostError(f"the test host's answer is not JSON: {line}") from None
        if not isinstance(answer, dict) or answer.get("ok") is not True:
            raise TestHostError(str(answer.get("error", line)) if isinstance(answer, dict) else line)
        return answer

    def _call(self, request):
        try:
            self._process.stdin.write(json.dumps({k: v for k, v in request.items() if v is not None}) + "\n")
            self._process.stdin.flush()
        except BrokenPipeError:
            pass  # _next reports the exit
        return self._next()

    def http(self, method, path, body=None, headers=None):
        """Sends an HTTP request through the gateway, as a client would; returns a TestResponse.

        `body` is bytes, str, or a value sent as JSON (with content-type application/json).
        """
        wire, is_json = _wire_body(body)
        hdrs = _with_content_type([[n, v] for n, v in (headers or {}).items()], is_json)
        answer = self._call({"op": "http", "method": method, "path": path, "headers": hdrs, **wire})
        return TestResponse(answer["status"], answer["headers"], _bytes_of(answer), answer.get("turn"))

    def send(self, actor, name, body=""):
        """Sends the message `name` to `actor` ("kind/key") as the operator; returns the API's answer (`outcome`, `reply`, `turn_id`)."""
        return self._api("POST", f"/v1/actors/{actor}/messages", {"name": name, "text": body, "reason": "test"})

    def advance(self, ms):
        """Moves the clock forward and runs the timers that came due; returns the new time in ms since the Unix epoch."""
        return self._call({"op": "advance", "ms": ms})["now_ms"]

    def stub(self, url, method=None, status=200, headers=None, body=None, error=None, times=None):
        """Adds an answer for the outgoing requests whose URL starts with `url`.

        The newest stub that matches answers; a request no stub matches fails
        as if the connection were refused. `method` limits it to one method,
        `error` fails instead (`connect`: not sent; `io`: may have arrived,
        outcome unknown), `times` answers only that many requests.
        """
        wire, is_json = _wire_body(body)
        hdrs = _with_content_type([list(h) for h in headers or ()], is_json)
        self._call({"op": "stub", "url": url, "method": method, "status": status, "headers": hdrs, "error": error, "times": times, **wire})

    def requests(self, clear=False):
        """The outgoing requests the actors made so far, oldest first; `clear` forgets them."""
        answer = self._call({"op": "requests", "clear": clear})
        return [RecordedRequest(r["method"], r["url"], r["headers"], _bytes_of(r)) for r in answer["requests"]]

    def grant(self, kind, capability, delivery=None):
        """Grants the actor type `kind` a capability, such as `http:api.example.com` or `secret:stripe`.

        `http:` grants need a delivery: `idempotency-keyed`, `at-most-once` or `unsafe`.
        """
        self._api("POST", "/v1/grants", {"kind": kind, "capability": capability, "delivery": delivery, "reason": "test"})

    def secret(self, name, value):
        """Sets the secret `name`."""
        self._api("PUT", f"/v1/secrets/{name}", {"text": value, "reason": "test"})

    def state(self, actor):
        """The key-value state of `actor` ("kind/key") as a dict of bytes."""
        answer = self._api("GET", f"/v1/actors/{actor}")
        return {e["key"]: base64.b64decode(e["base64"]) for e in answer["state"]}

    def state_json(self, actor, key):
        """The state value `key` of `actor` parsed as JSON, or None."""
        value = self.state(actor).get(key)
        return None if value is None else json.loads(value)

    def api(self, method, path, body=None):
        """Any request to the daemon's API, as `kronik` sends it over its socket (`/v1/...`)."""
        answer = self._call({"op": "api", "method": method, "path": path, "body": body})
        return ApiAnswer(answer["status"], answer.get("body"))

    def _api(self, method, path, body=None):
        answer = self.api(method, path, body)
        if answer.status != 200:
            error = answer.body.get("error") if isinstance(answer.body, dict) else None
            error = error if isinstance(error, dict) else {}
            raise TestHostError(f"{error.get('code', f'HTTP {answer.status}')}: {error.get('message', 'the request failed')}")
        return answer.body

    def close(self):
        """Stops the test host."""
        if self._process.poll() is None:
            self._process.stdin.close()
            self._process.wait()
        self._process.stdout.close()
