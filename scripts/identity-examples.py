#!/usr/bin/env python3
"""Identity replay of every example app (Definition of done: "Identity
replay empty for all example apps"), on a real daemon. Run it with
scripts/identity-examples.sh.

Each example gets a fresh daemon on a real disk. The script deploys the
example and gives it the secrets and grants it needs. Then it drives
representative traffic and checks that the traffic did what it should, so
that an empty diff means something. Last, it forks right after the setup
and replays every root input since then with the same code, first in
isolated mode, then in continuous mode. Each replay's diff must be empty:
nothing changed, no divergent turn, every root input replayed, and every
effect answered from its recording (exact grounding).

The traffic:

- counter-rs, -ts, -py, -go: increments and reads over HTTP, a retry with
  the same Idempotency-Key, and operator messages.
- notes-rs, -ts, -py, -go: SQL writes (create, delete) and paged reads,
  invalid input, and a message, which notes does not handle: a dead
  letter, resent.
- webhook-relay-rs, -ts, -py, -go: webhooks forwarded to a local target.
  These are effects with recorded responses, signed, with a secret
  inserted by the host. Also: a 500 retried by timer, a 400, a host that
  is not granted, and a configure message with a bad target, which becomes
  a dead letter and is resent.
- todo-ts: items added, changed, done and deleted. Then the daemon restarts
  a day later: libfaketime moves its wall clock 25 h ahead, so the sweep
  timer fires and removes the done items. Also a message, which todo does
  not handle: a dead letter, resent.
- billing-ts with its ledger: invoices finalized through calls to the
  ledger actor and charges to fake-payments, run as a plain local HTTP
  service (the gVisor path is demo/billing.sh's). A declined charge fails
  its turn, so the ledger gets the compensation. An unknown message
  becomes a dead letter and is resent.

The first failure stops the run and keeps its work directory.
"""

import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True  # no __pycache__ in scripts/
from kronikd import Daemon, Violation  # noqa: E402

REASON = "identity replay of the examples"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Example:
    """One example's daemon and the calls the traffic makes."""

    def __init__(self, args, name):
        self.args, self.name = args, name
        self.dir = os.path.join(args.dir, name)
        os.makedirs(self.dir)
        self.port = free_port()
        self.daemon = Daemon(args.bin, os.path.join(self.dir, "data"), os.path.join(self.dir, "api.sock"),
                             self.port, os.path.join(self.dir, "serve.log"))
        self.services = []

    def check(self, what, ok, detail=""):
        if not ok:
            raise Violation(f"{self.name}: {what}{': ' + str(detail) if detail != '' else ''}")

    def api(self, method, path, body=None):
        status, out = self.daemon.api(method, path, body)
        self.check(f"{method} {path} answered {status}", status < 300, out)
        return out

    def http(self, method, path, body=None, headers=None):
        """A request through the gateway: (status, body as JSON or text, headers)."""
        data = body if isinstance(body, bytes) else None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                status, raw, hdrs = r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            status, raw, hdrs = e.code, e.read(), e.headers
        try:
            out = json.loads(raw) if raw else None
        except ValueError:
            out = raw.decode(errors="replace")
        return status, out, {k.lower(): v for k, v in hdrs.items()}

    def expect(self, method, path, status, body=None, headers=None):
        got, out, _ = self.http(method, path, body, headers)
        self.check(f"{method} {path}: want {status}, got {got}", got == status, out)
        return out

    def send(self, actor, name, body="", committed=True):
        """An operator message; `committed` says whether its turn must commit."""
        kind, key = actor.split("/")
        text = body if isinstance(body, str) else json.dumps(body)
        out = self.api("POST", f"/v1/actors/{kind}/{key}/messages", {"name": name, "text": text, "reason": REASON})
        kind_of = out["outcome"]["kind"]
        self.check(f"message {name} to {actor} ended {kind_of}", (kind_of == "committed") == committed, out)
        return out

    def secret(self, name, value):
        self.api("PUT", f"/v1/secrets/{name}", {"text": value, "reason": REASON})

    def grant(self, kind, capability, delivery=None):
        body = {"kind": kind, "capability": capability, "reason": REASON}
        if delivery:
            body["delivery"] = delivery
        self.api("POST", "/v1/grants", body)

    def dead_letter_resent(self, actor, name, body=""):
        """Sends a message `actor` rejects, finds its dead letter, resends it
        and checks that the resend is rejected again."""
        turn = self.send(actor, name, body, committed=False)["turn_id"]
        letters = self.api("GET", "/v1/dead-letters")["dead_letters"]
        letter = next((d for d in letters if d["id"] == turn), None)
        self.check(f"the rejected {name} to {actor} is a dead letter", letter is not None, letters)
        again = self.api("POST", f"/v1/dead-letters/{turn}/resend", {"reason": REASON})
        self.check(f"the resent {name} to {actor} is rejected again", again["outcome"]["kind"] != "committed", again)

    def wait_for(self, what, poll, timeout=30.0):
        """Polls until `poll()` returns something true; returns it."""
        deadline = time.time() + timeout
        while True:
            got = poll()
            if got:
                return got
            if time.time() > deadline:
                raise Violation(f"{self.name}: {what} did not happen within {timeout:.0f} s")
            time.sleep(0.1)

    def coverage(self):
        """What the traffic exercised, from every actor's history."""
        inputs, outcomes, effects, sql = {}, {}, 0, 0
        for actor in self.api("GET", "/v1/actors?limit=1000")["actors"]:
            before = None
            while True:
                q = f"?limit=500{'&before=' + str(before) if before else ''}"
                page = self.api("GET", f"/v1/actors/{actor['kind']}/{actor['key']}/history{q}")
                for t in page["turns"]:
                    inputs[t["input"]["type"]] = inputs.get(t["input"]["type"], 0) + 1
                    outcomes[t["outcome"]["kind"]] = outcomes.get(t["outcome"]["kind"], 0) + 1
                    effects += len(t.get("effects") or [])
                    sql += t.get("sql_changes", 0) > 0
                before = page.get("next")
                if not before:
                    break
        return {"inputs": inputs, "outcomes": outcomes, "effects": effects, "turns_with_sql_writes": sql}

    def close(self):
        for s in self.services:
            s()
        if self.daemon.proc and self.daemon.proc.poll() is None:
            self.daemon.stop()


# ----------------------------------------------------------------- counter


def counter_traffic(ex):
    for key in ("alice", "bob", "carol"):
        for n in range(1, 4):
            ex.check(f"increment {key}", ex.expect("POST", f"/counter/{key}/increment", 200) == {"n": n})
    first = ex.http("POST", "/counter/alice/increment", headers={"Idempotency-Key": "identity-1"})
    again = ex.http("POST", "/counter/alice/increment", headers={"Idempotency-Key": "identity-1"})
    ex.check("a retry with the same Idempotency-Key gets the same answer from the same turn",
             (first[1], first[2].get("kronik-turn-id")) == (again[1], again[2].get("kronik-turn-id")), (first, again))
    for n in (4, 5):
        reply = ex.send("counter/bob", "increment")["reply"]["text"]
        ex.check("increment message", json.loads(reply)["n"] == n, reply)
    ex.check("GET /counter/alice", ex.expect("GET", "/counter/alice", 200) == {"n": 4})
    ex.check("GET /counter/bob", ex.expect("GET", "/counter/bob", 200) == {"n": 5})
    ex.expect("GET", "/counter/alice/nope", 404)


# ------------------------------------------------------------------- notes


def notes_traffic(ex):
    ids = [ex.expect("POST", "/notes/alice", 201, {"title": f"note {i}", "body": f"body {i}"})["id"] for i in range(5)]
    ex.expect("POST", "/notes/bob", 201, {"title": "bob's", "body": "hello"})
    page = ex.expect("GET", "/notes/alice?limit=2", 200)
    ex.check("the first page", [n["id"] for n in page["notes"]] == ids[:2] and page["next"], page)
    page = ex.expect("GET", f"/notes/alice?limit=2&after={page['next']}", 200)
    ex.check("the second page", [n["id"] for n in page["notes"]] == ids[2:4], page)
    ex.expect("GET", f"/notes/alice/{ids[0]}", 200)
    ex.expect("DELETE", f"/notes/alice/{ids[1]}", 204)
    ex.expect("GET", f"/notes/alice/{ids[1]}", 404)
    ex.expect("DELETE", f"/notes/alice/{ids[1]}", 404)
    ex.expect("POST", "/notes/alice", 400, b"not json")
    ex.expect("POST", "/notes/alice", 400, {"title": "x" * 201, "body": ""})
    ex.check("four notes left", len(ex.expect("GET", "/notes/alice", 200)["notes"]) == 4)
    ex.dead_letter_resent("notes/alice", "archive")


# ----------------------------------------------------------- webhook-relay


class RelayTarget:
    """Where the relay forwards to: /ok answers 200, /flaky 500 to the first
    request of each webhook and 200 after that, /bad 400."""

    def __init__(self):
        target = self
        self.requests, self.lock, self.seen = [], threading.Lock(), set()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                hook = self.headers.get("x-webhook-id")
                with target.lock:
                    status = {"/ok": 200, "/bad": 400}.get(self.path, 200 if hook in target.seen else 500)
                    target.seen.add(hook)
                    target.requests.append({"path": self.path, "body": body,
                                            "headers": {k.lower(): v for k, v in self.headers.items()}})
                self.send_response(status)
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def relay_setup(ex):
    ex.secret("relay-signing-key", "identity-signing-key")
    ex.secret("relay-auth", "tok-identity")
    ex.grant("webhook-relay", "secret:relay-signing-key")
    ex.grant("webhook-relay", "secret:relay-auth")
    ex.grant("webhook-relay", "http:127.0.0.1", "idempotency-keyed")


def relay_traffic(ex):
    target = RelayTarget()
    ex.services.append(target.stop)

    def configure(**update):
        ex.send("webhook-relay/acme", "configure", update)

    def hook(body, status, want):
        got, record, _ = ex.http("POST", "/hooks/acme", body)
        ex.check(f"webhook {body!r}: want {status} {want}", (got, record["status"]) == (status, want), record)
        return record

    configure(target=f"{target.url}/ok", auth_secret="relay-auth")
    first = hook({"event": "paid", "amount": 42}, 200, "delivered")
    hook(b"plain text", 200, "delivered")
    sent = target.requests[0]["headers"]
    ex.check("the forwarded request is signed, with the secret inserted by the host",
             sent.get("x-signature", "").startswith("sha256=") and sent.get("authorization") == "Bearer tok-identity",
             sent)
    ex.check("GET the delivery", ex.expect("GET", f"/hooks/acme/{first['id']}", 200)["status"] == "delivered")
    configure(target=f"{target.url}/flaky")
    flaky = hook({"event": "flaky"}, 502, "retrying")
    ex.wait_for("the retry by timer", lambda: ex.expect("GET", f"/hooks/acme/{flaky['id']}", 200)["status"] == "delivered")
    configure(target=f"{target.url}/bad")
    hook({"event": "bad"}, 502, "failed")
    # Another source keeps the default target, whose host is not granted.
    got, record, _ = ex.http("POST", "/hooks/globex", {"event": "denied"})
    ex.check("a target that is not granted fails", got == 502 and "CAPABILITY_NOT_GRANTED" in str(record.get("error")),
             record)
    ex.expect("GET", "/hooks/acme/nope", 404)
    ex.dead_letter_resent("webhook-relay/acme", "configure", {"target": "ftp://example.com/"})


# -------------------------------------------------------------------- todo


def todo_traffic(ex):
    for title in ("buy milk", "call mum", "file taxes", "water plants"):
        ex.expect("POST", "/todo/home", 201, {"title": title})
    ex.expect("POST", "/todo/work", 201, {"title": "review the diff"})
    ex.check("rename", ex.expect("PATCH", "/todo/home/1", 200, {"title": "buy oat milk"})["title"] == "buy oat milk")
    ex.expect("PATCH", "/todo/home/2", 200, {"done": True})
    ex.expect("PATCH", "/todo/home/3", 200, {"done": True})
    ex.expect("PATCH", "/todo/home/3", 200, {"done": False})
    ex.expect("DELETE", "/todo/home/4", 204)
    ex.expect("GET", "/todo/home/4", 404)
    ex.expect("POST", "/todo/home", 400, {"title": ""})
    ex.expect("PATCH", "/todo/home/1", 400, {"done": "yes"})
    timers = ex.api("GET", "/v1/actors/todo/home/timers")["timers"]
    ex.check("one sweep is pending", len(timers) == 1, timers)
    ex.dead_letter_resent("todo/home", "sweep")

    # A day later: the daemon restarts with its wall clock 25 h ahead, and
    # the sweep removes the item done more than a day ago.
    ex.daemon.stop()
    ex.daemon.start(env={"LD_PRELOAD": ex.args.faketime_lib, "FAKETIME": "+25h",
                         "FAKETIME_DONT_FAKE_MONOTONIC": "1"})
    ex.wait_for("the sweep", lambda: [i["id"] for i in ex.expect("GET", "/todo/home", 200)["items"]] == [1, 3])
    ex.check("no sweep is pending", ex.api("GET", "/v1/actors/todo/home/timers")["timers"] == [])
    item = ex.expect("POST", "/todo/home", 201, {"title": "a day later"})
    ex.check("the daemon's clock is a day ahead", item["created_ms"] > (time.time() + 24 * 3600) * 1000, item)


# ----------------------------------------------------------------- billing


def billing_setup(ex):
    port = free_port()
    data = os.path.join(ex.dir, "payments")
    os.makedirs(data)
    log = open(os.path.join(ex.dir, "payments.log"), "ab")
    proc = subprocess.Popen([ex.args.fake_payments, "--listen", f"127.0.0.1:{port}", "--data-dir", data],
                            env={**os.environ, "PAYMENTS_API_KEY": "pk_identity"}, stdout=log, stderr=log)

    def stop():
        proc.terminate()
        proc.wait(timeout=30)

    ex.services.append(stop)
    ex.payments = f"http://127.0.0.1:{port}"
    ex.wait_for("fake-payments", lambda: _healthy(ex.payments))
    ex.secret("payments-key", "pk_identity")
    ex.secret("payments-wrong-key", "pk_wrong")
    ex.grant("billing", "http:127.0.0.1", "idempotency-keyed")
    ex.grant("billing", "secret:payments-key")
    ex.grant("billing", "secret:payments-wrong-key")


def _healthy(url):
    try:
        with urllib.request.urlopen(f"{url}/healthz", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


def billing_traffic(ex):
    def configure(actor, **update):
        ex.send(actor, "configure", update)

    lines = [{"description": "Widgets", "quantity": 3, "unit_price": 1250},
             {"description": "Support", "quantity": 1, "unit_price": 9900}]
    for actor in ("billing/acme", "billing/lagom"):
        configure(actor, payments=ex.payments, api_key_secret="payments-key")
    ex.expect("PUT", "/billing/acme", 200, {"name": "Acme GmbH", "country": "DE", "vat_id": None})
    ex.expect("PUT", "/billing/lagom", 200, {"name": "Lagom AB", "country": "SE", "vat_id": "SE556677889901"})
    ex.expect("POST", "/billing/acme/invoices/inv-1", 201, {"currency": "EUR", "lines": lines[:1]})
    ex.expect("POST", "/billing/acme/invoices/inv-1", 200, {"currency": "EUR", "lines": lines})
    paid = ex.expect("POST", "/billing/acme/invoices/inv-1/finalize", 200)
    ex.check("inv-1 is paid with domestic VAT", paid["status"] == "paid" and paid["charge"]
             and paid["total"] == 13650 + 3413, paid)
    ex.expect("POST", "/billing/acme/invoices/inv-1/finalize", 409)
    ex.expect("POST", "/billing/acme/invoices/inv-1", 409, {"currency": "EUR", "lines": lines})
    ex.expect("GET", "/billing/acme/invoices/inv-1", 200)
    ex.expect("GET", "/billing/acme", 200)
    ex.expect("POST", "/billing/acme/invoices/inv-3", 400, {"currency": "eur", "lines": lines})
    ex.check("acme's ledger", ex.expect("GET", "/ledger/acme", 200)["balance"] == {"EUR": paid["total"]})

    # A declined charge fails the turn; the ledger gets the compensation.
    configure("billing/lagom", api_key_secret="payments-wrong-key")
    ex.expect("POST", "/billing/lagom/invoices/inv-2", 201, {"currency": "EUR", "lines": lines})
    ex.expect("POST", "/billing/lagom/invoices/inv-2/finalize", 500)
    ledger = ex.wait_for("the compensation", lambda: (lambda l: l if [e["kind"] for e in l["entries"]] == ["post", "reverse"]
                                                     else None)(ex.expect("GET", "/ledger/lagom", 200)))
    ex.check("the reversal cancels the posting", ledger["balance"] == {"EUR": 0}, ledger)
    ex.check("inv-2 is still a draft", ex.expect("GET", "/billing/lagom/invoices/inv-2", 200)["status"] == "draft")
    configure("billing/lagom", api_key_secret="payments-key")
    ex.check("inv-2 is paid", ex.expect("POST", "/billing/lagom/invoices/inv-2/finalize", 200)["status"] == "paid")
    ex.dead_letter_resent("billing/acme", "refund", {"invoice": "inv-1"})
    ex.dead_letter_resent("ledger/acme", "post", {"invoice": "inv-9"})


EXAMPLES = {
    "counter-rs": (["counter.wasm"], None, counter_traffic),
    "counter-ts": (["counter-ts.wasm"], None, counter_traffic),
    "counter-py": (["counter-py.wasm"], None, counter_traffic),
    "counter-go": (["counter-go.wasm"], None, counter_traffic),
    "notes-rs": (["notes.wasm"], None, notes_traffic),
    "notes-ts": (["notes-ts.wasm"], None, notes_traffic),
    "notes-py": (["notes-py.wasm"], None, notes_traffic),
    "notes-go": (["notes-go.wasm"], None, notes_traffic),
    "webhook-relay-rs": (["webhook-relay.wasm"], relay_setup, relay_traffic),
    "webhook-relay-ts": (["webhook-relay-ts.wasm"], relay_setup, relay_traffic),
    "webhook-relay-py": (["webhook-relay-py.wasm"], relay_setup, relay_traffic),
    "webhook-relay-go": (["webhook-relay-go.wasm"], relay_setup, relay_traffic),
    "todo-ts": (["todo-ts.wasm"], None, todo_traffic),
    "billing-ts": (["billing-ts.wasm", "billing-ts-ledger.wasm"], billing_setup, billing_traffic),
}


def run(args, name):
    components, setup, traffic = EXAMPLES[name]
    ex = Example(args, name)
    started = time.time()
    try:
        ex.daemon.start()
        for c in components:
            with open(os.path.join(args.dist, c), "rb") as f:
                ex.api("POST", "/v1/deployments", {"wasm_base64": base64.b64encode(f.read()).decode(), "reason": REASON})
        if setup:
            setup(ex)
        fork_lsn = ex.api("GET", "/v1/health")["applied_lsn"]
        traffic(ex)
        coverage = ex.coverage()
        ex.daemon.cli("fork", "create", "--at", str(fork_lsn), "--name", "identity", "--reason", REASON)
        replays, failures = {}, []
        for mode in ("isolated", "continuous"):
            s = ex.daemon.cli("replay", "identity", "--mode", mode, "--reason", f"{REASON}, {mode}")["summary"]
            replays[mode] = {k: s[k] for k in ("root_inputs", "replayed", "changed", "divergent_turns", "exact",
                                               "approximate", "synthetic")}
            if (s["changed"] or s["divergent_turns"] or s["replayed"] != s["root_inputs"] or s["approximate"]
                    or s["synthetic"]):
                diff = subprocess.run([args.bin, "--socket", ex.daemon.sock, "diff", "show", "identity", "--md"],
                                      capture_output=True, text=True).stdout
                failures.append(f"the {mode} identity replay is not empty: {json.dumps(s)}\n{diff}")
        if failures:
            raise Violation(f"{name}: " + "\n".join(failures))
        return {"fork_lsn": fork_lsn, "coverage": coverage, "replays": replays,
                "seconds": round(time.time() - started, 1)}
    finally:
        ex.close()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bin", required=True, help="the kronik binary")
    p.add_argument("--dir", required=True, help="the work directory (emptied first)")
    p.add_argument("--dist", default="examples/dist", help="where the example components are")
    p.add_argument("--fake-payments", help="the fake-payments binary, for billing-ts")
    p.add_argument("--faketime-lib", help="libfaketime's shared library, for todo-ts")
    p.add_argument("--only", help="comma-separated examples to run (default all)")
    args = p.parse_args()
    names = args.only.split(",") if args.only else list(EXAMPLES)
    unknown = [n for n in names if n not in EXAMPLES]
    if unknown:
        sys.exit(f"error: unknown examples {unknown}; there are {', '.join(EXAMPLES)}")
    missing = [c for n in names for c in EXAMPLES[n][0] if not os.path.exists(os.path.join(args.dist, c))]
    if missing:
        sys.exit(f"error: {', '.join(missing)} not in {args.dist}; build the examples with scripts/build-examples.sh, "
                 "scripts/build-examples-ts.sh, -py.sh and -go.sh")
    if "billing-ts" in names and not args.fake_payments:
        sys.exit("error: billing-ts needs --fake-payments")
    if "todo-ts" in names and not args.faketime_lib:
        sys.exit("error: todo-ts needs libfaketime (Debian and Ubuntu: apt-get install faketime) for its sweep")
    shutil.rmtree(args.dir, ignore_errors=True)
    os.makedirs(args.dir)
    results = {}
    for name in names:
        try:
            results[name] = run(args, name)
        except Violation as v:
            print(f"{name}: FAIL: {v}", flush=True)
            print(json.dumps({"passed": list(results), "failed": name, "dir": args.dir}))
            sys.exit(1)
        r = results[name]
        print(f"{name}: identity replay empty in both modes ({r['replays']['isolated']['root_inputs']} root inputs, "
              f"{r['replays']['isolated']['exact']} effects exact; turns by input {r['coverage']['inputs']}; "
              f"{r['seconds']} s)", flush=True)
    print(json.dumps(results))
    shutil.rmtree(args.dir, ignore_errors=True)


if __name__ == "__main__":
    main()
