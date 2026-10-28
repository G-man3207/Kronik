#!/usr/bin/env python3
"""Kronik's crash test (brief: Test strategy and Definition of done): kill -9
in a loop under load on a real disk, with the invariants checked after every
restart. Run it with scripts/chaos.sh.

Every cycle starts load on the daemon, kills it with SIGKILL at a random
moment, restarts it on the same data directory and checks:

- the daemon comes back healthy within --healthy-timeout seconds;
- no acknowledged turn is lost and none is applied twice: every HTTP request
  carries its own Idempotency-Key and is retried with it until it is
  acknowledged, and then each counter's and each notes actor's answers are
  exactly 1..n, where n is its counter value or row count;
- an ingress retry never makes a new turn: requests acknowledged before the
  kill, sent again with their key after the restart, get the same answer
  from the same turn;
- logical time never goes below what is durable: the first turn after the
  restart has a later logical time than every turn in the recovered log;
- effects: a POST to the `unsafe` target is never sent twice; when the kill
  leaves its outcome unknown, the re-executed turn fails with
  EFFECT_OUTCOME_UNKNOWN and its message becomes a dead letter; the
  `idempotency-keyed` target gets retries with the same key and body; no
  other dead letter appears;
- every --verify-every cycles and at the end, the derived state after
  recovery (state.db and every SQL database) is the same as the state
  rebuilt from the log alone.

At the end, a fork right after the setup (the deploys and grants) replays
all of main's root inputs with the same code, and the behavior diff must be
empty (identity replay).
The first violation stops the run and keeps the data directory.
"""

import argparse
import fcntl
import hashlib
import http.client
import json
import os
import random
import re
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True  # no __pycache__ in scripts/
from kronikd import Daemon, Violation  # noqa: E402


class Target:
    """The local HTTP service the effects go to; it records every request."""

    def __init__(self, rng):
        self.lock = threading.Lock()
        self.seen = {}  # path -> [(idempotency key, body)]
        target = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                with target.lock:
                    target.seen.setdefault(self.path, []).append((self.headers.get("idempotency-key"), body))
                    # Some slow answers make a kill between a request and
                    # its recorded result likely.
                    delay = 0.2 + rng.random() * 0.8 if rng.random() < 0.3 else rng.random() * 0.02
                time.sleep(delay)
                try:
                    self.send_response(200)
                    self.send_header("content-length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")
                except OSError:
                    pass  # the daemon was killed while waiting for the answer

            def log_message(self, *_):
                pass

        class DualStack(ThreadingHTTPServer):
            address_family = socket.AF_INET6
            daemon_threads = True

            def server_bind(self):
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                super().server_bind()

        self.server = DualStack(("::", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def receipts(self, path):
        with self.lock:
            return list(self.seen.get(path, []))


def post(port, path, key, body):
    """One HTTP request through the gateway: (status, body text, turn id), or None."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request("POST", path, body=body, headers={"Idempotency-Key": key})
        resp = conn.getresponse()
        text = resp.read().decode(errors="replace")
        return resp.status, text, resp.getheader("kronik-turn-id")
    except OSError:
        return None
    finally:
        conn.close()


class Clients:
    """The HTTP load: every request has its own Idempotency-Key and is retried
    with it until it is acknowledged; after a failure, a client waits until
    the main thread says the daemon is back."""

    RETRY = (409, 429, 500, 502, 503, 504)

    def __init__(self, port):
        self.port = port
        self.lock = threading.Lock()
        self.acks = {}  # key -> (path, answer, turn id, acknowledged at)
        self.resume = threading.Event()
        self.resume.set()
        self.errors = []

    def worker(self, jobs, deadline):
        for key, path, body in jobs:
            while True:
                r = post(self.port, path, key, body)
                if r is not None and r[0] == 200:
                    with self.lock:
                        if key in self.acks:
                            self.errors.append(f"{key} was acknowledged twice")
                        self.acks[key] = (path, r[1].strip(), r[2], time.time())
                    break
                if r is not None and r[0] not in self.RETRY:
                    self.errors.append(f"{key}: HTTP {r[0]} {r[1][:200]}")
                    return
                if time.time() > deadline:
                    self.errors.append(f"{key} was not acknowledged before the deadline")
                    return
                self.resume.wait(timeout=max(0.0, deadline - time.time()))
                time.sleep(0.01)


def effect_worker(daemon, actor, spec, wait):
    """Sends one effect message, once and never again, whatever happens."""
    time.sleep(wait)
    try:
        daemon.api("POST", f"/v1/actors/counter/{actor}/messages",
                   {"name": "fetch", "text": spec, "reason": "chaos"}, timeout=30)
    except OSError:
        pass


class Turns:
    """The turns of the actors the run uses, fetched as they appear."""

    def __init__(self, daemon):
        self.daemon = daemon
        self.by = {}  # actor -> its turns fetched so far, oldest first

    def fetch(self, actor):
        """Fetches the actor's turns since the last fetch; returns the new ones, oldest first."""
        known = self.by.setdefault(actor, [])
        after, before, new = (known[-1]["lsn"] if known else 0), None, []
        while True:
            q = "?limit=200" + (f"&before={before}" if before else "")
            status, body = self.daemon.api("GET", f"/v1/actors/{actor}/history{q}")
            if status == 404:
                return []
            if status != 200:
                raise Violation(f"history of {actor}: HTTP {status} {body}")
            page = body.get("turns", [])
            fresh = [t for t in page if t["lsn"] > after]
            new.extend(fresh)
            if len(fresh) < len(page) or not body.get("next"):
                break
            before = body["next"]
        new.sort(key=lambda t: t["lsn"])
        known.extend(new)
        return new


def digest(data):
    """The derived state of a stopped daemon: state.db and the SQL databases."""
    branch = os.path.join(data, "branches", "main")
    sql = []
    for root, _, names in os.walk(os.path.join(branch, "sql")):
        sql += [os.path.relpath(os.path.join(root, n), branch) for n in names if n.endswith(".db")]
    files = ["state.db"] + sorted(sql)
    h = hashlib.sha256()
    with tempfile.TemporaryDirectory(dir=os.path.dirname(data)) as tmp:
        for rel in files:
            src, copy = os.path.join(branch, rel), os.path.join(tmp, rel.replace("/", "_"))
            for suffix in ("", "-wal"):
                if os.path.exists(src + suffix):
                    shutil.copyfile(src + suffix, copy + suffix)
            db = sqlite3.connect(copy)
            h.update(rel.encode() + b"\0")
            tables = [r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            for t in tables:
                cols = [r[1] for r in db.execute(f'PRAGMA table_info("{t}")')]
                h.update(f"{t}({','.join(cols)})\0".encode())
                order = ", ".join(f'"{c}"' for c in cols)
                for row in db.execute(f'SELECT * FROM "{t}" ORDER BY {order}'):
                    h.update(repr(row).encode())
            db.close()
    return h.hexdigest()


def rebuild_check(daemon, data):
    """Recovered derived state == derived state rebuilt from the log alone."""
    daemon.stop()
    live = digest(data)
    branch = os.path.join(data, "branches", "main")
    kept = os.path.join(os.path.dirname(data), "derived-as-recovered")
    shutil.rmtree(kept, ignore_errors=True)
    os.makedirs(kept)
    # Without state and snapshots the start replays the whole log.
    moved = [(os.path.join(branch, n), os.path.join(kept, n)) for n in os.listdir(branch)
             if n.startswith("state.db") or n == "sql"]
    if os.path.isdir(os.path.join(data, "snapshots")):
        moved.append((os.path.join(data, "snapshots"), os.path.join(kept, "snapshots")))
    for src, dst in moved:
        shutil.move(src, dst)
    seconds, _ = daemon.start()
    # Killed once it serves (its replay is applied by then): a stop would
    # take a shutdown snapshot, whose marker the recovered state lacks.
    daemon.kill9()
    rebuilt = digest(data)
    if live != rebuilt:
        raise Violation(f"the recovered derived state ({live[:12]}, kept in {kept}) is not the "
                        f"state rebuilt from the log ({rebuilt[:12]})")
    # The recovered files and the snapshots go back; the rebuilt ones go.
    for name in os.listdir(branch):
        if name.startswith("state.db"):
            os.remove(os.path.join(branch, name))
    for path in (os.path.join(branch, "sql"), os.path.join(data, "snapshots")):
        shutil.rmtree(path, ignore_errors=True)
    for src, dst in moved:
        shutil.move(dst, src)
    shutil.rmtree(kept)
    daemon.start()
    return seconds


# Where this script and the crates' tests (crates/kronik/tests/common) claim the
# ports they hand out.
CLAIMS = "/var/tmp/kronik-test-ports"
_claims = []  # this process's claims, held until it exits


def free_port():
    """A port for the gateway, which every restart binds again: below the kernel's
    ephemeral range, which bind(0) and connect() never hand out, free now, and
    claimed with a lock in CLAIMS until this process exits. A fixed port inside the
    range (the old default 47970) was taken by another process during a restart."""
    os.makedirs(CLAIMS, exist_ok=True)
    try:
        os.chmod(CLAIMS, 0o1777)  # every user's runs share it, as they share /tmp
    except OSError:
        pass
    with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
        start = int(f.read().split()[0])
    pick = random.SystemRandom()
    for _ in range(10_000):
        port = pick.randrange(start // 2, start)
        try:
            claim = open(os.path.join(CLAIMS, str(port)), "a")
        except OSError:
            continue  # another user's claim
        try:
            fcntl.flock(claim, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with socket.socket() as s:
                s.bind(("127.0.0.1", port))
        except OSError:
            claim.close()
            continue
        _claims.append(claim)
        return port
    raise SystemExit(f"no free port in {start // 2}..{start}")


def main():
    p = argparse.ArgumentParser(description="Kronik's crash test: kill -9 in a loop under load")
    p.add_argument("--bin", required=True)
    p.add_argument("--dir", required=True)
    p.add_argument("--port", type=int,
                   help="the gateway's port (default: a free one below the ephemeral range, claimed)")
    p.add_argument("--cycles", type=int, default=1000)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--verify-every", type=int, default=50)
    p.add_argument("--healthy-timeout", type=float, default=60)
    p.add_argument("--min-kill", type=float, default=0.2, help="least seconds of load before the kill")
    p.add_argument("--max-kill", type=float, default=2.0, help="most seconds of load before the kill")
    p.add_argument("--clients", type=int, default=12)
    p.add_argument("--guests", default="tests/guests")
    p.add_argument("--skip-identity-replay", action="store_true")
    args = p.parse_args()
    if args.port is None:
        args.port = free_port()
    # The admin listener (/metrics) is not used here: port 0, which nothing can take first.
    os.environ.setdefault("KRONIK_ADMIN_LISTEN", "127.0.0.1:0")

    rng = random.Random(args.seed)
    shutil.rmtree(args.dir, ignore_errors=True)
    os.makedirs(args.dir)
    data, sock = os.path.join(args.dir, "data"), os.path.join(args.dir, "api.sock")
    daemon = Daemon(args.bin, data, sock, args.port, os.path.join(args.dir, "serve.log"), args.healthy_timeout)
    target = Target(random.Random(args.seed + 1))
    clients = Clients(args.port)
    turns = Turns(daemon)
    counters = [f"/counter/c{i}/increment" for i in range(4)]
    notes = [f"/notes/n{i}" for i in range(4)]
    actors = [f"counter/c{i}" for i in range(4)] + [f"notes/n{i}" for i in range(4)] + ["counter/probe"]
    explained = set()  # actors whose dead letter an unknown unsafe outcome explains
    durable_time = 0
    recoveries = []
    report = {"cycles": 0, "acknowledged": 0, "retried_keys": 0, "rebuild_checks": 0, "unsafe_sent": 0,
              "unsafe_reached_target": 0, "unsafe_dead_letters": 0, "keyed_sent": 0, "keyed_resent": 0}
    started = time.time()

    daemon.start()
    for wasm in ("counter.wasm", "notes.wasm"):
        daemon.cli("deploy", os.path.join(args.guests, wasm), "--reason", "chaos")
    # POST to 127.0.0.1 is unsafe (the default); to localhost it is keyed.
    daemon.cli("grant", "counter", "http:127.0.0.1", "--reason", "chaos: the unsafe target")
    daemon.cli("grant", "counter", "http:localhost", "--delivery", "idempotency-keyed",
                "--reason", "chaos: the keyed target")
    # The identity replay forks here: a fork has the deployments and grants
    # of its fork point, so it must come after the setup.
    setup_lsn = daemon.api("GET", "/v1/health")[1]["applied_lsn"]

    try:
        for cycle in range(1, args.cycles + 1):
            jobs = []
            for i in range(rng.randint(40, 200)):
                key = f"k{cycle}-{i}"
                if rng.random() < 0.7:
                    jobs.append((key, rng.choice(counters), b""))
                else:
                    jobs.append((key, rng.choice(notes), f"note {key}".encode()))
            effects = []
            for i in range(rng.randint(1, 4)):
                u, k = f"u{cycle}x{i}", f"k{cycle}x{i}"
                effects.append((u, f"POST http://127.0.0.1:{target.port}/unsafe/{u}\n\n{u}"))
                effects.append((k, f"POST http://localhost:{target.port}/keyed/{k}\n\n{k}"))
            kill_after = args.min_kill + rng.random() * (args.max_kill - args.min_kill)
            deadline = time.time() + 180
            threads = [threading.Thread(target=clients.worker, args=(jobs[i::args.clients], deadline))
                       for i in range(args.clients)]
            # The effects start at random moments before the kill.
            threads += [threading.Thread(target=effect_worker, args=(daemon, actor, spec, rng.random() * kill_after))
                        for actor, spec in effects]
            for t in threads:
                t.start()
            time.sleep(kill_after)
            clients.resume.clear()
            killed_at = time.time()
            daemon.kill9()
            recovery, boundary = daemon.start()
            recoveries.append(recovery)

            # Logical time: the first new turn is later than everything durable.
            for actor in actors + [f"counter/{a}" for a, _ in effects]:
                for t in turns.fetch(actor):
                    if t["lsn"] <= boundary:
                        durable_time = max(durable_time, t["logical_time_ms"])
            status, body = daemon.api("POST", "/v1/actors/counter/probe/messages",
                                      {"name": "probe", "text": "", "reason": "chaos"})
            m = re.search(r"now=(\d+)", (body.get("reply") or {}).get("text") or "")
            if status != 200 or not m:
                raise Violation(f"cycle {cycle}: the probe failed: {status} {body}")
            if int(m.group(1)) <= durable_time:
                raise Violation(f"cycle {cycle}: the first turn after the restart has logical time "
                                f"{m.group(1)}, not above {durable_time} in the recovered log")
            clients.resume.set()
            for t in threads:
                t.join()
            if clients.errors:
                raise Violation(f"cycle {cycle}: {clients.errors[:3]}")

            # An ingress retry never makes a new turn.
            before = sorted(k for k, a in clients.acks.items() if a[3] < killed_at and k.startswith(f"k{cycle}-"))
            for key in rng.sample(before, min(20, len(before))):
                path, answer, turn, _ = clients.acks[key]
                body = f"note {key}".encode() if path.startswith("/notes/") else b""
                r = post(args.port, path, key, body)
                if r is None or r[0] != 200 or r[1].strip() != answer or r[2] != turn:
                    raise Violation(f"cycle {cycle}: retrying {key} gave {r}, not {answer!r} from {turn}")
                report["retried_keys"] += 1

            # No acknowledged turn lost, none applied twice.
            answers = {}
            for path, answer, _, _ in clients.acks.values():
                answers.setdefault(path, []).append(int(answer))
            for path, got in answers.items():
                if sorted(got) != list(range(1, len(got) + 1)):
                    raise Violation(f"cycle {cycle}: {path}'s {len(got)} acknowledged answers are not "
                                    f"exactly 1..{len(got)} ({len(got) - len(set(got))} repeated)")
            for path in counters:
                actor = path.split("/")[2]
                _, body = daemon.api("GET", f"/v1/actors/counter/{actor}")
                n = int(next((e["text"] for e in body.get("state", []) if e["key"] == "n"), "0"))
                if n != len(answers.get(path, [])):
                    raise Violation(f"cycle {cycle}: counter/{actor} is {n}, but "
                                    f"{len(answers.get(path, []))} increments were acknowledged")
            for path in notes:
                actor = path.split("/")[2]
                _, body = daemon.api("GET", f"/v1/actors/notes/{actor}")
                tables = (body.get("sql") or {}).get("tables", [])
                rows = next((t["rows"] for t in tables if t["name"] == "notes"), 0)
                if rows != len(answers.get(path, [])):
                    raise Violation(f"cycle {cycle}: notes/{actor} has {rows} rows, but "
                                    f"{len(answers.get(path, []))} inserts were acknowledged")
            report["acknowledged"] = len(clients.acks)

            # Effects. A turn that sent its request had a durable TurnBegin,
            # so it ends, committed or failed, once the daemon is back.
            for actor, _ in effects:
                kind = "unsafe" if actor.startswith("u") else "keyed"
                receipts = target.receipts(f"/{kind}/{actor}")
                report[f"{kind}_sent"] += 1
                if kind == "unsafe" and len(receipts) > 1:
                    raise Violation(f"cycle {cycle}: the unsafe effect {actor} was sent {len(receipts)} times")
                if kind == "keyed":
                    if len(set(receipts)) > 1:
                        raise Violation(f"cycle {cycle}: {actor}'s requests differ: {receipts}")
                    report["keyed_resent"] += max(0, len(receipts) - 1)
                if kind == "unsafe" and receipts:
                    report["unsafe_reached_target"] += 1
                # History lists ended turns only, so the first one is final. A
                # request that reached the target had a durable TurnBegin, so
                # its turn must end. One the target never got may still have
                # been under way (cut off by the kill: outcome unknown), or
                # its message was never durable and there is no turn at all.
                for _ in range(600 if receipts else 40):
                    turns.fetch(f"counter/{actor}")
                    if turns.by[f"counter/{actor}"]:
                        break
                    time.sleep(0.05)
                else:
                    if receipts:
                        raise Violation(f"cycle {cycle}: {actor} reached the target, but no turn of it ended")
                    continue
                if len(turns.by[f"counter/{actor}"]) > 1:
                    raise Violation(f"cycle {cycle}: {actor}'s one message gave several turns")
                outcome = turns.by[f"counter/{actor}"][0]["outcome"]
                if outcome["kind"] == "committed":
                    continue
                if kind == "unsafe" and outcome.get("error_code") == "EFFECT_OUTCOME_UNKNOWN":
                    explained.add(f"counter/{actor}")
                    report["unsafe_dead_letters"] += 1
                    continue
                raise Violation(f"cycle {cycle}: {actor} ended {outcome}")
            _, body = daemon.api("GET", "/v1/dead-letters")
            for dl in body.get("dead_letters", []):
                if dl["actor"] not in explained or dl["error_code"] != "EFFECT_OUTCOME_UNKNOWN":
                    raise Violation(f"cycle {cycle}: a dead letter no unsafe outcome explains: {dl}")

            if args.verify_every and cycle % args.verify_every == 0:
                rebuild_check(daemon, data)
                report["rebuild_checks"] += 1
            report["cycles"] = cycle
            print(f"cycle {cycle}: {len(jobs)} requests and {len(effects)} effects, killed after "
                  f"{kill_after:.2f} s, healthy again in {recovery:.2f} s, {len(clients.acks)} "
                  f"acknowledged so far: ok", flush=True)

        if not args.verify_every or args.cycles % args.verify_every:
            rebuild_check(daemon, data)
            report["rebuild_checks"] += 1

        # Identity replay: all of main's root inputs since the setup, through
        # the same code, must give an empty behavior diff.
        if not args.skip_identity_replay:
            daemon.cli("fork", "create", "--at", str(setup_lsn), "--name", "chaos-identity", "--reason", "chaos")
            replay = daemon.cli("replay", "chaos-identity", "--reason", "chaos identity replay")
            summary = replay.get("summary", {})
            report["identity_replay"] = {k: summary.get(k) for k in
                                         ("root_inputs", "replayed", "changed", "divergent_turns", "confidence")}
            if summary.get("changed") is not False or summary.get("divergent_turns"):
                raise Violation(f"the identity replay is not empty: {json.dumps(replay)[:2000]}")
    except Violation as v:
        report["violation"] = str(v)
    finally:
        try:
            daemon.stop()
        except Exception:  # noqa: BLE001 - it may be dead already
            pass
    rec = sorted(recoveries) or [0.0]
    report["healthy_after_restart_s"] = {"p50": round(rec[len(rec) // 2], 3),
                                         "p99": round(rec[min(len(rec) - 1, len(rec) * 99 // 100)], 3),
                                         "max": round(rec[-1], 3)}
    report["seconds"] = round(time.time() - started, 1)
    print(json.dumps(report))
    return 1 if "violation" in report else 0

if __name__ == "__main__":
    sys.exit(main())
