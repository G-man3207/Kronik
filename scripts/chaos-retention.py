#!/usr/bin/env python3
"""Retention under kill -9: idle SQL actors and a log that is compacted past them.

`scripts/chaos.py` keeps every actor busy and the log whole, so it cannot meet
the failure this script is for: an actor with an SQL database that has not
changed for longer than `[retention] history`. The start replays the log from
the lowest applied LSN of state.db and of every actor database, so once
retention had deleted the log past such an actor the node refused every start
(`STORAGE_CORRUPT: state is at lsn N, but the log starts at M (compacted)`).

The daemon runs with a short history, short segments and a snapshot every
second, so retention compacts within seconds. `--idle` notes actors get one
row each at the start and are never written again; counters take the load.
Every cycle kills the daemon with SIGKILL at a random moment, starts it again
on the same data directory and checks:

- the daemon is healthy again within --healthy-timeout seconds (a start that
  stops at the log's start is a violation);
- every idle actor still has exactly its one row;
- the log's first LSN never goes down, and by the end retention did compact
  (otherwise the run proves nothing and says so).

A read that answers 503 SECRET_UNAVAILABLE or UNAVAILABLE (the window in which
secret coverage is being restored after a restart) is a violation, as in
chaos.py; --read-retry-budget lets it retry that long instead, as the CLI does
(30 s), and the retries are counted in the report.

Usage: scripts/chaos-retention.py --bin PATH --dir WORKDIR [--cycles 60]
Prints a line per cycle and a JSON summary; exits 1 on the first violation.
"""

import argparse
import json
import os
import random
import shutil
import sys
import threading
import time

sys.dont_write_bytecode = True  # no __pycache__ in scripts/
from kronikd import Daemon, Violation  # noqa: E402

CONFIG = """[log]
segment_max_age_s = 1

[retention]
history = "{history}"
snapshot_interval = "1s"
"""


READ_RETRY_CODES = ("SECRET_UNAVAILABLE", "UNAVAILABLE")
READ_RETRY_BACKOFF_S = 0.1


def get(daemon, path, budget, retries):
    """One GET; a 503 of the secret-coverage window is retried within `budget`
    seconds and counted in retries[0]."""
    deadline = time.monotonic() + budget
    while True:
        status, body = daemon.api("GET", path)
        if status != 503:
            return status, body
        code = ""
        try:
            code = body.get("error", {}).get("code", "")
        except AttributeError:
            pass
        if code not in READ_RETRY_CODES or time.monotonic() >= deadline:
            return status, body
        retries[0] += 1
        time.sleep(READ_RETRY_BACKOFF_S)


def rows(daemon, actor, budget, retries):
    status, body = get(daemon, f"/v1/actors/{actor}", budget, retries)
    if status != 200:
        raise Violation(f"{actor}: HTTP {status} {body}")
    tables = (body.get("sql") or {}).get("tables", [])
    return next((t["rows"] for t in tables if t["name"] == "notes"), 0)


def log_first(daemon, budget, retries):
    status, body = get(daemon, "/v1/integrity", budget, retries)
    if status != 200:
        raise Violation(f"integrity: HTTP {status} {body}")
    return body["log_first_lsn"]


def main():
    p = argparse.ArgumentParser(description="kill -9 under load with a log that retention compacts past idle SQL actors")
    p.add_argument("--bin", required=True)
    p.add_argument("--dir", required=True)
    p.add_argument("--port", type=int, default=0, help="the gateway port (0: 38900 + the process id modulo 500)")
    p.add_argument("--cycles", type=int, default=60)
    p.add_argument("--idle", type=int, default=12, help="notes actors written once and then idle")
    p.add_argument("--history", default="4s", help="[retention] history")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--healthy-timeout", type=float, default=60)
    p.add_argument("--read-retry-budget", type=float, default=0,
                   help="seconds a read may be retried after a 503 SECRET_UNAVAILABLE (0: a 503 is a violation)")
    p.add_argument("--guests", default="tests/guests")
    args = p.parse_args()
    port = args.port or 38900 + os.getpid() % 500
    rng = random.Random(args.seed)
    shutil.rmtree(args.dir, ignore_errors=True)
    os.makedirs(args.dir)
    config = os.path.join(args.dir, "kronik.toml")
    with open(config, "w", encoding="utf-8") as f:
        f.write(CONFIG.format(history=args.history))
    os.environ["KRONIK_CONFIG"] = config
    # The admin listener (/metrics) is not used here: port 0, which nothing can take first.
    os.environ.setdefault("KRONIK_ADMIN_LISTEN", "127.0.0.1:0")
    data, sock = os.path.join(args.dir, "data"), os.path.join(args.dir, "api.sock")
    daemon = Daemon(args.bin, data, sock, port, os.path.join(args.dir, "serve.log"), args.healthy_timeout)
    idle = [f"notes/idle{i}" for i in range(args.idle)]
    report = {"cycles": 0, "idle_actors": args.idle, "log_first_lsn": 1, "sent": 0, "read_retries": 0}
    retries = [0]
    started = time.time()
    daemon.start()
    try:
        for wasm in ("counter.wasm", "notes.wasm"):
            daemon.cli("deploy", os.path.join(args.guests, wasm), "--reason", "chaos-retention")
        for actor in idle:
            daemon.cli("send", actor, "add", "--text", "written once", "--reason", "chaos-retention")
        for cycle in range(1, args.cycles + 1):
            stop = threading.Event()
            sent = [0]

            def load():
                i = 0
                while not stop.is_set():
                    try:
                        daemon.cli("send", f"counter/c{i % 4}", "increment", "--reason", "chaos-retention")
                        sent[0] += 1
                    except Violation:
                        pass  # the kill can land inside a request
                    i += 1

            thread = threading.Thread(target=load)
            thread.start()
            time.sleep(1.5 + rng.random() * 2.0)
            daemon.kill9()
            stop.set()
            thread.join()
            report["sent"] += sent[0]
            try:
                seconds, _ = daemon.start()
            except Violation as v:
                with open(os.path.join(args.dir, "serve.log"), encoding="utf-8", errors="replace") as log:
                    errors = [line.strip() for line in log if " ERROR " in line]
                raise Violation(f"cycle {cycle}: {v}: {errors[-1][-300:] if errors else 'no ERROR line'}") from v
            for actor in idle:
                n = rows(daemon, actor, args.read_retry_budget, retries)
                if n != 1:
                    raise Violation(f"cycle {cycle}: {actor} has {n} rows after the restart, not its one")
            first = log_first(daemon, args.read_retry_budget, retries)
            if first < report["log_first_lsn"]:
                raise Violation(f"cycle {cycle}: the log's first LSN went from {report['log_first_lsn']} to {first}")
            report["log_first_lsn"] = first
            report["read_retries"] = retries[0]
            report["cycles"] = cycle
            print(f"cycle {cycle}: {sent[0]} requests, healthy again in {seconds:.2f} s, "
                  f"log first LSN {first}, {args.idle} idle actors intact: ok", flush=True)
        if report["log_first_lsn"] <= 1:
            raise Violation("retention never compacted the log: the run proves nothing; "
                            "raise --cycles or lower --history")
    except Violation as v:
        report["violation"] = str(v)
    finally:
        try:
            daemon.stop()
        except Exception:  # noqa: BLE001 - it may be dead already
            pass
    report["seconds"] = round(time.time() - started, 1)
    print(json.dumps(report))
    return 1 if "violation" in report else 0


if __name__ == "__main__":
    sys.exit(main())
