#!/usr/bin/env python3
"""HTTP load for the M1 acceptance runs (scripts/acceptance-m1.sh).

Sends COUNT POST requests to PATH on 127.0.0.1:PORT from CONCURRENCY threads.
Every request has its own Idempotency-Key; a request that fails (connection
refused or reset while the daemon is killed, 5xx) is retried with the same
key until it gets a 2xx, so after a kill -9 and restart each request ends up
acknowledged exactly once. Prints JSON: acknowledged count, the largest
counter value seen, and how many were acknowledged before the first failure.
"""

import http.client
import json
import sys
import threading
import time


def main() -> int:
    port, path, count, concurrency, prefix = (
        int(sys.argv[1]),
        sys.argv[2],
        int(sys.argv[3]),
        int(sys.argv[4]),
        sys.argv[5],
    )
    body = sys.argv[6].encode() if len(sys.argv) > 6 else b""
    lock = threading.Lock()
    state = {"next": 0, "acked": 0, "acked_before_failure": None, "retries": 0, "max": 0}

    def take():
        with lock:
            if state["next"] >= count:
                return None
            i = state["next"]
            state["next"] += 1
            return i

    def worker():
        conn = None
        while True:
            i = take()
            if i is None:
                return
            key = f"{prefix}-{i}"
            deadline = time.time() + 120
            while True:
                try:
                    if conn is None:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
                    conn.request("POST", path, body=body, headers={"Idempotency-Key": key})
                    resp = conn.getresponse()
                    data = resp.read()
                    if 200 <= resp.status < 300:
                        with lock:
                            state["acked"] += 1
                            try:
                                state["max"] = max(state["max"], int(data))
                            except ValueError:
                                pass
                        break
                    raise RuntimeError(f"HTTP {resp.status}: {data[:200]!r}")
                except Exception as e:  # noqa: BLE001 - every failure is retried
                    if conn is not None:
                        conn.close()
                        conn = None
                    with lock:
                        state["retries"] += 1
                        if state["acked_before_failure"] is None:
                            state["acked_before_failure"] = state["acked"]
                    if time.time() > deadline:
                        print(f"giving up on {key}: {e}", file=sys.stderr)
                        return
                    time.sleep(0.05)

    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    state["seconds"] = round(time.time() - start, 2)
    del state["next"]
    print(json.dumps(state))
    return 0 if state["acked"] == count else 1


if __name__ == "__main__":
    sys.exit(main())
