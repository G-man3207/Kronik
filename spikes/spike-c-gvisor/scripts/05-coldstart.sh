#!/usr/bin/env bash
# Cold start: from just before `runsc run` until the first HTTP 200 through
# the bridge, for each bridge, ITER times. Teardown (runsc delete --force)
# is timed as well.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 05-coldstart
stop_all
ITER=${ITER:-10}
LINES=$RUNDIR/coldstart-lines.txt
: >"$LINES"

teardown_ms() {
    local t0
    t0=$(date +%s%N)
    rs delete --force "$ID" >/dev/null 2>&1
    ms_since "$t0"
}

for i in $(seq "$ITER"); do
    t0=$(date +%s%N)
    start_uds
    run_ms=$(ms_since "$t0")
    start_shim
    r=$(ready "unix:$SOCKDIR/http.sock" --since-ns "$t0")
    echo "bridge=hostuds-shim iter=$i run_ms=$run_ms $r delete_ms=$(teardown_ms)" | tee -a "$LINES"
    stop_all

    t0=$(date +%s%N)
    start_pf
    run_ms=$(ms_since "$t0")
    start_pf_local
    r=$(ready "tcp:127.0.0.1:$PF_PORT" --since-ns "$t0")
    echo "bridge=portforward-local iter=$i run_ms=$run_ms $r delete_ms=$(teardown_ms)" | tee -a "$LINES"
    stop_all

    t0=$(date +%s%N)
    start_pf
    run_ms=$(ms_since "$t0")
    r=$(ready "pfstream:$ROOT:$ID:8080" --since-ns "$t0")
    echo "bridge=portforward-stream iter=$i run_ms=$run_ms $r delete_ms=$(teardown_ms)" | tee -a "$LINES"
    stop_all
done

section "Summary over $ITER starts, milliseconds (run_ms: runsc run --detach incl. netns setup; ready_ms: until the first 200)"
python3 - "$LINES" <<'PY'
import collections, statistics, sys
rows = collections.defaultdict(list)
for line in open(sys.argv[1]):
    kv = dict(f.split("=", 1) for f in line.split() if "=" in f)
    rows[kv["bridge"]].append(kv)
print(f"{'bridge':<20}{'run p50':>9}{'ready min':>11}{'ready p50':>11}{'ready max':>11}{'delete p50':>12}")
for bridge, runs in rows.items():
    ready = [float(r["ready_ms"]) for r in runs]
    print(f"{bridge:<20}{statistics.median(int(r['run_ms']) for r in runs):>9.0f}{min(ready):>11.1f}"
          f"{statistics.median(ready):>11.1f}{max(ready):>11.1f}{statistics.median(int(r['delete_ms']) for r in runs):>12.0f}")
PY
