#!/usr/bin/env bash
# Measures HTTP latency from the host to the server in the sandbox through
# each bridge, with a plain host process as the baseline. Every benchmark is
# ROUNDS rounds of N sequential POST /echo requests (64-byte body) after W
# warmup requests, over one kept-alive connection or a new connection per
# request. With CPU_LIMIT=on (default) the sandbox keeps its --cpu 1 limit;
# CPU_LIMIT=off lifts the quota after start to show the bridge overhead alone.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record "04-bridges-cpu-$CPU_LIMIT"
stop_all
ROUNDS=${ROUNDS:-3}
N=${N:-1000}
W=${W:-100}
LINES=$RUNDIR/bench-lines-cpu-$CPU_LIMIT.txt
: >"$LINES"

bench() {
    for mode in keepalive newconn; do
        for _ in $(seq "$ROUNDS"); do
            "$BIN/bridge-bench" bench --target "$2" --mode "$mode" --requests "$N" --warmup "$W" --label "$1" | tee -a "$LINES"
        done
    done
}

section "Baseline: echo-server as a plain host process, no sandbox"
"$BIN/echo-server" --listen 127.0.0.1:18090 --listen-unix "$RUNDIR/baseline.sock" >"$LOGS/baseline.log" 2>&1 &
base=$!
ready tcp:127.0.0.1:18090
bench host-tcp tcp:127.0.0.1:18090
bench host-unix "unix:$RUNDIR/baseline.sock"
kill "$base"

section "(b) --network=none --host-uds=create: host -> unix socket -> uds-shim in the sandbox -> 127.0.0.1:8080"
start_uds
start_shim
ready "unix:$SOCKDIR/http.sock"
ls -l "$SOCKDIR"
get /info
throttling
bench hostuds-shim "unix:$SOCKDIR/http.sock"
throttling

section "(b') same sandbox, the app itself listens on a unix socket in the shared directory (no shim)"
rs exec --detach --user 0:0 "$ID" /bin/echo-server --listen-unix /.kronik/sock/direct.sock >>"$LOGS/direct.log" 2>&1 </dev/null
ready "unix:$SOCKDIR/direct.sock"
bench hostuds-direct "unix:$SOCKDIR/direct.sock"
throttling
stop_all

section "(a) --network=sandbox in netns $NETNS (only lo): runsc port-forward $ID $PF_PORT:8080"
start_pf
start_pf_local
ready "tcp:127.0.0.1:$PF_PORT"
echo "the port-forward listener (note the address):"
ss -ltnp | grep ":$PF_PORT "
throttling
bench portforward-local "tcp:127.0.0.1:$PF_PORT"
throttling

section "(a') same sandbox, runsc port-forward --stream: one runsc process per connection"
bench portforward-stream "pfstream:$ROOT:$ID:8080"
throttling
stop_all

section "Summary: median over $ROUNDS rounds of each percentile, microseconds"
python3 - "$LINES" <<'PY'
import collections, statistics, sys
rows = collections.defaultdict(list)
for line in open(sys.argv[1]):
    kv = dict(f.split("=", 1) for f in line.split() if "=" in f)
    rows[(kv["label"], kv["mode"])].append(kv)
print(f"{'bridge':<20}{'mode':<11}{'p50':>8}{'p90':>8}{'p99':>8}{'p99.9':>8}{'max':>8}  errors")
for (label, mode), runs in rows.items():
    med = lambda k: int(statistics.median(int(r[k]) for r in runs))
    errors = sum(int(r["errors"]) for r in runs)
    print(f"{label:<20}{mode:<11}{med('p50_us'):>8}{med('p90_us'):>8}{med('p99_us'):>8}{med('p999_us'):>8}{med('max_us'):>8}  {errors}")
PY
