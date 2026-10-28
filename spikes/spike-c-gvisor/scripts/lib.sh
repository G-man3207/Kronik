# shellcheck shell=bash disable=SC2034
# Shared settings and helpers for the experiment scripts. Sourced, not run.
# The experiments run as root on the test host after scripts/deploy.sh.

SPIKE=/root/kronik-spike-c
BIN=$SPIKE/bin
LAYOUT=$SPIKE/foreign-echo-layout
RESULTS=$SPIKE/results
DATA=/var/lib/kronik-spike-c
RUNDIR=/run/kronik-spike-c
ROOT=$RUNDIR/runsc                         # runsc state, separate from other runsc users
LOGS=$RUNDIR/logs
ID=kronik-echo                             # container (sandbox) id
SOCKDIR=$RUNDIR/foreign/echo/sock          # bind-mounted at /.kronik/sock
DATADIR=$DATA/foreign/echo/data            # bind-mounted at /data
BUNDLE=$DATA/foreign/echo/bundle           # for --network=none
BUNDLE_PF=$DATA/foreign/echo-pf/bundle     # joins the network namespace $NETNS
NETNS=kronik-echo
CGROUP=/sys/fs/cgroup/kronik/foreign-echo
PF_PORT=18080

# The bridge under test:
#   pf  (default, the one ADR 0003 picks): --network=sandbox in a fresh
#       network namespace that has only lo; every connection is one
#       `runsc port-forward --stream` to port 8080.
#   uds: --network=none --host-uds=create; uds-shim in the sandbox listens on
#       /.kronik/sock/http.sock and forwards to 127.0.0.1:8080.
BRIDGE=${BRIDGE:-pf}

# Extra runsc flags for experiments, e.g. RUNSC_EXTRA=--systrap-disable-fast-path.
read -r -a RUNSC_EXTRA <<<"${RUNSC_EXTRA:-}"

# CPU_LIMIT=off lifts the cgroup CPU quota right after start, to separate
# bridge overhead from CPU throttling.
CPU_LIMIT=${CPU_LIMIT:-on}

mkdir -p "$RESULTS" "$LOGS" "$SOCKDIR" "$DATADIR" "$ROOT"
chmod 700 "$SOCKDIR"

rs() { runsc --root "$ROOT" "$@"; }

# Writes everything the calling script prints to results/<name>.txt as well.
record() {
    exec > >(tee "$RESULTS/$1.txt") 2>&1
    echo "# $1 on $(hostname) at $(date -u +%FT%TZ), $(runsc --version | head -1), bridge $BRIDGE"
}

section() { printf '\n=== %s\n' "$*"; }

# Prints a command, then runs it.
show() {
    echo "\$ $*"
    "$@"
}

stop_all() {
    pkill -f "^runsc --root $ROOT port-forward" 2>/dev/null || true
    rs delete --force "$ID" >/dev/null 2>&1 || true
    ip netns del "$NETNS" 2>/dev/null || true
    rm -f "$SOCKDIR"/* "$RUNDIR/shim.pid"
    : >"$LOGS/$ID.log"
}

target() {
    case "$BRIDGE" in
        pf) echo "pfstream:$ROOT:$ID:8080" ;;
        uds) echo "unix:$SOCKDIR/http.sock" ;;
    esac
}

ready() { "$BIN/bridge-bench" ready --timeout-ms 10000 --target "$@"; }
get() { "$BIN/bridge-bench" get --target "$(target)" --path "$1"; }
throttling() { echo "cgroup cpu.stat: $(grep -E '^(usage_usec|nr_periods|nr_throttled|throttled_usec)' "$CGROUP/cpu.stat" | tr '\n' ' ')"; }

after_start() {
    if [ "$CPU_LIMIT" = off ]; then
        echo "max 100000" >"$CGROUP/cpu.max"
    fi
}

# A fresh network namespace with only lo, up. runsc port-forward needs
# --network=sandbox and a loopback NIC; with nothing else in the namespace
# the sandbox has no route out.
make_netns() {
    ip netns del "$NETNS" 2>/dev/null || true
    ip netns add "$NETNS"
    ip -n "$NETNS" link set lo up
}

runsc_flags() {
    case "$BRIDGE" in
        pf) echo "--platform=systrap --network=sandbox" ;;
        uds) echo "--platform=systrap --network=none --host-uds=create" ;;
    esac
}

bundle() {
    case "$BRIDGE" in
        pf) echo "$BUNDLE_PF" ;;
        uds) echo "$BUNDLE" ;;
    esac
}

start_pf() {
    make_netns
    rs --platform=systrap --network=sandbox "${RUNSC_EXTRA[@]}" \
        run --detach --bundle "$BUNDLE_PF" "$ID" >>"$LOGS/$ID.log" 2>&1 </dev/null
    after_start
}

start_uds() {
    rm -f "$SOCKDIR"/*
    rs --platform=systrap --network=none --host-uds=create "${RUNSC_EXTRA[@]}" \
        run --detach --bundle "$BUNDLE" "$ID" >>"$LOGS/$ID.log" 2>&1 </dev/null
    after_start
}

start_shim() {
    rs exec --detach --user 0:0 --internal-pid-file "$RUNDIR/shim.pid" "$ID" \
        /.kronik/bin/uds-shim --listen-unix /.kronik/sock/http.sock --connect 127.0.0.1:8080 \
        >>"$LOGS/$ID-shim.log" 2>&1 </dev/null
}

# Starts the sandbox (detached) and the bridge for $BRIDGE.
start_sandbox() {
    case "$BRIDGE" in
        pf) start_pf ;;
        uds) start_uds && start_shim ;;
    esac
}

# runsc port-forward in local mode: one long-lived process listening on $PF_PORT.
start_pf_local() {
    nohup runsc --root "$ROOT" port-forward "$ID" "$PF_PORT:8080" >>"$LOGS/pf.log" 2>&1 </dev/null &
}

sandbox_pid() { rs state "$ID" | jq -r .pid; }

ms_since() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }

# Set by start_foreground and start_waiter: the background job to wait for.
FG_PID=""
WAITER_PID=""

wait_running() {
    for _ in $(seq 100); do
        [ "$(rs state "$ID" 2>/dev/null | jq -r .status)" = running ] && return 0
        sleep 0.05
    done
    return 1
}

# `runsc wait` in the background; its output lands in $RUNDIR/wait.json.
start_waiter() {
    rm -f "$RUNDIR/wait.json"
    (timeout 30 runsc --root "$ROOT" wait "$ID" >"$RUNDIR/wait.json" 2>&1; echo "runsc wait exit status $?" >>"$RUNDIR/wait.json") &
    WAITER_PID=$!
}

# runsc run without --detach, as a child of this shell; prints its exit status.
start_foreground() {
    if [ "$BRIDGE" = pf ]; then make_netns; fi
    (
        # shellcheck disable=SC2046
        timeout 60 runsc --root "$ROOT" $(runsc_flags) run --bundle "$(bundle)" "$ID" \
            >>"$LOGS/$ID.log" 2>&1 </dev/null
        echo "runsc run exited with status $?"
    ) &
    FG_PID=$!
    wait_running && echo "container running"
}
