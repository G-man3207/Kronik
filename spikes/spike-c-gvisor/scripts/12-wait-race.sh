#!/usr/bin/env bash
# Repeats the exit-status scenarios N times to show which supervision path is
# reliable: `runsc run` in the foreground (Kronik's child) versus
# `runsc run --detach` plus `runsc wait`. Causes: the app exits with 3,
# `runsc kill KILL`, and kill -9 of the sandbox process on the host.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 12-wait-race
stop_all
N=${N:-10}
TALLY=$RUNDIR/wait-race.txt
: >"$TALLY"

trigger() {
    case "$1" in
        exit) timeout 20 runsc --root "$ROOT" exec "$ID" /bin/busybox wget -qO- "http://127.0.0.1:8080/exit?code=3" </dev/null >/dev/null 2>&1 ;;
        kill) rs kill "$ID" KILL ;;
        kill9) kill -9 "$(sandbox_pid)" ;;
    esac
}

foreground_status() {
    if [ "$BRIDGE" = pf ]; then make_netns; fi
    rm -f "$RUNDIR/fg-status"
    (
        # shellcheck disable=SC2046
        timeout 60 runsc --root "$ROOT" $(runsc_flags) run --bundle "$(bundle)" "$ID" \
            >>"$LOGS/$ID.log" 2>&1 </dev/null
        echo $? >"$RUNDIR/fg-status"
    ) &
    local child=$!
    wait_running
    trigger "$1"
    wait "$child"
    cat "$RUNDIR/fg-status"
}

detached_status() {
    start_sandbox
    wait_running
    start_waiter
    trigger "$1"
    wait "$WAITER_PID"
    local status
    status=$(grep -o '"exitStatus":[0-9]*' "$RUNDIR/wait.json" | cut -d: -f2)
    echo "${status:-unavailable}"
}

for i in $(seq "$N"); do
    for cause in exit kill kill9; do
        fg_status=$(foreground_status "$cause")
        stop_all
        detached=$(detached_status "$cause")
        stop_all
        echo "iter=$i cause=$cause foreground=$fg_status detached_wait=$detached" | tee -a "$TALLY"
    done
done

section "Tally over $N runs (expected: exit 3, kill 137, kill9 137)"
python3 - "$TALLY" <<'PY'
import collections, sys
rows = [dict(f.split("=", 1) for f in line.split()) for line in open(sys.argv[1])]
for cause in ["exit", "kill", "kill9"]:
    sel = [r for r in rows if r["cause"] == cause]
    fg = collections.Counter(r["foreground"] for r in sel)
    dw = collections.Counter(r["detached_wait"] for r in sel)
    print(f"{cause:<6} runsc run (foreground): {dict(fg)}   runsc run --detach + runsc wait: {dict(dw)}")
PY
