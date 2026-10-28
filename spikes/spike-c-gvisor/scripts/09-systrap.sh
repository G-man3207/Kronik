#!/usr/bin/env bash
# The systrap platform under the --cpu 1 quota: CPU used by an idle
# sandbox, and bridge latency with and without the systrap fast path
# (which spins host threads to cut syscall latency).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 09-systrap
stop_all

idle_cpu() {
    local u0 u1
    u0=$(awk '/^usage_usec/ {print $2}' "$CGROUP/cpu.stat")
    sleep 5
    u1=$(awk '/^usage_usec/ {print $2}' "$CGROUP/cpu.stat")
    echo "idle sandbox used $(( (u1 - u0) / 1000 )) ms of CPU in 5000 ms"
}

for flags in "" "--systrap-disable-fast-path"; do
    section "runsc flags: ${flags:-(defaults)}"
    # shellcheck disable=SC2034 # read by start_sandbox in lib.sh
    read -r -a RUNSC_EXTRA <<<"$flags"
    start_sandbox
    ready "$(target)" >/dev/null
    idle_cpu
    for mode in keepalive newconn; do
        throttling
        "$BIN/bridge-bench" bench --target "$(target)" --mode "$mode" \
            --requests 1000 --warmup 100 --label "$BRIDGE${flags:+-nofastpath}"
    done
    throttling
    stop_all
done
