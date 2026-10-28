#!/usr/bin/env bash
# Verifies --cpu 1 --memory 512Mi (plus pids 256): the cgroup runsc creates,
# what the app sees, and that CPU and memory are actually capped.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 07-limits
stop_all
start_sandbox
ready "$(target)" >/dev/null

section "cgroup that runsc created for cgroupsPath /kronik/foreign-echo"
pid=$(sandbox_pid)
echo "sandbox pid $pid: $(cat "/proc/$pid/cgroup")"
for f in cpu.max memory.max memory.swap.max pids.max; do
    echo "$f: $(cat "$CGROUP/$f")"
done
echo "host processes in the cgroup:"
while read -r p; do ps -o pid=,comm= -p "$p"; done <"$CGROUP/cgroup.procs"

section "What the app sees (GET /info through the bridge)"
get /info | grep -E 'available_parallelism|MemTotal'

burn() {
    local u0 u1 n0 n1 t0 wall
    u0=$(awk '/^usage_usec/ {print $2}' "$CGROUP/cpu.stat")
    n0=$(awk '/^nr_throttled/ {print $2}' "$CGROUP/cpu.stat")
    t0=$(date +%s%N)
    get "/burn?threads=2&ms=3000" | tail -1
    wall=$(ms_since "$t0")
    u1=$(awk '/^usage_usec/ {print $2}' "$CGROUP/cpu.stat")
    n1=$(awk '/^nr_throttled/ {print $2}' "$CGROUP/cpu.stat")
    awk -v u=$(( (u1 - u0) / 1000 )) -v w="$wall" -v n=$(( n1 - n0 )) \
        'BEGIN { printf "cgroup CPU time %d ms over %d ms wall = %.2f CPUs; throttled periods +%d\n", u, w, u / w, n }'
}

section "CPU: 2 busy threads for 3 s with cpu.max = $(cat "$CGROUP/cpu.max")"
burn
section "Control: the same with the quota lifted in place (cpu.max = max)"
echo "max 100000" >"$CGROUP/cpu.max"
burn
echo "100000 100000" >"$CGROUP/cpu.max"

section "Memory: touch 300 MiB under memory.max = $(cat "$CGROUP/memory.max")"
get "/alloc?mb=300" | tail -1
echo "memory.peak: $(( $(cat "$CGROUP/memory.peak") / 1048576 )) MiB"

section "Memory: touch 700 MiB"
(timeout 30 runsc --root "$ROOT" wait "$ID" >"$RUNDIR/wait.json" 2>&1) &
waiter=$!
get "/alloc?mb=700" 2>&1 | tail -1
wait "$waiter"
echo "runsc wait: $(cat "$RUNDIR/wait.json")"
echo "runsc state: $(rs state "$ID" | jq -c '{status, pid}')"
echo "memory.events: $(tr '\n' ' ' <"$CGROUP/memory.events" 2>/dev/null || echo '<cgroup gone>')"
echo "container output:"
cat "$LOGS/$ID.log"
dmesg 2>/dev/null | grep -iE 'oom|killed process' | tail -3
stop_all
