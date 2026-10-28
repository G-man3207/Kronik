#!/usr/bin/env bash
# Supervision: how the host learns that the sandboxed process exited or the
# sandbox died, what a dead uds-shim looks like, and clean teardown.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 08-supervise
stop_all

section "1. Foreground: runsc run blocks and exits with the container's exit status"
echo "--- 1a. the app exits with status 3"
start_foreground
timeout 20 runsc --root "$ROOT" exec "$ID" /bin/busybox wget -qO- "http://127.0.0.1:8080/exit?code=3" </dev/null
wait "$FG_PID"
stop_all
echo "--- 1b. runsc kill KILL"
start_foreground
rs kill "$ID" KILL
wait "$FG_PID"
stop_all
echo "--- 1c. the sandbox process is killed on the host (kill -9)"
start_foreground
kill -9 "$(sandbox_pid)"
wait "$FG_PID"
stop_all

section "2. Detached: the app exits with status 42; what runsc wait and runsc state report"
start_sandbox
ready "$(target)" >/dev/null
start_waiter
get "/exit?code=42" | head -1
wait "$WAITER_PID"
cat "$RUNDIR/wait.json"
echo "runsc state: $(rs state "$ID" | jq -c '{status, pid}')"
echo "container output (what kronik foreign logs would show):"
cat "$LOGS/$ID.log"
stop_all

section "3. Detached: runsc kill (Kronik stopping the actor), observed through runsc wait and runsc state"
start_sandbox
wait_running
start_waiter
show rs kill "$ID" KILL
wait "$WAITER_PID"
cat "$RUNDIR/wait.json"
echo "runsc state: $(rs state "$ID" | jq -c '{status, pid}')"
stop_all

section "4. Detached: the sandbox process is killed on the host (kill -9)"
start_sandbox
ready "$(target)" >/dev/null
start_waiter
show kill -9 "$(sandbox_pid)"
wait "$WAITER_PID"
cat "$RUNDIR/wait.json"
echo "runsc state: $(rs state "$ID" 2>&1 | jq -c '{status, pid}' 2>/dev/null)"
get /healthz 2>&1 | head -1
stop_all

section "5. Stats for monitoring: runsc events --stats"
start_sandbox
wait_running
rs events --stats "$ID" | jq -c '{type, id, cpu_total_ns: .data.cpu.usage.total, memory_usage: .data.memory.usage.usage, pids: .data.pids.current}'
stop_all

section "6. Only with the uds bridge: the shim (a runsc exec child) dies"
BRIDGE=uds start_uds
(
    timeout 120 runsc --root "$ROOT" exec --user 0:0 "$ID" \
        /.kronik/bin/uds-shim --listen-unix /.kronik/sock/http.sock --connect 127.0.0.1:8080 \
        >>"$LOGS/$ID-shim.log" 2>&1 </dev/null
    echo "the shim's runsc exec exited with status $?"
) &
shim_child=$!
ready "unix:$SOCKDIR/http.sock" >/dev/null
rs ps "$ID"
show rs kill --pid "$(rs ps "$ID" | awk '/uds-shim/ {print $2}')" "$ID" KILL
wait "$shim_child"
echo "the socket file is still there, but nobody accepts on it any more:"
ls -l "$SOCKDIR"
t0=$(date +%s%N)
BRIDGE=uds get /healthz 2>&1 | head -1
echo "(request failed after $(ms_since "$t0") ms, by the client's 10 s timeout)"
echo "remedy: remove the stale socket file, then exec the shim again"
rm -f "$SOCKDIR/http.sock"
start_shim
ready "unix:$SOCKDIR/http.sock"
BRIDGE=uds get /healthz | head -1
stop_all

section "7. Teardown of the $BRIDGE configuration"
start_sandbox
ready "$(target)" >/dev/null
echo "network namespaces: $(ip netns list | tr '\n' ' ')"
show rs delete --force "$ID"
show rs list
echo "state dir $ROOT: $(ls -A "$ROOT" | tr '\n' ' ')"
test -d "$CGROUP" && echo "cgroup $CGROUP still exists" || echo "cgroup $CGROUP removed"
echo "network namespaces after runsc delete: $(ip netns list | tr '\n' ' ')"
show ip netns del "$NETNS"
pgrep -af "^runsc" || echo "no runsc processes left"
stop_all
