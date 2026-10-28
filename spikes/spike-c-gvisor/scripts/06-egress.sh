#!/usr/bin/env bash
# Proves that the sandbox cannot reach anything outside: external IPs, DNS
# and this host's own addresses. Run with BRIDGE=pf (default) and BRIDGE=uds.
# For uds it also checks that --host-uds=create does not let the sandbox
# connect to host sockets in its bind mounts.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record "06-egress-$BRIDGE"
stop_all
echo "runsc flags: $(runsc_flags)"
start_sandbox
ready "$(target)" >/dev/null

addr() { ip -4 -o addr show "$1" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1; }
public_ip=$(ip -4 route get 1.1.1.1 | grep -o 'src [0-9.]*' | cut -d' ' -f2)
targets=("$public_ip:22")
for dev in docker0 tailscale0; do
    a=$(addr "$dev") && [ -n "$a" ] && targets+=("$a:22")
done

section "netprobe in the sandbox: external IPs, DNS, and this host's own addresses (${targets[*]})"
rs exec "$ID" /bin/netprobe "${targets[@]}" </dev/null

section "busybox in the sandbox"
for cmd in "ip addr" "ip route" "nslookup example.com 8.8.8.8" "wget -T 3 -qO- http://1.1.1.1/" "ping -c 1 -W 2 1.1.1.1"; do
    echo "\$ $cmd"
    # shellcheck disable=SC2086
    timeout 20 runsc --root "$ROOT" exec "$ID" /bin/busybox $cmd </dev/null 2>&1
    echo "(exit $?)"
done

section "Host view: the sandbox processes run in their own network namespace"
pid=$(sandbox_pid)
echo "host netns:    $(readlink /proc/1/ns/net)"
echo "sandbox netns: $(readlink "/proc/$pid/ns/net")"
nsenter -t "$pid" -n ip -br link

if [ "$BRIDGE" = uds ]; then
    section "--host-uds=create lets the sandbox create sockets, not connect to host sockets"
    python3 - "$SOCKDIR/host.sock" >"$LOGS/host-listener.log" 2>&1 <<'PY' &
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen(1)
s.settimeout(5)
try:
    s.accept()
    print("host listener: ACCEPTED a connection from the sandbox")
except socket.timeout:
    print("host listener: no connection within 5 s")
PY
    listener=$!
    sleep 0.5
    ls -l "$SOCKDIR"
    rs exec --user 0:0 "$ID" /.kronik/bin/bridge-bench get --target unix:/.kronik/sock/host.sock </dev/null
    echo "(exit $?)"
    wait "$listener"
    cat "$LOGS/host-listener.log"
fi
stop_all
