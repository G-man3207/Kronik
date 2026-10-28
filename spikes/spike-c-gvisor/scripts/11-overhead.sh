#!/usr/bin/env bash
# Host memory overhead: an idle sandbox with the echo server and the shim,
# and one open `runsc port-forward --stream` connection (its helper process).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 11-overhead
stop_all

rss_mib() { ps -o rss= -p "$1" | awk '{printf "%.1f", $1 / 1024}'; }

section "Idle sandbox with the echo server ($(runsc_flags))"
start_sandbox
ready "$(target)" >/dev/null
sleep 1
echo "cgroup memory.current: $(( $(cat "$CGROUP/memory.current") / 1048576 )) MiB"
total=0
while read -r p; do
    r=$(ps -o rss= -p "$p")
    total=$(( total + r ))
    echo "  pid $p $(ps -o comm= -p "$p"): $(rss_mib "$p") MiB RSS"
done <"$CGROUP/cgroup.procs"
echo "sum of RSS (shared pages counted per process): $(( total / 1024 )) MiB"
for p in $(pgrep -f "^runsc-gofer.*$ID"); do echo "gofer pid $p: $(rss_mib "$p") MiB RSS"; done
stop_all

section "One open runsc port-forward --stream connection"
BRIDGE=pf start_sandbox
ready "pfstream:$ROOT:$ID:8080" >/dev/null
python3 - "$ROOT" "$ID" <<'PY'
import os, socket, subprocess, sys, time
root, cid = sys.argv[1], sys.argv[2]
path = f"/tmp/kronik-pf-overhead-{os.getpid()}.sock"
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen(1)
p = subprocess.Popen(["runsc", "--root", root, "port-forward", "--stream", path, cid, "8080"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
conn, _ = srv.accept()
status = open(f"/proc/{p.pid}/status").read()
rss = status.split("VmRSS:")[1].split()[0] if "VmRSS:" in status else None
print(f"helper right after connecting: {'running, ' + str(int(rss) // 1024) + ' MiB RSS' if rss else 'already exited'}")
time.sleep(1)
print(f"helper 1 s later, connection still open: {'running' if p.poll() is None else f'exited with status {p.returncode}'}")
conn.sendall(b"GET /healthz HTTP/1.1\r\nhost: x\r\n\r\n")
print("request on the kept-alive connection after that:", conn.recv(4096).split(b"\r\n")[0].decode())
conn.close()
p.wait(timeout=10)
os.unlink(path)
PY
stop_all
