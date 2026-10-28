#!/usr/bin/env bash
# Records the edge cases behind ADR 0003's choice: what port-forward needs,
# which --host-uds mode the shim needs, passing a listening socket in,
# checkpointing with each bridge, and where writes inside the sandbox go.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 13-alternatives
stop_all
CK=$DATA/ckpt
rm -rf "$CK"

# One connection through runsc port-forward --stream; prints the response
# status line or runsc's error.
stream_once() {
    python3 - "$ROOT" "$ID" <<'PY'
import os, socket, subprocess, sys
root, cid = sys.argv[1], sys.argv[2]
path = f"/tmp/kronik-stream-{os.getpid()}.sock"
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen(1)
srv.settimeout(5)
p = subprocess.Popen(["runsc", "--root", root, "port-forward", "--stream", path, cid, "8080"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
try:
    conn, _ = srv.accept()
    conn.settimeout(5)
    conn.sendall(b"GET /healthz HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
    data = conn.recv(4096)
    print("response:", data.split(b"\r\n")[0].decode() if data else "(connection closed without a response)")
except OSError as e:
    print("no connection:", e)
p.wait(timeout=10)
err = p.stderr.read().strip()
print(f"runsc port-forward --stream exit {p.returncode}{': ' + err if err else ''}")
os.unlink(path)
PY
}

section "port-forward with --network=none"
rs --platform=systrap --network=none --debug --debug-log="$LOGS/debug-none/" \
    run --detach --bundle "$BUNDLE" "$ID" >>"$LOGS/$ID.log" 2>&1 </dev/null
stream_once
grep -h "PortForward failed" "$LOGS"/debug-none/*boot* | tail -1 | sed 's/.*err: /sandbox log: /'
stop_all
rm -rf "$LOGS/debug-none"

section "port-forward with --network=sandbox in a namespace that runsc creates (lo down)"
rs --platform=systrap --network=sandbox --debug --debug-log="$LOGS/debug-sandbox/" \
    run --detach --bundle "$BUNDLE" "$ID" >>"$LOGS/$ID.log" 2>&1 </dev/null
nsenter -t "$(sandbox_pid)" -n ip -br link
stream_once
grep -h "PortForward failed" "$LOGS"/debug-sandbox/*boot* | tail -1 | sed 's/.*err: /sandbox log: /'
stop_all
rm -rf "$LOGS/debug-sandbox"

section "port-forward with --network=sandbox in a namespace with lo up (chosen)"
start_pf
stream_once
stop_all

section "--host-uds modes: where the shim's socket ends up"
for mode in none open create; do
    rs --platform=systrap --network=none --host-uds="$mode" \
        run --detach --bundle "$BUNDLE" "$ID" >>"$LOGS/$ID.log" 2>&1 </dev/null
    start_shim
    sleep 0.5
    echo "--host-uds=$mode: host sees [$(ls "$SOCKDIR" | tr '\n' ' ')], $("$BIN/bridge-bench" get --target "unix:$SOCKDIR/http.sock" --path /healthz 2>&1 | head -1)"
    stop_all
done

section "The shim as the image's user (65534) cannot bind in the 0700 socket directory"
start_uds
rs exec "$ID" /.kronik/bin/uds-shim --listen-unix /.kronik/sock/http.sock --connect 127.0.0.1:8080 </dev/null 2>&1 | head -1
stop_all

section "Passing a listening host socket into the sandbox (runsc exec --pass-fd)"
rs --platform=systrap --network=none run --detach --bundle "$BUNDLE" "$ID" >>"$LOGS/$ID.log" 2>&1 </dev/null
python3 - "$ROOT" "$ID" "$RUNDIR/passfd.sock" "$LOGS/passfd.log" <<'PY'
import os, socket, subprocess, sys, time
root, cid, path, log = sys.argv[1:]
if os.path.exists(path):
    os.unlink(path)
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen(8)
fd = srv.fileno()
with open(log, "w") as out:
    subprocess.run(["runsc", "--root", root, "exec", "--detach", "--user", "0:0", "--pass-fd", f"{fd}:3", cid,
                    "/.kronik/bin/uds-shim", "--listen-fd", "3", "--connect", "127.0.0.1:8080"],
                   pass_fds=[fd], stdout=subprocess.DEVNULL, stderr=out, stdin=subprocess.DEVNULL, check=True)
srv.close()
time.sleep(0.5)
print("shim:", " | ".join(l.strip() for l in open(log) if l.strip()))
os.unlink(path)
PY
stop_all

section "Checkpoint with the shim's bound host socket (--host-uds=create)"
start_uds
start_shim
ready "unix:$SOCKDIR/http.sock" >/dev/null
timeout 60 runsc --root "$ROOT" checkpoint --image-path="$CK/uds" "$ID" 2>&1 | grep -E "checkpoint failed|Cannot save" | head -1
echo "exit ${PIPESTATUS[0]}; container afterwards: $(rs state "$ID" | jq -c '{status}')"
stop_all

section "Checkpoint after serving port-forward connections (chosen)"
start_pf
stream_once
timeout 60 runsc --root "$ROOT" checkpoint --image-path="$CK/pf" "$ID" 2>&1 | tail -1
echo "exit ${PIPESTATUS[0]}; image files: $(ls "$CK/pf" | tr '\n' ' ')"
stop_all
rm -rf "$CK"

section "Writes inside the sandbox: rootfs overlay (--overlay2 root:self by default) versus the data bind mount"
start_pf
rs exec --user 0:0 "$ID" /bin/busybox sh -c 'echo inside > /srv/written-inside.txt && echo inside > /data/written-inside.txt' </dev/null
echo "rootfs on the host: srv/written-inside.txt $(test -e "$BUNDLE_PF/rootfs/srv/written-inside.txt" && echo present || echo absent)"
echo "data dir on the host: written-inside.txt $(test -e "$DATADIR/written-inside.txt" && echo present || echo absent)"
echo "files runsc added to the rootfs directory: $(find "$BUNDLE_PF/rootfs" -maxdepth 1 -newer "$BUNDLE_PF/config.json" | tr '\n' ' ')"
stop_all
rm -f "$DATADIR/written-inside.txt"
