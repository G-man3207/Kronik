#!/usr/bin/env bash
# Throughput and latency of committed counter turns (docs/perf.md).
#
# Usage: scripts/perf-m1.sh [WORKDIR] [PORT] [SECONDS]
# Defaults: /var/tmp/kronik-perf (a real disk, not tmpfs), port 47813, 10 s
# per measurement. Needs a release build of kronik and of tools/loadgen
# (cargo build --release --manifest-path tools/loadgen/Cargo.toml).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

dir="${1:-/var/tmp/kronik-perf}"
port="${2:-47813}"
secs="${3:-10}"
bin=target/release/kronik
load="${LOADGEN:-tools/loadgen/target/release/kronik-loadgen}"
sock="$dir/api.sock"
pid=""

rm -rf "$dir"
mkdir -p "$dir"
setsid "$bin" serve --data-dir "$dir/data" --http-listen "127.0.0.1:$port" \
    --api-socket "$sock" >>"$dir/serve.log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null' EXIT
for _ in $(seq 1 200); do
    curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null 2>&1 && break
    sleep 0.05
done
python3 -c "import base64,json; print(json.dumps({'wasm_base64': base64.b64encode(open('tests/guests/counter.wasm','rb').read()).decode(), 'reason': 'perf'}))" >"$dir/deploy.json"
curl -sf --unix-socket "$sock" -X POST -d @"$dir/deploy.json" http://kronik/v1/deployments >/dev/null

echo "# $(uname -n) $(nproc) vCPU, load average $(cut -d' ' -f1-3 /proc/loadavg)"
run() { # run <label> <loadgen args...>
    local label="$1"
    shift
    printf '%-28s %s\n' "$label" "$("$load" --addr "127.0.0.1:$port" --seconds "$secs" --warmup 2 "$@")"
}
run "1 actor, 1 client" --keys 1 --concurrency 1
run "1 actor, 16 clients" --keys 1 --concurrency 16
run "64 actors, 64 clients" --keys 64 --concurrency 64
run "256 actors, 256 clients" --keys 256 --concurrency 256
run "256 actors, 200 req/s" --keys 256 --concurrency 32 --rate 200
echo "# load average after: $(cut -d' ' -f1-3 /proc/loadavg)"
