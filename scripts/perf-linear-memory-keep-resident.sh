#!/usr/bin/env bash
# Sweep linear_memory_keep_resident on the release musl build (issue #78).
# Rebuilds kronik for each byte value, runs the 64-actor perf-m1 row, and
# prints a table. Mimalloc/jemalloc need a maintainer decision (ADR) first.
#
# Usage: scripts/perf-linear-memory-keep-resident.sh [SECONDS]
# Needs cargo, the release's zig + cargo-zigbuild for musl (scripts/install-zig.sh),
# and tools/loadgen built once (see perf-m1.sh).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

secs="${1:-10}"
tools="${CARGO_TARGET_DIR:-target}/tools"
zig_dir="$(scripts/install-zig.sh 2>/dev/null || true)"
if [ -n "${zig_dir:-}" ] && [ -d "$zig_dir" ]; then
    PATH="$zig_dir:$tools/bin:$PATH"
    export PATH
fi

cargo build --locked --release --manifest-path tools/loadgen/Cargo.toml

values=(0 262144 524288 1048576 2097152)
labels=("0" "256 KiB" "512 KiB" "1 MiB" "2 MiB (default)")

echo "# linear_memory_keep_resident sweep ($(date -u +%Y-%m-%dT%H:%M:%SZ), ${secs}s row)"
printf '%-18s %s\n' "keep resident" "64 actors, 64 clients (turns/s, p50 / p99 ms)"

for i in "${!values[@]}"; do
    bytes="${values[$i]}"
    label="${labels[$i]}"
    export KRONIK_PERF_LINEAR_MEMORY_KEEP_RESIDENT="$bytes"
    if command -v cargo-zigbuild >/dev/null 2>&1; then
        rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
        cargo zigbuild --locked --release -p kronik \
            --target x86_64-unknown-linux-musl
        bin="${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-musl/release/kronik"
    else
        cargo build --locked --release -p kronik
        bin="${CARGO_TARGET_DIR:-target}/release/kronik"
    fi
    row=$(KRONIK_BIN="$(realpath "$bin")" SECONDS="$secs" bash -c '
        set -euo pipefail
        dir=$(mktemp -d /var/tmp/kronik-keep-resident-XXXXXX)
        chmod 700 "$dir"
        port=47814
        sock="$dir/api.sock"
        bin="$KRONIK_BIN"
        load="tools/loadgen/target/release/kronik-loadgen"
        secs="${SECONDS:-10}"
        setsid "$bin" serve --data-dir "$dir/data" --http-listen "127.0.0.1:$port" \
            --api-socket "$sock" >>"$dir/serve.log" 2>&1 &
        pid=$!
        trap "kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -rf \"$dir\"" EXIT
        . scripts/lib.sh
        wait_healthy "$sock" "$dir/serve.log"
        python3 -c "import base64,json; print(json.dumps({\"wasm_base64\": base64.b64encode(open(\"tests/guests/counter.wasm\",\"rb\").read()).decode(), \"reason\": \"perf\"}))" >"$dir/deploy.json"
        curl -sf --unix-socket "$sock" -X POST -d @"$dir/deploy.json" http://kronik/v1/deployments >/dev/null
        "$load" --addr "127.0.0.1:$port" --seconds "$secs" --warmup 2 --keys 64 --concurrency 64
    ')
    printf '%-18s %s\n' "$label" "$row"
done

echo "# After each value, re-run scripts/acceptance-m24.sh load if M24 criterion 1 is in doubt (issue #78)."