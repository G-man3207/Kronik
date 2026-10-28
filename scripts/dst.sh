#!/usr/bin/env bash
# DST at the Definition of done's scale: kronik-sim's harness
# (crates/kronik-sim/tests/dst.rs) over a range of seeds, split across
# parallel processes. Each seed is still a single-threaded deterministic run,
# so the split changes nothing but the wall time.
#
# Usage: scripts/dst.sh [SEEDS] [JOBS] [harness options...]
#   SEEDS   A..B, default 0..10000
#   JOBS    processes, default the number of CPUs
#   harness options such as `--scenario webhook` or `--twice`;
#   KRONIK_DST_RELAY=<component> runs the webhook workload with another
#   relay, as in the harness. For the long run, call the harness directly:
#   cargo test --release -p kronik-sim --test dst -- --long 1000000
#
# Builds the harness in release first, prints every shard's summary and the
# total, and exits non-zero if any seed failed; each failure prints the
# command that reproduces it. The shards' output is kept in a directory under
# $TMPDIR (default /var/tmp).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# rustup may be installed without being added to PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
    # shellcheck source=/dev/null
    . "${CARGO_HOME:-$HOME/.cargo}/env"
fi

seeds="${1:-0..10000}"
jobs="${2:-$(nproc)}"
shift $(($# < 2 ? $# : 2))
start="${seeds%..*}"
end="${seeds#*..}"

harness="$(cargo test --locked --release -p kronik-sim --test dst --no-run --message-format=json |
    python3 -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m["target"]["name"] == "dst" and m.get("executable"):
        print(m["executable"])
')"
logs="$(mktemp -d "${TMPDIR:-/var/tmp}/kronik-dst.XXXXXX")"
step=$(((end - start + jobs - 1) / jobs))
SECONDS=0
pids=()
for ((i = 0; i < jobs; i++)); do
    a=$((start + i * step))
    b=$((a + step < end ? a + step : end))
    ((a < b)) || break
    "$harness" --seeds "$a..$b" "$@" >"$logs/shard-$i.log" 2>&1 &
    pids+=("$!")
done
status=0
for pid in "${pids[@]}"; do
    wait "$pid" || status=1
done
grep -h '^dst:' "$logs"/shard-*.log
if [ "$status" -ne 0 ]; then
    grep -h -B2 -A24 'violation\|nondeterminism\|ended after' "$logs"/shard-*.log | head -200 || true
fi
runs=$(cat "$logs"/shard-*.log | grep -cE '^[a-z]+ +seed ' || true)
failed=$(grep -h '^dst:' "$logs"/shard-*.log | sed -E 's/.*, ([0-9]+) failed.*/\1/' | awk '{ n += $1 } END { print n + 0 }')
echo "dst.sh: seeds $seeds in $jobs processes ($*): $runs runs, $failed failed seeds, ${SECONDS} s; logs in $logs"
exit "$status"
