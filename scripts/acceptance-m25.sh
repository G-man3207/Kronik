#!/usr/bin/env bash
# M25 acceptance at the test VPS's sizes (docs/design/m25-streaming-bodies.md
# §17): a 300 MB upload, a 40 MB fetch replayed by a fork, and a 1 GB
# response, through a real `kronik serve`, each with the daemon's peak RSS
# growth over a warm-up request. Prints the peaks for docs/perf.md.
#
#   scripts/acceptance-m25.sh             the VPS sizes (KRONIK_M25_FULL=1)
#   scripts/acceptance-m25.sh --ci        CI's sizes (as `cargo test` runs them)
#   scripts/acceptance-m25.sh --confine   on two CPUs and at most 4 GiB
#                                         (systemd-run --scope), like the VPS
#
# It builds the tests in release mode first. The data goes to a temporary
# directory under TMPDIR: the VPS sizes need about 3 GB free there. The
# client runs in the same scope as the daemon; memory, not throughput, is
# what the run checks.
#
# On a machine without the toolchain, run the test binary itself (built
# with `cargo zigbuild test --release --target x86_64-unknown-linux-musl
# -p kronik --test blobs_streaming --no-run`) with KRONIK_M25_FULL=1,
# KRONIK_M25_KRONIK (a static `kronik`) and KRONIK_M25_MEDIA
# (tests/guests/media.wasm), and `--test-threads 1 --nocapture`.
set -euo pipefail
cd "$(dirname "$0")/.."

full=1
confine=0
for arg in "$@"; do
    case "$arg" in
        --ci) full=0 ;;
        --confine) confine=1 ;;
        *)
            echo "usage: $0 [--ci] [--confine]" >&2
            exit 2
            ;;
    esac
done

if [ "$full" = 1 ]; then
    export KRONIK_M25_FULL=1
fi

echo "==> building the acceptance tests (release)"
cargo test --locked --release -p kronik --test blobs_streaming --no-run

run=(cargo test --locked --release -p kronik --test blobs_streaming --
    --test-threads 1 --nocapture)
if [ "$confine" = 1 ]; then
    run=(systemd-run --scope --quiet -p AllowedCPUs=0-1 -p MemoryMax=4G -- "${run[@]}")
fi

log="${TMPDIR:-/tmp}/acceptance-m25.$$.log"
echo "==> running (log: $log)"
status=0
"${run[@]}" 2>&1 | tee "$log" || status=$?

echo
echo "==> peak RSS growth over the warm-up request (M25 §17):"
grep '^M25 ' "$log" || true
grep -E '^test result' "$log" || true
exit "$status"
