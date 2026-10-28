#!/usr/bin/env sh
# Spike E: per-actor SQL state. Builds the prototype and runs the checks and
# measurements behind docs/adr/0005-sql-state.md.
#
# Usage: spikes/spike-e-sql/run.sh [check|bench|all]   (default: check)
# bench writes to /var/tmp (a real disk, not tmpfs) and removes its files.
set -eu
cd "$(dirname "$0")"
what="${1:-check}"
cargo build --release
bin=target/release/spike-e-sql
if [ "$what" = check ] || [ "$what" = all ]; then
  "$bin" check
fi
if [ "$what" = bench ] || [ "$what" = all ]; then
  "$bin" bench --actors 10000 --dir /var/tmp/kronik-spike-e-bench
fi
