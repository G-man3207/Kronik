#!/usr/bin/env bash
# Kronik's crash test (brief: Test strategy; Definition of done: 1,000 cycles
# without violations): kill -9 in a loop under load on a real disk, with the
# invariants checked after every restart. scripts/chaos.py has the details:
# what each cycle does and which invariants it checks.
#
# Usage: [KRONIK_BIN=path] scripts/chaos.sh [CYCLES] [WORKDIR] [chaos.py options]
# Defaults: 1000 cycles in /var/tmp/kronik-chaos (a real disk, not tmpfs),
# KRONIK_BIN $CARGO_TARGET_DIR/release/kronik or target/release/kronik. The
# test guests come from tests/guests. Needs python3. Prints a line per cycle
# and a JSON summary; exits non-zero on the first violation, keeping the
# work directory for inspection.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

bin="$(realpath "${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}")"
cycles="${1:-1000}"
dir="${2:-/var/tmp/kronik-chaos}"
exec python3 scripts/chaos.py --bin "$bin" --dir "$dir" --cycles "$cycles" "${@:3}"
