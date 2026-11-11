#!/usr/bin/env bash
# M10 criterion 2: a replay held for at least 30 minutes survives the CLI
# that started it, and `kronik proposal wait` stays attached for the hold.
#
# Runs the existing test
# `a_proposal_outlives_its_client_and_wait_shows_progress` with
# `KRONIK_TEST_HOLD_SECS=1800`. The test starts `proposal wait` before the
# hold and fails if the job is reaped, a token expires, or `proposal wait`
# gives up before the hold ends. Expect a little over 30 minutes, plus the
# time to build the test.
#
# Not a `scripts/ci.sh` step, and not started by a push or a schedule.
#
# Usage: scripts/acceptance-m10-hold.sh
#
# Equivalent:
#   KRONIK_TEST_HOLD_SECS=1800 cargo test --locked -p kronik --test remote \
#       a_proposal_outlives_its_client_and_wait_shows_progress -- --exact
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# rustup may be installed without being added to PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
    # shellcheck source=/dev/null
    . "${CARGO_HOME:-$HOME/.cargo}/env"
fi

# The documented hold. Do not inherit a shorter value from the environment.
export KRONIK_TEST_HOLD_SECS=1800
export CARGO_TERM_COLOR=never

echo "== M10 criterion 2: replay held for ${KRONIK_TEST_HOLD_SECS}s with proposal wait attached"
output="$(mktemp)"
trap 'rm -f "$output"' EXIT
cargo test --locked -p kronik --test remote \
    a_proposal_outlives_its_client_and_wait_shows_progress -- \
    --exact | tee "$output"
grep -q 'test result: ok. 1 passed' "$output"

echo "PASS: M10 30-minute hold"
