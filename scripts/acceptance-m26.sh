#!/usr/bin/env bash
# M26 acceptance with a real `kronik serve` (docs/design/m26-blobs.md §17):
# the crash tests of criteria 3, 4, 8 and 9 (`kill -9` at the hidden
# `--test-hold` points: crates/kronik/tests/blobs_kill.rs) and the window
# and restore tests of criteria 6 and 13 (crates/kronik/tests/blobs.rs),
# built in release mode and run one at a time.
#
#   scripts/acceptance-m26.sh
#
# On the test VPS, without the toolchain: build the two test binaries with
# `cargo zigbuild test --release --target x86_64-unknown-linux-musl -p kronik
# --test blobs_kill --test blobs --no-run`, copy them there with a static
# `kronik` and tests/guests/media.wasm, and run each with
# KRONIK_M26_KRONIK=<kronik> KRONIK_M26_MEDIA=<media.wasm> and
# `--test-threads 1`. The tests need a few hundred MB under TMPDIR; the
# window tests take about four minutes (their timers are due 90 and 120 s
# after they are scheduled, longer than the window takes to pass on a
# loaded machine).
#
# The in-process tests of the other criteria run in CI (`scripts/ci.sh
# test`); criterion 13 against S3 runs in kronik-ship's tests with
# KRONIK_TEST_S3_URL (scripts/s3.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$#" -ne 0 ]; then
    echo "usage: $0" >&2
    exit 2
fi

echo "==> building the acceptance tests (release)"
cargo test --locked --release -p kronik --test blobs_kill --test blobs --no-run

status=0
for test in blobs_kill blobs; do
    echo "==> $test"
    cargo test --locked --release -p kronik --test "$test" -- --test-threads 1 || status=$?
done
exit "$status"
