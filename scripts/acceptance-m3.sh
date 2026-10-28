#!/usr/bin/env bash
# M3 acceptance (brief: fork, replay and behavior diff), in one run:
#   1. the replay and proposal tests, including identity replay of 10 000
#      recorded requests (release, the ignored test included);
#   2. the M3 API endpoints (forks, replay, diffs, proposals, approval,
#      promote, rollback and policy) against a real node;
#   3. demo/verify-change.sh end to end with the release binary;
#   4. the replay speed of the reference counter workload
#      (crates/kronik-fork/examples/replay_speed.rs, 200 req/s).
# Usage: scripts/acceptance-m3.sh [REQUESTS for step 4, default 12000]
# Needs a Rust toolchain (it builds in release), curl and python3, and the
# example actors (scripts/build-examples.sh) for step 3.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
requests="${1:-12000}"

echo "== 1. replay and proposal tests (release, with the 10 000-request identity replay)"
cargo test --locked --release -p kronik-fork -- --include-ignored

echo "== 2. the M3 API endpoints (kronik-api)"
cargo test --locked --release -p kronik-api --test api

echo "== 3. demo/verify-change.sh"
cargo build --locked --release -p kronik
demo/verify-change.sh

echo "== 4. replay speed (reference counter workload, 200 req/s)"
cargo run --locked --release -p kronik-fork --example replay_speed -- \
    --requests "$requests" --rate 200

echo "PASS: M3 acceptance"
