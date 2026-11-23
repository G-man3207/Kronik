#!/usr/bin/env bash
# Builds the Python or Go example actors (M15) with `kronik build` into
# examples/dist/, for the language the argument names (py|go):
#
#   counter-<lang>.wasm, notes-<lang>.wasm     twins of counter-ts and
#                                              notes-ts, for M1_GUESTS=py|go
#   counter-<lang>-step2.wasm                  counter adding 2, for the M3
#                                              demo (COUNTER_NEW)
#   webhook-relay-<lang>.wasm                  twin of webhook-relay-ts
#                                              (RELAY=, KRONIK_DST_RELAY=)
#
# The pinned toolchain comes from scripts/install-sdk-tools.sh --only
# python|go ($KRONIK_SDK_TOOLS). kronik build compiles each example,
# composes the WASI deny adapter, checks its imports against the allowlist
# and keeps the previous component if its inputs are unchanged (ADR 0030).
#
# Usage: [KRONIK_BIN=path] scripts/build-examples-py-go.sh py|go
# KRONIK_BIN defaults to $CARGO_TARGET_DIR/release/kronik, or
# target/release/kronik (cargo build --release -p kronik).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

case "${1:-}" in
    py) entry=step2 ;;
    go) entry=./step2 ;;
    *) echo 'usage: scripts/build-examples-py-go.sh py|go' >&2; exit 2 ;;
esac

bin="${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}"
mkdir -p examples/dist
for example in "counter-$1" "notes-$1" "webhook-relay-$1"; do
    "$bin" build --dir "examples/$example"
    cp "examples/$example/dist/$example.wasm" "examples/dist/$example.wasm"
done
"$bin" build --dir "examples/counter-$1" --entry "$entry"
cp "examples/counter-$1/dist/counter-$1-step2.wasm" "examples/dist/counter-$1-step2.wasm"
ls -l examples/dist/*-"$1"*.wasm
