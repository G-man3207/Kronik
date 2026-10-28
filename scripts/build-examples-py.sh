#!/usr/bin/env bash
# Builds the Python example actors (M15) with `kronik build` into examples/dist/:
#
#   counter-py.wasm, notes-py.wasm     twins of counter-ts and notes-ts,
#                                          for M1_GUESTS=py
#   counter-py-step2.wasm               counter-py adding 2, for the M3
#                                          demo (COUNTER_NEW)
#   webhook-relay-py.wasm               twin of webhook-relay-ts (RELAY=,
#                                          KRONIK_DST_RELAY=)
#
# The pinned toolchain comes from scripts/install-sdk-tools.sh --only python
# ($KRONIK_SDK_TOOLS). kronik build compiles each example, composes the
# WASI deny adapter, checks its imports against the allowlist and keeps the
# previous component if its inputs are unchanged (ADR 0030).
#
# Usage: [KRONIK_BIN=path] scripts/build-examples-py.sh
# KRONIK_BIN defaults to $CARGO_TARGET_DIR/release/kronik, or
# target/release/kronik (cargo build --release -p kronik).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

bin="${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}"
mkdir -p examples/dist
for example in counter-py notes-py webhook-relay-py; do
    "$bin" build --dir "examples/$example"
    cp "examples/$example/dist/$example.wasm" "examples/dist/$example.wasm"
done
"$bin" build --dir examples/counter-py --entry step2
cp examples/counter-py/dist/counter-py-step2.wasm examples/dist/counter-py-step2.wasm
ls -l examples/dist/*-py*.wasm
