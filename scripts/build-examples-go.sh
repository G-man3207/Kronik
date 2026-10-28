#!/usr/bin/env bash
# Builds the Go example actors (M15) with `kronik build` into examples/dist/:
#
#   counter-go.wasm, notes-go.wasm     twins of counter-ts and notes-ts,
#                                          for M1_GUESTS=go
#   counter-go-step2.wasm               counter-go adding 2, for the M3
#                                          demo (COUNTER_NEW)
#   webhook-relay-go.wasm               twin of webhook-relay-ts (RELAY=,
#                                          KRONIK_DST_RELAY=)
#
# The pinned toolchain comes from scripts/install-sdk-tools.sh --only go
# ($KRONIK_SDK_TOOLS). kronik build compiles each example, composes the
# WASI deny adapter, checks its imports against the allowlist and keeps the
# previous component if its inputs are unchanged (ADR 0030).
#
# Usage: [KRONIK_BIN=path] scripts/build-examples-go.sh
# KRONIK_BIN defaults to $CARGO_TARGET_DIR/release/kronik, or
# target/release/kronik (cargo build --release -p kronik).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

bin="${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}"
mkdir -p examples/dist
for example in counter-go notes-go webhook-relay-go; do
    "$bin" build --dir "examples/$example"
    cp "examples/$example/dist/$example.wasm" "examples/dist/$example.wasm"
done
"$bin" build --dir examples/counter-go --entry ./step2
cp examples/counter-go/dist/counter-go-step2.wasm examples/dist/counter-go-step2.wasm
ls -l examples/dist/*-go*.wasm
