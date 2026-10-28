#!/usr/bin/env bash
# Builds the TypeScript example actors in examples/ (an npm workspace using
# the SDK in sdk/ts) with `kronik build` into examples/dist/:
#
#   counter-ts.wasm, notes-ts.wasm         twins of counter-rs and notes-rs,
#                                          for M1_GUESTS=ts
#   counter-ts-step2.wasm                  counter-ts adding 2, for the M3
#                                          demo (COUNTER_NEW)
#   todo-ts.wasm                           to-do lists with a sweep timer
#   webhook-relay-ts.wasm                  twin of webhook-relay-rs
#   billing-ts.wasm                        invoices with VAT, charged through
#                                          payments.internal
#   billing-ts-ledger.wasm                 the ledger billing-ts calls
#   billing-ts-eu-vat.wasm                 billing-ts with EU VAT, the change
#                                          to propose (payments-must-be-exact)
#
# `npm ci` installs the pinned toolchain (jco, ComponentizeJS, TypeScript)
# first. kronik build type-checks each example, builds it, checks its imports
# against the allowlist and keeps the previous component if its inputs are
# unchanged.
#
# Usage: [KRONIK_BIN=path] scripts/build-examples-ts.sh
# KRONIK_BIN defaults to $CARGO_TARGET_DIR/release/kronik, or
# target/release/kronik (cargo build --release -p kronik).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

bin="${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}"
npm ci --prefix examples --no-audit --no-fund
mkdir -p examples/dist
for example in counter-ts notes-ts todo-ts webhook-relay-ts; do
    "$bin" build --dir "examples/$example"
    cp "examples/$example/dist/$example.wasm" "examples/dist/$example.wasm"
done
"$bin" build --dir examples/counter-ts --entry src/step2.ts
cp examples/counter-ts/dist/counter-ts-step2.wasm examples/dist/counter-ts-step2.wasm
# billing-ts's package is called billing, so its dist/ matches the brief's
# ./dist/billing.wasm.
for entry in actor ledger eu-vat; do
    "$bin" build --dir examples/billing-ts --entry "src/$entry.ts"
done
cp examples/billing-ts/dist/billing.wasm examples/dist/billing-ts.wasm
cp examples/billing-ts/dist/billing-ledger.wasm examples/dist/billing-ts-ledger.wasm
cp examples/billing-ts/dist/billing-eu-vat.wasm examples/dist/billing-ts-eu-vat.wasm
ls -l examples/dist/*-ts*.wasm
