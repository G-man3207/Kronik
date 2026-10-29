#!/usr/bin/env bash
# Spike M22 (ADR 0070): builds the ComponentizeJS guest and the harness, then
# runs every mode RUNS times (default 100) and writes the transcripts to
# results/run.txt. Exits non-zero when a driven mode gives more than one
# transcript. Needs Node.js (the TypeScript SDK's toolchain) and cargo.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
./build-guest.sh
cargo build --release --offline
mkdir -p results
"${CARGO_TARGET_DIR:-target}/release/spike-m22-wasi-http" guest/spike.wasm | tee results/run.txt
