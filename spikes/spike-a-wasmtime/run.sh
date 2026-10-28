#!/usr/bin/env sh
# Spike A: build the Rust guest and the host harness, then run the acceptance
# checks and the measurements. See docs/adr/0001-wasmtime-determinism.md.
#
# Usage: spikes/spike-a-wasmtime/run.sh [demo|bench|all]   (default: all)
#
# The harness can also run any other kronik:actor component, e.g.:
#   target/release/spike-a-wasmtime imports  <component.wasm>
#   target/release/spike-a-wasmtime describe <component.wasm>
#   target/release/spike-a-wasmtime handle   <component.wasm> --msg probe --repeat 3
#   target/release/spike-a-wasmtime handle   <component.wasm> --http "POST /x/acme" --body '{}'
set -eu
cd "$(dirname "$0")"
what="${1:-all}"

(cd guest && cargo build --release --target wasm32-wasip2)
(cd guest && cargo build --release --target wasm32-wasip2 --features fs-probe --target-dir target/fs-probe)
cargo build --release

guest=guest/target/wasm32-wasip2/release/spike_a_guest.wasm
fs_guest=guest/target/fs-probe/wasm32-wasip2/release/spike_a_guest.wasm
bin=target/release/spike-a-wasmtime

if [ "$what" = demo ] || [ "$what" = all ]; then
  "$bin" imports "$guest"
  "$bin" demo "$guest" --fs-guest "$fs_guest"
fi
if [ "$what" = bench ] || [ "$what" = all ]; then
  "$bin" bench "$guest" --iterations 5000
  "$bin" bench "$guest" --iterations 2000 --msg probe
fi
