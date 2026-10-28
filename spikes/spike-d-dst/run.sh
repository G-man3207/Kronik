#!/usr/bin/env sh
# Spike D: build the guest and the simulator, then run the checks behind
# docs/adr/0004-deterministic-simulation.md.
#
# Usage: spikes/spike-d-dst/run.sh [quick|full|madsim]   (default: quick)
#   quick  : determinism, 200 seeds, the custom-harness test, real mode
#   full   : quick + 1000 seeds, the mutation suite and the 1M-step run
#   madsim : the same scenario on madsim (separate --cfg madsim build)
set -eu
cd "$(dirname "$0")"
what="${1:-quick}"

(cd guest && cargo build --release --target wasm32-wasip2)

if [ "$what" = madsim ]; then
  RUSTFLAGS="--cfg madsim" cargo build --release --target-dir target/madsim
  target/madsim/release/spike-d-dst madsim-seeds 0..100
  target/madsim/release/spike-d-dst exec-bench
  exit 0
fi

cargo build --release
bin=target/release/spike-d-dst
"$bin" determinism 0..20
"$bin" seeds 0..200 -j 8 | tail -1
cargo test --release --test dst -- --seed 12345
"$bin" real
"$bin" exec-bench
if [ "$what" = full ]; then
  "$bin" seeds 0..1000 -j 8 | tail -1
  "$bin" mutants 0..100 -j 8
  "$bin" long --requests 5000
fi
