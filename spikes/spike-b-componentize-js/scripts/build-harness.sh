#!/usr/bin/env bash
# Builds a copy of the spike A harness with scripts/harness-experiments.patch
# applied, for experiments that Kronik itself must never do:
#   - `reuse`: calls `handle` repeatedly on one instance (scripts/reuse-wasmtime.sh);
#   - SPIKE_B_KEEP_RESIDENT_MIB: sets the pooling allocator's
#     linear_memory_keep_resident and table_keep_resident (scripts/keep-resident.sh).
# spikes/spike-a-wasmtime itself is not modified.
# Output: out/harness/experiments/target/release/spike-a-wasmtime
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# The harness generates bindings from ../../wit/kronik-actor.wit relative to
# its manifest, so the copy lives two levels below out/, next to out/wit,
# which gets the WIT the harness implements (WIT_REV).
copy=$SPIKE_B/out/harness/experiments
rm -rf "$copy/src" "$SPIKE_B/out/wit"
mkdir -p "$copy" "$SPIKE_B/out/wit"
spike_wit >"$SPIKE_B/out/wit/kronik-actor.wit"
cp -r ../spike-a-wasmtime/Cargo.toml ../spike-a-wasmtime/Cargo.lock ../spike-a-wasmtime/src "$copy/"
cd "$copy"
patch -s -p1 <"$SPIKE_B/scripts/harness-experiments.patch"
cargo build --release --locked -q
