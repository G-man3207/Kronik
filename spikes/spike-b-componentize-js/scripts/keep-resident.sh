#!/usr/bin/env bash
# Does keeping pool slots resident make the fresh instance per turn cheaper
# for JavaScript components, without breaking I3? Uses the patched harness
# copy (scripts/build-harness.sh), where SPIKE_B_KEEP_RESIDENT_MIB sets
# PoolingAllocationConfig::linear_memory_keep_resident and table_keep_resident
# (0 is Wasmtime's default). The probe reports turnsSeenByThisInstance, so a
# slot that kept the previous turn's heap would show up as a changed digest.
# Output: results/keep-resident-<host>.txt
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record "keep-resident-$(hostname)"

for mib in 0 2 4 16; do
    export SPIKE_B_KEEP_RESIDENT_MIB=$mib
    section "keep resident $mib MiB: 5 fresh instances in one process"
    for msg in probe counter json; do
        out=$("$EXPERIMENT_HARNESS" handle out/actor.wasm --cache "$CACHE" --msg "$msg" --repeat 5)
        echo "$msg: $(grep -E '^fuel' <<<"$out"), digest $(grep -m1 -E '^digest' <<<"$out" | awk '{print $3}'), identical $(grep -E '^identical' <<<"$out" | awk '{print $2}')"
    done
    for spec in "actor noop" "counter counter" "actor json"; do
        read -r variant msg <<<"$spec"
        section "keep resident $mib MiB: bench out/$variant.wasm --msg $msg"
        "$EXPERIMENT_HARNESS" bench "out/$variant.wasm" --msg "$msg" --iterations 2000 | grep -A3 '^\[pooling\]'
    done
done
