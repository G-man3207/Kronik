#!/usr/bin/env bash
# Copies the built components, the spike A harness (stripped), the patched
# harness copy and wasm-tools to the test host, runs experiments there and
# fetches the results.
#
# Usage: scripts/deploy.sh [HOST [STEP...]]
#   HOST  default travelfiesta
#   STEP  determinism, bench, reuse, keep-resident (default: all four)
# Needs scripts/build.sh and scripts/build-harness.sh to have run locally.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

host=${1:-travelfiesta}
shift || true
steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(determinism bench reuse keep-resident)
dest=/root/kronik-spike-b

strip -o out/spike-a-wasmtime "$HARNESS"
strip -o out/spike-a-wasmtime-experiments "$EXPERIMENT_HARNESS"
ssh "$host" "mkdir -p $dest/bin $dest/out"
rsync -a out/spike-a-wasmtime out/spike-a-wasmtime-experiments "$(command -v wasm-tools)" "$host:$dest/bin/"
rsync -a out/actor.wasm out/actor-aot.wasm out/counter.wasm out/counter-aot.wasm out/counter-rebuild.wasm "$host:$dest/out/"
rsync -a --delete scripts "$host:$dest/"

env="cd $dest && export PATH=$dest/bin:\$PATH HARNESS=$dest/bin/spike-a-wasmtime EXPERIMENT_HARNESS=$dest/bin/spike-a-wasmtime-experiments"
for step in "${steps[@]}"; do
    case "$step" in
        determinism | bench | keep-resident) script=$step ;;
        reuse) script=reuse-wasmtime ;;
        *)
            echo "unknown step $step" >&2
            exit 2
            ;;
    esac
    # shellcheck disable=SC2029 # expanded locally on purpose
    ssh "$host" "$env && bash scripts/$script.sh >/dev/null"
done
rsync -a "$host:$dest/results/" results/
ls -l results
