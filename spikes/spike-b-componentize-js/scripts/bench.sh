#!/usr/bin/env bash
# Measures the TypeScript components with the spike A harness: size, compile
# time, .cwasm deserialize time, fresh-instance instantiation and whole-turn
# latency (pooling and on-demand allocator), fuel and memory per turn.
# Output: results/bench-<host>.txt
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record "bench-$(hostname)"
ITER=${ITER:-2000}

section "Machine"
grep -m1 'model name' /proc/cpuinfo
echo "cpus $(nproc), load $(cut -d' ' -f1-3 /proc/loadavg)"

section "Linear memory declared by the components (64 KiB pages)"
for variant in actor actor-aot counter; do
    echo "$variant: $(wasm-tools print "out/$variant.wasm" | grep -m3 -oE '\(memory \(;[0-9]+;\) [0-9]+( [0-9]+)?\)' | tr '\n' ' ')"
done

section "Fuel and peak memory per turn (handle, default limits)"
for spec in "actor noop" "actor counter" "actor probe" "actor json" "counter counter" "actor-aot noop" "actor-aot json" "counter-aot counter"; do
    read -r variant msg <<<"$spec"
    out=$(handle "out/$variant.wasm" --msg "$msg")
    echo "$variant/$msg: $(grep -oE '^outcome [A-Z_]+' <<<"$out"), $(grep -E '^fuel' <<<"$out"), $(grep -E '^memory' <<<"$out" | tr -s ' ')"
done

for spec in "counter counter $ITER" "actor noop $ITER" "actor json $((ITER / 2))" "counter-aot counter $ITER" "actor-aot json $((ITER / 2))"; do
    read -r variant msg n <<<"$spec"
    section "bench out/$variant.wasm --msg $msg --iterations $n"
    "$HARNESS" bench "out/$variant.wasm" --msg "$msg" --iterations "$n" | grep -v '^engine'
done
