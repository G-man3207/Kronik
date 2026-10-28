#!/usr/bin/env bash
# Lists the imports of every build variant with wasm-tools and checks them
# against the deploy allowlist with the spike A harness. Also records which
# WebAssembly features the components need, their tables and memories, and
# the producers metadata.
# Output: results/imports.txt
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record imports

for variant in actor actor-aot counter actor-no-http actor-default; do
    wasm=out/$variant.wasm
    section "$variant ($(stat -c %s "$wasm") bytes): $(variant_flags "$variant")"
    echo "\$ wasm-tools component wit $wasm | grep -E '^ *(import|export) '"
    wasm-tools component wit "$wasm" | grep -E '^ *(import|export) ' | sed 's/^ *//'
    echo "\$ spike-a-wasmtime imports $wasm"
    "$HARNESS" imports "$wasm" | grep -vE '^ +allowed +kronik:actor/'
    echo "(exit ${PIPESTATUS[0]})"
done

section "WebAssembly features: validation with SIMD, relaxed SIMD and threads disabled"
for variant in actor actor-aot; do
    wasm-tools validate --features=-simd,-relaxed-simd,-threads "out/$variant.wasm"
    echo "out/$variant.wasm: exit $?"
done

section "Tables and memories in out/actor.wasm (main module first)"
wasm-tools print out/actor.wasm | grep -oE '\((table|memory) \(;[0-9]+;\) [0-9]+( [0-9]+)?( funcref)?\)'

section "Producers metadata of out/actor.wasm (component, then its core modules)"
wasm-tools metadata show out/actor.wasm | grep -E '(language|processed-by) ' | tr -s ' '
