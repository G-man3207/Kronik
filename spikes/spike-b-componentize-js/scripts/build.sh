#!/usr/bin/env bash
# Builds the spike B components with the pinned toolchain from package.json,
# the way `kronik build --lang ts` would: WIT -> TypeScript declarations ->
# type check -> jco componentize (ComponentizeJS + Wizer). Also builds the
# comparison variants and checks the expected build failure.
#
# Output:
#   out/actor.wasm, out/counter.wasm          --disable http fetch-event stdio (the chosen flags)
#   out/actor-aot.wasm, out/counter-aot.wasm  the same with --aot (weval)
#   out/actor-default.wasm                    no features disabled
#   out/actor-no-http.wasm                    --disable http fetch-event
#   out/build-log.txt                         full tool output
#   results/build.txt                         step timings, the expected failure, reproducibility
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ -d node_modules ] || npm ci --no-audit --no-fund
rm -rf generated
rm -f out/*.wasm
mkdir -p generated/wit out
log=out/build-log.txt
summary=results/build.txt
: >"$log"
echo "# build on $(hostname) at $(date -u +%FT%TZ), node $(node --version), $(npx jco --version | sed 's/^/jco /'), componentize-js $(node -p "require('./node_modules/@bytecodealliance/componentize-js/package.json').version"), tsc $(npx tsc --version | cut -d' ' -f2)" | tee "$summary"

step() {
    local t0
    t0=$(date +%s%N)
    "$@" >>"$log" 2>&1
    echo "$(( ($(date +%s%N) - t0) / 1000000 )) ms  $*" | tee -a "$summary"
}

spike_wit >generated/wit/kronik-actor.wit
echo "WIT: wit/kronik-actor.wit at $WIT_REV, sha256 $(sha256sum generated/wit/kronik-actor.wit | cut -d' ' -f1)" | tee -a "$summary"
step npx jco guest-types generated/wit/kronik-actor.wit --world-name actor -o generated/types -q
step npx tsc -p tsconfig.json

wit=(--wit generated/wit/kronik-actor.wit --world-name actor)
chosen=(--disable http fetch-event stdio)
for name in actor counter; do
    step npx jco componentize "src/$name.ts" "${wit[@]}" "${chosen[@]}" -o "out/$name.wasm"
    step npx jco componentize "src/$name.ts" "${wit[@]}" "${chosen[@]}" --aot -o "out/$name-aot.wasm"
done
step npx jco componentize src/actor.ts "${wit[@]}" -o out/actor-default.wasm
step npx jco componentize src/actor.ts "${wit[@]}" --disable http fetch-event -o out/actor-no-http.wasm

# Math.random() in module scope runs during Wizer pre-initialization and must
# fail the build instead of baking a seed into the snapshot.
if npx jco componentize src/build-time-random.ts "${wit[@]}" "${chosen[@]}" \
    -o out/build-time-random.wasm >out/build-time-random.err 2>&1; then
    echo "UNEXPECTED: src/build-time-random.ts built" | tee -a "$summary"
    exit 1
fi
echo "expected failure for src/build-time-random.ts: $(grep -o "attempted to call an unknown imported function: '[^']*' '[^']*'" out/build-time-random.err)" | tee -a "$summary"

# Is the build reproducible? src/counter.ts reads no clock or randomness in
# module scope, so two builds should match byte for byte if Wizer's snapshot
# is deterministic.
step npx jco componentize src/counter.ts "${wit[@]}" "${chosen[@]}" -o out/counter-rebuild.wasm
if cmp -s out/counter.wasm out/counter-rebuild.wasm; then
    echo "reproducible: two builds of src/counter.ts are byte-identical" | tee -a "$summary"
else
    echo "NOT reproducible: two builds of src/counter.ts differ in $(cmp -l out/counter.wasm out/counter-rebuild.wasm 2>/dev/null | wc -l) bytes (sizes $(stat -c %s out/counter.wasm) and $(stat -c %s out/counter-rebuild.wasm))" | tee -a "$summary"
fi

(cd out && stat -c '%s bytes  out/%n' actor.wasm actor-aot.wasm actor-default.wasm actor-no-http.wasm \
    counter.wasm counter-aot.wasm counter-rebuild.wasm) | tee -a "$summary"
