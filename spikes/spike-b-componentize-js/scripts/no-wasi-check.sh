#!/usr/bin/env bash
# For comparison only: builds src/actor.ts with every ComponentizeJS feature
# disabled (`--disable all`), lists what it imports and runs a few turns, to
# see what happens to Math.random, crypto and Date without wasi:random and
# wasi:clocks. The component stays in a scratch directory.
# Output: results/no-wasi.txt
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record no-wasi

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
spike_wit >"$scratch/kronik-actor.wit"
wasm=$scratch/actor-no-wasi.wasm
section "jco componentize src/actor.ts --disable all"
npx jco componentize src/actor.ts --wit "$scratch/kronik-actor.wit" --world-name actor \
    --disable all -o "$wasm" 2>&1 | grep -E '^OK' | sed "s|$scratch|<scratch>|g"
echo "$(stat -c %s "$wasm") bytes"
wasm-tools component wit "$wasm" | grep -E '^ *import ' | grep -v 'kronik:actor/' | sed 's/^ *//'
"$HARNESS" imports "$wasm" | grep -E '^(imports|allowlist)'

for msg in noop counter probe; do
    section "handle --msg $msg"
    "$HARNESS" handle "$wasm" --cache "$CACHE" --msg "$msg" | grep -E '^(outcome|fuel)' | cut -c1-240
done
