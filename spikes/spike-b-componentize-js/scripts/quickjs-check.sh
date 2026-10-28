#!/usr/bin/env bash
# For comparison only: builds src/counter.ts with jco's QuickJS backend
# (componentize-qjs) and lists what it imports. Jco edits the WIT it is
# given, so it gets a scratch copy; the component stays in scratch too.
# Output: results/quickjs.txt
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record quickjs

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
spike_wit >"$scratch/original.wit"
wasm=$scratch/counter-qjs.wasm
for flags in "--backend-qjs-disable-async" "--backend-qjs-disable-async --backend-qjs-stub-wasi"; do
    cp "$scratch/original.wit" "$scratch/kronik-actor.wit"
    rm -rf "$scratch/deps" "$wasm"
    section "jco componentize src/counter.ts --backend quickjs $flags"
    t0=$(date +%s%N)
    # shellcheck disable=SC2086
    npx jco componentize src/counter.ts --wit "$scratch/kronik-actor.wit" --world-name actor \
        --backend quickjs $flags -o "$wasm" 2>&1 | grep -E '^(warning|OK)' | sed "s|$scratch|<scratch>|g" | cut -c1-160
    echo "build $(( ($(date +%s%N) - t0) / 1000000 )) ms, $(stat -c %s "$wasm") bytes"
    echo "WIT lines jco added: $(diff "$scratch/original.wit" "$scratch/kronik-actor.wit" | grep -c '^>')"
    wasm-tools component wit "$wasm" | grep -E '^ *import ' | grep -v 'kronik:actor/' | sed 's/^ *//'
    "$HARNESS" imports "$wasm" | grep -E 'DENIED|allowlist'
    echo "(exit ${PIPESTATUS[0]})"
done
