#!/usr/bin/env bash
# Runs the TypeScript actor in the spike A harness and checks determinism:
# identical digests across fresh instances and processes, and which values
# follow the turn seed and the logical time. Shows where Math.random gets its
# randomness and that module scope does not survive a turn.
# Output: results/determinism-<host>.txt
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record "determinism-$(hostname)"
C=out/actor.wasm
SEED_B=0101010101010101010101010101010101010101010101010101010101010101

section "describe"
"$HARNESS" describe "$C" --cache "$CACHE"

section "HTTP input: POST /spike-b/acme/probe, 3 fresh instances"
handle "$C" --http 'POST /spike-b/acme/probe' --body '{}' --repeat 3

section "Message input: probe with starting state n=41, 3 fresh instances"
handle "$C" --msg probe --state n=41 --repeat 3

section "Same input in two more processes (default seed and time)"
for _ in 1 2; do handle "$C" --msg probe | grep -E '^digest'; done

section "Another seed: every JavaScript random source changes"
handle "$C" --msg probe --seed "$SEED_B" | grep -E '^outcome|random|^digest'

section "Another logical time: Date and now-ms follow it"
handle "$C" --msg probe --time-ms 1800000000000 | grep -E '^outcome|clock|now-ms|^digest'

section "How Math.random draws randomness: host calls per N calls"
for n in 1 10 100 1000; do
    out=$(handle "$C" --msg math --body "$n")
    echo "Math.random() x $n: $(grep -c 'wasi:random/random.get-random-u64' <<<"$out") get-random-u64 calls, $(grep -E '^fuel' <<<"$out")"
done

section "Fuel of JSON work: build N objects, JSON.stringify, JSON.parse (fuel limit raised to 2e9)"
for n in 100 1000 10000; do
    out=$(handle "$C" --msg json --body "$n" --fuel 2000000000)
    echo "json $n: $(grep -oE 'bytes[^0-9]+[0-9]+' <<<"$out" | grep -oE '[0-9]+$') bytes of JSON text, $(grep -E '^fuel' <<<"$out"), $(grep -E '^memory' <<<"$out" | tr -s ' ')"
done

section "Turn outcomes for errors and limits"
for args in "--msg throw" "--msg reject" "--msg spin" "--msg alloc --body 16" "--msg alloc --body 100"; do
    # shellcheck disable=SC2086
    out=$(handle "$C" $args --repeat 2)
    echo "$args: $(grep -E '^outcome' <<<"$out" | cut -c1-160); $(grep -E '^fuel' <<<"$out"); $(grep -E '^memory' <<<"$out" | tr -s ' '); identical $(grep -E '^identical' <<<"$out" | awk '{print $2}')"
done

section "Two builds of the same source: out/counter.wasm and out/counter-rebuild.wasm"
for variant in counter counter-rebuild; do
    out=$(handle "out/$variant.wasm" --msg counter)
    echo "$variant: $(grep -E '^code' <<<"$out" | awk '{print $2}'), $(grep -E '^fuel' <<<"$out"), digest $(grep -E '^digest' <<<"$out" | awk '{print $3}')"
done

section "Digest summary (compare across machines)"
digest() { grep -E '^digest' | awk '{print $3}'; }
echo "probe, message:   $(handle "$C" --msg probe | digest)"
echo "probe, HTTP:      $(handle "$C" --http 'POST /spike-b/acme/probe' --body '{}' | digest)"
echo "counter, message: $(handle "$C" --msg counter | digest)"
echo "noop, message:    $(handle "$C" --msg noop | digest)"
echo "json 1000:        $(handle "$C" --msg json --body 1000 | digest)"
