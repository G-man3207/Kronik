# shellcheck shell=bash disable=SC2034
# Shared settings for the spike B experiment scripts. Sourced, not run.
#
# HARNESS is the spike A harness (spikes/spike-a-wasmtime, built with
# `cargo build --release`); EXPERIMENT_HARNESS is its patched copy from
# scripts/build-harness.sh. On the test host, scripts/deploy.sh copies both
# next to the components and sets these variables.
#
# WIT_REV is the commit whose wit/kronik-actor.wit the spike was made with
# and the harness implements. Later amendments (b8a3b39 added state.set-for
# and privacy.current-subject) are not in the harness, so the components are
# built from this revision rather than from the working tree.

SPIKE_B=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$SPIKE_B" || exit 1
HARNESS=${HARNESS:-$SPIKE_B/../spike-a-wasmtime/target/release/spike-a-wasmtime}
EXPERIMENT_HARNESS=${EXPERIMENT_HARNESS:-$SPIKE_B/out/harness/experiments/target/release/spike-a-wasmtime}
WIT_REV=5a8d400
RESULTS=$SPIKE_B/results
CACHE=$SPIKE_B/out/cache
mkdir -p "$RESULTS" "$CACHE"
if ! command -v wasm-tools >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    . "$HOME/.cargo/env"
fi

# Writes everything the calling script prints to results/<name>.txt as well.
record() {
    exec > >(tee "$RESULTS/$1.txt") 2>&1
    echo "# $1 on $(hostname) at $(date -u +%FT%TZ), $("$HARNESS" version)"
}

section() { printf '\n=== %s\n' "$*"; }

variant_flags() {
    case "$1" in
        actor | counter) echo "--disable http fetch-event stdio" ;;
        actor-aot | counter-aot) echo "--disable http fetch-event stdio --aot" ;;
        actor-no-http) echo "--disable http fetch-event" ;;
        actor-default) echo "(no features disabled)" ;;
    esac
}

handle() { "$HARNESS" handle "$@" --cache "$CACHE"; }

# Prints the spike's WIT (see WIT_REV); needs the git checkout.
spike_wit() { git -C "$SPIKE_B" show "$WIT_REV:wit/kronik-actor.wit"; }
