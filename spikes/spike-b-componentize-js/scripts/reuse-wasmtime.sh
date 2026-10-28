#!/usr/bin/env bash
# How much of a JavaScript turn is per-instance work? Compares the fresh
# instance per turn with repeated calls of `handle` on one instance (which
# Kronik never does, I3), using the `reuse` subcommand of the patched harness
# copy (scripts/build-harness.sh).
# Output: results/reuse-<host>.txt
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record "reuse-$(hostname)"

for spec in "counter counter" "actor noop" "actor json"; do
    read -r variant msg <<<"$spec"
    section "out/$variant.wasm --msg $msg"
    "$EXPERIMENT_HARNESS" reuse "out/$variant.wasm" --msg "$msg" --iterations 500
done
