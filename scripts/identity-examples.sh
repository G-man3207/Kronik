#!/usr/bin/env bash
# Identity replay of every example app (Definition of done: "Identity replay
# empty for all example apps"), each on a fresh daemon on a real disk. Each
# example is deployed and driven with representative traffic, then forked
# after its setup and replayed with the same code in isolated and continuous
# mode. Both behavior diffs must be empty. scripts/identity-examples.py has
# the details: the traffic per example and the checks.
#
# Usage: [KRONIK_BIN=path] scripts/identity-examples.sh [WORKDIR] [identity-examples.py options]
# Defaults: /var/tmp/kronik-identity; KRONIK_BIN $CARGO_TARGET_DIR/release/kronik
# or target/release/kronik. `--only todo-ts,billing-ts` runs some of them.
#
# Needs python3 and the example components in examples/dist
# (scripts/build-examples.sh and scripts/build-examples-ts.sh). Builds
# fake-payments for billing-ts. todo-ts's sweep timer fires a day after an
# item is done, so its daemon restarts with libfaketime moving its clock
# ahead. Install libfaketime (Debian and Ubuntu: apt-get install faketime) or
# point FAKETIME_LIB at libfaketimeMT.so.1. That works only for a
# dynamically linked kronik, not for the static release builds. Prints a
# line per example and a JSON summary. Exits non-zero on the first failure
# and keeps that example's work directory.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# rustup may be installed without being added to PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
    # shellcheck source=/dev/null
    . "${CARGO_HOME:-$HOME/.cargo}/env"
fi

bin="$(realpath "${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}")"
# WORKDIR is optional: ci.sh passes only `--only ...` when libfaketime is missing.
dir=/var/tmp/kronik-identity
if [ "$#" -gt 0 ] && [[ "$1" != -* ]]; then
    dir="$1"
    shift
fi

payments="$(cargo build --quiet --locked --release --manifest-path examples/fake-payments/Cargo.toml \
    --message-format=json | python3 -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable"):
        print(m["executable"])
')"

faketime_lib="${FAKETIME_LIB:-}"
if [ -z "$faketime_lib" ]; then
    for lib in /usr/lib/*/faketime/libfaketimeMT.so.1 /usr/lib/faketime/libfaketimeMT.so.1 \
        /usr/local/lib/faketime/libfaketimeMT.so.1; do
        if [ -f "$lib" ]; then
            faketime_lib="$lib"
            break
        fi
    done
fi

exec python3 scripts/identity-examples.py --bin "$bin" --dir "$dir" --fake-payments "$payments" \
    ${faketime_lib:+--faketime-lib "$faketime_lib"} "$@"
