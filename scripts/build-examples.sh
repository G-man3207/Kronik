#!/usr/bin/env bash
# Builds the example actors in examples/ (a workspace of their own, using the
# Rust SDK in sdk/rust) for wasm32-wasip2 into examples/dist/:
#
#   counter.wasm, notes.wasm, webhook-relay.wasm   counter-rs, notes-rs and
#                                                  webhook-relay-rs
#   counter-step2.wasm                             counter-rs, feature step2
#   webhook-relay-body-v2.wasm                     webhook-relay-rs, feature body-v2
#
# The variants change behavior on purpose, for the M3 behavior-diff tests.
# Paths of the checkout and of the Cargo home are remapped, so a component's
# hash does not depend on where the sources are. CI then checks the imports
# of everything in examples/dist (scripts/ci.sh examples).
#
# Usage: scripts/build-examples.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../examples"

# rustup may be installed without being added to PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
    # shellcheck source=/dev/null
    . "${CARGO_HOME:-$HOME/.cargo}/env"
fi

root=$(cd .. && pwd)
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=/kronik --remap-path-prefix=$cargo_home=/cargo"

out="${CARGO_TARGET_DIR:-target}/wasm32-wasip2/release"
mkdir -p dist
cargo build --locked --release --target wasm32-wasip2
for crate in counter-rs notes-rs webhook-relay-rs; do
    cp "$out/${crate//-/_}.wasm" "dist/${crate%-rs}.wasm"
done
cargo build --locked --release --target wasm32-wasip2 -p counter-rs --features step2
cp "$out/counter_rs.wasm" dist/counter-step2.wasm
cargo build --locked --release --target wasm32-wasip2 -p webhook-relay-rs --features body-v2
cp "$out/webhook_relay_rs.wasm" dist/webhook-relay-body-v2.wasm
ls -l dist/*.wasm
