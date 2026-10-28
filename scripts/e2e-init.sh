#!/usr/bin/env bash
# What a new user does first, for both languages: `kronik init` in an empty
# directory, the new project's own tests (`npm test`, `cargo test`), which run
# its actor in a test host, and `kronik build`. The projects get their SDK
# from the kronik binary and their toolchain from the public registries.
#
# Usage: [KRONIK_BIN=path] scripts/e2e-init.sh [WORKDIR]
# Defaults: /var/tmp/kronik-e2e-init, KRONIK_BIN
# $CARGO_TARGET_DIR/release/kronik or target/release/kronik. Needs
# npm (Node.js 22.20 or later), rustup, and network access to npm and
# crates.io.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

bin="$(realpath "${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}")"
dir="${1:-/var/tmp/kronik-e2e-init}"
rm -rf "$dir"
mkdir -p "$dir"
cd "$dir"

"$bin" init --lang ts shop-ts
(cd shop-ts && npm install --no-audit --no-fund && KRONIK_BIN="$bin" npm test && "$bin" build)
# --json (docs/reference/json.md): unchanged inputs keep the component.
(cd shop-ts && "$bin" --json build) | python3 -c '
import json, sys
b = json.load(sys.stdin)
assert b["wasm"] == "dist/shop-ts.wasm" and b["cached"] is True, b
assert b["code_hash"].startswith("b3:") and b["bytes"] > 0 and b["imports"], b
'

"$bin" --json init --lang rust shop-rs | python3 -c '
import json, sys
c = json.load(sys.stdin)
assert c["kind"] == "shop-rs" and c["lang"] == "rust" and "Cargo.toml" in c["files"], c
assert c["next"][-2:] == ["kronik build", "kronik deploy dist/shop-rs.wasm --reason '"'"'first deploy'"'"'"], c
'
(cd shop-rs && KRONIK_BIN="$bin" cargo test && "$bin" build)

echo "PASS: kronik init, the projects' tests and kronik build, for TypeScript and Rust (in $dir)"
