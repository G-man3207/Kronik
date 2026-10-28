#!/usr/bin/env bash
# What a new user does first, per language: `kronik init` in an empty
# directory, the new project's own tests (`npm test`, `cargo test`, `python3
# -m unittest`, `go test`), which run its actor in a test host, and `kronik
# build`. The projects get their SDK from the kronik binary; TypeScript and
# Rust get their toolchain from the public registries, Python and Go from
# the pinned tools (scripts/install-sdk-tools.sh, $KRONIK_SDK_TOOLS).
#
# Usage: [KRONIK_BIN=path] [E2E_INIT_LANGS="ts rust python go"] scripts/e2e-init.sh [WORKDIR]
# Defaults: /var/tmp/kronik-e2e-init, E2E_INIT_LANGS "ts rust", KRONIK_BIN
# $CARGO_TARGET_DIR/release/kronik or target/release/kronik. TypeScript
# needs npm (Node.js 22.20 or later) and network access to npm; Rust needs
# rustup and crates.io; Python needs python3 3.11 or later.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

bin="$(realpath "${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}")"
dir="${1:-/var/tmp/kronik-e2e-init}"
rm -rf "$dir"
mkdir -p "$dir"
cd "$dir"

langs="${E2E_INIT_LANGS:-ts rust}"
tools="${KRONIK_SDK_TOOLS:-$HOME/.cache/kronik/sdk-tools}"
has() { [[ " $langs " == *" $1 "* ]]; }

if has ts; then
"$bin" init --lang ts shop-ts
(cd shop-ts && npm install --no-audit --no-fund && KRONIK_BIN="$bin" npm test && "$bin" build)
# --json (docs/reference/json.md): unchanged inputs keep the component.
(cd shop-ts && "$bin" --json build) | python3 -c '
import json, sys
b = json.load(sys.stdin)
assert b["wasm"] == "dist/shop-ts.wasm" and b["cached"] is True, b
assert b["code_hash"].startswith("b3:") and b["bytes"] > 0 and b["imports"], b
'
fi

if has rust; then
"$bin" --json init --lang rust shop-rs | python3 -c '
import json, sys
c = json.load(sys.stdin)
assert c["kind"] == "shop-rs" and c["lang"] == "rust" and "Cargo.toml" in c["files"], c
assert c["next"][-2:] == ["kronik build", "kronik deploy dist/shop-rs.wasm --reason '"'"'first deploy'"'"'"], c
'
(cd shop-rs && KRONIK_BIN="$bin" cargo test && "$bin" build)
fi

if has python; then
"$bin" --json init --lang python shop-py | python3 -c '
import json, sys
c = json.load(sys.stdin)
assert c["kind"] == "shop-py" and c["lang"] == "python" and "pyproject.toml" in c["files"], c
assert c["next"][1].endswith("install-sdk-tools.sh  # once: the pinned toolchains"), c
assert c["next"][2] == "python3 -m unittest discover -s tests", c
'
(cd shop-py && KRONIK_BIN="$bin" KRONIK_SDK_TOOLS="$tools" python3 -m unittest discover -s tests &&
    KRONIK_SDK_TOOLS="$tools" "$bin" build && test -s dist/shop-py.wasm)
fi

if has go; then
"$bin" --json init --lang go shop-go | python3 -c '
import json, sys
c = json.load(sys.stdin)
assert c["kind"] == "shop-go" and c["lang"] == "go" and "go.mod" in c["files"], c
assert c["next"][2] == "go test ./test", c
'
(cd shop-go && KRONIK_BIN="$bin" KRONIK_SDK_TOOLS="$tools" PATH="$tools/bin:$PATH" GOTOOLCHAIN=local go test ./test &&
    KRONIK_SDK_TOOLS="$tools" "$bin" build && test -s dist/shop-go.wasm)
fi

echo "PASS: kronik init, the projects' tests and kronik build, for $langs (in $dir)"
