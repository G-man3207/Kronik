#!/usr/bin/env bash
# Builds guest/spike.wasm with the TypeScript SDK's pinned ComponentizeJS
# (jco 1.39.0 → componentize-js 0.23.0, sdk/ts/package-lock.json), with the
# `http` feature on: Kronik's builds disable `http fetch-event stdio`; here
# only `fetch-event stdio` are off.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
jco=../../sdk/ts/node_modules/.bin/jco
[ -x "$jco" ] || (cd ../../sdk/ts && npm ci --no-audit --no-fund)
"$jco" componentize guest/spike.js --wit guest/spike.wit --world-name spike \
    --disable fetch-event stdio -o guest/spike.wasm
