#!/usr/bin/env bash
# Regenerates the committed bindings in internal/wit from wit/ with the
# pinned wit-bindgen-go (ADR 0030); CI checks that this changes nothing.
set -euo pipefail
cd "$(dirname "$0")"
bin=${KRONIK_SDK_TOOLS:-$HOME/.cache/kronik/sdk-tools}/bin
rm -rf internal/wit
"$bin/wit-bindgen-go" generate --world actor-go --package-root kronik.dev/sdk/internal/wit --out internal/wit ./wit
