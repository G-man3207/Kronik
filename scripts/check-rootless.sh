#!/usr/bin/env bash
# Required, read-only service audit plus exclusive child-only filesystem probes.
# Usage: bash scripts/check-rootless.sh --fixture /absolute/owned-proof-root
set -euo pipefail
exec python3 "$(dirname "${BASH_SOURCE[0]}")/isolation-conformance.py" check "$@"
