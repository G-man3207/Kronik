#!/usr/bin/env bash
# Required, read-only service audit plus exclusive child-only filesystem probes.
# These act on a fixture made by scripts/proof-rootless.sh (or its helper's `create`), which
# runs only on a machine whose operator wrote /etc/kronik-proof-host (see that script).
# Usage: bash scripts/check-rootless.sh --fixture /absolute/owned-proof-root
set -euo pipefail
exec python3 "$(dirname "${BASH_SOURCE[0]}")/isolation-conformance.py" check "$@"
