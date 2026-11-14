#!/usr/bin/env bash
# Prebuilt artifacts only; missing prerequisites and every FAIL are fatal.
# These act on a fixture made by scripts/proof-rootless.sh (or its helper's `create`), which
# runs only on a machine whose operator wrote /etc/kronik-proof-host (see that script).
# Usage: bash scripts/conformance-rootless.sh --fixture /absolute/owned-proof-root [--isolation gvisor|microvm]
# Full program proof: add --program-proof (actual demos, Postgres, fork, ship/restore and UID audit).
set -euo pipefail
exec python3 "$(dirname "${BASH_SOURCE[0]}")/isolation-conformance.py" conformance "$@"
