#!/usr/bin/env bash
# M23 B1: real REST emulators, an already-built static Linux binary, no cloud account.
# Usage: KRONIK_BIN=target/x86_64-unknown-linux-musl/release/kronik scripts/e2e-keys.sh [options]
# Needs root, Linux Python 3.12+, Docker and openssl. Does not build or install anything.
# Containers have no external network; only this run's containers/data are changed.
# On a shared VPS: flock /var/tmp/kronik-vps.lock scripts/e2e-keys.sh [options]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 -B scripts/e2e-keys.py \
    --bin "${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-musl/release/kronik}" "$@"
