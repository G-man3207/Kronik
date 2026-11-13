#!/usr/bin/env bash
# M23 B4/B5: the external-secret criteria (docs/design/m23-secret-backends.md
# section 9, criteria 2 and 3, and the outages) against real secret services
# in Docker: OpenBao (KV v2, token and AppRole), moto (AWS Secrets Manager),
# the Blackwell Systems GCP Secret Manager emulator and the rokeller Azure
# Key Vault emulator, every image pinned by digest in scripts/e2e-secrets.py.
#
# Usage: KRONIK_BIN=target/debug/kronik scripts/e2e-secrets.sh [--only openbao,openbao-approle,aws,gcp,azure] [--dir DIR]
#
# Needs Docker, Python 3.11+ and openssl. Does not build or install anything:
# KRONIK_BIN is an already-built kronik (a development or a release build; the
# results record which file ran). The services publish their ports on
# 127.0.0.1 only, in 47100-47199, as do the script's own fixtures; the daemons
# talk to them over loopback. Only containers this run created are removed,
# also when it fails. Writes its evidence to results.json in the run
# directory, which it prints.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 -B scripts/e2e-secrets.py \
    --bin "${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/debug/kronik}" "$@"
