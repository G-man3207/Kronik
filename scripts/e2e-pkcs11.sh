#!/usr/bin/env bash
# M23 B6: the kronik-keyhelper flow of ADR 0093 end to end against SoftHSM2.
#
# Usage: KRONIK_BIN=target/debug/kronik KRONIK_KEYHELPER=target/debug/kronik-keyhelper \
#            scripts/e2e-pkcs11.sh [--dir DIR]
#
# Needs root (the helper and the daemon run as the user that owns the token),
# Linux, Python 3.11+, and the Debian packages softhsm2 and opensc. Does not
# build or install anything: KRONIK_BIN is an already-built kronik and
# KRONIK_KEYHELPER a kronik-keyhelper built with `--features pkcs11` (a
# development or a release build; the results record which files ran).
#
# The helper runs with an empty environment, as the daemon starts it, so
# SoftHSM reads its system configuration (/etc/softhsm/softhsm2.conf): the
# run creates one token with a random label in the system token directory
# and deletes it at the end, also when the run fails. No other token is
# touched. Writes its evidence to results.json in the run directory.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 -B scripts/e2e-pkcs11.py \
    --bin "${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/debug/kronik}" \
    --helper "${KRONIK_KEYHELPER:-${CARGO_TARGET_DIR:-target}/debug/kronik-keyhelper}" "$@"
