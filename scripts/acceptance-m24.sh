#!/usr/bin/env bash
# M24 acceptance (brief: long-lived connections), docs/design/m24-connections.md
# section 18. Criterion 3 (a crash after send-now) is a Rust test run by
# `cargo test`; this script runs the other three end to end:
#
#   scripts/acceptance-m24.sh load      criterion 1: chat-ts with 1 000
#                                       concurrent WebSocket clients
#   scripts/acceptance-m24.sh replay    criterion 2: identity replay of a
#                                       recorded WebSocket session, and a
#                                       changed message format
#   scripts/acceptance-m24.sh restart   criterion 4: restarts close
#                                       connections with a dedicated reason,
#                                       and the clients reconnect
#
# It builds the release kronik and loadgen and chat-ts with its step2
# variant first, unless NO_BUILD=1. scripts/acceptance_m24.py runs the
# command: the environment sets the scale (a small machine runs a reduced
# shape, such as CLIENTS=100 ROOMS=5 SECONDS=60), the ports (PORT, default
# 47510, and ADMIN_PORT, 47511) and the work directory, and it writes
# WORKDIR/report.json. Criterion 1's reference run is on the 2-vCPU test VPS.
# Needs python3, cargo and Node.js 22.20 or later.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

command="${1:-}"
case "$command" in
    load | replay | restart) ;;
    *)
        echo "usage: scripts/acceptance-m24.sh load|replay|restart" >&2
        exit 2
        ;;
esac

if [ "${NO_BUILD:-0}" != 1 ]; then
    cargo build --locked --release -p kronik
    cargo build --locked --release --manifest-path tools/loadgen/Cargo.toml
    bin="${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}"
    npm ci --prefix examples --no-audit --no-fund
    mkdir -p examples/dist
    "$bin" build --dir examples/chat-ts
    "$bin" build --dir examples/chat-ts --entry src/step2.ts
    cp examples/chat-ts/dist/chat-ts.wasm examples/chat-ts/dist/chat-ts-step2.wasm examples/dist/
fi
export KRONIK_BIN="${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/release/kronik}"
exec python3 -B scripts/acceptance_m24.py "$command"
