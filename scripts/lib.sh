#!/usr/bin/env bash
# Sourced from the repository root by the scripts and demos below it; never
# run: it only defines helpers.

# wait_healthy SOCKET LOG: wait up to 60 s for the daemon on SOCKET to answer
# GET /v1/health (a shared CI runner can be slow to start one); otherwise
# print the end of LOG and exit 1.
wait_healthy() {
    local _
    for _ in $(seq 1 1200); do
        curl -sf --unix-socket "$1" http://kronik/v1/health >/dev/null 2>&1 && return 0
        sleep 0.05
    done
    echo "FAIL: daemon did not become healthy in 60 s" >&2
    tail -n 40 "$2" >&2 || true
    exit 1
}
