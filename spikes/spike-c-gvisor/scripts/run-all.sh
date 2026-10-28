#!/usr/bin/env bash
# Runs every experiment on the test host, in order. Results go to
# /root/kronik-spike-c/results/; fetch them with scripts/fetch-results.sh.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

run() {
    echo ">>> $*"
    env "$@" >/dev/null
    echo "    exit $?"
}

run bash 01-survey.sh
run bash 02-bundle.sh
run bash 03-start.sh
run CPU_LIMIT=on bash 04-bridges.sh
run CPU_LIMIT=off bash 04-bridges.sh
run bash 05-coldstart.sh
run BRIDGE=pf bash 06-egress.sh
run BRIDGE=uds bash 06-egress.sh
run bash 07-limits.sh
run bash 08-supervise.sh
run bash 09-systrap.sh
run bash 11-overhead.sh
run bash 12-wait-race.sh
run bash 13-alternatives.sh
