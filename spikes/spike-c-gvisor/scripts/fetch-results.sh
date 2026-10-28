#!/usr/bin/env bash
# Copies the experiment results from the test host into results/ and
# replaces the host's public and Tailscale addresses with placeholders.
# Usage: scripts/fetch-results.sh [HOST]   (default: travelfiesta)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
host="${1:-travelfiesta}"
mkdir -p results
rsync -a "$host:/root/kronik-spike-c/results/" results/

# shellcheck disable=SC2016 # expanded on the host
public_ip=$(ssh "$host" 'ip -4 route get 1.1.1.1 | grep -o "src [0-9.]*" | cut -d" " -f2')
# shellcheck disable=SC2016 # expanded on the host
tailscale_ip=$(ssh "$host" 'ip -4 -o addr show tailscale0 2>/dev/null | awk "{print \$4}" | cut -d/ -f1')
for f in results/*.txt; do
    sed -i -e "s/${public_ip//./\\.}/<public-ip>/g" "$f"
    if [ -n "$tailscale_ip" ]; then
        sed -i -e "s/${tailscale_ip//./\\.}/<tailscale-ip>/g" "$f"
    fi
done
ls -l results
