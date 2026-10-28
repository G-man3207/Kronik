#!/usr/bin/env bash
# Copies the built binaries, the OCI layout and the scripts to the test host.
# Usage: scripts/deploy.sh [HOST]   (default: travelfiesta)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
host="${1:-travelfiesta}"
dest=/root/kronik-spike-c
ssh "$host" "mkdir -p $dest"
rsync -a --delete out/bin out/foreign-echo-layout scripts "$host:$dest/"
echo "deployed to $host:$dest"
