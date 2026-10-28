#!/usr/bin/env bash
# Installs a pinned gVisor release into /usr/local/bin, verifying the
# published SHA-512 checksum. Run as root on the test host.
#
# Since 2026-07, gVisor releases ship as a tarball that contains `runsc`,
# `containerd-shim-runsc-v1` and a `gvisor-bin/` directory of sidecar binaries
# that runsc executes at runtime and looks up next to its own binary.
#
# Usage: scripts/install-runsc.sh [RELEASE]   (default: 20261019.0)
set -euo pipefail

release="${1:-20261019.0}"
arch="$(uname -m)"
url="https://storage.googleapis.com/gvisor/releases/release/${release}/${arch}"
dest=/usr/local/bin

if command -v zstd >/dev/null 2>&1; then
    archive=gvisor.tar.zstd
    tar_flags=(--zstd)
else
    archive=gvisor.tar.bz2
    tar_flags=(--bzip2)
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

curl -fsSLO --max-time 300 "${url}/${archive}"
curl -fsSLO --max-time 60 "${url}/${archive}.sha512"
sha512sum -c "${archive}.sha512"

tar "${tar_flags[@]}" -tvf "$archive"
tar "${tar_flags[@]}" -xf "$archive" -C "$dest"

"$dest/runsc" --version
