#!/usr/bin/env bash
# Installs the pinned zig and cargo-zigbuild into TOOLS and prints zig's
# directory: the toolchain that links the static release binaries
# (scripts/release.sh) and the CI's musl check (scripts/ci.sh musl), so that
# the two cannot drift apart. zig is checked against its pinned SHA-256;
# cargo-zigbuild is installed with `cargo install --locked`. Only the
# directory goes to standard output.
#
# Usage: scripts/install-zig.sh TOOLS
set -euo pipefail

zig_version=0.17.0
# shellcheck disable=SC2034 # read through ${!zig_sha256_var} below
zig_sha256_x86_64=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
# shellcheck disable=SC2034 # read through ${!zig_sha256_var} below
zig_sha256_aarch64=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8
zigbuild_version=0.24.0

tools="${1:?usage: scripts/install-zig.sh TOOLS}"
host="$(uname -m)"
zig_sha256_var="zig_sha256_$host"
if [ -z "${!zig_sha256_var:-}" ]; then
    echo "install-zig: no pinned zig $zig_version for $host" >&2
    exit 1
fi
zig_dir="$tools/zig-$host-linux-$zig_version"
if [ ! -x "$zig_dir/zig" ]; then
    mkdir -p "$tools"
    archive="$tools/zig-$host-linux-$zig_version.tar.xz"
    curl -fsSL --retry 3 -o "$archive" "https://ziglang.org/download/$zig_version/zig-$host-linux-$zig_version.tar.xz"
    echo "${!zig_sha256_var}  $archive" | sha256sum -c - >&2
    tar -xJf "$archive" -C "$tools"
    rm "$archive"
fi
if [ "$("$zig_dir/zig" version)" != "$zig_version" ]; then
    echo "install-zig: wrong pinned Zig version in $zig_dir" >&2
    exit 1
fi
if [ "$(PATH="$tools/bin:$PATH" cargo-zigbuild --version 2>/dev/null)" != "cargo-zigbuild $zigbuild_version" ]; then
    cargo install --locked --root "$tools" --version "$zigbuild_version" cargo-zigbuild >&2
fi
echo "$zig_dir"
