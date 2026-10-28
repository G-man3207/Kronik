#!/usr/bin/env bash
# Builds a release of kronik into dist/release/:
#
#   kronik-x86_64-unknown-linux-musl     static binaries (musl, bundled SQLite)
#   kronik-aarch64-unknown-linux-musl
#   kronik.cdx.json                      CycloneDX SBOM of the binary's crates
#   install.sh                           scripts/install.sh with the release's
#                                        version and base URL
#   SHA256SUMS                           SHA-256 of all of the above
#
# The binaries are cross-compiled with cargo-zigbuild, which links with zig
# and compiles the C code (SQLite, ring) with zig's clang for musl. Paths of
# the checkout and of the Cargo home are remapped, as for the examples. The
# tools are pinned and installed on first use into
# $CARGO_TARGET_DIR/release-tools (default target/release-tools): zig is
# downloaded and its SHA-256 checked; cargo-zigbuild and cargo-cyclonedx come
# from crates.io with --locked.
#
# Usage: [KRONIK_BASE_URL=url] scripts/release.sh
# KRONIK_BASE_URL is where the release's files will be published; install.sh
# downloads from there. Without it, install.sh needs KRONIK_BASE_URL when it
# runs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# rustup may be installed without being added to PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
    # shellcheck source=/dev/null
    . "${CARGO_HOME:-$HOME/.cargo}/env"
fi

zig_version=0.17.0
zig_sha256_x86_64=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
zig_sha256_aarch64=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8
zigbuild_version=0.24.0
cyclonedx_version=0.5.9
targets=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)

root="$(pwd)"
target_dir="$(mkdir -p "${CARGO_TARGET_DIR:-target}" && cd "${CARGO_TARGET_DIR:-target}" && pwd)"
tools="$target_dir/release-tools"
out="$root/dist/release"
version="$(cargo metadata --format-version 1 --no-deps --locked |
    python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "kronik"))')"

# zig, checked against its pinned SHA-256.
host="$(uname -m)"
zig_sha256_var="zig_sha256_$host"
zig_dir="$tools/zig-$host-linux-$zig_version"
if [ ! -x "$zig_dir/zig" ]; then
    mkdir -p "$tools"
    archive="$tools/zig-$host-linux-$zig_version.tar.xz"
    curl -fsSL -o "$archive" "https://ziglang.org/download/$zig_version/zig-$host-linux-$zig_version.tar.xz"
    echo "${!zig_sha256_var}  $archive" | sha256sum -c -
    tar -xJf "$archive" -C "$tools"
    rm "$archive"
fi
export PATH="$zig_dir:$tools/bin:$PATH"

# cargo-zigbuild and cargo-cyclonedx, pinned.
if [ "$(cargo-zigbuild --version 2>/dev/null)" != "cargo-zigbuild $zigbuild_version" ]; then
    cargo install --locked --root "$tools" --version "$zigbuild_version" cargo-zigbuild
fi
if [ "$(cargo-cyclonedx --version 2>/dev/null)" != "cargo-cyclonedx $cyclonedx_version" ]; then
    cargo install --locked --root "$tools" --version "$cyclonedx_version" cargo-cyclonedx
fi
rustup target add "${targets[@]}"

cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=/kronik --remap-path-prefix=$cargo_home=/cargo"
rm -rf "$out"
mkdir -p "$out"
for target in "${targets[@]}"; do
    cargo zigbuild --locked --release -p kronik --target "$target" \
        --config 'profile.release.strip = "symbols"'
    cp "$target_dir/$target/release/kronik" "$out/kronik-$target"
done

# The SBOM: every crate in the binary, from Cargo.lock. cargo-cyclonedx
# writes one next to the manifest of every workspace member (all under
# crates/); keep the binary's, out of the source tree, and drop the rest.
cargo cyclonedx --manifest-path crates/kronik/Cargo.toml --format json \
    --spec-version 1.5 --target "${targets[0]}" --override-filename kronik.cdx
mv crates/kronik/kronik.cdx.json "$out/kronik.cdx.json"
rm -f crates/*/kronik.cdx.json

base_url="${KRONIK_BASE_URL:-@BASE_URL@}"
sed -e "s|@BASE_URL@|$base_url|g" -e "s|@VERSION@|$version|g" scripts/install.sh >"$out/install.sh"
chmod 755 "$out/install.sh"

(cd "$out" && sha256sum kronik-* kronik.cdx.json install.sh >SHA256SUMS)
echo "kronik $version in $out:"
ls -l "$out"
cat "$out/SHA256SUMS"
