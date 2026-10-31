#!/usr/bin/env bash
# Builds unsigned release candidates into dist/release/:
#
#   kronik-x86_64-unknown-linux-musl.tar.gz  static binary, licenses, notices,
#   kronik-aarch64-unknown-linux-musl.tar.gz and target-specific CycloneDX SBOM
#   *.tar.gz.sha256                       per-archive checksum (also usable
#                                         for additive historical bundles)
#   install.sh                            version and base URL substituted
#   SHA256SUMS                            SHA-256 of all of the above
# The manual tag workflow compares two real builds before OIDC attestation.
#
# The binaries are cross-compiled with cargo-zigbuild, which links with zig
# and compiles the C code (SQLite, ring) with zig's clang for musl. Paths of
# the checkout and of the Cargo home are remapped, as for the examples. The
# pinned tools live in $KRONIK_RELEASE_TOOLS (default
# $CARGO_TARGET_DIR/release-tools). Only tool inputs may be shared between
# independent builds, never compiled Kronik output.
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
tools="${KRONIK_RELEASE_TOOLS:-$target_dir/release-tools}"
out="$root/dist/release"
version="$(cargo metadata --format-version 1 --no-deps --locked |
    python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "kronik"))')"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || { echo "invalid SOURCE_DATE_EPOCH" >&2; exit 1; }

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
[ "$("$zig_dir/zig" version)" = "$zig_version" ] || { echo "wrong pinned Zig version" >&2; exit 1; }
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
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=/kronik --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$target_dir=/target --remap-path-prefix=$tools=/tools"
export CFLAGS="${CFLAGS:-} -ffile-prefix-map=$root=/kronik -ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$target_dir=/target -ffile-prefix-map=$tools=/tools"
rm -rf "$out"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
for target in "${targets[@]}"; do
    cargo zigbuild --locked --release -p kronik --target "$target" \
        --config 'profile.release.strip = "symbols"'
    # Keep each target's SBOM inside its own archive. cargo-cyclonedx writes
    # beside workspace manifests; remove only this invocation's generated name.
    cargo cyclonedx --manifest-path crates/kronik/Cargo.toml --format json \
        --spec-version 1.5 --target "$target" --override-filename kronik.cdx
    mv crates/kronik/kronik.cdx.json "$work/kronik.cdx.json"
    python3 - "$work/kronik.cdx.json" <<'PY'
from pathlib import Path
import runpy
import sys
path = Path(sys.argv[1])
path.write_bytes(runpy.run_path("scripts/package-release.py")["reproducible_sbom"](path, Path.cwd()))
PY
    rm -f crates/*/kronik.cdx.json
    cargo metadata --locked --format-version 1 --filter-platform "$target" >"$work/metadata.json"
    python3 scripts/package-release.py "$target" "$target_dir/$target/release/kronik" \
        "$work/kronik.cdx.json" "$work/metadata.json" "$zig_dir" "$out"
done

base_url="${KRONIK_BASE_URL:-@BASE_URL@}"
python3 - "$root" "$version" "$base_url" "$out/install.sh" <<'PY'
from pathlib import Path
import runpy
import sys
root, version, base_url, output = sys.argv[1:]
render = runpy.run_path(str(Path(root) / "scripts/package-release.py"))["render_installer"]
Path(output).write_text(render(Path(root), version, base_url))
PY
chmod 755 "$out/install.sh"

(cd "$out" && sha256sum kronik-*.tar.gz kronik-*.tar.gz.sha256 install.sh >SHA256SUMS)
echo "kronik $version in $out:"
ls -l "$out"
cat "$out/SHA256SUMS"
