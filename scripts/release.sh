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
# KRONIK_RELEASE_KEYHELPER=yes adds the separate optional x86_64 GNU PKCS#11
# helper archive; it never enables cryptoki in the daemon.
#
# The binaries are cross-compiled with cargo-zigbuild, which links with zig
# and compiles the C code (SQLite, ring) with zig's clang for musl. Paths of
# the checkout and of the Cargo home are remapped, as for the examples. The
# pinned tools live in $KRONIK_RELEASE_TOOLS (default
# $CARGO_TARGET_DIR/release-tools). Only tool inputs may be shared between
# independent builds, never compiled Kronik output.
#
# Usage: [KRONIK_BASE_URL=url] [KRONIK_RELEASE_KEYHELPER=yes] scripts/release.sh
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

# zig and cargo-zigbuild are pinned in scripts/install-zig.sh, which the CI's
# musl step uses too.
cyclonedx_version=0.5.9
targets=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
with_keyhelper="${KRONIK_RELEASE_KEYHELPER:-no}"
case "$with_keyhelper" in
    yes) targets+=(x86_64-unknown-linux-gnu) ;;
    no) ;;
    *) echo "KRONIK_RELEASE_KEYHELPER must be yes or no" >&2; exit 1 ;;
esac

root="$(pwd)"
target_dir="$(mkdir -p "${CARGO_TARGET_DIR:-target}" && cd "${CARGO_TARGET_DIR:-target}" && pwd)"
tools="${KRONIK_RELEASE_TOOLS:-$target_dir/release-tools}"
out="$root/dist/release"
version="$(cargo metadata --format-version 1 --no-deps --locked |
    python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "kronik"))')"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || { echo "invalid SOURCE_DATE_EPOCH" >&2; exit 1; }

host="$(uname -m)"
if [ "$with_keyhelper" = yes ] && [ "$host" != x86_64 ]; then
    echo "the optional GNU helper must be built on the supported x86_64 GNU host" >&2
    exit 1
fi
# zig, checked against its pinned SHA-256, and cargo-zigbuild, pinned.
zig_dir="$(scripts/install-zig.sh "$tools")"
export PATH="$zig_dir:$tools/bin:$PATH"

# cargo-cyclonedx, pinned.
if [ "$(cargo cyclonedx --version 2>/dev/null)" != "cargo-cyclonedx-cyclonedx $cyclonedx_version" ]; then
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
    package=kronik
    features=()
    metadata_features=()
    if [ "$target" = x86_64-unknown-linux-gnu ]; then
        package=kronik-keyhelper
        features=(--features pkcs11)
        metadata_features=(--features kronik-keyhelper/pkcs11)
        cargo build --locked --release -p "$package" --target "$target" "${features[@]}" \
            --config 'profile.release.strip = "symbols"'
    else
        cargo zigbuild --locked --release -p kronik --target "$target" \
            --config 'profile.release.strip = "symbols"'
    fi
    # Each archive carries only its own target-specific SBOM.
    cargo cyclonedx --manifest-path "crates/$package/Cargo.toml" --format json \
        --spec-version 1.5 --target "$target" "${features[@]}" --override-filename "$package.cdx"
    mv "crates/$package/$package.cdx.json" "$work/$package.cdx.json"
    python3 - "$work/$package.cdx.json" <<'PY'
from pathlib import Path
import runpy
import sys
path = Path(sys.argv[1])
path.write_bytes(runpy.run_path("scripts/package-release.py")["reproducible_sbom"](path, Path.cwd()))
PY
    rm -f crates/*/"$package.cdx.json"
    cargo metadata --locked --format-version 1 --filter-platform "$target" "${metadata_features[@]}" >"$work/metadata.json"
    python3 scripts/package-release.py "$target" "$target_dir/$target/release/$package" \
        "$work/$package.cdx.json" "$work/metadata.json" "$zig_dir" "$out"
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
