#!/usr/bin/env bash
# Builds the foreign-actor examples (standalone Cargo projects, std only) as
# static musl binaries and packs each into a local OCI image layout:
#
#   examples/foreign-echo   -> examples/dist/foreign-echo.oci   (foreign-echo:dev)
#   examples/fake-payments  -> examples/dist/fake-payments.oci  (fake-payments:dev)
#
# Each image is one gzip layer with /bin/<name>, /etc/passwd, /etc/group and
# /tmp; it runs as nobody, listens on 8080/tcp. The packer is the
# kronik-foreign example `oci_pack`, which writes a deterministic layout.
# Paths of the sources and of the Cargo home are remapped, so the digest does
# not depend on where the checkout is.
#
# Prints one line per image: `<name> oci-layout:<absolute dir>@<digest>`,
# usable as `kronik foreign add --image`.
#
# Usage: scripts/build-foreign-examples.sh [--check] [--only foreign-echo|fake-payments]
#   --check  build everything a second time from scratch into separate
#            directories and fail unless the digests match (reproducibility)
set -euo pipefail
# `digest=$(image ...)` must stop at the first failing step inside.
shopt -s inherit_errexit
cd "$(dirname "${BASH_SOURCE[0]}")/.."
root=$(pwd)

# rustup may be installed without being added to PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
    # shellcheck source=/dev/null
    . "${CARGO_HOME:-$HOME/.cargo}/env"
fi

usage() {
    echo "usage: $0 [--check] [--only foreign-echo|fake-payments]" >&2
    exit 2
}

check=0
names=(foreign-echo fake-payments)
while [ $# -gt 0 ]; do
    case "$1" in
        --check) check=1 ;;
        --only)
            [ $# -ge 2 ] || usage
            case "$2" in
                foreign-echo | fake-payments) names=("$2") ;;
                *) usage ;;
            esac
            shift
            ;;
        -h | --help) usage ;;
        *) usage ;;
    esac
    shift
done

target=x86_64-unknown-linux-musl
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)

# build NAME TARGET_DIR: builds the static binary of examples/NAME.
build() {
    local name=$1 target_dir=$2 dir="$root/examples/$1"
    (
        cd "$dir"
        CARGO_TARGET_DIR="$target_dir" \
            SOURCE_DATE_EPOCH=0 \
            RUSTFLAGS="-C target-feature=+crt-static --remap-path-prefix=$dir=/src --remap-path-prefix=$cargo_home=/cargo" \
            cargo build --quiet --release --locked --target "$target"
    )
}

# stage NAME BINARY ROOTFS: lays out the image's file system.
stage() {
    local name=$1 binary=$2 rootfs=$3
    rm -rf "$rootfs"
    mkdir -p "$rootfs/bin" "$rootfs/etc" "$rootfs/tmp"
    install -m 0755 "$binary" "$rootfs/bin/$name"
    printf 'root:x:0:0:root:/root:/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n' \
        >"$rootfs/etc/passwd"
    printf 'root:x:0:\nnogroup:x:65534:\n' >"$rootfs/etc/group"
    chmod 0755 "$rootfs" "$rootfs/bin" "$rootfs/etc"
    chmod 0644 "$rootfs/etc/passwd" "$rootfs/etc/group"
    chmod 1777 "$rootfs/tmp"
}

# pack NAME ROOTFS OUT: writes the OCI layout OUT and prints its manifest digest.
pack() {
    local name=$1 rootfs=$2 out=$3
    cargo run -q --release -p kronik-foreign --example oci_pack -- \
        --out "$out" \
        --ref "$name:dev" \
        --layer "gzip:$rootfs" \
        --entrypoint "[\"/bin/$name\"]" \
        --cmd '["--listen","0.0.0.0:8080"]' \
        --user nobody \
        --workdir / \
        --expose 8080/tcp
}

# image NAME TARGET_DIR OUT: builds, stages and packs one image; prints the digest.
image() {
    local name=$1 target_dir=$2 out=$3
    build "$name" "$target_dir"
    stage "$name" "$target_dir/$target/release/$name" "$target_dir/rootfs"
    pack "$name" "$target_dir/rootfs" "$out"
}

mkdir -p "$root/examples/dist"
failed=0
for name in "${names[@]}"; do
    target_dir="$root/examples/$name/target"
    out="$root/examples/dist/$name.oci"
    digest=$(image "$name" "$target_dir" "$out")
    echo "$name oci-layout:$out@$digest"
    if [ "$check" = 1 ]; then
        # A second build from scratch, in other directories (still under the
        # remapped source directory, so no path differs in the output).
        again_dir="$target_dir/check-build"
        again_out="$target_dir/check.oci"
        rm -rf "$again_dir" "$again_out"
        again=$(image "$name" "$again_dir" "$again_out")
        if [ "$again" = "$digest" ]; then
            echo "$name reproducible: $digest"
        else
            echo "$name NOT reproducible: $digest vs $again ($out vs $again_out)" >&2
            failed=1
        fi
    fi
done
exit "$failed"
