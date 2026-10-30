#!/usr/bin/env bash
# Installs actionlint into target/tools/, like install-mdbook.sh. Archive
# SHA-256 values are pinned from rhysd/actionlint v1.7.12 release asset digests.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
version=1.7.12
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)
        target=linux_amd64
        sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 ;;
    Linux-aarch64 | Linux-arm64)
        target=linux_arm64
        sha256=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6 ;;
    Darwin-x86_64)
        target=darwin_amd64
        sha256=5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644 ;;
    Darwin-arm64)
        target=darwin_arm64
        sha256=aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f ;;
    *)
        echo "install-actionlint: no pinned actionlint $version for $(uname -s) $(uname -m)" >&2
        exit 1 ;;
esac
dir="$PWD/target/tools/actionlint-$version"
if [ ! -x "$dir/actionlint" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    url="https://github.com/rhysd/actionlint/releases/download/v$version/actionlint_${version}_${target}.tar.gz"
    curl -fsSL --retry 3 -o "$tmp/actionlint.tar.gz" "$url"
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$tmp/actionlint.tar.gz")"
    else
        actual="$(shasum -a 256 "$tmp/actionlint.tar.gz")"
    fi
    actual="${actual%% *}"
    if [ "$actual" != "$sha256" ]; then
        echo "install-actionlint: checksum mismatch for $url: expected $sha256, got $actual" >&2
        exit 1
    fi
    tar -xzf "$tmp/actionlint.tar.gz" -C "$tmp" actionlint
    mkdir -p "$dir"
    mv "$tmp/actionlint" "$dir/actionlint"
fi
printf '%s\n' "$dir/actionlint"
