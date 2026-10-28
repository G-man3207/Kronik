#!/usr/bin/env bash
# Installs the pinned mdBook release into target/tools/mdbook-<version>/ and
# prints the path of the binary. The downloaded archive must match the
# SHA-256 checksum below (from the GitHub release's asset digests);
# otherwise nothing is installed. An installed binary is reused.
#
# Usage: scripts/install-mdbook.sh
set -euo pipefail

VERSION=0.5.4

cd "$(dirname "${BASH_SOURCE[0]}")/.."

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)
        target=x86_64-unknown-linux-musl
        sha256=5222beabd3e37dc5be0d18ff99b79058469354db5c220153a1b92db5ba12be89
        ;;
    Linux-aarch64 | Linux-arm64)
        target=aarch64-unknown-linux-musl
        sha256=753e5c5c363ee8a56972344dcf91466f005a51db84a7aeffe427ae3ef83d6d44
        ;;
    Darwin-x86_64)
        target=x86_64-apple-darwin
        sha256=a47d7bf0d5d670cff9ee6cce95537cbeb62dc10704d9e7131ffbd13e2b59a5de
        ;;
    Darwin-arm64)
        target=aarch64-apple-darwin
        sha256=03e8a6d8b13a2971e0b3280affd03b388373c1485e26f73407c3a76b0b1838df
        ;;
    *)
        echo "install-mdbook: no pinned mdBook $VERSION for $(uname -s) $(uname -m)" >&2
        exit 1
        ;;
esac

dir="target/tools/mdbook-$VERSION"
if [ ! -x "$dir/mdbook" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    url="https://github.com/rust-lang/mdBook/releases/download/v$VERSION/mdbook-v$VERSION-$target.tar.gz"
    curl -fsSL --retry 3 -o "$tmp/mdbook.tar.gz" "$url"
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$tmp/mdbook.tar.gz")"
    else
        actual="$(shasum -a 256 "$tmp/mdbook.tar.gz")"
    fi
    actual="${actual%% *}"
    if [ "$actual" != "$sha256" ]; then
        echo "install-mdbook: checksum mismatch for $url" >&2
        echo "  expected $sha256" >&2
        echo "  got      $actual" >&2
        exit 1
    fi
    tar -xzf "$tmp/mdbook.tar.gz" -C "$tmp"
    mkdir -p "$dir"
    mv "$tmp/mdbook" "$dir/mdbook"
fi
echo "$dir/mdbook"
