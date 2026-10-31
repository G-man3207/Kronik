#!/bin/sh
# Trusted-checkout CI entry point; release.sh embeds this same setup in install.sh.
(
set -eu
RUNSC_RELEASE=20261019.0
RUNSC_URL="https://storage.googleapis.com/gvisor/releases/release/$RUNSC_RELEASE"
RUNSC_DIR=/usr/local/bin
say() { printf '%s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is needed; install it and run this again"; }
case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) fail "there is no pinned gVisor for $(uname -m)" ;;
esac
runsc_sha512() {
    case "$1/$2" in
        x86_64/gvisor.tar.zstd) echo bcbf431b2f9a039f6ab23bfe23986031130c0f149294978cedfd46910901deba0737d8642c848f597ed4b5c72324885db4d75ee86a1f6a90915fbe1f2f2eb915 ;;
        x86_64/gvisor.tar.bz2) echo 7cbc2aeeee809dcccfb40e612504a1b76f2c119790cee59e482f7b35428cccc4f71705e7e322442d07d1f7d29b5d9e72e31319fc3088d6dcbec9fc7c1f0d8881 ;;
        aarch64/gvisor.tar.zstd) echo 60a8239ec21ba1495633dbfa24ab4d43578066fcebef2482f9d0cd1486abbfd3c5c5face1749a31cc62b287a0a44198a0852024c7f2e5683917c7c1c342d0bbe ;;
        aarch64/gvisor.tar.bz2) echo 6b14b582cd3185169df54275eed8721d94c9b40e6cb1533d0d0c46573271c6d2d03db586ea1caac46a45e805797f00b115bead9fb93636a1ffa69f2430958977 ;;
        *) fail "no pinned checksum for $1/$2" ;;
    esac
}
install_runsc() {
    if [ "$(id -u)" != 0 ]; then
        say "Skipping runsc: installing it into $RUNSC_DIR needs root"
        return 0
    fi
    need curl
    need sha512sum
    need tar
    if command -v zstd >/dev/null 2>&1 && tar --zstd --help >/dev/null 2>&1; then
        archive=gvisor.tar.zstd
        unpack=--zstd
    else
        need bzip2
        archive=gvisor.tar.bz2
        unpack=--bzip2
    fi
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT INT TERM
    say "Downloading gVisor release-$RUNSC_RELEASE ($archive)"
    curl -q -fsSL -o "$tmp/$archive" "$RUNSC_URL/$arch/$archive" ||
        fail "could not download $RUNSC_URL/$arch/$archive"
    printf '%s  %s\n' "$(runsc_sha512 "$arch" "$archive")" "$tmp/$archive" | sha512sum -c - >/dev/null ||
        fail "the SHA-512 of $archive is not the pinned one"
    tar "$unpack" -xf "$tmp/$archive" -C "$RUNSC_DIR"
    say "Installed $("$RUNSC_DIR/runsc" --version | head -n 1) to $RUNSC_DIR/runsc"
}
installed_runsc="$( (runsc --version 2>/dev/null || true) | head -n 1)"
case "$installed_runsc" in
    *"release-$RUNSC_RELEASE"*) say "runsc release-$RUNSC_RELEASE is already installed" ;;
    *)
        answer="${KRONIK_INSTALL_RUNSC:-ask}"
        if [ "$answer" = ask ]; then
            answer=no
            if (: </dev/tty) 2>/dev/null; then
                printf 'Install gVisor runsc release-%s for foreign actors? [y/N] ' "$RUNSC_RELEASE" >/dev/tty
                read -r reply </dev/tty || reply=""
                case "$reply" in y | Y | yes | YES) answer=yes ;; esac
            fi
        fi
        case "$answer" in
            yes) install_runsc ;;
            no) say "Skipping runsc; foreign actors need it (install it later with KRONIK_INSTALL_RUNSC=yes)" ;;
            *) fail "KRONIK_INSTALL_RUNSC must be yes, no or ask, not $answer" ;;
        esac
        ;;
esac
)
