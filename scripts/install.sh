#!/bin/sh
# Installs kronik:
#
#   curl -fsSL https://<project>/install.sh | sh
#
# Downloads the licensed static release archive for Linux x86_64 or aarch64.
# A source-pinned official GitHub verifier checks its GitHub OIDC attestation
# before any archive member is read or executed. Then the installer offers
# pinned gVisor setup and suggests `kronik doctor`.
#
# scripts/release.sh writes the release's version and base URL into the copy
# of this script that it puts next to the binaries. The environment
# overrides them:
#
#   KRONIK_BASE_URL       where the release's files are: https://, http:// or
#                         file://
#   KRONIK_VERSION        exact signed release version (needed in a checkout)
#   KRONIK_INSTALL_DIR    where kronik goes; default /usr/local/bin as root,
#                         else ~/.local/bin
#   KRONIK_INSTALL_RUNSC  yes, no or ask (the default): ask asks on the
#                         terminal, and without one installs nothing
set -eu

RELEASE_BASE_URL='@BASE_URL@'
RELEASE_VERSION='@VERSION@'
BASE_URL="${KRONIK_BASE_URL:-$RELEASE_BASE_URL}"
VERSION="${KRONIK_VERSION:-$RELEASE_VERSION}"
RELEASE_REPOSITORY=G-man3207/Kronik
RELEASE_REPOSITORY_ID=1432583300
RELEASE_WORKFLOW=.github/workflows/release.yml
RELEASE_ISSUER=https://token.actions.githubusercontent.com
RELEASE_REF='refs/tags/v{version}'
RELEASE_FILES='kronik kronik
LICENSE LICENSE
NOTICE NOTICE
THIRD_PARTY_LICENSES.txt THIRD_PARTY_LICENSES.txt'
VERIFIER_VERSION=2.103.3
VERIFIER_URL=https://github.com/cli/cli/releases/download/v2.103.3

say() { printf '%s\n' "$*"; }
fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}
need() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is needed; install it and run this again"
}

# Verify the downloaded verifier against this trusted script, never its server.
verify_release() {
    case "$arch" in
        x86_64)
            gh_arch=amd64
            gh_sha256=4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d
            ;;
        aarch64)
            gh_arch=arm64
            gh_sha256=ee32df2323c8847f5fac6cb6b4b69ca75828e9329a8f22f677021f7b3306ce63
            ;;
    esac
    gh_name="gh_${VERIFIER_VERSION}_linux_$gh_arch"
    curl -q -fsSL --proto '=https,file' -o "$tmp/verifier.tar.gz" "$VERIFIER_URL/$gh_name.tar.gz" ||
        fail "could not download the pinned official GitHub verifier"
    printf '%s  %s\n' "$gh_sha256" "$tmp/verifier.tar.gz" | sha256sum -c - >/dev/null ||
        fail "the official GitHub verifier does not match its source-pinned SHA-256"
    tar -xzOf "$tmp/verifier.tar.gz" "$gh_name/bin/gh" >"$tmp/gh"
    tar -xzOf "$tmp/verifier.tar.gz" "$gh_name/LICENSE" >"$tmp/gh-LICENSE"
    chmod 700 "$tmp/gh"
    mkdir -m 700 "$tmp/home" "$tmp/config" "$tmp/cache" "$tmp/tmp"
    ref="$(printf '%s\n' "$RELEASE_REF" | sed "s/{version}/$VERSION/")"
    query="if length > 0 and all(.[].verificationResult.signature.certificate; .sourceRepositoryIdentifier == \"$RELEASE_REPOSITORY_ID\") then true else error(\"wrong numeric repository identity\") end"
    verified="$(env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$tmp/home" \
        GH_CONFIG_DIR="$tmp/config" XDG_CACHE_HOME="$tmp/cache" TMPDIR="$tmp/tmp" \
        GH_HOST=github.com GH_PROMPT_DISABLED=1 \
        timeout --kill-after=10s 180 "$tmp/gh" attestation verify "$tmp/release.tar.gz" \
        --bundle "$tmp/bundle.json" --repo "$RELEASE_REPOSITORY" \
        --cert-identity "https://github.com/$RELEASE_REPOSITORY/$RELEASE_WORKFLOW@$ref" \
        --source-ref "$ref" --cert-oidc-issuer "$RELEASE_ISSUER" \
        --deny-self-hosted-runners --format json --jq "$query")" ||
        fail "release signature verification failed; the existing binary is unchanged"
    [ "$verified" = true ] || fail "release signature verification returned no verified repository identity"
}

case "$BASE_URL" in
    "" | @*) fail "this install.sh does not name a release; set KRONIK_BASE_URL to where the release's files are" ;;
esac
BASE_URL="${BASE_URL%/}"
VERSION="${VERSION#v}"
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$' ||
    fail "set KRONIK_VERSION to the exact signed release version, for example 0.4.0"
[ "$(uname -s)" = Linux ] || fail "kronik runs on Linux, not $(uname -s)"
case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) fail "there is no kronik for $(uname -m); there is one for x86_64 and one for aarch64" ;;
esac
need curl
need sha256sum
need tar
need sync
need timeout
need od
need sed
archive="kronik-$arch-unknown-linux-musl.tar.gz"

tmp="$(mktemp -d)"
candidate=""
trap 'rm -rf "$tmp"; if [ -n "$candidate" ]; then rm -f "$candidate"; fi' EXIT INT TERM

say "Downloading kronik $VERSION for $arch from $BASE_URL"
curl -q -fsSL --proto '=https,http,file' -o "$tmp/release.tar.gz" "$BASE_URL/$archive" ||
    fail "could not download $BASE_URL/$archive"
curl -q -fsSL --proto '=https,http,file' -o "$tmp/bundle.json" "$BASE_URL/$archive.sigstore.json" ||
    fail "could not download $BASE_URL/$archive.sigstore.json; unsigned releases are refused"
verify_release
# Stream only named members into private regular files: archive paths, links
# and ownership are never extracted onto the installer's filesystem.
while read -r member path; do
    tar -xzOf "$tmp/release.tar.gz" "$path" >"$tmp/$member" ||
        fail "the release archive has no readable $member"
    [ -s "$tmp/$member" ] || fail "the release archive has an empty $member"
done <<EOF
$RELEASE_FILES
EOF
magic="$(od -An -tx1 -N6 "$tmp/kronik" | tr -d ' \n')"
machine="$(od -An -tx1 -j18 -N2 "$tmp/kronik" | tr -d ' \n')"
[ "$magic" = 7f454c460201 ] || fail "the signed release is not a 64-bit little-endian ELF"
case "$arch/$machine" in
    x86_64/3e00 | aarch64/b700) ;;
    *) fail "the signed release ELF does not match $arch" ;;
esac
chmod 755 "$tmp/kronik"
"$tmp/kronik" --version >/dev/null || fail "the downloaded kronik does not run on this machine"

if [ -n "${KRONIK_INSTALL_DIR:-}" ]; then
    dir="$KRONIK_INSTALL_DIR"
elif [ "$(id -u)" = 0 ]; then
    dir=/usr/local/bin
else
    dir="$HOME/.local/bin"
fi
mkdir -p "$dir/kronik-licenses"
for member in LICENSE NOTICE THIRD_PARTY_LICENSES.txt; do
    cp "$tmp/$member" "$dir/kronik-licenses/$member"
    chmod 644 "$dir/kronik-licenses/$member"
done
# Stage on the destination filesystem so rename never copies over the live binary.
candidate="$(mktemp "$dir/.kronik.XXXXXX")"
cp "$tmp/kronik" "$candidate" || fail "could not stage kronik; the existing binary is unchanged"
chmod 755 "$candidate"
sync "$candidate" || fail "could not sync kronik; the existing binary is unchanged"
mv -fT "$candidate" "$dir/kronik"
candidate=""
say "Installed $("$dir/kronik" --version | head -n 1) to $dir/kronik"
case ":$PATH:" in
    *":$dir:"*) ;;
    *) say "Note: $dir is not on your PATH; add it, or run $dir/kronik" ;;
esac

# release.sh embeds the same trusted-checkout setup that CI uses directly.
sh "$(dirname "$0")/install-runsc.sh" # @RUNSC_SETUP@

say "Next: kronik doctor"
