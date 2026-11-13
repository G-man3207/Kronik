#!/usr/bin/env bash
# Checks the install.sh of a release (scripts/release.sh) in a clean Ubuntu
# 24.04 container, the brief's install target:
#
#   1. As root, from file://: kronik goes to /usr/local/bin, runsc is skipped
#      without a terminal, and `kronik --version` runs and `kronik doctor`
#      passes (warnings are fine; a failed check is not).
#   2. As a user, as the brief says, `curl -fsSL <url>/install.sh | sh` over
#      HTTP: kronik goes to ~/.local/bin, with notices in kronik-licenses/.
#   3. Tampered and unsigned archives are refused without replacing a real binary.
#   4. With RUNSC=1, as root with KRONIK_INSTALL_RUNSC=yes: the pinned gVisor
#      release is downloaded and checked, runsc is installed, and
#      `kronik doctor`'s runsc check passes on it. Doctor's own exit code is
#      not checked here: its sandbox checks can fail in a container.
#
# Usage: [RUNSC=1] scripts/e2e-install.sh [RELEASE_DIR] [PORT]
# Defaults: dist/release and port 47950 for the HTTP server. Needs docker and
# python3. The container (kronik-e2e-install-<pid>), the HTTP server and the
# temporary copy are removed at exit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

release="$(cd "${1:-dist/release}" && pwd)"
test -s "$release/kronik-x86_64-unknown-linux-musl.tar.gz.sigstore.json" || {
    echo "This drill requires an actually attested release, not unsigned build candidates." >&2
    exit 1
}
port="${2:-47950}"
name="kronik-e2e-install-$$"
work="$(mktemp -d "${TMPDIR:-/var/tmp}/kronik-e2e-install.XXXXXX")"
server=""
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    [ -n "$server" ] && kill "$server" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

# Untrusted mirrors cannot substitute bytes or omit their standard signature bundle.
mkdir -p "$work/bad" "$work/unsigned"
cp "$release"/* "$work/bad/"
cp "$release"/* "$work/unsigned/"
printf 'x' >>"$work/bad/kronik-x86_64-unknown-linux-musl.tar.gz"
rm -f "$work/unsigned"/*.sigstore.json

python3 -m http.server "$port" --bind 127.0.0.1 --directory "$release" >"$work/http.log" 2>&1 &
server=$!
for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:$port/kronik-x86_64-unknown-linux-musl.tar.gz.sha256" >/dev/null && break
    sleep 0.1
done

docker run --rm --name "$name" --network host \
    -e RUNSC="${RUNSC:-0}" -e PORT="$port" \
    -v "$release:/release:ro" -v "$work/bad:/bad:ro" -v "$work/unsigned:/unsigned:ro" \
    ubuntu:24.04 bash -euo pipefail -c '
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates bzip2 >/dev/null

echo "== 1. root, from file://"
KRONIK_BASE_URL=file:///release sh /release/install.sh </dev/null
test "$(command -v kronik)" = /usr/local/bin/kronik
for file in LICENSE NOTICE THIRD_PARTY_LICENSES.txt; do
    test -s "/usr/local/bin/kronik-licenses/$file"
done
kronik --version
kronik doctor

echo "== 2. a user, curl | sh over HTTP"
useradd -m dev
su dev -c "curl -fsSL http://127.0.0.1:$PORT/install.sh | KRONIK_BASE_URL=http://127.0.0.1:$PORT sh"
su dev -c "test -x ~/.local/bin/kronik && ~/.local/bin/kronik --version | head -n 1"

echo "== 3. corrupted and unsigned archives preserve an actual executable"
mkdir /tmp/bad
cp /usr/local/bin/kronik /tmp/bad/kronik
before=$(sha256sum /tmp/bad/kronik)
version=$(/tmp/bad/kronik --version)
for source in /bad /unsigned; do
    if KRONIK_BASE_URL="file://$source" KRONIK_INSTALL_DIR=/tmp/bad sh /release/install.sh </dev/null; then
        echo "FAIL: untrusted release was installed"; exit 1
    fi
    test "$(sha256sum /tmp/bad/kronik)" = "$before"
    test "$(/tmp/bad/kronik --version)" = "$version"
done

if [ "$RUNSC" = 1 ]; then
    echo "== 4. runsc"
    KRONIK_BASE_URL=file:///release KRONIK_INSTALL_RUNSC=yes sh /release/install.sh </dev/null
    runsc --version | head -n 1
    test -x /usr/local/bin/gvisor-bin/gvisor_sentry
    kronik doctor >/tmp/doctor.txt || true
    cat /tmp/doctor.txt
    grep -q -E "^  pass  runsc +/usr/local/bin/runsc release-" /tmp/doctor.txt
fi
echo "PASS: install.sh"
'
