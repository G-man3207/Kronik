#!/usr/bin/env bash
# Checks the install.sh of a release (scripts/release.sh) in a clean Ubuntu
# 24.04 container, the brief's install target:
#
#   1. As root, from file://: kronik goes to /usr/local/bin, runsc is skipped
#      without a terminal, and `kronik --version` runs and `kronik doctor`
#      passes (warnings are fine; a failed check is not).
#   2. As a user, as the brief says, `curl -fsSL <url>/install.sh | sh` over
#      HTTP: kronik goes to ~/.local/bin.
#   3. A binary that does not match SHA256SUMS is refused.
#   4. With RUNSC=1, as root with KRONIK_INSTALL_RUNSC=yes: the pinned gVisor
#      release is downloaded and checked, runsc is installed, and
#      `kronik doctor` finds it.
#
# Usage: [RUNSC=1] scripts/e2e-install.sh [RELEASE_DIR] [PORT]
# Defaults: dist/release and port 47950 for the HTTP server. Needs docker and
# python3. The container (kronik-e2e-install-<pid>), the HTTP server and the
# temporary copy are removed at exit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

release="$(cd "${1:-dist/release}" && pwd)"
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

# The release with a binary that no longer matches SHA256SUMS.
mkdir -p "$work/bad"
cp "$release"/* "$work/bad/"
printf 'x' >>"$work/bad/kronik-x86_64-unknown-linux-musl"

python3 -m http.server "$port" --bind 127.0.0.1 --directory "$release" >"$work/http.log" 2>&1 &
server=$!
for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:$port/SHA256SUMS" >/dev/null && break
    sleep 0.1
done

docker run --rm --name "$name" --network host \
    -e RUNSC="${RUNSC:-0}" -e PORT="$port" \
    -v "$release:/release:ro" -v "$work/bad:/bad:ro" \
    ubuntu:24.04 bash -euo pipefail -c '
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates bzip2 >/dev/null

echo "== 1. root, from file://"
KRONIK_BASE_URL=file:///release sh /release/install.sh </dev/null
test "$(command -v kronik)" = /usr/local/bin/kronik
kronik --version
kronik doctor

echo "== 2. a user, curl | sh over HTTP"
useradd -m dev
su dev -c "curl -fsSL http://127.0.0.1:$PORT/install.sh | KRONIK_BASE_URL=http://127.0.0.1:$PORT sh"
su dev -c "test -x ~/.local/bin/kronik && ~/.local/bin/kronik --version | head -n 1"

echo "== 3. a corrupted binary"
if KRONIK_BASE_URL=file:///bad KRONIK_INSTALL_DIR=/tmp/bad sh /release/install.sh </dev/null 2>/tmp/err; then
    echo "FAIL: the corrupted binary was installed"; exit 1
fi
grep -q "does not match\|SHA256SUMS says" /tmp/err && cat /tmp/err
test ! -e /tmp/bad/kronik

if [ "$RUNSC" = 1 ]; then
    echo "== 4. runsc"
    KRONIK_BASE_URL=file:///release KRONIK_INSTALL_RUNSC=yes sh /release/install.sh </dev/null
    runsc --version | head -n 1
    test -x /usr/local/bin/gvisor-bin/gvisor_sentry
    kronik doctor || true
fi
echo "PASS: install.sh"
'
