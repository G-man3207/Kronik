#!/usr/bin/env bash
# End-to-end ACME (ADR 0009): kronik's gateway gets a certificate from
# Pebble, Let's Encrypt's test CA, by TLS-ALPN-01 on its own port, serves
# HTTPS with it, and after a restart serves the cached certificate without a
# new order. pebble-challtestsrv answers DNS so that the test name resolves
# to 127.0.0.1.
#
# Usage: scripts/e2e-acme-pebble.sh [path/to/kronik]   (Linux x86_64)
# Downloads (pinned, checked) are cached in $KRONIK_PEBBLE_CACHE, by default
# /var/tmp/kronik-pebble.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
bin="$(realpath "${1:-target/debug/kronik}")"
cache="${KRONIK_PEBBLE_CACHE:-/var/tmp/kronik-pebble}"
version=v2.10.1
release="https://github.com/letsencrypt/pebble/releases/download/$version"
raw="https://raw.githubusercontent.com/letsencrypt/pebble/$version"

fetch() { # url sha256 file
    if [ ! -f "$cache/$3" ] || ! echo "$2  $cache/$3" | sha256sum -c --quiet 2>/dev/null; then
        curl -fsSL -o "$cache/$3" "$1"
        echo "$2  $cache/$3" | sha256sum -c --quiet
    fi
}
mkdir -p "$cache"
fetch "$release/pebble-linux-amd64.tar.gz" \
    4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed pebble.tar.gz
fetch "$release/pebble-challtestsrv-linux-amd64.tar.gz" \
    e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92 challtestsrv.tar.gz
fetch "$raw/test/certs/pebble.minica.pem" \
    0c502e52627ff7de972c7e9e065640103b4589b4e2d23d3fcf21bef1e3c8c67c minica.pem
fetch "$raw/test/certs/localhost/cert.pem" \
    c87fb918d9bac8db11aa54493b5f0cf6e0725a3fe73f617d1c64737e1ab4caf9 localhost-cert.pem
fetch "$raw/test/certs/localhost/key.pem" \
    0977979255b0e0721c17335c056b627f66a43cf56e5a52f3cda81fb111ecf00e localhost-key.pem
tar xzf "$cache/pebble.tar.gz" -C "$cache"
tar xzf "$cache/challtestsrv.tar.gz" -C "$cache"
pebble="$cache/pebble-linux-amd64/linux/amd64/pebble"
challtestsrv="$cache/pebble-challtestsrv-linux-amd64/linux/amd64/pebble-challtestsrv"
# The release tarballs carry the binaries without execute permission.
chmod +x "$pebble" "$challtestsrv"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
acme_port=$(free_port); mgmt_port=$(free_port); dns_port=$(free_port); https_port=$(free_port)

work="$(mktemp -d /var/tmp/kronik-acme.XXXXXX)"
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

"$challtestsrv" -defaultIPv4 127.0.0.1 -defaultIPv6 "" -dnsserver "127.0.0.1:$dns_port" \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" -management "127.0.0.1:$(free_port)" \
    >"$work/challtestsrv.log" 2>&1 &
pids+=($!)
cat >"$work/pebble.json" <<EOF
{"pebble": {
  "listenAddress": "127.0.0.1:$acme_port",
  "managementListenAddress": "127.0.0.1:$mgmt_port",
  "certificate": "$cache/localhost-cert.pem",
  "privateKey": "$cache/localhost-key.pem",
  "httpPort": $(free_port),
  "tlsPort": $https_port,
  "ocspResponderURL": "",
  "externalAccountBindingRequired": false
}}
EOF
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 \
    "$pebble" -config "$work/pebble.json" -dnsserver "127.0.0.1:$dns_port" >"$work/pebble.log" 2>&1 &
pids+=($!)

cat >"$work/kronik.toml" <<EOF
[server]
data_dir = "$work/data"
api_socket = "$work/api.sock"
http_listen = "127.0.0.1:$https_port"
admin_listen = "127.0.0.1:$(free_port)"

[tls]
mode = "acme"
domains = ["kronik.test"]
acme_email = "ops@kronik.test"
acme_directory = "https://127.0.0.1:$acme_port/dir"
acme_ca_file = "$cache/minica.pem"
EOF

start_kronik() { # log file
    KRONIK_LOG=info "$bin" serve --config "$work/kronik.toml" >"$1" 2>&1 &
    pids+=($!)
    kronik_pid=$!
}

# Serves HTTPS with a certificate that chains to Pebble's root: the gateway
# answers a request for no route with ROUTE_NOT_FOUND.
https_ok() {
    curl -sS --max-time 5 --cacert "$work/pebble-root.pem" \
        --resolve "kronik.test:$https_port:127.0.0.1" "https://kronik.test:$https_port/" 2>/dev/null |
        grep -q ROUTE_NOT_FOUND
}

wait_for() { # description command...
    local what=$1; shift
    for _ in $(seq 1 120); do
        if "$@"; then return 0; fi
        sleep 0.5
    done
    echo "error: timed out waiting for $what" >&2
    for log in "$work"/*.log; do echo "== $log" >&2; tail -20 "$log" >&2; done
    exit 1
}

wait_for "Pebble" curl -fs --cacert "$cache/minica.pem" -o /dev/null "https://127.0.0.1:$acme_port/dir"
curl -fsS --cacert "$cache/minica.pem" "https://127.0.0.1:$mgmt_port/roots/0" >"$work/pebble-root.pem"

start_kronik "$work/kronik-1.log"
wait_for "a certificate from Pebble" https_ok
grep -q "ACME: installed a new certificate" "$work/kronik-1.log"
echo "ok: the gateway got a certificate from Pebble by TLS-ALPN-01 and serves HTTPS"

kill "$kronik_pid"
wait "$kronik_pid" 2>/dev/null || true
start_kronik "$work/kronik-2.log"
wait_for "the restarted gateway" https_ok
if grep -q "ACME: installed a new certificate" "$work/kronik-2.log"; then
    echo "error: the restart ordered a new certificate instead of using the cached one" >&2
    exit 1
fi
echo "ok: after a restart the gateway serves the cached certificate without a new order"
