#!/usr/bin/env bash
# Dogfood scenario 3 (issue #136): billing-ts with recorded traffic, then a
# build that inserts GET payments/healthz after charge (tail insertion, ADR
# 0147). The diff shows three added payment effects without shifting earlier
# ordinal pairs; propose needs approval for the new live GETs.
#
# Usage: [KRONIK_BIN=path] demo/payments-platform-reorder.sh [WORKDIR] [PORT]
# Defaults: /var/tmp/kronik-payments-reorder, port 47843, target/release/kronik.
# Needs root, runsc, curl, python3, examples/dist/billing-ts*.wasm (including
# billing-ts-reorder.wasm), and fake-payments OCI (built if missing).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

started=$(date +%s)
dir="${1:-/var/tmp/kronik-payments-reorder}"
port="${2:-47843}"
bin="${KRONIK_BIN:-target/release/kronik}"
billing=examples/dist/billing-ts.wasm
reorder=examples/dist/billing-ts-reorder.wasm
ledger=examples/dist/billing-ts-ledger.wasm
layout=examples/dist/fake-payments.oci
api_key="demo-key-$(date +%s%N | sha256sum | cut -c1-16)"

[ "$(id -u)" = 0 ] || { echo "$0 needs root (foreign actors run in gVisor)" >&2; exit 2; }
[ -x /usr/local/bin/runsc ] || { echo "needs runsc: scripts/install.sh installs gVisor" >&2; exit 2; }
for f in "$bin" "$billing" "$reorder" "$ledger"; do
    [ -e "$f" ] || { echo "missing $f (cargo build --release; scripts/build-examples-ts.sh)" >&2; exit 2; }
done
if [ ! -e "$layout/index.json" ]; then
    scripts/build-foreign-examples.sh --only fake-payments
fi

pid=""
cleanup() {
    if [ -n "$pid" ]; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
if [ -d "$dir" ]; then
    umount "$dir/run/runsc/null-netns" 2>/dev/null || true
    rm -rf "$dir"
fi
umask 077
mkdir -p "$dir"
sock="$dir/api.sock"
gw="http://127.0.0.1:$port"
image="oci-layout:$(realpath "$layout")"

step() { printf '\n== %s (%ss)\n' "$1" "$(( $(date +%s) - started ))"; }
fail() { echo "FAIL: $*" >&2; tail -20 "$dir/serve.log" >&2 || true; exit 1; }
api() {
    printf '%s' "${3:-}" | curl -s --unix-socket "$sock" -X "$1" \
        -H 'content-type: application/json' ${3:+--data-binary @-} "http://kronik$2" ||
        fail "API $1 $2"
}
field() { python3 -c 'import json,sys; v=json.loads(sys.argv[1]); print(eval(sys.argv[2]))' "$1" "$2"; }
b64() { python3 -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1],"rb").read()).decode())' "$1"; }
http() {
    curl -s -o "$dir/out" -w '%{http_code}' -X "$1" -H 'content-type: application/json' \
        ${3:+--data-binary "$3"} "$gw$2" >"$dir/code" || fail "$1 $2"
    printf '%s %s' "$(cat "$dir/code")" "$(cat "$dir/out")"
}
invoice() {
    local c="$1"
    [ "$(http PUT "/$billing_kind/$c" "{\"name\":\"$c\",\"country\":\"$2\",\"vat_id\":null}" | cut -d' ' -f1)" -lt 300 ] ||
        fail "customer $c"
    r=$(api POST "/v1/actors/$billing_kind/$c/messages" \
        "{\"name\":\"configure\",\"content_type\":\"application/json\",\"text\":\"{\\\"api_key_secret\\\":\\\"$secret\\\"}\",\"reason\":\"demo\"}")
    [ "$(field "$r" 'v["outcome"]["kind"]')" = committed ] || fail "configure $c: $r"
    [ "$(http POST "/$billing_kind/$c/invoices/$3" \
        '{"currency":"EUR","lines":[{"description":"widgets","quantity":4,"unit_price":2500}]}' | cut -d' ' -f1)" -lt 300 ] ||
        fail "invoice $c/$3"
    http POST "/$billing_kind/$c/invoices/$3/finalize"
}

step "serve"
printf '[server]\ndata_dir = "%s/data"\n\n[foreign]\nrun_dir = "%s/run"\n\n[fork]\nlive_allowlist = ["payments.internal"]\n' "$dir" "$dir" >"$dir/kronik.toml"
setsid "$bin" serve --config "$dir/kronik.toml" --http-listen "127.0.0.1:$port" \
    --admin-listen 127.0.0.1:0 --api-socket "$sock" >>"$dir/serve.log" 2>&1 &
pid=$!
for _ in $(seq 400); do
    curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null 2>&1 && break
    sleep 0.05
done
curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null || fail "daemon not healthy"

manifest=$(api POST /v1/deployments "{\"wasm_base64\":\"$(b64 "$billing")\",\"dry_run\":true,\"reason\":\"dogfood manifest\"}")
billing_kind=$(field "$manifest" 'v["deployment"]["kind"]')
manifest=$(api POST /v1/deployments "{\"wasm_base64\":\"$(b64 "$ledger")\",\"dry_run\":true,\"reason\":\"dogfood manifest\"}")
ledger_kind=$(field "$manifest" 'v["deployment"]["kind"]')
secret="payments-key-standalone"

step "fake-payments foreign actor"
api PUT "/v1/secrets/$secret" "{\"text\":\"$api_key\",\"reason\":\"dogfood\"}" >/dev/null
r=$(api POST /v1/foreign "{\"name\":\"payments.internal\",\"image\":\"$image\",\"port\":8080,\"cpu_millis\":1000,\"memory_bytes\":268435456,\"secrets\":[\"PAYMENTS_API_KEY=$secret\"],\"reason\":\"dogfood\"}")
[ "$(field "$r" 'v["foreign"]["status"]["state"]')" = running ] || fail "foreign add: $r"

step "deploy billing and ledger"
for w in "$billing" "$ledger"; do
    api POST /v1/deployments "{\"wasm_base64\":\"$(b64 "$w")\",\"reason\":\"dogfood\"}" >/dev/null
done
api POST /v1/grants "{\"kind\":\"$billing_kind\",\"capability\":\"foreign:payments.internal\",\"delivery\":\"idempotency-keyed\",\"reason\":\"dogfood\"}" >/dev/null
api POST /v1/grants "{\"kind\":\"$billing_kind\",\"capability\":\"http:payments.internal\",\"delivery\":\"replay-safe\",\"reason\":\"dogfood\"}" >/dev/null
api POST /v1/grants "{\"kind\":\"$billing_kind\",\"capability\":\"secret:$secret\",\"reason\":\"dogfood\"}" >/dev/null
fork_lsn=$(field "$(api GET /v1/health)" 'v["applied_lsn"]')

step "fork before traffic"
r=$(api POST /v1/forks "{\"at\":$fork_lsn,\"name\":\"reorder\",\"reason\":\"dogfood scenario 3\"}")
[ "$(field "$r" 'v["fork"]["name"]')" = reorder ] || fail "fork: $r"

step "record billing traffic"
for c in se-1:SE de-1:DE us-1:US; do
    out=$(invoice "${c%%:*}" "${c##*:}" inv-1)
    [ "${out%% *}" = 200 ] || fail "finalize ${c%%:*}: $out"
done
out=$(invoice declined-1 SE inv-1)
[ "${out%% *}" = 500 ] || fail "declined card must fail the turn: $out"

step "deploy reorder on fork, replay"
api POST /v1/forks/reorder/deployments "{\"wasm_base64\":\"$(b64 "$reorder")\",\"reason\":\"dogfood\"}" >/dev/null
r=$(api POST /v1/forks/reorder/replay '{"reason":"dogfood"}')
divergent=$(field "$r" 'v["summary"]["divergent_turns"]')
live=$(field "$r" 'v["summary"]["live"]')
# Three paid finalizes each gain one live GET (billing + ledger diverge).
[ "$divergent" = 6 ] || fail "expected 6 divergent turns (3 billing + 3 ledger): $r"
[ "$live" = 3 ] || fail "expected 3 live payment health checks: $r"
[ "$(field "$r" 'v["summary"]["changed"]')" = True ] || fail "replay must report a change: $r"

step "diff shows tail insertions"
d=$(api GET "/v1/forks/reorder/diff")
added=$(field "$d" 'v["effects"]["added"]')
changed=$(field "$d" 'v["effects"]["changed"]')
[ "$added" = 3 ] || fail "expected 3 added payment effects: $d"
[ "$changed" = 0 ] || fail "earlier ordinal pairs must not cascade: $d"

step "propose inserted health check"
r=$(api POST /v1/proposals "{\"wasm_base64\":[\"$(b64 "$reorder")\"],\"reason\":\"dogfood: ping after charge\"}")
[ "$(field "$r" 'v["proposal"]["summary"]["live"]')" = 3 ] || fail "proposal live count: $r"
outcome=$(field "$r" 'v["proposal"]["policy"]["outcome"]')
[ "$outcome" = deny ] || [ "$outcome" = require_approval ] ||
    fail "live payment GETs must not allow promotion: $r"
echo "$r" | python3 -c 'import json,sys; fired=[r["name"] for r in json.load(sys.stdin)["proposal"]["policy"]["fired"]]; sys.exit(0 if "low-grounding-needs-approval" in fired else 1)' ||
    fail "low-grounding-needs-approval must fire: $r"

cleanup
pid=""
echo
printf 'PASS: payments-platform reorder in %ss\n' "$(( $(date +%s) - started ))"