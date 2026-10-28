#!/usr/bin/env bash
# The M7 demo end to end with the real binary (brief: billing-ts with
# fake-payments): fake-payments runs as the foreign actor payments.internal
# in gVisor with its API key injected from the secret store; billing-ts and
# its ledger charge invoices through foreign://payments.internal; a declined
# card fails the turn and the ledger's posting is compensated. Then the
# "Apply EU VAT" change is proposed: it changes the charges, so the default
# policy rule payments-must-be-exact requires approval; promote is refused
# until it is approved, and the new VAT applies after promote.
#
# Usage: [KRONIK_BIN=path] demo/billing.sh [WORKDIR] [PORT]
# Defaults: /var/tmp/kronik-billing, port 47831, target/release/kronik.
# Needs root, runsc (/usr/local/bin/runsc), curl, python3, the components
# from scripts/build-examples-ts.sh (examples/dist/billing-ts*.wasm) and the
# image from scripts/build-foreign-examples.sh (built here if missing).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

started=$(date +%s)
dir="${1:-/var/tmp/kronik-billing}"
port="${2:-47831}"
bin="${KRONIK_BIN:-target/release/kronik}"
billing=examples/dist/billing-ts.wasm
ledger=examples/dist/billing-ts-ledger.wasm
eu_vat=examples/dist/billing-ts-eu-vat.wasm
layout=examples/dist/fake-payments.oci
api_key="demo-key-$(date +%s%N | sha256sum | cut -c1-16)"

[ "$(id -u)" = 0 ] || { echo "demo/billing.sh needs root (foreign actors run in gVisor)" >&2; exit 2; }
[ -x /usr/local/bin/runsc ] || { echo "needs runsc: scripts/install.sh installs gVisor" >&2; exit 2; }
for f in "$bin" "$billing" "$ledger" "$eu_vat"; do
    [ -e "$f" ] || { echo "missing $f (cargo build --release; scripts/build-examples-ts.sh)" >&2; exit 2; }
done
[ -e "$layout/index.json" ] || scripts/build-foreign-examples.sh --only fake-payments

sock="$dir/api.sock"
gw="http://127.0.0.1:$port"
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
mkdir -p "$dir"

step() { printf '\n== %s (%ss)\n' "$1" "$(( $(date +%s) - started ))"; }
fail() { echo "FAIL: $*" >&2; tail -20 "$dir/serve.log" >&2 || true; exit 1; }
api() { # METHOD PATH [JSON]
    printf '%s' "${3:-}" | curl -s --unix-socket "$sock" -X "$1" \
        -H 'content-type: application/json' ${3:+--data-binary @-} "http://kronik$2" ||
        fail "API $1 $2"
}
field() { python3 -c 'import json,sys; v=json.loads(sys.argv[1]); print(eval(sys.argv[2]))' "$1" "$2"; }
b64() { python3 -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1],"rb").read()).decode())' "$1"; }
http() { # METHOD PATH [JSON] -> "<status> <body>"
    curl -s -o "$dir/out" -w '%{http_code}' -X "$1" -H 'content-type: application/json' \
        ${3:+--data-binary "$3"} "$gw$2" >"$dir/code" || fail "$1 $2"
    printf '%s %s' "$(cat "$dir/code")" "$(cat "$dir/out")"
}
invoice() { # CUSTOMER COUNTRY ID -> "<status> <body>" of finalize
    local c="$1"
    [ "$(http PUT "/billing/$c" "{\"name\":\"$c\",\"country\":\"$2\",\"vat_id\":null}" | cut -d' ' -f1)" -lt 300 ] ||
        fail "customer $c"
    r=$(api POST "/v1/actors/billing/$c/messages" \
        '{"name":"configure","content_type":"application/json","text":"{\"api_key_secret\":\"payments-api-key\"}","reason":"demo"}')
    [ "$(field "$r" 'v["outcome"]["kind"]')" = committed ] || fail "configure $c: $r"
    [ "$(http POST "/billing/$c/invoices/$3" \
        '{"currency":"EUR","lines":[{"description":"widgets","quantity":4,"unit_price":2500}]}' | cut -d' ' -f1)" -lt 300 ] ||
        fail "invoice $c/$3"
    http POST "/billing/$c/invoices/$3/finalize"
}

step "serve, with [foreign] run_dir under $dir"
printf '[server]\ndata_dir = "%s/data"\n\n[foreign]\nrun_dir = "%s/run"\n' "$dir" "$dir" >"$dir/kronik.toml"
setsid "$bin" serve --config "$dir/kronik.toml" --http-listen "127.0.0.1:$port" \
    --admin-listen 127.0.0.1:0 --api-socket "$sock" >>"$dir/serve.log" 2>&1 &
pid=$!
for _ in $(seq 400); do
    curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null 2>&1 && break
    sleep 0.05
done

step "fake-payments as the foreign actor payments.internal (gVisor)"
api PUT /v1/secrets/payments-api-key "{\"text\":\"$api_key\",\"reason\":\"demo: the payments API key\"}" >/dev/null
r=$(api POST /v1/foreign "{\"name\":\"payments.internal\",\"image\":\"oci-layout:$(realpath "$layout")\",\"port\":8080,\"cpu_millis\":1000,\"memory_bytes\":268435456,\"secrets\":[\"PAYMENTS_API_KEY=payments-api-key\"],\"reason\":\"demo: the payments service\"}")
[ "$(field "$r" 'v["foreign"]["status"]["state"]')" = running ] || fail "foreign add: $r"
echo "payments.internal: $(field "$r" 'v["foreign"]["image"]'), $(field "$r" 'v["foreign"]["isolation"]') ($(field "$r" 'v["foreign"]["platform"]'))"

step "deploy billing and ledger; grants"
for w in "$billing" "$ledger"; do
    r=$(api POST /v1/deployments "{\"wasm_base64\":\"$(b64 "$w")\",\"reason\":\"demo\"}")
    echo "deployed $(field "$r" 'v["deployment"]["kind"]') $(field "$r" 'v["deployment"]["code_hash"]')"
done
epoch0=$(field "$r" 'v["deployment"]["epoch"]')
api POST /v1/grants '{"kind":"billing","capability":"foreign:payments.internal","delivery":"idempotency-keyed","reason":"demo: billing charges invoices"}' >/dev/null
api POST /v1/grants '{"kind":"billing","capability":"secret:payments-api-key","reason":"demo: the charges carry the API key"}' >/dev/null

step "invoices: Swedish, German, Finnish and US customers, and a declined card"
for c in se-1:SE se-2:SE se-3:SE de-1:DE de-2:DE fi-1:FI us-1:US; do
    out=$(invoice "${c%%:*}" "${c##*:}" inv-1)
    [ "${out%% *}" = 200 ] || fail "finalize ${c%%:*}: $out"
    echo "${c%%:*}: paid, total $(field "${out#* }" 'v["total"]'), charge $(field "${out#* }" 'v["charge"]')"
done
out=$(invoice declined-1 SE inv-1)
[ "${out%% *}" = 500 ] || fail "a declined card must fail the turn: $out"
echo "declined-1: $(field "${out#* }" 'v["error"]["message"]')"
out=$(http GET /ledger/declined-1)
echo "ledger/declined-1: ${out#* }"
# The failed turn's compensation reversed the posting: a post and its
# reverse, and nothing left on the balance.
python3 - "${out#* }" <<'PY' || fail "the compensation did not reverse the posting: $out"
import json, sys
ledger = json.loads(sys.argv[1])
entries = [[e["kind"], e["amount"]] for e in ledger["entries"]]
assert entries == [["post", 12500], ["reverse", -12500]], entries
assert ledger["balance"] == {"EUR": 0}, ledger["balance"]
PY

step "propose Apply EU VAT"
r=$(api POST /v1/proposals "{\"wasm_base64\":[\"$(b64 "$eu_vat")\"],\"reason\":\"demo: apply EU VAT\"}")
id=$(field "$r" 'v["proposal"]["id"]')
outcome=$(field "$r" 'v["proposal"]["policy"]["outcome"]')
echo "proposal $id: policy $outcome"
[ "$outcome" = require_approval ] || fail "the policy must require approval: $r"
curl -s --unix-socket "$sock" "http://kronik/v1/proposals/$id/diff?format=md" >"$dir/proposal-diff.md"
grep -n 'payments.internal' "$dir/proposal-diff.md" | head -5

step "promote without approval is refused"
r=$(api POST "/v1/proposals/$id/promote" '{"reason":"demo"}')
code=$(field "$r" 'v.get("error",{}).get("code")')
[ "$code" = APPROVAL_REQUIRED ] || fail "promote must need approval: $r"
echo "promote: $code"

step "approve, then promote"
api POST "/v1/proposals/$id/approve" '{"reason":"demo: the new VAT is intended"}' >/dev/null
r=$(api POST "/v1/proposals/$id/promote" '{"reason":"demo: apply EU VAT"}')
epoch=$(field "$r" 'v["deployment"]["epoch"]')
[ "$epoch" -gt "$epoch0" ] ||
    fail "promote must switch to a newer epoch: $epoch, still at $epoch0"
echo "deployment epoch $epoch, was $epoch0"

step "the new VAT applies"
out=$(invoice de-3 DE inv-1)
[ "${out%% *}" = 200 ] || fail "finalize after promote: $out"
total=$(field "${out#* }" 'v["total"]')
echo "de-3: total $total"
[ "$total" = 11900 ] || fail "German VAT after promote: $total"

step "stop: the sandbox stops with the daemon; the API key never reached the log"
# While it runs, the key is in the sandbox's config.json (mode 0600, the
# program's environment); it is deleted with the sandbox.
cleanup
pid=""
[ -z "$(runsc --root "$dir/run/runsc" list -quiet 2>/dev/null)" ] || fail "a sandbox outlived the daemon"
if grep -rqa "$api_key" "$dir/data" "$dir/serve.log"; then fail "the API key leaked"; fi
echo "no sandbox left; the key is not in $dir/data or serve.log"

echo
echo "PASS demo/billing.sh in $(( $(date +%s) - started ))s"
