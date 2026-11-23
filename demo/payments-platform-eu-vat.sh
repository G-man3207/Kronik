#!/usr/bin/env bash
# Dogfood scenario 2 (issue #136): domestic-VAT billing-ts traffic, then an EU
# VAT rule change on the fork. Only non-SE finalize turns diverge; propose
# hits payments-must-be-exact -> require_approval.
#
# Usage: [KRONIK_BIN=path] demo/payments-platform-eu-vat.sh [WORKDIR] [PORT]
# Defaults: /var/tmp/kronik-payments-eu-vat, port 47842, target/release/kronik.
# Needs root, runsc, curl, python3, examples/dist/billing-ts*.wasm (including
# billing-ts-eu-vat.wasm), and fake-payments OCI (built if missing).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

started=$(date +%s)
dir="${1:-/var/tmp/kronik-payments-eu-vat}"
port="${2:-47842}"
bin="${KRONIK_BIN:-target/release/kronik}"
billing=examples/dist/billing-ts.wasm
eu_vat=examples/dist/billing-ts-eu-vat.wasm
ledger=examples/dist/billing-ts-ledger.wasm
. demo/payments-lib.sh

payments_preflight "$eu_vat"
payments_serve
payments_deploy

step "fork before traffic"
r=$(api POST /v1/forks "{\"at\":$fork_lsn,\"name\":\"eu-vat\",\"reason\":\"dogfood scenario 2\"}")
[ "$(field "$r" 'v["fork"]["name"]')" = eu-vat ] || fail "fork: $r"

step "record billing traffic (domestic VAT on every customer)"
for c in se-1:SE de-1:DE us-1:US; do
    out=$(invoice "${c%%:*}" "${c##*:}" inv-1)
    [ "${out%% *}" = 200 ] || fail "finalize ${c%%:*}: $out"
done
out=$(invoice declined-1 SE inv-1)
[ "${out%% *}" = 500 ] || fail "declined card must fail the turn: $out"

step "deploy EU VAT on fork, replay"
api POST /v1/forks/eu-vat/deployments "{\"wasm_base64\":\"$(b64 "$eu_vat")\",\"reason\":\"dogfood\"}" >/dev/null
r=$(api POST /v1/forks/eu-vat/replay '{"reason":"dogfood"}')
divergent=$(field "$r" 'v["summary"]["divergent_turns"]')
consequences=$(field "$r" 'v["summary"]["consequences"]')
# SE matches; DE and US finalizes (and their ledger posts) diverge from domestic VAT.
[ "$divergent" = 4 ] || fail "expected 4 divergent turns (DE and US billing + ledger): $r"
[ "$consequences" = 2 ] || fail "expected 2 payment consequences: $r"
[ "$(field "$r" 'v["summary"]["changed"]')" = True ] || fail "EU VAT replay must change payment effects: $r"

step "propose EU VAT change"
r=$(api POST /v1/proposals "{\"wasm_base64\":[\"$(b64 "$eu_vat")\"],\"reason\":\"dogfood: apply EU VAT\"}")
[ "$(field "$r" 'v["proposal"]["summary"]["divergent_turns"]')" = 4 ] || fail "proposal diverged wrong: $r"
[ "$(field "$r" 'v["proposal"]["policy"]["outcome"]')" = require_approval ] ||
    fail "payments-must-be-exact must require approval: $r"

payments_cleanup
pid=""
echo
printf 'PASS: payments-platform EU VAT in %ss\n' "$(( $(date +%s) - started ))"
