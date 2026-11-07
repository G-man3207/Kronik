#!/usr/bin/env bash
# Required installed rootless proof, using ONLY exact prebuilt artifacts.
# Usage: timeout --signal=TERM --kill-after=10s 1800s bash scripts/proof-rootless.sh \
#   HELPER PRODUCT PROBE_LAYOUT PG_LAYOUT PAYMENTS_LAYOUT OUTPUT_PARENT UID GID SUBID OPERATOR_UID
# Add --microvm DIR for required mapped DIRECTORY metadata proof before real VM actors.
# This wrapper requires an Ubuntu 24.04 host with systemd 255 and AppArmor's
# restriction on unprivileged user namespaces active, because that is the
# target of the brief; Kronik has not been tested there. On another host use
# the explicit helper and conformance commands of ADR 0064: their result then
# says nothing about Ubuntu 24.04.
set -euo pipefail
[ "$#" -ge 10 ] || { echo "proof-rootless: ten explicit fixture/artifact arguments required" >&2; exit 2; }
helper=$1 product=$2 probe=$3 pg=$4 payments=$5 parent=$6 uid=$7 gid=$8 subid=$9 operator=${10}
shift 10
isolation=gvisor
microvm=()
proof_mode=--program-proof
if [ "$#" -gt 0 ]; then
    [ "$#" = 2 ] && [ "$1" = --microvm ] || { echo "expected --microvm ARTIFACT_DIR" >&2; exit 2; }
    isolation=microvm
    proof_mode=--microvm-proof
    microvm=("$2")
fi
for binary in "$helper" "$product"; do [ -x "$binary" ] || { echo "missing prebuilt $binary" >&2; exit 1; }; done
umask 077
proof=$("$helper" create "$parent" "$product" "$probe" "$pg" "$payments" "$uid" "$gid" "$subid" "$operator" "${microvm[@]}")
[ -d "$proof" ] || { echo "fixture helper did not return its exact proof root" >&2; exit 1; }
echo "rootless evidence retained: $proof"
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    "$helper" cleanup "$proof" >>"$proof/cleanup.log" 2>&1 || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$helper" init "$proof" rootless >"$proof/initial-init.log" 2>&1
bash "$(dirname "${BASH_SOURCE[0]}")/conformance-rootless.sh" --fixture "$proof" \
    --isolation "$isolation" "$proof_mode" --ubuntu-required
