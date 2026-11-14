#!/usr/bin/env bash
# Required installed rootless proof, using ONLY exact prebuilt artifacts.
# Usage: timeout --signal=TERM --kill-after=10s 3900s bash scripts/proof-rootless.sh \
#   HELPER PRODUCT PROBE_LAYOUT PG_LAYOUT PAYMENTS_LAYOUT OUTPUT_PARENT UID GID SUBID OPERATOR_UID \
#   [--microvm DIR] [--max-runtime SECONDS]
# Add --microvm DIR for required mapped DIRECTORY metadata proof before real VM actors.
# --max-runtime (default 3600) bounds the transient manager of the proof, and so the whole
# run: systemd ends it then, in the middle of whatever is running. A slow machine needs more;
# the outer timeout above must exceed it.
#
# THIS CHANGES THE HOST. It starts a transient service of the host's service manager that
# keeps the whole bounding set of root except nine capabilities (CAP_SYS_TIME, CAP_SYS_BOOT,
# CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_MKNOD, CAP_MAC_ADMIN, CAP_MAC_OVERRIDE,
# CAP_AUDIT_CONTROL, CAP_NET_ADMIN), so it still holds CAP_SYS_ADMIN, CAP_SYS_PTRACE,
# CAP_DAC_OVERRIDE, CAP_SETUID/GID and CAP_NET_RAW, in the host's user and network
# namespaces, by design (the
# oracle must prove that sandboxes cannot reach host listeners and must read true host
# uids), and it opens listeners on the host's real addresses. A bug in the system under
# test then runs against a live host. So it runs only on a machine that holds nothing worth
# protecting, and only after the operator has said so, once, as root, on that machine:
#   cat /etc/machine-id > /etc/kronik-proof-host
# (bound to the machine id, so that it cannot be copied to another host by accident; it is
# no check that the machine is virtual, because the KVM proof may run on bare metal). The
# helper's `create` refuses to run without it. It also refuses ids that the name service or
# a running process uses (the ends of the subordinate range included), and an
# OUTPUT_PARENT without room for the copies and a 1 GiB reserve, which is a floor: plan for
# about 12 GiB free (an estimate; the oracle's own budget is 8 GiB of allocated disk). Every
# run retains its tree under OUTPUT_PARENT, which is never pruned (`rm -r` it once its
# evidence is read). If a run is killed without its cleanup (SIGKILL skips the traps),
# `HELPER cleanup <retained tree>` recovers: the helper prints that command at the end of
# `create`.
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
runtime=()
proof_mode=--program-proof
while [ "$#" -gt 0 ]; do
    case "$1" in
        --microvm)
            [ "$#" -ge 2 ] && [ "${#microvm[@]}" = 0 ] || { echo "expected one --microvm ARTIFACT_DIR" >&2; exit 2; }
            isolation=microvm
            proof_mode=--microvm-proof
            microvm=("$2")
            shift 2;;
        --max-runtime)
            [ "$#" -ge 2 ] && [ "${#runtime[@]}" = 0 ] || { echo "expected one --max-runtime SECONDS" >&2; exit 2; }
            runtime=(--max-runtime "$2")
            shift 2;;
        *) echo "expected --microvm ARTIFACT_DIR and/or --max-runtime SECONDS, not: $1" >&2; exit 2;;
    esac
done
cat >&2 <<'NOTICE'
proof-rootless: this changes the host (a transient service of the host's manager with most of
root's capabilities in the host's namespaces; listeners on the host's addresses). It runs only
on a machine whose operator has said that it is disposable, as root, once, on that machine:
    cat /etc/machine-id > /etc/kronik-proof-host
NOTICE
for binary in "$helper" "$product"; do [ -x "$binary" ] || { echo "missing prebuilt $binary" >&2; exit 1; }; done
umask 077
proof=$("$helper" create "$parent" "$product" "$probe" "$pg" "$payments" "$uid" "$gid" "$subid" "$operator" "${microvm[@]}" "${runtime[@]}")
[ -d "$proof" ] || { echo "fixture helper did not return its exact proof root" >&2; exit 1; }
echo "rootless evidence retained: $proof"
echo "if this run is killed without its cleanup: $helper cleanup $proof" >&2
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
