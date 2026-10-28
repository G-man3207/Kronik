#!/usr/bin/env bash
# Starts the sandbox with the systrap platform on a host without /dev/kvm:
# first with --network=none, then in the configuration ADR 0003 picks.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 03-start
stop_all

section "No /dev/kvm on this host"
ls -l /dev/kvm 2>&1

section "The kvm platform cannot start here (kronik doctor: KVM_UNAVAILABLE)"
rs --platform=kvm --network=none run --detach --bundle "$BUNDLE" kvm-probe </dev/null 2>&1 | tail -1
rs delete --force kvm-probe >/dev/null 2>&1

section "systrap with --network=none"
t0=$(date +%s%N)
echo "\$ runsc --root $ROOT --platform=systrap --network=none run --detach --bundle $BUNDLE $ID"
rs --platform=systrap --network=none run --detach --bundle "$BUNDLE" "$ID" >>"$LOGS/$ID.log" 2>&1 </dev/null
echo "runsc run --detach returned after $(ms_since "$t0") ms with status $?"
show rs list
show rs state "$ID"
show rs ps "$ID"

section "Host processes of the sandbox"
ps -o pid,ppid,user,rss,args -p "$(pgrep -d, -f "^runsc-(sandbox|gofer).*$ID")" | cut -c1-200

section "Inside: GET /info on the sandbox's own loopback (runsc exec busybox wget)"
rs exec "$ID" /bin/busybox wget -qO- http://127.0.0.1:8080/info </dev/null

section "Container stdout and stderr: runsc run --detach hands the caller's stdio to the container"
cat "$LOGS/$ID.log"
stop_all

section "systrap with --network=sandbox in a network namespace that has only lo (the configuration ADR 0003 picks)"
t0=$(date +%s%N)
echo "\$ ip netns add $NETNS && ip -n $NETNS link set lo up"
echo "\$ runsc --root $ROOT --platform=systrap --network=sandbox run --detach --bundle $BUNDLE_PF $ID"
BRIDGE=pf start_sandbox
echo "netns setup and runsc run --detach took $(ms_since "$t0") ms"
jq -c '.linux.namespaces' "$BUNDLE_PF/config.json"
BRIDGE=pf ready "$(BRIDGE=pf target)"
BRIDGE=pf get /info
stop_all
