#!/usr/bin/env bash
# Turns the image in the OCI layout into runsc bundles: verifies digests,
# unpacks the layers with whiteouts and opaque directories, and generates
# config.json from the image config plus the operator's overrides
# (--cpu 1 --memory 512Mi, bind mounts, cgroup path).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
record 02-bundle
stop_all

common=(--layout "$LAYOUT" --ref foreign-echo:spike --replace
    --cpu 1 --memory 512Mi --pids 256
    --bind "$SOCKDIR:/.kronik/sock" --bind "$BIN:/.kronik/bin:ro" --bind "$DATADIR:/data"
    --cgroups-path /kronik/foreign-echo --hostname echo)

section "Bundle for --network=none (host-uds bridge)"
show "$BIN/oci-tool" bundle "${common[@]}" --bundle "$BUNDLE"

section "Bundle for --network=sandbox in netns $NETNS (port-forward bridge)"
show "$BIN/oci-tool" bundle "${common[@]}" --bundle "$BUNDLE_PF" --netns "/var/run/netns/$NETNS"

section "Layout"
cat "$LAYOUT/index.json"
echo
ls -l "$LAYOUT/blobs/sha256"

section "Rootfs"
cd "$BUNDLE"
find rootfs | sort
echo "whiteout files left in the rootfs: $(find rootfs -name '.wh.*' | wc -l)"
echo "/etc/stale.conf (whited out in layer 2): $(test -e rootfs/etc/stale.conf && echo present || echo absent)"
echo "/srv/old (opaque in layer 2): $(ls rootfs/srv/old)"
stat -c '%A %U:%G %n' rootfs/tmp rootfs/bin/echo-server

section "config.json"
jq '{process: .process | {user, args, env, cwd, noNewPrivileges}, root, hostname, mounts: [.mounts[] | select(.type == "bind")], linux: .linux | {namespaces, resources, cgroupsPath}}' config.json
echo "port-forward bundle differs in: $(diff <(jq -S . "$BUNDLE/config.json") <(jq -S . "$BUNDLE_PF/config.json") | grep '^[<>]' | tr -s ' ')"

section "Tampered layout is rejected"
tampered=$(mktemp -d)
cp -r "$LAYOUT/." "$tampered/"
layer=$(jq -r '.layers[0].digest' "$tampered/blobs/sha256/$(jq -r '.manifests[0].digest' "$LAYOUT/index.json" | cut -d: -f2)" | cut -d: -f2)
chmod u+w "$tampered/blobs/sha256/$layer"
printf 'x' >>"$tampered/blobs/sha256/$layer"
"$BIN/oci-tool" bundle --layout "$tampered" --bundle "$tampered/bundle" || echo "(rejected as expected, exit $?)"
rm -rf "$tampered"
