#!/usr/bin/env bash
# Checks the unpacker against layers written by a real builder: builds a
# small multi-layer image with BuildKit (docker buildx), exports it as an OCI
# layout and turns it into a bundle with oci-tool. Runs on the development
# machine; needs docker with buildx and the containerd image store.
# Output: results/10-buildkit-check.txt
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p results
exec > >(tee results/10-buildkit-check.txt) 2>&1
echo "# 10-buildkit-check at $(date -u +%FT%TZ), $(docker buildx version | cut -d' ' -f1-2)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/ctx" "$work/layout"
cat >"$work/ctx/Dockerfile" <<'EOF'
FROM busybox:1.37-musl
RUN mkdir -p /srv/old/sub && echo a > /srv/old/a.txt && echo b > /srv/old/sub/b.txt \
 && echo stale > /etc/stale.conf && ln -s /srv /opt-link
RUN rm /etc/stale.conf && rm -rf /srv/old && mkdir /srv/old && echo c > /srv/old/c.txt \
 && echo via-link > /opt-link/via-link.txt
EOF
cat "$work/ctx/Dockerfile"

docker buildx build -q --output "type=oci,dest=$work/layout.tar" "$work/ctx" >/dev/null
tar -xf "$work/layout.tar" -C "$work/layout"
manifest=$(jq -r '.manifests[0].digest' "$work/layout/index.json" | cut -d: -f2)
for layer in $(jq -r '.layers[1:][] | .digest' "$work/layout/blobs/sha256/$manifest" | cut -d: -f2); do
    echo "--- entries of layer sha256:$layer"
    tar -tvzf "$work/layout/blobs/sha256/$layer"
done

echo "--- oci-tool bundle"
out/bin/oci-tool bundle --layout "$work/layout" --bundle "$work/bundle"
rootfs=$work/bundle/rootfs
echo "--- result"
echo "/etc/stale.conf: $(test -e "$rootfs/etc/stale.conf" && echo present || echo absent)"
echo "/srv/old: $(ls "$rootfs/srv/old")"
echo "/opt-link: $(readlink "$rootfs/opt-link")"
echo "/srv/via-link.txt: $(cat "$rootfs/srv/via-link.txt")"
echo "whiteout files left: $(find "$rootfs" -name '.wh.*' | wc -l)"
