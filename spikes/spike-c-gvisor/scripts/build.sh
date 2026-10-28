#!/usr/bin/env bash
# Builds the static spike binaries and packs the test image into an OCI
# layout under out/. Runs on the development machine (Debian or Ubuntu with
# rustup and apt).
#
# Output:
#   out/bin/                    echo-server, netprobe, uds-shim, bridge-bench, oci-tool
#   out/foreign-echo-layout/    OCI layout with the image foreign-echo:spike
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
target=x86_64-unknown-linux-musl
cargo build --release --locked --target "$target"

rm -rf out
mkdir -p out/bin out/stage/l1 out/stage/l2 out/deb
for b in echo-server netprobe uds-shim bridge-bench oci-tool; do
    cp "target/$target/release/$b" out/bin/
done

# A static busybox from the distribution's busybox-static package, for
# diagnostics inside the sandbox (ip, nslookup, wget). apt verifies the
# package against the signed repository metadata.
(cd out/deb && apt-get download busybox-static 2>/dev/null >/dev/null && dpkg-deb -x busybox-static_*.deb root)
busybox=out/deb/root/usr/bin/busybox
file "$busybox" | grep -q 'statically linked' || {
    echo "$busybox is not statically linked" >&2
    exit 1
}

# Layer 1 (gzip): the server, users, a file and a directory that layer 2
# removes again.
l1=out/stage/l1
mkdir -p "$l1/bin" "$l1/etc" "$l1/srv/old/sub" "$l1/tmp"
cp out/bin/echo-server "$l1/bin/"
printf 'root:x:0:0:root:/root:/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n' >"$l1/etc/passwd"
printf 'root:x:0:\nnogroup:x:65534:\n' >"$l1/etc/group"
echo "layer 1: deleted by a whiteout in layer 2" >"$l1/etc/stale.conf"
echo "layer 1: hidden by the opaque marker in layer 2" >"$l1/srv/old/a.txt"
echo "layer 1: hidden by the opaque marker in layer 2" >"$l1/srv/old/sub/b.txt"
chmod 1777 "$l1/tmp"

# Layer 2 (uncompressed tar): diagnostics, a whiteout and an opaque directory.
l2=out/stage/l2
mkdir -p "$l2/bin" "$l2/etc" "$l2/srv/old"
cp out/bin/netprobe "$l2/bin/"
cp "$busybox" "$l2/bin/"
: >"$l2/etc/.wh.stale.conf"
: >"$l2/srv/old/.wh..wh..opq"
echo "layer 2: the only entry left in /srv/old" >"$l2/srv/old/c.txt"

out/bin/oci-tool pack --out out/foreign-echo-layout --ref foreign-echo:spike \
    --layer "gzip:$l1" --layer "tar:$l2" \
    --entrypoint '["/bin/echo-server"]' --cmd '["--listen","0.0.0.0:8080"]' \
    --env PATH=/bin --env GREETING=hello-from-the-image-config \
    --workdir /srv --user nobody --expose 8080/tcp
