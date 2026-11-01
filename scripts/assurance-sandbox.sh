#!/usr/bin/env bash
# Run an offline local proof with read-only source/toolchain and bounded scratch.
set -euo pipefail
if [ "$#" -lt 4 ]; then
    echo 'usage: bash scripts/assurance-sandbox.sh SOURCE TOOLCHAIN LOCAL_IMAGE COMMAND [ARG...]' >&2
    exit 2
fi
source_root=$(realpath "$1")
toolchain=$(realpath "$2")
image=$3
shift 3
registry=$(realpath "${CARGO_HOME:-$HOME/.cargo}/registry")
[ -x "$toolchain/bin/cargo" ] && [ -d "$source_root/.git" -o -f "$source_root/.git" ]
# Inspect, never pull: this command cannot download or alter a shared image.
image=$(docker image inspect "$image" --format '{{.Id}}')
name="kronik-assurance-$(id -u)-$$"
cleanup() { docker container rm --force "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM HUP
# Host /usr supplies only the already-installed compiler/linker tools. No host
# home, credentials, daemon sockets or retained artifact directory is mounted.
# UID 0 reads root-owned cached crates; all capabilities are dropped and every
# host input is read-only, with no host namespace, home or socket exposed.
timeout --signal=TERM --kill-after=10 900 docker run --rm --pull=never \
    --name "$name" --network=none --ipc=none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --user=0:0 \
    --cpus=3 --memory=8g --memory-swap=8g --pids-limit=128 \
    --ulimit cpu=600:600 --ulimit fsize=1073741824:1073741824 \
    --ulimit nofile=256:256 \
    --tmpfs /scratch:rw,exec,nosuid,nodev,size=6g,mode=1777 \
    --mount "type=bind,source=$source_root,target=/source,readonly" \
    --mount "type=bind,source=$toolchain,target=/toolchain,readonly" \
    --mount "type=bind,source=$registry,target=/registry,readonly" \
    --mount type=bind,source=/usr,target=/usr,readonly \
    --workdir=/source "$image" /usr/bin/env -i \
    PATH=/toolchain/bin:/usr/bin:/bin HOME=/scratch/home TMPDIR=/scratch/tmp \
    CARGO_HOME=/scratch/cargo CARGO_TARGET_DIR=/scratch/target \
    CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=3 CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 LANG=C.UTF-8 TZ=UTC \
    CC=/usr/bin/gcc-14 CXX=/usr/bin/g++-14 \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc-14 \
    /bin/bash -c 'mkdir -p "$HOME" "$TMPDIR" "$CARGO_HOME"; ln -s /registry "$CARGO_HOME/registry"; exec "$@"' assurance "$@"
