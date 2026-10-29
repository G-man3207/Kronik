#!/usr/bin/env bash
# Simulates "VPS dies, new VPS, restore" with two data directories and one
# bucket (docs/design/m6-storage.md §6, §8). A real second host is this
# script pointed at a bucket the first host already shipped to. It does not
# touch any remote machine.
#
# Usage: scripts/minio.sh demo/vps-restore.sh
#        [KRONIK_BIN=path] [INCREMENTS=300] demo/vps-restore.sh [WORKDIR]
# Needs KRONIK_TEST_S3_URL, KRONIK_TEST_S3_ENDPOINT and the AWS_* variables
# that scripts/minio.sh exports. The counter is tests/guests/counter.wasm
# (decimal n, not the examples' JSON). Needs curl and python3.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -z "${KRONIK_TEST_S3_URL:-}" ] || [ -z "${KRONIK_TEST_S3_ENDPOINT:-}" ]; then
    echo "KRONIK_TEST_S3_URL and KRONIK_TEST_S3_ENDPOINT are unset." >&2
    echo "Run: scripts/minio.sh demo/vps-restore.sh" >&2
    exit 2
fi

started=$(date +%s)
dir="${1:-/var/tmp/kronik-vps-restore-$$}"
increments="${INCREMENTS:-300}"
guest=tests/guests/counter.wasm
if [ -n "${KRONIK_BIN:-}" ]; then
    bin="$KRONIK_BIN"
elif [ -x target/release/kronik ]; then
    bin=target/release/kronik
elif [ -x target/debug/kronik ]; then
    bin=target/debug/kronik
else
    echo "missing kronik binary; set KRONIK_BIN or cargo build -p kronik" >&2
    exit 2
fi
for f in "$bin" "$guest"; do
    [ -e "$f" ] || { echo "missing $f" >&2; exit 2; }
done

port_a=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
port_b=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
a="$dir/a"
b="$dir/b"
pid=""
log="$dir/serve-a.log"

rm -rf "$dir"
mkdir -p "$a" "$dir"
trap '[ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; true' EXIT

step() { printf '\n== %s (%ss)\n' "$1" "$(( $(date +%s) - started ))"; }
fail() {
    echo "FAIL: $*" >&2
    echo "--- serve log ---" >&2
    tail -40 "$log" >&2 || true
    if [ -f "$dir/serve-b.log" ]; then
        echo "--- serve B log ---" >&2
        tail -40 "$dir/serve-b.log" >&2 || true
    fi
    exit 1
}

# Bucket object for the snapshot manifest: s3://bucket/prefix + main/snapshots/<lsn>/manifest.json
manifest_url() { # LSN
    local rest bucket prefix lsn
    rest=${KRONIK_TEST_S3_URL#s3://}
    bucket=${rest%%/*}
    prefix=${rest#*/}
    lsn=$(printf '%020d' "$1")
    if [ "$prefix" = "$rest" ]; then
        printf '%s/%s/main/snapshots/%s/manifest.json' "$KRONIK_TEST_S3_ENDPOINT" "$bucket" "$lsn"
    else
        printf '%s/%s/%s/main/snapshots/%s/manifest.json' "$KRONIK_TEST_S3_ENDPOINT" "$bucket" "$prefix" "$lsn"
    fi
}
in_bucket() { # LSN
    curl -fsS --aws-sigv4 "aws:amz:${AWS_REGION:-us-east-1}:s3" \
        --user "${AWS_ACCESS_KEY_ID:?}:${AWS_SECRET_ACCESS_KEY:?}" \
        -o /dev/null -I "$(manifest_url "$1")" 2>/dev/null
}

write_config() { # PATH DATA_DIR SOCKET HTTP SHIP
    local ship="enabled = false"
    if [ "$5" = yes ]; then
        ship=$(printf 'enabled = true\nurl = "%s"\nendpoint = "%s"' \
            "$KRONIK_TEST_S3_URL" "$KRONIK_TEST_S3_ENDPOINT")
    fi
    cat >"$1" <<EOF
[server]
data_dir = "$2"
api_socket = "$3"
http_listen = "127.0.0.1:$4"

[ship]
$ship
EOF
}

start_serve() { # CONFIG SOCKET LOG
    log=$3
    setsid "$bin" serve --config "$1" >>"$3" 2>&1 &
    pid=$!
    for _ in $(seq 1 100); do
        curl -sf --unix-socket "$2" http://kronik/v1/health >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    fail "daemon not healthy ($1)"
}

stop_serve() {
    if [ -n "$pid" ]; then
        kill -9 "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        pid=""
    fi
}

step "serve A, shipping on"
write_config "$dir/a.toml" "$a/data" "$a/api.sock" "$port_a" yes
start_serve "$dir/a.toml" "$a/api.sock" "$dir/serve-a.log"
sock="$a/api.sock"
gw="http://127.0.0.1:$port_a"

step "deploy counter and record $increments increments"
"$bin" --socket "$sock" deploy "$guest" --reason "vps-restore" >/dev/null
for i in $(seq 1 "$increments"); do
    curl -sf -X POST "$gw/counter/alice/increment" >/dev/null || fail "increment $i"
done
n_a=$(curl -sf "$gw/counter/alice") || fail "read counter"
[ "$n_a" = "$increments" ] || fail "counter is $n_a, want $increments"

step "snapshot, then wait until it is in the bucket"
snap=$("$bin" --socket "$sock" --json snapshot create --reason "before the move")
lsn=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["snapshot"]["lsn"])' "$snap")
echo "snapshot lsn $lsn"
# The shipper runs every 10s. The manifest is uploaded last, so its presence
# means the snapshot's files are in the bucket. Wait for the active segment
# to be caught up too, so the log hash can match.
caught_up() {
    python3 - "$a/data" <<'PY'
import json, pathlib, sys
data = pathlib.Path(sys.argv[1])
ship = data / "ship.json"
if not ship.exists():
    sys.exit(1)
v = json.loads(ship.read_text())
active = v.get("active")
if not active or not v.get("code"):
    sys.exit(1)
start, size = active
seg = data / "branches/main/log" / f"{int(start):020}.seg"
sys.exit(0 if seg.exists() and seg.stat().st_size == int(size) else 1)
PY
}
for _ in $(seq 1 60); do
    if in_bucket "$lsn" && caught_up; then
        break
    fi
    sleep 1
done
in_bucket "$lsn" || fail "snapshot $lsn was not in the bucket after 60s"
caught_up || fail "the shipper had not caught up with the log"

step "record integrity, counter and a history sample"
integrity_a=$("$bin" --socket "$sock" --json integrity)
history_a=$("$bin" --socket "$sock" --json history counter/alice --limit 5)
echo "A: $integrity_a"
echo "counter $n_a"

step "VPS dies"
stop_serve

step "restore into a fresh directory"
write_config "$dir/b.toml" "$b/data" "$b/api.sock" "$port_b" no
# The master key is never shipped. B needs A's key before the restore, which
# installs the privacy keystore backup with it, and before serving.
if [ -f "$a/data/keys/master.key" ]; then
    mkdir -p "$b/data/keys"
    cp "$a/data/keys/master.key" "$b/data/keys/master.key"
    chmod 600 "$b/data/keys/master.key"
fi
"$bin" restore --from "$KRONIK_TEST_S3_URL" --endpoint "$KRONIK_TEST_S3_ENDPOINT" \
    --data-dir "$b/data" --config "$dir/b.toml"

step "serve B and compare"
start_serve "$dir/b.toml" "$b/api.sock" "$dir/serve-b.log"
sock="$b/api.sock"
gw="http://127.0.0.1:$port_b"
# B's first start appends one `restore` audit event after A's last record
# (M28): compare the log through A's applied LSN, then what follows it.
applied_a=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["applied_lsn"])' "$integrity_a")
integrity_b=$("$bin" --socket "$sock" --json integrity --through "$applied_a")
after_b=$("$bin" --socket "$sock" --json audit show --from "$((applied_a + 1))")
history_b=$("$bin" --socket "$sock" --json history counter/alice --limit 5)
n_b=$(curl -sf "$gw/counter/alice") || fail "read restored counter"

python3 - "$integrity_a" "$integrity_b" "$history_a" "$history_b" "$n_a" "$n_b" "$lsn" "$after_b" <<'PY' || fail "restored node does not match"
import json, sys
a, b, ha, hb, na, nb, lsn, after = sys.argv[1:]
ia, ib = json.loads(a), json.loads(b)
lsn = int(lsn)
# B's state equals A's, and B's log through A's applied LSN is A's log.
for key in ("state_hash", "log_first_lsn"):
    if ia[key] != ib[key]:
        print(f"{key}: {ia[key]} != {ib[key]}", file=sys.stderr)
        sys.exit(1)
if ib["through_lsn"] != ia["applied_lsn"] or ia["log_hash"] != ib["log_hash"]:
    print(f"log through {ia['applied_lsn']}: {ia['log_hash']} != {ib['log_hash']}", file=sys.stderr)
    sys.exit(1)
# After it comes exactly one record: the restore's audit event.
lines = json.loads(after)["lines"]
if int(ib["applied_lsn"]) != int(ia["applied_lsn"]) + 1 or [
    (l["lsn"], l["action"]) for l in lines
] != [(int(ia["applied_lsn"]) + 1, "restore")]:
    print(f"after lsn {ia['applied_lsn']}: applied {ib['applied_lsn']}, lines {lines}", file=sys.stderr)
    sys.exit(1)
# The restored node replayed at least to the snapshot's LSN, like A.
for name, node in (("A", ia), ("B", ib)):
    if not 0 < lsn <= int(node["applied_lsn"]):
        print(
            f"snapshot lsn {lsn} is outside {name}'s applied lsn {node['applied_lsn']}",
            file=sys.stderr,
        )
        sys.exit(1)
if na != nb:
    print(f"counter: {na} != {nb}", file=sys.stderr)
    sys.exit(1)
def sample(text):
    turns = json.loads(text)["turns"]
    return [(t["turn_id"], t["lsn"], t["outcome"]["kind"]) for t in turns]
if sample(ha) != sample(hb):
    print("history sample differs", file=sys.stderr)
    print(sample(ha), file=sys.stderr)
    print(sample(hb), file=sys.stderr)
    sys.exit(1)
print(f"state {ia['state_hash']}")
print(f"log   {ia['log_hash']}")
print(f"n     {na}")
print(f"lsn   {lsn} (A applied {ia['applied_lsn']}; B adds its restore event at {ib['applied_lsn']})")
PY

stop_serve
elapsed=$(( $(date +%s) - started ))
printf '\nPASS: vps-restore in %ss\n' "$elapsed"
