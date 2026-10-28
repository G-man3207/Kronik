#!/usr/bin/env bash
# M1 acceptance runs with the release binary:
#   1. 10 000 POST /counter/alice/increment give n = 10000.
#   2. kill -9 under load, restart: n equals the acknowledged requests.
#   3. The same for SQL state: notes rows equal the acknowledged inserts.
#   4. The SQL databases rebuilt from the log have the same canonical digest
#      as the live ones, and the same query gives the same answer.
#   5. (SDK examples only) The notes migration's CREATE TABLE and ALTER TABLE
#      are recorded as DDL in its turn record.
#
# M1_GUESTS picks the actors: `test` (default) runs the WIT-level test guests
# in tests/guests; `examples` runs the Rust SDK examples counter-rs and
# notes-rs from examples/dist (build them with scripts/build-examples.sh);
# `ts` runs their TypeScript twins counter-ts and notes-ts (build them with
# scripts/build-examples-ts.sh).
#
# Usage: [M1_GUESTS=test|examples|ts] [KRONIK_BIN=path] scripts/acceptance-m1.sh [WORKDIR] [PORT] [N]
# Defaults: /var/tmp/kronik-m1 (a real disk, not tmpfs), port 47812, N 10000,
# KRONIK_BIN target/release/kronik.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

dir="${1:-/var/tmp/kronik-m1}"
port="${2:-47812}"
n="${3:-10000}"
bin="${KRONIK_BIN:-target/release/kronik}"
guests="${M1_GUESTS:-test}"
sock="$dir/api.sock"
gw="http://127.0.0.1:$port"
pid=""

case "$guests" in
    test)
        counter=tests/guests/counter.wasm
        notes=tests/guests/notes.wasm
        note_body="a note"
        ;;
    examples)
        counter=examples/dist/counter.wasm
        notes=examples/dist/notes.wasm
        note_body='{"title":"note","body":"a note"}'
        ;;
    ts)
        counter=examples/dist/counter-ts.wasm
        notes=examples/dist/notes-ts.wasm
        note_body='{"title":"note","body":"a note"}'
        ;;
    *)
        echo "M1_GUESTS must be test, examples or ts, not '$guests'" >&2
        exit 2
        ;;
esac

rm -rf "$dir"
mkdir -p "$dir"

start() {
    setsid "$bin" serve --data-dir "$dir/data" --http-listen "127.0.0.1:$port" \
        --api-socket "$sock" >>"$dir/serve.log" 2>&1 &
    pid=$!
    for _ in $(seq 1 200); do
        curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null 2>&1 && return
        sleep 0.05
    done
    echo "FAIL: daemon did not become healthy" >&2
    exit 1
}
stop() { [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null; pid=""; }
trap stop EXIT
deploy() {
    python3 -c "import base64,json,sys; print(json.dumps({'wasm_base64': base64.b64encode(open(sys.argv[1],'rb').read()).decode(), 'reason': 'm1 acceptance'}))" "$1" >"$dir/deploy.json"
    curl -s --unix-socket "$sock" -X POST -d @"$dir/deploy.json" http://kronik/v1/deployments >/dev/null
}
api() { curl -s --unix-socket "$sock" "$@"; }
kill_after() { # kill_after <seconds>: kill -9 the daemon, then restart it
    sleep "$1"
    echo "kill -9 $pid"
    kill -9 "$pid"
    wait "$pid" 2>/dev/null || true
    sleep 0.5
    start
    echo "restarted as $pid"
}
# The counter's value in a response body: the decimal n from the test guest,
# {"n": n} from the SDK examples.
counter_value() {
    if [ "$guests" != test ]; then
        python3 -c 'import json,sys; print(json.load(sys.stdin)["n"])'
    else
        cat
    fi
}
# A digest of every actor's SQL database under the data directory: per
# database file, the schema and every row of every table in primary-key
# order (rowid for a table without one), without Kronik's own _kronik
# tables. Reads copies, so the files stay as they are. Needs a stopped
# daemon.
sql_digest() {
    python3 - "$1/branches/main/sql" <<'PY'
import glob, hashlib, os, shutil, sqlite3, sys, tempfile
h = hashlib.sha256()
for db in sorted(glob.glob(os.path.join(sys.argv[1], "*", "*.db"))):
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, "x.db")
        for suffix in ("", "-wal"):
            if os.path.exists(db + suffix):
                shutil.copy(db + suffix, copy + suffix)
        con = sqlite3.connect(copy)
        h.update(os.path.basename(db).encode() + b"\0")
        objects = con.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' "
            "AND name NOT LIKE '_kronik%' ORDER BY type, name").fetchall()
        for kind, name, sql in objects:
            h.update(repr((kind, name, sql)).encode())
            if kind == "table":
                pk = [row[1] for row in
                      sorted(con.execute(f'PRAGMA table_info("{name}")'), key=lambda r: r[5])
                      if row[5] > 0]
                order = ", ".join(f'"{column}"' for column in pk) if pk else "rowid"
                for row in con.execute(f'SELECT * FROM "{name}" ORDER BY {order}'):
                    h.update(repr(row).encode())
        con.close()
print(h.hexdigest())
PY
}
# All notes of notes/alice through the gateway, as "<sha256> <count>"; fails
# unless every request gets 200. The SDK examples list a page at a time.
notes_answer() {
    python3 - "$port" "$guests" <<'PY'
import hashlib, http.client, json, sys
port, guests = int(sys.argv[1]), sys.argv[2]
def get(path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    c.request("GET", path)
    r = c.getresponse()
    body = r.read()
    if r.status != 200:
        sys.exit(f"FAIL: GET {path}: HTTP {r.status}: {body[:300]!r}")
    return body
h = hashlib.sha256()
if guests != "test":
    after, count = 0, 0
    while after is not None:
        page = json.loads(get(f"/notes/alice?after={after}&limit=1000"))
        h.update(json.dumps(page["notes"]).encode())
        count += len(page["notes"])
        after = page["next"]
else:
    body = get("/notes/alice")
    h.update(body)
    count = body.count(b"\n")
print(h.hexdigest(), count)
PY
}

start
deploy "$counter"
deploy "$notes"
echo "guests: $guests ($counter, $notes)"

echo "== 1. $n increments of counter/alice"
python3 scripts/load-m1.py "$port" /counter/alice/increment "$n" 16 alice
got=$(curl -s "$gw/counter/alice" | counter_value)
echo "n = $got"
[ "$got" = "$n" ] || { echo "FAIL: expected $n"; exit 1; }

echo "== 2. kill -9 under load (counter/bob, 4000 requests)"
python3 scripts/load-m1.py "$port" /counter/bob/increment 4000 16 bob >"$dir/bob.json" &
load=$!
kill_after 3
wait "$load"
cat "$dir/bob.json"
got=$(curl -s "$gw/counter/bob" | counter_value)
acked=$(python3 -c "import json; print(json.load(open('$dir/bob.json'))['acked'])")
echo "n = $got, acknowledged = $acked"
[ "$got" = "$acked" ] || { echo "FAIL: n != acknowledged"; exit 1; }

echo "== 3. kill -9 under load with SQL state (notes/alice, 3000 inserts)"
python3 scripts/load-m1.py "$port" /notes/alice 3000 16 note "$note_body" >"$dir/notes.json" &
load=$!
kill_after 3
wait "$load"
cat "$dir/notes.json"
rows=$(api http://kronik/v1/actors/notes/alice | python3 -c "import json,sys; print(next(t['rows'] for t in json.load(sys.stdin)['sql']['tables'] if t['name'] == 'notes'))")
acked=$(python3 -c "import json; print(json.load(open('$dir/notes.json'))['acked'])")
echo "rows = $rows, acknowledged = $acked"
[ "$rows" = "$acked" ] || { echo "FAIL: rows != acknowledged"; exit 1; }

echo "== 4. SQL state rebuilt from the log"
answer_live=$(notes_answer)
stop
digest_live=$(sql_digest "$dir/data")
mv "$dir/data/branches/main/sql" "$dir/sql-live"
start
answer_rebuilt=$(notes_answer)
stop
digest_rebuilt=$(sql_digest "$dir/data")
echo "digest of the SQL databases: live $digest_live, rebuilt $digest_rebuilt"
echo "all notes of notes/alice (sha256, count): live $answer_live, rebuilt $answer_rebuilt"
[ "$digest_live" = "$digest_rebuilt" ] || { echo "FAIL: the rebuilt databases differ"; exit 1; }
[ "$answer_live" = "$answer_rebuilt" ] || { echo "FAIL: the query answers differ"; exit 1; }
[ "${answer_live#* }" = "$rows" ] || { echo "FAIL: the answer has ${answer_live#* } notes, not $rows"; exit 1; }
start

if [ "$guests" != test ]; then
    echo "== 5. the migration's DDL is recorded (notes/ddl)"
    curl -s -X POST -d '{"title":"first"}' "$gw/notes/ddl" >/dev/null
    migrate=$(api "http://kronik/v1/actors/notes/ddl/history?limit=10" | python3 -c "import json,sys; print(next(t['turn_id'] for t in json.load(sys.stdin)['turns'] if t['input']['type'] == 'migrate'))")
    api "http://kronik/v1/turns/$migrate" | python3 -c '
import json, re, sys
ddl = [re.sub(r"\s+", " ", s) for s in json.load(sys.stdin)["sql_schema"]]
for want in ("CREATE TABLE notes (", "ALTER TABLE notes ADD COLUMN token"):
    if not any(s.startswith(want) for s in ddl):
        sys.exit(f"FAIL: no DDL starting with {want!r} in turn {sys.argv[1]}: {ddl}")
print(f"turn {sys.argv[1]} records the DDL:")
for s in ddl:
    print(f"  {s}")
' "$migrate"
fi

echo "PASS: M1 acceptance runs with the $guests guests (log: $dir/serve.log)"
