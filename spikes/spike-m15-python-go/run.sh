#!/usr/bin/env bash
# run.sh WASM : deploy on a fresh daemon, 3 increments, probe x2, error modes; print outcomes and fuel
set -uo pipefail
wasm=$1; dir=$(mktemp -d /var/tmp/m15-run-XXXX); port=$(python3 -c "import socket;s=socket.socket();s.bind((\"127.0.0.1\",0));print(s.getsockname()[1])")
K=/var/tmp/kronik-m12/target/release/kronik
$K serve --data-dir $dir/data --http-listen 127.0.0.1:$port --api-socket $dir/api.sock >$dir/serve.log 2>&1 &
pid=$!
for i in $(seq 100); do curl -sf --unix-socket $dir/api.sock http://k/v1/health >/dev/null && break; sleep 0.05; done
export KRONIK_SOCKET=$dir/api.sock
$K --socket $dir/api.sock deploy $wasm --reason spike 2>&1 | head -30
for i in 1 2 3; do curl -s -XPOST http://127.0.0.1:$port/counter/c1/increment; echo; done
for m in probe probe noop fail boom spin; do echo "-- $m"; $K --socket $dir/api.sock send counter/c1 $m --reason spike 2>&1 | head -4; done
$K --socket $dir/api.sock history counter/c1 --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d.get('turns',d if isinstance(d,list) else []):
    o=t.get('outcome',{}); print(t.get('turn_id'), o.get('kind'), o.get('message'), {k:v for k,v in t.items() if 'fuel' in k or 'memory' in k}, (t.get('reply') or {}).get('text') if isinstance(t.get('reply'),dict) else '')
" 2>&1 | head -20
kill $pid; wait $pid 2>/dev/null; echo dir=$dir
