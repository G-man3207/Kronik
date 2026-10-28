#!/usr/bin/env bash
# The cost of privacy mode (docs/design/m8-privacy.md §13, docs/perf.md):
# two release builds, the last commit before the sealing code (BASE) and
# one with it (NEW), measured alternately with the same workloads; NEW also
# with the mode on. Prints mean ± standard deviation per build and workload:
# throughput and latency, which a busy machine blurs, and the daemon's CPU
# time per log record (user + system, from /proc), which it blurs much less.
#
# Usage: [NICE=-10] scripts/bench-privacy.sh BASE NEW [RUNS] [SECONDS]
# Defaults: 5 runs of 10 s per workload. NICE runs the daemon and the load
# generator at that niceness (negative needs root), which keeps other work
# on a shared machine from blurring the numbers. Builds in /var/tmp (worktrees and
# target directories per commit), data on /var/tmp (a real disk).
# Workloads (privacy.subject_from = "header:x-user-id"):
#   counter: the gateway, POST /counter/k<key>/increment, 64 keys, 16
#            clients, half of the keys with the header (a subject);
#   send:    the API over TCP, POST /v1/actors/counter/s<key>/messages with
#            a subject, 64 keys, 16 clients;
#   notes:   the gateway, POST /notes/n<key> with a body (an add), 16 keys,
#            16 clients, every request with the header (an SQL row with
#            _subject per turn).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
base="${1:?usage: scripts/bench-privacy.sh BASE NEW [RUNS] [SECONDS]}"
new="${2:?usage: scripts/bench-privacy.sh BASE NEW [RUNS] [SECONDS]}"
runs="${3:-5}"
secs="${4:-10}"
work=/var/tmp/kronik-bench-privacy
port=47851
api_port=47852
load=(nice -n "${NICE:-0}" tools/loadgen/target/release/kronik-loadgen)
mkdir -p "$work"
(cd tools/loadgen && cargo build -q --release)

build() { # REF -> path of its kronik binary
    local ref="$1" sha
    sha=$(git rev-parse --short "$ref")
    local wt="$work/src-$sha"
    if [ ! -x "$work/target-$sha/release/kronik" ]; then
        git worktree remove --force "$wt" 2>/dev/null || true
        git worktree add --detach "$wt" "$sha" >/dev/null
        (cd "$wt" && CARGO_TARGET_DIR="$work/target-$sha" cargo build -q --release -p kronik)
        git worktree remove --force "$wt"
    fi
    echo "$work/target-$sha/release/kronik"
}

measure() { # BIN LABEL MODE -> JSON lines on stdout
    local bin="$1" label="$2" mode="$3" dir="$work/run" pid
    rm -rf "$dir"
    mkdir -p "$dir"
    printf '[server]\ndata_dir = "%s/data"\n\n[privacy]\nsubject_from = "header:x-user-id"\n' "$dir" >"$dir/kronik.toml"
    setsid nice -n "${NICE:-0}" "$bin" serve --config "$dir/kronik.toml" --http-listen "127.0.0.1:$port" \
        --api-listen "127.0.0.1:$api_port" --admin-listen 127.0.0.1:0 \
        --api-socket "$dir/api.sock" >>"$dir/serve.log" 2>&1 &
    pid=$!
    for _ in $(seq 1 200); do
        curl -sf --unix-socket "$dir/api.sock" http://kronik/v1/health >/dev/null 2>&1 && break
        sleep 0.05
    done
    for g in counter notes; do
        python3 -c "import base64,json,sys; print(json.dumps({'wasm_base64': base64.b64encode(open(sys.argv[1],'rb').read()).decode(), 'reason': 'bench'}))" \
            "tests/guests/$g.wasm" >"$dir/deploy.json"
        curl -sf --unix-socket "$dir/api.sock" -X POST -d @"$dir/deploy.json" http://kronik/v1/deployments >/dev/null
    done
    if [ "$mode" = on ]; then
        curl -sf --unix-socket "$dir/api.sock" -X POST -d '{"mode":"on","reason":"bench"}' \
            http://kronik/v1/privacy/mode >/dev/null
    fi
    local secret
    secret=$(curl -sf --unix-socket "$dir/api.sock" -X POST \
        -d '{"name":"bench","scopes":["operate"],"reason":"bench"}' http://kronik/v1/tokens |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["secret"])')
    # Log size and records before and after each workload: bytes per record.
    local b0 r0 c0 b1 r1 c1 out
    b0=$(log_bytes "$dir"); r0=$(applied "$dir"); c0=$(cpu_ticks "$pid")
    for w in counter send notes; do
        case $w in
        counter) out=$("${load[@]}" --addr "127.0.0.1:$port" --path '/counter/k{key}/increment' \
            --keys 64 --concurrency 16 --seconds "$secs" --warmup 2 \
            --header 'x-user-id: user:{key}' --header-half) ;;
        send) out=$("${load[@]}" --addr "127.0.0.1:$api_port" --path '/v1/actors/counter/s{key}/messages' \
            --keys 64 --concurrency 16 --seconds "$secs" --warmup 2 \
            --header "authorization: Bearer $secret" \
            --body '{"name":"increment","text":"","subject":"user:{key}","reason":"bench"}') ;;
        notes) out=$("${load[@]}" --addr "127.0.0.1:$port" --path '/notes/n{key}' --keys 16 \
            --concurrency 16 --seconds "$secs" --warmup 2 --header 'x-user-id: user:{key}' \
            --body 'a note of user {key}') ;;
        esac
        b1=$(log_bytes "$dir"); r1=$(applied "$dir"); c1=$(cpu_ticks "$pid")
        echo "{\"build\":\"$label\",\"workload\":\"$w\",\"result\":$out,\"log_bytes\":$((b1 - b0)),\"records\":$((r1 - r0)),\"cpu_ticks\":$((c1 - c0)),\"load\":\"$(cut -d' ' -f1 /proc/loadavg)\"}"
        b0=$b1; r0=$r1; c0=$c1
    done
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

log_bytes() { du -sb "$1/data/branches/main/log" | cut -f1; }
# utime + stime of a process in clock ticks (fields 14 and 15 of its stat).
cpu_ticks() {
    local s
    s=$(cat "/proc/$1/stat")
    s=${s##*) }
    # shellcheck disable=SC2086
    set -- $s
    echo $((${12} + ${13}))
}
applied() {
    curl -sf --unix-socket "$1/api.sock" http://kronik/v1/health |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["applied_lsn"])'
}

base_bin=$(build "$base")
new_bin=$(build "$new")
out="$work/results.jsonl"
: >"$out"
echo "# $(uname -n) $(nproc) vCPU, niceness ${NICE:-0}; base $(git rev-parse --short "$base"), new $(git rev-parse --short "$new"); $runs runs of ${secs}s"
for _ in $(seq 1 "$runs"); do
    {
        measure "$base_bin" base off
        measure "$new_bin" off off
        measure "$new_bin" on on
    } >>"$out"
done
python3 - "$out" <<'PY'
import json, os, statistics, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
tick_us = 1e6 / os.sysconf("SC_CLK_TCK")
def ms(xs):
    m = statistics.mean(xs)
    s = statistics.stdev(xs) if len(xs) > 1 else 0.0
    return m, s
print(f"{'workload':8} {'build':5} {'turns/s':>16} {'p50 ms':>14} {'p99 ms':>14} {'CPU µs/record':>15} {'log B/record':>12}")
summary = {}
for w in ("counter", "send", "notes"):
    for b in ("base", "off", "on"):
        rs = [r for r in rows if r["workload"] == w and r["build"] == b]
        rps = ms([r["result"]["rps"] for r in rs])
        p50 = ms([r["result"]["p50_ms"] for r in rs])
        p99 = ms([r["result"]["p99_ms"] for r in rs])
        cpu = ms([r["cpu_ticks"] * tick_us / max(r["records"], 1) for r in rs])
        bpr = statistics.mean([r["log_bytes"] / max(r["records"], 1) for r in rs])
        summary[(w, b)] = (rps, p99, cpu)
        print(f"{w:8} {b:5} {rps[0]:9.0f} ± {rps[1]:4.0f} {p50[0]:7.2f} ± {p50[1]:4.2f} {p99[0]:7.2f} ± {p99[1]:4.2f} {cpu[0]:8.1f} ± {cpu[1]:4.1f} {bpr:12.0f}")
print("# load average during the runs:", " ".join(r["load"] for r in rows))
print()
def within(base, new):
    """The difference is noise: under 2 standard deviations or under 3 %."""
    (mb, sb), (mn, sn) = base, new
    d = (mn - mb) / mb * 100 if mb else 0.0
    return d, abs(mn - mb) < 2 * max(sb, sn) or abs(d) < 3

for w in ("counter", "send", "notes"):
    base, off, on = summary[(w, "base")], summary[(w, "off")], summary[(w, "on")]
    checks = [within(base[i], off[i]) for i in range(3)]
    verdict = "no measurable overhead" if all(ok for _, ok in checks) else "MEASURABLE"
    (d_rps, _), (d_p99, _), (d_cpu, _) = checks
    d_on = (on[2][0] - base[2][0]) / base[2][0] * 100
    print(f"{w}: off vs base: turns/s {d_rps:+.1f}%, p99 {d_p99:+.1f}%, CPU/record {d_cpu:+.1f}% -> {verdict}; on: CPU/record {d_on:+.1f}%")
PY
