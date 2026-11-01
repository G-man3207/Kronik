#!/usr/bin/env python3
"""Measure the real public daemon path; never label this a cluster benchmark."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import statistics
import subprocess
import sys
import time
from kronikd import Daemon, Violation


def positive(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return number


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            result.update(chunk)
    return result.hexdigest()


def run_json(argv, directory, name, timeout=120, env=None):
    # CLI output goes to a bounded-by-process fixture file, not an unbounded pipe
    # accumulated in memory. Large replay diffs are never requested.
    output = directory / f"{name}.json"
    with output.open("xb") as stdout, (directory / f"{name}.stderr").open("xb") as stderr:
        result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout, check=False, env=env)
    if result.returncode:
        with (directory / f"{name}.stderr").open("rb") as source:
            detail = source.read(4096).decode("utf-8", errors="replace")
        with output.open("rb") as source:
            answer = source.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"{name} exited {result.returncode}: {detail or answer}")
    if output.stat().st_size > 1 << 20:
        raise RuntimeError(f"{name} exceeded the 1 MiB result limit")
    with output.open() as source:
        value = json.load(source, parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
    if not isinstance(value, dict):
        raise RuntimeError(f"{name} did not return a JSON object")
    if "error" in value:
        raise RuntimeError(f"{name} returned an error")
    return value


def read_limit(name):
    path = Path("/sys/fs/cgroup") / name
    return path.read_text().strip() if path.is_file() else "unavailable"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--loadgen", type=Path, required=True)
    parser.add_argument("--guest", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True, help="must not already exist")
    parser.add_argument("--revision", required=True, help="exact 40-hex source commit")
    parser.add_argument("--rig-id", required=True, help="stable identifier for this hardware and placement")
    parser.add_argument("--port", type=int, required=True, help="owned loopback gateway port")
    parser.add_argument("--seconds", type=positive, default=10)
    parser.add_argument("--warmup", type=positive, default=2)
    parser.add_argument("--gateway-rate", type=positive, default=5000)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--keys", type=int, default=256)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("revision must be the exact lowercase 40-hex source commit")
    if not 1024 <= args.port <= 65535 or not 1 <= args.repetitions <= 20:
        parser.error("port must be 1024..65535 and repetitions 1..20")
    if not 1 <= args.concurrency <= 1024 or not args.concurrency <= args.keys <= 1000000:
        parser.error("need 1 <= concurrency <= keys <= 1000000, concurrency <= 1024")
    if not args.rig_id.strip() or len(args.rig_id) > 128:
        parser.error("rig-id must be a nonblank identifier of at most 128 characters")
    binary, loadgen, guest = (path.resolve(strict=True) for path in (args.binary, args.loadgen, args.guest))
    if guest.stat().st_size > 1 << 20:
        parser.error("use the maintained counter guest, at most 1 MiB")
    work = args.workdir.resolve()
    work.mkdir(mode=0o700)
    os.umask(0o077)
    socket = work / "api.sock"
    if len(str(socket).encode()) > 100:
        raise RuntimeError("workdir is too long for the Unix API socket")
    config = work / "kronik.toml"
    config.write_text("[server]\n" + f"data_dir = {json.dumps(str(work / 'data'))}\n" +
                      f"api_socket = {json.dumps(str(socket))}\n" +
                      f"http_listen = \"127.0.0.1:{args.port}\"\n" +
                      "admin_listen = \"127.0.0.1:0\"\n")
    command = [str(binary), "--socket", str(socket), "--json"]
    daemon = Daemon(str(binary), str(work / "data"), str(socket), args.port,
                    str(work / "daemon.log"), healthy_timeout=30)
    rows, replay_speeds, snapshot_times = [], [], []
    try:
        daemon.start(env={"KRONIK_CONFIG": str(config), "KRONIK_ADMIN_LISTEN": "127.0.0.1:0"})
        run_json(command + ["deploy", str(guest), "--reason", "owned benchmark fixture"], work, "deploy")
        for repetition in range(args.repetitions):
            fork = f"bench-{repetition}"
            for scenario, extra in [("counter", []), ("gateway", ["--rate", str(args.gateway_rate)])]:
                if scenario == "gateway":
                    # Replay a fixed open-loop window, not the throughput row's
                    # variable amount of work when one release gets faster.
                    run_json(command + ["fork", "create", "--at", "now", "--name", fork,
                                        "--reason", "benchmark identity replay"], work, f"fork-{repetition}")
                    begin = time.perf_counter()
                row = run_json([str(loadgen), "--addr", f"127.0.0.1:{args.port}", "--path",
                                "/counter/k{key}/increment", "--seconds", str(args.seconds),
                                "--warmup", str(args.warmup), "--keys", str(args.keys),
                                "--concurrency", str(args.concurrency)] + extra,
                               work, f"{scenario}-{repetition}", timeout=math.ceil(args.seconds + args.warmup + 15))
                if row.get("errors") != 0 or row.get("ok", 0) <= 0:
                    raise RuntimeError(f"{scenario} has failed or no committed requests")
                for key in ["rps", "p99_ms", "elapsed_seconds"]:
                    value = row.get(key)
                    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                        raise RuntimeError(f"{scenario} has invalid {key}")
                rows.append((scenario, row))
            production_seconds = time.perf_counter() - begin
            replay_begin = time.perf_counter()
            replay = run_json(command + ["replay", fork, "--mode", "both", "--threads", "3",
                                         "--reason", "benchmark identity replay"], work, f"replay-{repetition}")
            replay_seconds = time.perf_counter() - replay_begin
            summary = replay.get("summary", {})
            if summary.get("changed") is not False or summary.get("root_inputs", 0) <= 0 or summary.get("replayed") != summary.get("root_inputs"):
                raise RuntimeError("identity replay changed behavior or omitted root inputs")
            replay_speeds.append(production_seconds / replay_seconds)
            snapshot_begin = time.perf_counter()
            run_json(command + ["snapshot", "create", "--reason", "benchmark snapshot"], work, f"snapshot-{repetition}")
            snapshot_times.append((time.perf_counter() - snapshot_begin) * 1000)
            run_json(command + ["fork", "delete", fork, "--reason", "benchmark fixture cleanup"], work, f"delete-{repetition}")
        filesystem = subprocess.check_output(["stat", "-f", "-c", "%T", str(work)], text=True, timeout=5).strip()
        def measurement(name, unit, direction, samples):
            return {"name": name, "unit": unit, "direction": direction,
                    "value": statistics.median(samples), "errors": 0}
        report = {
            "format": "kronik.benchmark/v1", "profile": "single-node-public",
            "source": {"revision": args.revision, "binary_sha256": digest(binary), "guest_sha256": digest(guest)},
            "rig": {"id": args.rig_id, "nodes": 1, "placement": "single-host", "kernel": platform.release(),
                    "architecture": platform.machine(), "filesystem": filesystem,
                    "cpu_quota": read_limit("cpu.max"), "memory_limit": read_limit("memory.max"),
                    "loadgen_sha256": digest(loadgen), "seconds": args.seconds, "warmup": args.warmup,
                    "harness_sha256": digest(Path(__file__)),
                    "repetitions": args.repetitions, "gateway_rate": args.gateway_rate,
                    "concurrency": args.concurrency, "keys": args.keys, "replay_mode": "both", "replay_threads": 3},
            "measurements": [
                measurement("counter_committed_turns", "turns/s", "higher", [r["rps"] for s, r in rows if s == "counter"]),
                measurement("gateway_p99", "ms", "lower", [r["p99_ms"] for s, r in rows if s == "gateway"]),
                measurement("single_node_replay_speed", "ratio", "higher", replay_speeds),
                measurement("snapshot_ms", "ms", "lower", snapshot_times)],
        }
        (work / "benchmark.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
        print(json.dumps(report, allow_nan=False))
    finally:
        process = daemon.proc
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        daemon.log.close()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, Violation, subprocess.SubprocessError) as error:
        print(f"benchmark: {error}", file=sys.stderr)
        sys.exit(1)
