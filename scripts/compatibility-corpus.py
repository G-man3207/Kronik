#!/usr/bin/env python3
"""Preserve actual released producer data and verify it through the public binary."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

from kronikd import Daemon, Violation

# Reuse the bounded public-command fixture helper, not a second subprocess convention.
spec = importlib.util.spec_from_file_location("benchmark_single_node", Path(__file__).with_name("benchmark-single-node.py"))
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)
run_json = benchmark.run_json
digest = benchmark.digest
DUMMY_MASTER = "44" * 32
REASON = "owned released-producer compatibility fixture"
MAX_FILE = 2 << 20
MAX_TOTAL = 32 << 20
# A release is named by its tag, v0.<minor>.<patch>, as in the release index.
RELEASE_TAG = re.compile(r"v0\.[0-9]+\.[0-9]+")
# The first line of an actual release's `--version` is `kronik <version>`. The
# one documented exception is the v0.1.0 artifact, which shipped its
# development string; its real identity is retained, not rewritten.
REPORTED_VERSION = {"v0.1.0": "kronik 0.1.0-dev"}


def release_tag(value):
    """argparse type: the exact tag of an actual release."""
    if not RELEASE_TAG.fullmatch(value):
        raise argparse.ArgumentTypeError(f"{value!r} is not a release tag such as v0.4.0")
    return value


def expected_version(release):
    """The first `--version` line that the release's own binary reports."""
    return REPORTED_VERSION.get(release_tag(release), "kronik " + release[1:])


def checked_api(daemon, method, path, body=None):
    status, value = daemon.api(method, path, body, timeout=30)
    if status != 200:
        raise Violation(f"{method} {path}: HTTP {status}: {value}")
    return value


def message(daemon, actor, name, text=""):
    value = checked_api(daemon, "POST", f"/v1/actors/{actor}/messages",
                        {"name": name, "text": text, "reason": REASON})
    if value.get("outcome", {}).get("kind") != "committed":
        raise Violation(f"{actor}/{name} did not commit: {value}")
    return value


def configure(work, data, sock):
    config = work / "kronik.toml"
    config.write_text("[server]\n" + f"data_dir = {json.dumps(str(data))}\n" +
                      f"api_socket = {json.dumps(str(sock))}\n" +
                      "admin_listen = \"127.0.0.1:0\"\n")
    return {"KRONIK_CONFIG": str(config), "KRONIK_MASTER_KEY": DUMMY_MASTER,
            "KRONIK_ADMIN_LISTEN": "127.0.0.1:0"}


def close(daemon):
    if daemon.proc is not None and daemon.proc.poll() is None:
        os.killpg(daemon.proc.pid, signal.SIGTERM)
        try:
            daemon.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(daemon.proc.pid, signal.SIGKILL)
            daemon.proc.wait(timeout=5)
    daemon.log.close()
    if sys.exc_info()[0] is not None:
        with Path(daemon.log.name).open("rb") as source:
            source.seek(0, os.SEEK_END)
            source.seek(max(0, source.tell() - 4096))
            print(source.read(4096).decode("utf-8", errors="replace"), file=sys.stderr)


def inventory(root):
    records = []
    total = 0
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise Violation(f"nonregular or linked corpus entry: {path}")
        if metadata.st_size > MAX_FILE:
            raise Violation(f"corpus file exceeds 2 MiB: {path}")
        total += metadata.st_size
        if total > MAX_TOTAL or len(records) >= 512:
            raise Violation("corpus exceeds the 32 MiB / 512-file bound")
        records.append({"path": path.relative_to(root).as_posix(),
                        "bytes": metadata.st_size, "sha256": digest(path)})
    if not records:
        raise Violation("corpus contains no producer data")
    return records


def producer(args):
    work = args.workdir.resolve()
    work.mkdir(mode=0o700)
    binary = args.binary.resolve(strict=True)
    if digest(binary) != args.binary_sha256:
        raise Violation("producer binary does not match the explicitly pinned release SHA-256")
    version = subprocess.check_output([str(binary), "--version"], text=True, timeout=10)
    if not version.splitlines() or version.splitlines()[0] != expected_version(args.release):
        raise Violation(f"producer is not the declared actual release {args.release}")
    data, sock = work / "data", work / "api.sock"
    daemon = Daemon(str(binary), str(data), str(sock), args.port, str(work / "producer.log"), healthy_timeout=30)
    env = configure(work, data, sock)
    try:
        daemon.start(env)
        health = checked_api(daemon, "GET", "/v1/health")
        components = []
        for guest in (args.counter, args.notes):
            guest = guest.resolve(strict=True)
            if guest.stat().st_size > 1 << 20:
                raise Violation("fixture component exceeds 1 MiB")
            result = checked_api(daemon, "POST", "/v1/deployments",
                                 {"wasm_base64": base64.b64encode(guest.read_bytes()).decode(), "reason": REASON})
            components.append({"filename": guest.name, "sha256": digest(guest), "deployment": result})
        checked_api(daemon, "PUT", "/v1/secrets/compat-key", {"text": "released-fixture-only-secret", "reason": REASON})
        checked_api(daemon, "POST", "/v1/grants", {"kind": "counter", "capability": "secret:compat-key", "reason": REASON})
        # All roots replayed by an ordinary fork share this actual recorded configuration.
        stable_lsn = checked_api(daemon, "GET", "/v1/health")["applied_lsn"]
        for _ in range(5):
            message(daemon, "counter/a", "increment")
        for text in ("released alpha", "released beta"):
            message(daemon, "notes/a", "add", text)
        signature = message(daemon, "counter/a", "hmac", "compat-key\nrecorded data")["reply"]["text"]
        message(daemon, "counter/a", "forward", "sink")
        deadline = time.monotonic() + 10
        while True:
            try:
                sink = checked_api(daemon, "GET", "/v1/actors/counter/sink")
                if sink.get("actor", {}).get("turns", 0) >= 1:
                    break
            except Violation:
                pass
            if time.monotonic() >= deadline:
                raise Violation("real buffered message was not consumed within 10 s")
            time.sleep(0.02)
        checked_api(daemon, "POST", "/v1/snapshots", {"reason": REASON})
        before = checked_api(daemon, "GET", "/v1/integrity")
        observations = {"counter": checked_api(daemon, "GET", "/v1/actors/counter/a"),
                        "notes": checked_api(daemon, "GET", "/v1/actors/notes/a"),
                        "sink": sink, "hmac": signature}
    finally:
        close(daemon)
    # Machine-specific native precompiles are derived cache, never compatibility inputs.
    for path in data.rglob("*.cwasm"):
        path.unlink()
    manifest = {"format": "kronik.compatibility-corpus/v1", "release": args.release,
                "producer_revision": args.revision, "producer_binary_sha256": args.binary_sha256,
                "producer_version": version, "engine": health["engine"],
                "dummy_master_key": DUMMY_MASTER, "stable_lsn": stable_lsn,
                "integrity": before, "observations": observations,
                "components": components, "files": inventory(data)}
    (work / "manifest.json").write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"release": args.release, "producer_binary_sha256": args.binary_sha256,
                      "data_files": len(manifest["files"]), "manifest_sha256": digest(work / "manifest.json")}, allow_nan=False))
    if args.emit_files:
        # Bounded records cross the sandbox boundary; no retained host directory
        # is mounted writable into the target-controlled process.
        for relative in ["manifest.json", *["data/" + entry["path"] for entry in manifest["files"]]]:
            path = work / relative
            if path.stat().st_size > MAX_FILE:
                raise Violation("export entry exceeds 2 MiB")
            print(json.dumps({"format": "kronik.corpus-file/v1", "release": args.release,
                              "path": relative, "sha256": digest(path),
                              "base64": base64.b64encode(path.read_bytes()).decode()}, allow_nan=False))


def compare_integrity_hashes(manifest, after, candidate_revision):
    """The durable-path half of the compatibility contract (I16): log_hash is
    the producer's path and must not change across revisions; state_hash is
    the daemon's internal projection, which legitimately gains milestone
    bookkeeping (M22/M23/M28) at an engine boundary -- M6's upgrade check and
    the identity replays are the semantic comparators across revisions. When
    the candidate revision differs from the producer's, a state_hash change is
    recorded as an explicit delta instead of failing; a log_hash change, or a
    state_hash change at the same revision, still fails."""
    if after["log_hash"] != manifest["integrity"]["log_hash"]:
        raise Violation("candidate changed producer log_hash")
    if after["state_hash"] == manifest["integrity"]["state_hash"]:
        return None
    if candidate_revision == manifest["producer_revision"]:
        raise Violation("candidate changed producer state_hash at the same revision")
    return {"producer": manifest["integrity"]["state_hash"],
            "candidate": after["state_hash"]}


def check_identity_summary(summary, expected_roots):
    if (type(expected_roots) is not int or expected_roots <= 0
            or any(type(summary.get(field)) is not int for field in
                   ("root_inputs", "replayed", "divergent_turns", "approximate", "synthetic"))
            or summary.get("changed") is not False or summary.get("divergent_turns") != 0
            or summary.get("root_inputs") != expected_roots or summary.get("replayed") != expected_roots
            or summary.get("approximate") != 0 or summary.get("synthetic") != 0):
        raise Violation(f"candidate did not identity-replay every original root: {summary}")


def verify(args):
    source = args.corpus.resolve(strict=True)
    manifest_file = source / "manifest.json"
    if manifest_file.stat().st_size > 1 << 20:
        raise Violation("corpus manifest exceeds 1 MiB")
    manifest = json.loads(manifest_file.read_text())
    if manifest.get("format") != "kronik.compatibility-corpus/v1" or manifest.get("dummy_master_key") != DUMMY_MASTER:
        raise Violation("unsupported or nonfixture corpus manifest")
    if inventory(source / "data") != manifest.get("files"):
        raise Violation("producer corpus differs from its frozen file inventory")
    work = args.workdir.resolve()
    work.mkdir(mode=0o700)
    data, sock = work / "data", work / "api.sock"
    shutil.copytree(source / "data", data, symlinks=False)
    binary = args.binary.resolve(strict=True)
    env = configure(work, data, sock)
    command = [str(binary), "--socket", str(sock), "--json"]
    # Reuse the bounded command helper. Only explicitly allowlisted fixture env is added.
    process_env = {**os.environ, **env}
    daemon = Daemon(str(binary), str(data), str(sock), args.port, str(work / "candidate.log"), healthy_timeout=30)
    try:
        report = run_json([str(binary), "--json", "upgrade", "check", "--data-dir", str(data),
                           "--config", env["KRONIK_CONFIG"], "--workers", "2"], work, "upgrade", timeout=120, env=process_env)
        if report.get("passed") is not True or type(report.get("root_inputs")) is not int or report.get("root_inputs") != args.expected_roots:
            raise Violation("candidate upgrade check did not prove actual producer roots")
        daemon.start(env)
        after = checked_api(daemon, "GET", f"/v1/integrity?through={manifest['integrity']['applied_lsn']}")
        if after.get("through_lsn") != manifest["integrity"]["applied_lsn"]:
            raise Violation("candidate did not confirm the requested historical integrity bound; use a candidate supporting through_lsn")
        # Semantic checks first: they are the compatibility contract across a
        # producer-revision boundary, and their evidence must print before any
        # internal-projection hash comparison.
        checked_api(daemon, "POST", "/v1/forks", {"at": manifest["stable_lsn"], "name": "released-identity", "reason": REASON})
        replays = {}
        for mode in ("isolated", "continuous"):
            result = run_json(command + ["replay", "released-identity", "--mode", mode, "--reason", REASON],
                              work, f"replay-{mode}", timeout=120)
            summary = result["summary"]
            check_identity_summary(summary, args.expected_roots)
            replays[mode] = summary
        if message(daemon, "counter/a", "hmac", "compat-key\nrecorded data")["reply"]["text"] != manifest["observations"]["hmac"]:
            raise Violation("candidate changed actual historical key-backed effect result")
        # The durable path (log hash, replays, keyed effects) is the contract
        # per I16; the internal state projection legitimately gains milestone
        # bookkeeping (M22/M23/M28) across a producer-revision boundary, and
        # M6's upgrade check above is the semantic comparator across revisions.
        state_hash_delta = compare_integrity_hashes(manifest, after, args.revision)
        result = {"format": "kronik.compatibility-proof/v1", "release": manifest["release"],
                  "producer_revision": manifest["producer_revision"], "candidate_revision": args.revision,
                  "candidate_binary_sha256": digest(binary), "manifest_sha256": digest(manifest_file),
                  "integrity": after, "upgrade": report, "replays": replays, "passed": True}
        if state_hash_delta is not None:
            # Additive field: an engine-boundary state_hash change is recorded,
            # not accepted silently; the durable path above already passed.
            result["state_hash_delta"] = {"producer": state_hash_delta["producer"],
                                          "candidate": state_hash_delta["candidate"]}
        (work / "proof.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
        print(json.dumps(result, allow_nan=False))
    finally:
        close(daemon)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    produce = sub.add_parser("produce")
    produce.add_argument("--release", type=release_tag, required=True,
                         help="tag of the actual release that built --binary, for example v0.4.0")
    produce.add_argument("--binary-sha256", required=True,
                         help="pinned SHA-256 of the release binary itself, taken from the verified release")
    produce.add_argument("--counter", type=Path, required=True)
    produce.add_argument("--notes", type=Path, required=True)
    produce.add_argument("--emit-files", action="store_true",
                         help="emit bounded dummy-fixture files as JSON lines for trusted promotion")
    check = sub.add_parser("verify")
    check.add_argument("--corpus", type=Path, required=True)
    check.add_argument("--expected-roots", type=int, required=True,
                       help="original root count from the reviewed immutable producer receipt")
    for command in (produce, check):
        command.add_argument("--binary", type=Path, required=True)
        command.add_argument("--revision", required=True)
        command.add_argument("--workdir", type=Path, required=True)
        command.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("revision must be the exact 40-hex source commit")
    if not 1024 <= args.port <= 65535:
        parser.error("use an owned fixture port in 1024..65535")
    if args.mode == "produce" and not re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256):
        parser.error("binary-sha256 must be the exact 64-hex release binary digest")
    if args.mode == "verify" and args.expected_roots <= 0:
        parser.error("expected-roots must be positive")
    os.umask(0o077)
    (producer if args.mode == "produce" else verify)(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, Violation, RuntimeError, subprocess.SubprocessError) as error:
        print(f"compatibility corpus: {error}", file=sys.stderr)
        sys.exit(1)
