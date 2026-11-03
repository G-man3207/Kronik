#!/usr/bin/env python3
"""Exercise ordinary backup/restore, crash recovery and dummy credential rotation."""
import argparse
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from kronikd import Daemon, UnixConnection, Violation

spec = importlib.util.spec_from_file_location("compatibility_corpus", Path(__file__).with_name("compatibility-corpus.py"))
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)
REASON = "owned non-secret runbook drill"


def bearer_status(sock, bearer):
    connection = UnixConnection(str(sock), 5)
    try:
        connection.request("GET", "/v1/actors", headers={"Authorization": f"Bearer {bearer}"})
        response = connection.getresponse()
        body = response.read((1 << 20) + 1)
        if len(body) > 1 << 20:
            raise Violation("bounded bearer probe response exceeded 1 MiB")
        return response.status, json.loads(body)
    finally:
        connection.close()


def exact_replay(daemon, lsn, name):
    corpus.checked_api(daemon, "POST", "/v1/forks", {"at": lsn, "name": name, "reason": REASON})
    results = {}
    for mode in ("isolated", "continuous"):
        summary = daemon.cli("replay", name, "--mode", mode, "--reason", REASON)["summary"]
        if (summary.get("changed") is not False or summary.get("divergent_turns") != 0 or
            summary.get("root_inputs", 0) <= 0 or summary.get("replayed") != summary.get("root_inputs") or
            summary.get("approximate") != 0 or summary.get("synthetic") != 0):
            raise Violation(f"{name}/{mode} was not exact complete identity replay: {summary}")
        results[mode] = summary
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--counter", type=Path, required=True)
    parser.add_argument("--notes", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--workdir", type=Path, required=True, help="new owned directory only")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision) or not 1024 <= args.port <= 65535:
        parser.error("need exact 40-hex revision and owned port 1024..65535")
    os.umask(0o077)
    binary = args.binary.resolve(strict=True)
    work = args.workdir.resolve()
    work.mkdir(mode=0o700)
    data, sock, bucket = work / "source-data", work / "source.sock", work / "file-shipped"
    env = corpus.configure(work, data, sock)
    config = Path(env["KRONIK_CONFIG"])
    with config.open("a") as output:
        output.write("[ship]\nenabled = true\nurl = " + json.dumps(bucket.as_uri()) + "\n")
    source = Daemon(str(binary), str(data), str(sock), args.port, str(work / "source.log"), healthy_timeout=30)
    recovery = None
    results = {"format": "kronik.runbook-proof/v1", "revision": args.revision,
               "binary_sha256": corpus.digest(binary), "storage": "same-host file fixture; not off-host backup",
               "cluster_node_loss": "not exercised; requires actual public member lifecycle and three-node test environment"}
    try:
        source.start(env)
        for guest in (args.counter, args.notes):
            if guest.stat().st_size > 1 << 20:
                raise Violation("component exceeds 1 MiB")
            source.cli("deploy", str(guest.resolve(strict=True)), "--reason", REASON)
        corpus.checked_api(source, "PUT", "/v1/secrets/drill-key", {"text": "fixture-only-old-value", "reason": REASON})
        corpus.checked_api(source, "POST", "/v1/grants", {"kind": "counter", "capability": "secret:drill-key", "reason": REASON})
        stable_lsn = corpus.checked_api(source, "GET", "/v1/health")["applied_lsn"]
        for _ in range(3):
            corpus.message(source, "counter/drill", "increment")
        corpus.message(source, "notes/drill", "add", "retained fixture row")
        old = corpus.message(source, "counter/drill", "hmac", "drill-key\nprobe")["reply"]["text"]
        expected_old = hmac.new(b"fixture-only-old-value", b"probe", hashlib.sha256).hexdigest()
        if old != expected_old:
            raise Violation("old dummy key-backed effect did not match its actual key")
        # An actual crash, not an invented wait/elapsed result or a cluster failover.
        source.kill9()
        recovery_begin = time.perf_counter()
        source.start(env)
        recovery_seconds = time.perf_counter() - recovery_begin
        if corpus.message(source, "counter/drill", "get")["reply"]["text"] != "3":
            raise Violation("acknowledged counter state changed after SIGKILL")
        if corpus.message(source, "notes/drill", "list")["reply"]["text"] != "retained fixture row [-]\n":
            raise Violation("acknowledged SQL state changed after SIGKILL")
        results["single_node_crash_control"] = {"passed": True, "actual_recovery_seconds": recovery_seconds,
                                                 "counter": 3, "sql_rows": 1, "is_cluster_replacement": False}
        token = corpus.checked_api(source, "POST", "/v1/tokens",
                                   {"name": "drill-reader", "scopes": ["read"], "reason": REASON})
        bearer = token.get("secret")
        if not isinstance(bearer, str) or bearer_status(sock, bearer)[0] != 200:
            raise Violation("new fixture reader token did not authorize its read")
        source.cli("token", "revoke", "drill-reader", "--reason", REASON)
        denied_status, denied = bearer_status(sock, bearer)
        if denied_status != 401 or denied.get("error", {}).get("code") != "UNAUTHENTICATED":
            raise Violation("revoked fixture token still authorized a new protected request")
        corpus.checked_api(source, "PUT", "/v1/secrets/drill-key", {"text": "fixture-only-replacement", "reason": REASON})
        new = corpus.message(source, "counter/drill", "hmac", "drill-key\nprobe")["reply"]["text"]
        expected_new = hmac.new(b"fixture-only-replacement", b"probe", hashlib.sha256).hexdigest()
        if new != expected_new or new == old:
            raise Violation("new operation did not use the replaced dummy credential")
        replays = exact_replay(source, stable_lsn, "rotation-identity")
        results["dummy_credential_rotation"] = {"passed": True, "old_reader_status": denied_status,
                                                 "old_and_new_effects_differ": True, "replays": replays,
                                                 "cross_node_or_inflight_revocation": "not exercised"}
        snapshot = source.cli("snapshot", "create", "--reason", REASON)["snapshot"]
        if not snapshot:
            raise Violation("actual snapshot was not created")
        source_integrity = source.cli("integrity", "--through", str(snapshot["lsn"]))
        deadline = time.monotonic() + 35
        while True:
            snapshots = source.cli("snapshot", "list")["snapshots"]
            if any(item["id"] == snapshot["id"] and item.get("shipped") for item in snapshots):
                break
            if time.monotonic() >= deadline:
                raise Violation("actual snapshot did not ship within the 35 s fixture deadline")
            time.sleep(0.1)
        results["backup_format_flow"] = {"passed": True, "snapshot": snapshot,
                                          "source_integrity": source_integrity, "off_host": False}
        # Stop the source cleanly before reading an immutable shipped recovery fixture.
        source.stop()
        restored_data, restored_sock = work / "restored-data", work / "restored.sock"
        restore_work = work / "restore"
        restore_work.mkdir(mode=0o700)
        restored_env = corpus.configure(restore_work, restored_data, restored_sock)
        flags = [str(binary), "--json", "restore", "--from", bucket.as_uri(),
                 "--config", restored_env["KRONIK_CONFIG"], "--data-dir", str(restored_data)]
        wrong_env = {**os.environ, **restored_env, "KRONIK_MASTER_KEY": "55" * 32}
        with (restore_work / "wrong-key.json").open("xb") as output, (restore_work / "wrong-key.stderr").open("xb") as errors:
            refusal = subprocess.run(flags, stdout=output, stderr=errors, timeout=60, env=wrong_env)
        refusal_path = restore_work / "wrong-key.json"
        if refusal_path.stat().st_size > 1 << 20:
            raise Violation("wrong-key fixture response exceeded 1 MiB")
        failure = json.loads(refusal_path.read_text())
        if refusal.returncode == 0 or failure.get("error", {}).get("code") != "MASTER_KEY_MISMATCH":
            raise Violation("wrong fixture key was not explicitly refused")
        if (restored_data / "branches/main/state.db").exists():
            raise Violation("refused restore published the materialized store")
        restore_report = corpus.run_json(flags, restore_work, "restore", timeout=60,
                                         env={**os.environ, **restored_env})
        recovery = Daemon(str(binary), str(restored_data), str(restored_sock), args.port,
                          str(work / "restored.log"), healthy_timeout=30)
        recovery.start(restored_env)
        restored_integrity = recovery.cli("integrity", "--through", str(snapshot["lsn"]))
        for field in ("state_hash", "log_hash"):
            if restored_integrity[field] != source_integrity[field]:
                raise Violation(f"restored {field} differs at the actual source recovery point")
        if restored_integrity.get("keys_missing"):
            raise Violation("restored fixture has missing subject keys")
        if corpus.message(recovery, "counter/drill", "get")["reply"]["text"] != "3":
            raise Violation("restored acknowledged counter state changed")
        if corpus.message(recovery, "notes/drill", "list")["reply"]["text"] != "retained fixture row [-]\n":
            raise Violation("restored acknowledged SQL state changed")
        restored_replays = exact_replay(recovery, stable_lsn, "restored-identity")
        audit = corpus.checked_api(recovery, "GET", "/v1/audit?limit=1000")
        if not any(item.get("action") == "restore" for item in audit["lines"]):
            raise Violation("restored node did not publish its actual restore audit marker")
        results["restore_format_flow"] = {"passed": True, "wrong_key_refused": True,
                                           "restore": restore_report, "integrity": restored_integrity,
                                           "replays": restored_replays}
        results["passed"] = True
        (work / "proof.json").write_text(json.dumps(results, indent=2, allow_nan=False) + "\n")
        print(json.dumps(results, allow_nan=False))
    finally:
        if recovery is not None:
            corpus.close(recovery)
        corpus.close(source)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, Violation, RuntimeError, subprocess.SubprocessError) as error:
        print(f"runbook drill: {error}", file=sys.stderr)
        sys.exit(1)
