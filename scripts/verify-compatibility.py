#!/usr/bin/env python3
"""Verify frozen released logs and genuine released components through a candidate."""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

from kronikd import Daemon, Violation

spec = importlib.util.spec_from_file_location("compatibility_corpus", Path(__file__).with_name("compatibility-corpus.py"))
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)
spec = importlib.util.spec_from_file_location("compatibility_contracts", Path(__file__).with_name("compatibility-contracts.py"))
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)


def fixture_file(root, relative):
    if not isinstance(relative, str) or "\\" in relative or "\0" in relative:
        raise Violation("invalid compatibility fixture path")
    parts = relative.split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise Violation("compatibility fixture path must be normalized and relative")
    path = root / PurePosixPath(relative)
    if not path.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
        raise Violation("compatibility fixture escapes its root")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > corpus.MAX_FILE:
        raise Violation("compatibility fixture must be a regular file at most 2 MiB")
    return path


def load_index(path):
    if path.stat().st_size > 1 << 20:
        raise Violation("compatibility index exceeds 1 MiB")
    index = json.loads(path.read_text())
    if not isinstance(index, dict):
        raise Violation("compatibility index must be an object")
    cases = index.get("releases")
    if index.get("format") != "kronik.compatibility-index/v2" or not isinstance(cases, list) or not 1 <= len(cases) <= 128:
        raise Violation("unsupported or empty compatibility index")
    published = index.get("published_releases")
    if (not isinstance(published, list) or not 1 <= len(published) <= 128
            or not all(isinstance(release, str) and re.fullmatch(r"v0\.[0-9]+\.[0-9]+", release) for release in published)
            or len(set(published)) != len(published)):
        raise Violation("declare the complete inspected published release set")
    seen = set()
    for case in cases:
        if not isinstance(case, dict):
            raise Violation("release entry must be an object")
        release = case.get("release", "")
        if not re.fullmatch(r"v0\.[0-9]+\.[0-9]+", release) or release in seen:
            raise Violation("invalid or duplicate actual release")
        seen.add(release)
        if not re.fullmatch(r"[0-9a-f]{40}", case.get("producer_revision", "")):
            raise Violation("release source revision must be pinned")
        for field in ("producer_binary_sha256", "manifest_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", case.get(field, "")):
                raise Violation(f"release {field} must be pinned")
        if type(case.get("root_inputs")) is not int or case["root_inputs"] <= 0:
            raise Violation("pin the original producer root count")
        snapshots = case.get("contracts")
        source_paths = {"api": ("openapi.json", "docs/reference/openapi.json"),
                        "cli": ("cli-json.txt", "docs/reference/json.md"),
                        "diff": ("diff-v1.schema.json", "docs/reference/diff-v1.schema.json"),
                        "wit": ("actor.wit", "wit/kronik-actor.wit")}
        if not isinstance(snapshots, dict) or snapshots.keys() != source_paths.keys():
            raise Violation("pin every released interface source snapshot")
        for role, (name, source_path) in source_paths.items():
            snapshot = snapshots[role]
            if (not isinstance(snapshot, dict) or snapshot.get("source_path") != source_path
                    or snapshot.get("path") != f"{release}/contracts/{name}"):
                raise Violation("released contract source lineage changed")
            payload = fixture_file(path.parent, snapshot["path"])
            content = payload.read_bytes()
            git_blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content, usedforsecurity=False).hexdigest()
            if (type(snapshot.get("bytes")) is not int or len(content) != snapshot["bytes"]
                    or corpus.digest(payload) != snapshot.get("sha256") or git_blob != snapshot.get("git_blob")):
                raise Violation("released contract snapshot differs from pinned source bytes")
        manifest_path = fixture_file(path.parent, case["manifest"])
        if corpus.digest(manifest_path) != case["manifest_sha256"]:
            raise Violation("frozen producer manifest digest mismatch")
        manifest = json.loads(manifest_path.read_text())
        for field in ("release", "producer_revision", "producer_binary_sha256"):
            if manifest.get(field) != case[field]:
                raise Violation(f"producer provenance disagrees with index: {field}")
        components = case.get("components")
        if (not isinstance(components, list) or len(components) != 2 or
                not all(isinstance(item, dict) for item in components) or
                {item.get("role") for item in components} != {"counter", "notes"}):
            raise Violation("each actual release needs its counter and SQL component")
        for component in components:
            if not re.fullmatch(r"[0-9a-f]{40}", component.get("git_blob", "")) or not re.fullmatch(r"[0-9a-f]{64}", component.get("sha256", "")):
                raise Violation("released component source and payload must be pinned")
            if component.get("source_path") != f"tests/guests/{component['role']}.wasm":
                raise Violation("unexpected released component source path")
            payload = fixture_file(path.parent, component["path"])
            if type(component.get("bytes")) is not int or payload.stat().st_size != component["bytes"] or corpus.digest(payload) != component["sha256"]:
                raise Violation("released component payload differs from source evidence")
    if seen != set(published):
        raise Violation("published release coverage is incomplete")
    return cases


def deploy_component(command, work, name):
    output, errors = work / f"{name}.json", work / f"{name}.stderr"
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=60, check=False)
    if output.stat().st_size > 1 << 20:
        raise Violation("component deployment response exceeds 1 MiB")
    value = json.loads(output.read_text())
    contracts.deployment_result(result.returncode, value)
    return result.returncode, value


def check_policy(daemon, root):
    fixture = json.loads(fixture_file(root, "policy-cases.json").read_text())
    cases = fixture.get("cases")
    if (fixture.get("format") != "kronik.policy-compatibility/v1" or not isinstance(cases, list)
            or not 1 <= len(cases) <= 128 or len({case["id"] for case in cases}) != len(cases)):
        raise Violation("invalid versioned public policy cases")
    results = {}
    for case in cases:
        rules_toml = "".join("[[rule]]\n" + "".join(f"{key} = {json.dumps(rule[key])}\n" for key in ("name", "when", "action"))
                             for rule in case["rules"])
        actual = corpus.checked_api(daemon, "POST", "/v1/policy/test",
                                    {"proposal": "released-components", "rules_toml": rules_toml})
        contracts.policy_result_compatible(case, actual)
        results[case["id"]] = actual
    return results


def check_components(args, case, root, work):
    work.mkdir(mode=0o700)
    data, sock = work / "data", work / "api.sock"
    daemon = Daemon(str(args.binary), str(data), str(sock), args.port, str(work / "components.log"), healthy_timeout=30)
    env = corpus.configure(work, data, sock)
    command = [str(args.binary), "--socket", str(sock), "--json"]
    source_root = Path(__file__).resolve().parents[1]
    old_package = contracts.wit_package(fixture_file(root, case["contracts"]["wit"]["path"]).read_text())
    supported_package = contracts.wit_package((source_root / "wit/kronik-actor.wit").read_text())
    component_modes = []
    try:
        daemon.start(env)
        for component in case["components"]:
            before = corpus.checked_api(daemon, "GET", "/v1/deployments")
            status, response = deploy_component(command + ["deploy", str(fixture_file(root, component["path"])), "--reason", corpus.REASON],
                                                work, f"deploy-{component['role']}")
            mode = {"role": component["role"], "status": "legacy-component-executed", "deployment": response}
            if status:
                if not contracts.migration_rejection(response, old_package, supported_package):
                    raise Violation("old WIT component needs an actual clear product migration rejection, not a generic failure")
                if corpus.checked_api(daemon, "GET", "/v1/deployments") != before:
                    raise Violation("rejected old component partially changed deployments")
                current = fixture_file(source_root, f"tests/guests/{component['role']}.wasm")
                current_status, current_response = deploy_component(command + ["deploy", str(current), "--reason", corpus.REASON],
                                                                    work, f"deploy-current-{component['role']}")
                if current_status:
                    raise Violation("the current maintained component cannot execute the stated migration path")
                mode = {"role": component["role"], "status": "clear-migration-rejection",
                        "rejection_exit_code": status, "rejection": response,
                        "current_component_sha256": corpus.digest(current), "deployment": current_response}
            component_modes.append(mode)
        stable_lsn = corpus.checked_api(daemon, "GET", "/v1/health")["applied_lsn"]
        for _ in range(2):
            corpus.message(daemon, "counter/released", "increment")
        counter = corpus.message(daemon, "counter/released", "get")["reply"]["text"]
        corpus.message(daemon, "notes/released", "add", "released component retained row")
        sql_rows = corpus.message(daemon, "notes/released", "count")["reply"]["text"]
        if counter != "2" or sql_rows != "1":
            raise Violation(f"released component state transitions changed: counter={counter!r}, SQL rows={sql_rows!r}")
        corpus.checked_api(daemon, "POST", "/v1/forks", {"at": stable_lsn, "name": "released-components", "reason": corpus.REASON})
        replays = {}
        for mode in ("isolated", "continuous"):
            result = corpus.run_json(command + ["replay", "released-components", "--mode", mode, "--reason", corpus.REASON],
                                     work, f"components-replay-{mode}", timeout=120)
            summary = result["summary"]
            if (summary.get("changed") is not False or summary.get("divergent_turns") != 0 or
                    summary.get("root_inputs") != 5 or summary.get("replayed") != 5 or
                    summary.get("approximate") != 0 or summary.get("synthetic") != 0):
                raise Violation(f"released component {mode} replay is not exact and complete: {summary}")
            replays[mode] = summary
        diff = corpus.checked_api(daemon, "GET", "/v1/forks/released-components/diff")
        if diff.get("schema") != "kronik.diff/v1":
            raise Violation("public diff lost its versioned compatibility contract")
        for field in ("changed", "divergent_turns", "root_inputs", "replayed", "approximate", "synthetic"):
            if diff.get("summary", {}).get(field) != replays["continuous"][field]:
                raise Violation(f"public API diff disagrees with the actual CLI replay: {field}")
        policy = check_policy(daemon, root)
        return {"release": case["release"], "counter": counter, "sql_rows": sql_rows,
                "components": case["components"], "replays": replays, "diff_schema": diff["schema"],
                "wit": {"original_package": old_package, "supported_package": supported_package, "components": component_modes},
                "policy": policy, "passed": True}
    finally:
        corpus.close(daemon)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision) or not 1024 <= args.port <= 65535:
        parser.error("use an exact 40-hex candidate revision and an owned fixture port")
    os.umask(0o077)
    args.binary = args.binary.resolve(strict=True)
    args.index = args.index.resolve(strict=True)
    cases = load_index(args.index)
    args.workdir = args.workdir.resolve()
    args.workdir.mkdir(mode=0o700)
    proofs = []
    for case in cases:
        log_args = argparse.Namespace(binary=args.binary, revision=args.revision, port=args.port,
                                      corpus=fixture_file(args.index.parent, case["manifest"]).parent,
                                      expected_roots=case["root_inputs"],
                                      workdir=args.workdir / f"{case['release']}-log")
        corpus.verify(log_args)
        proofs.append(check_components(args, case, args.index.parent, args.workdir / f"{case['release']}-components"))
    result = {"format": "kronik.compatibility-index-proof/v2", "candidate_revision": args.revision,
              "candidate_binary_sha256": corpus.digest(args.binary), "index_sha256": corpus.digest(args.index),
              "releases": proofs, "passed": True}
    (args.workdir / "proof.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, Violation, RuntimeError, subprocess.SubprocessError) as error:
        print(f"compatibility verification: {error}", file=sys.stderr)
        sys.exit(1)
