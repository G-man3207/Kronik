#!/usr/bin/env python3
"""Bounded real M10 fixture for the repository's propose/verify/promote jobs.

The two prebuilt guests and historical daemon are pinned; no builds, public
listener, production credentials or GitHub approval simulation occur here.
Run `smoke` for the local TLS/persistence/scoped-credential acceptance.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import ssl
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "G-man3207/Kronik"
BINARY_SHA256 = "1681833ad84da60622a6c196b8084bbe52a2deb8f6860a26c81dc9ea4f4a3947"
COMPONENTS = {
    "counter.wasm": "747c8630dfe34766b8b29f81787145b0c5061acef875be5c2c04c8da4ea70fb5",
    "counter-step2.wasm": "ea98978176bc2a2304cac9cd85f6e40636a9ed43980f722607403f6a4f30a8df",
}
# A public synthetic-fixture seed, never a production master key or artifact input.
FIXTURE_KEY = "4d" * 32
MAX_ARTIFACT = 128 << 20
TOKEN = re.compile(rb"kronik_[A-Za-z0-9_-]{43}")
PRIVATE_KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
KEYS = runpy.run_path(str(ROOT / "scripts/e2e-keys.py"))


def run(*args, env=None, check=True, timeout=60, data=None):
    result = subprocess.run([str(a) for a in args], input=data, env=env, capture_output=True, timeout=timeout)
    if check and result.returncode:
        output = result.stdout[-3000:] + result.stderr[-3000:]
        message = ("private-key output refused" if PRIVATE_KEY.search(output)
                   else TOKEN.sub(b"<redacted>", output).decode(errors="replace"))
        raise AssertionError(f"{args[:2]} exited {result.returncode}: {message}")
    return result


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def change(path):
    selected = json.loads(Path(path).read_text())
    if (not isinstance(selected, dict) or set(selected) != {"component", "reason"} or
            not isinstance(selected["component"], str) or selected["component"] not in COMPONENTS or
            not isinstance(selected["reason"], str) or not selected["reason"].strip() or
            len(selected["reason"]) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in selected["reason"])):
        raise ValueError("the proof manifest must select a pinned component and a short single-line reason")
    component = ROOT / "tests/guests" / selected["component"]
    if component.is_symlink() or digest(component) != COMPONENTS[selected["component"]]:
        raise ValueError("the selected component does not match its pinned real fixture")
    return selected


def identity():
    value = {"repository": os.environ.get("GITHUB_REPOSITORY", REPOSITORY),
             "head_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
             "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1")}
    if (value["repository"] != REPOSITORY or not re.fullmatch(r"[0-9a-f]{40}", value["head_sha"]) or
            not value["run_id"].isdigit() or not value["run_attempt"].isdigit()):
        raise ValueError("invalid repository/head/run/attempt correlation")
    return value


def state(root):
    root = Path(root).resolve()
    value = json.loads((root / "fixture.json").read_text())
    if value["root"] != str(root) or not value["name"].startswith("kronik-m10-"):
        raise ValueError("not an owned M10 fixture")
    return value


def owned(name, kind):
    result = run("docker", kind, "inspect", name, check=False)
    if result.returncode:
        return False
    item = json.loads(result.stdout)[0]
    labels = item.get("Config", item).get("Labels") or {}
    if labels.get("kronik.m10.fixture") != name:
        raise ValueError("refusing an unowned Docker resource")
    return True


def operator(root, *args):
    s = state(root)
    result = run("docker", "exec", "--user", f"{s['uid']}:{s['gid']}", s["name"],
                 "/release/kronik", "--socket", "/work/api.sock", "--json", *args)
    return json.loads(result.stdout)


def url_cli(root, token, *args, check=True, ca=None):
    s = state(root)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("KRONIK_", "SSL_CERT_", "INPUT_", "GITHUB_"))}
    env.update(KRONIK_URL=s["api"], KRONIK_TOKEN=token,
               SSL_CERT_FILE=str(ca or Path(root) / "tls/ca.pem"), SSL_CERT_DIR=str(Path(root) / "empty-ca"))
    return run(s["binary"], "--json", *args, env=env, check=check)


def response(root, key):
    s = state(root)
    request = urllib.request.Request(s["gateway"] + f"/counter/{key}/increment", data=b"", method="POST")
    with urllib.request.urlopen(request, timeout=10,
                                context=ssl.create_default_context(cafile=str(Path(root) / "tls/ca.pem"))) as result:
        assert result.status == 200
        return result.read(1024).decode()


def begin(selected, restored=None, parent=None):
    binary = Path(os.environ.get("KRONIK_BIN") or shutil.which("kronik") or "").resolve()
    if not binary.is_file() or digest(binary) != BINARY_SHA256:
        raise ValueError("KRONIK_BIN/PATH must select the pinned historical v0.3.0 binary")
    for name, expected in COMPONENTS.items():
        if digest(ROOT / "tests/guests" / name) != expected:
            raise ValueError("a pinned component fixture changed")
    root = Path(tempfile.mkdtemp(prefix="kronik-m10-", dir=parent or os.environ.get("RUNNER_TEMP", "/var/tmp")))
    uid, gid = (os.getuid(), os.getgid()) if os.getuid() else (10001, 10001)
    name = "kronik-m10-" + uuid.uuid4().hex[:16]
    s = {"root": str(root), "name": name, "uid": uid, "gid": gid, "binary": str(binary),
         "selection": selected, "identity": identity()}
    save(root / "fixture.json", s)
    try:
        KEYS["tls_fixtures"](root / "tls")
        (root / "empty-ca").mkdir(mode=0o700)
        for path in (root / "tls").iterdir():
            if os.getuid() == 0:
                os.chown(path, uid, gid)
        config = root / "kronik.toml"
        config.write_text('[server]\ndata_dir="/work/data"\napi_socket="/work/api.sock"\n'
                          'api_listen="0.0.0.0:7443"\nhttp_listen="0.0.0.0:7444"\n'
                          'admin_listen="127.0.0.1:9464"\n[tls]\nmode="files"\n'
                          'cert_file="/tls/server.pem"\nkey_file="/tls/server.key"\n'
                          '[log]\ndisk_reserve="16MiB"\n')
        run("docker", "network", "create", "--internal", "--label", "kronik.m10.fixture=" + name, name)
        run("docker", "create", "--name", name, "--label", "kronik.m10.fixture=" + name,
            "--network", name, "--read-only", "--user", f"{uid}:{gid}", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--memory", "768m", "--memory-swap", "768m",
            "--cpus", "1", "--pids-limit", "64", "--ulimit", "core=0:0",
            "--ulimit", "fsize=67108864:67108864", "--ulimit", "memlock=8388608:8388608",
            "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
            "--tmpfs", f"/work:rw,exec,nosuid,nodev,size=128m,mode=0700,uid={uid},gid={gid}",
            "--tmpfs", f"/tmp:rw,nosuid,nodev,size=16m,mode=0700,uid={uid},gid={gid}",
            "--mount", f"type=bind,src={binary},dst=/release/kronik,readonly",
            "--mount", f"type=bind,src={ROOT / 'tests/guests'},dst=/guests,readonly",
            "--mount", f"type=bind,src={root / 'tls/server.pem'},dst=/tls/server.pem,readonly",
            "--mount", f"type=bind,src={root / 'tls/server.key'},dst=/tls/server.key,readonly",
            "--mount", f"type=bind,src={config},dst=/config/kronik.toml,readonly",
            "--env", "KRONIK_MASTER_KEY", "--env", "RAYON_NUM_THREADS=1", "--env", "TOKIO_WORKER_THREADS=2",
            "--entrypoint", "sleep", KEYS["RUNTIME"], "600", env={**os.environ, "KRONIK_MASTER_KEY": FIXTURE_KEY})
        run("docker", "start", name)
        networks = json.loads(run("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", name).stdout)
        address = networks[name]["IPAddress"]
        # Internal networks intentionally do not publish ports; the runner uses its owned bridge route.
        extension = root / "tls/server.ext"
        extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                             f"extendedKeyUsage=serverAuth\nsubjectAltName=IP:{address}\n")
        run("openssl", "x509", "-req", "-in", root / "tls/server.csr", "-CA", root / "tls/ca.pem",
            "-CAkey", root / "tls/ca.key", "-CAcreateserial", "-days", "2", "-extfile", extension,
            "-out", root / "tls/server.pem")
        s.update(api=f"https://{address}:7443", gateway=f"https://{address}:7444")
        save(root / "fixture.json", s)
        if restored is not None:
            contents = io.BytesIO()
            with tarfile.open(fileobj=contents, mode="w") as tar:
                for path in restored.rglob("*"):
                    if path.is_file():
                        tar.add(path, arcname=str(path.relative_to(restored)), recursive=False)
            run("docker", "exec", "-i", name, "sh", "-c",
                "mkdir /work/data && tar -x --no-same-owner -C /work/data", data=contents.getvalue())
        run("docker", "exec", "--detach", name, "sh", "-c",
            '/release/kronik serve --config /config/kronik.toml >/work/serve.log 2>&1 & '
            'child=$!; echo "$child" >/work/daemon.pid; wait "$child"; echo "$?" >/work/daemon.exit')
        def healthy():
            result = run("docker", "exec", name, "/release/kronik", "--socket", "/work/api.sock",
                         "--json", "actors", "list", check=False, timeout=5)
            return result.returncode == 0
        KEYS["wait_for"]("real M10 daemon", healthy, seconds=45)
        if restored is None:
            operator(root, "deploy", "/guests/counter.wasm", "--reason", "synthetic M10 baseline")
            s["baseline_responses"] = [response(root, "m10-proof") for _ in range(3)]
            assert s["baseline_responses"] == ["1", "2", "3"]
            policy = root / "policy.toml"
            policy.write_text('[[rule]]\nname="m10-human-review"\nwhen="true"\naction="require_approval"\n')
            run("docker", "exec", "-i", name, "sh", "-c", "cat >/work/policy.toml", data=policy.read_bytes())
            operator(root, "policy", "set", "/work/policy.toml", "--reason", "real M10 approval gate")
        save(root / "fixture.json", s)
        return root
    except BaseException:
        cleanup(root)
        raise


def persisted(root, meta):
    proposal = meta["proposal_id"]
    paths = [f"branches/{proposal}/proposal.json", f"branches/{proposal}/diff.json"]
    paths += [path for path in meta["files"] if path.startswith("code/")]
    output = run("docker", "exec", state(root)["name"], "sha256sum",
                 *("/work/data/" + path for path in paths)).stdout.decode().splitlines()
    for relative, line in zip(paths, output, strict=True):
        if line.split()[0] != meta["files"][relative]:
            raise ValueError("persisted proposal/code/diff changed across the gate")


def credential(root, promote=False):
    name, scopes = ("m10-promote", "read,approve,promote") if promote else ("m10-propose", "read,propose")
    proof = state(root).get("proof")
    if proof is not None:
        persisted(root, proof)
    created = operator(root, "token", "create", "--name", name, "--scopes", scopes,
                       "--reason", "owned M10 fixture scoped credential")
    assert set(created["token"]["scopes"]) == set(scopes.split(","))
    assert created["token"]["created_by"] == f"unix:uid={state(root)['uid']}"
    if proof is not None:
        persisted(root, proof)
    return created["secret"]


def expose(root, token):
    s = state(root)
    print("::add-mask::" + token, flush=True)
    values = {"M10_FIXTURE": str(root), "KRONIK_URL": s["api"], "KRONIK_TOKEN": token,
              "SSL_CERT_FILE": str(root / "tls/ca.pem"), "SSL_CERT_DIR": str(root / "empty-ca")}
    with open(os.environ["GITHUB_ENV"], "a") as stream:
        for name, value in values.items():
            stream.write(f"{name}={value}\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write(f"component={ROOT / 'tests/guests' / s['selection']['component']}\n")
        stream.write(f"reason={s['selection']['reason']}\n")


def stopped_copy(root):
    s = state(root)
    run("docker", "exec", s["name"], "sh", "-c", 'kill -TERM "$(cat /work/daemon.pid)"')
    def exited():
        return run("docker", "exec", s["name"], "test", "-f", "/work/daemon.exit", check=False).returncode == 0
    KEYS["wait_for"]("clean daemon shutdown", exited, seconds=30)
    assert run("docker", "exec", s["name"], "cat", "/work/daemon.exit").stdout.strip() == b"0"
    copy = Path(root) / ("copy-" + uuid.uuid4().hex[:8])
    copy.mkdir(mode=0o700)
    data = copy / "data"
    data.mkdir(mode=0o700)
    raw = run("docker", "exec", s["name"], "tar", "-C", "/work/data", "-cf", "-", ".").stdout
    unpack(io.BytesIO(raw), data)
    return data


def distributable(path):
    # Never persist bootstrap/bearer credentials, master seeds or private TLS keys.
    return (path.name not in {"master.key", "admin.token", "bootstrap.token"} and
            not path.name.endswith((".key", ".pem", ".token")) and
            ("token" not in path.name.lower() or path.name.startswith("tokens.db")))


def files(data):
    result = {}
    for path in sorted(data.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("non-regular data artifact input")
        if path.is_file() and distributable(path):
            contents = path.read_bytes()
            if TOKEN.search(contents) or PRIVATE_KEY.search(contents):
                raise ValueError(f"plaintext credential/private key in artifact input: {path.relative_to(data)}")
            result[str(path.relative_to(data))] = hashlib.sha256(contents).hexdigest()
    return result


def unpack(archive, destination, expected=None):
    total, seen = 0, set()
    with tarfile.open(fileobj=archive, mode="r:*") as tar:
        for member in tar:
            relative = Path(member.name)
            name = relative.as_posix()
            total += member.size
            if (relative.is_absolute() or ".." in relative.parts or
                    not (member.isfile() or member.isdir()) or total > MAX_ARTIFACT):
                raise ValueError("unsafe/oversized artifact member")
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            if name in seen or (expected is not None and (name not in expected or not distributable(relative))):
                raise ValueError("duplicate/unknown/credential artifact member")
            seen.add(name)
            payload = tar.extractfile(member).read(MAX_ARTIFACT + 1)
            if expected is not None and (hashlib.sha256(payload).hexdigest() != expected[name] or
                                         TOKEN.search(payload) or PRIVATE_KEY.search(payload)):
                raise ValueError("changed artifact member or plaintext credential")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(payload)
            target.chmod(0o600)
    if expected is not None and seen != set(expected):
        raise ValueError("incomplete proposal artifact")


def artifact_digest(artifact):
    return hashlib.sha256((artifact / "proof.json").read_bytes() +
                          bytes.fromhex(digest(artifact / "data.tar.gz"))).hexdigest()


def snapshot(root, proposal):
    if not re.fullmatch(r"p-[0-9a-f]{12}", proposal):
        raise ValueError("invalid proposal identity")
    info = operator(root, "proposal", "status", proposal)
    assert info["policy"]["outcome"] == "require_approval" and info["status"] == "evaluated"
    data = stopped_copy(root)
    inventory = files(data)
    proposal_path = f"branches/{proposal}/proposal.json"
    diff_path = f"branches/{proposal}/diff.json"
    artifact = Path(root) / "artifact"
    artifact.mkdir(mode=0o700)
    archive = artifact / "data.tar.gz"
    total = 0
    with tarfile.open(archive, "w:gz") as tar:
        for relative in inventory:
            path = data / relative
            total += path.stat().st_size
            if total > MAX_ARTIFACT:
                raise ValueError("synthetic data exceeds its artifact limit")
            tar.add(path, arcname=relative, recursive=False)
    meta = {"schema_version": 1, **state(root)["identity"], "proposal_id": proposal,
            "selection": state(root)["selection"], "diff_hash": info["diff_hash"], "kinds": info["kinds"],
            "verified_through_lsn": info["verified_through_lsn"], "files": inventory,
            "proposal_file_sha256": inventory[proposal_path], "diff_file_sha256": inventory[diff_path],
            "archive_sha256": digest(archive), "baseline_responses": state(root)["baseline_responses"]}
    save(artifact / "proof.json", meta)
    for path in (archive, artifact / "proof.json"):
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
    meta["artifact_sha256"] = artifact_digest(artifact)
    return artifact, meta


def restore(artifact, proposal, expected_sha256, expected):
    artifact = Path(artifact)
    meta = json.loads((artifact / "proof.json").read_text())
    archive = artifact / "data.tar.gz"
    if (meta["schema_version"] != 1 or any(meta[key] != value for key, value in expected.items()) or
            meta["proposal_id"] != proposal or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or
            artifact_digest(artifact) != expected_sha256 or digest(archive) != meta["archive_sha256"] or
            archive.stat().st_size > MAX_ARTIFACT):
        raise ValueError("proposal artifact repository/head/run/attempt/proposal/digest mismatch")
    scratch = Path(tempfile.mkdtemp(prefix="kronik-m10-restore-", dir=artifact.parent))
    data = scratch / "data"
    data.mkdir(mode=0o700)
    try:
        with archive.open("rb") as stream:
            unpack(stream, data, meta["files"])
        for relative, field in ((f"branches/{proposal}/proposal.json", "proposal_file_sha256"),
                                (f"branches/{proposal}/diff.json", "diff_file_sha256")):
            if digest(data / relative) != meta[field]:
                raise ValueError("persisted proposal/diff identity mismatch")
        root = begin(meta["selection"], restored=data)
        try:
            actual = operator(root, "proposal", "status", proposal)
            assert actual["id"] == proposal and actual["diff_hash"] == meta["diff_hash"]
            assert actual["kinds"] == meta["kinds"] and actual["status"] == "evaluated"
            persisted(root, meta)
            s = state(root)
            s["proof"] = meta
            save(root / "fixture.json", s)
            return root
        except BaseException:
            cleanup(root)
            raise
    finally:
        shutil.rmtree(scratch)


def cleanup(root):
    root = Path(root)
    s = state(root)
    previous = root / "cleanup.json"
    evidence = json.loads(previous.read_text()) if previous.exists() else {"name": s["name"], "removed": []}
    for kind in ("container", "network"):
        if owned(s["name"], kind):
            args = ("docker", "rm", "--force", s["name"]) if kind == "container" else ("docker", "network", "rm", s["name"])
            run(*args)
            evidence["removed"].append(kind)
        assert not owned(s["name"], kind)
    for path in list(root.iterdir()):
        if path.name not in {"artifact", "evidence.json", "fixture.json"}:
            shutil.rmtree(path) if path.is_dir() and not path.is_symlink() else path.unlink()
    save(root / "cleanup.json", evidence)
    return evidence


def wire_fields(payload):
    """Read only the varint/bytes wire types in pinned Approval and Audit."""
    fields, offset = {}, 0
    def varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(payload):
                raise ValueError("truncated approval record")
            byte = payload[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError("oversized approval varint")
    while offset < len(payload):
        tag = varint()
        if tag >> 3 in fields or tag >> 3 == 0 or tag & 7 not in (0, 2):
            raise ValueError("unexpected approval wire field")
        if tag & 7 == 0:
            fields[tag >> 3] = varint()
        else:
            size = varint()
            if size > len(payload) - offset:
                raise ValueError("truncated approval field")
            fields[tag >> 3] = payload[offset:offset + size]
            offset += size
    return fields


def approval_record(payload, lsn, gated, github):
    fields = wire_fields(payload)
    audit = wire_fields(fields[4])
    actual = (fields[1].decode(), "b3:" + fields[2].hex(), fields.get(3, 0))
    expected = (gated["proposal_id"], gated["diff_hash"], gated["verified_through_lsn"])
    if actual != expected or fields.get(5, 0) != 0:
        raise ValueError("raw Approval does not match the original gated proposal/diff/verified LSN")
    assert audit[1].decode() == "token:m10-promote"
    reason = audit[2].decode()
    if github:
        assert "approved in the GitHub environment kronik-production" in reason
        assert "by G-man3207" in reason
        assert f"/{REPOSITORY}/actions/runs/{identity()['run_id']}" in reason
    return {"proposal_id": actual[0], "diff_hash": actual[1], "verified_through_lsn": actual[2],
            "lsn": lsn, "request": False, "token_id": audit[1].decode(), "reason": reason,
            "wire_payload_hex": payload.hex()}


def completed(root, proposal, github=True):
    gated = state(root)["proof"]
    if gated["proposal_id"] != proposal:
        raise ValueError("completion proposal does not match the original gated artifact")
    info = operator(root, "proposal", "status", proposal)
    assert info["status"] == "promoted"
    deployment = operator(root, "deployments", "list")["deployments"][-1]
    assert deployment["cause"] == "promote" and deployment["kinds"] == info["kinds"] == gated["kinds"]
    assert deployment["token_id"] == "token:m10-promote"
    assert response(root, "m10-completed") == "2"
    integrity = operator(root, "integrity")
    data = stopped_copy(root)
    meta = json.loads((data / f"branches/{proposal}/proposal.json").read_text())
    approval_lsn = meta["approved"]["lsn"]
    approvals = []
    for path in (data / "branches/main/log").glob("*.seg"):
        image = path.read_bytes()
        assert image[:8] == b"KRNK\x01\x00\x00\x00"
        offset = 24 + struct.unpack_from("<I", image, 16)[0]
        while offset < len(image):
            size, _, lsn, kind = struct.unpack_from("<IIQB", image, offset)
            end = offset + 17 + size
            assert end <= len(image)
            if kind == 8 and lsn == approval_lsn:
                approvals.append(approval_record(image[offset + 17:end], lsn, gated, github))
            offset = end
    assert len(approvals) == 1
    report = {"github_approval_record_required": github, "proposal_id": proposal,
              "gated_diff_hash": gated["diff_hash"],
              "gated_verified_through_lsn": gated["verified_through_lsn"],
              "post_promote_diff_hash": info["diff_hash"],
              "post_promote_verified_through_lsn": info["verified_through_lsn"],
              "approval": approvals[0], "deployment": deployment, "integrity": integrity,
              "changed_fresh_response": "2"}
    save(Path(root) / "evidence.json", report)
    return report


def reject_stale(root, proposal, previous_sha):
    if not re.fullmatch(r"[0-9a-f]{40}", previous_sha) or previous_sha == identity()["head_sha"]:
        raise ValueError("stale-head proof requires an actual different prior commit")
    before = operator(root, "proposal", "status", proposal)
    deployments = operator(root, "deployments", "list")
    assert before["status"] == "evaluated"
    env = dict(os.environ, GITHUB_SHA=previous_sha, INPUT_COMMAND="promote",
               INPUT_PROPOSAL=proposal, INPUT_ENVIRONMENT="kronik-production")
    result = run("python3", ROOT / "action/kronik_action.py", env=env, check=False)
    assert result.returncode != 0, "the actual stale-head promotion must fail"
    assert operator(root, "proposal", "status", proposal) == before
    assert operator(root, "deployments", "list") == deployments


def smoke():
    selected = {"component": "counter-step2.wasm", "reason": "real local M10 persistence smoke"}
    root = begin(selected)
    restored = None
    try:
        propose = credential(root)
        assert json.loads(url_cli(root, propose, "actors", "list").stdout)["actors"] == operator(root, "actors", "list")["actors"]
        for token in ("", "kronik_wrong"):
            assert url_cli(root, token, "actors", "list", check=False).returncode != 0
        assert url_cli(root, propose, "actors", "list", ca=root / "tls/untrusted.pem", check=False).returncode != 0
        assert url_cli(root, propose, "actors", "list", ca=root / "empty-ca/missing.pem", check=False).returncode != 0
        # The propose credential cannot create a privileged credential or approve.
        denied = url_cli(root, propose, "token", "create", "--name", "forbidden", "--scopes", "admin",
                         "--reason", "scope negative", check=False)
        assert denied.returncode != 0 and json.loads(denied.stdout)["error"]["code"] == "SCOPE_MISSING"
        started = json.loads(url_cli(root, propose, "propose", ROOT / "tests/guests/counter-step2.wasm",
                                     "--async", "--reason", selected["reason"]).stdout)
        pid = started["proposal"]["id"]
        info = json.loads(url_cli(root, propose, "proposal", "wait", pid, "--timeout", "30s").stdout)
        assert info["policy"]["outcome"] == "require_approval"
        assert url_cli(root, propose, "approve", pid, "--reason", "scope negative", check=False).returncode != 0
        run("docker", "exec", "-i", state(root)["name"], "sh", "-c",
            "mkdir /work/data/credentials; cat >/work/data/credentials/admin.token", data=propose.encode())
        run("docker", "exec", "-i", state(root)["name"], "sh", "-c",
            "cat >/work/data/credentials/bootstrap.key", data=(root / "tls/ca.key").read_bytes())
        artifact, meta = snapshot(root, pid)
        assert not any("credentials/" in name for name in meta["files"])
        for field, value in (("head_sha", "b" * 40), ("run_id", "999999"), ("run_attempt", "99"),
                             ("repository", "other/repository")):
            wrong = dict(identity(), **{field: value})
            try:
                restore(artifact, pid, meta["artifact_sha256"], wrong)
            except ValueError:
                pass
            else:
                raise AssertionError("a mismatched artifact identity was accepted")
        cleanup(root)
        restored = restore(artifact, pid, meta["artifact_sha256"], identity())
        promote = credential(restored, promote=True)
        assert all(t["name"] != "forbidden" for t in operator(restored, "token", "list")["tokens"])
        again = operator(restored, "proposal", "status", pid)
        assert again["diff_hash"] == meta["diff_hash"] and again["kinds"] == meta["kinds"]
        rejected = url_cli(restored, promote, "propose", ROOT / "tests/guests/counter-step2.wasm",
                           "--reason", "scope negative", check=False)
        assert rejected.returncode != 0 and json.loads(rejected.stdout)["error"]["code"] == "SCOPE_MISSING"
        # Local product proof only: this is deliberately not a fake GitHub human approval.
        approved = json.loads(url_cli(restored, promote, "approve", pid, "--reason", "local product smoke, not GitHub approval").stdout)
        deployment = json.loads(url_cli(restored, promote, "promote", pid, "--reason", selected["reason"]).stdout)
        assert response(restored, "m10-fresh") == "2"
        final = completed(restored, pid, github=False)
        report = {"github_acceptance": False, "tls": "trusted success; wrong CA/missing/wrong token refused",
                  "scopes": "real Unix operator creates read/propose then fresh read/approve/promote; cross-scope calls refused",
                  "exact_persisted_proposal": pid, "diff_hash_before_and_after_credential": meta["diff_hash"],
                  "kinds_before_and_after_credential": meta["kinds"], "artifact_sha256": meta["artifact_sha256"],
                  "baseline_responses": meta["baseline_responses"], "changed_fresh_response": "2",
                  "approval": approved, "deployment": deployment, "record_proof": final,
                  "plaintext_bootstrap_and_private_key_injection_excluded": True}
        save(root / "evidence.json", report)
        return root, report
    finally:
        if restored is not None:
            cleanup(restored)
        cleanup(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("start")
    snap = commands.add_parser("snapshot")
    snap.add_argument("--proposal", required=True)
    resumed = commands.add_parser("restore")
    resumed.add_argument("--artifact", required=True, type=Path)
    resumed.add_argument("--proposal", required=True)
    resumed.add_argument("--sha256", required=True)
    commands.add_parser("cleanup")
    commands.add_parser("smoke")
    checked = commands.add_parser("check")
    checked.add_argument("--proposal", required=True)
    stale = commands.add_parser("reject-stale")
    stale.add_argument("--proposal", required=True)
    stale.add_argument("--previous-sha", required=True)
    args = parser.parse_args()
    if args.command == "start":
        root = begin(change(ROOT / "examples/github-flow/proof/change.json"))
        try:
            expose(root, credential(root))
        except BaseException:
            cleanup(root)
            raise
    elif args.command == "snapshot":
        artifact, meta = snapshot(Path(os.environ["M10_FIXTURE"]), args.proposal)
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            stream.write(f"artifact={artifact}\nsha256={meta['artifact_sha256']}\n")
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(f"Persisted `{args.proposal}` at `{meta['head_sha']}`; diff `{meta['diff_hash']}`; artifact `{meta['artifact_sha256']}`.\n")
    elif args.command == "restore":
        root = restore(args.artifact, args.proposal, args.sha256, identity())
        try:
            expose(root, credential(root, promote=True))
        except BaseException:
            cleanup(root)
            raise
    elif args.command == "check":
        report = completed(Path(os.environ["M10_FIXTURE"]), args.proposal)
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(json.dumps(report, indent=2) + "\n")
    elif args.command == "reject-stale":
        reject_stale(Path(os.environ["M10_FIXTURE"]), args.proposal, args.previous_sha)
    elif args.command == "cleanup":
        if os.environ.get("M10_FIXTURE"):
            cleanup(Path(os.environ["M10_FIXTURE"]))
    else:
        root, report = smoke()
        print(json.dumps({"root": str(root), "result": report}, indent=2))


if __name__ == "__main__":
    main()
