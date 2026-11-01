#!/usr/bin/env python3
"""Build one committed source twice, without sharing compiled Kronik output."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import tempfile
import sys


TARGETS = ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl")
ROOT = Path(__file__).resolve().parent.parent


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def compare_builds(first, second, with_keyhelper=False):
    targets = {}
    artifacts = [("kronik", target) for target in TARGETS]
    if with_keyhelper:
        artifacts.append(("kronik-keyhelper", "x86_64-unknown-linux-gnu"))
    for name, target in artifacts:
        binaries = [root / "target" / target / "release" / name for root in (first, second)]
        digest = sha256(binaries[0])
        if digest != sha256(binaries[1]):
            raise ValueError(f"compiled {target} ELF bytes differ between independent builds")
        archives = [root / "source/dist/release" / f"{name}-{target}.tar.gz" for root in (first, second)]
        members = []
        for archive in archives:
            current = {}
            with tarfile.open(archive, "r:gz") as tar:
                for member in tar:
                    if not member.isfile() or member.name in current:
                        raise ValueError(f"invalid release member in {archive.name}: {member.name}")
                    current[member.name] = hashlib.file_digest(tar.extractfile(member), "sha256").hexdigest()
            if current.get(name) != digest:
                raise ValueError(f"{archive.name} does not contain this build's actual ELF")
            members.append(current)
        if members[0] != members[1]:
            raise ValueError(f"{target} archive payload bytes differ between independent builds")
        targets[target] = {"elf_sha256": digest, "compiled_paths": [str(path) for path in binaries],
                           "members": members[0], "archive_sha256": sha256(archives[0])}
    outputs = [root / "source/dist/release" for root in (first, second)]
    names = [{path.name for path in output.iterdir() if path.is_file()} for output in outputs]
    if names[0] != names[1]:
        raise ValueError("independent build output inventories differ")
    files = {}
    for name in sorted(names[0]):
        digest = sha256(outputs[0] / name)
        if digest != sha256(outputs[1] / name):
            raise ValueError(f"unsigned distribution bytes differ: {name}")
        files[name] = digest
    return {"targets": targets, "files": files}


def build(source, env, log):
    with log.open("xb") as output:
        child = subprocess.Popen(["timeout", "--kill-after=30s", "7200", "bash", "scripts/release.sh"],
                                 cwd=source, env=env, start_new_session=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def stop(signum, _frame):
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            raise SystemExit(128 + signum)

        previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            for line in child.stdout:
                output.write(line)
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
            code = child.wait()
            if code:
                raise subprocess.CalledProcessError(code, child.args)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            child.stdout.close()
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def main():
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    epoch = subprocess.check_output(["git", "show", "-s", "--format=%ct", commit], cwd=ROOT, text=True).strip()
    with_keyhelper = os.environ.get("KRONIK_RELEASE_KEYHELPER", "no")
    if with_keyhelper not in ("yes", "no"):
        raise ValueError("KRONIK_RELEASE_KEYHELPER must be yes or no")
    with tempfile.TemporaryDirectory(prefix="kronik-repro-", dir=os.environ.get("TMPDIR", "/var/tmp")) as directory:
        work = Path(directory)
        source_archive = work / "source.tar"
        subprocess.run(["git", "archive", "--format=tar", "--output", str(source_archive), commit], cwd=ROOT, check=True)
        cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
        rustup_home = Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup")).resolve()
        home = work / "home"
        home.mkdir(mode=0o700)
        env = {"PATH": str(cargo_home / "bin") + ":/usr/local/bin:/usr/bin:/bin", "HOME": str(home),
               "CARGO_HOME": str(cargo_home), "RUSTUP_HOME": str(rustup_home), "LC_ALL": "C", "TZ": "UTC",
               "SOURCE_DATE_EPOCH": epoch, "CARGO_BUILD_JOBS": "4", "KRONIK_RELEASE_TOOLS": str(work / "tools"),
               "KRONIK_BASE_URL": os.environ.get("KRONIK_BASE_URL", "@BASE_URL@"),
               "KRONIK_RELEASE_KEYHELPER": with_keyhelper, "CARGO_INCREMENTAL": "0"}
        builds = []
        for name in ("first", "second"):
            root = work / name
            source = root / "source"
            source.mkdir(parents=True, mode=0o700)
            subprocess.run(["tar", "-xf", str(source_archive), "-C", str(source)], check=True)
            env["CARGO_TARGET_DIR"] = str(root / "target")
            build(source, env, root / "cargo-build.log")
            builds.append(root)
        proof = compare_builds(*builds, with_keyhelper=with_keyhelper == "yes")
        proof.update(source_commit=commit, source_date_epoch=int(epoch), source_archive_sha256=sha256(source_archive),
                     shared_inputs="pinned compiler, Rust/Cargo source inputs and release tools only; no compiled Kronik output",
                     rustc=subprocess.check_output([str(cargo_home / "bin/rustc"), "-Vv"], env=env, text=True).strip(),
                     input_sha256={name: sha256(builds[0] / "source" / name)
                                   for name in ("Cargo.lock", "rust-toolchain.toml", "scripts/release.sh", "scripts/package-release.py")})
        proof["build_logs"] = [{"source": str(root / "source"), "target": str(root / "target"),
                                "sha256": sha256(root / "cargo-build.log"),
                                "text": (root / "cargo-build.log").read_text()}
                               for root in builds]
        proof["with_keyhelper"] = with_keyhelper == "yes"
        sysroot = Path(subprocess.check_output([str(cargo_home / "bin/rustc"), "--print", "sysroot"], env=env, text=True).strip())
        tools = work / "tools"
        zig = list(tools.glob("zig-*-linux-*/zig"))
        if len(zig) != 1:
            raise ValueError("reproduction must use one exact pinned Zig input")
        proof["tool_sha256"] = {str(path.relative_to(tools)): sha256(path)
                                for path in (*zig, tools / "bin/cargo-zigbuild", tools / "bin/cargo-cyclonedx")}
        proof["rustc_sha256"] = sha256(sysroot / "bin/rustc")
        proof["rustup_manifest_sha256"] = sha256(sysroot / "lib/rustlib/multirust-channel-manifest.toml")
        proof["build_platform"] = {"system": os.uname().sysname, "machine": os.uname().machine}
        destination = ROOT / "dist/release"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(builds[0] / "source/dist/release", destination)
        report = destination / "reproducibility.json"
        report.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
        with (destination / "SHA256SUMS").open("a") as stream:
            stream.write(f"{sha256(report)}  reproducibility.json\n")
        print(f"Independent compiled release comparison passed for {commit}")


if __name__ == "__main__":
    main()
