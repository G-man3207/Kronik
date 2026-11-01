#!/usr/bin/env python3
"""Real public Sigstore fixture through both consumers; no production trust override.

The private SOURCE copies name cli/cli's genuine signed 2.103.3 artifact and
certificate. They do not manufacture a certificate or claim a signed Kronik
release. --with-runsc belongs only in an owned disposable root container.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action/kronik_action.py"
FIXTURE_VERSION = "2.103.3"
FIXTURE_REPO = "cli/cli"
FIXTURE_REPO_ID = "212613049"
FIXTURE_WORKFLOW = ".github/workflows/deployment.yml"
FIXTURE_REF = "refs/heads/trunk"
HASHES = {
    "amd64": "4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d",
    "arm64": "ee32df2323c8847f5fac6cb6b4b69ca75828e9329a8f22f677021f7b3306ce63",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def action_source(values):
    tree = ast.parse(ACTION.read_text())
    remaining = set(values)
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in values:
                node.value = ast.parse(repr(values[name]), mode="eval").body
                remaining.remove(name)
    if remaining:
        raise ValueError(f"missing fixture SOURCE constants: {sorted(remaining)}")
    return ast.unparse(tree) + "\n"


def shell_source(text, values):
    for name, value in values.items():
        pattern = r"(?m)^" + re.escape(name) + r"=(?:'[^']*'|[^\n]*)"
        text, count = re.subn(pattern, lambda _match: name + "=" + shlex.quote(value), text, count=1)
        if count != 1:
            raise ValueError(f"missing fixture SOURCE constant: {name}")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, help="Read-only cache of the two exact official archives")
    parser.add_argument("--download-tmp", type=Path, help="Owned executable temp filesystem, distinct for cross-filesystem proof")
    parser.add_argument("--with-runsc", action="store_true", help="Exercise existing yes/install semantics in an owned disposable root container")
    args = parser.parse_args()
    if args.with_runsc and (os.getuid() != 0 or not Path("/.dockerenv").exists()):
        raise SystemExit("--with-runsc requires an owned disposable root Docker container")
    if args.with_runsc:
        assert shutil.which("gh") is None, "fresh-bootstrap fixture must not contain a system gh"
        assert shutil.which("runsc") is None, "runtime-install fixture must start without runsc"
    with tempfile.TemporaryDirectory(prefix="kronik-signed-consumers-") as directory:
        work = Path(directory)
        fixtures = work / "fixtures"
        fixtures.mkdir()
        home = work / "home"
        home.mkdir(mode=0o700)
        private = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C"}
        archives = {}
        members = {}
        for arch, expected in HASHES.items():
            name = f"gh_{FIXTURE_VERSION}_linux_{arch}.tar.gz"
            path = fixtures / name
            if args.fixture_dir:
                shutil.copyfile(args.fixture_dir / name, path)
            else:
                subprocess.run(["curl", "-q", "-fsSL", "--proto", "=https", "--max-time", "120", "-o", str(path),
                                f"https://github.com/cli/cli/releases/download/v{FIXTURE_VERSION}/{name}"],
                               env=private, check=True, timeout=130)
            if digest(path) != expected:
                raise ValueError(f"official {arch} fixture hash mismatch")
            archives[arch] = path
            with tarfile.open(path, "r:gz") as tar:
                members[arch] = tuple(member.name for member in tar)
        bundle = ROOT / "action/tests/fixtures/gh-2.103.3.sigstore.json"
        render = runpy.run_path(str(ROOT / "scripts/package-release.py"))["render_installer"]
        template = (ROOT / "scripts/install.sh").read_text()
        helper = (ROOT / "scripts/install-runsc.sh").read_text()
        real_binary = {}
        for arch in HASHES:
            with tarfile.open(archives[arch], "r:gz") as tar:
                real_binary[arch] = tar.extractfile(f"gh_{FIXTURE_VERSION}_linux_{arch}/bin/gh").read()
        if len(real_binary["amd64"]) <= 1024 * 1024:
            raise ValueError("fixture executable is too small for the real EFBIG test")
        results = []
        cases = [("valid", {}), ("unsigned", {}), ("changed-artifact", {}), ("changed-signature", {}),
                 ("wrong-repository", {"RELEASE_REPOSITORY": "G-man3207/Kronik"}),
                 ("wrong-numeric-repository", {"RELEASE_REPOSITORY_ID": "1432583300"}),
                 ("wrong-workflow", {"RELEASE_WORKFLOW": ".github/workflows/not-deployment.yml"}),
                 ("wrong-ref", {"RELEASE_REF": "refs/tags/v2.103.3"}),
                 ("wrong-issuer", {"RELEASE_ISSUER": "https://example.invalid/issuer"}),
                 ("changed-verifier", {}), ("wrong-elf-architecture", {}),
                 ("real-write-failure", {}), ("real-notice-write-failure", {})]
        helper_cases = [("helper-" + case, changes) for case, changes in cases if case != "changed-verifier"]
        helper_cases.append(("helper-wrong-artifact", {}))
        consumers = ("standalone", "source", "action") if args.with_runsc else ("source", "standalone", "action")
        for consumer in consumers:
            selected = cases[:1] if args.with_runsc or consumer == "source" else cases[:]
            if not args.with_runsc and consumer != "action":
                selected += helper_cases[:1] if consumer == "source" else helper_cases
            for case, changes in selected:
                case_label = case
                helper_selected = case.startswith("helper-")
                case = case.removeprefix("helper-")
                fault_limit = 512 if case == "real-notice-write-failure" else 1048576
                root = work / f"{consumer}-{case_label}"
                root.mkdir()
                mirror = root / "mirror"
                mirror.mkdir()
                archive_name = archives["amd64"].name
                arch = "arm64" if case == "wrong-elf-architecture" else "amd64"
                daemon_arch = "amd64" if helper_selected else arch
                (mirror / archive_name).symlink_to(archives[daemon_arch])
                bundle_path = mirror / (archive_name + ".sigstore.json")
                if helper_selected or case != "unsigned":
                    shutil.copyfile(bundle, bundle_path)
                artifact_name = archive_name
                if helper_selected:
                    artifact_name = "helper-fixture.tar.gz"
                    (mirror / artifact_name).symlink_to(archives[arch])
                    bundle_path = mirror / (artifact_name + ".sigstore.json")
                    if case != "unsigned":
                        shutil.copyfile(bundle, bundle_path)
                if case == "changed-artifact":
                    (mirror / artifact_name).unlink()
                    shutil.copyfile(archives["amd64"], mirror / artifact_name)
                    with (mirror / artifact_name).open("ab") as stream:
                        stream.write(b"changed artifact")
                    (mirror / (artifact_name + ".sha256")).write_text(f"{digest(mirror / artifact_name)}  {artifact_name}\n")
                if case == "changed-signature":
                    item = json.loads(bundle.read_text())
                    for signature in item["dsseEnvelope"]["signatures"]:
                        signature["sig"] = ("A" if signature["sig"][0] != "A" else "B") + signature["sig"][1:]
                    bundle_path.write_text(json.dumps(item) + "\n")
                verifier_url = fixtures.as_uri()
                if case == "changed-verifier":
                    bad = root / "bad-verifier"
                    bad.mkdir()
                    bad_path = bad / archive_name
                    shutil.copyfile(archives["amd64"], bad_path)
                    with bad_path.open("ab") as stream:
                        stream.write(b"changed verifier")
                    verifier_url = bad.as_uri()
                prefix = f"gh_{FIXTURE_VERSION}_linux_{daemon_arch}/"
                files = {"kronik": prefix + "bin/gh", "LICENSE": prefix + "LICENSE",
                         "NOTICE": prefix + "LICENSE", "THIRD_PARTY_LICENSES.txt": prefix + "LICENSE"}
                values = {"RELEASE_REPOSITORY": FIXTURE_REPO, "RELEASE_REPOSITORY_ID": FIXTURE_REPO_ID,
                          "RELEASE_WORKFLOW": FIXTURE_WORKFLOW, "RELEASE_REF": FIXTURE_REF,
                          "RELEASE_ARCHIVE": archive_name, "RELEASE_FILES": files,
                          "RELEASE_EXTRA_FILES": tuple(name for name in members[daemon_arch] if name not in files.values()),
                          "VERIFIER_URL": verifier_url}
                if helper_selected:
                    helper_prefix = f"gh_{FIXTURE_VERSION}_linux_{arch}/"
                    helper_files = {"kronik-keyhelper": helper_prefix + "bin/gh",
                                    "LICENSE": helper_prefix + "LICENSE", "NOTICE": helper_prefix + "LICENSE",
                                    "THIRD_PARTY_LICENSES.txt": helper_prefix + "LICENSE"}
                    if case == "wrong-artifact":
                        helper_files["kronik-keyhelper"] = "kronik-keyhelper"
                    values.update(HELPER_ARCHIVE=artifact_name, HELPER_FILES=helper_files)
                else:
                    values.update(changes)
                if args.with_runsc:
                    values.pop("VERIFIER_URL")
                destination = root / "runner/kronik-bin"
                destination.mkdir(parents=True)
                old = destination / "kronik"
                old.write_bytes(Path(sys.executable).read_bytes())
                old.chmod(0o755)
                before = digest(old)
                old_helper = destination / "kronik-keyhelper"
                old_helper.write_bytes(Path(sys.executable).read_bytes())
                old_helper.chmod(0o755)
                helper_before = digest(old_helper)
                notices = destination / "kronik-licenses"
                notices.mkdir()
                original_notices = {name: ("existing-" + name).encode() for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt")}
                for name, data in original_notices.items():
                    (notices / name).write_bytes(data)
                temporary = args.download_tmp or root / "tmp"
                temporary.mkdir(mode=0o700, exist_ok=True)
                env = dict(private, TMPDIR=str(temporary), RUNNER_TEMP=str(root / "runner"),
                           INPUT_COMMAND="install", INPUT_BASE_URL=mirror.as_uri(), INPUT_VERSION=FIXTURE_VERSION,
                           KRONIK_BASE_URL=mirror.as_uri(), KRONIK_VERSION=FIXTURE_VERSION,
                           KRONIK_INSTALL_DIR=str(destination), KRONIK_INSTALL_RUNSC="yes" if args.with_runsc and case == "valid" else "no",
                           KRONIK_INSTALL_KEYHELPER="yes" if helper_selected else "no")
                if consumer == "action":
                    source = root / "action.py"
                    source.write_text(action_source(values))
                    command = [sys.executable, "-B", str(source)]
                    if case in ("real-write-failure", "real-notice-write-failure"):
                        fault = root / "fault.py"
                        fault.write_text("import resource,runpy,signal,sys\n"
                                         "m=runpy.run_path(sys.argv[1]); main=m['main']; original=main.__globals__['install_payload']\n"
                                         "def fail_write(payload):\n"
                                         " signal.signal(signal.SIGXFSZ,signal.SIG_IGN)\n"
                                         f" resource.setrlimit(resource.RLIMIT_FSIZE,({fault_limit},{fault_limit}))\n"
                                         " original(payload)\n"
                                         "main.__globals__['install_payload']=fail_write\n"
                                         "try: main()\n"
                                         "except m['Failure'] as error: print(error,file=sys.stderr); sys.exit(1)\n")
                        command = [sys.executable, "-B", str(fault), str(source)]
                else:
                    shell_values = {name: value for name, value in values.items()
                                    if name not in ("RELEASE_ARCHIVE", "RELEASE_EXTRA_FILES", "RELEASE_FILES", "HELPER_FILES")}
                    shell_values.update(RELEASE_FILES="\n".join(f"{name} {path}" for name, path in files.items()),
                                        archive=archive_name)
                    if helper_selected:
                        shell_values["HELPER_FILES"] = "\n".join(f"{name} {path}" for name, path in helper_files.items())
                    source = root / "install.sh"
                    text = template if consumer == "source" else render(ROOT, FIXTURE_VERSION, mirror.as_uri())
                    text = shell_source(text, shell_values)
                    if helper_selected and changes:
                        # Change only trusted fixture SOURCE policy after the daemon is verified.
                        call = '    verify_release "$tmp/helper.tar.gz" "$tmp/helper.bundle.json"'
                        assert text.count(call) == 1
                        assignments = "\n".join("    " + name + "=" + shlex.quote(value)
                                                for name, value in changes.items())
                        text = text.replace(call, assignments + "\n" + call, 1)
                    source.write_text(text)
                    if consumer == "source":
                        (root / "install-runsc.sh").write_text(helper)
                    else:
                        env.pop("KRONIK_BASE_URL")
                        env.pop("KRONIK_VERSION")
                    command = ["sh", str(source)]
                    if consumer == "standalone":
                        command = ["bash", "-o", "pipefail", "-c",
                                   'curl -q -fsSL --max-time 30 "$1" | sh', "fixture", source.as_uri()]
                    if case in ("real-write-failure", "real-notice-write-failure"):
                        fault_bin = root / "fault-bin"
                        fault_bin.mkdir()
                        cp = fault_bin / "cp"
                        fault_name = "LICENSE" if case == "real-notice-write-failure" else "kronik-keyhelper" if helper_selected else "kronik"
                        fault_condition = f"os.path.basename(sys.argv[1]) == {fault_name!r}"
                        if helper_selected:
                            fault_condition += " and os.path.basename(os.path.dirname(sys.argv[1])) == 'helper'"
                        cp.write_text(f"#!{sys.executable}\nimport os,resource,signal,sys\n"
                                      f"if {fault_condition}:\n"
                                      " signal.signal(signal.SIGXFSZ,signal.SIG_IGN)\n"
                                      f" resource.setrlimit(resource.RLIMIT_FSIZE,({fault_limit},{fault_limit}))\n"
                                      f"os.execv({shutil.which('cp')!r},sys.argv)\n")
                        cp.chmod(0o700)
                        env["PATH"] = str(fault_bin) + ":" + private["PATH"]
                old_version = subprocess.check_output([str(old), "--version"], env=private)
                process = subprocess.run(command, env=env, capture_output=True, text=True,
                                         stdin=subprocess.DEVNULL, timeout=240)
                if case == "valid":
                    assert process.returncode == 0, (consumer, case, process.stdout, process.stderr)
                    assert old.read_bytes() == real_binary["amd64"]
                    assert old.stat().st_mode & 0o777 == 0o755
                    actual_version = subprocess.check_output([str(old), "--version"], env=private).decode().splitlines()[0]
                    assert "2.103.3" in actual_version
                    if helper_selected:
                        assert old_helper.read_bytes() == real_binary["amd64"]
                        assert old_helper.stat().st_mode & 0o777 == 0o755
                        assert "2.103.3" in subprocess.check_output([str(old_helper), "--version"], env=private).decode()
                    else:
                        assert digest(old_helper) == helper_before, "default install changed the unselected helper"
                else:
                    assert process.returncode != 0, (consumer, case, process.stdout, process.stderr)
                    assert digest(old) == before, (consumer, case, "existing executable changed")
                    assert subprocess.check_output([str(old), "--version"], env=private) == old_version
                    assert digest(old_helper) == helper_before, "existing helper changed on refusal/write failure"
                    if case in ("real-write-failure", "real-notice-write-failure"):
                        assert "File too large" in process.stdout + process.stderr
                    elif case == "wrong-elf-architecture":
                        assert "ELF" in process.stdout + process.stderr
                    elif case == "wrong-artifact":
                        assert "kronik-keyhelper" in process.stdout + process.stderr
                    else:
                        assert {name: (notices / name).read_bytes() for name in original_notices} == original_notices
                    assert list(destination.glob(".kronik*")) == []
                results.append({"consumer": consumer, "case": case_label, "exit": process.returncode,
                                "existing_binary_preserved": case != "valid",
                                "selected_helper": helper_selected,
                                "existing_helper_preserved": not helper_selected or case != "valid",
                                "cross_filesystem": temporary.stat().st_dev != destination.stat().st_dev,
                                "installed_executable_mode": oct(old.stat().st_mode & 0o777),
                                "official_https_bootstrap": args.with_runsc,
                                "curl_pipe": consumer == "standalone",
                                "stdout": process.stdout[-800:], "stderr": process.stderr[-800:]})
                if args.with_runsc:
                    results[-1]["runsc_version"] = subprocess.check_output(["runsc", "--version"], env=private).decode()
        print(json.dumps({"fixture": "official cli/cli2.103.3; SOURCE-only policy/layout substitutions",
                          "archive_sha256": HASHES, "numeric_repository_id": FIXTURE_REPO_ID,
                          "original_bundle_sha256": digest(bundle), "cases": results,
                          "production_signed_kronik_claimed": False, "runsc_yes_exercised": args.with_runsc}, indent=2))


if __name__ == "__main__":
    main()
