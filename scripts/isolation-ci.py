#!/usr/bin/env python3
"""The steps of the isolation workflow (.github/workflows/isolation.yml), one subcommand each.

The workflow runs the M20 and M21 proofs of ADR 0064 on GitHub-hosted runners, which are
disposable virtual machines, and keeps their evidence. Every subcommand that changes the host
(`mark`, `userns`, `kvm`, `boundary`, `fixture`) refuses to run anywhere but a GitHub-hosted
runner (GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted): run through sudo, pass those
two variables on. The others run anywhere: `facts` and `ids` only read the host, `build` builds
in the checkout, `collect` copies evidence into a new directory, and `verify` reads it.

    facts OUT                 record the host (kernel, distribution, systemd, AppArmor, KVM)
    build OUT [--examples]    build the product, the two drivers and the images (and the demos' examples)
    mark OUT                  as root: declare this runner disposable (/etc/kronik-proof-host)
    userns MODE OUT           as root: Ubuntu's restriction on user namespaces on (restricted) or off (lifted)
    kvm OUT                   as root: give /dev/kvm to the kvm group and prove the KVM API
    ids OUT                   choose numeric ids and a subordinate range that nobody uses
    boundary OUT              as root: the rootless_boundary driver (B1)
    fixture OUT ...           as root: the installed fixture with the hostile actor and the proofs (B2, M20)
    tool-record BUILD DEST    keep the microVM tool build's manifest, provenance and logs
    collect OUT DEST          as root: copy the evidence (text, no keys, no images) into DEST
    verify JOB DEST           fail unless every proof of JOB ran and passed; write the verdict
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
# The parent of the fixture's proof trees. /var/tmp: the fixture rebinds its retained tree over
# its private scratch mounts there (ADR 0064), and it is on the runner's large root file system.
PROOF_PARENT = Path("/var/tmp/kronik-isolation")
BOUNDARY_PARENT = Path("/var/tmp")
MARKER = Path("/etc/kronik-proof-host")
APPARMOR_USERNS = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
KVM_RULE = Path("/etc/udev/rules.d/99-kronik-kvm.rules")
# The runner's /dev/kvm, made the kvm group's (0660), not everyone's (0666, the Android emulator's
# recipe): the nonroot unit must open it through its own grant, SupplementaryGroups= of that group
# in the KVM drop-in that `serve --init` writes, and the proof must show that this grant works.
KVM_RULE_TEXT = 'KERNEL=="kvm", GROUP="kvm", MODE="0660", OPTIONS+="static_node=kvm"\n'
# ioctl requests of the KVM API (linux/kvm.h): KVMIO is 0xAE.
KVM_GET_API_VERSION = 0xAE00
KVM_CREATE_VM = 0xAE01
BOUNDARY_PASS = "namespace identity, owned unpin, startup caps, true peer UIDs and acceptor death: pass"
# Evidence is text: logs, JSON records, unit files. Images, disks, memory snapshots, databases,
# keys and the copied tool bundle stay behind.
SKIPPED_DIRECTORIES = {"layouts", "rootfs", "blobs", "keys", "bundle", "sources", "microvm",
                       "directory-tools", ".restore", "code", "node_modules"}
SKIPPED_SUFFIXES = (".ext4", ".mem", ".state", ".img", ".db", ".db-wal", ".db-shm", ".seg",
                    ".wasm", ".cwasm", ".zst", ".gz", ".xz", ".tar", ".key", ".pem", ".sock")
SKIPPED_NAMES = {"master.key", "vmlinux", "firecracker", "guest-init", "mke2fs", "debugfs", "e2fsck",
                 "initrd", "initrd.cpio"}
MAX_FILE = 16 << 20
MAX_TOTAL = 400 << 20


class Refused(Exception):
    """A step that must not run here, or a proof that did not pass."""


def hosted_only(what):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise Refused(f"{what} changes the host, so it runs only on a GitHub-hosted runner "
                      "(GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted; pass both through sudo)")
    if os.geteuid() != 0:
        raise Refused(f"{what} needs root")


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def read(path, default=None):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return default


def output(args, timeout=60):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def summary(text):
    """Appends to the job's summary page, when there is one."""
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a") as stream:
            stream.write(text + "\n")


def facts(out):
    """What this host is, before anything changes it."""
    cpuinfo = read("/proc/cpuinfo", "")
    flags = next((line.split(":", 1)[1].split() for line in cpuinfo.splitlines()
                  if line.startswith("flags")), [])
    record = {
        "uname": list(os.uname()),
        "os_release": read("/etc/os-release"),
        "systemd": (output(["systemctl", "--version"]) or "").splitlines()[:1],
        "nproc": os.cpu_count(),
        "memory": next((line for line in read("/proc/meminfo", "").splitlines()
                        if line.startswith("MemTotal")), None),
        "disk_free_bytes": shutil.disk_usage("/").free,
        "cpu_virtualization": sorted({"vmx", "svm"} & set(flags)),
        "dev_kvm": Path("/dev/kvm").exists(),
        "apparmor_enabled": read("/sys/module/apparmor/parameters/enabled"),
        "apparmor_restrict_unprivileged_userns": read(APPARMOR_USERNS),
        "max_user_namespaces": read("/proc/sys/user/max_user_namespaces"),
        "unprivileged_userns_clone": read("/proc/sys/kernel/unprivileged_userns_clone"),
        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
        "image": {key: os.environ.get(key) for key in ["ImageOS", "ImageVersion"]},
    }
    save(out / "host-facts.json", record)
    summary(f"Host: {record['uname'][2]}, {record['systemd'][:1]}, AppArmor userns restriction "
            f"{record['apparmor_restrict_unprivileged_userns']!r}, /dev/kvm "
            f"{'present' if record['dev_kvm'] else 'absent'}")
    print(json.dumps(record, indent=2))


def userns_plan(initial, mode):
    """The value the restriction must have for `mode`, and what the proof can then claim."""
    if initial not in ("0", "1"):
        raise Refused(f"{APPARMOR_USERNS} reads {initial!r}: this kernel has no AppArmor restriction on "
                      "unprivileged user namespaces, so Ubuntu's R1 cannot be exercised here")
    wanted = {"restricted": "1", "lifted": "0"}[mode]
    return {"initial": initial, "mode": mode, "wanted": wanted, "changed_by_job": initial != wanted,
            "r1_exercised": wanted == "1",
            "note": ("Ubuntu 24.04's AppArmor restriction on unprivileged user namespaces is active: "
                     "this run exercises R1" if wanted == "1" else
                     "the restriction is lifted: this run does NOT exercise R1 and says nothing about it")}


def userns(mode, out):
    hosted_only("userns")
    plan = userns_plan(read(APPARMOR_USERNS), mode)
    if plan["changed_by_job"]:
        subprocess.run(["sysctl", "-w", f"kernel.apparmor_restrict_unprivileged_userns={plan['wanted']}"],
                       check=True)
    plan["final"] = read(APPARMOR_USERNS)
    if plan["final"] != plan["wanted"]:
        raise Refused(f"the restriction reads {plan['final']!r} after setting it to {plan['wanted']}")
    save(out / "userns.json", plan)
    summary(f"User namespaces: {plan['note']} (image default {plan['initial']}, "
            f"{'set by this job' if plan['changed_by_job'] else 'unchanged'}).")
    print(json.dumps(plan, indent=2))


def kvm_api(device="/dev/kvm"):
    """The KVM API answers: version 12, and a VM can be created (and is closed at once)."""
    fd = os.open(device, os.O_RDWR | os.O_CLOEXEC)
    try:
        version = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
        if version != 12:
            raise Refused(f"KVM API version {version}, not 12")
        vm = fcntl.ioctl(fd, KVM_CREATE_VM, 0)
        if vm < 0:
            raise Refused("KVM_CREATE_VM failed")
        os.close(vm)
        return version
    finally:
        os.close(fd)


def kvm(out):
    hosted_only("kvm")
    KVM_RULE.write_text(KVM_RULE_TEXT)
    subprocess.run(["udevadm", "control", "--reload-rules"], check=True)
    subprocess.run(["udevadm", "trigger", "--name-match=kvm"], check=True)
    deadline = time.monotonic() + 30
    while not Path("/dev/kvm").exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    device = os.stat("/dev/kvm")
    if not stat.S_ISCHR(device.st_mode):
        raise Refused("/dev/kvm is not a character device")
    if device.st_gid == 0:
        raise Refused("/dev/kvm belongs to group 0; the nonroot unit refuses a supplementary gid 0")
    if stat.S_IMODE(device.st_mode) & 0o007:
        raise Refused(f"/dev/kvm is open to everyone ({oct(stat.S_IMODE(device.st_mode))}): the unit's own "
                      "grant would prove nothing")
    record = {"rule": KVM_RULE_TEXT, "mode": oct(stat.S_IMODE(device.st_mode)), "gid": device.st_gid,
              "api_version": kvm_api(), "create_vm": True}
    save(out / "kvm.json", record)
    summary(f"KVM: /dev/kvm {record['mode']} gid {record['gid']}, API {record['api_version']}, a VM can be created.")
    print(json.dumps(record, indent=2))


def mark(out):
    hosted_only("mark")
    machine = read("/etc/machine-id")
    if not machine or len(machine) != 32:
        raise Refused("/etc/machine-id holds no machine id")
    MARKER.write_text(machine + "\n")
    os.chown(MARKER, 0, 0)
    MARKER.chmod(0o644)
    save(out / "marker.json", {"marker": str(MARKER), "machine_id": machine,
                               "why": "a GitHub-hosted runner is a disposable virtual machine"})


def used_ids():
    """The user and group ids that the flat files, the name service and running processes use."""
    users, groups, ranges = set(), set(), []
    for name, into in [("passwd", users), ("group", groups)]:
        for line in read(f"/etc/{name}", "").splitlines():
            fields = line.split(":")
            if len(fields) > 2 and fields[2].isdigit():
                into.add(int(fields[2]))
    for name in ["subuid", "subgid"]:
        for line in read(f"/etc/{name}", "").splitlines():
            fields = line.strip().split(":")
            if len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit():
                ranges.append((int(fields[1]), int(fields[1]) + int(fields[2])))
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            status = read(entry / "status", "")
            for line in status.splitlines():
                key, _, values = line.partition(":")
                if key in ("Uid", "Gid"):
                    (users if key == "Uid" else groups).update(int(v) for v in values.split())
    return users, groups, ranges


def choose_ids(users, groups, ranges, known=lambda kind, n: False, first=61000, subid=2_000_000_000):
    """A service uid and gid (the same number), an operator uid and a 65,536-id subordinate range
    that nobody uses. `known` asks the name service."""
    def free(n, kind):
        taken = users if kind == "passwd" else groups
        return n not in taken and not any(lo <= n < hi for lo, hi in ranges) and not known(kind, n)
    candidates = [n for n in range(first, first + 1000) if free(n, "passwd") and free(n, "group")]
    if len(candidates) < 2:
        raise Refused(f"no two free ids between {first} and {first + 1000}")
    start = subid
    while any(lo < start + 65536 and start < hi for lo, hi in ranges) or \
            any(start <= n < start + 65536 for n in users | groups):
        start += 65536
        if start + 65536 > 2**32 - 2:
            raise Refused("no free subordinate range")
    return {"uid": candidates[0], "gid": candidates[0], "operator": candidates[1], "subid": start}


def getent_known(kind, n):
    return subprocess.run(["getent", kind, str(n)], capture_output=True).returncode == 0


def ids(out):
    chosen = choose_ids(*used_ids(), known=getent_known)
    save(out / "ids.json", chosen)
    print(json.dumps(chosen))


def run(args, log=None, env=None, timeout=None, check=True):
    """Runs `args` in the checkout. With `log`, its output goes to that file and to this job's log
    as it comes; without, it is returned. With `timeout` (seconds), timeout(1) ends it: exit 124."""
    args = [str(a) for a in args]
    if timeout:
        args = ["timeout", "--signal=TERM", "--kill-after=30s", f"{int(timeout)}s", *args]
    print("+ " + " ".join(args), flush=True)
    process = subprocess.Popen(args, cwd=ROOT, env=env, text=True, errors="replace",
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    captured = []
    stream = open(log, "a") if log else None
    try:
        for line in process.stdout:
            if stream:
                stream.write(line)
                stream.flush()
                sys.stdout.write(line)
                sys.stdout.flush()
            else:
                captured.append(line)
        status = process.wait()
    finally:
        if stream:
            stream.close()
    result = subprocess.CompletedProcess(args, status, "".join(captured))
    if check and status != 0:
        if captured:
            print("".join(captured)[-20000:])
        raise Refused(f"{args[0]} exited {status}" + (f"; see {log}" if log else ""))
    return result


def test_executables(names, profile_args=("--release",)):
    """The paths of the explicit driver targets, built by name (they are never run by cargo test)."""
    args = ["cargo", "test", *profile_args, "--locked", "-p", "kronik", "--no-run", "--message-format=json"]
    for name in names:
        args += ["--test", name]
    result = run(args)
    return executables_from(result.stdout, names)


def executables_from(messages, names):
    found = {}
    for line in messages.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = message.get("target") or {}
        if message.get("reason") == "compiler-artifact" and target.get("name") in names \
                and message.get("executable"):
            found[target["name"]] = message["executable"]
    missing = sorted(set(names) - set(found))
    if missing:
        raise Refused(f"cargo built no executable for {missing}")
    return found


def build(out, examples):
    out.mkdir(parents=True, exist_ok=True)
    log = out / "build.log"
    run(["cargo", "build", "--release", "--locked", "-p", "kronik"], log=log)
    drivers = test_executables(["isolation_fixture", "rootless_boundary"])
    layouts = {}
    for key, name in [("probe", "foreign-probe"), ("pg", "foreign-pg"), ("payments", "fake-payments")]:
        run(["scripts/build-foreign-examples.sh", "--only", name], log=log)
        layout = ROOT / "examples/dist" / f"{name}.oci"
        if not (layout / "index.json").is_file():
            raise Refused(f"{name}: no OCI layout at {layout}")
        layouts[key] = str(layout)
    if examples:
        run(["scripts/build-examples.sh"], log=log)
        run(["scripts/build-examples-ts.sh"], log=log,
            env=dict(os.environ, KRONIK_BIN=str(ROOT / "target/release/kronik")))
    artifacts = {"product": str(ROOT / "target/release/kronik"), "helper": drivers["isolation_fixture"],
                 "boundary": drivers["rootless_boundary"], **layouts}
    for key in ["product", "helper", "boundary"]:
        path = Path(artifacts[key])
        artifacts[key + "_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        path.chmod(0o755)
    save(out / "artifacts.json", artifacts)
    print(json.dumps(artifacts, indent=2))


def load(out, name):
    return json.loads((out / name).read_text())


def boundary(out):
    hosted_only("boundary")
    artifacts, chosen = load(out, "artifacts.json"), load(out, "ids.json")
    log = out / "boundary.log"
    result = run([artifacts["boundary"], chosen["uid"], chosen["gid"], chosen["subid"], chosen["subid"],
                  chosen["operator"]], log=log, timeout=600, check=False)
    text = log.read_text(errors="replace")
    evidence = next((line.rsplit("evidence ", 1)[1].strip() for line in text.splitlines()
                     if BOUNDARY_PASS in line and "evidence " in line), None)
    record = {"exit": result.returncode, "timed_out": result.returncode == 124,
              "passed": result.returncode == 0 and evidence is not None, "evidence": evidence}
    save(out / "boundary.json", record)
    summary(f"B1 rootless_boundary: {'pass' if record['passed'] else 'FAIL'} (exit {result.returncode}).")
    if not record["passed"]:
        raise Refused(f"the rootless boundary driver did not pass; see {log}")


def fixture(out, isolation, mode, tools, max_runtime):
    hosted_only("fixture")
    artifacts, chosen = load(out, "artifacts.json"), load(out, "ids.json")
    PROOF_PARENT.mkdir(mode=0o755, exist_ok=True)
    log = out / f"fixture-{isolation}.log"
    positional = [artifacts["helper"], artifacts["product"], artifacts["probe"], artifacts["pg"],
                  artifacts["payments"], PROOF_PARENT, chosen["uid"], chosen["gid"], chosen["subid"],
                  chosen["operator"]]
    before = set(PROOF_PARENT.glob("kronik-proof-*"))
    os.umask(0o077)
    if mode == "restricted":
        # The Ubuntu 24.04 wrapper: it refuses a host that is not Ubuntu 24.04 with systemd 255 and
        # AppArmor's restriction on unprivileged user namespaces active.
        extra = (["--microvm", tools] if isolation == "microvm" else []) + ["--max-runtime", max_runtime]
        result = run(["bash", "scripts/proof-rootless.sh", *positional, *extra], log=log,
                     timeout=int(max_runtime) + 600, check=False)
    else:
        result = explicit_fixture(positional, isolation, tools, max_runtime, log)
    created = sorted(set(PROOF_PARENT.glob("kronik-proof-*")) - before)
    record = {"isolation": isolation, "userns": mode, "exit": result.returncode,
              "proof_roots": [str(p) for p in created]}
    save(out / f"fixture-{isolation}.json", record)
    summary(f"Installed fixture ({isolation}, user namespaces {mode}): exit {result.returncode}.")
    if result.returncode != 0:
        raise Refused(f"the installed fixture proof failed; see {log}")


def explicit_fixture(positional, isolation, tools, max_runtime, log):
    """ADR 0064's commands for a host that is not the Ubuntu target: create, init, the conformance
    harness, and the helper's cleanup whatever happened."""
    # proof-rootless.sh's order is HELPER PRODUCT PROBE PG PAYMENTS PARENT UID GID SUBID OPERATOR;
    # the helper's `create` takes PARENT first.
    helper, product, probe, pg, payments, parent, *numbers = positional
    args = [parent, product, probe, pg, payments, *numbers]
    args += ([tools] if isolation == "microvm" else []) + ["--max-runtime", max_runtime]
    print(f"+ {helper} create {' '.join(str(a) for a in args)}", flush=True)
    with open(log, "a") as stream:
        created = subprocess.run([str(a) for a in [helper, "create", *args]], cwd=ROOT, text=True,
                                 stdout=subprocess.PIPE, stderr=stream, timeout=1800)
    if created.returncode != 0 or not created.stdout.strip():
        return created
    proof = created.stdout.strip().splitlines()[-1]
    try:
        result = run([helper, "init", proof, "rootless"], log=log, timeout=180, check=False)
        if result.returncode == 0:
            proof_mode = "--microvm-proof" if isolation == "microvm" else "--program-proof"
            result = run(["bash", "scripts/conformance-rootless.sh", "--fixture", proof, "--isolation",
                          isolation, proof_mode], log=log, timeout=int(max_runtime), check=False)
        return result
    finally:
        cleanup = run([helper, "cleanup", proof], log=Path(proof) / "cleanup.log", check=False)
        if cleanup.returncode != 0:
            print(f"the helper's cleanup failed; see {proof}/cleanup.log", file=sys.stderr)


def wanted(relative):
    """Whether the name of a file of a proof tree may be evidence: no key, image, disk, database,
    tool or copied layout."""
    if any(part in SKIPPED_DIRECTORIES for part in relative.parts[:-1]):
        return False
    return relative.name not in SKIPPED_NAMES and not relative.name.endswith(SKIPPED_SUFFIXES)


def text_file(path):
    """A regular file (not a link) of at most MAX_FILE bytes whose start holds no NUL byte."""
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            return False
        with path.open("rb") as stream:
            return b"\0" not in stream.read(8192)
    except OSError:
        return False


def copy_evidence(source, destination, budget):
    """Copies the evidence files of `source` below `destination`; returns (copied, skipped, bytes)."""
    copied = skipped = total = 0
    for directory, subdirectories, files in os.walk(source, followlinks=False):
        relative = Path(directory).relative_to(source)
        subdirectories[:] = [d for d in subdirectories if d not in SKIPPED_DIRECTORIES]
        for name in files:
            path = Path(directory) / name
            if not wanted(relative / name) or not text_file(path):
                skipped += 1
                continue
            size = path.lstat().st_size
            if total + size > budget:
                skipped += 1
                continue
            target = destination / relative / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target, follow_symlinks=False)
            copied, total = copied + 1, total + size
    return copied, skipped, total


def collect(out, destination, owner):
    destination.mkdir(parents=True, exist_ok=False)
    budget, inventory = MAX_TOTAL, []
    sources = [("run", out)]
    sources += [(f"proof-{p.name}", p) for p in sorted(PROOF_PARENT.glob("kronik-proof-*"))]
    sources += [(f"boundary-{p.name}", p) for p in sorted(BOUNDARY_PARENT.glob("kronik-boundary-*"))]
    for label, source in sources:
        if source.is_dir():
            copied, skipped, size = copy_evidence(source, destination / label, budget)
            budget -= size
            inventory.append({"source": str(source), "into": label, "copied": copied, "skipped": skipped,
                              "bytes": size})
    kernel = output(["journalctl", "-k", "--no-pager", "-o", "short-monotonic"], timeout=60)
    if kernel:
        (destination / "kernel.log").write_text(kernel[-(8 << 20):] + "\n")
    save(destination / "inventory.json", inventory)
    if owner:
        uid, gid = (int(n) for n in owner.split(":"))
        for directory, subdirectories, files in os.walk(destination):
            for name in [directory, *[os.path.join(directory, f) for f in subdirectories + files]]:
                os.chown(name, uid, gid, follow_symlinks=False)
    print(json.dumps(inventory, indent=2))


def tool_record(build_parent, destination):
    destination.mkdir(parents=True, exist_ok=True)
    found = []
    for tree in sorted(build_parent.iterdir()) if build_parent.is_dir() else []:
        if not tree.is_dir():
            continue
        target = destination / tree.name.lstrip(".")
        for name in ["manifest.json", "provenance.json"]:
            if (tree / name).is_file():
                target.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(tree / name, target / name)
        if (tree / "logs").is_dir():
            copy_evidence(tree / "logs", target / "logs", MAX_TOTAL)
        found.append(tree.name)
    save(destination / "tool-builds.json", {"trees": found})


# What each job must leave, below the collected evidence: a (description, glob) pair matches at least
# one file; result files must say PASS.
REQUIRED = {
    "m21": [
        ("host facts", "run/host-facts.json"),
        ("user-namespace setting", "run/userns.json"),
        ("B1 boundary record", "run/boundary.json"),
        ("conformance result (gVisor)", "proof-*/result-conformance-gvisor.json"),
        ("hostile actor evidence (gVisor)", "proof-*/conformance-gvisor.json"),
        ("host listener receipts", "proof-*/host-listeners.json"),
        ("outside writes", "proof-*/outside-writes.json"),
        ("service audit", "proof-*/check-rootless.json"),
        ("verify-change demo", "proof-*/verify-change.log"),
        ("billing demo", "proof-*/billing.log"),
        ("Postgres fork proof", "proof-*/postgres-replies.json"),
        ("Postgres continuous replay", "proof-*/pg-replay.json"),
        ("UID audit", "proof-*/uid-audit.json"),
        ("acceptor restart", "proof-*/acceptor-restart.json"),
        ("ship and restore", "proof-*/ship-restore.json"),
    ],
    "m20": [
        ("host facts", "run/host-facts.json"),
        ("KVM", "run/kvm.json"),
        ("user-namespace setting", "run/userns.json"),
        ("conformance result (microVM)", "proof-*/result-conformance-microvm.json"),
        ("hostile actor evidence (microVM)", "proof-*/conformance-microvm.json"),
        ("mapped directory proof", "proof-*/mapped-directory.json"),
        ("VM calibration, attacker", "proof-*/vm-calibration-probe-attacker-*.json"),
        ("VM calibration, neighbour", "proof-*/vm-calibration-probe-neighbour-*.json"),
        ("VM calibration, Postgres", "proof-*/vm-calibration-pg-*.json"),
        ("VM calibration, fork copy", "proof-*/vm-calibration-copy.json"),
        ("guest ENOSPC", "proof-*/guest-enospc-host.json"),
        ("graceful STOP, attacker", "proof-*/vm-stop-probe-attacker-*.json"),
        ("graceful STOP, neighbour", "proof-*/vm-stop-probe-neighbour-*.json"),
        ("graceful STOP, Postgres", "proof-*/vm-stop-pg-*.json"),
        ("Postgres snapshot fork proof", "proof-*/postgres-replies.json"),
        ("Postgres continuous replay", "proof-*/pg-replay.json"),
    ],
}


def verdict(job, evidence, mode):
    rows, passed = [], True
    for description, pattern in REQUIRED[job]:
        matches = sorted(evidence.glob(pattern))
        ok = bool(matches)
        detail = ", ".join(str(m.relative_to(evidence)) for m in matches[:3]) or "missing"
        if ok and pattern.endswith(("result-conformance-gvisor.json", "result-conformance-microvm.json")):
            results = [json.loads(m.read_text()).get("status") for m in matches]
            ok = ok and results and all(r == "PASS" for r in results)
            detail += f" ({', '.join(str(r) for r in results)})"
        if ok and pattern == "run/boundary.json":
            ok = json.loads(matches[0].read_text()).get("passed") is True
        if ok and pattern.endswith("host-listeners.json"):
            ok = all(json.loads(m.read_text()) == [] for m in matches)
        rows.append({"proof": description, "passed": ok, "evidence": detail})
        passed = passed and ok
    userns_record = evidence / "run/userns.json"
    r1 = json.loads(userns_record.read_text()) if userns_record.is_file() else {}
    if r1.get("mode") != mode:
        rows.append({"proof": "user-namespace mode", "passed": False,
                     "evidence": f"recorded {r1.get('mode')!r}, expected {mode!r}"})
        passed = False
    return {"job": job, "userns": mode, "passed": passed, "r1_exercised": r1.get("r1_exercised"),
            "r1_note": r1.get("note"), "apparmor_default": r1.get("initial"), "proofs": rows}


def verify(job, evidence, mode):
    result = verdict(job, evidence, mode)
    save(evidence / "verdict.json", result)
    lines = [f"### {job.upper()} isolation proofs: {'PASS' if result['passed'] else 'FAIL'}", "",
             f"R1 (Ubuntu's AppArmor restriction on unprivileged user namespaces): "
             f"{'exercised' if result['r1_exercised'] else 'NOT exercised'}. {result['r1_note'] or ''}", "",
             "| Proof | Result | Evidence |", "|---|---|---|"]
    lines += [f"| {row['proof']} | {'pass' if row['passed'] else 'FAIL'} | {row['evidence']} |"
              for row in result["proofs"]]
    text = "\n".join(lines)
    (evidence / "summary.md").write_text(text + "\n")
    summary(text)
    print(text)
    if not result["passed"]:
        raise Refused("a required proof is missing or did not pass (a skipped proof counts as missing)")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["facts", "mark", "kvm", "ids", "boundary"]:
        commands.add_parser(name).add_argument("out", type=Path)
    command = commands.add_parser("build")
    command.add_argument("out", type=Path)
    command.add_argument("--examples", action="store_true")
    command = commands.add_parser("userns")
    command.add_argument("mode", choices=["restricted", "lifted"])
    command.add_argument("out", type=Path)
    command = commands.add_parser("fixture")
    command.add_argument("out", type=Path)
    command.add_argument("--isolation", choices=["gvisor", "microvm"], required=True)
    command.add_argument("--userns", choices=["restricted", "lifted"], required=True)
    command.add_argument("--tools", type=Path)
    command.add_argument("--max-runtime", default="3600")
    command = commands.add_parser("tool-record")
    command.add_argument("build_parent", type=Path)
    command.add_argument("destination", type=Path)
    command = commands.add_parser("collect")
    command.add_argument("out", type=Path)
    command.add_argument("destination", type=Path)
    command.add_argument("--owner")
    command = commands.add_parser("verify")
    command.add_argument("job", choices=sorted(REQUIRED))
    command.add_argument("evidence", type=Path)
    command.add_argument("--userns", choices=["restricted", "lifted"], required=True)
    args = parser.parse_args()
    try:
        if args.command == "facts":
            args.out.mkdir(parents=True, exist_ok=True)
            facts(args.out)
        elif args.command == "build":
            build(args.out, args.examples)
        elif args.command == "mark":
            mark(args.out)
        elif args.command == "userns":
            userns(args.mode, args.out)
        elif args.command == "kvm":
            kvm(args.out)
        elif args.command == "ids":
            ids(args.out)
        elif args.command == "boundary":
            boundary(args.out)
        elif args.command == "fixture":
            if args.isolation == "microvm" and not args.tools:
                raise Refused("the microVM proof needs --tools, the pinned tool bundle")
            fixture(args.out, args.isolation, args.userns, args.tools, args.max_runtime)
        elif args.command == "tool-record":
            tool_record(args.build_parent, args.destination)
        elif args.command == "collect":
            collect(args.out, args.destination, args.owner or (
                f"{os.environ['SUDO_UID']}:{os.environ['SUDO_GID']}" if "SUDO_UID" in os.environ else None))
        elif args.command == "verify":
            verify(args.job, args.evidence, args.userns)
    except Refused as error:
        print(f"isolation-ci: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
