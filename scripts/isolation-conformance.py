#!/usr/bin/env python3
"""Required real-binary isolation proof. Only the recorded owned fixture is writable.

No package installation, build, user database update, arbitrary service target,
privileged container, or host security-policy change is performed here.
"""
import argparse
import base64
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import select
import socket
import stat
import struct
import subprocess
import sys
import threading
import tempfile
import time
import urllib.parse

from kronikd import Daemon, UnixConnection, Violation

ROOT = Path(__file__).resolve().parent.parent
LIMIT = 8 * 1024 * 1024
# Every foreign call from an actor is cut off at its kind's effect timeout, ten
# seconds by default, and the guest's fill of its 1 GiB data drive is one call:
# on a slow disk or nested virtualization that alone can fail the oracle.
EFFECT_TIMEOUT_MS = 300_000
# ADR 0096: the VMM must exit within a second of the guest's acknowledged STOP.
STOP_LIMIT_MS = 1000
# What a guest console shows when its kernel or its PID 1 panics. `panic=1` on the kernel
# command line makes a panic restart the guest, which ends the VMM just as a clean stop does,
# so only the console tells the two apart.
PANIC = re.compile(r"Kernel panic|panicked at|Oops:|BUG: ")


def require(condition, message):
    if not condition:
        raise Violation(message)


def remove_owned(path, identity):
    now = path.lstat()
    require((now.st_dev, now.st_ino) == (identity.st_dev, identity.st_ino),
            f"resource replaced; refusing cleanup: {path}")
    path.unlink()


def assert_absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise Violation(f"outside write or canary collision observed: {path}")


def outside_candidates(paths, roots, token):
    targets = set(paths)
    name = f".kronik-probe-{token}"
    count = 0
    def walk_error(error):
        raise error
    for root in roots:
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            count += len(dirs) + len(files)
            require(count <= 1000000, "outside-write observation entry limit")
            if name in dirs or name in files:
                targets.add(Path(directory)/name)
    found = []
    for path in targets:
        try:
            found.append((path,path.lstat()))
        except FileNotFoundError:
            pass
    return found


def observe_outside_writes(root, paths, roots, token):
    found = outside_candidates(paths, roots, token)
    records, owned = [], {}
    for path, identity in found:
        require(stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1,
                f"outside canary replaced; refusing cleanup: {path}")
        with path.open("rb") as stream:
            content = stream.read(65)
        require(content == token.encode(), f"outside canary replaced; refusing cleanup: {path}")
        records.append({"path":str(path),"uid":identity.st_uid,"mode":stat.S_IMODE(identity.st_mode),
                        "identity":[identity.st_dev,identity.st_ino],"sha256":hashlib.sha256(content).hexdigest()})
        owned[(identity.st_dev,identity.st_ino)] = path, identity
    (root/"outside-writes.json").write_text(json.dumps(records,indent=2))
    for path, identity in owned.values():
        remove_owned(path,identity)
    require(not found, "actual outside writes observed (owned canaries captured and cleaned)")


def command(args, timeout=90, env=None, log=None, expected_exit=0):
    environment = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                   "LANG": "C.UTF-8", **(env or {})}
    with tempfile.TemporaryFile() as stream:
        proc = subprocess.Popen([str(a) for a in args], stdout=stream, stderr=stream,
                                env=environment, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while proc.poll() is None:
                require(time.monotonic() < deadline, f"command deadline: {args}")
                require(os.fstat(stream.fileno()).st_size <= LIMIT, f"output limit: {args[0]}")
                time.sleep(0.05)
        except BaseException:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
            raise
        finally:
            stream.seek(0)
            out = stream.read(LIMIT).decode(errors="replace")
            if log is not None:
                Path(log).write_text(out)
        require(proc.returncode == expected_exit, f"command failed ({proc.returncode}, expected {expected_exit}): {args}: {out[-4096:]}")
        return out


def status(pid):
    return dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)


def process_args(pid):
    """argv of a process, as /proc/PID/cmdline holds it."""
    return Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")


def fixture(root):
    root = Path(root).resolve(strict=True)
    md = root.stat()
    require(md.st_uid == os.getuid() == 0 and stat.S_IMODE(md.st_mode) == 0o700,
            "fixture must be an exclusive root-owned 0700 directory")
    manifest = root / "fixture.json"
    st = manifest.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600,
            "fixture manifest must be root-owned regular 0600")
    cfg = json.loads(manifest.read_text())
    require(cfg["version"] == "kronik.isolation-fixture/v1", "wrong fixture version")
    require(cfg["root_identity"] == [md.st_dev, md.st_ino], "fixture directory was replaced")
    require(cfg["unit"] == f"kronik-proof-{cfg['token']}.service", "unit is not the exact allocated fixture")
    require(cfg["manager_unit"] == f"kronik-proof-{cfg['token']}-manager.service", "wrong allocated manager parent")
    require(cfg["uid"] > 0 and cfg["gid"] > 0, "required nonroot mode cannot target root")
    for key in ["data", "run", "etc", "socket", "binary", "helper", "probe_layout"]:
        require(Path(cfg[key]).is_absolute(), f"{key} must be absolute")
    for key in ["data", "run", "etc", "socket"]:
        require(Path(cfg[key]).is_relative_to(root), f"{key} escapes owned fixture")
    for logical in cfg["data_roots"]:
        require(Path(logical).resolve(strict=True).is_relative_to(root),"logical data root is not fixture-owned")
    cfg["root"] = str(root)
    cfg["manager"] = json.loads(command([cfg["helper"],"manager-info",root],10))
    return root, cfg

def manager_command(cfg, *args):
    return [cfg["helper"], "control", cfg["root"], *args]


def fixture_pin(cfg):
    return Path(f"/proc/{cfg['manager']['pid']}/root") / Path(cfg["root"]).relative_to("/") / "run/kronik-userns/user"


def validate_fixture_pid(cfg, pid):
    record = json.loads((Path(cfg["root"])/f"pid-{pid}.json").read_text())
    fields = status(pid)
    started = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()[19])
    namespace = Path(f"/proc/{pid}/ns/pid").stat()
    require(record["host"] == pid and record["start_time"] == started and
            record["inside"] == int(fields["NSpid"].split()[-1]) and
            record["pid_namespace"] == [namespace.st_dev, namespace.st_ino] == cfg["manager"]["pid_namespace"],
            "translated PID identity/start time/namespace changed")
    group = Path(f"/proc/{pid}/cgroup").read_text().strip().split("::",1)[1]
    require(group == record["parent_cgroup"] or group.startswith(record["parent_cgroup"]+"/"),
            "translated process is not in the owned manager parent")



def service(cfg):
    raw = command(manager_command(cfg, "show", cfg["unit"], "--property=MainPID,ControlGroup,ActiveState", "--no-pager"), 10)
    props = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    require(props["ActiveState"] == "active", "owned service is not active")
    pid = int(props["MainPID"])
    require(pid > 1, "owned service has no live main process")
    validate_target_pid(pid, cfg["uid"])
    validate_fixture_pid(cfg, pid)
    cg = Path("/sys/fs/cgroup") / props["ControlGroup"].lstrip("/")
    require(cfg["unit"] in cg.parts and cg.is_dir(), "wrong cgroup target")
    peer = socket.socket(socket.AF_UNIX)
    peer.settimeout(3)
    try:
        peer.connect(cfg["socket"])
        import struct
        peer_pid, peer_uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer_uid == cfg["uid"], f"API peer has wrong host uid {peer_uid}")
        inside = status(peer_pid)["NSpid"].split()[-1]
        require(int(command([cfg["helper"],"host-pid",cfg["root"],inside],10)) == peer_pid,
                "API peer is not the actual private-manager process")
        validate_fixture_pid(cfg, peer_pid)
        peer_group = Path(f"/proc/{peer_pid}/cgroup").read_text().strip().split("::",1)[1]
        owned_group = props["ControlGroup"].rstrip("/")
        require(peer_group == owned_group or peer_group.startswith(owned_group+"/"),
                "API socket belongs to a different service")
    finally:
        peer.close()
    return pid, cg


def validate_target_pid(pid, uid):
    require(uid > 0, "required nonroot mode cannot target root")
    uids = list(map(int, status(pid)["Uid"].split()))
    require(uids == [uid] * 4, f"wrong target or root service: {pid}: {uids}")


def consumed_service(root, cfg, pid):
    """Observe systemd's resolved argv, credential bytes and actual namespace."""
    version = int(command(["systemctl", "--version"], 10).split()[1])
    require(version >= 255, "installed proof requires systemd 255 or newer")
    args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    flag = b"--master-key-file"
    require(args.count(flag) == 1, "service did not consume the selected file credential")
    selected = Path(os.fsdecode(args[args.index(flag) + 1]))
    require(selected.is_absolute() and selected.name == "master-key" and
            selected.is_relative_to("/run/credentials"),
            f"systemd did not resolve its credential directory: {selected}")
    credential = Path(f"/proc/{pid}/root") / selected.relative_to("/")
    source = root / "etc/kronik/master.key"
    source_md = source.lstat()
    require(stat.S_ISREG(source_md.st_mode) and source_md.st_uid == 0 and
            stat.S_IMODE(source_md.st_mode) == 0o600, "selected master source is not root-only")
    require(credential.read_bytes() == source.read_bytes(), "consumed credential differs from selected source")
    loaded = ok(api_daemon(cfg), "GET", "/v1/keys")
    require(loaded["source"] == "file" and loaded["check_ok"], "actual loaded file source failed")
    initial = os.readlink(f"/proc/{cfg['manager']['pid']}/ns/cgroup")
    actual = os.readlink(f"/proc/{pid}/ns/cgroup")
    require((actual != initial) == (version >= 257),
            f"systemd {version} did not consume the version-specific cgroup protection")
    view = (Path(f"/proc/{pid}") / "root" / "sys/fs/cgroup/cgroup.controllers").read_text().split()
    require({"cpu", "memory", "pids"} <= set(view), "consumed cgroup mount lacks required controllers")
    (root / "consumed-service.json").write_text(json.dumps({
        "systemd":version, "pid":pid, "credential_path":str(selected),
        "credential_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),
        "loaded_source":loaded, "cgroup_namespace":actual, "initial_cgroup_namespace":initial,
        "controllers":view}, indent=2))
    return credential


# Fixed non-shipped fixture operation: no executable/path dispatch or host mounts.
MAPPED_DIRECTORY = r'''
import hashlib, json, os, pathlib, re, struct, subprocess, sys, tempfile
assert sys.argv[1] in ["directory-only", "microvm"]
tools = pathlib.Path("/usr/local/lib/kronik") / ("directory-tools" if sys.argv[1] == "directory-only" else "microvm")
manifest = json.loads((tools/"manifest.json").read_text())
provenance_bytes = (tools/"provenance.json").read_bytes()
assert hashlib.sha256(provenance_bytes).hexdigest() == manifest["provenance_sha256"]
provenance = json.loads(provenance_bytes)
for name in ["mke2fs","debugfs","e2fsck"]:
    digest = hashlib.sha256((tools/name).read_bytes()).hexdigest()
    assert digest == provenance["offline_tools"][name], name
    if name == "mke2fs": assert digest == manifest["mke2fs_sha256"]
work = pathlib.Path(tempfile.mkdtemp(prefix="mapped-directory-", dir="/run/kronik"))
def run(name, *args, env=None):
    result = subprocess.run([str(tools/name), *map(str,args)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    assert result.returncode == 0, result.stdout.decode(errors="replace")
    assert len(result.stdout) <= 1024*1024, "tool output limit"
    return result.stdout.decode(errors="replace")
caps = struct.pack("<IIIII", 0x02000001, 1 << 10, 0, 0, 0)
user = b"mapped\x00binary\xff"
root_value = b"root\x00metadata\xfe"
mtime, root_mtime = 2300000000, 2300000123
def source(name):
    root = work/name
    root.mkdir()
    payload = root/"payload"
    payload.write_bytes(b"actual mapped directory data\n")
    os.chown(payload, 12345, 23456)
    payload.chmod(0o640)
    os.setxattr(payload, "security.capability", caps)
    os.setxattr(payload, "user.binary", user)
    assert os.getxattr(payload, "security.capability") == caps
    os.link(payload, root/"hardlink")
    root.chmod(0o751)
    os.setxattr(root, "user.root", root_value)
    os.utime(payload, (mtime, mtime))
    os.utime(root, (root_mtime, root_mtime))
    return root
def image(root, name, owner):
    disk = work/name
    with disk.open("xb") as stream: stream.truncate(96 << 20)
    env = {"E2FSPROGS_FAKE_TIME":"1", "MKE2FS_CONFIG":"/dev/null", "LC_ALL":"C", "UNIX_IO_NOZEROOUT":"1"}
    run("mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-I", "256",
        "-m", "0", "-N", "512", "-U", "12345678-1234-1234-1234-123456789abc",
        "-O", "none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum",
        "-E", f"lazy_itable_init=0,lazy_journal_init=0,nodiscard,hash_seed=12345678-1234-1234-1234-123456789abc,root_owner={owner},root_perms=0751",
        "-d", root, disk, env=env)
    run("e2fsck", "-f", "-n", disk)
    return disk
def stat_inode(disk, path, uid, gid, mode, stamp, links):
    text = run("debugfs", "-R", f"stat {path}", disk)
    assert int(re.search(r"User:\s+(\d+)",text)[1]) == uid, text
    assert int(re.search(r"Group:\s+(\d+)",text)[1]) == gid, text
    assert int(re.search(r"Mode:\s+0*([0-7]+)",text)[1],8) == mode, text
    assert int(re.search(r"Links:\s+(\d+)",text)[1]) == links, text
    seconds, extra = re.search(r"mtime:\s+0x([0-9a-f]+):([0-9a-f]+)",text).groups()
    low, high = int(seconds,16), int(extra,16)
    decoded = low - (1 << 32) if low & (1 << 31) else low
    assert decoded + ((high & 3) << 32) == stamp and high >> 2 == 0, text
    return int(re.search(r"Inode:\s+(\d+)",text)[1]), text
def xattr(disk, path, key, value, name):
    out = work/name
    run("debugfs", "-R", f"ea_get -f {out} {path} {key}", disk)
    assert out.read_bytes() == value, (path,key)
for name in ["mke2fs","debugfs","e2fsck"]:
    assert run(name,"-V").split()[1] == "1.47.2"
first = source("first")
import time
time.sleep(1.1)
second = source("second")
assert int(first.stat().st_ctime) != int(second.stat().st_ctime), "construction-time control did not differ"
# Force different construction metadata without changing content or any mtime.
os.chown(second/"payload", 12345, 23456)
os.setxattr(second/"payload", "security.capability", caps)
os.utime(second/"payload", (mtime,mtime))
a, b = image(first,"first.ext4","0:0"), image(second,"second.ext4","0:0")
assert a.read_bytes() == b.read_bytes(), "host construction metadata changed filesystem bytes"
inode, payload_stat = stat_inode(a,"/payload",12345,23456,0o640,mtime,2)
other, _ = stat_inode(a,"/hardlink",12345,23456,0o640,mtime,2)
assert inode == other, "hardlink identity lost"
_, root_stat = stat_inode(a,"/",0,0,0o751,root_mtime,3)
xattr(a,"/payload","security.capability",caps,"capability.bin")
xattr(a,"/payload","user.binary",user,"user.bin")
xattr(a,"/","user.root",root_value,"root.bin")
dump = work/"dump"
run("debugfs","-R",f"dump /payload {dump}",a)
assert dump.read_bytes() == (first/"payload").read_bytes()
data = image(first,"data.ext4","123:456")
stat_inode(data,"/",123,456,0o751,root_mtime,3)
xattr(data,"/","user.root",root_value,"data-root.bin")
print(json.dumps({"work":str(work),"uid":12345,"gid":23456,"root_mtime":root_mtime,
    "future_mtime":mtime,"payload_stat":payload_stat,"root_stat":root_stat,
    "capability_hex":caps.hex(),"user_xattr_hex":user.hex(),"root_xattr_hex":root_value.hex(),
    "image_sha256":hashlib.sha256(a.read_bytes()).hexdigest(),
    "tools":{name:hashlib.sha256((tools/name).read_bytes()).hexdigest()
             for name in ["mke2fs","debugfs","e2fsck"]},"status":"PASS"}))
'''


def mapped_directory_proof(root, cfg, directory_only=False):
    pid = audit(root, cfg)
    raw = command(["nsenter", "--target", pid, "--mount", "--pid",
                   "nsenter", "--user=/run/kronik-userns/user", "--setuid=0", "--setgid=0",
                   "python3", "-c", MAPPED_DIRECTORY, "directory-only" if directory_only else "microvm"],
                  240, log=root/"mapped-directory.log")
    result = json.loads(raw)
    work = Path(cfg["run"]) / Path(result["work"]).name
    payload = work / "first/payload"
    require((payload.stat().st_uid, payload.stat().st_gid) ==
            (cfg["subid"] + 12344, cfg["subid"] + 23455),
            "DIRECTORY proof did not use actual mapped host ownership")
    require((work/"first").stat().st_uid == cfg["uid"], "mapped source root is not the service owner")
    result["host_uid"], result["host_gid"] = payload.stat().st_uid, payload.stat().st_gid
    (root/"mapped-directory.json").write_text(json.dumps(result, indent=2))

def check_errno(value, allowed):
    require(type(value) is int and value in allowed, f"unexpected errno: {value}")


def owner_tree(roots, cfg):
    """Explicit roots cover supported separate actor filesystems without find -xdev."""
    allowed = {Path(p).resolve(strict=True) for p in roots}
    seen = set()
    for root in allowed:
        stack = [root]
        while stack:
            path = stack.pop()
            md = path.lstat()
            require(md.st_uid != 0 and md.st_gid != 0, f"root-owned data: {path}")
            require(md.st_uid == cfg["uid"] or cfg["subid"] <= md.st_uid < cfg["subid"] + 65536,
                    f"unexpected data uid {md.st_uid}: {path}")
            require(md.st_gid == cfg["gid"] or cfg["subid"] <= md.st_gid < cfg["subid"] + 65536,
                    f"unexpected data gid {md.st_gid}: {path}")
            if stat.S_ISLNK(md.st_mode):
                # Only legacy actor-root links designate host roots; OCI/application links are leaves.
                if path.parent == Path(cfg["data"])/"foreign/actors":
                    target = path.resolve(strict=True)
                    require(target.is_dir() and
                            (target in allowed or any(target.is_relative_to(r) for r in allowed)),
                            f"unlisted logical actor root: {path} -> {target}")
                continue
            if stat.S_ISDIR(md.st_mode):
                identity = (md.st_dev, md.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                stack.extend(path.iterdir())


# Executed only after nsenter enters the target and unshare creates a CHILD mount namespace.
CHILD_FS = r'''
import ctypes, errno, json, os, pathlib, secrets
name = ".kronik-check-" + secrets.token_hex(16)
results = []
for directory in ["/etc", "/usr", "/root"]:
    path = pathlib.Path(directory) / name
    created = None
    try:
        fd = os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
        created = os.fstat(fd)
        os.close(fd)
        raise RuntimeError("write escaped read-only service policy: " + str(path))
    except OSError as error:
        if error.errno not in [errno.EROFS, errno.EACCES, errno.EPERM]: raise
        results.append([str(path), error.errno])
    finally:
        if created is not None:
            now = path.lstat()
            if (now.st_dev, now.st_ino) != (created.st_dev, created.st_ino):
                raise RuntimeError("probe file replaced; refusing cleanup")
            path.unlink()
path = pathlib.Path("/var/lib/kronik") / name
fd = os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
identity = os.fstat(fd)
os.write(fd, b"owned positive control")
os.fsync(fd)
os.close(fd)
if (path.stat().st_dev, path.stat().st_ino) != (identity.st_dev, identity.st_ino):
    raise RuntimeError("data control replaced")
path.unlink()
libc = ctypes.CDLL(None, use_errno=True)
# This mount namespace is a disposable descendant, NEVER the running daemon's.
ret = libc.mount(None, b"/", None, 32, None)
if ret == 0: raise RuntimeError("remount unexpectedly succeeded in child namespace")
error = ctypes.get_errno()
if error not in [errno.EPERM, errno.EACCES, errno.EROFS]:
    raise OSError(error, "unexpected remount error")
print(json.dumps({"readonly":results,"own_write":True,"remount_errno":error}))
'''


def audit(root, cfg):
    pid, cg = service(cfg)
    initial = os.readlink("/proc/1/ns/user")
    pids = set()
    for leaf in cg.rglob("cgroup.procs"):
        pids.update(map(int, leaf.read_text().split()))
    require(pids, "no processes in owned cgroup")
    rows = []
    for child in sorted(pids):
        try:
            fields = status(child)
            userns = os.readlink(f"/proc/{child}/ns/user")
        except FileNotFoundError:
            continue
        require(all(int(uid) != 0 for uid in fields["Uid"].split()), f"host root in owned cgroup: {child}")
        if userns == initial:
            for key in ["CapEff", "CapPrm", "CapInh", "CapAmb"]:
                require(int(fields[key], 16) == 0, f"host capability {key} retained by {child}")
        rows.append({"pid":child,"uid":fields["Uid"].split(),"userns":userns,
                     "capabilities":{k:fields[k].strip() for k in ["CapEff","CapPrm","CapInh","CapAmb"]}})
    main = status(pid)
    require(main["NoNewPrivs"].strip() == "1", "main lacks no-new-privileges")
    require(main["Seccomp"].strip() == "2", "main lacks seccomp filter")
    require(os.readlink(f"/proc/{pid}/ns/user") != initial, "daemon did not enter owned user namespace")
    require(list(map(int, main["Gid"].split())) == [cfg["gid"]] * 4, "wrong numeric service groups")
    actual_ns = Path(f"/proc/{pid}/ns/user").stat()
    pinned_ns = fixture_pin(cfg).stat()
    require((actual_ns.st_dev, actual_ns.st_ino) == (pinned_ns.st_dev, pinned_ns.st_ino),
            "service is not in the exact owned pinned namespace")
    for name, owner in [("uid", cfg["uid"]), ("gid", cfg["gid"])]:
        mapping = [list(map(int, line.split())) for line in
                   Path(f"/proc/{pid}/{name}_map").read_text().splitlines()]
        require(mapping == [[0, owner, 1], [1, cfg["subid"], 65535]],
                f"actual {name} namespace mapping differs from the owned fixture")
    consumed_service(root, cfg, pid)
    legacy = Path(cfg["data"])/".kronik-check-rootless"
    legacy_identity, legacy_bytes = legacy.lstat(), legacy.read_bytes()
    require(legacy_bytes == cfg["token"].encode(),"exclusive legacy canary control is missing/wrong")
    before = Path(f"/proc/{pid}/mountinfo").read_bytes()
    raw = command(["nsenter", "--target", pid, "--mount", "--pid",
                   "nsenter", "--user=/run/kronik-userns/user", "--setuid=0", "--setgid=0",
                   "unshare", "--mount", "--propagation", "private", "python3", "-c", CHILD_FS], 15)
    require(Path(f"/proc/{pid}/mountinfo").read_bytes() == before, "live service mount namespace changed")
    require((legacy.lstat().st_dev,legacy.lstat().st_ino) ==
            (legacy_identity.st_dev,legacy_identity.st_ino) and legacy.read_bytes() == legacy_bytes,
            "filesystem probe overwrote/deleted the preexisting legacy canary")
    owner_tree(cfg["data_roots"], cfg)
    for name, maximum in [("memory.max", 2147483648), ("pids.max", 512)]:
        got = (cg / name).read_text().strip()
        require(got != "max" and int(got) <= maximum, f"unbounded {name}: {got}")
    require((cg / "cpu.max").read_text().split()[0] != "max", "CPU has no quota")
    result = {"processes":rows,"filesystem":json.loads(raw),"main_pid":pid,"cgroup":str(cg),
              "legacy_canary_unchanged":True,"memory_current":int((cg/"memory.current").read_text()),
              "memory_peak":int((cg/"memory.peak").read_text())}
    (root / "check-rootless.json").write_text(json.dumps(result, indent=2))
    return pid


class HostControls:
    """Exclusive real host canaries; control traffic is drained before actor checks."""
    def __init__(self, root, token, forbidden_ports=()):
        self.root, self.token = root, token
        self.forbidden_ports = forbidden_ports
        self.sockets, self.receipts, self.threads = [], [], []
        self.stop = threading.Event()
        self.process = None
        self.sysv = None
        self.files = []

    def listener(self, family, kind, address):
        for _ in range(32):
            sock = socket.socket(family, kind)
            try:
                sock.bind(address)
            except BaseException:
                sock.close()
                raise
            if family in [socket.AF_INET,socket.AF_INET6] and sock.getsockname()[1] in self.forbidden_ports:
                sock.close()
                continue
            self.sockets.append(sock)
            sock.settimeout(0.2)
            if kind == socket.SOCK_STREAM:
                sock.listen(8)
            return sock
        raise Violation("could not allocate a host listener distinct from actor controls")

    def __enter__(self):
        try:
            return self.enter()
        except BaseException:
            self.__exit__()
            raise

    def enter(self):
        self.v4 = self.listener(socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 0))
        self.v6 = self.listener(socket.AF_INET6, socket.SOCK_STREAM, ("::1", 0))
        self.dns4 = self.listener(socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.1", 0))
        self.dns6 = self.listener(socket.AF_INET6, socket.SOCK_DGRAM, ("::1", 0))
        addresses = json.loads(command(["ip","-json","address","show","up"],10))
        local_v4 = [a["local"] for interface in addresses for a in interface.get("addr_info",[])
                    if a["family"] == "inet" and a["scope"] == "global"]
        require(local_v4, "required owned non-loopback host IPv4 listener has no local address")
        self.host_ip = local_v4[0]
        self.external_v4 = self.listener(socket.AF_INET,socket.SOCK_STREAM,(self.host_ip,0))
        self.external_dns = self.listener(socket.AF_INET,socket.SOCK_DGRAM,(self.host_ip,0))
        self.unix_path = str(self.root / "host-listener.sock")
        self.unix = self.listener(socket.AF_UNIX, socket.SOCK_STREAM, self.unix_path)
        self.unix_identity = Path(self.unix_path).lstat()
        self.abstract_name = f"host-{self.token}"
        self.abstract = self.listener(socket.AF_UNIX, socket.SOCK_STREAM, "\0" + self.abstract_name)
        for index, sock in enumerate(self.sockets):
            peer = socket.socket(sock.family, sock.type)
            peer.settimeout(1)
            try:
                peer.connect(sock.getsockname())
                if sock.type == socket.SOCK_STREAM:
                    accepted, _ = sock.accept()
                    accepted.close()
                else:
                    peer.send(b"positive-host-control")
                    require(sock.recv(256) == b"positive-host-control", "host UDP control did not run")
            finally:
                peer.close()
            def observe(sock=sock, index=index):
                while not self.stop.is_set():
                    try:
                        if sock.type == socket.SOCK_STREAM:
                            peer, _ = sock.accept()
                            peer.close()
                            self.receipts.append([index, "accept"])
                        else:
                            packet, _ = sock.recvfrom(512)
                            self.receipts.append([index, "udp", packet.hex()])
                    except socket.timeout:
                        pass
                    except OSError:
                        if not self.stop.is_set():
                            self.receipts.append([index, "listener error"])
                        return
            thread = threading.Thread(target=observe, daemon=True)
            thread.start()
            self.threads.append(thread)
        marker = self.root / "host-marker"
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, self.token.encode())
        os.close(fd)
        self.files.append((marker, marker.stat()))
        self.process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(900)", self.token])
        libc = ctypes.CDLL(None, use_errno=True)
        for _ in range(32):
            key = secrets.randbelow(0x7ffffffe) + 1
            ident = libc.shmget(key, 4096, 0o1000 | 0o2000 | 0o666)
            if ident >= 0:
                self.sysv = (libc, key, ident)
                break
            require(ctypes.get_errno() == errno.EEXIST, "host SysV control creation failed")
        require(self.sysv is not None, "no exclusive SysV key")
        return self

    def __exit__(self, *_):
        self.stop.set()
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            thread.join(timeout=1)
        (self.root / "host-listeners.json").write_text(json.dumps(self.receipts, indent=2))
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=5)
        if self.sysv is not None:
            libc, _, ident = self.sysv
            require(libc.shmctl(ident, 0, None) == 0, "owned SysV cleanup failed")
        cleanup_errors = []
        resources = list(self.files)
        if hasattr(self, "unix_identity"):
            resources.append((Path(self.unix_path), self.unix_identity))
        for path, identity in resources:
            try:
                remove_owned(path, identity)
            except (OSError, Violation) as error:
                cleanup_errors.append(str(error))
        (self.root/"host-cleanup.json").write_text(json.dumps(cleanup_errors,indent=2))
        require(not cleanup_errors, "owned host resource cleanup failed: " + "; ".join(cleanup_errors))
        require(not self.receipts,f"actual forbidden host listener receipts: {self.receipts}")


def api_daemon(cfg):
    return Daemon(cfg["binary"], cfg["data"], cfg["socket"], 0, os.devnull)


def ok(daemon, method, path, body=None):
    code, result = daemon.api(method, path, body, timeout=90)
    require(code == 200, f"API {method} {path}: {code}: {result}")
    return result


def deploy_caller(daemon, root, cfg):
    wasm = base64.b64encode((ROOT / "tests/guests/counter.wasm").read_bytes()).decode()
    manifest = ok(daemon, "POST", "/v1/deployments",
                  {"wasm_base64":wasm,"dry_run":True,"reason":"owned caller manifest"})
    kind = manifest["deployment"]["kind"]
    deployments = ok(daemon, "GET", "/v1/deployments")["deployments"]
    require(not any(k["kind"] == kind for d in deployments for k in d["kinds"]),
            f"kind {kind} exists: refusing to overwrite it")
    result = ok(daemon, "POST", "/v1/deployments", {"wasm_base64":wasm,"reason":"owned isolation caller"})
    require(result["deployment"]["kind"] == kind, "caller manifest changed")
    cfg["caller_kind"] = kind
    raise_effect_timeout(daemon, kind)
    return kind


def raise_effect_timeout(daemon, kind):
    """Sets the caller kind's effect timeout, recorded in the log like any limit."""
    result = ok(daemon, "POST", "/v1/limits",
                {"kind":kind,"effect_timeout_ms":EFFECT_TIMEOUT_MS,
                 "reason":"owned isolation proof: the guest fills its 1GiB drive in one call"})
    require(result["limits"]["effect_timeout_ms"] == EFFECT_TIMEOUT_MS,
            f"the caller's effect timeout was not raised: {result}")


def report_items(report, count=None, reached=False):
    require(isinstance(report, dict) and isinstance(report.get("items"), list), "malformed probe report")
    items = report["items"]
    require(items and (count is None or len(items) == count), "missing probe targets")
    for item in items:
        require(set(item) == {"target", "outcome", "detail", "errno"}, "unknown probe report shape")
        if reached:
            require(item["outcome"] == "reached" and item["errno"] is None, f"positive control failed: {item}")
        else:
            require(item["outcome"] in ["blocked", "absent"], f"boundary reached or unexpected error: {item}")
            if item["outcome"] == "blocked":
                allowed = [errno.EPERM,errno.EACCES,errno.ENOENT,errno.ENOTDIR]
                if report.get("check") == "/check/network":
                    allowed = [errno.EPERM,errno.EACCES,errno.ENOENT,errno.ECONNREFUSED,errno.ENETUNREACH,
                               errno.EHOSTUNREACH,errno.ETIMEDOUT,errno.EAFNOSUPPORT,errno.EADDRNOTAVAIL,errno.EAGAIN]
                if report.get("check") == "/check/sysv":
                    allowed = [errno.ENOENT]
                check_errno(item["errno"], allowed)
    return items


def identity_report(report, isolation):
    items = report.get("items", [])
    targets = ["/proc/self/status", "/proc/self/cgroup", "/proc/sys/kernel/hostname"]
    targets += [f"/proc/self/ns/{ns}" for ns in ["user", "mnt", "net", "pid", "ipc", "uts", "cgroup"]]
    require([item["target"] for item in items] == targets, "identity probe omitted/replaced a target")
    checked = items
    # Sentry exposes ns/cgroup only after its virtual cgroupfs was mounted; retain the diagnostic.
    if isolation == "gvisor" and items[-1]["errno"] == errno.ENOENT:
        require(items[-1]["outcome"] == "error", "unexpected missing namespace report")
        checked = items[:-1]
    report_items({**report, "items": checked}, len(checked), reached=True)
    return items


def device_report(report, isolation):
    expected = ["/dev/kvm","/dev/sda","/dev/vda","/dev/vdb","/dev/nvme0n1","/dev/mem"]
    require(report["check"] == "/check/devices" and [i["target"] for i in report["items"]] == expected,
            "device probe omitted/replaced a target")
    for item in report["items"]:
        if isolation == "microvm" and item["target"] in ["/dev/vda","/dev/vdb"]:
            # These are OWN guest disks, not host devices. Guest init may hide their nodes.
            if item["outcome"] == "reached":
                require(item["errno"] is None, "guest disk reported an unexpected errno")
                continue
        require(item["outcome"] == "blocked", f"host device reached or unexpected error: {item}")
        check_errno(item["errno"],[errno.ENOENT,errno.EACCES,errno.EPERM])


def vm_roots(cfg):
    directory = Path(cfg["run"])/"microvm"
    try:
        return set(directory.iterdir())
    except FileNotFoundError:
        return set()


def nspid(fields):
    """The NSpid line of /proc/PID/status as integers: the id in each PID namespace, the reader's first."""
    return [int(n) for n in fields["NSpid"].split()]


def vm_processes(members, read_status, read_args):
    """Tell the two processes of a VM's cgroup apart.

    The VMM is init of a PID namespace of its own, so the cgroup holds two processes: the
    launcher, an ordinary process of the private manager's PID namespace that waits for the
    VMM, and the VMM, a child of the launcher whose NSpid ends in 1. Returns (launcher, vmm,
    launcher_inside): the two host ids, and the launcher's id in the manager's namespace, which
    is what the fixture helper translates. The last NSpid entry of the VMM is its id in its
    own namespace (1) and says nothing about the manager's, and the helper only knows the
    processes of the manager's namespace: the VMM is found through its launcher.
    """
    require(len(members) == 2 and len(set(members)) == 2,
            f"owned VM cgroup must hold exactly the launcher and the VMM: {members}")
    seen = {}
    for pid in members:
        ids = nspid(read_status(pid))
        require(len(ids) >= 1 and ids[0] == pid, f"NSpid of {pid} does not start with its own id: {ids}")
        seen[pid] = ids
    # The VMM lives one PID namespace below the launcher and is init of it.
    vmm = max(members, key=lambda pid: len(seen[pid]))
    launcher = next(pid for pid in members if pid != vmm)
    require(len(seen[vmm]) == len(seen[launcher]) + 1,
            f"the VMM is not in a PID namespace of its own one level below the launcher's: {seen}")
    require(seen[vmm][-1] == 1, f"the VMM is not init of its PID namespace: {seen}")
    require(int(read_status(vmm)["PPid"]) == launcher, "the VMM is not a child of the launcher")
    require(read_args(vmm)[:1] == [b"/firecracker"], f"the VMM is not /firecracker: {read_args(vmm)}")
    require(b"launch-microvm" in read_args(launcher), "the launcher is not `kronik foreign launch-microvm`")
    return launcher, vmm, seen[launcher][-1]


def stop_record(line):
    """The fields of the daemon's `microVM stopped` log line, text or JSON format."""
    def field(key):
        match = re.search(key + r'"?\s*[=:]\s*"?([A-Za-z0-9_]+)', line)
        return match.group(1) if match else None
    return {"acknowledged": field("acknowledged"), "exit_ms": field("exit_ms"), "forced": field("forced")}


def console_panics(text):
    """The lines of a guest console that show a kernel or PID 1 panic."""
    return [line for line in text.splitlines() if PANIC.search(line)]


def vm_stop_proof(root, cfg, name, offset):
    """ADR 0096's graceful stop, after the removal of the microVM actor `name`: the daemon logs
    the guest's acknowledged STOP and how long after it the VMM exited (`serve.log` after
    `offset`). The VMM must exit by itself within STOP_LIMIT_MS, and the guest console must
    show no panic: a panic ends the VMM as quickly as a clean stop does."""
    log = root / "serve.log"
    deadline = time.monotonic() + 60
    while True:
        with log.open("rb") as stream:
            stream.seek(offset)
            text = stream.read(LIMIT).decode(errors="replace")
        lines = [line for line in text.splitlines() if "microVM stopped" in line and name in line]
        if lines:
            break
        require(time.monotonic() < deadline, f"no microVM stop record for {name} in {log}")
        time.sleep(0.2)
    record = stop_record(lines[-1])
    console = Path(cfg["data"])/"foreign/actors"/name/"output.log"
    shown = console.read_bytes()[-LIMIT:].decode(errors="replace") if console.exists() else ""
    panics = console_panics(shown)
    evidence = {"actor":name,"log_line":lines[-1],**record,"limit_ms":STOP_LIMIT_MS,
                "console":str(console),"console_bytes":len(shown),"panic_lines":panics}
    (root/f"vm-stop-{name}.json").write_text(json.dumps(evidence,indent=2))
    require(record["acknowledged"] == "true", f"the guest did not acknowledge STOP: {lines[-1]}")
    require(record["forced"] == "false", f"the VMM had to be killed after STOP: {lines[-1]}")
    require(record["exit_ms"] is not None and int(record["exit_ms"]) <= STOP_LIMIT_MS,
            f"the VMM exited {record['exit_ms']} ms after the acknowledged STOP, more than {STOP_LIMIT_MS}")
    require(shown.strip(), f"the guest console log {console} is missing or empty")
    require(not panics, f"the guest console shows a panic: {panics}")
    return evidence


def vm_config(directory):
    """Firecracker's whole configuration of a running VM (`GET /vm/config`)."""
    conn = UnixConnection(str(directory/"jail/api.sock"),5)
    try:
        conn.request("GET","/vm/config")
        response = conn.getresponse()
        raw = response.read(LIMIT + 1)
        require(response.status == 200 and len(raw) <= LIMIT, f"real Firecracker vm/config failed: {response.status}")
        return json.loads(raw)
    finally:
        conn.close()


def no_network_device(config):
    """A VM configuration with a vsock device and no network interface (and so no MMDS)."""
    require(not config.get("network-interfaces"), f"the VM has a network interface: {config.get('network-interfaces')}")
    require(config.get("vsock"), "the VM has no vsock device, so no bridge")
    require(not config.get("mmds-config"), "the VM has a metadata service")


def vm_calibration(root, cfg, name, cpu, memory, candidates):
    require(len(candidates) == 1, "actual VM runtime root was not uniquely created")
    directory = next(iter(candidates))
    require(directory.parent == Path(cfg["run"])/"microvm", "VMM root escaped fixture")
    state = json.loads((directory/"state.json").read_text())
    child_name = state["cgroup"].rstrip("/").split("/")[-1]
    expected_child = ("copy-" + directory.name.removeprefix("kronik-copy-")
                      if directory.name.startswith("kronik-copy-") else directory.name)
    require(child_name == expected_child, "VMM state names a different owned sandbox")
    _, service_cg = service(cfg)
    matches = list(service_cg.rglob(child_name))
    require(len(matches) == 1, "VMM is not in the exact owned delegated cgroup")
    cg = matches[0]
    members = [int(p) for p in (cg/"cgroup.procs").read_text().split()]
    launcher, pid, launcher_inside = vm_processes(members, status, process_args)
    # The launcher is a process of the private manager's namespace and the helper translates it;
    # the VMM, init of a namespace of its own, is identified through it.
    require(int(command([cfg["helper"],"host-pid",root,launcher_inside],10)) == launcher,
            "VM launcher PID translation changed")
    validate_fixture_pid(cfg,launcher)
    fields = status(pid)
    main, _ = service(cfg)
    for who, process in [("VM launcher",launcher),("VMM",pid)]:
        held = status(process)
        require(list(map(int,held["Uid"].split())) == [cfg["uid"]]*4, f"{who} has host root/wrong uid")
        for cap in ["CapEff","CapPrm","CapInh","CapAmb","CapBnd"]:
            require(int(held[cap],16) == 0, f"{who} retained {cap}")
        require(held["NoNewPrivs"].strip() == "1", f"{who} can gain privilege")
        for ns in ["mnt","net","cgroup"]:
            require(os.readlink(f"/proc/{process}/ns/{ns}") != os.readlink(f"/proc/{main}/ns/{ns}"),
                    f"{who} did not enter its child-only {ns} namespace")
    require(fields["Seccomp"].strip() == "2", "real VMM lacks seccomp")
    require(os.readlink(f"/proc/{launcher}/ns/pid") == os.readlink(f"/proc/{main}/ns/pid") and
            os.readlink(f"/proc/{pid}/ns/pid") != os.readlink(f"/proc/{launcher}/ns/pid"),
            "the VMM did not enter a PID namespace of its own below the manager's")
    manifest = json.loads((root/"microvm/manifest.json").read_text())
    with open(f"/proc/{pid}/exe","rb") as executable:
        require(hashlib.file_digest(executable,"sha256").hexdigest() == manifest["firecracker_sha256"],
                "running VMM is not the exact pinned Firecracker")
    conn = UnixConnection(str(directory/"jail/api.sock"),5)
    try:
        conn.request("GET","/machine-config")
        response = conn.getresponse()
        raw = response.read(65537)
        require(response.status == 200 and len(raw) <= 65536, "real Firecracker machine-config failed")
        machine = json.loads(raw)
    finally:
        conn.close()
    guest_mib = memory >> 20
    requested = (cpu+999)//1000
    vcpus = 1 if requested == 1 else ((requested+1)//2)*2
    require(machine["mem_size_mib"] == guest_mib and machine["vcpu_count"] == vcpus,
            f"actual VMM resource rounding mismatch: {machine}")
    limits = {key:(cg/key).read_text().strip() for key in
              ["cpu.max","memory.max","memory.swap.max","pids.max","memory.current","memory.peak"]}
    require(limits["cpu.max"] == f"{cpu*100} 100000", f"wrong exact CPU quota: {limits}")
    require(int(limits["memory.max"]) == (guest_mib+128)*(1<<20), f"wrong fixed VMM overhead cap: {limits}")
    require(limits["memory.swap.max"] == "0" and limits["pids.max"] == "1024", f"missing VMM hard cap: {limits}")
    require(0 < int(limits["memory.current"]) <= int(limits["memory.max"]) and
            0 < int(limits["memory.peak"]) <= int(limits["memory.max"]), "VMM calibration exceeds its cap")
    data = Path(cfg["data"])/"foreign/actors"/name/"data.ext4"
    if name.startswith("probe-") or name.startswith("pg-"):
        require(data.stat().st_size == 1<<30 and data.stat().st_blocks*512 >= 1<<30,
                "actual persistent drive is not fixed/reserved 1GiB")
    whole = vm_config(directory)
    no_network_device(whole)
    evidence = {"actor":name,"pid":pid,"launcher_pid":launcher,"runtime":str(directory),"cgroup":str(cg),
                "machine_config":machine,"vm_config":whole,"declared_cpu_millis":cpu,
                "declared_memory_bytes":memory,"limits":limits}
    (root/f"vm-calibration-{name}.json").write_text(json.dumps(evidence,indent=2))
    return directory, cg


def allocated_bytes(root):
    total, count, seen = 0, 0, set()
    def failed(error):
        raise error
    for directory, dirs, files in os.walk(root,followlinks=False,onerror=failed):
        count += len(dirs)+len(files)
        require(count <= 1000000,"proof disk observation entry limit")
        for name in files:
            try:
                md = (Path(directory)/name).lstat()
            except FileNotFoundError:
                continue  # A fixture log/WAL may rotate during this read-only observation.
            key = md.st_dev,md.st_ino
            if stat.S_ISREG(md.st_mode) and key not in seen:
                seen.add(key)
                total += md.st_blocks*512
    require(total <= 8<<30,"owned proof exceeds its fixed 8GiB allocated disk budget")
    return total


def conformance(root, cfg, isolation):
    audit(root, cfg)  # Fail wrong/root target before any mutation.
    host_hostname = socket.gethostname()
    daemon = api_daemon(cfg)
    kind = deploy_caller(daemon, root, cfg)
    names, secrets_created, evidence = [], [], []
    reason = "owned malicious actor conformance"
    def fetch(actor, path):
        response = ok(daemon, "POST", f"/v1/actors/{kind}/{cfg['token']}/messages",
                      {"name":"fetch-ok","text":f"GET foreign://{actor}{path}","reason":reason})
        reply = response.get("reply", {}).get("text", "")
        require(reply.startswith("200 "), f"ordinary recorded actor call failed: {response}")
        result = json.loads(reply[4:])
        evidence.append({"actor":actor,"path":path,"turn":response.get("turn_id"),"report":result})
        parsed = urllib.parse.urlsplit(path)
        require(result.get("check") == parsed.path, "probe answered the wrong check")
        pairs = urllib.parse.parse_qsl(parsed.query)
        if parsed.path in ["/check/paths","/check/marker","/check/network","/check/processes","/check/sysv"]:
            keyset = {"/check/paths":{"path"},"/check/marker":{"path"},"/check/network":{"tcp","udp","unix","abstract"},
                      "/check/processes":{"token"},"/check/sysv":{"key"}}[parsed.path]
            targets = [value for key,value in pairs if key in keyset]
            require([i["target"] for i in result["items"]] == targets, "probe omitted/replaced a requested target")
        return result
    def query(path, pairs):
        return path + "?" + urllib.parse.urlencode(pairs)
    completed = False
    try:
        identities = []
        control_ports = set()
        for role in ["attacker", "neighbour"]:
            for _ in range(32):
                token = secrets.token_hex(16)
                control_port = 20000 + int(token[:4],16) % 40000
                if control_port not in control_ports:
                    control_ports.add(control_port)
                    break
            else:
                raise Violation("actor private control port collision")
            cpu, memory = (1000,256 << 20)
            if isolation == "microvm":
                cpu, memory = (1000,128 << 20) if role == "attacker" else (2001,(256 << 20)+17)
            before_vm = vm_roots(cfg) if isolation == "microvm" else set()
            name = f"probe-{role}-{cfg['token']}"
            secret = f"probe-token-{role}-{cfg['token']}"
            ok(daemon, "PUT", f"/v1/secrets/{secret}", {"text":token,"reason":reason})
            secrets_created.append(secret)
            actor = ok(daemon, "POST", "/v1/foreign", {"name":name,"image":cfg["probe_image"],"port":8080,
                       "cpu_millis":cpu,"memory_bytes":memory,"isolation":isolation,
                       "secrets":[f"KRONIK_PROBE_TOKEN={secret}"],"reason":reason})
            names.append(name)
            require(actor["foreign"]["isolation"] == isolation, "backend changed unexpectedly")
            ok(daemon, "POST", "/v1/grants", {"kind":kind,"capability":f"foreign:{name}","reason":reason})
            deadline = time.monotonic() + 90
            while True:
                state = ok(daemon, "GET", f"/v1/foreign/{name}")["foreign"]["status"]
                if state["state"] == "running":
                    break
                require(time.monotonic() < deadline, f"probe not ready: {state}")
                time.sleep(0.2)
            controls = report_items(fetch(name, "/check/control"), 9, reached=True)
            identity = identity_report(fetch(name, "/check/identity"), isolation)
            # The guest's own view of the network: loopback and nothing else.
            interfaces = report_items(fetch(name, "/check/interfaces"), 1, reached=True)
            require(interfaces[0]["detail"] == "lo", f"the actor sees a network interface: {interfaces}")
            fields = dict(line.split(":",1) for line in identity[0]["detail"].splitlines() if ":" in line)
            require(list(map(int,fields["Uid"].split())) == [0,0,0,0], "malicious actor image must actually run as UID0")
            require(int(fields["CapEff"],16) != 0, "malicious namespace-root capabilities were silently removed")
            if isolation == "microvm":
                vm_calibration(root,cfg,name,cpu,memory,vm_roots(cfg)-before_vm)
            identities.append((name, token, controls, identity))
        attacker, neighbour = identities
        own, _, _, own_identity = attacker
        other, other_token, controls, other_identity = neighbour
        own_identity = identity_report(fetch(own,"/check/identity"), isolation)
        require(socket.gethostname() == host_hostname,"actor startup changed host UTS identity")
        # Separate kernels/synthetic procfs may reuse namespace inode numbers.
        # Real resource operations below, exact hostname and cgroup views are the oracle.
        for actor, identity in [(own, own_identity), (other, other_identity)]:
            require(identity[2]["detail"].strip() == actor, f"wrong UTS identity: {identity[2]}")
            require(cfg["unit"] not in identity[1]["detail"], "host delegated cgroup is visible inside actor")
        _, host_cgroup = service(cfg)
        populated = [p for p in host_cgroup.rglob("cgroup.procs") if p.read_text().strip()]
        require(populated,"host cgroup positive control empty")
        report_items(fetch(own,query("/check/paths",[("path",str(populated[0])),
                     ("path",str(populated[0].parent/"cgroup.subtree_control"))])),2)
        report_items(fetch(own, query("/check/marker", [("token",other_token),
                     ("path",f"/data/owned-{other_token}"),("path",f"/dev/shm/owned-{other_token}")])), 2)
        report_items(fetch(own, query("/check/processes", [("token",other_token)])), 1)
        report_items(fetch(own, query("/check/network", [("tcp",controls[3]["target"]),
                     ("abstract",other_token)])), 2)
        report_items(fetch(own, query("/check/sysv", [("key",controls[5]["target"])])), 1)
        device_report(fetch(own,"/check/devices"),isolation)
        if isolation == "microvm":
            disks = report_items(fetch(own,"/check/guest-disks"),3,reached=True)
            require(disks[0]["detail"].strip() == "1", "own guest root drive is not read-only")
            require(int(disks[1]["detail"].strip())*512 == 1 << 30, "own guest data drive is not fixed 1GiB")
            mounts = [line.split() for line in disks[2]["detail"].splitlines()]
            require(any(row[4] == "/" and row[row.index("-")+1] == "overlay" for row in mounts),
                    "guest writable root is not an ephemeral overlay")
            require(any(row[4] == "/data" and row[row.index("-")+1] == "ext4" and "rw" in row[5].split(",")
                        for row in mounts), "own guest data ext4 is not mounted writable")
            drive = Path(cfg["data"])/"foreign/actors"/own/"data.ext4"
            before_drive = drive.stat()
            before_used = allocated_bytes(root)
            require(os.statvfs(drive).f_bavail*os.statvfs(drive).f_frsize >= 64<<20,
                    "host reserve below 64MiB before guest-only ENOSPC proof")
            fill_seconds = None
            try:
                started = time.monotonic()
                filled = fetch(own,query("/check/fill-data",[("token",secrets.token_hex(16))]))
                fill_seconds = round(time.monotonic()-started,3)
                require(filled["errno"] == errno.ENOSPC and filled["capacity_bytes"] == 1<<30 and
                        512<<20 <= filled["written_bytes"] <= (1<<30)+(1<<20) and
                        filled["marker_unchanged"] is True and filled["cleanup"] is True,
                        f"guest ENOSPC/no-data-loss proof failed: {filled}")
            finally:
                after_drive = drive.stat()
                after_used = allocated_bytes(root)
                allocation = {"before_drive_bytes":before_drive.st_size,"after_drive_bytes":after_drive.st_size,
                              "before_drive_allocated":before_drive.st_blocks*512,
                              "after_drive_allocated":after_drive.st_blocks*512,
                              "host_allocated_before":before_used,"host_allocated_after":after_used,
                              "fill_seconds":fill_seconds,"effect_timeout_ms":EFFECT_TIMEOUT_MS}
                (root/"guest-enospc-host.json").write_text(json.dumps(allocation,indent=2))
                require((before_drive.st_dev,before_drive.st_ino) == (after_drive.st_dev,after_drive.st_ino) and
                        before_drive.st_size == after_drive.st_size == 1<<30 and
                        min(before_drive.st_blocks,after_drive.st_blocks)*512 >= 1<<30,
                        "guest fill replaced/expanded or unreserved its fixed drive")
                require(after_used-before_used <= LIMIT,"guest fill caused uncapped host extent growth")
                require(os.statvfs(drive).f_bavail*os.statvfs(drive).f_frsize >= 64<<20,
                        "guest fill consumed host disk reserve")
            report_items(fetch(own,"/check/control"),9,reached=True)
        with HostControls(root,secrets.token_hex(16),control_ports) as host:
            target_pairs = [("tcp",f"127.0.0.1:{host.v4.getsockname()[1]}"),
                            ("tcp",f"[::1]:{host.v6.getsockname()[1]}"),
                            ("tcp",f"{host.host_ip}:{host.external_v4.getsockname()[1]}"),
                            ("udp",f"127.0.0.1:{host.dns4.getsockname()[1]}"),
                            ("udp",f"[::1]:{host.dns6.getsockname()[1]}"),
                            ("udp",f"{host.host_ip}:{host.external_dns.getsockname()[1]}"),
                            ("unix",host.unix_path),("abstract",host.abstract_name)]
            report_items(fetch(own, query("/check/network", target_pairs)), len(target_pairs))
            report_items(fetch(own, query("/check/processes", [("token",host.token)])), 1)
            report_items(fetch(own, query("/check/marker", [("token",host.token),("path",str(root / "host-marker"))])), 1)
            report_items(fetch(own, query("/check/sysv", [("key",host.sysv[1])])), 1)
            # Every attempted name is exclusive; observe ALL host and daemon-private views.
            write_token = secrets.token_hex(16)
            directories = ["/", "/etc", "/usr", "/root", "/tmp", str(root), cfg["data"], cfg["run"]]
            paths = [Path(directory) / f".kronik-probe-{write_token}" for directory in directories]
            pid, _ = service(cfg)
            paths += [Path(f"/proc/{pid}/root") / p.relative_to("/") for p in paths]
            for path in paths:
                assert_absent(path)
            watched_roots = cfg["data_roots"] + [cfg["run"]]
            require(not outside_candidates(paths,watched_roots,write_token), "outside canary collision")
            try:
                write_report = fetch(own, query("/check/write", [("token",write_token)] + [("dir",p) for p in directories]))
                require(len(write_report["items"]) == len(directories), "write probe omitted targets")
                for directory, item in zip(directories,write_report["items"]):
                    require(item["target"] == str(Path(directory)/f".kronik-probe-{write_token}"),
                            "write probe replaced a target")
                    require(item["outcome"] in ["reached","blocked"], f"write probe error: {item}")
                    if item["outcome"] == "blocked":
                        check_errno(item["errno"],[errno.ENOENT,errno.ENOTDIR,errno.EACCES,errno.EPERM,errno.EROFS])
                require(any(i["outcome"] == "reached" and i["target"].startswith("/tmp/") for i in write_report["items"]),
                        "writable actor /tmp positive control failed")
            finally:
                observe_outside_writes(root,paths,watched_roots,write_token)
            time.sleep(0.3)
            require(not host.receipts, f"host listeners received actor traffic: {host.receipts}")
            evidence.append({"host_listener_receipts":host.receipts,"outside_paths":[str(p) for p in paths]})
        audit(root, cfg)
        completed = True
    finally:
        (root / f"conformance-{isolation}.json").write_text(json.dumps(evidence, indent=2))
        cleanup = []
        stop_offset = (root/"serve.log").stat().st_size if (root/"serve.log").exists() else 0
        for name in reversed(names):
            try:
                ok(daemon, "DELETE", f"/v1/foreign/{name}", {"reason":reason})
                cleanup.append({"actor":name,"removed":True})
            except Exception as error:
                cleanup.append({"actor":name,"error":str(error)})
        for secret in secrets_created:
            try:
                ok(daemon, "DELETE", f"/v1/secrets/{secret}", {"reason":reason})
            except Exception as error:
                cleanup.append({"secret":secret,"error":str(error)})
        (root / "actor-cleanup.json").write_text(json.dumps(cleanup, indent=2))
        require(not any("error" in row for row in cleanup), "owned actor cleanup failed")
        # Only after the proof itself passed: a failure above stays the reported one.
        if completed and isolation == "microvm":
            for name in names:
                vm_stop_proof(root, cfg, name, stop_offset)


def wait_healthy(cfg, timeout=90):
    daemon = api_daemon(cfg)
    deadline = time.monotonic() + timeout
    while True:
        try:
            code, health = daemon.api("GET", "/v1/health", timeout=2)
            if code == 200 and health["status"] == "ok":
                cfg["http_url"] = "http://" + health["http_listen"]
                return
        except (OSError, KeyError):
            pass
        require(time.monotonic() < deadline, "owned daemon readiness timed out")
        time.sleep(0.1)


def fresh_generation(root, cfg, label):
    command([cfg["helper"], "reset", root], 180, log=root/f"reset-{label}.log")
    wait_healthy(cfg)
    audit(root, cfg)


def program_proof(root, cfg, isolation="gvisor"):
    # Actual demos' fixed manifest kinds each get a fresh OWNED daemon generation.
    for demo in ["verify-change", "billing"]:
        fresh_generation(root, cfg, demo)
        env = {"KRONIK_BIN":cfg["binary"],"KRONIK_DEMO_SOCKET":cfg["socket"],
               "KRONIK_DEMO_HTTP":cfg["http_url"],"KRONIK_DEMO_DATA_DIR":cfg["data"],
               "KRONIK_DEMO_RUN_DIR":cfg["run"],"KRONIK_DEMO_OWNER_TOKEN":cfg["token"],
               "KRONIK_DEMO_PAYMENTS_IMAGE":cfg["payments_image"],"KRONIK_DEMO_FIXTURE":str(root)}
        work = root / f"demo-{demo}-{secrets.token_hex(8)}"
        command(["bash", ROOT / "demo" / f"{demo}.sh", work], 600, env, root / f"{demo}.log")
        audit(root, cfg)
    fresh_generation(root, cfg, "postgres")
    daemon = api_daemon(cfg)
    deploy_caller(daemon, root, cfg)
    postgres_proof(root, cfg, daemon, isolation)
    uid_audit(root, cfg, daemon)
    shipping_proof(root, cfg, daemon)


def postgres_proof(root, cfg, daemon, isolation="gvisor"):
    name = f"pg-{cfg['token']}"
    kind = cfg["caller_kind"]
    reason = "owned rootless Postgres fork proof"
    replies = []
    def sql(text, fork=None):
        prefix = f"/v1/forks/{fork}" if fork else "/v1"
        result = ok(daemon,"POST",f"{prefix}/actors/{kind}/{cfg['token']}/messages",
                    {"name":"fetch-ok","text":f"POST foreign://{name}/sql\n\n{text}","reason":reason})
        replies.append(result)
        require(result.get("reply",{}).get("text","").startswith("200 "), f"SQL failed: {result}")
        return result
    def wait_pg():
        deadline = time.monotonic()+90
        while ok(daemon,"GET",f"/v1/foreign/{name}")["foreign"]["status"]["state"] != "running":
            require(time.monotonic()<deadline,"Postgres readiness timed out")
            time.sleep(0.2)
    fork = f"pg-fork-{cfg['token']}"
    completed = False
    try:
        before_vm = vm_roots(cfg) if isolation == "microvm" else set()
        ok(daemon,"POST","/v1/foreign",{"name":name,"image":cfg["pg_image"],"port":8080,
           "cpu_millis":1000,"memory_bytes":512<<20,"isolation":isolation,"fork_mode":"sandbox","reason":reason})
        ok(daemon,"POST","/v1/grants",{"kind":kind,"capability":f"foreign:{name}","reason":reason})
        wait_pg()
        if isolation == "microvm":
            vm_calibration(root,cfg,name,1000,512<<20,vm_roots(cfg)-before_vm)
        sql("CREATE TABLE owned_proof (n integer); INSERT INTO owned_proof VALUES (42)")
        actor_data = Path(cfg["data"])/"foreign/actors"/name
        pgdata = actor_data/("data.ext4" if isolation == "microvm" else "data/pg")
        expected = (cfg["uid"],cfg["gid"]) if isolation == "microvm" else (cfg["subid"]+69,cfg["gid"])
        require((pgdata.stat().st_uid,pgdata.stat().st_gid) == expected, "rootless disk/image ownership is wrong")
        if isolation == "microvm":
            production = {p for p in vm_roots(cfg) if p.name.startswith("kronik-foreign-")}
            vm_calibration(root,cfg,name,1000,512<<20,production)
            require(pgdata.stat().st_size == 1<<30, "the fixed ext4 data drive changed capacity")
        audit(root,cfg)
        pin = fixture_pin(cfg)
        before_pin = pin.stat()
        before_main, _ = service(cfg)
        before_start = sql("SELECT pg_postmaster_start_time()::text")["reply"]["text"]
        pin_unit = cfg["unit"].removesuffix(".service")+"-pin.service"
        command(manager_command(cfg,"restart",pin_unit),90,log=root/"live-pin-restart.log")
        after_pin = pin.stat()
        require((before_pin.st_dev,before_pin.st_ino) == (after_pin.st_dev,after_pin.st_ino),
                "pin restart replaced the live daemon's owned namespace")
        require(service(cfg)[0] == before_main and
                sql("SELECT pg_postmaster_start_time()::text")["reply"]["text"] == before_start,
                "pin restart disrupted the actual daemon/Postgres")
        # A postmaster's live start timestamp cannot be reconstructed by cold
        # booting Postgres from a copied disk; full VM memory must retain it.
        started = sql("SELECT pg_postmaster_start_time()::text")["reply"]["text"]
        ok(daemon,"POST","/v1/snapshots",{"reason":reason})
        sql("UPDATE owned_proof SET n=43")
        ok(daemon,"POST","/v1/forks",{"at":"now","name":fork,"reason":reason})
        replay = ok(daemon,"POST",f"/v1/forks/{fork}/replay",{"mode":"continuous","reason":reason})
        (root/"pg-replay.json").write_text(json.dumps(replay,indent=2))
        diff = ok(daemon,"GET",f"/v1/forks/{fork}/diff")
        (root/"pg-failed-or-passed-diff.json").write_text(json.dumps(diff,indent=2))
        require(any(row.get("mode")=="sandbox" for row in diff["options"]["foreign"]),"fork has no real sandbox copy")
        copy_parent = Path(cfg["data"])/"branches"/fork/"foreign"/name
        copy_dirs = list(copy_parent.iterdir())
        require(len(copy_dirs) == 1, "copy data directory is not exclusively owned")
        copy_key = copy_dirs[0].name
        if isolation == "microvm":
            copy_vm = Path(cfg["run"])/"microvm"/f"kronik-copy-{copy_key}"
            _, copy_cgroup = vm_calibration(root,cfg,"copy",1000,512<<20,{copy_vm})
            for filename in ["data.ext4","root.ext4","out/restore.mem","out/restore.state"]:
                require((copy_dirs[0]/filename).stat().st_size > 0, f"real snapshot backing missing: {filename}")
            require((copy_dirs[0]/"data.ext4").stat().st_size == 1<<30,"copy persistent drive is not 1GiB")
            require(sql("SELECT pg_postmaster_start_time()::text",fork)["reply"]["text"] == started,
                    "copy cold-booted instead of loading the live postmaster's memory")
        else:
            require((copy_dirs[0]/"data/pg").is_dir(),"real Postgres copy data was not created")
            pid, _ = service(cfg)
            runtime_command = ["nsenter","--target",pid,"--mount","--pid",
                               "nsenter","--user=/run/kronik-userns/user","--setuid=0","--setgid=0",
                               "/usr/local/bin/runsc","--root","/run/kronik/runsc","list","-quiet"]
            require(f"kronik-copy-{copy_key}" in command(runtime_command,10).splitlines(),
                    "copy data exists without a real running copy")
        sql("UPDATE owned_proof SET n=99",fork)
        fork_read = sql("SELECT n FROM owned_proof",fork)
        require(fork_read["reply"]["text"] == "200 99\n", "fork mutation missing")
        require(sql("SELECT n FROM owned_proof")["reply"]["text"] == "200 43\n", "fork changed production data")
        require(any(g.get("grounding") == "forked" for g in fork_read.get("effects", [])), "missing forked grounding")
        ok(daemon,"DELETE",f"/v1/forks/{fork}",{"reason":reason})
        deadline = time.monotonic() + 30
        while True:
            if isolation == "microvm":
                alive = copy_vm.exists() or copy_cgroup.exists()
            else:
                alive = f"kronik-copy-{copy_key}" in command(runtime_command,10).splitlines()
            if not alive and not copy_parent.exists():
                break
            require(time.monotonic() < deadline, "fork-owned runtime/data survived deletion")
            time.sleep(0.1)
        require(sql("SELECT n FROM owned_proof")["reply"]["text"] == "200 43\n",
                "fork cleanup stopped or damaged production Postgres")
        completed = True
    finally:
        (root/"postgres-replies.json").write_text(json.dumps(replies,indent=2))
        stop_offset = (root/"serve.log").stat().st_size if (root/"serve.log").exists() else 0
        ok(daemon,"DELETE",f"/v1/foreign/{name}",{"reason":reason})
    # A Postgres VM with a live database stops gracefully as well (ADR 0096).
    if completed and isolation == "microvm":
        vm_stop_proof(root, cfg, name, stop_offset)


def acceptor_restart(root,cfg):
    main, cg = service(cfg)
    initial = os.readlink("/proc/1/ns/user")
    candidates = []
    for leaf in cg.rglob("cgroup.procs"):
        for raw in leaf.read_text().split():
            pid = int(raw)
            try:
                fields = status(pid)
                if int(fields["PPid"]) == main and os.readlink(f"/proc/{pid}/ns/user") == initial:
                    require(list(map(int,fields["Uid"].split())) == [cfg["uid"]]*4,"acceptor wrong host UID")
                    require(all(int(fields[k],16) == 0 for k in ["CapEff","CapPrm","CapInh","CapAmb"]),
                            "actual API acceptor retained host capabilities")
                    candidates.append(pid)
            except FileNotFoundError:
                continue
    require(len(candidates) == 1,"actual initial-userns API acceptor was not uniquely identified")
    inside = status(candidates[0])["NSpid"].split()[-1]
    require(int(command([cfg["helper"],"host-pid",root,inside],10)) == candidates[0],"acceptor PID translation changed")
    validate_fixture_pid(cfg,candidates[0])
    mainfd, childfd = os.pidfd_open(main), os.pidfd_open(candidates[0])
    try:
        validate_fixture_pid(cfg,main)
        validate_fixture_pid(cfg,candidates[0])
        signal.pidfd_send_signal(childfd,signal.SIGKILL)
        deadline = time.monotonic()+30
        while True:
            new = int(command(manager_command(cfg,"show",cfg["unit"],"--property=MainPID","--value"),10))
            if new > 1 and new != main and select.select([mainfd],[],[],0)[0]:
                break
            require(time.monotonic()<deadline,"acceptor death did not boundedly fail/restart the daemon")
            time.sleep(0.1)
        wait_healthy(cfg)
        audit(root,cfg)
        (root/"acceptor-restart.json").write_text(json.dumps({"old_main_pid":main,"acceptor_pid":candidates[0],
            "new_main_pid":service(cfg)[0],"restart_observed":True},indent=2))
    finally:
        os.close(mainfd)
        os.close(childfd)


def uid_audit(root, cfg, daemon):
    reason0 = f"owned audit root {cfg['token']}"
    reason1 = f"owned audit operator {cfg['token']}"
    reason2 = f"owned audit service {cfg['token']}"
    reason3 = f"owned audit bearer {cfg['token']}"
    command([cfg["binary"],"--socket",cfg["socket"],"deploy",ROOT/"examples/dist/notes.wasm",
             "--reason",reason0],60,log=root/"audit-root.log")
    pid, _ = service(cfg)
    # The real 12 MiB JavaScript components use the demos' finite compilation budget.
    for uid, artifact, filename, reason in [
            (cfg["operator_uid"],"webhook-relay.wasm","operator.wasm",reason1),
            (cfg["uid"],"billing-ts-ledger.wasm","service.wasm",reason2)]:
        source = ROOT/"examples/dist"/artifact
        target = Path(cfg["run"])/filename
        with target.open("xb") as output:
            output.write(source.read_bytes())
        os.chown(target,cfg["uid"],cfg["gid"])
        target.chmod(0o640)
        command(["nsenter","--target",pid,"--mount","--pid","setpriv",f"--reuid={uid}",
                 f"--regid={cfg['gid']}","--clear-groups","--no-new-privs","/usr/local/bin/kronik",
                 "--socket","/run/kronik/api.sock","deploy",f"/run/kronik/{filename}","--reason",reason],
                600,log=root/f"audit-uid-{uid}.log")
    token_name = f"audit-{cfg['token']}"
    token = ok(daemon,"POST","/v1/tokens",{"name":token_name,"scopes":["admin"],"reason":reason3})["secret"]
    command([cfg["binary"],"--socket",cfg["socket"],"deploy",ROOT/"examples/dist/billing-ts-eu-vat.wasm",
             "--reason",reason3],600,env={"KRONIK_TOKEN":token},log=root/"audit-bearer.log")
    command(manager_command(cfg,"restart",cfg["unit"]),90,log=root/"audit-restart.log")
    wait_healthy(cfg)
    acceptor_restart(root,cfg)
    rows = ok(daemon,"GET","/v1/deployments")["deployments"]
    (root/"uid-audit.json").write_text(json.dumps(rows,indent=2))
    for reason, identity in [(reason0,"unix:uid=0"),(reason1,f"unix:uid={cfg['operator_uid']}"),
                             (reason2,f"unix:uid={cfg['uid']}"),(reason3,f"token:{token_name}")]:
        require(any(row.get("reason")==reason and row.get("token_id")==identity for row in rows),
                f"durable audit did not retain true caller identity {identity}")


def key_accesses(fd):
    opened = []
    while True:
        try:
            events = os.read(fd, 65536)
        except BlockingIOError:
            return opened
        offset = 0
        while offset < len(events):
            watch, mask, _, length = struct.unpack_from("iIII", events, offset)
            require(not mask & 0x00004000, "credential read observation overflowed")
            require(not mask & 0x00008000, "credential read watch was removed")
            if mask & 0x00000021:
                opened.append(watch)
            offset += 16 + length


def watch_key_reads(paths):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    require(fd >= 0, f"cannot observe credential reads: errno {ctypes.get_errno()}")
    try:
        watches = []
        for path in paths:
            watch = libc.inotify_add_watch(fd, os.fsencode(path), 0x00000021)
            require(watch >= 0, f"cannot watch credential: errno {ctypes.get_errno()}")
            watches.append(watch)
        # Real opens calibrate both watches before the no-reload interval.
        for path in paths:
            with path.open("rb") as stream:
                stream.read(1)
        require(set(key_accesses(fd)) == set(watches), "actual credential read controls were not observed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def shipping_proof(root, cfg, daemon):
    reason = "owned loaded-key rootless ship/restore"
    kind = cfg["caller_kind"]
    subject = f"owned:{cfg['token']}"
    personal = f"sealed-{secrets.token_hex(16)}"
    ok(daemon, "POST", "/v1/privacy/mode", {"mode":"on","reason":reason})
    before = ok(daemon, "POST", f"/v1/actors/{kind}/{cfg['token']}/messages",
                {"name":"increment","reason":reason})["reply"]["text"]
    secret_name = f"ship-key-{cfg['token']}"
    ok(daemon, "PUT", f"/v1/secrets/{secret_name}", {"text":f"secret-{secrets.token_hex(32)}","reason":reason})
    backups_before = set((root/"ship/main/keystore").glob("*.bin"))
    source = root / "etc/kronik/master.key"
    retained = root / "retained-master.key"
    require(not retained.exists(), "retained credential collision")
    pid, _ = service(cfg)
    credential = consumed_service(root, cfg, pid)
    reads = watch_key_reads([source, credential])
    try:
        source.rename(retained)
    except BaseException:
        os.close(reads)
        raise
    try:
        stored = ok(daemon, "POST", f"/v1/actors/{kind}/{cfg['token']}/messages",
                    {"name":"store","text":personal,"subject":subject,"reason":reason})
        require(stored["outcome"]["kind"] == "committed" and stored["reply"]["text"] == "stored",
                "live sealed store positive control did not commit")
        live = ok(daemon, "GET", f"/v1/actors/{kind}/{cfg['token']}")["state"]
        (root/"ship-before-state.json").write_text(json.dumps(live,indent=2))
        require(any(row["key"] == "stored" and row.get("text") == personal and row["subject"] == subject
                    for row in live), "live sealed read positive control failed")
        snap = ok(daemon, "POST", "/v1/snapshots", {"reason":reason})["snapshot"]["lsn"]
        deadline = time.monotonic() + 100
        while True:
            state_path = Path(cfg["data"]) / "ship.json"
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
            backups = list((root/"ship/main/keystore").glob("*.bin"))
            if snap in state.get("snapshots", []) and set(backups) - backups_before:
                break
            require(time.monotonic() < deadline, "snapshot/keystore did not ship during credential outage")
            time.sleep(0.2)
        require(service(cfg)[0] == pid, "daemon restarted during credential-outage shipping")
        require(not key_accesses(reads), "shipping reloaded a plaintext master-key source/credential")
    finally:
        os.close(reads)
        retained.rename(source)
    command(manager_command(cfg, "stop", cfg["unit"]), 45, log=root/"restore-stop.log")
    command([cfg["helper"], "restore", root], 180, log=root/"restore.log")
    command(manager_command(cfg, "start", cfg["unit"]), 90, log=root/"restore-start.log")
    # Shipping carries raw Wasm, not host-ABI compiled caches; cold JS compilation uses the demos' bound.
    wait_healthy(cfg,600)
    after = ok(daemon, "POST", f"/v1/actors/{kind}/{cfg['token']}/messages",
               {"name":"increment","reason":reason})["reply"]["text"]
    require(int(after) == int(before) + 1, "ship/restore lost counter state")
    state = ok(daemon, "GET", f"/v1/actors/{kind}/{cfg['token']}")["state"]
    (root/"ship-after-state.json").write_text(json.dumps(state,indent=2))
    require(any(row["key"] == "stored" and row["text"] == personal for row in state),
            "restored sealed subject value is unreadable")
    needle = personal.encode()
    for path in (Path(cfg["data"])/"branches").rglob("*"):
        if stat.S_ISREG(path.lstat().st_mode):
            with path.open("rb") as stream:
                previous = b""
                while block := stream.read(65536):
                    require(needle not in previous+block,f"sealed value leaked in {path}")
                    previous = block[-(len(needle)-1):]
    owner_tree(cfg["data_roots"], cfg)
    (root/"ship-restore.json").write_text(json.dumps({"snapshot_lsn":snap,"before_counter":int(before),
        "restored_counter":int(after),"source_authenticated":True,"sealed_value_readable":True,
        "plaintext_key_reopens":0}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=["check","conformance","directory"])
    parser.add_argument("--fixture",required=True)
    parser.add_argument("--isolation",choices=["gvisor","microvm"],default="gvisor")
    parser.add_argument("--program-proof",action="store_true")
    parser.add_argument("--microvm-proof",action="store_true")
    parser.add_argument("--ubuntu-required",action="store_true")
    args = parser.parse_args()
    root, cfg = fixture(args.fixture)
    result = {"mode":args.mode,"isolation":args.isolation,"status":"FAIL"}
    try:
        require(cfg["expected_mode"] == "rootless", "required rootless expectation cannot be inferred from target")
        require(not (args.program_proof and args.microvm_proof),"choose full program proof or the dedicated microVM oracle")
        require(not args.microvm_proof or args.isolation == "microvm","microVM oracle requires the actual microvm backend")
        require(args.mode != "directory" or
                (args.isolation == "gvisor" and not args.program_proof and not args.microvm_proof),
                "standalone DIRECTORY proof uses the basic rootless service, not VM actors")
        if args.isolation == "microvm":
            mapped_directory_proof(root, cfg)
        wait_healthy(cfg)
        hashes = {}
        for key in ["binary","helper"]:
            with open(cfg[key],"rb") as artifact:
                hashes[key] = hashlib.file_digest(artifact,"sha256").hexdigest()
        host = {"uname":list(os.uname()),"os_release":Path("/etc/os-release").read_text(),
                "systemd":command(["systemctl","--version"],10),
                "artifact_sha256":hashes}
        (root/"host.json").write_text(json.dumps(host,indent=2))
        if args.ubuntu_required:
            require('ID=ubuntu' in host["os_release"] and 'VERSION_ID="24.04"' in host["os_release"],
                    "an Ubuntu 24.04 kernel and userspace host is required; other userspace is not equivalent")
            require("Ubuntu" in os.uname().version,"an actual Ubuntu kernel is required, not only Ubuntu userspace")
            require(host["systemd"].split()[1] == "255", "actual systemd 255 proof required")
            require(Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y",
                    "an AppArmor-enabled Ubuntu host is required")
            require(Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip() == "1",
                    "Ubuntu restricted-userns AppArmor policy must actually be active")
        if args.mode == "check":
            audit(root,cfg)
        elif args.mode == "directory":
            mapped_directory_proof(root,cfg,directory_only=True)
        else:
            conformance(root,cfg,args.isolation)
            if args.program_proof:
                program_proof(root,cfg,args.isolation)
            elif args.microvm_proof:
                fresh_generation(root,cfg,"microvm-postgres")
                daemon = api_daemon(cfg)
                deploy_caller(daemon,root,cfg)
                postgres_proof(root,cfg,daemon,"microvm")
        result["status"] = "PASS"
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        (root/f"result-{args.mode}-{args.isolation}.json").write_text(json.dumps(result,indent=2))


if __name__ == "__main__":
    main()
