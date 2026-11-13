#!/usr/bin/env python3
"""M23 B6: the PKCS#11 master-key flow of ADR 0093 against SoftHSM2; see e2e-pkcs11.sh.

1. A SoftHSM token with a random label; in it an AES-256 key that is
   sensitive, not extractable and not modifiable (made through PKCS#11 itself,
   as pkcs11-tool cannot set CKA_MODIFIABLE), and a second, extractable key.
2. `kronik keys enroll` verifies the key through `kronik-keyhelper` and
   prints the probe; the extractable key is refused.
3. `kronik serve` on an empty data directory with `[keys] source = "pkcs11"`:
   the seed is made in memory and only its envelope is written. A secret is
   set and used by a turn; the daemon stops and starts again (the helper
   unwraps the seed) and the secret still works. `kronik keys rewrap`
   replaces the envelope with one that unwraps to the same seed.
4. The test learns the seed from outside the daemon: it runs the helper
   itself with the envelope's ciphertext, and proves the seed right by
   opening a copy of the data directory with it as an `env` key. It then
   searches the data directory, the configuration directory, the daemon's
   output and SoftHSM's token directory for the seed (raw, hex, base64), the
   PIN and the secret's value. None may match (the PIN file excepted).
5. A wrong PIN fails the start closed: no new envelope, no key file.
"""
import argparse
import base64
import contextlib
import ctypes
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets as random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
GUESTS = ROOT / "tests/guests"
TOKEN_DIR = Path("/var/lib/softhsm/tokens")
MODULE_CANDIDATES = ["/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/lib/softhsm/libsofthsm2.so"]
REASON = "M23 PKCS#11 acceptance"
GATEWAY = 47180


def command(*args, timeout=120, check=True, data=None, env=None, pass_fds=()):
    r = subprocess.run([str(a) for a in args], input=data, capture_output=True, timeout=timeout, env=env,
                       pass_fds=pass_fds)
    if check and r.returncode:
        raise AssertionError(f"{[str(a) for a in args[:4]]} exited {r.returncode}: "
                             f"{r.stdout[-2000:].decode(errors='replace')}{r.stderr[-2000:].decode(errors='replace')}")
    return r


def write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text if isinstance(text, bytes) else text.encode())
    path.chmod(mode)


def wait_for(description, predicate, seconds=120, step=0.2):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError, http.client.HTTPException, ValueError, KeyError):
            value = predicate()
            if value:
                return value
        time.sleep(step)
    raise AssertionError("timed out: " + description)


# ------------------------------------------------------------------ PKCS#11

CK_ULONG = ctypes.c_ulong
CKF_RW_SESSION, CKF_SERIAL_SESSION = 0x2, 0x4
CKU_USER = 1
CKM_AES_KEY_GEN, CKM_AES_GCM = 0x1080, 0x1087
CKO_SECRET_KEY, CKK_AES = 4, 0x1F
CKA = {"class": 0x0, "token": 0x1, "private": 0x2, "label": 0x3, "key_type": 0x100, "id": 0x102,
       "sensitive": 0x103, "encrypt": 0x104, "decrypt": 0x105, "wrap": 0x106, "unwrap": 0x107,
       "sign": 0x108, "verify": 0x10A, "value_len": 0x161, "extractable": 0x162, "modifiable": 0x170,
       "allowed_mechanisms": 0x40000600}


class Attribute(ctypes.Structure):
    _fields_ = [("type", CK_ULONG), ("value", ctypes.c_void_p), ("length", CK_ULONG)]


class Mechanism(ctypes.Structure):
    _fields_ = [("mechanism", CK_ULONG), ("parameter", ctypes.c_void_p), ("length", CK_ULONG)]


class Version(ctypes.Structure):
    _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]


class TokenInfo(ctypes.Structure):
    _fields_ = [("label", ctypes.c_char * 32), ("manufacturer", ctypes.c_char * 32), ("model", ctypes.c_char * 16),
                ("serial", ctypes.c_char * 16), ("flags", CK_ULONG)] + \
               [(name, CK_ULONG) for name in ("max_sessions", "sessions", "max_rw", "rw", "max_pin", "min_pin",
                                              "public_total", "public_free", "private_total", "private_free")] + \
               [("hardware", Version), ("firmware", Version), ("time", ctypes.c_char * 16)]


class Pkcs11:
    """The few PKCS#11 calls the setup needs, straight from the module."""

    def __init__(self, module):
        self.lib = ctypes.CDLL(module)
        self.call("C_Initialize", None)

    def call(self, name, *args):
        rv = getattr(self.lib, name)(*args)
        if rv != 0:
            raise AssertionError(f"{name} returned 0x{rv:x}")

    def token(self, label):
        count = CK_ULONG(0)
        self.call("C_GetSlotList", ctypes.c_ubyte(1), None, ctypes.byref(count))
        slots = (CK_ULONG * count.value)()
        self.call("C_GetSlotList", ctypes.c_ubyte(1), slots, ctypes.byref(count))
        found = []
        for slot in slots[:count.value]:
            info = TokenInfo()
            self.call("C_GetTokenInfo", CK_ULONG(slot), ctypes.byref(info))
            if info.label.decode().rstrip() == label:
                found.append((slot, info.manufacturer.decode().rstrip(), info.model.decode().rstrip(),
                              info.serial.decode().rstrip()))
        assert len(found) == 1, found
        return found[0]

    def generate(self, slot, pin, key_id, label, extractable):
        session = CK_ULONG()
        self.call("C_OpenSession", CK_ULONG(slot), CK_ULONG(CKF_SERIAL_SESSION | CKF_RW_SESSION), None, None,
                  ctypes.byref(session))
        self.call("C_Login", session, CK_ULONG(CKU_USER), pin, CK_ULONG(len(pin)))
        keep = []

        def value(data):
            buffer = ctypes.create_string_buffer(data, len(data))
            keep.append(buffer)
            return ctypes.cast(buffer, ctypes.c_void_p), len(data)

        def ulong(n):
            return value(bytes(CK_ULONG(n)))

        def flag(b):
            return value(bytes([1 if b else 0]))

        template = [("class", ulong(CKO_SECRET_KEY)), ("key_type", ulong(CKK_AES)), ("value_len", ulong(32)),
                    ("token", flag(True)), ("private", flag(True)), ("sensitive", flag(True)),
                    ("extractable", flag(extractable)), ("modifiable", flag(extractable)),
                    ("encrypt", flag(True)), ("decrypt", flag(True)), ("wrap", flag(False)),
                    ("unwrap", flag(False)), ("sign", flag(False)), ("verify", flag(False)),
                    ("id", value(key_id)), ("label", value(label.encode())),
                    ("allowed_mechanisms", ulong(CKM_AES_GCM))]
        attributes = (Attribute * len(template))(*[Attribute(CKA[name], pointer, length)
                                                   for name, (pointer, length) in template])
        handle = CK_ULONG()
        mechanism = Mechanism(CKM_AES_KEY_GEN, None, 0)
        self.call("C_GenerateKey", session, ctypes.byref(mechanism), attributes, CK_ULONG(len(template)),
                  ctypes.byref(handle))
        self.call("C_Logout", session)
        self.call("C_CloseSession", session)

    def close(self):
        self.call("C_Finalize", None)


# ------------------------------------------------------------------- daemon

class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=60):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class Daemon:
    def __init__(self, binary, config, data, socket_path, log, env):
        self.binary, self.config, self.data, self.socket, self.log = binary, config, data, socket_path, log
        self.env, self.process = env, None

    def start(self, expect_ok=True, seconds=120):
        output = self.log.open("ab")
        self.process = subprocess.Popen(
            [str(self.binary), "serve", "--config", str(self.config), "--http-listen", f"127.0.0.1:{GATEWAY}",
             "--api-socket", str(self.socket)], stdin=subprocess.DEVNULL, stdout=output, stderr=output,
            env=self.env)
        output.close()
        if not expect_ok:
            self.process.wait(timeout=seconds)
            return self.process.returncode

        def healthy():
            if self.process.poll() is not None:
                raise SystemExit("daemon exited: " + self.log.read_text(errors="replace")[-4000:])
            return self.api("GET", "/v1/health", status=None)[0] == 200
        wait_for("healthy", healthy, seconds)
        return 0

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def api(self, method, path, data=None, status=200):
        with contextlib.closing(UnixConnection(self.socket)) as conn:
            conn.request(method, path, body=None if data is None else json.dumps(data),
                         headers={"Content-Type": "application/json", "Host": "localhost"})
            response = conn.getresponse()
            raw = response.read()
            value = json.loads(raw) if raw.strip() else {}
            if status is None:
                return response.status, value
            assert response.status == status, (method, path, response.status, value)
            return value

    def mutate(self, method, path, data):
        def ok():
            status, value = self.api(method, path, data, status=None)
            if status == 200:
                return [value]
            assert status == 503 and value["error"]["code"] == "SECRET_UNAVAILABLE", (path, status, value)
            return None
        return wait_for(method + " " + path, ok)[0]

    def cli(self, *args):
        return command(self.binary, "--socket", self.socket, *args, env=self.env).stdout.decode()


def hmac_hex(key, data):
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()


def forms(raw):
    return [raw, raw.hex().encode(), raw.hex().upper().encode(), base64.b64encode(raw),
            base64.urlsafe_b64encode(raw).rstrip(b"=")]


def hits(paths, needles, skip=()):
    found = []
    for root in paths:
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and not p.is_socket()]
        for path in files:
            if path in skip:
                continue
            data = path.read_bytes()
            for name, values in needles.items():
                if any(v in data for v in values):
                    found.append(f"{name} in {path}")
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--dir", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0, "run as root: the token, the helper and the daemon share one user"
    module = next((m for m in MODULE_CANDIDATES if Path(m).is_file()), None)
    assert module, "install softhsm2 (Debian: apt-get install softhsm2 opensc)"
    module = str(Path(module).resolve())
    os.umask(0o077)
    root = args.dir.resolve() if args.dir else Path(tempfile.mkdtemp(prefix="kronik-m23-pkcs11.", dir="/var/tmp"))
    if args.dir:
        root.mkdir(mode=0o700)
    print("Artifacts:", root, flush=True)
    binary, helper_source = args.bin.resolve(), args.helper.resolve()
    # The helper is copied into a root-owned directory of this run.
    tools = root / "bin"
    tools.mkdir(mode=0o755)
    helper = tools / "kronik-keyhelper"
    shutil.copy2(helper_source, helper)
    helper.chmod(0o755)
    results = {"schema": "kronik.m23-pkcs11-acceptance/v1", "directory": str(root),
               "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "binary_version": command(binary, "--version").stdout.decode().strip(),
               "helper": str(helper_source), "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
               "module": module, "module_sha256": hashlib.sha256(Path(module).read_bytes()).hexdigest(),
               "packages": command("dpkg-query", "-W", "softhsm2", "opensc").stdout.decode().split("\n"),
               "checks": []}
    checks = results["checks"]
    label = "kronik-m23-" + random.token_hex(6)
    pin = random.token_hex(12)
    so_pin = random.token_hex(12)
    before = set(TOKEN_DIR.iterdir()) if TOKEN_DIR.exists() else set()
    token_dir = None
    daemon = None
    passed = False
    try:
        command("softhsm2-util", "--init-token", "--free", "--label", label, "--so-pin", so_pin, "--pin", pin)
        created = set(TOKEN_DIR.iterdir()) - before
        assert len(created) == 1, created
        token_dir = created.pop()
        p11 = Pkcs11(module)
        slot, manufacturer, model, serial = p11.token(label)
        key_id, bad_id = random.token_bytes(8), random.token_bytes(8)
        p11.generate(slot, pin.encode(), key_id, "kronik-master", extractable=False)
        p11.generate(slot, pin.encode(), bad_id, "kronik-extractable", extractable=True)
        p11.close()
        results["token"] = {"label": label, "manufacturer": manufacturer, "model": model, "serial": serial,
                            "key_id": key_id.hex()}
        checks.append("token and keys made through PKCS#11: AES-256, sensitive, not extractable, not modifiable, "
                      "AES-GCM only; a second, extractable and modifiable key")

        config_dir = root / "etc"
        config_dir.mkdir(mode=0o700)
        pin_file = config_dir / "pin"
        write(pin_file, pin)
        data = root / "data"
        sock = root / "api.sock"
        config = config_dir / "kronik.toml"

        def write_config(key, probe=None, timeout="15s"):
            text = (f'[server]\ndata_dir = "{data}"\n\n[log]\ndisk_reserve = "0B"\n\n'
                    f'[foreign]\nrun_dir = "{root / "foreign-run"}"\n\n'
                    f'[keys]\nsource = "pkcs11"\nstart_timeout = "{timeout}"\n\n[keys.pkcs11]\n'
                    f'helper_path = "{helper}"\nmodule = "{module}"\nmodule_sha256 = "{results["module_sha256"]}"\n'
                    f'pin_file = "{pin_file}"\nmanufacturer = "{manufacturer}"\nmodel = "{model}"\n'
                    f'serial = "{serial}"\nkey_id = "{key.hex()}"\nkey_version = "1"\n')
            if probe:
                text += f'\n[keys.pkcs11.probe]\nnonce = "{probe["nonce"]}"\nciphertext = "{probe["ciphertext"]}"\n'
            write(config, text)

        env = {k: v for k, v in os.environ.items() if not k.startswith("KRONIK_")}
        env["KRONIK_LOG"] = "info"
        # The extractable key is refused by the helper.
        write_config(bad_id)
        refused = command(binary, "keys", "enroll", "--config", config, "--json", check=False, env=env)
        assert refused.returncode != 0 and b"nonce" not in refused.stdout, refused
        results["refused_enrollment"] = (refused.stdout + refused.stderr).decode(errors="replace")[-600:]
        checks.append("keys enroll refuses the extractable, modifiable key")
        write_config(key_id)
        enrolled = command(binary, "keys", "enroll", "--config", config, "--json", env=env)
        probe = json.loads(enrolled.stdout)
        assert set(probe) == {"nonce", "ciphertext"}, probe
        write_config(key_id, probe)
        checks.append("keys enroll verifies the key through the helper and prints the probe")

        daemon = Daemon(binary, config, data, sock, root / "serve.log", env)
        daemon.start()
        keys = data / "keys"
        wrapped_path = keys / "master.wrapped"
        wrapped = json.loads(wrapped_path.read_text())
        assert wrapped["source"] == "pkcs11" and wrapped["schema"] == "kronik.wrapped-key/v1", wrapped
        assert not (keys / "master.key").exists(), sorted(p.name for p in keys.iterdir())
        status = daemon.api("GET", "/v1/keys")
        assert status["source"] == "pkcs11" and status["check_ok"] is True, status
        value = "pkcs11-needle-" + random.token_hex(12)
        daemon.mutate("PUT", "/v1/secrets/signing", {"text": value, "reason": REASON})
        wasm = base64.b64encode((GUESTS / "counter.wasm").read_bytes()).decode()
        daemon.mutate("POST", "/v1/deployments", {"wasm_base64": wasm, "reason": REASON})
        daemon.mutate("POST", "/v1/grants", {"kind": "counter", "capability": "secret:signing", "reason": REASON})
        turn = daemon.api("POST", "/v1/actors/counter/h/messages",
                          {"name": "hmac", "text": "signing\npayload", "reason": REASON})
        assert turn["reply"]["text"] == hmac_hex(value, "payload"), turn
        checks.append("a fresh start with [keys] source = \"pkcs11\" writes only master.wrapped (no master.key); "
                      "keys status: pkcs11, check ok; a secret is set and a turn's HMAC uses it")

        daemon.stop()
        daemon.start()
        again = daemon.api("POST", "/v1/actors/counter/h/messages",
                           {"name": "hmac", "text": "signing\npayload", "reason": REASON})
        assert again["reply"]["text"] == turn["reply"]["text"], again
        history = daemon.cli("history", "counter/h")
        assert "secret:signing@v1" in history, history
        checks.append("a restart unwraps the seed through the helper: the secret decrypts and the history reads")

        envelope = wrapped_path.read_bytes()
        daemon.cli("keys", "rewrap", "--reason", REASON)
        rewrapped = wrapped_path.read_bytes()
        assert rewrapped != envelope, "rewrap left the envelope as it was"
        daemon.stop()
        daemon.start()
        third = daemon.api("POST", "/v1/actors/counter/h/messages",
                           {"name": "hmac", "text": "signing\npayload", "reason": REASON})
        assert third["reply"]["text"] == turn["reply"]["text"], third
        daemon.stop()
        checks.append("keys rewrap replaces the envelope (a new nonce); a restart unwraps the new one")

        # The seed, learned outside the daemon: the helper unwraps the envelope.
        payload = json.loads(base64.b64decode(json.loads(rewrapped)["ciphertext"]))
        request = {"schema": "kronik.pkcs11/v1", "op": "unwrap", "module": module,
                   "module_sha256": results["module_sha256"], "manufacturer": manufacturer, "model": model,
                   "serial": serial, "key_id": key_id.hex(), "key_version": "1", "purpose": "kronik master v1",
                   "nonce": payload["nonce"], "ciphertext": payload["ciphertext"]}
        fd = os.open(pin_file, os.O_RDONLY)
        try:
            if fd != 3:
                os.dup2(fd, 3)
                os.close(fd)
            answer = subprocess.run([str(helper)], input=json.dumps(request).encode(), capture_output=True,
                                    env={}, pass_fds=(3,), timeout=30)
        finally:
            with contextlib.suppress(OSError):
                os.close(3)
        reply = json.loads(answer.stdout)
        assert reply.get("ok") is True and len(reply.get("plaintext", "")) == 64, {k: v for k, v in reply.items()
                                                                                     if k != "plaintext"}
        seed = bytes.fromhex(reply["plaintext"])
        # Proof that it is the seed: a copy of the data directory opens with it.
        copy = root / "copy"
        shutil.copytree(data, copy / "data", symlinks=True)
        (copy / "data/keys/master.wrapped").unlink()
        write(copy / "kronik.toml", f'[server]\ndata_dir = "{copy / "data"}"\n\n[log]\ndisk_reserve = "0B"\n\n'
                                    f'[foreign]\nrun_dir = "{copy / "foreign-run"}"\n')
        proof = Daemon(binary, copy / "kronik.toml", copy / "data", copy / "api.sock", copy / "serve.log",
                       {**env, "KRONIK_MASTER_KEY": seed.hex()})
        proof.start()
        checked = proof.api("POST", "/v1/actors/counter/h/messages",
                            {"name": "hmac", "text": "signing\npayload", "reason": REASON})
        proof.stop()
        assert checked["reply"]["text"] == turn["reply"]["text"], checked
        shutil.rmtree(copy)
        checks.append("the seed learned by running the helper on the envelope opens a copy of the data directory as "
                      "an env key (the same HMAC)")

        needles = {"the seed": forms(seed), "the PIN": [pin.encode()], "the secret": [value.encode()]}
        found = hits([data, config_dir, token_dir, root / "serve.log"], needles, skip={pin_file})
        assert not found, found
        checks.append("needle: neither the seed (raw, hex, base64), the PIN nor the secret's value is in the data "
                      "directory, the configuration directory (the PIN file excepted), the daemon's output or "
                      "SoftHSM's token directory")

        # A wrong PIN fails the start closed.
        before_files = sorted(p.name for p in keys.iterdir())
        write(pin_file, "0" * len(pin))
        write_config(key_id, probe, timeout="3s")
        code = daemon.start(expect_ok=False, seconds=120)
        assert code != 0, "the daemon started with a wrong PIN"
        assert wrapped_path.read_bytes() == rewrapped and sorted(p.name for p in keys.iterdir()) == before_files
        tail = (root / "serve.log").read_text(errors="replace")[-3000:]
        results["wrong_pin"] = {"exit": code, "codes": sorted({c for c in ("KEY_SOURCE_UNAVAILABLE",
                                                                          "KEY_HELPER_FAILED") if c in tail})}
        assert results["wrong_pin"]["codes"], tail
        write(pin_file, pin)
        daemon.start()
        last = daemon.api("POST", "/v1/actors/counter/h/messages",
                          {"name": "hmac", "text": "signing\npayload", "reason": REASON})
        assert last["reply"]["text"] == turn["reply"]["text"], last
        daemon.stop()
        checks.append("a wrong PIN fails the start closed (" + ", ".join(results["wrong_pin"]["codes"]) +
                      "): no new envelope or key file; the right PIN starts again")
        passed = True
    except BaseException as error:  # noqa: BLE001 - every failure is evidence
        results["error"] = repr(error)[:4000]
        raise
    finally:
        if daemon:
            daemon.stop()
        if token_dir is not None:
            deleted = command("softhsm2-util", "--delete-token", "--token", label, check=False)
            results["token_deleted"] = deleted.returncode == 0 and not token_dir.exists()
        results["passed"] = passed and results.get("token_deleted", False)
        write(root / "results.json", json.dumps(results, indent=2, sort_keys=True) + "\n", 0o644)
        print("Evidence:", root / "results.json", flush=True)
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    sys.exit(main())
