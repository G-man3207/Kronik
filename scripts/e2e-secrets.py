#!/usr/bin/env python3
"""M23 B4/B5: the external-secret criteria against real services; see e2e-secrets.sh.

For each service, a real `kronik serve` links the name `stripe` to a reference
in the service and runs criteria 2 and 3 of docs/design/m23-secret-backends.md
section 9 and the outages:

- criterion 2: an HMAC turn uses version 1; the log (read here from the segment
  files, not through the API) has its SecretVersion with the hash, the
  backend and the service's own version id, and the effect's SecretRef names
  the same version and hash; a `file` node with the same master key computes
  the same hash for the same value; neither value is in a file of the data
  directory, the configuration, the daemon's log, nor in an answer of the
  API, the CLI or MCP;
- criterion 3: a new version in the service and `secret refresh` give
  version 2 in `secret history` and in the log; the new turn shows
  `secret:stripe@v2`, the old one `@v1`; a fork from before the rotation
  replays the old turns identically while the service is paused, so the fork
  asks it nothing; the crash re-run of a recorded `secret.reveal` waits while
  the service is down and then gets the recorded version's value, not the
  current one; once the service destroyed a recorded version, the crash
  re-run fails the turn with SECRET_VERSION_GONE and sends nothing;
- outages: with the service down (stopped, sealed or paused), turns that need
  no secret commit within a moment, a turn with a cached secret uses it, a
  turn whose secret is not cached fails within `[secrets] fetch_timeout` with
  SECRET_UNAVAILABLE and leaves no open TurnBegin, and the secret works again
  once the service is back.

Only this run's containers and files are touched. The evidence, with the
images' digests, is written to results.json in the run directory.
"""
import argparse
import base64
import contextlib
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import secrets as random
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
GUESTS = ROOT / "tests/guests"

# Every image by digest. The first three are the ones scripts/e2e-keys.py pins
# for the KMS lifecycle (B1); the GCP Secret Manager emulator is its own.
IMAGES = {
    "openbao": "openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f",
    "aws": "motoserver/moto@sha256:59a1965d845249b04def37a0e2565f9cc6c44543cb89b68e90f28f344b3b0d1a",
    "gcp": "ghcr.io/blackwell-systems/gcp-secret-manager-emulator-dual@sha256:2c9d3bb0453fdff102b29af00b4abd9b2c6fa466031a9d8e6d93a270ba22a6e2",
    "azure": "ghcr.io/rokeller/azure-keyvault-emulator@sha256:126d8433d11f4983dba5337352311bcf9278a566b415b0cbfd5eea2b7d8e9d88",
}
PROVIDERS = ["openbao", "openbao-approle", "aws", "gcp", "azure"]
# Host ports, all on 127.0.0.1 and in 47100-47199.
PORTS = {"openbao": 47110, "openbao-approle": 47111, "aws": 47120, "gcp": 47130, "azure": 47140}
# The loopback shim in front of moto (see MotoShim).
MOTO_SHIM_PORT = 47122
TARGET_PORT = 47150
AUTH_PORT = 47160
GATEWAY_PORTS = (47170, 47171)
MASTER_KEY = "5a" * 32
REASON = "M23 external secret acceptance"
TOKEN = "m23-disposable-token-only"
# A well-formed JWT: the Azure emulator checks the syntax only.
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjQxMDI0NDQ4MDAsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9."
       "42D_zJ3qM02NM_ExWU9S9jvNGMfpop3YuWT9lFqJ5yU")
FETCH_TIMEOUT = 2.0
OWNED = set()
CREATED = set()
DAEMONS = []


# ----------------------------------------------------------------- helpers

def command(*args, timeout=120, check=True, data=None, env=None):
    r = subprocess.run([str(a) for a in args], input=data, capture_output=True, timeout=timeout, env=env)
    if check and r.returncode:
        raise AssertionError(f"{[str(a) for a in args[:4]]} exited {r.returncode}: "
                             f"{r.stdout[-2000:].decode(errors='replace')}{r.stderr[-2000:].decode(errors='replace')}")
    return r


def write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text)
    path.chmod(mode)


def wait_for(description, predicate, seconds=90, step=0.1):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
        except (OSError, http.client.HTTPException, AssertionError, KeyError, ValueError) as error:
            last = None
            failure = error
        else:
            failure = None
        if last:
            return last
        time.sleep(step)
    raise AssertionError(f"timed out: {description}" + (f" ({failure})" if failure else ""))


def hmac_hex(key, data):
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()


def listening(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def image(ref):
    info = command("docker", "image", "inspect", ref, check=False)
    if info.returncode:
        command("docker", "pull", ref, timeout=600)
        info = command("docker", "image", "inspect", ref)
    info = json.loads(info.stdout)[0]
    return {"requested": ref, "id": info["Id"], "repo_digests": info.get("RepoDigests", []),
            "created": info.get("Created")}


def docker_run(name, ref, ports, args=(), extra=(), memory="512m"):
    publish = [v for host, inner in ports for v in ("--publish", f"127.0.0.1:{host}:{inner}")]
    # Owned before it runs: a container that fails to start is removed too.
    OWNED.add(name)
    CREATED.add(name)
    for attempt in range(6):
        r = command("docker", "run", "--detach", "--name", name,
                    "--label", "kronik.m23.secrets=" + name,
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--pids-limit", "256", "--memory", memory, "--memory-swap", memory, "--cpus", "1",
                    "--log-opt", "max-size=4m", "--log-opt", "max-file=1",
                    *publish, *extra, ref, *args, check=False)
        if r.returncode == 0:
            return
        # The fixed ports lie in the kernel's ephemeral range: a local
        # connection may hold one for a moment. Try again.
        command("docker", "rm", "--force", name, check=False)
        if b"address already in use" not in r.stderr or attempt == 5:
            raise AssertionError(f"docker run {name}: {r.stderr[-1500:].decode(errors='replace')}")
        time.sleep(2)


def remove(name, logs):
    if name in OWNED:
        command("docker", "unpause", name, check=False)
        r = command("docker", "logs", name, check=False)
        logs.write_bytes(r.stdout + r.stderr)
        command("docker", "rm", "--force", "--volumes", name)
        OWNED.remove(name)


def rsa_key(path):
    command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", path)
    path.chmod(0o600)


def tls_fixtures(root):
    """A disposable CA and a server leaf for 127.0.0.1 and localhost."""
    root.mkdir(mode=0o755)
    rsa_key(root / "ca.key")
    command("openssl", "req", "-x509", "-new", "-key", root / "ca.key", "-days", "2",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-subj", "/CN=Kronik disposable test CA", "-out", root / "ca.pem")
    rsa_key(root / "server.key")
    command("openssl", "req", "-new", "-key", root / "server.key", "-subj", "/CN=kronik-m23-server",
            "-out", root / "server.csr")
    write(root / "server.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
          "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n")
    command("openssl", "x509", "-req", "-in", root / "server.csr", "-CA", root / "ca.pem",
            "-CAkey", root / "ca.key", "-CAcreateserial", "-days", "2",
            "-extfile", root / "server.ext", "-out", root / "server.pem")
    for name in ("server.key", "server.pem", "ca.pem"):
        (root / name).chmod(0o644)


def request(url, data=None, headers=None, tls=None, status=200, method=None, raw=None):
    body = raw if raw is not None else (None if data is None else json.dumps(data).encode())
    req = urllib.request.Request(url, body, {"Content-Type": "application/json", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10, context=tls) as r:
            code, text = r.status, r.read(1 << 20)
    except urllib.error.HTTPError as e:
        code, text = e.code, e.read(1 << 20)
    accepted = (status,) if isinstance(status, int) else status
    assert code in accepted, (url, code, text[:600])
    return json.loads(text) if text.strip() else {}


# ------------------------------------------------------------ the log reader

def _crc32c_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


CRC_TABLE = _crc32c_table()


def crc32c(data):
    c = 0xFFFFFFFF
    for b in data:
        c = CRC_TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def varint(buf, i):
    shift = value = 0
    while True:
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, i
        shift += 7


def fields(buf):
    """Protobuf wire fields: {number: [values]}; bytes for length-delimited."""
    out, i = {}, 0
    while i < len(buf):
        key, i = varint(buf, i)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, i = varint(buf, i)
        elif wire == 2:
            n, i = varint(buf, i)
            value, i = bytes(buf[i:i + n]), i + n
        elif wire == 1:
            value, i = int.from_bytes(buf[i:i + 8], "little"), i + 8
        elif wire == 5:
            value, i = int.from_bytes(buf[i:i + 4], "little"), i + 4
        else:
            raise ValueError(f"wire type {wire}")
        out.setdefault(number, []).append(value)
    return out


def one(f, number, default=None):
    return f.get(number, [default])[-1]


def text(f, number):
    return one(f, number, b"").decode()


def log_records(data_dir):
    """(lsn, kind, fields) of every intact entry of main's log, in order."""
    records = []
    log = data_dir / "branches/main/log"
    for segment in sorted(log.glob("*.seg")):
        image_ = segment.read_bytes()
        assert image_[:4] == b"KRNK", segment
        branch_len = int.from_bytes(image_[16:20], "little")
        off = 20 + branch_len + 4
        while off + 17 <= len(image_):
            length = int.from_bytes(image_[off:off + 4], "little")
            crc = int.from_bytes(image_[off + 4:off + 8], "little")
            end = off + 17 + length
            body = image_[off + 8:end]
            if end > len(image_) or crc32c(body) != crc:
                break  # a torn tail of the active segment
            lsn = int.from_bytes(body[:8], "little")
            kind = body[8]
            if kind != 255:
                records.append((lsn, kind, fields(body[9:])))
            off = end
    return records


SECRET_VERSION, SECRET_LINK, TURN_BEGIN, TURN_RECORD = 45, 46, 1, 3


def secret_versions(records, name):
    """The active, not deleted SecretVersion records of `name`."""
    out = []
    for _, kind, f in records:
        if kind == SECRET_VERSION and text(f, 1) == name and one(f, 12, 0) == 2 and not one(f, 6, 0):
            out.append({"version": one(f, 2, 0), "hash": one(f, 3, b"").hex(), "backend": text(f, 4),
                        "source_version": text(f, 5), "ref": text(f, 8), "canonical_ref": text(f, 11)})
    return out


def allocations(records, name):
    """Every (version, phase, source_version) a SecretVersion record of `name` holds."""
    return [(one(f, 2, 0), one(f, 12, 0), text(f, 5)) for _, kind, f in records
            if kind == SECRET_VERSION and text(f, 1) == name]


def turns(records):
    """Every TurnRecord: actor, input message name, outcome and effects."""
    out = []
    for lsn, kind, f in records:
        if kind != TURN_RECORD:
            continue
        actor = fields(one(f, 3, b""))
        name = ""
        input_ = fields(one(f, 9, b""))
        if 2 in input_:  # Input.message: MessageInput.msg (3), Message.name (1)
            message = fields(input_[2][-1])
            msg = fields(one(message, 3, b""))
            name = text(msg, 1)
        outcome = fields(one(f, 14, b""))
        effects = []
        for raw in f.get(10, []):
            e = fields(raw)
            request = fields(one(e, 4, b""))
            plain = one(request, 2)
            secret = None
            if plain is not None and text(e, 2) in ("crypto.hmac-sha256", "crypto.sign-ed25519"):
                secret = fields(one(fields(plain), 2, b""))
            elif plain is not None and text(e, 2) == "secret.reveal":
                secret = fields(one(fields(plain), 1, b""))
            effects.append({
                "kind": text(e, 2), "status": one(e, 9, 0), "error": text(e, 12),
                "secret": None if secret is None else {
                    "name": text(secret, 1), "version": one(secret, 3, 0) or one(secret, 5, 0),
                    "hash": one(secret, 4, b"").hex()},
            })
        out.append({"lsn": lsn, "execution_id": text(f, 2), "actor": f"{text(actor, 1)}/{text(actor, 2)}",
                    "message": name, "outcome": one(outcome, 1, 0), "error_code": text(outcome, 2),
                    "outcome_message": text(outcome, 3), "effects": effects})
    return out


def open_turns(records):
    begun = {}
    for lsn, kind, f in records:
        if kind == TURN_BEGIN:
            begun[text(f, 1)] = lsn
        elif kind == TURN_RECORD:
            begun.pop(text(f, 2), None)
    return sorted(begun.values())


COMMITTED, FAILED = 1, 3
OK, DENIED = 1, 2


# ------------------------------------------------------------ host fixtures

class Target(http.server.ThreadingHTTPServer):
    """The fetches of the leaky guest: /hang... answers once released."""
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", TARGET_PORT), TargetHandler)
        self.lock = threading.Condition()
        self.seen = []
        self.released = False
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def hold(self):
        with self.lock:
            self.released = False

    def release(self):
        with self.lock:
            self.released = True
            self.lock.notify_all()

    def requests(self):
        with self.lock:
            return list(self.seen)

    def close(self):
        self.release()
        self.shutdown()
        self.server_close()


class TargetHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        server = self.server
        with server.lock:
            server.seen.append({"path": self.path, "headers": dict(self.headers), "body": body.decode(errors="replace")})
            server.lock.notify_all()
            deadline = time.monotonic() + 300
            while self.path.startswith("/hang") and not server.released and time.monotonic() < deadline:
                server.lock.wait(1)
        reply = b'{"ok":true}'
        with contextlib.suppress(OSError):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)


class AuthFixture(http.server.ThreadingHTTPServer):
    """Loopback OAuth for GCP (RS256 JWT, verified) and Azure (client credentials)."""
    daemon_threads = True

    def __init__(self, root):
        self.root, self.counts = root, {}
        rsa_key(root / "oauth.key")
        command("openssl", "pkey", "-in", root / "oauth.key", "-pubout", "-out", root / "oauth.pub")
        super().__init__(("127.0.0.1", AUTH_PORT), AuthHandler)
        self.base = f"http://127.0.0.1:{AUTH_PORT}"
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def counted(self, name):
        self.counts[name] = self.counts.get(name, 0) + 1

    def close(self):
        self.shutdown()
        self.server_close()


class AuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, value, status=200):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            assert 0 < length < 32768
            form = urllib.parse.parse_qs(self.rfile.read(length).decode(), strict_parsing=True)
            if self.path == "/gcp-token":
                assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
                parts = form["assertion"][0].split(".")
                assert len(parts) == 3
                decode = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
                assert json.loads(decode(parts[0])) == {"alg": "RS256", "typ": "JWT"}
                claims = json.loads(decode(parts[1]))
                assert claims["iss"] == "kronik@m23.invalid"
                assert claims["scope"] == "https://www.googleapis.com/auth/cloud-platform", claims
                assert claims["aud"] == self.server.base + "/gcp-token"
                assert abs(claims["iat"] - time.time()) < 60 and claims["exp"] == claims["iat"] + 3600
                with tempfile.NamedTemporaryFile(dir=self.server.root, prefix="jwt-signature-") as sig:
                    sig.write(decode(parts[2]))
                    sig.flush()
                    verified = command("openssl", "dgst", "-sha256", "-verify", self.server.root / "oauth.pub",
                                       "-signature", sig.name, data=(parts[0] + "." + parts[1]).encode(), check=False)
                    assert verified.returncode == 0, "the RS256 signature is invalid"
                self.server.counted("gcp_rs256_verified")
                self.send({"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600})
            else:
                assert self.path == "/m23-tenant/oauth2/v2.0/token"
                assert form == {"grant_type": ["client_credentials"], "client_id": ["m23-client"],
                                "client_secret": [TOKEN], "scope": ["https://vault.azure.net/.default"]}
                self.server.counted("azure_client_credentials")
                self.send({"access_token": JWT, "token_type": "Bearer", "expires_in": 3600})
        except (AssertionError, KeyError, ValueError):
            self.server.counted("rejected")
            self.send({"error": "invalid_client"}, 401)


# ---------------------------------------------------------------- services

class Service:
    """One secret service in a container, and the reference Kronik links."""
    name = None

    def __init__(self, root, tag):
        self.root, self.container = root, tag + "-" + self.name
        self.port = PORTS[self.name]
        self.evidence = {"image": image(IMAGES[self.image_name])}
        root.mkdir(mode=0o700)
        self.versions = []  # the service's own id of each value written, in order

    image_name = property(lambda self: self.name)

    def outage(self, mode):
        """Takes the service down: `pause` hangs every request, `stop` stops it."""
        if mode == "pause":
            command("docker", "pause", self.container)
        else:
            command("docker", "stop", "--time", "5", self.container)

    def recover(self, mode):
        if mode == "pause":
            command("docker", "unpause", self.container)
        else:
            command("docker", "start", self.container)
            wait_for(self.name + " listening again", lambda: listening(self.port), 60)

    def outage_modes(self):
        return ["pause"]

    def close(self):
        remove(self.container, self.root / "service.log")


class OpenBao(Service):
    """OpenBao with file storage behind TLS: a stopped and started server is sealed until unsealed."""
    name = "openbao"
    image_name = "openbao"
    auth = "token"

    def __init__(self, root, tag):
        super().__init__(root, tag)
        tls_fixtures(root / "certs")
        (root / "storage").mkdir(mode=0o777)
        (root / "storage").chmod(0o777)
        # Integrated (raft) storage on a bind mount: a stopped and started
        # server keeps its data and comes back sealed.
        write(root / "certs/bao.json", json.dumps({
            "storage": {"raft": {"path": "/bao/storage", "node_id": "kronik-m23"}},
            "listener": {"tcp": {"address": "0.0.0.0:8200", "tls_cert_file": "/certs/server.pem",
                                 "tls_key_file": "/certs/server.key"}},
            "api_addr": "https://127.0.0.1:8200", "cluster_addr": "https://127.0.0.1:8201"}), mode=0o644)
        docker_run(self.container, IMAGES["openbao"], [(self.port, 8200)],
                   ["server", "-config=/certs/bao.json"],
                   ["--user", "0:0", "--entrypoint", "bao", "--env", "BAO_DISABLE_MLOCK=true",
                    "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=64m",
                    "--mount", f"type=bind,source={root / 'certs'},target=/certs,readonly",
                    "--mount", f"type=bind,source={root / 'storage'},target=/bao/storage"])
        self.base = f"https://127.0.0.1:{self.port}"
        self.tls = ssl.create_default_context(cafile=str(root / "certs/ca.pem"))
        wait_for("OpenBao listening", lambda: listening(self.port), 60)
        wait_for("OpenBao answering", lambda: request(self.base + "/v1/sys/seal-status", tls=self.tls), 60, 0.5)
        init = request(self.base + "/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1}, tls=self.tls)
        self.unseal_key = init["keys_base64"][0]
        self.unseal()
        self.headers = {"X-Vault-Token": init["root_token"]}
        self.call("/v1/sys/mounts/secret", {"type": "kv", "options": {"version": "2"}}, status=(200, 204))
        policy = ('path "secret/data/payments/*" { capabilities = ["read"] }\n'
                  'path "secret/metadata/payments/*" { capabilities = ["read", "list"] }\n')
        self.call("/v1/sys/policies/acl/kronik-secrets", {"policy": policy}, status=(200, 204))
        if self.auth == "token":
            minted = self.call("/v1/auth/token/create",
                               {"policies": ["kronik-secrets"], "ttl": "2h", "renewable": True})
            write(root / "token", minted["auth"]["client_token"])
        else:
            self.call("/v1/sys/auth/approle", {"type": "approle"}, status=(200, 204))
            self.call("/v1/auth/approle/role/kronik", {"token_policies": ["kronik-secrets"], "token_ttl": "1h",
                                                       "token_max_ttl": "4h"}, status=(200, 204))
            write(root / "role-id", self.call("/v1/auth/approle/role/kronik/role-id")["data"]["role_id"])
            write(root / "secret-id", self.call("/v1/auth/approle/role/kronik/secret-id", {})["data"]["secret_id"])
        # A token that is not allowed to read: the policy is the reference's.
        denied = self.call("/v1/auth/token/create", {"policies": ["default"], "ttl": "1h"})
        request(self.base + "/v1/secret/data/payments/stripe", headers={"X-Vault-Token": denied["auth"]["client_token"]},
                tls=self.tls, status=(403, 404))
        self.ref = "secret/payments/stripe#key"
        self.evidence["checks"] = ["TLS with a disposable CA", "KV v2 mount", f"{self.auth} authentication",
                                   "policy limited to secret/payments/*"]

    def unseal(self):
        request(self.base + "/v1/sys/unseal", {"key": self.unseal_key}, tls=self.tls)
        # Integrated storage elects its leader after the unseal; 200 is active.
        wait_for("OpenBao active", lambda: request(self.base + "/v1/sys/health", tls=self.tls,
                                                   status=(200, 429, 503)) and
                 urllib.request.urlopen(self.base + "/v1/sys/health", timeout=5, context=self.tls).status == 200,
                 60, 0.25)

    def call(self, path, data=None, status=200, method=None):
        return request(self.base + path, data, self.headers, self.tls, status, method)

    def put(self, value):
        r = self.call("/v1/secret/data/payments/stripe", {"data": {"key": value}})
        self.versions.append(str(r["data"]["version"]))
        return self.versions[-1]

    def destroy(self, version):
        self.call("/v1/secret/destroy/payments/stripe", {"versions": [int(version)]}, status=(200, 204))
        r = request(self.base + "/v1/secret/data/payments/stripe?version=" + version, headers=self.headers,
                    tls=self.tls, status=404)
        assert r["data"]["metadata"]["destroyed"] is True, r
        return "kv destroy of the version: reading it answers 404 with destroyed=true"

    def backend(self):
        config = {"type": "openbao", "address": self.base, "allowed_refs": ["secret/payments/"],
                  "ca_file": str(self.root / "certs/ca.pem")}
        if self.auth == "token":
            config.update({"auth": "token", "token_file": str(self.root / "token")})
        else:
            config.update({"auth": "approle", "role_id_file": str(self.root / "role-id"),
                           "secret_id_file": str(self.root / "secret-id")})
        return config

    def outage_modes(self):
        return ["stop", "pause"]

    def recover(self, mode):
        super().recover(mode)
        if mode == "stop":
            # Sealed after a restart: the daemon's requests get 503 until now.
            time.sleep(1)
            self.unseal()


class OpenBaoAppRole(OpenBao):
    name = "openbao-approle"
    auth = "approle"


class MotoShim(http.server.ThreadingHTTPServer):
    """Passes Kronik's requests to moto unchanged, with one correction.

    moto 5.2.5 answers ListSecretVersionIds with the secret's *name* in its
    `ARN` field (Secrets Manager answers the ARN). Kronik checks that a page
    names the secret it asked for, so the shim puts back the ARN, which it
    reads from moto's own DescribeSecret. Nothing else is changed, and every
    correction is counted in the evidence.
    """
    daemon_threads = True

    def __init__(self, upstream):
        self.upstream, self.corrected = upstream, 0
        super().__init__(("127.0.0.1", MOTO_SHIM_PORT), MotoShimHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()


class MotoShimHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")}
        target = self.headers.get("X-Amz-Target", "")
        try:
            req = urllib.request.Request(self.server.upstream + "/", body, headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    status, answer = r.status, r.read()
            except urllib.error.HTTPError as e:
                status, answer = e.code, e.read()
            if status == 200 and target == "secretsmanager.ListSecretVersionIds":
                page = json.loads(answer)
                if not page.get("ARN", "").startswith("arn:"):
                    describe = urllib.request.Request(self.server.upstream + "/", json.dumps(
                        {"SecretId": page["Name"]}).encode(), {**headers, "X-Amz-Target": "secretsmanager.DescribeSecret"},
                        method="POST")
                    with urllib.request.urlopen(describe, timeout=60) as r:
                        page["ARN"] = json.loads(r.read())["ARN"]
                    self.server.corrected += 1
                    answer = json.dumps(page).encode()
        except OSError:
            self.close_connection = True
            return
        with contextlib.suppress(OSError):
            self.send_response(status)
            self.send_header("Content-Type", "application/x-amz-json-1.1")
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)


class Aws(Service):
    """moto's Secrets Manager; a JSON field of a SecretString."""
    name = "aws"

    def __init__(self, root, tag):
        super().__init__(root, tag)
        docker_run(self.container, IMAGES["aws"], [(self.port, 5000)])
        self.base = f"http://127.0.0.1:{self.port}"
        wait_for("moto listening", lambda: listening(self.port), 60)
        wait_for("moto answering", lambda: self.sm("ListSecrets", {}), 60, 0.5)
        self.shim = MotoShim(self.base)
        self.ref = "payments/stripe#key"
        self.arn = None
        self.evidence["checks"] = ["SigV4 requests (moto does not verify signatures)",
                                   "JSON field of a SecretString",
                                   "shim: moto 5.2.5 answers ListSecretVersionIds with the name in ARN; "
                                   "the ARN from DescribeSecret is put back, nothing else is changed"]

    def close(self):
        self.evidence["shim_corrections"] = self.shim.corrected
        self.shim.close()
        super().close()

    def sm(self, operation, body, status=200):
        return request(self.base + "/", body, {
            "X-Amz-Target": "secretsmanager." + operation,
            "Content-Type": "application/x-amz-json-1.1",
            "Authorization": "AWS4-HMAC-SHA256 Credential=test/20261113/us-east-1/secretsmanager/aws4_request, "
                             "SignedHeaders=host, Signature=test"}, status=status)

    def put(self, value):
        secret = json.dumps({"key": value, "other": "not-this-field"})
        if self.arn is None:
            r = self.sm("CreateSecret", {"Name": "payments/stripe", "SecretString": secret})
            self.arn = r["ARN"]
        else:
            r = self.sm("PutSecretValue", {"SecretId": "payments/stripe", "SecretString": secret})
        self.versions.append(r["VersionId"])
        return self.versions[-1]

    def destroy(self, version):
        # Secrets Manager destroys no single version: deleting the secret
        # without recovery is what removes a version for good.
        self.sm("DeleteSecret", {"SecretId": "payments/stripe", "ForceDeleteWithoutRecovery": True})
        self.sm("GetSecretValue", {"SecretId": "payments/stripe", "VersionId": version}, status=(400, 404))
        return "DeleteSecret without recovery: GetSecretValue of the version answers ResourceNotFoundException"

    def backend(self):
        return {"type": "aws", "region": "us-east-1", "endpoint": f"http://127.0.0.1:{MOTO_SHIM_PORT}",
                "auth": "env", "allowed_refs": ["payments/"]}

    def daemon_env(self):
        return {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test", "AWS_REGION": "us-east-1"}


class Gcp(Service):
    """The Blackwell Systems Secret Manager emulator (REST), a service-account JWT for the token."""
    name = "gcp"

    def __init__(self, root, tag, auth):
        super().__init__(root, tag)
        docker_run(self.container, IMAGES["gcp"], [(self.port, 8080)])
        self.base = f"http://127.0.0.1:{self.port}"
        self.project = "123456789012"
        self.secret = f"projects/{self.project}/secrets/payments-stripe"
        wait_for("emulator listening", lambda: listening(self.port), 60)
        wait_for("emulator answering", lambda: request(f"{self.base}/v1/projects/{self.project}/secrets",
                                                       status=(200, 404)) is not None, 60, 0.5)
        request(f"{self.base}/v1/projects/{self.project}/secrets?secretId=payments-stripe",
                {"replication": {"automatic": {}}})
        write(root / "service-account.json", json.dumps({
            "type": "service_account", "client_email": "kronik@m23.invalid",
            "private_key": (auth.root / "oauth.key").read_text()}))
        self.auth = auth
        self.ref = self.secret
        self.evidence["checks"] = ["service-account RS256 JWT verified by the loopback token fixture",
                                   "numeric project, as Secret Manager names resources"]

    def put(self, value):
        r = request(f"{self.base}/v1/{self.secret}:addVersion",
                    {"payload": {"data": base64.b64encode(value.encode()).decode()}})
        self.versions.append(r["name"].rsplit("/", 1)[1])
        return self.versions[-1]

    def destroy(self, version):
        r = request(f"{self.base}/v1/{self.secret}/versions/{version}:destroy", {})
        assert r.get("state") == "DESTROYED", r
        request(f"{self.base}/v1/{self.secret}/versions/{version}:access", status=(400, 404, 410, 412))
        return "DestroySecretVersion: the version is DESTROYED and cannot be accessed"

    def backend(self):
        return {"type": "gcp", "endpoint": self.base, "allowed_refs": [f"projects/{self.project}/secrets/payments-"],
                "service_account_file": str(self.root / "service-account.json"),
                "token_endpoint": self.auth.base + "/gcp-token"}


class Azure(Service):
    """The rokeller Key Vault emulator behind TLS, client credentials for the token."""
    name = "azure"

    def __init__(self, root, tag, auth):
        super().__init__(root, tag)
        certs = root / "certs"
        tls_fixtures(certs)
        command("openssl", "pkcs12", "-export", "-out", certs / "server.pfx", "-inkey", certs / "server.key",
                "-in", certs / "server.pem", "-certfile", certs / "ca.pem", "-passout", "pass:" + TOKEN)
        (certs / "server.pfx").chmod(0o444)
        # The emulator listens on the published port itself, so the ids it
        # returns carry the address Kronik uses.
        docker_run(self.container, IMAGES["azure"], [(self.port, self.port)], [],
                   ["--mount", f"type=bind,source={certs / 'server.pfx'},target=/tls/server.pfx,readonly",
                    "--env", "ASPNETCORE_Kestrel__Certificates__Default__Path=/tls/server.pfx",
                    "--env", "ASPNETCORE_Kestrel__Certificates__Default__Password=" + TOKEN,
                    "--env", f"ASPNETCORE_URLS=https://+:{self.port}",
                    "--tmpfs", "/app/.vault:rw,nosuid,noexec,size=64m,mode=1777"])
        self.base = f"https://127.0.0.1:{self.port}"
        self.tls = ssl.create_default_context(cafile=str(certs / "ca.pem"))
        self.headers = {"Authorization": "Bearer " + JWT}
        wait_for("emulator listening", lambda: listening(self.port), 90)
        wait_for("emulator answering", lambda: request(self.base + "/secrets?api-version=7.4", headers=self.headers,
                                                       tls=self.tls, status=(200, 404)) is not None, 90, 0.5)
        write(root / "client-secret", TOKEN)
        self.auth = auth
        self.ref = self.base + "/secrets/payments-stripe"
        self.evidence["checks"] = ["TLS with a disposable CA", "client credentials through the loopback authority",
                                   "the emulator checks the bearer token's syntax only"]

    def put(self, value):
        r = request(self.base + "/secrets/payments-stripe?api-version=7.4", {"value": value},
                    self.headers, self.tls, method="PUT")
        assert r["id"].startswith(self.ref + "/"), (self.ref, r["id"])
        self.versions.append(r["id"].rsplit("/", 1)[1])
        return self.versions[-1]

    def destroy(self, version):
        # Key Vault destroys no single version; a disabled version can no
        # longer be read, and the emulator purges a deleted secret at once.
        r = request(f"{self.base}/secrets/payments-stripe/{version}?api-version=7.4",
                    {"attributes": {"enabled": False}}, self.headers, self.tls, method="PATCH")
        assert r["attributes"]["enabled"] is False, r
        return "the version disabled (Key Vault has no per-version destroy)"

    def backend(self):
        return {"type": "azure", "allowed_refs": [self.base + "/secrets/payments-"],
                "tenant_id": "m23-tenant", "client_id": "m23-client",
                "client_secret_file": str(self.root / "client-secret"),
                "authority_endpoint": self.auth.base, "ca_file": str(self.root / "certs/ca.pem")}


# ------------------------------------------------------------ real clouds

def cli_json(*args, data=None):
    r = command(*args, data=data, timeout=180)
    out = r.stdout.decode()
    return json.loads(out) if out.strip() else {}


def environment(name):
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"{name} is not set; see scripts/e2e-cloud-secrets.sh")
    return value


class Cloud(Service):
    """A real cloud's secret service, driven with its own CLI and the operator's login.

    There is no container and no outage: a real service cannot be stopped by a
    test, so the outage checks run against the emulators only. Each run makes
    its own secret with a random name and deletes it at the end.
    """

    def __init__(self, root, tag):
        self.root, self.container, self.port = root, None, None
        self.evidence = {"service": self.name, "checks": []}
        root.mkdir(mode=0o700)
        self.versions = []
        self.secret = "kronik-e2e-" + random.token_hex(6)

    def outage_modes(self):
        return []

    def close(self):
        with contextlib.suppress(Exception):
            self.cleanup()


class AwsCloud(Cloud):
    """AWS Secrets Manager: `aws` CLI for the test, AWS_* for the daemon (`auth = "env"`)."""
    name = "aws"

    def __init__(self, root, tag):
        super().__init__(root, tag)
        self.region = environment("KRONIK_E2E_AWS_REGION")
        self.ref = f"kronik-e2e/{self.secret}#key"
        self.created = False

    def aws(self, *args, data=None):
        return cli_json("aws", "--region", self.region, "--output", "json", "secretsmanager", *args, data=data)

    def put(self, value):
        secret = json.dumps({"key": value, "other": "not-this-field"})
        if not self.created:
            r = self.aws("create-secret", "--name", f"kronik-e2e/{self.secret}", "--secret-string", secret)
            self.created = True
        else:
            r = self.aws("put-secret-value", "--secret-id", f"kronik-e2e/{self.secret}", "--secret-string", secret)
        self.versions.append(r["VersionId"])
        return self.versions[-1]

    def destroy(self, version):
        self.aws("delete-secret", "--secret-id", f"kronik-e2e/{self.secret}", "--force-delete-without-recovery")
        self.created = False
        return "DeleteSecret without recovery (Secrets Manager destroys no single version)"

    def cleanup(self):
        if self.created:
            self.aws("delete-secret", "--secret-id", f"kronik-e2e/{self.secret}", "--force-delete-without-recovery")

    def backend(self):
        return {"type": "aws", "region": self.region, "auth": "env", "allowed_refs": ["kronik-e2e/"]}

    def daemon_env(self):
        return {k: os.environ[k] for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
                if k in os.environ}


class GcpCloud(Cloud):
    """GCP Secret Manager: `gcloud` for the test, a service-account key file for the daemon."""
    name = "gcp"

    def __init__(self, root, tag):
        super().__init__(root, tag)
        # Secret Manager names resources by project NUMBER in its answers.
        self.project = environment("KRONIK_E2E_GCP_PROJECT_NUMBER")
        self.account = environment("KRONIK_E2E_GCP_SERVICE_ACCOUNT_FILE")
        self.ref = f"projects/{self.project}/secrets/{self.secret}"
        command("gcloud", "secrets", "create", self.secret, "--project", self.project,
                "--replication-policy", "automatic", timeout=180)
        self.created = True

    def put(self, value):
        r = cli_json("gcloud", "secrets", "versions", "add", self.secret, "--project", self.project,
                     "--data-file=-", "--format=json", data=value.encode())
        self.versions.append(r["name"].rsplit("/", 1)[1])
        return self.versions[-1]

    def destroy(self, version):
        command("gcloud", "secrets", "versions", "destroy", version, "--secret", self.secret, "--project",
                self.project, "--quiet", timeout=180)
        return "DestroySecretVersion"

    def cleanup(self):
        if self.created:
            command("gcloud", "secrets", "delete", self.secret, "--project", self.project, "--quiet", timeout=180)

    def backend(self):
        return {"type": "gcp", "allowed_refs": [f"projects/{self.project}/secrets/kronik-e2e-"],
                "service_account_file": self.account}


class AzureCloud(Cloud):
    """Azure Key Vault: `az` for the test, client credentials for the daemon."""
    name = "azure"

    def __init__(self, root, tag):
        super().__init__(root, tag)
        self.vault = environment("KRONIK_E2E_AZURE_VAULT").rstrip("/")
        self.vault_name = urllib.parse.urlsplit(self.vault).hostname.split(".")[0]
        self.ref = f"{self.vault}/secrets/{self.secret}"
        self.created = False

    def put(self, value):
        r = cli_json("az", "keyvault", "secret", "set", "--vault-name", self.vault_name, "--name", self.secret,
                     "--file", "/dev/stdin", "--encoding", "utf-8", "--output", "json", data=value.encode())
        self.created = True
        self.versions.append(r["id"].rsplit("/", 1)[1])
        return self.versions[-1]

    def destroy(self, version):
        command("az", "keyvault", "secret", "set-attributes", "--vault-name", self.vault_name, "--name",
                self.secret, "--version", version, "--enabled", "false", timeout=180)
        return "the version disabled (Key Vault has no per-version destroy)"

    def cleanup(self):
        if self.created:
            command("az", "keyvault", "secret", "delete", "--vault-name", self.vault_name, "--name", self.secret,
                    timeout=180)

    def backend(self):
        return {"type": "azure", "allowed_refs": [f"{self.vault}/secrets/kronik-e2e-"],
                "tenant_id": environment("KRONIK_E2E_AZURE_TENANT_ID"),
                "client_id": environment("KRONIK_E2E_AZURE_CLIENT_ID"),
                "client_secret_file": environment("KRONIK_E2E_AZURE_CLIENT_SECRET_FILE")}


# ------------------------------------------------------------------ daemon

class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=60):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


def toml_value(value):
    if isinstance(value, list):
        return "[" + ", ".join(json.dumps(v) for v in value) + "]"
    return json.dumps(value)


class Daemon:
    def __init__(self, root, name, binary, service=None, gateway=GATEWAY_PORTS[0], env=None):
        self.root, self.name, self.binary = root, name, binary
        self.dir = root / name
        self.dir.mkdir(mode=0o700, exist_ok=True)
        self.data = self.dir / "data"
        self.socket = self.dir / "api.sock"
        self.log = self.dir / "serve.log"
        self.config = self.dir / "kronik.toml"
        self.gateway = gateway
        text = (f'[server]\ndata_dir = "{self.data}"\n\n[log]\ndisk_reserve = "0B"\n\n'
                f'[foreign]\nrun_dir = "{self.dir / "foreign-run"}"\n\n'
                f'[secrets]\nrefresh = "1h"\nfetch_timeout = "{int(FETCH_TIMEOUT)}s"\n')
        if service is not None:
            text += f"\n[secrets.backends.{service.backend_id}]\n"
            text += "".join(f"{key} = {toml_value(value)}\n" for key, value in service.backend().items())
        write(self.config, text)
        self.env = {**os.environ, "KRONIK_MASTER_KEY": MASTER_KEY, "KRONIK_LOG": "info",
                    "KRONIK_DISK_RESERVE": "0B", **(env or {})}
        for name_ in ("KRONIK_TOKEN", "KRONIK_API_SOCKET", "KRONIK_MASTER_KEY_FILE", "KRONIK_CONFIG", "KRONIK_URL"):
            self.env.pop(name_, None)
        self.process = None

    def start(self):
        DAEMONS.append(self)
        output = self.log.open("ab")
        self.process = subprocess.Popen(
            [str(self.binary), "serve", "--config", str(self.config), "--http-listen", f"127.0.0.1:{self.gateway}",
             "--api-socket", str(self.socket)], stdin=subprocess.DEVNULL, stdout=output, stderr=output, env=self.env)
        output.close()

        def healthy():
            if self.process.poll() is not None:
                raise SystemExit("daemon exited: " + self.log.read_text(errors="replace")[-4000:])
            return self.api("GET", "/v1/health", status=None)[0] == 200
        wait_for(self.name + " healthy", healthy, 180, 0.2)
        return self

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def kill9(self):
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait()

    def api(self, method, path, data=None, status=200, timeout=60):
        with contextlib.closing(UnixConnection(self.socket, timeout)) as conn:
            conn.request(method, path, body=None if data is None else json.dumps(data),
                         headers={"Content-Type": "application/json", "Host": "localhost"})
            response = conn.getresponse()
            raw = response.read()
            value = json.loads(raw) if raw.strip() else {}
            if status is None:
                return response.status, value
            assert response.status == status, (method, path, response.status, value)
            return value

    def get(self, path, seconds=120):
        """A read that waits out the fail-closed window of the secret coverage."""
        def ok():
            status, value = self.api("GET", path, status=None)
            if status == 200:
                return [value]
            assert status == 503 and value["error"]["code"] == "SECRET_UNAVAILABLE", (path, status, value)
            return None
        return wait_for("GET " + path, ok, seconds, 0.2)[0]

    def mutate(self, method, path, data, seconds=120):
        """A mutation that must succeed; a committed one that answers 503 is read back."""
        def ok():
            status, value = self.api(method, path, data, status=None)
            if status == 200:
                return [value]
            assert status == 503 and value["error"]["code"] == "SECRET_UNAVAILABLE", (path, status, value)
            if "already committed" in value["error"].get("message", ""):
                self.get("/v1/secrets/stripe/history")
                return [None]
            return None
        return wait_for(method + " " + path, ok, seconds, 0.2)[0]

    def cli(self, *args, ok=True):
        r = command(self.binary, "--socket", self.socket, *args, check=False, env=self.env, timeout=120)
        assert (r.returncode == 0) == ok, (args, r.returncode, r.stdout, r.stderr)
        return r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")

    def deploy(self, guest):
        wasm = base64.b64encode((GUESTS / guest).read_bytes()).decode()
        self.mutate("POST", "/v1/deployments", {"wasm_base64": wasm, "reason": REASON})

    def grant(self, kind, capability, delivery=None):
        self.mutate("POST", "/v1/grants", {"kind": kind, "capability": capability, "delivery": delivery,
                                           "reason": REASON})

    def send(self, actor, name, text_, status=200, timeout=60):
        return self.api("POST", f"/v1/actors/{actor}/messages", {"name": name, "text": text_, "reason": REASON},
                        status=status, timeout=timeout)

    def gateway_post(self, path, body, key, timeout=60):
        """A request to an actor through the gateway: the status, the body, the seconds it took."""
        started = time.monotonic()
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", self.gateway, timeout=timeout)) as conn:
            conn.request("POST", path, body=body.encode(), headers={"Idempotency-Key": key})
            response = conn.getresponse()
            text_ = response.read().decode(errors="replace")
        return response.status, text_, time.monotonic() - started

    def send_detached(self, actor, name, text_):
        def run():
            with contextlib.suppress(Exception):
                self.send(actor, name, text_, status=None, timeout=600)
        threading.Thread(target=run, daemon=True).start()

    def versions(self):
        return self.get("/v1/secrets/stripe/history")["versions"]

    def records(self):
        return log_records(self.data)

    def applied_lsn(self):
        return self.get("/v1/health")["applied_lsn"]

    def quiet(self):
        """Waits until the applied LSN has not moved for a second."""
        last, since = self.applied_lsn(), time.monotonic()
        deadline = time.monotonic() + 90
        while time.monotonic() - since < 1:
            assert time.monotonic() < deadline, "the daemon never became quiet"
            time.sleep(0.1)
            now = self.applied_lsn()
            if now != last:
                last, since = now, time.monotonic()

    def mcp(self, calls):
        answers = []
        for i, (method, params) in enumerate([("initialize", {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "clientInfo": {"name": "kronik-e2e-secrets", "version": "1"}})] + calls):
            with contextlib.closing(UnixConnection(self.socket)) as conn:
                conn.request("POST", "/mcp", body=json.dumps({"jsonrpc": "2.0", "id": i + 1, "method": method,
                                                              "params": params}),
                             headers={"Content-Type": "application/json", "Host": "localhost",
                                      "Accept": "application/json, text/event-stream"})
                response = conn.getresponse()
                raw = response.read().decode(errors="replace")
                assert response.status == 200, (method, response.status, raw[:400])
                assert '"error"' not in raw[:200] or '"result"' in raw, (method, raw[:400])
                answers.append(raw)
        return answers


def answers(d, actors, turn_ids):
    """Every answer a client can get about the actors and the secret."""
    out = []
    for actor in actors:
        out.append(d.cli("history", actor))
        out.append(d.cli("actors", "inspect", actor))
        out.append(json.dumps(d.get(f"/v1/actors/{actor}")))
        out.append(json.dumps(d.get(f"/v1/actors/{actor}/history")))
    out.append(d.cli("secret", "history", "stripe"))
    out.append(d.cli("secret", "list"))
    out.append(d.cli("secret", "backends"))
    for turn in turn_ids:
        out.append(json.dumps(d.get(f"/v1/turns/{turn}")))
        out.append(json.dumps(d.get(f"/v1/turns/{turn}/trace")))
    for path in ("/v1/secrets", "/v1/secrets/stripe/history", "/v1/secrets/backends", "/v1/dead-letters",
                 "/v1/grants", "/v1/deployments"):
        out.append(json.dumps(d.get(path)))
    calls = [("tools/call", {"name": "inspect_actor", "arguments": {"actor": a}}) for a in actors]
    calls += [("tools/call", {"name": "query_history", "arguments": {"actor": a, "limit": 100}}) for a in actors]
    calls += [("tools/call", {"name": "trace_turn", "arguments": {"turn_id": t}}) for t in turn_ids]
    calls += [("tools/call", {"name": "list_dead_letters", "arguments": {}}),
              ("resources/read", {"uri": "kronik://config"})]
    out.extend(d.mcp(calls))
    return out


def forms(value):
    return [value.encode(), value.encode().hex().encode(), base64.b64encode(value.encode())]


def needle_hits(dirs, files, texts, values):
    hits = []
    for value in values:
        needles = forms(value)
        for root in dirs:
            for path in root.rglob("*"):
                if path.is_file() and not path.is_socket():
                    data = path.read_bytes()
                    if any(n in data for n in needles):
                        hits.append(f"{value[:12]}... in {path}")
        for path in files:
            if path.exists() and any(n in path.read_bytes() for n in needles):
                hits.append(f"{value[:12]}... in {path}")
        for i, answer in enumerate(texts):
            if any(n.decode() in answer for n in needles):
                hits.append(f"{value[:12]}... in answer {i}: {answer[:200]}")
    return hits


# --------------------------------------------------------------- criteria

def turn_named(d, actor, message, count=1, seconds=120):
    """Waits until `actor` has `count` TurnRecords for `message` in the log."""
    def found():
        selected = [t for t in turns(d.records()) if t["actor"] == actor and t["message"] == message]
        return selected if len(selected) >= count else None
    return wait_for(f"{count} turns of {actor} for {message}", found, seconds, 0.25)


def run_service(service, binary, root, target, evidence):
    checks = evidence.setdefault("checks", [])
    values = [f"needle-{service.name}-{i}-{random.token_hex(8)}" for i in range(1, 6)]
    first = service.put(values[0])
    d = Daemon(root, "node", binary, service, env=getattr(service, "daemon_env", dict)()).start()
    started = time.monotonic()
    d.deploy("counter.wasm")
    d.deploy("leaky.wasm")
    d.grant("counter", "secret:stripe")
    d.grant("leaky", "secret-reveal:stripe")
    d.grant("leaky", "http:127.0.0.1", "replay-safe")
    linked = d.mutate("PUT", "/v1/secrets/stripe/link",
                      {"backend": service.backend_id, "ref": service.ref, "reason": REASON})
    evidence["link"] = None if linked is None else linked["link"]
    fork_point = d.applied_lsn()

    # Criterion 2: the version hash in the log, the built-in computation.
    t1 = d.send("counter/h", "hmac", "stripe\npayload")
    assert t1["outcome"]["kind"] == "committed", t1
    assert t1["reply"]["text"] == hmac_hex(values[0], "payload"), t1
    records = d.records()
    logged = secret_versions(records, "stripe")
    assert len(logged) == 1, logged
    v1 = logged[0]
    assert (v1["version"], v1["backend"], v1["source_version"]) == (1, service.backend_id, first), v1
    assert len(v1["hash"]) == 32, v1
    hmacs = [e["secret"] for t in turns(records) for e in t["effects"] if e["kind"] == "crypto.hmac-sha256"]
    assert hmacs == [{"name": "stripe", "version": 1, "hash": v1["hash"]}], hmacs
    history = d.versions()
    assert [(h["version"], h["version_hash"], h["source_version"], h["backend"], h["phase"]) for h in history] == \
        [(1, v1["hash"], first, service.backend_id, "active")], history
    file_node = Daemon(root, "file-node", binary, gateway=GATEWAY_PORTS[1]).start()
    try:
        built_in = file_node.mutate("PUT", "/v1/secrets/stripe", {"text": values[0], "reason": REASON})
        assert built_in["secret"]["version"] == 1 and built_in["secret"]["version_hash"] == v1["hash"], built_in
    finally:
        file_node.stop()
    acted = d.get("/v1/actors/counter/h/history")["turns"]
    assert acted[0]["effects"][0]["secrets"] == [{"name": "stripe", "version": 1, "version_hash": v1["hash"][:8]}], acted
    evidence["criterion_2"] = {"log_secret_version": v1, "effect_secret_ref": hmacs[0],
                               "file_node_hash": built_in["secret"]["version_hash"]}
    checks.append("criterion 2: SecretVersion in the log (hash, backend, source version) = the effect's SecretRef "
                  "= secret history = a file node's hash for the same value under the same master key")

    # Criterion 3: rotation, history, and the old turns replayed.
    second = service.put(values[1])
    refreshed = d.mutate("POST", "/v1/secrets/stripe/refresh", {"reason": REASON})
    rows = secret_versions(d.records(), "stripe")
    assert [(r["version"], r["source_version"]) for r in rows] == [(1, first), (2, second)], rows
    v2 = rows[1]
    assert v2["hash"] != v1["hash"] and rows[0] == v1, rows
    history = d.versions()
    assert [(h["version"], h["source_version"], h["version_hash"]) for h in history] == \
        [(1, first, v1["hash"]), (2, second, v2["hash"])], history
    shown = d.cli("secret", "history", "stripe")
    for row in (v1, v2):
        assert row["hash"] in shown and row["source_version"] in shown, shown
    t2 = d.send("counter/h", "hmac", "stripe\npayload")
    assert t2["reply"]["text"] == hmac_hex(values[1], "payload"), t2
    acted = {t["turn_id"]: t for t in d.get("/v1/actors/counter/h/history")["turns"]}
    assert acted[t1["turn_id"]]["effects"][0]["secrets"][0]["version"] == 1
    assert acted[t2["turn_id"]]["effects"][0]["secrets"] == [
        {"name": "stripe", "version": 2, "version_hash": v2["hash"][:8]}]
    table = d.cli("history", "counter/h")
    assert f"secret:stripe@v1 ({v1['hash'][:8]})" in table and f"secret:stripe@v2 ({v2['hash'][:8]})" in table, table
    evidence["criterion_3_rotation"] = {"refresh": refreshed, "log": rows}
    checks.append("criterion 3: a new version in the service + secret refresh = SecretVersion 2 in the log and in "
                  "secret history; the new turn shows secret:stripe@v2, the old one @v1")
    d.quiet()
    paused = "pause" in service.outage_modes()
    if paused:
        service.outage("pause")
    try:
        fork = d.mutate("POST", "/v1/forks", {"at": fork_point, "reason": REASON})["fork"]["name"]
        d.mutate("POST", f"/v1/forks/{fork}/replay", {"reason": REASON})
        diff = d.get(f"/v1/forks/{fork}/diff")
    finally:
        if paused:
            service.recover("pause")
    summary = diff["summary"]
    assert summary["changed"] is False and summary["divergent_turns"] == 0, diff
    assert (diff["effects"]["added"], diff["effects"]["removed"], diff["effects"]["changed"]) == (0, 0, 0), diff
    assert summary["exact"] >= 2 and all(summary[k] == 0 for k in ("approximate", "synthetic", "live")), diff
    evidence["criterion_3_fork"] = summary
    checks.append("criterion 3: a fork from before the rotation replays both turns identically (exact, no "
                  "divergence) while the service is paused, so the fork asks it nothing")

    # I8: no value anywhere.
    hits = needle_hits([d.data], [d.config, d.log], answers(d, ["counter/h"], [t1["turn_id"], t2["turn_id"]]),
                       values[:2])
    assert not hits, hits
    checks.append("needle: neither value, raw, hex or base64, in the data directory, the configuration, the daemon "
                  "log, the API, the CLI or MCP")

    # Criterion 3: crash recovery of a recorded reveal gets the recorded version.
    target.hold()
    before = len(target.requests())
    d.send_detached("leaky/a", "reveal-fetch", f"stripe http://127.0.0.1:{TARGET_PORT}/hang")
    wait_for("the reveal's fetch", lambda: len(target.requests()) > before)
    sent = target.requests()[before]
    assert sent["path"] == f"/hang?key={values[1]}", sent["path"]
    third = service.put(values[2])
    d.mutate("POST", "/v1/secrets/stripe/refresh", {"reason": REASON})
    assert [r["source_version"] for r in secret_versions(d.records(), "stripe")] == [first, second, third]
    d.kill9()
    mode = (service.outage_modes() or [None])[0]
    if mode:
        service.outage(mode)
    try:
        d.start()
        lsn = d.applied_lsn()
        increment = d.send("counter/a", "increment", "", timeout=30)
        assert increment["outcome"]["kind"] == "committed", increment
        if mode:
            time.sleep(4)
            assert len(target.requests()) == before + 1, "the re-run went on without the recorded value"
            assert not [t for t in turns(d.records())
                        if t["actor"] == "leaky/a" and t["message"] == "reveal-fetch"], \
                "the re-run ended during the outage"
    finally:
        if mode:
            service.recover(mode)
    target.release()
    rerun = turn_named(d, "leaky/a", "reveal-fetch")[0]
    assert rerun["outcome"] == COMMITTED, rerun
    resent = target.requests()[before + 1:]
    assert [r["path"] for r in resent] == [f"/hang?key={values[1]}"], resent
    assert resent[0]["headers"].get("x-api-key") == values[1]
    assert not any(values[2] in json.dumps(r) for r in target.requests()), "the current version's value went out"
    evidence["criterion_3_recovery"] = {"outage": mode, "rerun": rerun["lsn"], "start_lsn": lsn}
    checks.append("criterion 3: the crash re-run of a recorded reveal "
                  + (f"waits while the service is down ({mode}), other turns commit, then " if mode else "")
                  + "gets the recorded version's value (not the current one)")

    # Outages: turns without a secret, a cached secret, an uncached one.
    d.quiet()
    warm = d.send("counter/h", "hmac", "stripe\npayload")
    assert warm["reply"]["text"] == hmac_hex(values[2], "payload"), warm
    outages = {}
    for mode in service.outage_modes():
        service.outage(mode)
        try:
            # Turns arrive through the gateway: an operator's `send` is also a
            # mutation whose reason is scrubbed, and the first one after a
            # start waits for the first pass of the secret cycle (ADR 0091).
            timings = []
            for i in range(5):
                status, body, took = d.gateway_post("/counter/a/increment", "", f"{mode}-warm-{i}", 30)
                timings.append(took)
                assert status == 200, (status, body)
            assert max(timings) < FETCH_TIMEOUT / 2, timings
            cached = d.send("counter/h", "hmac", "stripe\npayload", timeout=30)
            assert cached["reply"]["text"] == hmac_hex(values[2], "payload"), cached
            d.kill9()
            d.start()
            after = []
            for i in range(5):
                status, body, took = d.gateway_post("/counter/b/increment", "", f"{mode}-cold-{i}", 30)
                after.append(took)
                assert status == 200, (status, body)
            assert max(after) < FETCH_TIMEOUT / 2, after
            status, body, waited = d.gateway_post("/counter/h/hmac", "stripe\npayload", f"{mode}-uncached", 60)
            assert status == 500 and "TURN_FAILED" in body, (status, body)
            assert waited < FETCH_TIMEOUT + 3, waited
            failed = [t for t in turns(d.records()) if t["actor"] == "counter/h"][-1]
            assert failed["outcome"] == FAILED and failed["effects"][0]["status"] == DENIED and \
                failed["effects"][0]["error"] == "SECRET_UNAVAILABLE: stripe", failed
            assert open_turns(d.records()) == [], "an open TurnBegin while the daemon runs"
            t0 = time.monotonic()
            r = d.send("counter/c", "increment", "", timeout=60)
            first_send = time.monotonic() - t0
            assert r["outcome"]["kind"] == "committed", r
        finally:
            service.recover(mode)
        def back():
            r = d.send("counter/h", "hmac", "stripe\npayload", timeout=60)
            return r if r["outcome"]["kind"] == "committed" else None
        again = wait_for("the secret after the outage", back, 60, 1)
        assert again["reply"]["text"] == hmac_hex(values[2], "payload"), again
        outages[mode] = {"no_secret_turns_s": [round(t, 3) for t in timings],
                         "after_restart_no_secret_turns_s": [round(t, 3) for t in after],
                         "uncached_secret_turn_s": round(waited, 3),
                         "first_operator_send_after_restart_s": round(first_send, 3)}
    evidence["outages"] = outages
    if outages:
        checks.append("outages (" + ", ".join(service.outage_modes()) + "): turns without a secret commit at once, a "
                      "cached secret is used, an uncached one fails within fetch_timeout with SECRET_UNAVAILABLE "
                      "recorded as the effect's result and no open TurnBegin, and the secret works again once the "
                      "service is back")

    # Criterion 3: a destroyed version gives SECRET_VERSION_GONE.
    target.hold()
    before = len(target.requests())
    d.send_detached("leaky/b", "reveal-fetch", f"stripe http://127.0.0.1:{TARGET_PORT}/hang")
    wait_for("the second reveal's fetch", lambda: len(target.requests()) > before)
    assert target.requests()[before]["path"] == f"/hang?key={values[2]}"
    fourth = service.put(values[3])
    d.mutate("POST", "/v1/secrets/stripe/refresh", {"reason": REASON})
    how = service.destroy(third)
    d.kill9()
    d.start()
    target.release()
    gone = turn_named(d, "leaky/b", "reveal-fetch")[0]
    assert (gone["outcome"], gone["error_code"]) == (FAILED, "SECRET_VERSION_GONE"), gone
    assert [e["kind"] for e in gone["effects"]] == ["secret.reveal"], gone
    assert gone["effects"][0]["secret"]["version"] == 3 and gone["effects"][0]["status"] == OK, gone
    time.sleep(3)
    assert len(target.requests()) == before + 1, "the failed re-run sent something"
    assert not any(values[3] in json.dumps(r) for r in target.requests())
    assert open_turns(d.records()) == []
    # The known defect of the operations guide ("Secrets that an external
    # backend no longer serves"): a recorded version the service no longer
    # serves keeps the reads that scrub at 503 after a restart. Observed, not
    # asserted either way.
    reads = {}
    for path in ("/v1/actors/counter/h/history", "/v1/secrets/stripe/history"):
        code, answer = d.api("GET", path, status=None)
        reads[path] = code if code == 200 else f"{code} {answer.get('error', {}).get('code')}"
    evidence["criterion_3_gone"] = {"destroyed": how, "source_version": third, "turn": gone["lsn"],
                                    "current_after": fourth, "scrubbed_reads_after_restart": reads}
    checks.append("criterion 3: once the service destroyed a recorded version, the crash re-run fails the turn with "
                  "SECRET_VERSION_GONE, keeps the recorded reveal, sends nothing and never uses the current value")

    allocated = allocations(d.records(), "stripe")
    numbers = sorted({v for v, _, _ in allocated})
    assert numbers == list(range(1, len(numbers) + 1)), allocated
    d.stop()
    hits = needle_hits([d.data], [d.config, d.log, root / "file-node/serve.log"], [], values)
    assert not hits, hits
    evidence["allocations"] = allocated
    evidence["seconds"] = round(time.monotonic() - started, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--dir", type=Path, help="a new private output directory")
    parser.add_argument("--only", default=None)
    parser.add_argument("--cloud", action="store_true",
                        help="real AWS, GCP and Azure with the operator's credentials (e2e-cloud-secrets.sh)")
    args = parser.parse_args()
    known = ["aws", "gcp", "azure"] if args.cloud else PROVIDERS
    selected = (args.only or ",".join(known)).split(",")
    if not selected or len(set(selected)) != len(selected) or any(s not in known for s in selected):
        parser.error("--only names services out of " + ",".join(known))
    binary = args.bin.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--bin must be an already-built kronik")
    os.umask(0o077)
    root = args.dir.resolve() if args.dir else Path(tempfile.mkdtemp(prefix="kronik-m23-secrets.", dir="/var/tmp"))
    if args.dir:
        root.mkdir(mode=0o700)
    root.chmod(0o755)
    tag = "kronik-m23-secrets-" + str(os.getpid())
    version = command(binary, "--version").stdout.decode().strip()
    results = {"schema": "kronik.m23-secrets-acceptance/v1", "cloud": args.cloud, "directory": str(root),
               "binary": str(binary),
               "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "binary_version": version,
               "services": {}}
    print("Artifacts:", root, flush=True)
    failures = []
    target = Target()
    auth = None
    try:
        auth_root = root / "auth"
        auth_root.mkdir(mode=0o700)
        auth = AuthFixture(auth_root)
        for name in selected:
            service = None
            evidence = {}
            try:
                directory = root / name
                if args.cloud:
                    service = {"aws": AwsCloud, "gcp": GcpCloud, "azure": AzureCloud}[name](directory, tag)
                else:
                    cls = {"openbao": OpenBao, "openbao-approle": OpenBaoAppRole, "aws": Aws}.get(name)
                    service = cls(directory, tag) if cls else {"gcp": Gcp, "azure": Azure}[name](directory, tag, auth)
                service.backend_id = "vault" if name.startswith("openbao") else name
                evidence.update(service.evidence)
                run_service(service, binary, directory, target, evidence)
                evidence["passed"] = True
                print("PASS", name, flush=True)
            except Exception as error:  # noqa: BLE001 - every failure is evidence
                failures.append(name)
                evidence.update({"passed": False, "error": repr(error)[:4000]})
                print("FAIL", name, repr(error)[:4000], file=sys.stderr, flush=True)
            finally:
                for daemon in DAEMONS:
                    with contextlib.suppress(Exception):
                        daemon.kill9()
                if service is not None:
                    service.close()
                for leftover in (root / name).glob("*/api.sock") if (root / name).exists() else []:
                    leftover.unlink(missing_ok=True)
                results["services"][name] = evidence
                write(root / "results.json", json.dumps(results, indent=2, sort_keys=True) + "\n", 0o644)
    finally:
        for daemon in DAEMONS:
            with contextlib.suppress(Exception):
                daemon.kill9()
        target.close()
        if auth:
            results["auth_requests"] = auth.counts
            auth.close()
        errors = []
        for name in list(OWNED):
            try:
                remove(name, root / (name + ".log"))
            except Exception as error:  # noqa: BLE001
                errors.append(str(error))
        remaining = command("docker", "ps", "--all", "--filter", "label=kronik.m23.secrets",
                            "--filter", "name=" + tag, "--format", "{{.Names}}").stdout.decode().split()
        results["cleanup"] = {"created": sorted(CREATED), "remaining": remaining, "errors": errors}
        results["passed"] = not failures and not remaining and not errors and len(results["services"]) == len(selected)
        write(root / "results.json", json.dumps(results, indent=2, sort_keys=True) + "\n", 0o644)
    print("Evidence:", root / "results.json", flush=True)
    return 1 if failures or not results["passed"] else 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    sys.exit(main())
