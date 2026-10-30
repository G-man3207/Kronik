#!/usr/bin/env python3
"""M23 B1 acceptance; see e2e-keys.sh. Uses only dummy credentials and owned data.

The provider and Kronik containers share an otherwise empty network namespace.
The trusted driver briefly enters it; the tested binary never gets host network,
Docker socket, host credentials, or writable files outside this run's directory.
A probe-only run establishes emulator capabilities, not a Kronik acceptance pass.
"""
import argparse
import base64
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import resource
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

IMAGES = {
    "openbao": "openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f",
    "aws": "motoserver/moto@sha256:59a1965d845249b04def37a0e2565f9cc6c44543cb89b68e90f28f344b3b0d1a",
    "gcp": "ghcr.io/blackwell-systems/gcp-kms-emulator-dual@sha256:c53eafad0d8d2c0497bfa13fa09e3230cd21b935b412c7cb3e64b46ed5e30f8c",
    "azure": "ghcr.io/rokeller/azure-keyvault-emulator@sha256:126d8433d11f4983dba5337352311bcf9278a566b415b0cbfd5eea2b7d8e9d88",
}
RUNTIME = "debian@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4"
PORTS = {"openbao": 8200, "aws": 5000, "gcp": 8080, "azure": 11001}
AAD = "kronik master v1"
REASON = "M23 isolated acceptance"
TOKEN = "m23-disposable-token-only"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjQxMDI0NDQ4MDAsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9."
       "42D_zJ3qM02NM_ExWU9S9jvNGMfpop3YuWT9lFqJ5yU")
DUMMY = b"0123456789abcdef0123456789abcdef"
SECRET = "m23-secret-round-trip"
OWNED = set()
CREATED = set()


def command(*args, timeout=60, check=True, data=None):
    r = subprocess.run([str(a) for a in args], input=data, capture_output=True, timeout=timeout)
    if check and r.returncode:
        raise AssertionError(f"{args[:3]} exited {r.returncode}: "
                             f"{r.stdout[-3000:].decode(errors='replace')}{r.stderr[-3000:].decode(errors='replace')}")
    return r


def write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def wait_for(description, predicate, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out: {description}")


def request(base, path, data=None, headers=None, tls=None, status=200, method=None):
    body = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(base + path, body, {"Content-Type": "application/json", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5, context=tls) as r:
            code, raw = r.status, r.read(1024 * 1024)
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read(1024 * 1024)
    accepted = (status,) if isinstance(status, int) else status
    assert code in accepted, (path, code, raw[:1200])
    return json.loads(raw) if raw else {}


def wait_http(base):
    address = urllib.parse.urlsplit(base)
    def listening():
        try:
            with socket.create_connection((address.hostname, address.port), timeout=1):
                return True
        except OSError:
            return False
    wait_for(base, listening, 60)


def image(ref):
    info = command("docker", "image", "inspect", ref, check=False)
    if info.returncode:
        command("docker", "pull", ref, timeout=240)
        info = command("docker", "image", "inspect", ref)
    info = json.loads(info.stdout)[0]
    return {"requested": ref, "id": info["Id"], "digests": info.get("RepoDigests", [])}


def docker_start(name, ref, args=(), extra=(), network="none", memory="384m"):
    command("docker", "create", "--name", name,
            "--label", "kronik.m23.acceptance=" + name,
            "--network", network, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "128",
            "--memory", memory, "--memory-swap", memory, "--cpus", "0.5",
            "--ulimit", "core=0:0", "--ulimit", "memlock=8388608:8388608",
            "--tmpfs", "/tmp:rw,nosuid,size=64m", "--env", "HOME=/tmp",
            "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
            *extra, ref, *args)
    OWNED.add(name)
    CREATED.add(name)
    command("docker", "start", name)


def remove(name, logs):
    if name in OWNED:
        r = command("docker", "logs", name, check=False)
        logs.write_bytes(r.stdout + r.stderr)
        command("docker", "rm", "--force", "--volumes", name)
        OWNED.remove(name)


def rsa_key(path):
    command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", path)
    path.chmod(0o600)


def tls_fixtures(root):
    root.mkdir(mode=0o700)
    rsa_key(root / "ca.key")
    command("openssl", "req", "-x509", "-new", "-key", root / "ca.key", "-days", "2",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-subj", "/CN=Kronik disposable test CA", "-out", root / "ca.pem")
    for name, usage, san in [("server", "serverAuth", "subjectAltName=IP:127.0.0.1,DNS:localhost\n"),
                              ("client", "clientAuth", "")]:
        rsa_key(root / (name + ".key"))
        command("openssl", "req", "-new", "-key", root / (name + ".key"),
                "-subj", "/CN=kronik-m23-" + name, "-out", root / (name + ".csr"))
        write(root / (name + ".ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + usage + "\n" + san)
        command("openssl", "x509", "-req", "-in", root / (name + ".csr"),
                "-CA", root / "ca.pem", "-CAkey", root / "ca.key", "-CAcreateserial",
                "-days", "2", "-extfile", root / (name + ".ext"), "-out", root / (name + ".pem"))
    rsa_key(root / "untrusted.key")
    command("openssl", "req", "-x509", "-new", "-key", root / "untrusted.key", "-days", "2",
            "-subj", "/CN=untrusted", "-out", root / "untrusted.pem")


class AuthFixture(http.server.ThreadingHTTPServer):
    """Loopback OAuth/metadata only. GCP assertions are cryptographically verified."""
    def __init__(self, root):
        self.root, self.counts = root, {}
        rsa_key(root / "oauth.key")
        command("openssl", "pkey", "-in", root / "oauth.key", "-pubout", "-out", root / "oauth.pub")
        super().__init__(("127.0.0.1", 0), AuthHandler)
        self.base = f"http://127.0.0.1:{self.server_port}"
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)

    def counted(self, name):
        self.counts[name] = self.counts.get(name, 0) + 1


class AuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, value, status=200, content_type="application/json"):
        body = json.dumps(value).encode() if content_type == "application/json" else value.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        assert self.path == "/latest/api/token" and self.headers.get("X-aws-ec2-metadata-token-ttl-seconds")
        self.server.counted("imds_v2_token")
        self.send(TOKEN, content_type="text/plain")

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path.startswith("/latest/meta-data/iam/security-credentials/"):
            assert self.headers.get("X-aws-ec2-metadata-token") == TOKEN
            self.server.counted("imds_v2_credentials")
            if parsed.path.endswith("/"):
                self.send("m23-role", content_type="text/plain")
            else:
                assert parsed.path.endswith("/m23-role")
                self.send({"Code": "Success", "AccessKeyId": "test", "SecretAccessKey": "test",
                           "Token": "m23-session", "Expiration": "2100-01-01T00:00:00Z"})
        elif parsed.path == "/gcp-metadata":
            assert self.headers.get("Metadata-Flavor") == "Google"
            self.server.counted("gcp_metadata")
            self.send({"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600})
        else:
            assert parsed.path == "/azure-metadata" and self.headers.get("Metadata") == "true"
            query = urllib.parse.parse_qs(parsed.query)
            assert query["resource"] == ["https://vault.azure.net"]
            self.server.counted("azure_metadata")
            self.send({"access_token": JWT, "token_type": "Bearer", "expires_in": "3600"})

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
                assert claims["scope"] == "https://www.googleapis.com/auth/cloudkms"
                assert claims["aud"] == self.server.base + "/gcp-token"
                assert abs(claims["iat"] - time.time()) < 60 and claims["exp"] == claims["iat"] + 3600
                with tempfile.NamedTemporaryFile(dir=self.server.root, prefix="jwt-signature-") as sig:
                    sig.write(decode(parts[2]))
                    sig.flush()
                    result = command("openssl", "dgst", "-sha256", "-verify", self.server.root / "oauth.pub",
                                     "-signature", sig.name, data=(parts[0] + "." + parts[1]).encode(), check=False)
                    assert result.returncode == 0, "GCP JWT RS256 signature is invalid"
                self.server.counted("gcp_rs256_verified")
                self.send({"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600})
            else:
                assert self.path == "/m23-tenant/oauth2/v2.0/token"
                assert form == {"grant_type": ["client_credentials"], "client_id": ["m23-client"],
                                "client_secret": [TOKEN], "scope": ["https://vault.azure.net/.default"]}
                self.server.counted("azure_client_credentials")
                self.send({"access_token": JWT, "token_type": "Bearer", "expires_in": 3600})
        except (AssertionError, KeyError, ValueError):
            self.server.counted("rejected_auth")
            self.send({"error": "invalid_client"}, 401)


class Provider:
    def __init__(self, name, root, tag):
        self.name, self.root, self.container = name, root, tag + "-" + name
        self.tls, self.auth, self.host_net = None, None, None
        self.config, self.alternate = {}, {}
        self.evidence = {"image": image(IMAGES[name]), "kms_checks": [], "product_checks": []}
        root.mkdir(mode=0o700)
        extra = []
        args = []
        if name == "openbao":
            tls_fixtures(root / "certs")
            write(root / "certs/bao.json", json.dumps({"storage": {"inmem": {}},
                  "listener": {"tcp": {"address": "0.0.0.0:8200", "tls_cert_file": "/certs/server.pem",
                                       "tls_key_file": "/certs/server.key"}}}))
            extra = ["--user", "0:0", "--entrypoint", "bao", "--env", "BAO_DISABLE_MLOCK=true",
                     "--mount", f"type=bind,source={root / 'certs'},target=/certs,readonly"]
            args = ["server", "-config=/certs/bao.json"]
            self.tls = ssl.create_default_context(cafile=str(root / "certs/ca.pem"))
            # Match the ring-backed client's standard X25519 group without lowering the TLS version.
            self.tls.set_ecdh_curve("X25519")
        elif name == "azure":
            certs = root / "azure-certs"
            tls_fixtures(certs)
            command("openssl", "pkcs12", "-export", "-out", certs / "server.pfx",
                    "-inkey", certs / "server.key", "-in", certs / "server.pem",
                    "-certfile", certs / "ca.pem", "-passout", "pass:" + TOKEN)
            (certs / "server.pfx").chmod(0o444)
            self.evidence["fixture_ca_sha256"] = hashlib.sha256((certs / "ca.pem").read_bytes()).hexdigest()
            self.evidence["certificate_fixture"] = "generated CA:false server leaf + separate trusted CA; upstream Kestrel certificate override"
            extra = ["--mount", f"type=bind,source={certs / 'server.pfx'},target=/tls/server.pfx,readonly",
                     "--env", "ASPNETCORE_Kestrel__Certificates__Default__Path=/tls/server.pfx",
                     "--env", "ASPNETCORE_Kestrel__Certificates__Default__Password=" + TOKEN,
                     "--tmpfs", "/app/.vault:rw,nosuid,noexec,size=64m,mode=1777"]
            self.tls = ssl.create_default_context(cafile=str(certs / "ca.pem"))
        docker_start(self.container, IMAGES[name], args, extra)
        self.host_net = os.open("/proc/self/ns/net", os.O_RDONLY)
        pid = json.loads(command("docker", "inspect", self.container).stdout)[0]["State"]["Pid"]
        with open(f"/proc/{pid}/ns/net") as ns:
            os.setns(ns.fileno(), 0)
        self.base = ("https" if name in ("openbao", "azure") else "http") + f"://127.0.0.1:{PORTS[name]}"
        wait_http(self.base)
        if self.tls:
            with socket.create_connection(("127.0.0.1", PORTS[name]), timeout=5) as tcp:
                with self.tls.wrap_socket(tcp, server_hostname="127.0.0.1") as secured:
                    self.evidence["tls"] = {"version": secured.version(), "cipher": secured.cipher()[0], "certificate_verified": True}
        self.auth = AuthFixture(root)
        self.bootstrap()

    def call(self, path, data=None, status=200, method=None):
        return request(self.base, path, data, self.headers, self.tls, status, method)

    def kms(self, operation, data, status=200):
        return request(self.base, "/", data, {"X-Amz-Target": "TrentService." + operation,
                       "Authorization": "AWS4-HMAC-SHA256 Credential=test/20261030/us-east-1/kms/aws4_request, SignedHeaders=host, Signature=test"}, status=status)

    def bootstrap(self):
        name = self.name
        if name == "openbao":
            self.headers = {}
            init = self.call("/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
            self.call("/v1/sys/unseal", {"key": init["keys_base64"][0]})
            self.headers = {"X-Vault-Token": init["root_token"]}
            self.call("/v1/sys/mounts/transit", {"type": "transit"}, status=204)
            self.call("/v1/transit/keys/kronik", {"derived": True}, status=(200, 204))
            policy = 'path "transit/encrypt/kronik" { capabilities = ["update"] }\npath "transit/decrypt/kronik" { capabilities = ["update"] }'
            self.call("/v1/sys/policies/acl/kronik-m23", {"policy": policy}, status=204)
            self.call("/v1/sys/auth/cert", {"type": "cert"}, status=204)
            self.call("/v1/auth/cert/certs/kronik", {"certificate": (self.root / "certs/ca.pem").read_text(),
                       "allowed_common_names": "kronik-m23-client", "token_policies": ["kronik-m23"]}, status=204)
            request(self.base, "/v1/auth/cert/login", {"name": "kronik"}, tls=self.tls, status=(400, 403))
            client = ssl.create_default_context(cafile=str(self.root / "certs/ca.pem"))
            client.set_ecdh_curve("X25519")
            client.load_cert_chain(self.root / "certs/client.pem", self.root / "certs/client.key")
            assert request(self.base, "/v1/auth/cert/login", {"name": "kronik"}, tls=client)["auth"]["client_token"]
            bad = ssl.create_default_context(cafile=str(self.root / "certs/ca.pem"))
            bad.set_ecdh_curve("X25519")
            bad.load_cert_chain(self.root / "certs/untrusted.pem", self.root / "certs/untrusted.key")
            request(self.base, "/v1/auth/cert/login", {"name": "kronik"}, tls=bad, status=(400, 403))
            self.config = {"address": self.base, "mount": "transit", "key": "kronik", "auth": "cert", "role": "kronik",
                           "ca_file": "/work/certs/ca.pem", "cert_file": "/work/certs/client.pem", "key_file": "/work/certs/client.key"}
            minted = self.call("/v1/auth/token/create", {"policies": ["kronik-m23"], "ttl": "1h"})
            write(self.root / "token", minted["auth"]["client_token"])
            self.alternate["token"] = {"address": self.base, "key": "kronik", "auth": "token", "token_file": "/work/token", "ca_file": "/work/certs/ca.pem"}
            self.call("/v1/sys/auth/approle", {"type": "approle"}, status=204)
            self.call("/v1/auth/approle/role/kronik", {"token_policies": ["kronik-m23"]}, status=204)
            write(self.root / "role-id", self.call("/v1/auth/approle/role/kronik/role-id")["data"]["role_id"])
            write(self.root / "secret-id", self.call("/v1/auth/approle/role/kronik/secret-id", {})["data"]["secret_id"])
            self.alternate["approle"] = {"address": self.base, "key": "kronik", "auth": "approle", "role_id_file": "/work/role-id", "secret_id_file": "/work/secret-id", "ca_file": "/work/certs/ca.pem"}
            self.evidence["kms_checks"].append("verified HTTPS + trusted cert login; missing/untrusted client identity rejected")
        elif name == "aws":
            self.key = self.kms("CreateKey", {"KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT"})["KeyMetadata"]["Arn"]
            self.config = {"region": "us-east-1", "key_id": self.key, "endpoint": self.base, "auth": "env"}
            self.alternate["imds"] = {**self.config, "auth": "imds", "imds_endpoint": self.auth.base}
            self.evidence["kms_checks"].append("moto real crypto; signature/IAM enforcement is not emulated")
        elif name == "gcp":
            self.headers = {"Authorization": "Bearer " + TOKEN}
            prefix = "/v1/projects/m23/locations/global/keyRings"
            self.call(prefix + "?keyRingId=kronik", {})
            self.call(prefix + "/kronik/cryptoKeys?cryptoKeyId=kronik", {"purpose": "ENCRYPT_DECRYPT"})
            self.key = "projects/m23/locations/global/keyRings/kronik/cryptoKeys/kronik"
            write(self.root / "service-account.json", json.dumps({"type": "service_account", "client_email": "kronik@m23.invalid", "private_key": (self.root / "oauth.key").read_text()}))
            self.config = {"key": self.key, "endpoint": self.base, "service_account_file": "/work/service-account.json", "token_endpoint": self.auth.base + "/gcp-token"}
            self.alternate["metadata"] = {"key": self.key, "endpoint": self.base, "metadata_endpoint": self.auth.base + "/gcp-metadata"}
            req = urllib.request.Request(self.auth.base + "/gcp-token", b"grant_type=wrong&assertion=invalid")
            try:
                urllib.request.urlopen(req, timeout=5)
                raise AssertionError("OAuth fixture accepted an invalid JWT")
            except urllib.error.HTTPError as e:
                assert e.code == 401
            self.evidence["kms_checks"].append("actual GCP KMS AES-GCM emulator; real IAM not emulated")
        else:
            self.headers = {"Authorization": "Bearer " + JWT}
            self.key = self.base + "/keys/kronik"
            created = self.call("/keys/kronik/create?api-version=7.4", {"kty": "RSA", "key_size": 2048, "key_ops": ["wrapKey", "unwrapKey"]})
            self.evidence["configured_key"] = self.key
            self.evidence["returned_kid"] = created["key"]["kid"]
            assert created["key"]["kid"].startswith(self.key + "/"), self.evidence["returned_kid"]
            write(self.root / "azure-secret", TOKEN)
            self.config = {"key": self.key, "tenant_id": "m23-tenant", "client_id": "m23-client", "client_secret_file": "/work/azure-secret", "authority_endpoint": self.auth.base, "ca_file": "/work/azure-certs/ca.pem"}
            self.alternate["metadata"] = {"key": self.key, "client_id": "m23-client", "metadata_endpoint": self.auth.base + "/azure-metadata", "ca_file": "/work/azure-certs/ca.pem"}
            self.evidence["kms_checks"].append("verified HTTPS + RSA-OAEP-256; emulator validates JWT syntax, not real IAM")
        wrapped = self.encrypt(DUMMY)
        assert self.decrypt(wrapped) == DUMMY
        wrong = {**wrapped, "aad": "wrong"}
        if name != "azure":
            assert self.decrypt(wrong, reject=True) is None
        self.evidence["kms_checks"].append("32-byte round trip" + (" + wrong AAD/context rejected" if name != "azure" else ""))

    def encrypt(self, seed):
        plain, aad = base64.b64encode(seed).decode(), base64.b64encode(AAD.encode()).decode()
        if self.name == "openbao":
            r = self.call("/v1/transit/encrypt/kronik", {"plaintext": plain, "context": aad})["data"]["ciphertext"]
            version = r.split(":")[1][1:]
        elif self.name == "aws":
            response = self.kms("Encrypt", {"KeyId": self.key, "Plaintext": plain, "EncryptionContext": {"purpose": AAD}})
            assert response["KeyId"] == self.key
            r, version = response["CiphertextBlob"], self.key
        elif self.name == "gcp":
            response = self.call("/v1/" + self.key + ":encrypt", {"plaintext": plain, "additionalAuthenticatedData": aad})
            r, version = response["ciphertext"], response["name"]
        else:
            kid = self.call("/keys/kronik?api-version=7.4")["key"]["kid"]
            assert kid.startswith(self.key + "/"), (self.key, kid)
            version = kid[len(self.key) + 1:]
            assert version and "/" not in version
            r = self.call("/keys/kronik/" + version + "/wrapkey?api-version=7.4", {"alg": "RSA-OAEP-256", "value": base64.urlsafe_b64encode(seed).decode().rstrip("=")})["value"]
        return {"ciphertext": r, "key_version": version, "aad": AAD}

    def decrypt(self, wrapped, reject=False):
        aad = base64.b64encode(wrapped["aad"].encode()).decode()
        status = (400, 500) if reject else 200
        if self.name == "openbao":
            r = self.call("/v1/transit/decrypt/kronik", {"ciphertext": wrapped["ciphertext"], "context": aad}, status)
            value = None if reject else r["data"]["plaintext"]
        elif self.name == "aws":
            r = self.kms("Decrypt", {"KeyId": self.key, "CiphertextBlob": wrapped["ciphertext"], "EncryptionContext": {"purpose": wrapped["aad"]}}, status)
            if not reject:
                assert r["KeyId"] == self.key
            value = None if reject else r["Plaintext"]
        elif self.name == "gcp":
            r = self.call("/v1/" + self.key + ":decrypt", {"ciphertext": wrapped["ciphertext"], "additionalAuthenticatedData": aad}, status)
            value = None if reject else r["plaintext"]
        else:
            r = self.call("/keys/kronik/" + wrapped["key_version"] + "/unwrapkey?api-version=7.4", {"alg": "RSA-OAEP-256", "value": wrapped["ciphertext"]})
            value = r["value"]
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)) if value is not None else None

    def rotate(self):
        if self.name == "openbao":
            self.call("/v1/transit/keys/kronik/rotate", {}, status=(200, 204))
        elif self.name == "gcp":
            version = self.call("/v1/" + self.key + "/cryptoKeyVersions", {})["name"].rsplit("/", 1)[1]
            self.call("/v1/" + self.key + ":updatePrimaryVersion", {"cryptoKeyVersionId": version})
        elif self.name == "azure":
            self.call("/keys/kronik/create?api-version=7.4", {"kty": "RSA", "key_size": 2048, "key_ops": ["wrapKey", "unwrapKey"]})
        # AWS KMS rotation retains the immutable ARN; re-encryption still produces fresh ciphertext.

    def close(self):
        if self.auth:
            self.evidence["auth_requests"] = self.auth.counts
            self.auth.close()
        if self.host_net is not None:
            os.setns(self.host_net, 0)
            os.close(self.host_net)
            self.host_net = None
        remove(self.container, self.root / "provider.log")


class Runtime:
    def __init__(self, provider, binary, tag):
        self.p, self.name = provider, tag + "-runtime-" + provider.name
        self.daemons = []
        docker_start(self.name, RUNTIME, ["-c", "exec sleep 2147483647"],
                     ["--user", "0:0", "--entrypoint", "/bin/sh",
                      "--mount", f"type=bind,source={binary},target=/kronik,readonly",
                      "--mount", f"type=bind,source={provider.root},target=/work",
                      "--mount", "type=bind,source=/etc/ssl/certs/ca-certificates.crt,target=/etc/ssl/certs/ca-certificates.crt,readonly",
                      "--env", "KRONIK_DISK_RESERVE=0B", "--env", "KRONIK_LOG=info",
                      "--env", "AWS_ACCESS_KEY_ID=test", "--env", "AWS_SECRET_ACCESS_KEY=test",
                      "--env", "AWS_REGION=us-east-1"], network="container:" + provider.container, memory="768m")

    def cli(self, *args, ok=True, env=None, json_output=True):
        flags = [v for k, value in (env or {}).items() for v in ("--env", k + "=" + value)]
        r = command("docker", "exec", *flags, self.name, "/kronik", *(["--json"] if json_output else []), *args, check=False, timeout=150)
        assert (r.returncode == 0) == ok, (args[:3], r.returncode, r.stdout, r.stderr)
        return json.loads(r.stdout) if json_output else r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")

    def config(self, name, provider=None, shipping=False, file_mode=False):
        text = f'[server]\ndata_dir = "/work/{name}/data"\napi_socket = "/work/{name}.sock"\n\n[log]\ndisk_reserve = "0B"\n\n[foreign]\nrun_dir = "/work/foreign-run"\n'
        if not file_mode:
            text += f'\n[keys]\nsource = "{self.p.name}"\nstart_timeout = "2s"\n\n[keys.{self.p.name}]\n'
            text += "".join(f"{key} = {json.dumps(value)}\n" for key, value in (provider or self.p.config).items())
        if shipping:
            text += '\n[ship]\nenabled = true\nurl = "file:///work/bucket"\n'
        text += f'\n[audit]\nsink = "file:///work/{name}/audit"\nhold_release = "1MiB"\n'
        write(self.p.root / (name + ".toml"), text)
        return "/work/" + name + ".toml"

    def start(self, config, name=None, env=None):
        daemon = Daemon(self, config, name, env)
        self.daemons.append(daemon)
        return daemon

    def close(self):
        for daemon in self.daemons:
            daemon.stop()
        remove(self.name, self.p.root / "runtime.log")


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=30)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class Daemon:
    def __init__(self, runtime, config, name, env):
        self.runtime, self.config = runtime, config
        self.name = name or Path(config).stem
        self.socket = runtime.p.root / (self.name + ".sock")
        self.log = runtime.p.root / (self.name + ".log")
        flags = [v for key, value in (env or {}).items() for v in ("--env", key + "=" + value)]
        self.output = self.log.open("wb")
        self.process = subprocess.Popen(["docker", "exec", *flags, runtime.name, "/bin/sh", "-c",
             'echo "$$" > "$1"; shift; exec /kronik "$@"', "kronik", "/work/" + self.name + ".pid",
             "serve", "--config", config, "--http-listen", "127.0.0.1:0", "--admin-listen", "127.0.0.1:0",
             "--api-socket", "/work/" + self.name + ".sock"], stdout=self.output, stderr=subprocess.STDOUT)

    def ready(self):
        def healthy():
            if self.process.poll() is not None:
                raise AssertionError(self.log.read_text(errors="replace"))
            try:
                return self.api("GET", "/v1/health", status=None)[0] == 200
            except (OSError, http.client.HTTPException):
                return False
        wait_for(self.name + " healthy", healthy, 120)
        return self

    def rejected(self, *codes):
        self.process.wait(timeout=30)
        self.output.close()
        text = self.log.read_text(errors="replace")
        assert self.process.returncode != 0 and any(
            re.search(r"(?<![A-Z_])" + re.escape(code) + r"(?![A-Z_])", text) for code in codes
        ), text

    def api(self, method, path, data=None, token=None, status=200):
        with contextlib.closing(UnixConnection(self.socket)) as conn:
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            conn.request(method, path, body=None if data is None else json.dumps(data), headers=headers)
            response = conn.getresponse()
            value = json.loads(response.read())
            if status is None:
                return response.status, value
            assert response.status == status, (method, path, response.status, value)
            return value

    def send(self, actor, name, text):
        return self.api("POST", "/v1/actors/" + actor + "/messages", {"name": name, "text": text, "reason": REASON})

    def hmac(self):
        return self.send("counter/h", "hmac", "api-key\nsome data")["reply"]["text"]

    def sealed(self):
        values = self.api("GET", "/v1/actors/counter/on")["state"]
        return next(value["text"] for value in values if value["key"] == "s")

    def stop(self):
        if self.process.poll() is None:
            pid = (self.runtime.p.root / (self.name + ".pid")).read_text().strip()
            command("docker", "exec", self.runtime.name, "/bin/sh", "-c", 'kill -TERM "$1"', "kronik", pid, check=False)
            self.process.wait(timeout=30)
        self.output.close()


def assert_memory(runtime, daemon, seed):
    namespace_pid = int((runtime.p.root / (daemon.name + ".pid")).read_text())
    owned_pids = command("docker", "top", runtime.name, "-eo", "pid").stdout.decode().splitlines()[1:]
    pid = next(int(value.strip()) for value in owned_pids
               if re.search(r"^NSpid:\s+(?:\d+\s+)*" + str(namespace_pid) + r"\s*$",
                            Path("/proc", value.strip(), "status").read_text(), re.M))
    smaps = Path(f"/proc/{pid}/smaps").read_text()
    pages = []
    locked_regions = 0
    page_size = os.sysconf("SC_PAGE_SIZE")
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as memory:
        for region in re.split(r"(?=^[0-9a-f]+-[0-9a-f]+ )", smaps, flags=re.M):
            if not region:
                continue
            flags = re.search(r"^VmFlags:\s+(.*)$", region, re.M).group(1).split()
            if "lo" not in flags:
                continue
            assert "dd" in flags, "locked key mapping is dumpable"
            locked_regions += 1
            start, end = (int(value, 16) for value in region.split()[0].split("-"))
            for address in range(start, end, page_size):
                memory.seek(address)
                pages.append(memory.read(32) == seed)
    assert sum(pages) == 1, "did not find exactly one actual-seed page in locked non-dumpable memory"
    return {"actual_seed_mapping_locked": True, "actual_seed_mapping_dontdump": True,
            "locked_key_pages": len(pages), "locked_regions": locked_regions}


def no_plaintext(root, seed):
    needles = (seed, seed.hex().encode(), base64.b64encode(seed))
    for path in root.rglob("*"):
        if path.is_file() and not path.is_socket():
            data = path.read_bytes()
            assert not any(needle in data for needle in needles), f"plaintext seed persisted: {path}"


def product(runtime, counter):
    p, root, checks = runtime.p, runtime.p.root, runtime.p.evidence["product_checks"]
    config = runtime.config("a")
    a = runtime.start(config).ready()
    status = runtime.cli("--socket", "/work/a.sock", "keys", "status")
    assert status["source"] == p.name and status["check_ok"]
    wrapper = root / "a/data/keys/master.wrapped"
    original = wrapper.read_bytes()
    seed = p.decrypt(json.loads(original))
    assert len(seed) == 32
    a.api("POST", "/v1/deployments", {"wasm_base64": base64.b64encode(counter.read_bytes()).decode(), "reason": REASON})
    a.api("PUT", "/v1/secrets/api-key", {"text": SECRET, "reason": REASON})
    a.api("POST", "/v1/grants", {"kind": "counter", "capability": "secret:api-key", "reason": REASON})
    a.api("POST", "/v1/privacy/mode", {"mode": "on", "reason": REASON})
    a.send("counter/on", "subject", "")
    mac = a.hmac()
    assert a.sealed() == "personal"
    p.evidence["memory"] = assert_memory(runtime, a, seed)
    no_plaintext(root, seed)
    assert not list((root / "a").rglob("master.key"))
    checks.append("fresh KMS initialization + secret HMAC + sealed value + actual key mapping flags + no plaintext seed on disk")

    a.api("POST", "/v1/keys/rewrap", {"reason": "", "dry_run": True}, status=400)
    tokens = {}
    for scope in ("read", "operate"):
        tokens[scope] = a.api("POST", "/v1/tokens", {"name": "keys-" + scope, "scopes": [scope], "reason": REASON})["secret"]
    assert a.api("GET", "/v1/keys", token=tokens["read"])["check_ok"]
    key_audit_before = [line for line in a.api("GET", "/v1/audit?limit=1000")["lines"] if line["action"].startswith("keys.")]
    command("docker", "pause", p.container)
    try:
        for token in tokens.values():
            started = time.monotonic()
            a.api("POST", "/v1/keys/rewrap", {"reason": REASON, "dry_run": False}, token=token, status=403)
            assert time.monotonic() - started < 1, "scope denial reached the unavailable provider"
    finally:
        command("docker", "unpause", p.container, check=False)
    assert wrapper.read_bytes() == original
    assert [line for line in a.api("GET", "/v1/audit?limit=1000")["lines"] if line["action"].startswith("keys.")] == key_audit_before
    checks.append("read/operate tokens denied rewrap immediately with provider unavailable; read token can inspect key status")
    before = wrapper.read_bytes()
    dry = runtime.cli("--socket", "/work/a.sock", "keys", "rewrap", "--reason", REASON, "--dry-run")
    assert dry["dry_run"] and wrapper.read_bytes() == before
    assert [line for line in a.api("GET", "/v1/audit?limit=1000")["lines"] if line["action"].startswith("keys.")] == key_audit_before
    a.stop()
    # Block this run's keystore destination, not any host service or unrelated bucket.
    (root / "bucket").mkdir()
    write(root / "bucket/keystore", "owned fault injection\n")
    config = runtime.config("a", shipping=True)
    a = runtime.start(config).ready()
    wait_for("independent encrypted wrapper upload", lambda: bool(list((root / "bucket/wrapped").glob("*.wrapped"))))
    ship_file = root / "a/data/ship.json"
    ship_state = json.loads(ship_file.read_text())
    assert ship_state["keystore_backup_ms"] is None and ship_state["keystore_stamp"] is None
    (root / "bucket/keystore").unlink()
    wait_for("unchanged keystore retries failed publication", lambda: bool(list((root / "bucket/keystore").glob("*.bin"))))
    for backup in (root / "bucket/keystore").glob("*.bin"):
        assert backup.with_suffix(".wrapped").exists(), "keystore .bin committed before its wrapper"
    checks.append("failed paired wrapper publication does not commit .bin/stamp; unchanged keystore retries")

    bins_before = set((root / "bucket/keystore").glob("*.bin"))
    independent_before = (root / "bucket/wrapped/current.wrapped").read_bytes()
    old_version = json.loads(wrapper.read_bytes())["key_version"]
    p.rotate()
    changed = a.api("POST", "/v1/keys/rewrap", {"reason": REASON, "dry_run": False})
    assert not changed["dry_run"] and changed["keys"]["check_ok"] and wrapper.read_bytes() != before
    assert p.decrypt(json.loads(wrapper.read_bytes())) == seed
    if p.name != "aws":
        assert json.loads(wrapper.read_bytes())["key_version"] != old_version
    wait_for("rewrap upload without keystore change", lambda: (root / "bucket/wrapped/current.wrapped").read_bytes() != independent_before)
    assert set((root / "bucket/keystore").glob("*.bin")) == bins_before
    checks.append("audited online rewrap + provider version change (AWS immutable ARN) + independent wrapper shipping")

    command("docker", "pause", p.container)
    try:
        a.api("POST", "/v1/actors/counter/outage/messages",
              {"name": "store", "text": "outage personal", "subject": "m23:outage", "reason": REASON})
        assert a.hmac() == mac and a.sealed() == "personal"
        assert a.api("GET", "/v1/keys")["check_ok"]
        runtime.start(config, name="concurrent").rejected("UNAVAILABLE")
        missing = runtime.config("outage-new")
        runtime.start(missing).rejected("KEY_SOURCE_UNAVAILABLE")
        assert not list((root / "outage-new").rglob("master.key"))
        wait_for("new subject-key backup during KMS outage", lambda: set((root / "bucket/keystore").glob("*.bin")) != bins_before, 100)
        snap = a.api("POST", "/v1/snapshots", {"reason": REASON})["snapshot"]["lsn"]
        wait_for("snapshot upload during KMS outage", lambda: snap in json.loads(ship_file.read_text()).get("snapshots", []))
    finally:
        command("docker", "unpause", p.container, check=False)
    checks.append("loaded daemon, secret reads, new subject keys, snapshot and keystore shipping survive KMS outage; fresh start fails closed")

    upgraded = runtime.cli("upgrade", "check", "--config", config, "--dry-run", "--workers", "1")
    assert upgraded["passed"] and upgraded["turns"] > 0
    # The export cursor bounds verification; it may lag the current log by one batch.
    report = runtime.cli("audit", "verify", "--config", config)
    assert report["complete"]
    audit = a.api("GET", "/v1/audit?limit=1000")
    assert any(line["action"] == "keys.rewrap" and line["reason"] == REASON for line in audit["lines"])
    integrity = a.api("GET", "/v1/integrity")
    a.stop()
    checks.append("offline upgrade check opens sealed history; offline audit verify opens keyed-hash audit data")

    # Refused restores must leave even a --force destination byte-for-byte alone.
    bad_config = runtime.config("bad-restore")
    victim = root / "bad-restore/data"
    write(victim / "sentinel", "must survive failed restore\n")
    bad = json.loads(wrapper.read_bytes())
    bad["aad"] = "wrong"
    write(victim / "keys/master.wrapped", json.dumps(bad))
    before_files = {str(path.relative_to(victim)): path.read_bytes() for path in victim.rglob("*") if path.is_file()}
    # Corrupt only this run's newest independent wrapper; restore must not skip it silently.
    newest = max((root / "bucket/wrapped").glob("*.wrapped"), key=lambda path: path.name)
    held = newest.read_bytes()
    newest.write_text(json.dumps(bad))
    try:
        runtime.cli("restore", "--from", "file:///work/bucket", "--config", bad_config, "--force", ok=False)
        assert before_files == {str(path.relative_to(victim)): path.read_bytes() for path in victim.rglob("*") if path.is_file()}
    finally:
        newest.write_bytes(held)
    restore_name = "b restore" if p.name == "openbao" else "b"
    restored_config = runtime.config(restore_name)
    restore_args = ["restore", "--from", "file:///work/bucket", "--config", restored_config,
                    "--data-dir", "/work/" + restore_name + "/data"]
    if p.name == "openbao":
        p.evidence["human_restore_dry_run"] = runtime.cli(*restore_args, "--dry-run", json_output=False)
        assert not (root / restore_name).exists()
        p.evidence["human_restore"] = runtime.cli(*restore_args, json_output=False)
    else:
        restored = runtime.cli(*restore_args)
        assert restored["keystore"] == "installed"
    b = runtime.start(restored_config).ready()
    restored_integrity = b.api("GET", "/v1/integrity?through=" + str(integrity["applied_lsn"]))
    assert not restored_integrity["keys_missing"]
    assert restored_integrity["log_hash"] == integrity["log_hash"]
    assert restored_integrity["state_hash"] == integrity["state_hash"]
    p.evidence["integrity"] = {"source": integrity, "restored_before_new_root": restored_integrity}
    assert b.hmac() == mac and b.sealed() == "personal"
    outage = b.api("GET", "/v1/actors/counter/outage")["state"]
    assert next(value["text"] for value in outage if value["key"] == "stored") == "outage personal"
    b.stop()
    no_plaintext(root, seed)
    assert not list((root / restore_name).rglob("master.key"))
    checks.append("fresh restore from shipped encrypted material reads secrets/sealed values and matches log prefix; corrupt wrapper failure preserves --force target")

    held = wrapper.read_bytes()
    wrapper.unlink()
    try:
        runtime.start(config, name="missing-wrapper").rejected("MASTER_KEY_MISSING")
        assert not (root / "a/data/keys/master.key").exists()
    finally:
        wrapper.write_bytes(held)
    checks.append("missing envelope on existing encrypted stores never regenerates a key")

    for variant, provider_config in p.alternate.items():
        alternate = runtime.config("auth-" + variant, provider_config)
        node = runtime.start(alternate).ready()
        assert node.api("GET", "/v1/keys")["check_ok"]
        node.stop()
        checks.append("real provider operations via " + variant + " credentials")
    if p.name == "gcp":
        assert p.auth.counts.get("gcp_rs256_verified", 0) > 0 and p.auth.counts.get("gcp_metadata", 0) > 0
        checks.append("GCP OAuth fixture cryptographically verified actual RS256 JWT signature/iss/scope/aud/iat/exp; invalid assertion rejected")
    if p.name == "openbao":
        invalid_ca = {**p.config, "ca_file": "/work/certs/untrusted.pem"}
        runtime.start(runtime.config("untrusted-ca", invalid_ca)).rejected("KEY_SOURCE_UNAVAILABLE")
        invalid_id = {**p.config, "cert_file": "/work/certs/untrusted.pem", "key_file": "/work/certs/untrusted.key"}
        runtime.start(runtime.config("untrusted-client", invalid_id)).rejected("KEY_SOURCE_UNAVAILABLE")
        checks.append("Kronik provider rejects wrong CA and untrusted client identity without plaintext fallback")

    for migration, env, remove_file in [("legacy-file", {}, False), ("legacy-remove", {}, True),
                                        ("legacy-env", {"KRONIK_MASTER_KEY": "5a" * 32}, False)]:
        human = p.name == "openbao" and migration == "legacy-env"
        if human:
            migration = "legacy env"
        legacy_config = runtime.config(migration, file_mode=True)
        node = runtime.start(legacy_config, env=env).ready()
        effective = runtime.cli("--socket", "/work/" + migration + ".sock", "keys", "status", env=env)
        assert effective["source"] == ("env" if env else "file") and effective["check_ok"]
        node.api("PUT", "/v1/secrets/migration", {"text": SECRET, "reason": REASON})
        node.stop()
        master = root / migration / "data/keys/master.key"
        old_bytes = master.read_bytes() if master.exists() else None
        target_config = runtime.config(migration)
        args = ["keys", "wrap", "--source", p.name, "--reason", REASON + " " + SECRET]
        if human:
            env = {**env, "KRONIK_CONFIG": target_config}
            args += ["--data-dir", "/work/" + migration + "/data"]
        else:
            args += ["--config", target_config]
        if remove_file:
            args += ["--remove-file"]
        if human:
            p.evidence["human_wrap_dry_run"] = runtime.cli(*args, "--dry-run", env=env, json_output=False)
            assert SECRET not in p.evidence["human_wrap_dry_run"] and env["KRONIK_MASTER_KEY"] not in p.evidence["human_wrap_dry_run"]
        else:
            dry = runtime.cli(*args, "--dry-run", env=env)
            assert dry["dry_run"]
        assert not (root / migration / "data/keys/master.wrapped").exists()
        assert (master.read_bytes() if master.exists() else None) == old_bytes
        if human:
            p.evidence["human_wrap"] = runtime.cli(*args, env=env, json_output=False)
            assert SECRET not in p.evidence["human_wrap"] and env["KRONIK_MASTER_KEY"] not in p.evidence["human_wrap"]
        else:
            wrapped = runtime.cli(*args, env=env)
            assert not wrapped["dry_run"] and wrapped["keys"]["check_ok"]
        assert master.exists() == (old_bytes is not None and not remove_file)
        marker = root / migration / "data/keys/key-source.json"
        assert marker.is_file() and SECRET.encode() not in marker.read_bytes()
        for path in (root / migration / "data").rglob("*"):
            if path.is_file():
                assert SECRET.encode() not in path.read_bytes(), "wrap marker persisted an existing secret in its reason"
        node = runtime.start(target_config).ready()  # Old seed environment is deliberately absent.
        assert node.api("GET", "/v1/keys")["check_ok"]
        node.stop()
        for path in (root / migration).rglob("*"):
            if path.is_file():
                assert SECRET.encode() not in path.read_bytes(), "migrated startup/audit persisted a secret reason"
        assert SECRET not in node.log.read_text(errors="replace")
    checks.append("offline file/env migration: dry-run writes no envelope, default preserves old file, explicit --remove-file removes it, KMS restart validates existing stores")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--dir", type=Path, help="new private output directory; never reuses existing data")
    parser.add_argument("--only", default="openbao,aws,gcp,azure", help="comma-separated provider subset")
    parser.add_argument("--probe-only", action="store_true", help="only emulator capability checks; no Kronik acceptance claim")
    args = parser.parse_args()
    providers = args.only.split(",")
    if not providers or len(providers) != len(set(providers)) or any(name not in IMAGES for name in providers):
        parser.error("--only must name unique providers: openbao,aws,gcp,azure")
    if sys.platform != "linux" or os.geteuid() != 0 or not hasattr(os, "setns"):
        parser.error("needs Linux root and Python 3.12+ for isolated network-namespace entry")
    binary = args.bin.resolve()
    if not args.probe_only and (not binary.is_file() or not os.access(binary, os.X_OK)):
        parser.error("--bin must be an already-built executable static Linux Kronik binary")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = args.dir.resolve() if args.dir else Path(tempfile.mkdtemp(prefix="kronik-m23-keys.", dir="/var/tmp"))
    if args.dir:
        root.mkdir(mode=0o700, parents=False)
    tag = "kronik-m23-" + str(os.getpid()) + "-" + root.name.rsplit(".", 1)[-1].lower()
    results = {"schema": "kronik.m23-keys-acceptance/v1", "directory": str(root), "run_tag": tag,
               "binary": str(binary), "runtime_image": RUNTIME, "probe_only": args.probe_only, "providers": {}}
    image(RUNTIME)
    failures = []
    print("Artifacts:", root, flush=True)
    try:
        for name in providers:
            provider, runtime = None, None
            try:
                # Allocate before bootstrap so failures still close owned namespaces/resources.
                provider = Provider.__new__(Provider)
                provider.root, provider.container = root / name, tag + "-" + name
                provider.host_net, provider.auth = None, None
                provider.evidence = {}
                Provider.__init__(provider, name, root / name, tag)
                if not args.probe_only:
                    runtime = Runtime(provider, binary, tag)
                    product(runtime, Path(__file__).resolve().parent.parent / "tests/guests/counter.wasm")
                provider.evidence["passed"] = True
                print("PASS", name, "emulator capabilities" if args.probe_only else "KMS lifecycle", flush=True)
            except Exception as error:
                failures.append(name)
                provider.evidence.update({"passed": False, "error": str(error)})
                print("FAIL", name, str(error), file=sys.stderr, flush=True)
            finally:
                try:
                    if runtime:
                        runtime.close()
                finally:
                    if provider:
                        provider.close()
                        results["providers"][name] = provider.evidence
                    write(root / "results.json", json.dumps(results, indent=2, sort_keys=True) + "\n")
    finally:
        cleanup_errors = []
        for name in list(OWNED):
            try:
                remove(name, root / (name + ".log"))
            except Exception as error:
                cleanup_errors.append(str(error))
        remaining = None
        selector = "^/" + re.escape(tag) + "-"
        try:
            remaining = command("docker", "ps", "--all", "--filter", "label=kronik.m23.acceptance",
                                "--filter", "name=" + selector, "--format", "{{.Names}}").stdout.decode().splitlines()
        except Exception as error:
            cleanup_errors.append(str(error))
        clean = remaining == [] and not OWNED and not cleanup_errors
        results["cleanup"] = {"verified": clean, "created": sorted(CREATED), "remaining_owned": remaining,
                              "name_filter": selector, "label_filter": "kronik.m23.acceptance", "errors": cleanup_errors}
        results["passed"] = (sys.exc_info()[0] is None and clean and len(results["providers"]) == len(providers)
                             and all(value.get("passed", False) for value in results["providers"].values()))
        write(root / "results.json", json.dumps(results, indent=2, sort_keys=True) + "\n")
        assert clean, "owned container cleanup failed; see results.json (no global cleanup attempted)"
    print("Evidence:", root / "results.json", flush=True)
    return bool(failures)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
    raise SystemExit(main())
