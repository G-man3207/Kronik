#!/usr/bin/env python3
"""Finite, synthetic M27 browser acceptance; NEVER a human identity proof.

Dependencies (no auto-install): Python 3.11+, cryptography, PyJWT, an OS sandbox, Node,
Google Chrome, @playwright/test and axe-core. Packages default to ui/node_modules;
--playwright/--axe explicitly select existing installations. Missing dependencies
fail without auto-install. Run only prebuilt KRONIK_BIN/guest files.

Example (inside an integrator-owned isolated-loopback sandbox):
  python3 scripts/e2e-ui-oidc.py --sandboxed --binary /absolute/path/kronik \
    --node /path/to/node \
    --playwright /path/to/node_modules/@playwright/test \
    --axe /path/to/node_modules/axe-core/axe.min.js \
    --chrome /usr/bin/google-chrome --timeout 600 --artifacts /private/new-directory

--live-fixture accepts a PRIVATE JSON file describing an already-running,
OWNED integrated local fixture: {"owned_synthetic_fixture":true,"origin":
"https://localhost:9443","gateway":"https://localhost:9444",
"socket":"/private/fixture/api.sock"}. Its OIDC issuer
must use --issuer-port, client kronik-ui, and the CA/certificate in
--fixture-root. First start --provider-only --fixture-root PRIVATE0700_DIR
--origin https://localhost:ADMINPORT --timeout 600 in the same sandbox; wait
for its readiness line, then start the integrated product using that CA and
bindings fixture-reviewer -> ui-reviewer, fixture-reader -> ui-reader,
fixture-revoked -> ui-revoked. Live mode attaches to that owned provider and
stops it on completion; its finite owner removes scratch. The socket MUST
belong to that fresh disposable fixture: ui-reviewer/ui-reader/ui-revoked token
names must not exist yet. Its valid initial OIDC file must use the real issuer
and fixture-root/excluded-native-root/ca.pem, not the provider's actual CA.
The manifest also requires "restart_command":["/private/fixture/owned-supervisor"].
This single executable must be private, owned, absolute and inside --fixture-root.
It runs INSIDE the same sandbox, never against host code or an existing service.
It is invoked without a shell, appending PROFILE UNREACHABLE_ISSUER EXCLUDED_CA.
PROFILE is "unreachable" (startup file matches the admitted unreachable issuer,
actual provider CA), "mismatch" (real issuer, excluded CA), or "correct" (real
issuer and actual provider CA). Both CA paths are inside the owned fixture root.
The owned supervisor must retain the node's original root/master/node-key
environment privately: no secrets/environment in this manifest or argv.
It changes only that valid startup profile, restarts only its own disposable node
and exits successfully. Each restart plus independently checked Unix/TLS readiness
has one 45-second limit; the whole runner remains bounded by --timeout <=600.
It additionally requires "data_dir":"/private/fixture/data" (read-only inspection)
and "approval_fault_command":["/private/fixture/owned-approval-fault"]. The latter
has the same private/owned/in-root executable requirements and receives only
MODE OPAQUE_PRINCIPAL, with MODE exactly "missing" or "restore". It MUST stop its
own disposable node, copy its private data, remove ONLY that principal's
subject_keys rows IN THE COPY (not an erasure), and start that copy; "restore"
returns to the untouched original. No customer/live keys or existing services.
The runner independently asserts real ordinary API200, pii-authorized historical
API503, no-PII API200/opaque origins/absent payload, then restored exact historical
pair API200. Each switch has a 45-second cap; the entire fault phase a 90-second
cap inside the same overall deadline. Missing/echo-only capabilities fail closed.
Both protected OIDC approval rows and a real native approval's legacy fields
1–6/absent field 7 are matched byte-for-byte in the WAL using the existing house
wire reader. The native proposal is separate and created only after OIDC
approvals alone changed the product. Only assertion IDs/counts/digests/statuses persist.
Synthetic deployments/policy/proposals are really written. Live mode must already
run inside the operator's enforced network/filesystem/resource sandbox; it never
discovers or probes another endpoint. Full acceptance requires an actual member
with at least three members and healthy leader/shard metadata. Standalone mode
intentionally fails that final gate; it never claims partial data as full proof.

Default guest inputs are the existing test-actor builds counter-respond.wasm
(--features respond) and counter-step2.wasm (--features step2). Both retain the
public increment route (one then two); removing respond in the candidate
produces a genuine changed credential-header entry, not identical replay.
Build each explicitly, outside this runner, from tests/guests/test-actor:
  cargo build --locked --release --target wasm32-wasip2 \
    --target-dir target/respond --features respond
  cargo build --locked --release --target wasm32-wasip2 \
    --target-dir target/step2 --features step2
The corresponding inputs are target/{respond,step2}/wasm32-wasip2/release/
kronik_test_actor.wasm; pass --counter/--candidate to use those exact files.
The issuer uses 127.0.0.1 while the admin UI uses localhost: genuinely
cross-site top-level callbacks exercise SameSite=Lax without leaking host-only
application cookies to the owned provider.
The default owned daemon starts with exclusive CA2 while SSL_CERT_FILE trusts
the real issuer's CA1. Existing M5 Admin PUT /v1/auth/config admits/repairs OIDC;
three owned restarts prove unreachable-provider, valid-file/durable mismatch,
and already-admitted matching-profile startup recovery. Real browser positives
and bound stale-epoch grants precede all original
view/mutation/privacy/accessibility checks and the strict final cluster gate.
Use --timeout 600 for standalone; with a 600-second provider owner, use a shorter
live timeout (for example --timeout 540) leaving attachment/cleanup headroom.

Artifacts contain only assertion names/counts/digests/sanitized status codes,
never response bodies, cookies, JWTs, bearer tokens or browser traces. TLS keys and product state are private
scratch and removed on exit (except explicit --prepare-only fixture material).
"""

import argparse
import base64
from contextlib import nullcontext
import datetime
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import resource
import re
import runpy
import secrets
import shutil
import signal
import select
import socket
import ssl
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from urllib.parse import parse_qs, urlencode, urlsplit
from types import SimpleNamespace

try:
    import jwt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    raise SystemExit("Missing Python cryptography/PyJWT; provision explicitly (no auto-install).")

ROOT = Path(__file__).resolve().parent.parent
SCOPES = ["read", "fork", "propose", "approve", "promote", "operate", "pii:read", "admin"]
MODES = {"valid", "issuer", "audience", "nonce", "state", "keys", "signature", "expired", "reader", "unmapped", "revoked"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    path.chmod(0o600)


def tls(root):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Kronik synthetic fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
          .not_valid_after(now + datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
          .sign(key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(name).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    for filename, content in {"ca.pem": ca.public_bytes(serialization.Encoding.PEM),
                              "server.pem": cert.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM),
                              "server.key": server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())}.items():
        path = root / filename
        path.write_bytes(content)
        path.chmod(0o600)


class Provider:
    def __init__(self, root, port, origin):
        self.issuer = f"https://127.0.0.1:{port}"
        self.redirect = origin + "/v1/auth/callback"
        self.control = secrets.token_urlsafe(32)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.codes = {}
        self.mode = "valid"
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.stats = {"authorizations": 0, "exchanges": 0, "pkce_verified": 0, "rejections": 0, "app_cookie_observed": 0}
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "KronikSyntheticOIDC"

            def log_message(self, *args):
                pass  # URLs contain authorization codes; never log them.

            def reply(self, status, value=None, location=None):
                data = json.dumps(value).encode() if value is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = urlsplit(self.path).path
                if any(name + "=" in self.headers.get("Cookie", "") for name in
                       ["__Host-kronik-session", "__Host-kronik-login"]):
                    with fixture.lock:
                        fixture.stats["app_cookie_observed"] += 1
                if path == "/synthetic":
                    return self.reply(200, {"synthetic_fixture": True, "value": 27})
                if path == "/.well-known/openid-configuration":
                    return self.reply(200, {"issuer": fixture.issuer, "authorization_endpoint": fixture.issuer + "/authorize",
                                           "token_endpoint": fixture.issuer + "/token", "jwks_uri": fixture.issuer + "/jwks",
                                           "response_types_supported": ["code"], "subject_types_supported": ["public"],
                                           "id_token_signing_alg_values_supported": ["RS256"],
                                           "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"]})
                if path == "/jwks":
                    public = fixture.key.public_key().public_numbers()
                    return self.reply(200, {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "fixture-key",
                                                      "n": b64(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
                                                      "e": b64(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big"))}]})
                if path != "/authorize":
                    return self.reply(404, {"error": "not_found"})
                try:
                    q = parse_qs(urlsplit(self.path).query, strict_parsing=True)
                except ValueError:
                    return self.reply(400, {"error": "invalid_request"})
                def one(name):
                    values = q.get(name, [])
                    return values[0] if len(values) == 1 else ""
                if not (one("client_id") == "kronik-ui" and one("response_type") == "code" and
                        one("redirect_uri") == fixture.redirect and one("code_challenge_method") == "S256" and
                        re.fullmatch(r"[A-Za-z0-9_-]{43}", one("code_challenge")) and len(one("state")) >= 16 and len(one("nonce")) >= 16 and
                        "openid" in one("scope").split()):
                    fixture.stats["rejections"] += 1
                    return self.reply(400, {"error": "invalid_request"})
                with fixture.lock:
                    code = secrets.token_urlsafe(32)
                    fixture.codes[code] = {"challenge": one("code_challenge"), "nonce": one("nonce"),
                                           "mode": fixture.mode, "expires": time.monotonic() + 30}
                    fixture.stats["authorizations"] += 1
                    state = "invalid-fixture-state" if fixture.mode == "state" else one("state")
                return self.reply(302, location=fixture.redirect + "?" + urlencode({"code": code, "state": state}))

            def do_POST(self):
                if any(name + "=" in self.headers.get("Cookie", "") for name in
                       ["__Host-kronik-session", "__Host-kronik-login"]):
                    with fixture.lock:
                        fixture.stats["app_cookie_observed"] += 1
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    return self.reply(400, {"error": "invalid_request"})
                if length < 1 or length > 8192:
                    return self.reply(400, {"error": "invalid_request"})
                body = self.rfile.read(length)
                if self.path == "/fixture/control":
                    if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + fixture.control):
                        return self.reply(403, {"error": "forbidden"})
                    try:
                        mode = json.loads(body)["mode"]
                        require(mode in MODES or mode == "stop", "invalid mode")
                    except (ValueError, KeyError, TypeError, RuntimeError):
                        return self.reply(400, {"error": "invalid_mode"})
                    with fixture.lock:
                        fixture.mode = mode
                    if mode == "stop":
                        fixture.stop_event.set()
                    return self.reply(200, {"mode": mode, "stats": dict(fixture.stats)})
                if self.path != "/token":
                    return self.reply(404, {"error": "not_found"})
                if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
                    return self.reply(400, {"error": "invalid_request"})
                try:
                    q = parse_qs(body.decode("ascii"), strict_parsing=True)
                except ValueError:
                    return self.reply(400, {"error": "invalid_request"})
                def one(name):
                    values = q.get(name, [])
                    return values[0] if len(values) == 1 else ""
                with fixture.lock:
                    item = fixture.codes.pop(one("code"), None)
                if not (item and item["expires"] > time.monotonic() and one("grant_type") == "authorization_code" and
                        one("client_id") == "kronik-ui" and one("redirect_uri") == fixture.redirect and
                        re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", one("code_verifier")) and
                        hmac.compare_digest(b64(hashlib.sha256(one("code_verifier").encode()).digest()), item["challenge"])):
                    fixture.stats["rejections"] += 1
                    return self.reply(400, {"error": "invalid_grant"})
                fixture.stats["exchanges"] += 1
                fixture.stats["pkce_verified"] += 1
                mode = item["mode"]
                now = int(time.time())
                subject = {"reader": "fixture-reader", "unmapped": "fixture-unmapped", "revoked": "fixture-revoked"}.get(mode, "fixture-reviewer")
                claims = {"iss": fixture.issuer, "aud": "kronik-ui", "sub": subject, "iat": now, "exp": now + 300,
                          "nonce": item["nonce"], "scope": " ".join(SCOPES), "fixture_not_human": True}
                if mode == "issuer":
                    claims["iss"] = fixture.issuer + "/wrong"
                if mode == "audience":
                    claims["aud"] = "wrong-client"
                if mode == "nonce":
                    claims["nonce"] = "wrong-nonce"
                if mode == "expired":
                    claims.update(iat=now - 600, exp=now - 300)
                header = {"typ": "JWT", "kid": "unknown-key" if mode == "keys" else "fixture-key"}
                signing_key = fixture.other_key if mode == "signature" else fixture.key
                token = jwt.encode(claims, signing_key, algorithm="RS256", headers=header)
                return self.reply(200, {"token_type": "Bearer", "access_token": secrets.token_urlsafe(32), "expires_in": 300, "id_token": token})

        class EffectHandler(Handler):
            def do_GET(self):
                if self.path != "/synthetic":
                    return self.reply(404, {"error": "not_found"})
                return self.reply(200, {"synthetic_fixture": True, "value": 27})

            def do_POST(self):
                return self.reply(405, {"error": "method_not_allowed"})

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        self.server.timeout = 1
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(root / "server.pem", root / "server.key")
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.effects = ThreadingHTTPServer(("127.0.0.1", port + 3), EffectHandler)
        self.effects.daemon_threads = True
        self.effect_thread = threading.Thread(target=self.effects.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        self.effect_thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.effects.shutdown()
        self.effects.server_close()
        self.effect_thread.join(timeout=2)


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=5)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def unix_reply(path, method, route, body=None):
    connection = UnixHTTP(path)
    try:
        connection.request(method, route, json.dumps(body).encode() if body is not None else None, {"Content-Type": "application/json"})
        response = connection.getresponse()
        return response.status, json.loads(response.read(16 << 20))
    finally:
        connection.close()


def unix_json(path, method, route, body=None):
    status, value = unix_reply(path, method, route, body)
    require(status == 200, f"Owned Unix API operation failed: {method} {route} ({status})")
    return value


def approval_storage_proof(data, principal, proposal, lsns, issuer, native):
    # Reuse the maintained house Approval/Audit wire reader, not a second codec.
    fields = runpy.run_path(str(ROOT / "scripts/e2e-github-flow.py"))["wire_fields"]
    database = private_file(data / "branches/main/state.db")
    payloads = []
    protected_identities = []
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        connection.execute("PRAGMA query_only=ON")
        for lsn in lsns:
            row = connection.execute("SELECT record FROM approvals WHERE lsn=? AND proposal_id=?", (lsn, proposal)).fetchone()
            require(row is not None, "approval-storage-exact-completed-row-required")
            record = bytes(row[0])
            approval = fields(record)
            audit = fields(approval[4])
            require(approval[1] == proposal.encode() and approval.get(5, 0) == 0 and audit[1] == principal.encode(),
                    "approval-storage-original-opaque-audit-owner")
            identity = fields(approval[7])
            require(identity.get(1) == principal.encode() and 2 not in identity and 3 in identity,
                    "approval-storage-field7-always-sealed-even-privacy-OFF")
            sealed = fields(identity[3])
            require(sealed.get(1, 0) > 0 and len(sealed.get(2, b"")) == 24 and len(sealed.get(3, b"")) >= 16,
                    "approval-storage-authenticated-sealed-envelope")
            require(issuer.encode() not in record and b"fixture-reviewer" not in record,
                    "approval-storage-no-plaintext-verified-pair")
            payloads.append(record)
            protected_identities.append(approval[7])
        row = connection.execute("SELECT record FROM approvals WHERE lsn=? AND proposal_id=?",
                                 (native["lsn"], native["proposal"])).fetchone()
        require(row is not None, "native-approval-exact-completed-producer-row-required")
        native_record = bytes(row[0])
        native_fields = fields(native_record)
        native_audit = fields(native_fields[4])
        require(native_fields[1] == native["proposal"].encode() and
                set(native_fields).issubset({1, 2, 3, 4, 5, 6}) and
                native_audit[1].startswith(b"token:") and issuer.encode() not in native_record and
                b"spoof-native-verified" not in native_record,
                "actual-native-approval-retains-legacy-wire-fields-and-no-identity-payload")
        payloads.append(native_record)
    require(len(set(protected_identities)) == 2, "fresh-OFF-and-ON-sessions-have-distinct-protected-payloads")
    found = set()
    for segment in sorted((data / "branches/main/log").glob("*.seg")):
        private_file(segment)
        require(segment.stat().st_size <= 128 << 20, "approval-WAL-segment-resource-bound")
        image = segment.read_bytes()
        for index, payload in enumerate(payloads):
            if payload in image:
                found.add(index)
        if len(found) == len(payloads):
            break
    require(len(found) == len(payloads), "approval-WAL-contains-exact-OIDC-and-native-completed-records")
    return {"checks": ["approval-storage-original-opaque-audit-owner",
                       "approval-storage-field7-always-sealed-even-privacy-OFF",
                       "approval-storage-authenticated-sealed-envelope",
                       "approval-storage-no-plaintext-verified-pair",
                       "fresh-OFF-and-ON-sessions-have-distinct-protected-payloads",
                       "actual-native-approval-retains-legacy-wire-fields-and-no-identity-payload",
                       "approval-WAL-contains-exact-OIDC-and-native-completed-records"],
            "approvals": len(protected_identities), "native_legacy": True,
            "native_record_sha256": hashlib.sha256(native_record).hexdigest(),
            "record_sha256": [hashlib.sha256(value).hexdigest() for value in payloads]}

def gateway_cookie_storage_proof(data, request):
    require(set(request) == {"action", "turn", "session_value", "app_cookie"} and
            isinstance(request["turn"], str) and re.fullmatch(r"main:[1-9][0-9]{0,18}", request["turn"]) and
            isinstance(request["session_value"], str) and re.fullmatch(r"[A-Za-z0-9_:.-]{20,200}", request["session_value"]) and
            isinstance(request["app_cookie"], str) and re.fullmatch(r"m27-app-[a-f0-9]{32}", request["app_cookie"]),
            "exact-private-native-cookie-proof-request-required")
    lsn = int(request["turn"].split(":")[1])
    require(lsn < 1 << 63, "native-cookie-proof-LSN-bound")
    database = private_file(data / "branches/main/state.db")
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        row = connection.execute("SELECT segment,offset FROM turn_index WHERE lsn=? AND kind=? AND key=?",
                                 (lsn, "counter", "m27-cookie-boundary")).fetchone()
    require(row is not None, "browser-cookie-probe-has-real-retained-turn-index")
    segment, offset = row
    require(type(segment) is int and segment > 0 and type(offset) is int and offset >= 24,
            "browser-cookie-probe-has-real-native-log-position")
    log = private_file(data / "branches/main/log" / f"{segment:020}.seg")
    with log.open("rb") as stream:
        require(stream.read(8) == b"KRNK\x01\x00\x00\x00", "browser-cookie-probe-native-log-format")
        stream.seek(offset)
        header = stream.read(17)
        require(len(header) == 17, "browser-cookie-probe-complete-frame-header")
        size, _crc, actual_lsn, kind = struct.unpack("<IIQB", header)
        require(actual_lsn == lsn and kind == 3 and 0 < size <= 16 << 20,
                "browser-cookie-probe-exact-committed-turn-frame")
        record = stream.read(size)
    require(len(record) == size, "browser-cookie-probe-complete-frame")
    require(request["session_value"].encode() not in record,
            "browser-admin-session-credential-absent-from-real-guest-WAL")
    require(("m27app=" + request["app_cookie"]).encode() in record,
            "browser-ordinary-app-cookie-retained-in-real-privacy-OFF-WAL")
    return {"checks": ["browser-admin-session-credential-absent-from-real-guest-WAL",
                       "browser-ordinary-app-cookie-retained-in-real-privacy-OFF-WAL"],
            "record_sha256": hashlib.sha256(record).hexdigest()}



def stop_owned(process):
    if process is not None and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def limits():
    for kind, maximum in [(resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 180),
                          (resource.RLIMIT_FSIZE, 256 << 20), (resource.RLIMIT_NOFILE, 512)]:
        hard = resource.getrlimit(kind)[1]
        maximum = maximum if hard == resource.RLIM_INFINITY else min(maximum, hard)
        resource.setrlimit(kind, (maximum, maximum))
    # Chrome reserves a large virtual address range; RSS is bounded by the
    # enclosing integrator cgroup, not RLIMIT_AS (which prevents Chrome startup).


def private_file(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "Expected an owned regular fixture file")
    require(path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0, "Fixture file must be private and owned")
    return path


def loopback_url(value):
    url = urlsplit(value)
    require(url.scheme == "https" and url.hostname == "localhost" and url.port and not url.username and
            not url.password and url.path in ("", "/") and not url.query and not url.fragment, "Only explicit https://localhost:PORT fixture origins are accepted")
    return value.rstrip("/")


def provider_control(root, provider, mode):
    connection = http.client.HTTPSConnection("localhost", urlsplit(provider.issuer).port, timeout=5,
                                           context=ssl.create_default_context(cafile=str(root / "ca.pem")))
    try:
        connection.request("POST", "/fixture/control", json.dumps({"mode": mode}).encode(),
                           {"Content-Type": "application/json", "Authorization": "Bearer " + provider.control})
        response = connection.getresponse()
        require(response.status == 200, "Owned provider control failed")
        return json.loads(response.read(8192))
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", default=os.environ.get("KRONIK_BIN"))
    parser.add_argument("--playwright", default=str(ROOT / "ui/node_modules/@playwright/test"), help="Installed @playwright/test package directory; default: ui/node_modules, no auto-install")
    parser.add_argument("--axe", default=str(ROOT / "ui/node_modules/axe-core/axe.min.js"), help="Installed axe-core/axe.min.js; default: ui/node_modules, no auto-install")
    parser.add_argument("--chrome", default="/usr/bin/google-chrome")
    parser.add_argument("--node", default=shutil.which("node") or "/usr/bin/node")
    parser.add_argument("--artifacts", required=True, help="New private assertion-only output directory")
    parser.add_argument("--fixture-root", help="Empty private0700 scratch, or prepared owned provider scratch")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--provider-only", action="store_true", help="Finite TLS provider starts before an integrated live fixture; private root/provider.json is its attachment contract")
    parser.add_argument("--origin", help="Planned exact admin origin for --provider-only")
    parser.add_argument("--live-fixture", help="Private explicit owned integrated fixture manifest")
    parser.add_argument("--sandboxed", action="store_true", help="Already inside an operator-enforced isolated loopback sandbox with read-only code/tooling, scratch-only writes, cgroup memory/pid/disk limits")
    parser.add_argument("--stream-auth-only", action="store_true", help="Independent real cookie SSE/WS/logout consumer only; no guest/fork/body/model/kernel, not full M27 acceptance")
    parser.add_argument("--issuer-port", type=int, default=19443)
    parser.add_argument("--admin-port", type=int, default=19444)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--counter", default=str(ROOT / "tests/guests/counter-respond.wasm"), help="Real counter test guest built with respond; increment adds one")
    parser.add_argument("--candidate", default=str(ROOT / "tests/guests/counter-step2.wasm"), help="Real counter test guest whose increment adds two")
    args = parser.parse_args()
    require(30 <= args.timeout <= 600, "Timeout must be 30..600 seconds")
    require(all(1024 <= p <= 65532 for p in [args.issuer_port, args.admin_port]) and len({args.issuer_port, args.issuer_port + 3, args.admin_port, 19445}) == 4, "Distinct unprivileged issuer/effect/admin/gateway ports required")
    run_deadline = time.monotonic() + args.timeout
    def expired(_signal, _frame):
        raise RuntimeError("Fixture wall-clock deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, args.timeout)
    os.umask(0o077)
    artifacts = Path(args.artifacts).absolute()
    if not args.sandboxed:
        raise RuntimeError("Run in an enforced isolated-loopback sandbox and pass --sandboxed. Required: empty environment, read-only code/toolchain, scratch-only writable HOME/TMP, no external network, <=2 GiB RAM/256 pids/512 MiB disk/2 CPUs, <=600s wall time. No target process was launched.")
    require(args.prepare_only or args.provider_only or args.live_fixture or args.binary, "Supply --binary/KRONIK_BIN or --live-fixture")
    require(sum(bool(value) for value in [args.prepare_only, args.provider_only, args.live_fixture]) <= 1, "Select only one fixture lifecycle mode")
    require(not (args.live_fixture or args.provider_only) or args.fixture_root, "Provider/live mode requires --fixture-root")
    require(not args.stream_auth_only or not (args.prepare_only or args.provider_only),
            "Stream authentication focus requires an actual product, not a provider/preparation-only run")
    if not (args.prepare_only or args.provider_only):
        prerequisites = [("Node", args.node), ("Chrome", args.chrome),
                         ("Playwright", str(Path(args.playwright) / "package.json"))]
        if not args.stream_auth_only:
            prerequisites += [("axe-core", args.axe), ("counter guest", args.counter), ("candidate guest", args.candidate)]
        for name, path in prerequisites:
            require(Path(path).is_file(), f"Missing {name}: provision explicitly; no auto-install")
        require(os.access(args.node, os.X_OK) and os.access(args.chrome, os.X_OK), "Node and Chrome must be executable; provision explicitly, no auto-install")
    # Apply inherited limits before starting provider threads; preexec_fn is unsafe with threads.
    limits()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    root = Path(args.fixture_root).absolute() if args.fixture_root else Path(tempfile.mkdtemp(prefix="kronik-ui-", dir=artifacts.parent))
    require(root.is_dir() and not root.is_symlink() and root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o077 == 0, "Fixture root must be owned private0700")
    require(not root.is_relative_to(artifacts) and not artifacts.is_relative_to(root), "Fixture scratch and assertion artifacts must be separate directories")
    owner = root / "fixture-owner.json"
    if owner.exists():
        require(json.loads(private_file(owner).read_text()) == {"kind": "kronik-m27-synthetic", "root": str(root)}, "Refusing an unowned fixture directory")
    else:
        require(not any(root.iterdir()), "A new fixture root must be empty")
        save(owner, {"kind": "kronik-m27-synthetic", "root": str(root)})
    child = None
    node = None
    attached_provider = None
    lifecycle = None
    unused_port = None
    try:
        if not (root / "ca.pem").exists():
            tls(root)
        for name in ["ca.pem", "server.pem", "server.key"]:
            private_file(root / name)
        excluded = root / "excluded-native-root"
        if not excluded.exists():
            excluded.mkdir(mode=0o700)
            tls(excluded)
        require(excluded.is_dir() and not excluded.is_symlink() and
                excluded.stat().st_uid == os.getuid() and excluded.stat().st_mode & 0o077 == 0,
                "Excluded CA scratch must be owned private0700")
        for name in ["ca.pem", "server.pem", "server.key"]:
            private_file(excluded / name)
        if args.prepare_only:
            require(bool(args.fixture_root), "--prepare-only requires --fixture-root for later live setup")
            save(artifacts / "result.json", {"prepared": True, "synthetic_not_human": True})
            return
        if args.provider_only:
            origin = loopback_url(args.origin or f"https://localhost:{args.admin_port}")
            with Provider(root, args.issuer_port, origin) as provider:
                save(root / "provider.json", {"kind": "kronik-m27-provider", "issuer": provider.issuer,
                                             "origin": origin, "control": provider.control,
                                             "expires_at_ms": int(time.time() * 1000 + max(0, run_deadline - time.monotonic() - 3) * 1000)})
                print("Owned synthetic OIDC provider ready.", flush=True)
                provider.stop_event.wait(max(0, run_deadline - time.monotonic() - 3))
                save(artifacts / "provider-result.json", {"synthetic_not_human": True, "stats": provider.stats})
            return
        origin = f"https://localhost:{args.admin_port}"
        gateway = "https://localhost:19445"
        socket_path = str(root / "api.sock")
        data_dir = root / "data"
        if args.live_fixture:
            live = json.loads(private_file(args.live_fixture).read_text())
            require(live.get("owned_synthetic_fixture") is True, "Live mode requires an explicit owned synthetic fixture declaration")
            required = {"owned_synthetic_fixture", "origin", "socket", "data_dir"}
            if not args.stream_auth_only:
                required |= {"gateway", "restart_command", "approval_fault_command"}
            require(set(live) == required,
                    "Live manifest accepts only the exact owned coordinates and required supervisor capabilities")
            origin = loopback_url(live["origin"])
            gateway = loopback_url(live["gateway"]) if not args.stream_auth_only else origin
            socket_path = live["socket"]
            owned_socket = Path(socket_path)
            require(owned_socket.is_absolute() and owned_socket.resolve().is_relative_to(root.resolve()) and
                    owned_socket.is_socket() and not owned_socket.is_symlink() and owned_socket.stat().st_uid == os.getuid(),
                    "Owned live Unix API socket is missing or outside fixture root")
            require(owned_socket.parent.stat().st_uid == os.getuid() and owned_socket.parent.stat().st_mode & 0o077 == 0, "Live API socket parent must be owned private0700")
            data_dir = Path(live["data_dir"])
            require(data_dir.is_absolute() and data_dir.resolve().is_relative_to(root.resolve()) and
                    data_dir.is_dir() and not data_dir.is_symlink(), "Live data must be inside the owned fixture root")
            if not args.stream_auth_only:
                for name in ["restart_command", "approval_fault_command"]:
                    command = live.get(name)
                    require(isinstance(command, list) and len(command) == 1 and
                            isinstance(command[0], str) and "\0" not in command[0] and Path(command[0]).is_absolute(),
                            "Live recovery requires one absolute private owned capability executable")
                    executable = private_file(command[0])
                    require(executable.resolve().is_relative_to(root.resolve()) and os.access(executable, os.X_OK),
                            "Live capability must be executable inside the owned fixture root")
                restart_command = live["restart_command"]
                fault_command = live["approval_fault_command"]
        clean_env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "TMPDIR": str(root), "LANG": "C.UTF-8",
                     "SSL_CERT_FILE": str(root / "ca.pem"), "NODE_EXTRA_CA_CERTS": str(root / "ca.pem")}
        daemon_env = {**clean_env, "KRONIK_MASTER_KEY": secrets.token_hex(32)}
        if args.live_fixture:
            value = json.loads(private_file(root / "provider.json").read_text())
            require(value.get("kind") == "kronik-m27-provider" and value.get("issuer") == f"https://127.0.0.1:{args.issuer_port}" and value.get("origin") == origin,
                    "Live fixture does not match the owned finite provider")
            attached_provider = SimpleNamespace(issuer=value["issuer"], control=value["control"], stats={})
            require(value.get("expires_at_ms", 0) >= int(time.time() * 1000) + (args.timeout + 15) * 1000,
                    "Owned provider has insufficient lifetime; start a fresh --provider-only --timeout 600 fixture")
            provider_control(root, attached_provider, "valid")
        manager = nullcontext(attached_provider) if attached_provider else Provider(root, args.issuer_port, origin)
        # Reserve a real unused OWN loopback port without a listener or any probe.
        unused_port = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        unused_port.bind(("127.0.0.1", 0))
        unreachable_issuer = f"https://127.0.0.1:{unused_port.getsockname()[1]}"
        with manager as provider:
            if not args.live_fixture:
                binary = Path(args.binary).resolve()
                require(binary.is_file() and os.access(binary, os.X_OK), "Supply an executable prebuilt KRONIK_BIN")
                config = root / "kronik.toml"
                # JSON strings are valid TOML basic strings for these local paths.
                q = json.dumps
                base_config = f'[server]\ndata_dir={q(str(root / "data"))}\napi_socket={q(socket_path)}\nhttp_listen="127.0.0.1:19445"\nadmin_listen="127.0.0.1:{args.admin_port}"\n[tls]\nmode="files"\ncert_file={q(str(root / "server.pem"))}\nkey_file={q(str(root / "server.key"))}\n[log]\ndisk_reserve="0B"\n[oidc]\nissuer={q(provider.issuer)}\nclient_id="kronik-ui"\nredirect_uri={q(origin + "/v1/auth/callback")}\nca_file={q(str(root / "ca.pem"))}\n' + ''.join(f'[[oidc.bindings]]\nsubject="fixture-{subject}"\ntoken="ui-{token}"\n' for subject, token in [("reviewer", "reviewer"), ("reader", "reader"), ("revoked", "revoked")])
                def write_startup(profile):
                    text = base_config
                    if profile == "unreachable":
                        text = text.replace(f'issuer={q(provider.issuer)}', f'issuer={q(unreachable_issuer)}')
                    elif profile == "mismatch":
                        text = text.replace(f'ca_file={q(str(root / "ca.pem"))}', f'ca_file={q(str(excluded / "ca.pem"))}')
                    config.write_text(text)
                    config.chmod(0o600)
                write_startup("mismatch")
            def wait_ready(deadline=None):
                deadline = min(run_deadline, deadline if deadline is not None else time.monotonic() + 25)
                while True:
                    require(time.monotonic() < deadline, "Ordinary Unix/TLS API readiness timed out")
                    if child is not None:
                        require(child.poll() is None, "Product exited before ordinary API readiness")
                    try:
                        unix_json(socket_path, "GET", "/v1/auth/config")
                        parsed = urlsplit(origin)
                        ready = http.client.HTTPSConnection("localhost", parsed.port, timeout=1,
                            context=ssl.create_default_context(cafile=str(root / "ca.pem")))
                        try:
                            ready.request("GET", "/v1/auth/session")
                            response = ready.getresponse()
                            require(response.status == 200, "Admin session endpoint did not become ready")
                            response.read(8192)
                        finally:
                            ready.close()
                        return
                    except (OSError, http.client.HTTPException):
                        require(time.monotonic() < deadline, "Ordinary Unix/TLS API readiness timed out")
                        time.sleep(0.1)
            def launch_daemon(ready_deadline=None, startup_config=None):
                nonlocal child
                # Reuse exactly the same environment and protected data on every restart.
                child = subprocess.Popen([str(binary), "serve", "--config", str(startup_config or config)], cwd=root, env=daemon_env,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                wait_ready(ready_deadline)
            if not args.live_fixture:
                launch_daemon()
            else:
                wait_ready()
            secrets_in_memory = {}
            for name, scopes in [("reviewer", SCOPES), ("reader", ["read"]), ("revoked", ["read", "approve"])]:
                value = unix_json(socket_path, "POST", "/v1/tokens", {"name": "ui-" + name, "scopes": scopes, "reason": "Synthetic M27 fixture bootstrap; not a human", "dry_run": False})
                require(isinstance(value.get("secret"), str), "Token bootstrap did not return its one-time secret")
                secrets_in_memory[name] = value["secret"]
            certificate = x509.load_pem_x509_certificate((root / "server.pem").read_bytes())
            spki = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            manifest = {"origin": origin, "issuer": provider.issuer, "control": provider.control,
                        "gateway": gateway, "tls_spki": base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii"),
                        "playwright": str(Path(args.playwright).resolve()), "axe": str(Path(args.axe).resolve()),
                        "chrome": str(Path(args.chrome).resolve()), "artifacts": str(artifacts),
                        "counter": str(Path(args.counter).resolve()), "candidate": str(Path(args.candidate).resolve()),
                        "ca": str(root / "ca.pem"), "excluded_ca": str(excluded / "ca.pem"),
                        "socket": socket_path, "bearer": secrets_in_memory["reader"],
                        "admin_bearer": secrets_in_memory["reviewer"], "unreachable_issuer": unreachable_issuer,
                        "effect": f"http://127.0.0.1:{args.issuer_port + 3}",
                        "timeout_ms": max(1000, int((run_deadline - time.monotonic() - 5) * 1000))}
            if args.stream_auth_only:
                manifest.update(focus="stream-auth", stream_source="metadata" if args.live_fixture else "actor-native")
            node = subprocess.Popen([args.node, str(ROOT / "scripts/test-ui-browser.cjs")],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    cwd=root, env=clean_env, start_new_session=True)
            node.stdin.write(json.dumps(manifest).encode() + b"\n")
            node.stdin.flush()
            restart_order = iter(["unreachable", "mismatch", "correct"])
            approval_protection_done = False
            gateway_cookie_protection_done = False
            def prove_approval_protection(request):
                nonlocal child, lifecycle
                principal, proposal, lsns, native = request["principal"], request["proposal"], request["lsns"], request["native"]
                require(set(request) == {"action", "principal", "proposal", "lsns", "native"} and
                        isinstance(principal, str) and re.fullmatch(r"oidc:[a-f0-9]{64}", principal) and
                        isinstance(proposal, str) and re.fullmatch(r"p-[A-Za-z0-9_-]{1,128}", proposal) and
                        isinstance(lsns, list) and len(lsns) == 2 and
                        all(type(lsn) is int and 0 < lsn < (1 << 63) for lsn in lsns) and len(set(lsns)) == 2 and
                        isinstance(native, dict) and set(native) == {"proposal", "lsn"} and
                        isinstance(native["proposal"], str) and re.fullmatch(r"p-[A-Za-z0-9_-]{1,128}", native["proposal"]) and
                        native["proposal"] != proposal and type(native["lsn"]) is int and
                        0 < native["lsn"] < (1 << 63) and native["lsn"] not in lsns,
                        "approval-fault-exact-owned-principal-and-completed-LSNs-required")
                fault_deadline = min(run_deadline, time.monotonic() + 90)
                signal.setitimer(signal.ITIMER_REAL, max(0.001, fault_deadline - time.monotonic()))
                report = approval_storage_proof(data_dir, principal, proposal, lsns, provider.issuer, native)
                key_path = private_file(data_dir / "keys/keystore.db")
                def key_rows():
                    with sqlite3.connect(key_path.as_uri() + "?mode=ro", uri=True) as database:
                        return database.execute("SELECT version,nonce,wrapped,created_wall_ms FROM subject_keys WHERE subject=? ORDER BY version",
                                                (principal,)).fetchall()
                original_key_rows = key_rows()
                original_keys = len(original_key_rows)
                require(original_keys > 0, "approval-original-subject-key-exists-before-private-copy-fault")
                fault_root = None
                if not args.live_fixture:
                    fault_root = Path(tempfile.mkdtemp(prefix="approval-key-fault-", dir=root))
                def switch(mode):
                    nonlocal child, lifecycle
                    deadline = min(fault_deadline, time.monotonic() + 45)
                    signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
                    if args.live_fixture:
                        lifecycle = subprocess.Popen([*fault_command, mode, principal], cwd=root, env=clean_env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
                        require(lifecycle.wait(timeout=max(0.1, deadline - time.monotonic())) == 0,
                                "owned-private-copy-key-fault-capability-failed")
                        wait_ready(deadline)
                    else:
                        stop_owned(child)
                        if mode == "missing":
                            files = list(data_dir.rglob("*"))
                            require(all(not path.is_symlink() for path in files) and
                                    sum(path.stat().st_size for path in files if path.is_file()) <= 192 << 20,
                                    "approval-private-data-copy-ownership-and-resource-bound")
                            copy = fault_root / "data"
                            shutil.copytree(data_dir, copy)
                            with sqlite3.connect(copy / "keys/keystore.db") as database:
                                require(database.execute("SELECT count(*) FROM erasures WHERE subject=?", (principal,)).fetchone()[0] == 0,
                                        "missing-key-fault-is-not-subject-erasure")
                                removed = database.execute("DELETE FROM subject_keys WHERE subject=?", (principal,)).rowcount
                                require(removed == original_keys, "private-copy-removes-only-exact-opaque-subject-keys")
                            original = config.read_text()
                            marker = "data_dir=" + json.dumps(str(data_dir))
                            require(original.count(marker) == 1, "owned-fault-config-has-exact-data-root")
                            fault_config = fault_root / "kronik.toml"
                            fault_config.write_text(original.replace(marker, "data_dir=" + json.dumps(str(copy)), 1))
                            fault_config.chmod(0o600)
                            launch_daemon(deadline, fault_config)
                        else:
                            launch_daemon(deadline)
                    require(time.monotonic() < deadline, "owned-private-key-fault-switch-exceeded-45-seconds")
                    signal.setitimer(signal.ITIMER_REAL, max(0.001, fault_deadline - time.monotonic()))
                try:
                    switch("missing")
                    status, _ = unix_reply(socket_path, "GET", "/v1/proposals/" + proposal)
                    require(status == 503, "real-authorized-historical-read-fails-closed-with-missing-private-copy-key")
                    unix_json(socket_path, "GET", "/v1/actors")
                    connection = http.client.HTTPSConnection("localhost", urlsplit(origin).port, timeout=5,
                        context=ssl.create_default_context(cafile=str(root / "ca.pem")))
                    try:
                        connection.request("GET", "/v1/proposals/" + proposal,
                            headers={"Authorization": "Bearer " + secrets_in_memory["reader"]})
                        response = connection.getresponse()
                        public = json.loads(response.read(16 << 20))
                        require(response.status == 200 and all(any(
                            row["lsn"] == lsn and row["token_id"] == principal and "verified_identity" not in row
                            for row in public["approvals"]) for lsn in lsns),
                            "missing-key-no-PII-read-still-has-opaque-origin-without-payload")
                    finally:
                        connection.close()
                finally:
                    try:
                        switch("restore")
                    finally:
                        if fault_root is not None:
                            shutil.rmtree(fault_root)
                require(key_rows() == original_key_rows, "original-keystore-unchanged-by-private-copy-key-fault")
                restored = unix_json(socket_path, "GET", "/v1/proposals/" + proposal)
                require(all(any(row["lsn"] == lsn and row["token_id"] == principal and
                            row.get("verified_identity") == {"state": "VERIFIED", "issuer": provider.issuer, "subject": "fixture-reviewer"}
                            for row in restored["approvals"]) for lsn in lsns),
                        "original-keystore-restores-exact-authenticated-historical-pair")
                report["checks"].extend(["real-authorized-historical-read-fails-closed-with-missing-private-copy-key",
                    "missing-key-no-PII-read-still-has-opaque-origin-without-payload",
                    "original-keystore-unchanged-by-private-copy-key-fault",
                    "original-keystore-restores-exact-authenticated-historical-pair"])
                report.update(missing_key_status=503, restored_status=200)
                save(artifacts / "approval-protection-result.json", report)
                signal.setitimer(signal.ITIMER_REAL, max(0.001, run_deadline - time.monotonic()))
                return {"ok": True, "approvals": 2, "native_legacy": True, "missing_key_status": 503, "restored_status": 200}
            while True:
                remaining = run_deadline - time.monotonic()
                require(remaining > 0, "Browser acceptance deadline exceeded")
                readable, _, _ = select.select([node.stdout], [], [], remaining)
                require(readable, "Browser acceptance deadline exceeded")
                line = node.stdout.readline(1024)
                if not line:
                    node.wait(timeout=max(1, run_deadline - time.monotonic()))
                    break
                require(len(line) < 512, "Bounded private browser lifecycle request required")
                request = json.loads(line)
                require(not args.stream_auth_only,
                        "Independent stream authentication never invokes recovery, approval/key-fault or kernel lifecycle capabilities")
                if isinstance(request, dict) and request.get("action") == "gateway_cookie_protection":
                    require(not gateway_cookie_protection_done and next(restart_order, None) is None,
                            "cookie-protection-follows-all-owned-recovery-restarts-exactly-once")
                    report = gateway_cookie_storage_proof(data_dir, request)
                    save(artifacts / "gateway-cookie-protection-result.json", report)
                    gateway_cookie_protection_done = True
                    node.stdin.write(b'{"ok":true,"recorded":true}\n')
                    node.stdin.flush()
                    continue
                if isinstance(request, dict) and request.get("action") == "approval_protection":
                    require(not approval_protection_done and next(restart_order, None) is None,
                            "approval-protection-follows-all-owned-recovery-restarts-exactly-once")
                    result = prove_approval_protection(request)
                    approval_protection_done = True
                    node.stdin.write(json.dumps(result).encode() + b"\n")
                    node.stdin.flush()
                    continue
                profile = next(restart_order, None)
                require(profile is not None and request == {"action": "restart", "profile": profile},
                        "Unexpected private browser lifecycle request")
                restart_deadline = min(run_deadline, time.monotonic() + 45)
                signal.setitimer(signal.ITIMER_REAL, max(0.001, restart_deadline - time.monotonic()))
                if args.live_fixture:
                    lifecycle = subprocess.Popen([*restart_command, profile, unreachable_issuer, str(excluded / "ca.pem")],
                        cwd=root, env=clean_env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, start_new_session=True)
                    require(lifecycle.wait(timeout=max(0.1, restart_deadline - time.monotonic())) == 0,
                            "Owned integrated fixture restart failed")
                    wait_ready(restart_deadline)
                else:
                    stop_owned(child)
                    write_startup(profile)
                    launch_daemon(restart_deadline)
                require(time.monotonic() < restart_deadline, "Owned restart readiness exceeded 45 seconds")
                signal.setitimer(signal.ITIMER_REAL, max(0.001, run_deadline - time.monotonic()))
                node.stdin.write(b'{"ok":true}\n')
                node.stdin.flush()
            node.stdin.close()
            browser_error = node.stderr.read(65536)
            # Driver/crash output can include URLs; promote only bounded IDs/source locations.
            messages = [line for line in browser_error.decode(errors="replace").splitlines()
                        if re.fullmatch(r"Assertion failed: [A-Za-z0-9_ /:,{}.-]{1,240}|Source: /work/scripts/test-ui-browser\.cjs:[0-9]+:[0-9]+|browser-acceptance-timeout|browser-cleanup-failed", line)]
            require(node.returncode == 0, "Browser acceptance failed: " + ("; ".join(messages[-3:]) or "nonzero exit; private details withheld"))
            if args.stream_auth_only:
                require(not approval_protection_done and not gateway_cookie_protection_done,
                        "Independent stream focus must not exercise full guest/approval/key-fault acceptance")
                if attached_provider:
                    provider.stats = provider_control(root, provider, "valid")["stats"]
                require(provider.stats["pkce_verified"] >= 2 and provider.stats["app_cookie_observed"] == 0,
                        "Stream cookie consumers require actual separate admin/reader PKCE logins without credential leakage")
                report = json.loads(private_file(artifacts / "browser-stream-auth-result.json").read_text())
                require(report.get("full_acceptance") is False and report.get("no_guest_fork_kernel_body_model_or_key_fault") is True,
                        "Independent stream evidence cannot claim full M27 or stopped fork/kernel work")
                save(artifacts / "oidc-stream-auth-result.json",
                     {"synthetic_not_human": True, "full_acceptance": False, "scope": "independent-cookie-stream-authentication-only",
                      "stats": provider.stats})
                print("Independent M27/M30 cookie stream authentication passed; not full M27 acceptance.")
                return
            require(approval_protection_done, "actual-stored-approval-protection-and-private-key-fault-proof-required")
            require(gateway_cookie_protection_done, "actual-browser-admin-cookie-guest-WAL-isolation-proof-required")
            if attached_provider:
                provider.stats = provider_control(root, provider, "valid")["stats"]
            require(provider.stats["pkce_verified"] >= 10, "Full PKCE exchanges were not observed")
            require(provider.stats["app_cookie_observed"] == 0, "Host-only application credentials reached the cross-site provider")
            save(artifacts / "oidc-result.json", {"synthetic_not_human": True, "stats": provider.stats})
            print("M27 synthetic browser/OIDC acceptance passed; assertion-only artifacts written.")
    finally:
        for process in [node, lifecycle, child]:
            stop_owned(process)
        if unused_port is not None:
            unused_port.close()
        if attached_provider:
            provider_control(root, attached_provider, "stop")
        elif not args.prepare_only:
            shutil.rmtree(root)


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print("Owned fixture interrupted; private process cleanup requested.", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        # Never print HTTP responses, subprocess output or credential-bearing URLs.
        if isinstance(error, RuntimeError):
            print(str(error), file=sys.stderr)
        else:
            print("Fixture failed: " + type(error).__name__ + " (private state discarded)", file=sys.stderr)
        for frame in traceback.extract_tb(error.__traceback__)[-6:]:
            if Path(frame.filename).parent == ROOT / "scripts":
                print(f'File "{frame.filename}", line {frame.lineno}', file=sys.stderr)
        sys.exit(1)
