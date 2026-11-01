#!/usr/bin/env python3
"""Finite M29 real-binary proof, with a real SNAT hop and no published ports.

KRONIK_BIN must name an already-built Linux binary. The already-present official
debian:13-slim image uses the host's public /usr, /lib and /lib64 read-only as a
fixture toolchain. Nothing is downloaded, built or installed. Requires root and
a local Docker daemon with isolated bridge networking. Only the owned router
retains NET_ADMIN; installation route-init drops every capability before serve.
Both networks are internal, and no host home, configuration or socket is mounted.
All credentials and roots are disposable FIXTURES, never product-generated roots.
Failure summaries retain only fixed phase/error codes, owned-container state and
packet/event counts before disposable private scratch is removed.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

CAP = 1_048_576
IMAGE = "debian:13-slim"
PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DROP = ["/usr/bin/setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all"]
URL = "https://controller.test:8443"
REASON = "owned M29 acceptance"
OWNER = "kronik.m29.acceptance"

# Runs inside the isolated installation, not against a host/public API listener.
UNIX_REQUEST = r'''
import base64, hashlib, http.client, json, socket, sys
request = json.load(sys.stdin)
class Unix(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(5)
        self.sock.connect('/work/api.sock')
headers = {'Content-Type': 'application/json'}
if request.get('bearer_file'):
    with open(request['bearer_file'], 'r', encoding='ascii') as source:
        headers['Authorization'] = 'Bearer ' + source.read(4096)
connection = Unix('localhost', timeout=5)
body = None if request.get('body') is None else json.dumps(request['body']).encode()
connection.request(request.get('method', 'GET'), request['path'], body, headers)
response = connection.getresponse()
raw = response.read(1048577)
if len(raw) > 1048576:
    raise ValueError('response bound')
try:
    value = json.loads(raw)
except ValueError:
    value = None
print(json.dumps({'status': response.status, 'value': value, 'body_sha256': hashlib.sha256(raw).hexdigest()}))
connection.close()
'''


def write(path, value):
    data = value.encode() if isinstance(value, str) else value
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)
    os.chmod(path, 0o600)


class Proof:
    def __init__(self, binary, image, scratch):
        self.root = Path(tempfile.mkdtemp(prefix="kronik-m29-", dir=scratch)).resolve()
        self.root.chmod(0o700)
        self.binary, self.image = binary, image
        self.id = "m29-" + uuid.uuid4().hex[:12]
        self.containers, self.networks = [], []
        self.env = {"PATH": PATH, "HOME": str(self.root), "LANG": "C.UTF-8"}
        self.install = self.root / "installation"
        self.controller = self.root / "controller"
        self.install.mkdir(mode=0o700)
        self.controller.mkdir(mode=0o700)
        self.install_name = self.id + "-installation"
        self.controller_name = self.id + "-controller"
        self.router_name = self.id + "-router"
        self.phase = "setup"
        self.cli_failures = []
        self.last_state_phase = None

    def run(self, *arguments, data=None, check=True, timeout=30):
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (CAP, CAP))
            resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        with tempfile.TemporaryFile(dir=self.root) as out, tempfile.TemporaryFile(dir=self.root) as err:
            result = subprocess.run([str(a) for a in arguments], input=data, stdout=out, stderr=err,
                                    env=self.env, timeout=timeout, preexec_fn=limits)
            out.seek(0)
            err.seek(0)
            result.stdout, result.stderr = out.read(CAP), err.read(CAP)
        if check and result.returncode:
            raise AssertionError("owned command failed: " + Path(str(arguments[0])).name + " exit " + str(result.returncode))
        return result

    def docker(self, *arguments, **kwargs):
        return self.run("docker", *arguments, **kwargs)

    def inspect(self, kind, name):
        return json.loads(self.docker(kind, "inspect", name).stdout)[0]

    def wait(self, description, predicate, seconds=45):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.1)
        raise AssertionError("timed out: " + description)

    def create(self, name, network, address, command, mounts=(), extra=(), memory="512m"):
        arguments = ["create", "--pull=never", "--name", name, "--label", OWNER + "=" + self.id,
                     "--network", network, "--ip", address, "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--pids-limit=256", "--cpus=1",
                     "--memory=" + memory, "--memory-swap=" + memory,
                     "--ulimit", "core=0:0", "--ulimit", "nofile=1024:1024",
                     "--tmpfs", "/tmp:rw,nosuid,size=64m", "--env", "HOME=/tmp",
                     "--env", "PATH=" + PATH, "--env", "KRONIK_LOG=error",
                     "--log-driver=json-file", "--log-opt=max-size=256k", "--log-opt=max-file=1"]
        toolchain = [(Path(path), path, True) for path in ("/usr", "/lib", "/lib64")]
        for source, destination, readonly in [*toolchain, *mounts]:
            arguments += ["--mount", "type=bind,src=" + str(source) + ",dst=" + destination + (",readonly" if readonly else "")]
        arguments += list(extra) + [self.image] + list(command)
        self.containers.append(name)
        self.docker(*arguments)

    def remove_container(self, name):
        if name not in self.containers:
            return
        info = self.inspect("container", name)
        if info["Config"].get("Labels", {}).get(OWNER) != self.id:
            raise AssertionError("container ownership changed")
        self.docker("rm", "--force", name)
        self.containers.remove(name)

    def network(self, suffix):
        name = self.id + suffix
        self.networks.append(name)
        self.docker("network", "create", "--internal", "--label", OWNER + "=" + self.id, name)
        info = self.inspect("network", name)
        assert info["Internal"] is True
        subnet = ipaddress.ip_network(info["IPAM"]["Config"][0]["Subnet"])
        assert subnet.version == 4 and subnet.is_private
        return name, subnet

    def openssl(self, *arguments):
        return self.run("openssl", *arguments, timeout=10).stdout

    def pki(self):
        for stem in ("realm", "wrong"):
            key = self.controller / (stem + ".key")
            self.openssl("genpkey", "-algorithm", "ED25519", "-out", key)
            key.chmod(0o600)
            self.openssl("req", "-new", "-x509", "-key", key, "-days", "2", "-subj", "/CN=owned-fleet-" + stem,
                         "-addext", "basicConstraints=critical,CA:TRUE",
                         "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", self.controller / (stem + ".pem"))
            (self.controller / (stem + ".pem")).chmod(0o600)
        self.openssl("genpkey", "-algorithm", "ED25519", "-out", self.controller / "server.key")
        (self.controller / "server.key").chmod(0o600)
        self.openssl("req", "-new", "-key", self.controller / "server.key", "-subj", "/CN=controller.test",
                     "-out", self.controller / "server.csr")
        write(self.controller / "server.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:controller.test\n")
        self.openssl("x509", "-req", "-in", self.controller / "server.csr", "-CA", self.controller / "realm.pem",
                     "-CAkey", self.controller / "realm.key", "-set_serial", "1", "-days", "2",
                     "-extfile", self.controller / "server.ext", "-out", self.controller / "server.pem")
        der = self.openssl("x509", "-in", self.controller / "realm.pem", "-outform", "DER")
        ca_hash = hashlib.sha256(len(der).to_bytes(8, "big") + der).hexdigest()
        self.plan = {"controller_url": URL, "identity": {"installation": "owned-fleet-installation", "node": "owned-node", "cluster": None},
                     "scopes": ["read"], "ca_sha256": ca_hash}
        write(self.controller / "plan.json", json.dumps(self.plan))

    def configure(self, wrong_ca=False, scopes=None):
        write(self.install / "realm.pem", (self.controller / ("wrong.pem" if wrong_ca else "realm.pem")).read_bytes())
        allowed = ["read"] if scopes is None else scopes
        write(self.install / "kronik.toml", '[server]\ndata_dir="/work/data"\napi_socket="/work/api.sock"\nhttp_listen="127.0.0.1:18080"\nadmin_listen="127.0.0.1:19464"\n[log]\ndisk_reserve="0B"\n[foreign]\nrun_dir="/work/foreign-run"\n[fleet]\nurl="' + URL + '"\nca_file="/work/realm.pem"\ninstallation="owned-fleet-installation"\nnode="owned-node"\nscopes=' + json.dumps(allowed) + '\n')

    def install_exec(self, *arguments, **kwargs):
        interactive = ["-i"] if kwargs.get("data") is not None else []
        return self.docker("exec", *interactive, self.install_name, *DROP, *arguments, **kwargs)

    def start_installation(self):
        self.docker("start", self.install_name)
        self.wait("ordinary API socket", lambda: self.install_exec("python3", "-c",
                  "import os,sys;sys.exit(0 if os.path.exists('/work/api.sock') else 1)", check=False).returncode == 0)
        self.wait("ordinary API readiness", lambda: self.api("/v1/health", allow_unready=True).get("status") == 200)
        observe = ("import json; wanted={'CapEff','CapPrm','CapInh','CapAmb','CapBnd','NoNewPrivs'};"
                   "values=dict(line.split(':',1) for line in open('/proc/1/status') if ':' in line);"
                   "print(json.dumps({k:values[k].strip() for k in wanted}))")
        self.daemon_security = json.loads(self.install_exec("python3", "-c", observe).stdout)
        assert self.daemon_security["NoNewPrivs"] == "1", "daemon lost no-new-privileges"
        assert all(int(self.daemon_security[name], 16) == 0 for name in
                   ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")), "actual daemon retained capabilities"

    def api(self, path, method="GET", body=None, bearer_file=None, allow_unready=False):
        request = {"path": path, "method": method, "body": body, "bearer_file": bearer_file}
        result = self.install_exec("python3", "-c", UNIX_REQUEST,
                             data=json.dumps(request).encode(), check=not allow_unready, timeout=10)
        if allow_unready and result.returncode:
            return {}
        return json.loads(result.stdout)

    def cli(self, *arguments, succeeds=True):
        result = self.install_exec("/opt/kronik", "--socket", "/work/api.sock", "--json",
                             "fleet", *arguments, check=False, timeout=45)
        if result.returncode:
            code = "UNCLASSIFIED"
            for raw in (result.stdout, result.stderr):
                try:
                    value = json.loads(raw)
                    error = value.get("error", value) if isinstance(value, dict) else {}
                    candidate = error.get("code") if isinstance(error, dict) else None
                    if candidate in {"BAD_REQUEST", "UNAUTHENTICATED", "UNAVAILABLE", "INTERNAL", "SCOPE_MISSING"}:
                        code = candidate
                except (ValueError, TypeError):
                    pass
            self.cli_failures.append({"phase": self.phase, "exit_code": result.returncode,
                                      "code": code, "observations": self.observation_summary()})
            self.cli_failures = self.cli_failures[-8:]
        assert (result.returncode == 0) == succeeds, "fleet CLI exit did not match the expected transition"
        if not succeeds:
            return None
        value = json.loads(result.stdout)
        state = value.get("state") if isinstance(value, dict) else None
        phase = state.get("phase") if isinstance(state, dict) else None
        if phase in {"pending", "requested", "active", "revoked", None}:
            self.last_state_phase = phase
        return value

    def events(self, event=None, request_id=None):
        path = self.controller / "observations.jsonl"
        if not path.exists():
            return []
        assert path.stat().st_size < CAP
        values = [json.loads(line) for line in path.read_text().splitlines() if line]
        return [v for v in values if (event is None or v["event"] == event) and (request_id is None or v.get("request_id") == request_id)]

    def observation_summary(self):
        names = {"tls_failure", "enrollment_http_start", "enrollment_plan_mismatch",
                 "enrollment_rejected", "enrollment_request", "issuer_step", "issuer_failure",
                 "issuer_environment", "issuer_tool_error",
                 "enrollment_admitted", "enrollment_reply_lost", "stream_open", "stream_closed",
                 "http_result", "sse_http", "sse_event", "ws_http", "ws_event", "ws_pong"}
        codes = {
            "TLSV1_ALERT_UNKNOWN_CA", "SSLV3_ALERT_BAD_CERTIFICATE", "CERTIFICATE_VERIFY_FAILED",
            "UNEXPECTED_EOF_WHILE_READING", "PEER_DID_NOT_RETURN_A_CERTIFICATE",
            "TLSV1_ALERT_CERTIFICATE_REQUIRED", "TLSV1_ALERT_INTERNAL_ERROR",
            "TLS_HANDSHAKE_FAILED", "TLS_HANDSHAKE_TIMEOUT", "TRANSFER_ENCODING",
            "BODY_LENGTH", "BODY_READ", "JSON_DECODE", "SCHEMA_FIELDS", "SCHEMA_VERSION",
            "PLAN_BINDING", "REQUEST_ID", "EPOCH", "BEARER_FORMAT", "CSR_FORMAT",
            "RETRY_BINDING", "INITIAL_CREDENTIAL", "CSR_ISSUANCE", "CSR_SIGNATURE",
            "CSR_PUBLIC_KEY", "CSR_SPKI", "CSR_KEY_BINDING", "LEAF_SIGNING",
            "DEFAULT_CONFIG_MISSING", "DEFAULT_CONFIG_PRESENT", "OPENSSL_CONFIG_MISSING",
            "OPENSSL_CSR_SIGNATURE_INVALID", "OPENSSL_ALGORITHM_UNAVAILABLE",
            "OPENSSL_ASN1_INVALID", "OPENSSL_FILE_ACCESS", "OPENSSL_EXECUTION_FAILED",
        }
        try:
            events = self.events()
            counts = {name: sum(v.get("event") == name for v in events) for name in sorted(names)}
            diagnostic_codes = {}
            for value in events:
                code = value.get("code")
                if value.get("event") in names and code in codes:
                    diagnostic_codes[code] = diagnostic_codes.get(code, 0) + 1
            mismatches = [v for v in events if v.get("event") == "enrollment_plan_mismatch"]
            fields = [name for name in ("controller_url", "identity", "scopes", "ca_sha256")
                      if mismatches and name in mismatches[-1].get("fields", [])]
            exit_codes = [v["exit_code"] for v in events if v.get("event") == "issuer_failure"
                          and type(v.get("exit_code")) is int][-8:]
            return {"read_status": "OK", "counts": counts, "codes": diagnostic_codes,
                    "last_plan_mismatch_fields": fields, "issuer_exit_codes": exit_codes}
        except Exception:
            return {"read_status": "UNREADABLE"}

    def diagnostic_summary(self):
        summary = {"phase": self.phase, "state_phase": self.last_state_phase,
                   "cli_failures": self.cli_failures, "observations": self.observation_summary(),
                   "containers": {}}
        for role, name in (("installation", self.install_name), ("controller", self.controller_name),
                           ("router", self.router_name)):
            if name not in self.containers:
                continue
            try:
                info = self.inspect("container", name)
                if info["Config"].get("Labels", {}).get(OWNER) != self.id:
                    summary["containers"][role] = {"inspection": "OWNERSHIP_CHANGED"}
                    continue
                state = info["State"]
                summary["containers"][role] = {key: state[key] for key in ("Running", "OOMKilled", "ExitCode")}
                if role == "router" and state["Running"]:
                    result = self.docker("exec", name, "/opt/iptables", "-t", "nat",
                                         "-L", "POSTROUTING", "-n", "-v", "-x",
                                         check=False, timeout=5)
                    packets = []
                    for line in result.stdout.decode("ascii", errors="replace").splitlines():
                        fields = line.split()
                        if len(fields) >= 3 and fields[2] == "MASQUERADE" and fields[0].isdigit():
                            packets.append(int(fields[0]))
                    summary["nat_rule_packet_counts"] = packets
                    summary["nat_counter_exit_code"] = result.returncode
            except Exception:
                summary["containers"][role] = {"inspection": "UNAVAILABLE"}
        return summary

    def start_controller(self, token, *flags):
        self.remove_container(self.controller_name)
        write(self.controller / "one-time", token)
        command = ["python3", "/opt/fleet-controller.py", "--host", self.controller_ip, "--owned-network", "--port", "8443",
                   "--cert", "/fixture/server.pem", "--key", "/fixture/server.key", "--client-ca", "/fixture/realm.pem",
                   "--issuer-key", "/fixture/realm.key", "--token-file", "/fixture/one-time", "--plan", "/fixture/plan.json",
                   "--state", "/fixture/state.json", "--observations", "/fixture/observations.jsonl",
                   "--rogue-token-file", "/fixture/rogue-token",
                   "--hold-open", *flags]
        self.create(self.controller_name, self.wan, self.controller_ip, command,
                    mounts=[(self.controller, "/fixture", False), (Path(__file__).with_name("fleet-controller.py").resolve(), "/opt/fleet-controller.py", True)], memory="128m")
        self.docker("start", self.controller_name)
        self.wait("owned controller TLS listener", lambda: self.docker("exec", self.controller_name, "python3", "-c",
                  "import socket,ssl;c=ssl.create_default_context(cafile='/fixture/realm.pem');"
                  "s=c.wrap_socket(socket.create_connection(('" + self.controller_ip + "',8443),1),"
                  "server_hostname='controller.test');s.close()", check=False).returncode == 0)

    def setup(self):
        required = ("/usr/bin/python3", "/usr/bin/openssl", "/usr/sbin/ip",
                    "/usr/sbin/iptables", "/usr/bin/sleep", "/usr/bin/setpriv")
        for path in required:
            if not Path(path).is_file() or not os.access(path, os.X_OK):
                raise RuntimeError("missing existing fixture toolchain prerequisite: " + path)
        self.iptables = Path("/usr/sbin/iptables").resolve(strict=True)
        for path in ("/usr", "/lib", "/lib64"):
            if not Path(path).is_dir():
                raise RuntimeError("missing existing fixture library mount: " + path)
        image = json.loads(self.docker("image", "inspect", self.image).stdout)[0]
        self.image_provenance = {"requested": self.image, "id": image["Id"], "digests": image.get("RepoDigests", [])}
        self.lan, lan = self.network("-lan")
        self.wan, wan = self.network("-wan")
        assert not lan.overlaps(wan), "owned NAT networks overlap"
        self.router_lan, self.router_wan = str(lan[10]), str(wan[10])
        self.install_ip, self.controller_ip = str(lan[11]), str(wan[11])
        self.create(self.router_name, self.lan, self.router_lan, ["sleep", "3600"],
                    mounts=[(self.iptables, "/opt/iptables", True)],
                    extra=["--cap-add=NET_ADMIN", "--sysctl", "net.ipv4.ip_forward=1",
                           "--env", "XTABLES_LOCKFILE=/tmp/xtables.lock"], memory="128m")
        self.docker("network", "connect", "--ip", self.router_wan, self.wan, self.router_name)
        self.docker("start", self.router_name)
        self.docker("exec", self.router_name, "/opt/iptables", "-P", "FORWARD", "DROP")
        self.docker("exec", self.router_name, "/opt/iptables", "-A", "FORWARD", "-s", str(lan), "-d", self.controller_ip + "/32", "-j", "ACCEPT")
        self.docker("exec", self.router_name, "/opt/iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        self.docker("exec", self.router_name, "/opt/iptables", "-t", "nat", "-A", "POSTROUTING", "-s", str(lan), "-d", self.controller_ip + "/32", "-j", "MASQUERADE")
        self.pki()
        self.configure(wrong_ca=True)
        initialize = ("ip route replace " + self.controller_ip + "/32 via " + self.router_lan
                      + "; exec " + " ".join(DROP) + " /opt/kronik serve --config /work/kronik.toml")
        self.create(self.install_name, self.lan, self.install_ip, ["/bin/sh", "-ec", initialize],
                    mounts=[(self.install, "/work", False), (self.binary, "/opt/kronik", True)],
                    extra=["--cap-add=NET_ADMIN", "--cap-add=SETPCAP", "--add-host", "controller.test:" + self.controller_ip])
        self.start_installation()
        higher = self.api("/v1/tokens", method="POST", body={
            "name": "rogue-higher-credential", "scopes": ["admin"], "reason": REASON,
        })
        assert higher["status"] == 200 and higher["value"]["secret"]
        write(self.controller / "rogue-token", higher["value"]["secret"])
        write(self.install / "rogue-admin", higher["value"]["secret"])
        del higher
        assert self.api("/v1/tokens", bearer_file="/work/rogue-admin")["status"] == 200
        self.start_controller("fixture-one-time-1", "--lost-reply-once")
        for name in self.containers:
            assert not self.inspect("container", name)["HostConfig"].get("PortBindings"), "an inbound port was published"
        router = self.inspect("container", self.router_name)["NetworkSettings"]["Networks"]
        installation = self.inspect("container", self.install_name)["NetworkSettings"]["Networks"]
        controller = self.inspect("container", self.controller_name)["NetworkSettings"]["Networks"]
        assert set(router) == {self.lan, self.wan}
        assert set(installation) == {self.lan} and set(controller) == {self.wan}
        assert installation[self.lan]["IPAddress"] == self.install_ip
        assert controller[self.wan]["IPAddress"] == self.controller_ip
        assert router[self.lan]["IPAddress"] == self.router_lan
        assert router[self.wan]["IPAddress"] == self.router_wan
        assert self.router_wan != self.install_ip
        self.nat_topology = {
            "installation_ip": self.install_ip, "controller_ip": self.controller_ip,
            "router_lan_ip": self.router_lan, "router_wan_ip": self.router_wan,
            "lan_subnet": str(lan), "wan_subnet": str(wan), "published_ports": 0,
            "iptables_source": str(self.iptables),
        }

    def exercise(self):
        self.phase = "preview"
        initial = self.cli("status")
        assert initial["configured"] and initial["state"] is None
        preview = self.cli("enroll", URL, "--reason", REASON, "--dry-run")
        assert preview["dry_run"] and preview["state"] is None
        assert not (self.install / "data/keys/fleet/client.key").exists()
        assert not (self.install / "data/keys/fleet/bearer").exists()
        assert not self.events()
        self.phase = "wrong_server_ca"
        self.cli("enroll", URL, "--token", "fixture-one-time-1", "--reason", REASON, succeeds=False)
        wrong = self.cli("status")["state"]
        assert wrong["phase"] == "requested" and not self.events("enrollment_request")
        self.phase = "revoke_wrong_ca_and_restart"
        self.cli("revoke", "--reason", REASON)
        self.docker("stop", "--time", "10", self.install_name)
        self.configure(wrong_ca=False)
        self.start_installation()
        self.phase = "initial_lost_reply_request"
        self.cli("enroll", URL, "--token", "fixture-one-time-1", "--reason", REASON, succeeds=False)
        requested = self.cli("status")["state"]
        assert requested["phase"] == "requested"
        self.phase = "waiting_lost_reply"
        self.wait("actual lost enrollment reply", lambda: self.events("enrollment_reply_lost", requested["request_id"]))
        before = len(self.events("enrollment_request"))
        self.phase = "tokenless_resume"
        self.cli("enroll", URL, "--token", "fixture-one-time-1", "--reason", REASON, succeeds=False)
        assert len(self.events("enrollment_request")) == before, "token was retransmitted during resume"
        active = self.cli("enroll", URL, "--reason", REASON)["state"]
        assert active["phase"] == "active" and active["client_cert_der"]
        assert active["controller_id"] == active["plan"]["ca_sha256"]
        assert all(active[k] == requested[k] for k in ("request_id", "csr_der", "client_key_sha256", "epoch", "plan"))
        attempts = self.events("enrollment_request", active["request_id"])
        assert len(attempts) == 2 and [v["credential_present"] for v in attempts] == [True, False]
        assert attempts[0]["csr_sha256"] == attempts[1]["csr_sha256"]
        assert all(v["peer_ip"] == self.router_wan for v in attempts), "controller did not observe the SNAT hop"
        self.phase = "ordinary_read_scope_parity"
        results = self.wait("ordinary HTTP and denied native stream responses", lambda: self.events("http_result", active["request_id"]) if len(self.events("http_result", active["request_id"])) == 4 else None)
        assert [r["status"] for r in results] == [200, 403, 403, 403]
        for remote in results:
            path = remote["path"]
            local = self.api(path, bearer_file="/work/data/keys/fleet/bearer")
            assert local["status"] == remote["status"]
            assert local["body_sha256"] == remote["body_sha256"], "local and remote ordinary dispatch differed"
        streams = self.events("stream_open", active["request_id"])
        assert streams and all(event["peer_ip"] == self.router_wan for event in streams)
        self.phase = "active_restart_and_revoke"
        key_before = hashlib.sha256((self.install / "data/keys/fleet/client.key").read_bytes()).hexdigest()
        old_bearer = self.install / "old-bearer"
        write(old_bearer, (self.install / "data/keys/fleet/bearer").read_bytes())
        self.docker("stop", "--time", "10", self.install_name)
        self.wait("stream closed on daemon stop", lambda: self.events("stream_closed", active["request_id"]))
        opened = len(self.events("stream_open", active["request_id"]))
        self.start_installation()
        assert self.cli("status")["state"] == active
        self.wait("same identity reconnect after restart", lambda: len(self.events("stream_open", active["request_id"])) > opened)
        closed = len(self.events("stream_closed", active["request_id"]))
        revoked = self.cli("revoke", "--reason", REASON)["state"]
        assert revoked["phase"] == "revoked" and revoked["epoch"] == active["epoch"]
        assert all(revoked[key] == active[key] for key in
                   ("request_id", "csr_der", "client_key_sha256", "client_cert_der", "plan"))
        self.wait("active stream closed by durable revoke", lambda: len(self.events("stream_closed", active["request_id"])) > closed, seconds=10)
        assert self.events("stream_closed", active["request_id"])[-1]["reason"] == "peer_closed"
        assert self.api("/v1/health", bearer_file="/work/old-bearer")["status"] in (401, 403)
        self.docker("stop", "--time", "10", self.install_name)
        self.start_installation()
        assert self.cli("status")["state"] == revoked
        assert self.api("/v1/health", bearer_file="/work/old-bearer")["status"] in (401, 403)
        self.phase = "wrong_issued_certificate"
        self.start_controller("fixture-one-time-2", "--wrong-client-binding")
        self.cli("enroll", URL, "--token", "fixture-one-time-2", "--reason", REASON, succeeds=False)
        bad_cert = self.cli("status")["state"]
        assert bad_cert["phase"] == "requested" and bad_cert["client_cert_der"] is None
        assert self.events("enrollment_request", bad_cert["request_id"])
        assert not self.events("stream_open", bad_cert["request_id"])
        self.cli("revoke", "--reason", REASON)
        self.phase = "admin_reenrollment_native_streams"
        self.docker("stop", "--time", "10", self.install_name)
        self.plan["scopes"] = ["admin"]
        write(self.controller / "plan.json", json.dumps(self.plan))
        self.configure(scopes=["admin"])
        self.start_installation()
        self.start_controller("fixture-one-time-3")
        renewed = self.cli("enroll", URL, "--token", "fixture-one-time-3", "--reason", REASON)["state"]
        assert renewed["phase"] == "active" and renewed["epoch"] > revoked["epoch"]
        assert renewed["request_id"] != active["request_id"]
        assert hashlib.sha256((self.install / "data/keys/fleet/client.key").read_bytes()).hexdigest() == key_before
        self.wait("actual native SSE operational record", lambda: self.events("sse_event", renewed["request_id"]))
        self.wait("actual native WebSocket operational record", lambda: self.events("ws_event", renewed["request_id"]))
        self.wait("actual inner WebSocket masked ping/pong", lambda: self.events("ws_pong", renewed["request_id"]))
        assert self.events("sse_http", renewed["request_id"])[-1]["status"] == 200
        assert self.events("ws_http", renewed["request_id"])[-1]["status"] == 101
        assert self.api("/v1/health", bearer_file="/work/old-bearer")["status"] in (401, 403)
        assert self.cli("status")["state"] == renewed
        self.phase = "native_upgrade_revoke"
        closed = len(self.events("stream_closed", renewed["request_id"]))
        final = self.cli("revoke", "--reason", REASON)["state"]
        assert final["phase"] == "revoked" and final["epoch"] == renewed["epoch"]
        self.wait("native upgraded channel closed on revoke",
                  lambda: len(self.events("stream_closed", renewed["request_id"])) > closed, seconds=10)
        assert self.events("stream_closed", renewed["request_id"])[-1]["reason"] == "peer_closed"
        streams = self.events("stream_open", renewed["request_id"])
        assert len(streams) >= 2 and all(event["peer_ip"] == self.router_wan for event in streams)
        return {"bootstrap": True, "preview_no_effects": True, "wrong_server_ca_denied": True,
                "lost_reply_same_csr_no_token_reuse": True, "ordinary_get_scope_denial_parity": True,
                "higher_remote_credentials_and_cookie_ignored": True,
                "native_sse_and_websocket_events_and_ping_pong": True,
                "restart_same_identity": True, "revoke_closes_active_stream": True,
                "wrong_issued_certificate_binding_denied": True, "reenroll_old_epoch_rejected": True,
                "nat": {"kind": "actual_owned_snat", **self.nat_topology}}

    def cleanup(self):
        errors = []
        for name in reversed(self.containers[:]):
            try:
                self.remove_container(name)
            except Exception:
                errors.append(name)
        for name in reversed(self.networks):
            try:
                info = self.inspect("network", name)
                assert info.get("Labels", {}).get(OWNER) == self.id
                self.docker("network", "rm", name)
            except Exception:
                errors.append(name)
        if errors:
            raise RuntimeError("owned cleanup failed; retained scratch " + str(self.root) + "; resources " + ",".join(errors))
        shutil.rmtree(self.root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, help="existing writable scratch parent; child is private and removed")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root so container-owned protected fixture files retain exact owner custody")
    if args.scratch is not None and (not args.scratch.is_dir()
            or args.scratch.resolve().is_relative_to(Path(__file__).resolve().parents[1])):
        parser.error("--scratch must be an existing directory outside the source worktree")
    binary = Path(os.environ.get("KRONIK_BIN", "")).expanduser()
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("set absolute executable KRONIK_BIN")
    for program in ("docker", "openssl"):
        if shutil.which(program) is None:
            parser.error("missing local prerequisite: " + program)
    proof = Proof(binary.resolve(), IMAGE, args.scratch)
    def expired(*_):
        raise TimeoutError("finite fleet proof deadline")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(300)
    result = None
    try:
        proof.setup()
        result = proof.exercise()
    except BaseException:
        # Only this allowlisted summary survives cleanup, never captured CLI output,
        # daemon/tool stderr, credentials, certificate subjects or request bodies.
        print(json.dumps({"m29_failure_diagnostic": proof.diagnostic_summary()}, sort_keys=True),
              file=sys.stderr, flush=True)
        raise
    finally:
        signal.alarm(0)
        proof.cleanup()
    print(json.dumps({"m29_real_binary": "passed", "checks": result,
                      "image": proof.image_provenance, "daemon_security": proof.daemon_security}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never dump command arguments, daemon logs, credentials or API bodies.
        detail = str(error) if isinstance(error, (AssertionError, RuntimeError, TimeoutError)) else type(error).__name__
        print("fleet proof failed: " + detail, file=sys.stderr)
        sys.exit(1)
