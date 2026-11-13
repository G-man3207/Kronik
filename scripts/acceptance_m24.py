#!/usr/bin/env python3
"""M24 acceptance driver (docs/design/m24-connections.md, section 18); run it
through scripts/acceptance-m24.sh, which builds what it needs first.

    acceptance_m24.py load     criterion 1: chat-ts with many WebSocket clients
    acceptance_m24.py replay   criterion 2: identity replay of a recorded
                               session is empty; chat-ts-step2 changes frames
    acceptance_m24.py restart  criterion 4: restarts close connections with
                               the reason restart, and the clients reconnect

Each starts its own `kronik serve` on a fresh data directory under WORKDIR
(default /var/tmp/kronik-m24-<command>), deploys examples/dist/chat-ts.wasm
and writes WORKDIR/report.json. The scale comes from the environment, so a
small machine can run a reduced shape; the defaults are the acceptance's:

    load:    CLIENTS=1000 ROOMS=50 RAMP=20 SETTLE=5 INTERVAL=10 SECONDS=600
             DRAIN=10, and it passes with P50_MS<=50, P99_MS<=250,
             HWM_MIB<=1536 and an RSS growth over the steady phase below
             RSS_GROWTH=0.10.
    restart: CLIENTS=200 ROOMS=10 SECONDS=90; a graceful restart after
             a third of it and a SIGKILL after two thirds.

PORT (default 47510) and ADMIN_PORT (47511) are the gateway's and the
admin listener's. KRONIK_BIN, LOADGEN and CHAT, CHAT_STEP2 name the binaries
and components. Exits 1 when a check fails, with the reasons in the report.
"""

import base64
import json
import os
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from kronikd import Daemon, Violation  # noqa: E402


def env(name, default, cast=str):
    value = os.environ.get(name)
    return default if value in (None, "") else cast(value)


class Node:
    """A `kronik serve` (scripts/kronikd.py) on a data directory that outlives
    its restarts, with the calls the checks make."""

    def __init__(self, workdir, port, admin_port, connections):
        config = workdir / "kronik.toml"
        text = f'[server]\nadmin_listen = "127.0.0.1:{admin_port}"\n'
        if connections:
            text += "\n[connections]\n" + "".join(f"{k} = {v}\n" for k, v in connections.items())
        config.write_text(text)
        self.dir = workdir
        self.port = port
        self.daemon = Daemon(
            env("KRONIK_BIN", str(ROOT / "target/release/kronik")),
            str(workdir / "data"),
            str(workdir / "api.sock"),
            port,
            str(workdir / "serve.log"),
            healthy_timeout=120.0,
            config=str(config),
        )

    def start(self):
        self.daemon.start()

    def stop(self, sig=signal.SIGTERM):
        if self.daemon.proc is None or self.daemon.proc.poll() is not None:
            return
        if sig == signal.SIGKILL:
            self.daemon.kill9()
        else:
            self.daemon.stop()

    def ok(self, method, path, body=None, timeout=60):
        status, answer = self.daemon.api(method, path, body, timeout=timeout)
        if status != 200:
            raise Violation(f"{method} {path}: {status} {answer}")
        return answer

    def deploy(self, wasm):
        """Deploys a component; compiling a JavaScript one takes minutes on
        a small or busy machine."""
        b64 = base64.b64encode(Path(wasm).read_bytes()).decode()
        return self.ok("POST", "/v1/deployments", {"wasm_base64": b64, "reason": "M24 acceptance"}, timeout=600)

    def applied_lsn(self):
        return self.ok("GET", "/v1/health")["applied_lsn"]

    def connections(self, state):
        """Every connection in `state` (open, closed, all), page by page."""
        out, after = [], None
        while True:
            query = f"/v1/connections?state={state}&limit=1000" + (f"&after={after}" if after else "")
            page = self.ok("GET", query)
            out += page["connections"]
            after = page.get("next")
            if not after:
                return out

    def dead_letters(self):
        return self.ok("GET", "/v1/dead-letters?limit=1000")["dead_letters"]

    def proc_status(self):
        """VmRSS and VmHWM in KiB, and user+system CPU seconds."""
        pid = self.daemon.proc.pid
        fields = {}
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            key, _, value = line.partition(":")
            if key in ("VmRSS", "VmHWM"):
                fields[key] = int(value.split()[0])
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        ticks = os.sysconf("SC_CLK_TCK")
        fields["cpu_s"] = (int(stat[11]) + int(stat[12])) / ticks
        return fields


def loadgen(port, args):
    binary = env("LOADGEN", str(ROOT / "tools/loadgen/target/release/kronik-loadgen"))
    return subprocess.Popen([binary, "chat", "--addr", f"127.0.0.1:{port}", *args], stdout=subprocess.PIPE, text=True)


def raise_open_files():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    return resource.getrlimit(resource.RLIMIT_NOFILE)[0]


def check(report, ok, what):
    report.setdefault("checks", []).append({"check": what, "ok": bool(ok)})
    if not ok:
        report.setdefault("failed", []).append(what)


def api_check(report, what, read, ok):
    """A check that reads the daemon's API: `read()` gets the value and
    `ok(value)` judges it. A failed call fails this check only, and the run
    goes on. Returns the value, or None."""
    try:
        value = read()
    except (Violation, OSError) as e:
        report.setdefault("api_errors", {})[what] = str(e)
        check(report, False, what)
        return None
    check(report, ok(value), what)
    return value


def workdir(command):
    d = Path(env("WORKDIR", f"/var/tmp/kronik-m24-{command}"))
    if d.exists():
        subprocess.run(["rm", "-rf", "--", str(d)], check=True)
    d.mkdir(parents=True)
    return d


def chat_component(name="CHAT", default="examples/dist/chat-ts.wasm"):
    return env(name, str(ROOT / default))


def load():
    """Criterion 1: chat-ts handles CLIENTS concurrent WebSocket clients."""
    d = workdir("load")
    clients, rooms = env("CLIENTS", 1000, int), env("ROOMS", 50, int)
    ramp, settle, interval = env("RAMP", 20.0, float), env("SETTLE", 5.0, float), env("INTERVAL", 10.0, float)
    seconds, drain, sample = env("SECONDS", 600.0, float), env("DRAIN", 10.0, float), env("SAMPLE", 10.0, float)
    report = {"criterion": 1, "clients": clients, "rooms": rooms, "seconds": seconds, "open_files": raise_open_files()}
    daemon = Node(d, env("PORT", 47510, int), env("ADMIN_PORT", 47511, int), {"max_open": 4096, "max_per_client": 2048})
    try:
        daemon.start()
        daemon.deploy(chat_component())
        started = time.monotonic()
        lg = loadgen(daemon.port, [
            "--clients", str(clients), "--rooms", str(rooms), "--ramp", str(ramp), "--settle", str(settle),
            "--interval", str(interval), "--seconds", str(seconds), "--drain", str(drain),
        ])
        steady, stop = started + ramp + settle, started + ramp + settle + seconds
        samples, open_mid = [], None
        while lg.poll() is None:
            now = time.monotonic()
            s = daemon.proc_status()
            s["t"] = round(now - started, 1)
            samples.append(s)
            if open_mid is None and now > steady + min(30.0, seconds / 2):
                # A failed listing fails its check, not the load run.
                try:
                    open_mid = len(daemon.connections("open"))
                except (Violation, OSError) as e:
                    open_mid = f"error: {e}"
            time.sleep(min(sample, 1.0) if now < steady else sample)
        out = json.loads(lg.stdout.read())
        report["loadgen"] = out
        report["samples"] = samples
        steady_samples = [s for s in samples if steady - started + 60 <= s["t"] <= stop - started]
        hwm_kib = max((s["VmHWM"] for s in samples), default=0)
        growth = (steady_samples[-1]["VmRSS"] / steady_samples[0]["VmRSS"] - 1) if len(steady_samples) >= 2 else 0.0
        cpu = (samples[-1]["cpu_s"] - samples[0]["cpu_s"]) / max(samples[-1]["t"] - samples[0]["t"], 1e-9) if len(samples) >= 2 else 0.0
        report.update({"vm_hwm_mib": round(hwm_kib / 1024, 1), "rss_growth": round(growth, 4), "daemon_cpu_cores": round(cpu, 3)})
        check(report, out["ok"], "loadgen: every client connected, no gap, duplicate, loss or unexpected close")
        check(report, out["connected"] == clients and out["unexpected_closes"] == 0, "all clients accepted and none closed early")
        check(report, out["p50_ms"] <= env("P50_MS", 50.0, float), "end-to-end p50 within P50_MS")
        check(report, out["p99_ms"] <= env("P99_MS", 250.0, float), "end-to-end p99 within P99_MS")
        check(report, hwm_kib <= env("HWM_MIB", 1536.0, float) * 1024, "the daemon's VmHWM within HWM_MIB")
        check(report, growth < env("RSS_GROWTH", 0.10, float), "VmRSS growth over the steady phase below RSS_GROWTH")
        time.sleep(3)  # the close turns of the last connections
        report["open_during_steady"] = open_mid
        check(report, open_mid == clients, "connections list shows every client open during the steady phase")
        report["open_after"] = api_check(report, "no connection open after the clients closed",
                                         lambda: len(daemon.connections("open")), lambda n: n == 0)
        report["dead_letters"] = api_check(report, "no dead letters", lambda: len(daemon.dead_letters()), lambda n: n == 0)
        per_room = clients // rooms

        def sample_room():
            turns = daemon.ok("GET", "/v1/actors/chat/r0/history?limit=1000")["turns"]
            inputs = [t["input"] for t in turns if t["input"]["type"] == "connection"]
            return [sum(1 for i in inputs if i["summary"].startswith(event)) for event in ("open", "close")]

        report["sample_room_opens_closes"] = api_check(report, "a sample room's history has one open and one close per member",
                                                       sample_room, lambda oc: oc == [per_room, per_room])
    except Exception as e:  # noqa: BLE001 (any failure fails the run, with its reason)
        check(report, False, f"error: {e}")
    finally:
        daemon.stop()
    return finish(d, report)


def replay():
    """Criterion 2: identity replay of a recorded session is empty, and a changed message format shows as changed frames."""
    d = workdir("replay")
    report = {"criterion": 2}
    daemon = Node(d, env("PORT", 47510, int), env("ADMIN_PORT", 47511, int), {})
    try:
        daemon.start()
        daemon.deploy(chat_component())
        daemon.ok("POST", "/v1/grants", {"kind": "chat", "capability": "connection:send-now", "reason": "M24 acceptance: the bot streams"})
        fork_lsn = daemon.applied_lsn()
        session = subprocess.run(
            [sys.executable, str(ROOT / "scripts/m24_ws.py"), "session", "--gateway", f"127.0.0.1:{daemon.port}", "--room", "lobby"],
            capture_output=True, text=True, timeout=300,
        )
        report["session"] = session.stdout.strip() or session.stderr.strip()
        check(report, session.returncode == 0, "the recorded session ran as expected")
        deadline = time.monotonic() + 30
        while daemon.connections("open") and time.monotonic() < deadline:
            time.sleep(0.2)
        check(report, not daemon.connections("open"), "every connection of the session closed")
        daemon.ok("POST", "/v1/forks", {"at": fork_lsn, "name": "identity", "reason": "M24 acceptance"})
        identity = daemon.ok("POST", "/v1/forks/identity/replay", {"mode": "both", "reason": "M24 acceptance"})
        report["identity_summary"] = identity["summary"]
        diff = daemon.ok("GET", "/v1/forks/identity/diff")
        frames = diff.get("frames") or {}
        check(report, identity["summary"]["changed"] is False, "identity replay: no change in both modes")
        check(report, frames.get("changed", 0) == 0 and not frames.get("items"), "identity replay: no changed frames")
        check(report, frames.get("inputs", {}).get("frame", 0) > 0, "the diff counted the session's frame inputs")
        b64 = base64.b64encode(Path(chat_component("CHAT_STEP2", "examples/dist/chat-ts-step2.wasm")).read_bytes()).decode()
        proposal = daemon.ok("POST", "/v1/proposals", {"wasm_base64": [b64], "at": fork_lsn, "mode": "both", "reason": "M24 acceptance: message format"})
        pid = proposal["proposal"]["id"]
        diff = daemon.ok("GET", f"/v1/proposals/{pid}/diff")
        frames = diff.get("frames") or {}
        report["step2_frames"] = {k: frames.get(k) for k in ("inputs", "unchanged", "changed", "skipped")}
        ops = [op for item in frames.get("items", []) for f in item.get("frames", []) for op in f.get("data", [])]
        check(report, frames.get("changed", 0) > 0, "chat-ts-step2: changed outgoing frames")
        check(report, ops and {(o["op"], o["path"]) for o in ops} <= {("remove", "/text"), ("add", "/body")},
              "chat-ts-step2: every frame change is text renamed to body")
        check(report, diff["responses"]["changed"] == 0, "chat-ts-step2: no HTTP response changed")
    except Exception as e:  # noqa: BLE001
        check(report, False, f"error: {e}")
    finally:
        daemon.stop()
    return finish(d, report)


def restart():
    """Criterion 4: restarts close connections with the reason restart, and the clients reconnect."""
    d = workdir("restart")
    clients, rooms, seconds = env("CLIENTS", 200, int), env("ROOMS", 10, int), env("SECONDS", 90.0, float)
    ramp, settle, interval = env("RAMP", 5.0, float), env("SETTLE", 2.0, float), env("INTERVAL", 1.0, float)
    report = {"criterion": 4, "clients": clients, "open_files": raise_open_files()}
    daemon = Node(d, env("PORT", 47510, int), env("ADMIN_PORT", 47511, int), {"max_open": 4096, "max_per_client": 2048})
    try:
        daemon.start()
        daemon.deploy(chat_component())
        started = time.monotonic()
        lg = loadgen(daemon.port, [
            "--clients", str(clients), "--rooms", str(rooms), "--ramp", str(ramp), "--settle", str(settle),
            "--interval", str(interval), "--seconds", str(seconds), "--drain", "10", "--reconnect",
        ])
        steady = started + ramp + settle
        restarts = []
        for at, sig in ((seconds / 3, signal.SIGTERM), (2 * seconds / 3, signal.SIGKILL)):
            time.sleep(max(0.0, steady + at - time.monotonic()))
            t0 = time.monotonic()
            daemon.stop(sig)
            daemon.start()
            restarts.append({"signal": sig.name, "down_s": round(time.monotonic() - t0, 2)})
        out = json.loads(lg.communicate()[0])
        report.update({"loadgen": out, "restarts": restarts})
        check(report, out["ok"], "loadgen: no gap or duplicate after resync, every client connected at the end")
        check(report, out["connected_at_end"] == clients, "every client reconnected")
        check(report, out["reconnect_max_ms"] <= 30000, "every reconnect within 30 s")
        check(report, out["close_codes"].get("1012", 0) == clients, "the graceful restart closed every client with 1012")
        check(report, out["close_reasons"].get("1012") == "kronik: restart", "with the reason kronik: restart")
        time.sleep(3)

        def restart_closes():
            closed = daemon.connections("closed")
            return [c for c in closed if (c.get("closed") or {}).get("cause") == "restart"]

        closes = api_check(report, "every connection broken by a restart has a restart close input",
                           restart_closes, lambda cs: len(cs) >= 2 * clients)
        report["restart_closes"] = None if closes is None else len(closes)
        check(report, closes is not None and all((c["closed"].get("initiator"), c["closed"].get("code")) == ("host", 1012) for c in closes),
              "restart closes are the host's, with code 1012")
        report["dead_letters"] = api_check(report, "no dead letters", lambda: len(daemon.dead_letters()), lambda n: n == 0)
    except Exception as e:  # noqa: BLE001
        check(report, False, f"error: {e}")
    finally:
        daemon.stop()
    return finish(d, report)


def finish(d, report):
    report["ok"] = not report.get("failed")
    (d / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    for c in report.get("checks", []):
        print(f"{'ok  ' if c['ok'] else 'FAIL'} {c['check']}")
    print(f"{'PASS' if report['ok'] else 'FAIL'}: criterion {report['criterion']}; report {d / 'report.json'}")
    return 0 if report["ok"] else 1


def main():
    commands = {"load": load, "replay": replay, "restart": restart}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print(__doc__, file=sys.stderr)
        return 2
    return commands[sys.argv[1]]()


if __name__ == "__main__":
    sys.exit(main())
