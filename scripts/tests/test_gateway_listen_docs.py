"""The security guide names both gateway binds.

`Config::http_listen` is loopback with TLS off and `0.0.0.0:443` with TLS.
`serve --init` without a domain writes a different address and turns TLS
off. The guide used to name only the config-less port, so an operator who
firewalled from it left the installed port open. The gateway still does
not authenticate routes.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
SECURITY = (ROOT / "docs/guides/security.md").read_text()
CONFIG = (ROOT / "crates/kronik/src/config.rs").read_text()
INIT = (ROOT / "crates/kronik/src/init.rs").read_text()


def address(octets, port):
    return ".".join(part.strip() for part in octets.split(",")) + ":" + port


def http_listen_defaults():
    found = re.search(
        r"pub fn http_listen\(&self\)[\s\S]*?"
        r"TlsMode::Off => SocketAddr::from\(\(\[([0-9, ]+)\], (\d+)\)\),"
        r"[\s\S]*?"
        r"TlsMode::Files \| TlsMode::Acme => SocketAddr::from\(\(\[([0-9, ]+)\], (\d+)\)\),",
        CONFIG,
    )
    if not found:
        raise AssertionError("Config::http_listen defaults moved")
    return address(found.group(1), found.group(2)), address(found.group(3), found.group(4))


def init_binds():
    found = re.search(
        r"SocketAddr::from\(\(\[([0-9, ]+)\], if domains\.is_empty\(\) \{ (\d+) \} else \{ (\d+) \}\)\)",
        INIT,
    )
    if not found:
        raise AssertionError("serve --init listen address moved")
    plain = address(found.group(1), found.group(2))
    acme = address(found.group(1), found.group(3))
    if 'mode = \\"off\\"' not in INIT.split("fn config_file", 1)[1].split("fn ", 1)[0]:
        raise AssertionError("serve --init no longer writes TLS off without a domain")
    return plain, acme


class GatewayListenDocsTest(unittest.TestCase):
    def test_guide_names_both_binds_and_does_not_authenticate(self):
        off, tls = http_listen_defaults()
        plain, acme = init_binds()
        self.assertNotEqual(off, plain)
        gateway = SECURITY.split("- **The gateway**", 1)[1].split("\n- **", 1)[0]
        flat = " ".join(gateway.split())
        self.assertIn("does not authenticate", flat)
        self.assertIn("every deployed route is open", flat)
        self.assertIn(f"config-less `kronik serve` listens on `{off}`", flat)
        self.assertIn(f"else `{off}` with `[tls]` off and `{tls}`", flat)
        self.assertIn(
            f"without `--domain` and without `--http-listen` writes "
            f'`http_listen = "{plain}"` and `[tls] mode = "off"`',
            flat,
        )
        self.assertIn("not the loopback port of a config-less start", flat)
        self.assertIn(
            f"With `--domain` it writes `{acme}` and ACME, unless `--http-listen`",
            flat,
        )
        self.assertNotIn("unless `--http-listen` says otherwise", flat)
