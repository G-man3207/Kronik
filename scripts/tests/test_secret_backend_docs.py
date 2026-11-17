"""The operator pages name the secret-backend allowlist.

An omitted `allowed_refs` defaults to an empty list, and an empty list
denies every link. The operations reference has to say so. The design's
copy-paste OpenBao and AWS examples have to include prefixes that cover
the `--ref` values shown next to them, or a copied backend rejects the
documented link.
"""

from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = (ROOT / "docs/guides/operations.md").read_text()
DESIGN = (ROOT / "docs/design/m23-secret-backends.md").read_text()


def section(text, heading):
    marker = f"### {heading}\n"
    start = text.index(marker) + len(marker)
    rest = text[start:]
    end = rest.find("\n### ")
    return rest if end < 0 else rest[:end]


def allows(prefixes, ref):
    # Same rule as Source::allows: a non-empty ref of at most 2048 bytes,
    # with no control character, that starts with a configured prefix.
    return (
        bool(ref)
        and len(ref) <= 2048
        and not any(ord(char) < 32 or ord(char) == 127 for char in ref)
        and any(ref.startswith(prefix) for prefix in prefixes)
    )


def flat(text):
    return " ".join(text.split())


class SecretBackendDocsTest(unittest.TestCase):
    def test_operations_requires_nonempty_allowed_refs(self):
        body = flat(section(OPERATIONS, "[secrets]"))
        self.assertIn("`[secrets.backends.<id>]`", body)
        self.assertIn("non-empty `allowed_refs` prefix list", body)
        self.assertIn("empty list denies every link", body)

    def test_examples_cover_refs_shown_next_to_them(self):
        backends = section(DESIGN, "4.2 Backends")
        links = section(DESIGN, "4.3 Links are log records")
        fence = re.search(r"```toml\n(.*?)```", backends, re.S)
        self.assertIsNotNone(fence)
        tables = tomllib.loads(fence.group(1))["secrets"]["backends"]
        shown = dict(re.findall(r"--backend (bao|aws) --ref (\S+)", links))
        self.assertEqual(set(shown), {"bao", "aws"})
        for backend, ref in shown.items():
            prefixes = tables[backend]["allowed_refs"]
            self.assertTrue(prefixes, backend)
            self.assertTrue(allows(prefixes, ref), (backend, ref, prefixes))
        prose = re.search(r'allowed_refs = \["([^"]+)"', links)
        self.assertIsNotNone(prose)
        self.assertTrue(allows([prose.group(1)], shown["bao"]), prose.group(1))
