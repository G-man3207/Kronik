"""SECURITY.md and the security guide match who gets personal data in a fork.

`no_pii` is true when the caller asks, or when the caller lacks
`pii:read`. `Caller::local` is every scope, and the Unix socket without a
token uses it. The policy and the threat table used to say forks have no
personal data by default, so an operator on that socket could share a fork
that still holds production subject values.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "SECURITY.md").read_text()
GUIDE = (ROOT / "docs/guides/security.md").read_text()
AUTH = (ROOT / "crates/kronik-api/src/auth.rs").read_text()
M3 = (ROOT / "crates/kronik-api/src/m3.rs").read_text()
FORK = (ROOT / "crates/kronik/src/cli/fork.rs").read_text()


def must(pattern, text, message):
    found = re.search(pattern, text)
    if not found:
        raise AssertionError(message)
    return found


def pii_scope():
    return must(
        r'Scope::PiiRead => "([^"]+)"',
        AUTH,
        "pii:read scope string moved",
    ).group(1)


def fork_create_flag():
    found = must(
        r"pub struct ForkCreateArgs \{[\s\S]*?#\[arg\(long\)\]\n    (no_pii): bool,",
        FORK,
        "fork create no_pii flag moved",
    )
    return "--" + found.group(1).replace("_", "-")


def agents_bullet():
    found = must(
        r"- \*\*Agents and operators\*\*([\s\S]*?)\n- \*\*",
        POLICY,
        "security policy has no agents bullet",
    )
    return " ".join(found.group(0).split())


def agents_threat_cell():
    found = must(
        r"\| Agents with too much power \| ([^|]+) \|",
        GUIDE,
        "security guide has no agents threat row",
    )
    return " ".join(found.group(1).split())


class ForkPiiDocsTest(unittest.TestCase):
    def test_policy_matches_no_pii_and_the_socket_caller(self):
        scope = pii_scope()
        flag = fork_create_flag()
        must(
            r"fn no_pii\(requested: bool, caller: &Caller\) -> bool \{\n"
            r"    requested \|\| !caller\.has\(Scope::PiiRead\)\n"
            r"\}",
            M3,
            "no_pii is no longer requested or missing pii:read",
        )
        must(
            r"no_pii\(r\.no_pii, caller\)",
            M3,
            "fork create no longer passes the shared no_pii rule",
        )
        must(
            r"pub const ALL: \[Scope; 8\] = \[[\s\S]*?Scope::PiiRead,[\s\S]*?\];",
            AUTH,
            "Caller::local's every-scope list no longer includes pii:read",
        )
        must(
            r"pub fn local\(token_id: impl Into<String>\) -> Caller \{\n"
            r"        Caller \{\n"
            r"            token_id: token_id\.into\(\),\n"
            r"            scopes: Scope::ALL\.into_iter\(\)\.collect\(\),\n"
            r"        \}\n"
            r"    \}",
            AUTH,
            "the socket caller is no longer every scope",
        )
        must(
            r"fn has\(&self, s: Scope\) -> bool \{\n"
            r"        self\.scopes\.contains\(&s\) \|\| self\.scopes\.contains\(&Scope::Admin\)\n"
            r"    \}",
            AUTH,
            "lacking a scope is no longer has()",
        )
        must(
            r"Ok\(Caller::local\(req\.token_id\.clone\(\)\)\)",
            AUTH,
            "the Unix socket without a token no longer uses Caller::local",
        )
        must(
            r'\.strip_prefix\("unix:uid="\)',
            AUTH,
            "the local caller is no longer a Unix peer",
        )

        bullet = agents_bullet()
        self.assertIn(
            f"A caller without `{scope}` cannot receive personal data in a fork",
            bullet,
        )
        self.assertIn(f"when the caller passes `{flag}`", bullet)
        self.assertIn("always when the caller lacks that scope", bullet)
        self.assertIn(
            f"a token without `{scope}` always gets such a fork",
            bullet,
        )
        self.assertIn(
            f"Unix socket without a token has every scope, including `{scope}`",
            bullet,
        )
        self.assertIn(
            f"`kronik fork create` keeps production subject values unless `{flag}`",
            bullet,
        )
        self.assertIn(
            f"That flag is how a local operator opts into a fork without personal data",
            bullet,
        )
        self.assertNotIn("personal data by default", POLICY)
        self.assertNotIn("forks have no access to personal data", POLICY)

    def test_threat_table_names_token_and_socket_rules(self):
        scope = pii_scope()
        flag = fork_create_flag()
        cell = agents_threat_cell()
        self.assertNotIn("by default", cell)
        self.assertNotIn("exclude personal data by default", cell)
        self.assertIn(
            f"A caller without `{scope}` cannot receive personal data in a fork",
            cell,
        )
        self.assertIn(
            f"A token without `{scope}` always gets a fork without personal data",
            cell,
        )
        self.assertIn(
            "a Unix-socket caller without a token keeps subject values unless "
            f"`{flag}`",
            cell,
        )
