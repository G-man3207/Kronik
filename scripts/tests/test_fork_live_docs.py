"""Operator texts name the four conditions for a live effect from a fork.

The live branch leaves only for a GET, a replay-safe grant, no secret
header, and a host on `[fork] live_allowlist`. `kronik explain fork`,
`kronik fork create` and the agent guide used to omit some of those, so an
allowlisted host looked like every effect, or a fork looked hermetic.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
FORK = (ROOT / "crates/kronik-core/explain/concepts/fork.md").read_text()
CLI = (ROOT / "docs/reference/cli.md").read_text()
GUIDE = (ROOT / "docs/AGENT_GUIDE.md").read_text()
GLOSSARY = (ROOT / "docs/concepts/glossary.md").read_text()
REPLAY = (ROOT / "crates/kronik-fork/src/replay.rs").read_text()
EXPLAIN = (ROOT / "crates/kronik-core/src/explain.rs").read_text()
SEND_HELP = (ROOT / "crates/kronik/src/cli/mod.rs").read_text()
MCP = (ROOT / "crates/kronik-mcp/src/tools.rs").read_text()

CLAUSE = (
    "a GET without secret headers to a host in `[fork] live_allowlist` "
    "whose grant's effective delivery class is `replay-safe`"
)


def flat(text):
    return " ".join(text.split())


def section(text, heading):
    body = text.split(heading, 1)
    if len(body) != 2:
        raise AssertionError(f"missing {heading}")
    return body[1].split("\n## ", 1)[0]


def must(pattern, text, message):
    found = re.search(pattern, text)
    if not found:
        raise AssertionError(message)
    return found


class ForkLiveDocsTest(unittest.TestCase):
    def test_live_branch_requires_the_four_conditions(self):
        must(
            r"let secretless = req\s*"
            r"\.headers\s*"
            r"\.iter\(\)\s*"
            r"\.all\(\|\(_, v\)\| matches!\(v, FetchHeader::Text\(_\)\)\);\s*"
            r"if let Some\(live\) = &setup\.live\s*"
            r'&& t\.scheme != "foreign"\s*'
            r'&& req\.method\.eq_ignore_ascii_case\("GET"\)\s*'
            r"&& delivery == Delivery::ReplaySafe\s*"
            r"&& secretless\s*"
            r"&& live\.hosts\.contains\(&t\.host\)",
            REPLAY,
            "a fork fetch no longer leaves only for a secretless replay-safe GET on the allowlist",
        )

    def test_explain_fork_create_and_the_agent_guide_state_the_clause(self):
        preview = flat(section(CLI, "## kronik preview create"))
        self.assertIn(CLAUSE, preview)
        surfaces = {
            "explain fork": flat(FORK),
            "fork create": flat(section(CLI, "## kronik fork create")),
            "agent guide": flat(GUIDE),
        }
        for name, text in surfaces.items():
            self.assertIn(CLAUSE, text, name)
            self.assertNotIn("allowlisted a target", text, name)
            self.assertNotIn("never live effects", text, name)
            self.assertNotIn("without secrets to a host the operator allowlisted", text, name)
            self.assertNotRegex(text, r"makes no live effects\.")
            self.assertNotRegex(text, r"make no live effects\.")
        self.assertIn(flat(FORK).split("See also")[0].strip(), flat(GLOSSARY))
        must(
            r'pub const AGENT_GUIDE: &str = include_str!\("\.\./\.\./\.\./docs/AGENT_GUIDE\.md"\);',
            EXPLAIN,
            "kronik explain agent no longer includes the agent guide",
        )

    def test_send_and_create_fork_do_not_say_a_fork_never_sends(self):
        send = flat(section(CLI, "## kronik send"))
        self.assertIn(CLAUSE, send)
        self.assertNotIn("without live effects", CLI)
        help_text = flat(re.sub(r"(?m)^\s*/// ?", "", SEND_HELP))
        self.assertIn(
            "A live effect leaves only as a GET without secret headers to a "
            "`[fork] live_allowlist` host whose grant is `replay-safe`",
            help_text,
        )
        self.assertNotIn("without live effects, and has no dry run", help_text)
        description = must(
            r'name: "create_fork",[\s\S]*?description: "([^"]*)"',
            MCP,
            "create_fork description moved",
        ).group(1)
        text = flat(description.replace("\\", " "))
        self.assertIn("GET without secret headers", text)
        self.assertIn("live_allowlist", text)
        self.assertIn("replay-safe", text)
        self.assertNotIn("makes no live effects", text)
        self.assertNotIn("no live effects", text)
