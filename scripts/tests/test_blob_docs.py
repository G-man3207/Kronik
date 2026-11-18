"""The WIT reference, the operator table and the security guide match the
shipped blob store.

`kronik serve` always starts a blob store. Blob calls trap with
`NOT_IMPLEMENTED` only in a turn that has no blob host, and a kind that
imports blobs may accept a gateway body up to its upload size. The security
guide states that limit beside the 1 MiB inline body.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WIT = (ROOT / "docs/reference/wit.md").read_text()
EXAMPLES = (ROOT / "docs/reference/wit-examples.md").read_text()
OPERATIONS = (ROOT / "docs/guides/operations.md").read_text()
SECURITY = (ROOT / "docs/guides/security.md").read_text()
EXPLAIN = (ROOT / "crates/kronik-core/explain/codes/PAYLOAD_TOO_LARGE.md").read_text()


def section(text, heading):
    marker = f"## {heading}\n"
    start = text.index(marker) + len(marker)
    rest = text[start:]
    end = rest.find("\n## ")
    return rest if end < 0 else rest[:end]


class BlobDocsTest(unittest.TestCase):
    def test_wit_does_not_forbid_shipped_blobs(self):
        types = section(WIT, "types")
        blobs = section(WIT, "blobs")
        examples = section(EXAMPLES, "blobs")
        for name, body in (("types", types), ("blobs", blobs), ("examples", examples)):
            self.assertNotIn("must be empty", body, name)
            self.assertNotIn("being built", body, name)
            self.assertNotIn("not available in v0.1", body, name)
            self.assertNotIn("until their parts land", body, name)
            self.assertNotIn("until then", body, name)
        for name, body in (("types", types), ("blobs", blobs), ("examples", examples)):
            self.assertIn("no blob host", body, name)
            self.assertIn("NOT_IMPLEMENTED", body, name)
        self.assertIn("message.blobs", types)
        self.assertIn("carries references", types)

    def test_limits_do_not_cap_every_gateway_body_at_1_mib(self):
        limits = section(WIT, "Limits")
        self.assertNotIn("accepts request bodies up to 1 MiB", limits)
        self.assertNotIn("only up to 1 MiB", limits)
        self.assertIn("upload size", limits)
        self.assertIn("imports `blobs`", limits)
        self.assertIn("64 MiB", limits)

    def test_security_guide_states_both_gateway_body_policies(self):
        gateway = SECURITY.split("- **The gateway**", 1)[1].split("\n- **", 1)[0]
        self.assertNotIn("accepts request bodies up to 1 MiB", gateway)
        self.assertNotIn("30 s for its body", gateway)
        self.assertIn("does not import", gateway)
        self.assertIn("1 MiB", gateway)
        self.assertIn("within\n  30 s", gateway)
        self.assertIn("imports `blobs`", gateway)
        self.assertIn("upload size", gateway)
        self.assertIn("64 MiB", gateway)
        self.assertIn("--upload-size", gateway)
        self.assertIn("no whole-body", gateway)
        self.assertIn("idle timeout", gateway)
        self.assertIn("upload_min_rate", gateway)

    def test_payload_too_large_row_matches_explain(self):
        row = next(
            line for line in OPERATIONS.splitlines() if line.startswith("| `PAYLOAD_TOO_LARGE`")
        )
        self.assertNotIn("v0.1's limit", row)
        self.assertNotIn("over 1 MiB", row)
        for fact in ("upload size", "64 MiB", "kronik:actor/blobs"):
            self.assertIn(fact, EXPLAIN, fact)
            self.assertIn(fact, row, fact)
