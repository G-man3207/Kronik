"""The /healthz paragraphs of the CLI reference and the operations guide name
every field the handler can answer with.

`low_disk` and `blobs_low_disk` appear only below their reserve, so a probe
author keys alerts on what the paragraph lists: a field it leaves out is a
full disk that no alert sees.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
ADMIN = (ROOT / "crates/kronik/src/admin.rs").read_text()
CLI = (ROOT / "docs/reference/cli.md").read_text()
OPERATIONS = (ROOT / "docs/guides/operations.md").read_text()


def between(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


def healthz_fields():
    arm = between(ADMIN, '"/healthz" =>', "Some(failure)")
    return set(re.findall(r'"(\w+)":', arm)) | set(re.findall(r'body\["(\w+)"\]', arm))


class HealthDocsTest(unittest.TestCase):
    def test_healthz_paragraphs_name_every_field(self):
        fields = healthz_fields()
        self.assertLessEqual({"status", "applied_lsn", "low_disk", "blobs_low_disk"}, fields)
        paragraphs = {
            "cli.md": between(CLI, "`GET /healthz` answers", "`GET /metrics`"),
            "operations.md": between(
                OPERATIONS, "- `GET /healthz` answers", "- `GET /metrics`"
            ),
        }
        for name, paragraph in paragraphs.items():
            for field in sorted(fields):
                self.assertIn(f'"{field}"', paragraph, f"{name} omits {field}")


if __name__ == "__main__":
    unittest.main()
