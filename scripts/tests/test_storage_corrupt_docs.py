"""The STORAGE_CORRUPT troubleshooting row matches the start error.

When the applied LSN is past the end of the log, moving state.db aside
installs a snapshot and replays what is left. That drops acknowledged
records only state.db still had. The row must send that case to restore
into a new directory.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = (ROOT / "docs/guides/operations.md").read_text()
NODE = (ROOT / "crates/kronik-sched/src/node.rs").read_text()


def troubleshooting_row():
    return next(
        line
        for line in OPERATIONS.splitlines()
        if line.startswith("| `STORAGE_CORRUPT`")
    )


def what_to_do(row):
    # Code | When | What to do. Cells do not contain a raw |.
    cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
    if len(cells) != 3:
        raise AssertionError(cells)
    return cells[2]


def start_refusal():
    marker = "if applied > last {"
    start = NODE.split(marker, 1)[1].split(")));", 1)[0]
    return re.sub(r"\\\n\s*", "", start)


class StorageCorruptTroubleshootingTest(unittest.TestCase):
    def test_short_log_matches_the_start_error(self):
        what = what_to_do(troubleshooting_row()).replace("`", "")
        start = start_refusal()
        for fact in (
            "do not delete segments",
            "kronik restore --from <url> into a new data directory",
            "the log lost records that were acknowledged",
        ):
            self.assertIn(fact, start, fact)
            self.assertIn(fact, what, fact)
        self.assertIn("Keep the", start)
        self.assertIn("Keep the data directory", what)
