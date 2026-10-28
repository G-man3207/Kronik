import json
import pathlib
import sys
import tomllib
import unittest

# The SDK is [tool.kronik] sdk in pyproject.toml.
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["kronik"]["sdk"]))

from kronik.testkit import TestHost  # noqa: E402


class CounterTest(unittest.TestCase):
    def test_each_counter_counts_its_increments(self):
        host = TestHost.start(ROOT)
        self.addCleanup(host.close)
        for n in [1, 2, 3]:
            self.assertEqual(host.http("POST", "/counter/alice/increment").json(), {"n": n})
        self.assertEqual(host.http("GET", "/counter/alice").json(), {"n": 3})
        self.assertEqual(host.http("GET", "/counter/bob").json(), {"n": 0})

        # A message increments too and replies with the count.
        sent = host.send("counter/alice", "increment")
        self.assertEqual(json.loads(sent["reply"]["text"]), {"n": 4})
        self.assertEqual(host.state_json("counter/alice", "n"), 4)


if __name__ == "__main__":
    unittest.main()
