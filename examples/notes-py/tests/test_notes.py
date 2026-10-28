import pathlib
import sys
import tomllib
import unittest

# The SDK is [tool.kronik] sdk in pyproject.toml.
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["kronik"]["sdk"]))

from kronik.testkit import TestHost  # noqa: E402


class NotesTest(unittest.TestCase):
    def host(self):
        host = TestHost.start(ROOT)
        self.addCleanup(host.close)
        return host

    def test_notes_are_created_listed_a_page_at_a_time_and_deleted(self):
        host = self.host()
        created = host.http("POST", "/notes/alice", body={"title": " first ", "body": "hello"})
        self.assertEqual(created.status, 201)
        first = created.json()
        self.assertEqual([first["id"], first["title"], first["body"]], [1, "first", "hello"])
        self.assertRegex(first["token"], r"^[0-9a-f]{16}$")
        for title in ["second", "third"]:
            self.assertEqual(host.http("POST", "/notes/alice", body={"title": title}).status, 201)

        page = host.http("GET", "/notes/alice?limit=2").json()
        self.assertEqual([n["title"] for n in page["notes"]], ["first", "second"])
        self.assertEqual(page["next"], 2)
        last = host.http("GET", f"/notes/alice?after={page['next']}&limit=2").json()
        self.assertEqual([n["title"] for n in last["notes"]], ["third"])
        self.assertIsNone(last["next"])

        self.assertEqual(host.http("DELETE", "/notes/alice/2").status, 204)
        self.assertEqual(host.http("GET", "/notes/alice/2").status, 404)
        self.assertEqual(host.http("DELETE", "/notes/alice/2").status, 404)
        self.assertEqual(host.http("GET", "/notes/alice/3").json()["title"], "third")

    def test_invalid_notes_and_pages_are_refused(self):
        host = self.host()
        self.assertEqual(host.http("POST", "/notes/bob", body="not json").status, 400)
        self.assertEqual(host.http("POST", "/notes/bob", body={"title": ""}).status, 400)
        self.assertEqual(host.http("POST", "/notes/bob", body={"title": "x", "body": 5}).status, 400)
        self.assertEqual(host.http("GET", "/notes/bob?limit=0").status, 400)
        self.assertEqual(host.http("GET", "/notes/bob?after=x").status, 400)
        self.assertEqual(host.http("GET", "/notes/bob/abc").status, 404)
        # Notes belong to their actor's user: bob has none of alice's.
        self.assertEqual(host.http("GET", "/notes/bob").json(), {"notes": [], "next": None})


if __name__ == "__main__":
    unittest.main()
