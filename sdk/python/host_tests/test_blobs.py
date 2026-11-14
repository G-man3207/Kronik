"""The SDK's blobs (M25) in an actor that `kronik build` makes from
host_tests/files, run by a test host (`kronik test-host`). They need a
kronik binary in KRONIK_BIN: scripts/ci.sh sdks runs them after it builds
one."""

import pathlib
import sys
import unittest
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from kronik.testkit import TestHost  # noqa: E402

MIB = 1 << 20
P = 1_000_000_007
PERIOD = bytes((i * 31 + 7) % 251 for i in range(251))


def pattern(start, n):
    k = start % 251
    return (PERIOD * ((k + n) // 251 + 1))[k : k + n]


def checksum(data):
    """The fixture's probe: every 4093th byte, weighted by its place."""
    return sum(data[i] * ((i // 4093) % 7 + 1) for i in range(0, len(data), 4093)) % P


class BlobsTest(unittest.TestCase):
    def test_an_actor_reads_answers_writes_and_sends_blobs(self):
        host = TestHost.start(HERE / "files")
        self.addCleanup(host.close)
        host.grant("files", "http:store.test")

        # A small body stays inline.
        small = pattern(0, 100)
        self.assertEqual(
            host.http("POST", "/files/a/info", body=small).json(),
            {"blob": False, "size": 100, "range": list(small[2:6]), "streamed": checksum(small), "whole": checksum(small)},
        )

        # One above the blob threshold (1 MiB) is a blob: read in a range,
        # with a reader and whole.
        big = pattern(0, MIB + MIB // 2)
        self.assertEqual(
            host.http("POST", "/files/a/info", body=big).json(),
            {"blob": True, "size": len(big), "range": list(big[2:6]), "streamed": checksum(big), "whole": checksum(big)},
        )

        # Answering with the blob it got.
        echo = host.http("POST", "/files/a/echo", body=big, headers={"content-type": "application/x-test"})
        self.assertEqual(echo.status, 200)
        self.assertEqual(echo.blob["size"], len(big))
        self.assertEqual(echo.header("content-type"), "application/x-test")
        self.assertEqual(echo.body, big)

        # A blob written in parts that are not whole frames.
        written = host.http("POST", "/files/a/write?size=1310720")
        self.assertEqual(written.blob["size"], 1310720)
        self.assertEqual(written.body, pattern(0, 1310720))

        # The blob it got as a fetch's body; the fetch's large answer is a blob.
        answer = pattern(7, MIB + MIB // 4)
        host.stub("http://store.test/up", body=answer)
        url = urllib.parse.quote("http://store.test/up", safe="")
        relayed = host.http("POST", f"/files/a/relay?url={url}", body=big)
        self.assertEqual(relayed.json(), {"status": 200, "blob": True, "size": len(answer), "sum": checksum(answer)})
        [sent] = host.requests()
        self.assertEqual(sent.method, "POST")
        self.assertEqual(sent.body, big)

        # A reference the turn never got.
        self.assertEqual(host.http("GET", "/files/a/forged").json(), {"error": "BLOB_NOT_HELD"})


if __name__ == "__main__":
    unittest.main()
