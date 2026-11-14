"""Cross-revision state_hash handling in the compatibility corpus checker:
the durable path (log_hash) is strict; the internal state projection records
an explicit delta across a producer-revision boundary instead of failing, and
still fails at the same revision. The producer also refuses a binary that is
not the pinned, declared release; and from v0.5.0 its scenario adds blobs and
connections, whose checks are tested here on synthetic answers. These tests use
synthetic stand-ins and produce no corpus."""
import argparse
import copy
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
CORPUS = runpy.run_path(str(SCRIPTS / "compatibility-corpus.py"))
COMPARE = CORPUS["compare_integrity_hashes"]
REASON = CORPUS["Violation"]
EXPECTED_VERSION = CORPUS["expected_version"]
RELEASE_TAG = CORPUS["release_tag"]
PRODUCE = CORPUS["producer"]
DIGEST = CORPUS["digest"]


def integrity(state_hash, log_hash):
    return {"state_hash": state_hash, "log_hash": log_hash}


class CompareIntegrityHashesTest(unittest.TestCase):
    MANIFEST = {"producer_revision": "a" * 40, "integrity": integrity("state-1", "log-1")}

    def test_log_hash_is_always_strict_even_across_revisions(self):
        after = integrity("state-1", "log-2")
        with self.assertRaises(REASON):
            COMPARE(self.MANIFEST, after, "b" * 40)

    def test_state_hash_change_at_the_same_revision_fails(self):
        after = integrity("state-2", "log-1")
        with self.assertRaises(REASON):
            COMPARE(self.MANIFEST, after, "a" * 40)

    def test_state_hash_change_across_revisions_records_an_explicit_delta(self):
        after = integrity("state-2", "log-1")
        delta = COMPARE(self.MANIFEST, after, "b" * 40)
        self.assertEqual(delta, {"producer": "state-1", "candidate": "state-2"})

    def test_matching_hashes_require_no_delta(self):
        self.assertIsNone(COMPARE(self.MANIFEST, integrity("state-1", "log-1"), "b" * 40))


class ReleaseIdentityTest(unittest.TestCase):
    def test_each_actual_release_reports_its_own_version_line(self):
        self.assertEqual("kronik 0.1.0-dev", EXPECTED_VERSION("v0.1.0"))
        self.assertEqual("kronik 0.3.0", EXPECTED_VERSION("v0.3.0"))
        self.assertEqual("kronik 0.4.0", EXPECTED_VERSION("v0.4.0"))

    def test_a_later_release_needs_no_script_edit_and_no_development_string(self):
        for release in ("v0.2.0", "v0.4.1", "v0.5.0", "v0.10.12"):
            with self.subTest(release=release):
                self.assertEqual("kronik " + release[1:], EXPECTED_VERSION(release))

    def test_a_release_is_an_exact_tag(self):
        for value in ("", "0.4.0", "v0.4", "v1.0.0", "v0.4.0-dev", "v0.4.0\n", " v0.4.0", "V0.4.0", "v0.4.x", "v0.4.0.1"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    RELEASE_TAG(value)
                with self.assertRaises(argparse.ArgumentTypeError):
                    EXPECTED_VERSION(value)


class ProducerBinaryTest(unittest.TestCase):
    """A stand-in that reports a fixed version; the checks run before any daemon starts."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "kronik"
        self.binary.write_text("#!/bin/sh\nprintf 'kronik 0.3.0\\nwasmtime 50.0.0\\n'\n")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)

    def produce(self, release, binary_sha256, **guests):
        return PRODUCE(argparse.Namespace(release=release, binary=self.binary, binary_sha256=binary_sha256,
                                          workdir=self.root / "work", **guests))

    def release_binary(self, version):
        self.binary.write_text(f"#!/bin/sh\nprintf 'kronik {version}\\nwasmtime 50.0.1\\n'\n")
        return DIGEST(self.binary)

    def test_a_binary_other_than_the_pinned_digest_is_refused(self):
        with self.assertRaisesRegex(REASON, "pinned release SHA-256"):
            self.produce("v0.3.0", "0" * 64)

    def test_a_pinned_binary_of_another_release_is_not_the_declared_release(self):
        with self.assertRaisesRegex(REASON, "not the declared actual release v0.4.0"):
            self.produce("v0.4.0", DIGEST(self.binary))

    def test_from_v0_5_0_the_producer_needs_the_media_and_room_guests(self):
        pinned = self.release_binary("0.5.0")
        with self.assertRaisesRegex(REASON, "give --media and --room"):
            self.produce("v0.5.0", pinned, media=None, room=None)

    def test_before_v0_5_0_the_producer_refuses_them(self):
        pinned = self.release_binary("0.4.1")
        with self.assertRaisesRegex(REASON, "has no blobs or connections"):
            self.produce("v0.4.1", pinned, media=Path("media.wasm"), room=Path("room.wasm"))

    def test_blobs_and_connections_start_with_v0_5_0(self):
        records = CORPUS["records_blobs_and_connections"]
        for release, expected in (("v0.1.0", False), ("v0.4.1", False), ("v0.5.0", True),
                                  ("v0.5.1", True), ("v0.10.0", True)):
            with self.subTest(release=release):
                self.assertIs(records(release), expected)

    def test_the_media_and_room_guests_go_together(self):
        script = SCRIPTS / "compatibility-corpus.py"
        result = subprocess.run(
            [sys.executable, str(script), "produce", "--release", "v0.5.0", "--binary-sha256", "0" * 64,
             "--counter", "c.wasm", "--notes", "n.wasm", "--media", "m.wasm", "--binary", "kronik",
             "--revision", "a" * 40, "--workdir", "work", "--port", "40000"],
            capture_output=True, text=True, timeout=30, cwd=tempfile.gettempdir())
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn("--media and --room go together", result.stderr)

    def test_the_configuration_has_no_blob_switch(self):
        # v0.5.0 removed `[blobs] enabled` (M26 slice B20) and refuses a
        # configuration that sets it; no release needs the table.
        CORPUS["configure"](self.root, self.root / "data", self.root / "api.sock")
        config = (self.root / "kronik.toml").read_text()
        self.assertNotIn("[blobs]", config)
        self.assertNotIn("enabled", config)


class BlobScenarioTest(unittest.TestCase):
    """The blob scenario's parts that need no daemon."""

    def test_fixture_bytes_are_deterministic_and_sized(self):
        fixture = CORPUS["fixture_bytes"]
        self.assertEqual(fixture("upload", 200_000), fixture("upload", 200_000))
        self.assertEqual(200_000, len(fixture("upload", 200_000)))
        self.assertNotEqual(fixture("upload", 1000), fixture("document", 1000))

    def test_every_blob_is_a_blob_and_at_most_300_kb(self):
        sizes = CORPUS["BLOB_SIZES"]
        self.assertEqual({"upload", "fetched", "written", "callee_reply", "put", "timer", "reply"}, set(sizes))
        for name, size in sizes.items():
            with self.subTest(name=name):
                self.assertGreater(size, CORPUS["BLOB_THRESHOLD"])
                self.assertLessEqual(size, 300_000)
        self.assertEqual(64 << 10, CORPUS["BLOB_THRESHOLD"])

    def test_the_media_pattern_is_the_guests(self):
        pattern = CORPUS["media_pattern"]
        self.assertEqual(bytes([7, 38, 69, 100, 131]), pattern(5))
        self.assertEqual(1000, len(pattern(1000)))
        # Period 251: byte 251 is byte 0 again.
        self.assertEqual(pattern(256)[:5], pattern(256)[251:256])

    def test_the_checksum_is_fnv1a_64(self):
        fnv = CORPUS["fnv1a64"]
        self.assertEqual("cbf29ce484222325", fnv(b""))
        self.assertEqual("af63dc4c8601ec8c", fnv(b"a"))
        self.assertEqual("85944171f73967e8", fnv(b"foobar"))

    def test_a_blob_answer_names_a_hash_and_a_size(self):
        answer = CORPUS["blob_answer"]
        self.assertEqual({"hash": "b3:" + "a" * 64, "size": 12}, answer("blob b3:" + "a" * 64 + " 12"))
        self.assertEqual("b3s:" + "b" * 64, answer("blob b3s:" + "b" * 64 + " 1")["hash"])
        for bad in ("inline 12", "blob b3:xyz 12", "blob b3:" + "a" * 64, "blob b3:" + "a" * 64 + " -1",
                    "blob B3:" + "a" * 64 + " 1"):
            with self.subTest(bad=bad):
                with self.assertRaises(REASON):
                    answer(bad)

    def test_a_call_reply_is_a_kept_blob(self):
        reply = CORPUS["reply_answer"]
        self.assertEqual({"hash": "b3:" + "c" * 64, "size": 80_000},
                         reply("reply blob b3:" + "c" * 64 + " 80000 retained"))
        for bad in ("reply none", "reply blob b3:" + "c" * 64 + " 80000", "call error Unavailable"):
            with self.subTest(bad=bad), self.assertRaises(REASON):
                reply(bad)

    def test_the_store_names_its_blobs_by_their_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            for name in ("ab/b3-" + "a" * 64, "cd/b3s-" + "c" * 64, "ab/b3-" + "a" * 64 + ".tmp", "ef/other"):
                (data / "blobs/objects" / name).parent.mkdir(parents=True, exist_ok=True)
                (data / "blobs/objects" / name).write_bytes(b"x")
            self.assertEqual({"b3:" + "a" * 64, "b3s:" + "c" * 64}, CORPUS["store_blobs"](data))

    def test_the_f1_hook_has_its_blob(self):
        # Enabling CALLEE_WRITTEN_REPLY needs nothing else: its blob has a size.
        self.assertIn("callee_reply", CORPUS["BLOB_SIZES"])
        self.assertIsInstance(CORPUS["CALLEE_WRITTEN_REPLY"], bool)


def transcript(sent=2, received=4, close=None):
    return {"connection": "c-" + "1" * 32, "path": "/room/compat/ws", "sent": ["frame"] * sent,
            "received": ["frame"] * received, "close": close or {"initiator": "actor", "cause": "actor", "code": 1000}}


def view(incoming=2, out=4, written=4, dropped=0, initiator="actor", code=1000):
    return {"id": "c-" + "1" * 32, "state": "closed", "subject": None,
            "frames": {"in": incoming, "out": out, "written": written, "queued": 0, "dropped": dropped, "unknown": 0},
            "closed": {"turn_id": "main:9", "initiator": initiator, "cause": initiator, "code": code}}


class ConnectionScenarioTest(unittest.TestCase):
    """The connection scenario's checks on synthetic records."""

    def test_a_record_that_agrees_with_its_transcript_passes(self):
        CORPUS["check_transcript"](view(), transcript())
        # A later binary may add fields.
        later = view()
        later["frames"]["bytes"] = 10
        CORPUS["check_transcript"](later, transcript())

    def test_a_record_that_disagrees_with_its_transcript_fails(self):
        for changed in (view(incoming=1), view(out=5, written=5), view(written=3, dropped=1),
                        view(initiator="client"), view(code=1001)):
            with self.subTest(changed=changed), self.assertRaises(REASON):
                CORPUS["check_transcript"](changed, transcript())

    def test_the_room_message_is_the_guests_json(self):
        self.assertEqual('{"type":"message","seq":1,"user":"7","text":"released corpus hello"}',
                         CORPUS["room_message"](1, "7", "released corpus hello"))

    def test_closed_connections_leave_out_what_this_node_or_retention_changes(self):
        connection = {"id": "c-" + "0" * 32, "actor": "room/compat", "state": "closed",
                      "opened": {"turn_id": "main:9", "logical_time_ms": 7},
                      "closed": {"cause": "actor", "code": 1000}, "live": None}

        class Daemon:
            def api(self, method, path, body=None, timeout=60):
                return 200, {"connections": [connection], "next": None}

        self.assertEqual([{"id": "c-" + "0" * 32, "actor": "room/compat", "state": "closed",
                           "opened": {"turn_id": "main:9"}, "closed": {"cause": "actor", "code": 1000}}],
                         CORPUS["closed_connections"](Daemon()))


class AgreesTest(unittest.TestCase):
    def test_a_later_binary_may_add_fields_but_not_change_or_drop_them(self):
        agrees = CORPUS["agrees"]
        recorded = {"a": 1, "b": [{"c": None}], "d": {"e": "x"}}
        self.assertTrue(agrees(recorded, {"a": 1, "b": [{"c": None, "new": 2}], "d": {"e": "x"}, "f": 0}))
        for changed in ({"a": 2, "b": [{"c": None}], "d": {"e": "x"}}, {"b": [{"c": None}], "d": {"e": "x"}},
                        {"a": 1, "b": [], "d": {"e": "x"}}, {"a": 1, "b": [{"c": None}, {}], "d": {"e": "x"}},
                        {"a": True, "b": [{"c": None}], "d": {"e": "x"}}, {"a": 1.0, "b": [{"c": None}], "d": {"e": "x"}}):
            with self.subTest(changed=changed):
                self.assertFalse(agrees(recorded, changed))


def observations():
    """The observations of a v0.5.0 corpus, reduced to what the replay checks read."""
    transcripts = {"member-7": transcript(sent=3, received=11), "member-anonymous": transcript(sent=2),
                   "follower": transcript(sent=0, received=2)}
    return {"roots": {"counter": 7, "notes": 2, "media": 9, "room": 14},
            "connections": {"transcripts": transcripts, "send_now": 3}}


def diff():
    """A replay's diff of that corpus, in the shape of `kronik.diff/v1`."""
    kinds = [{"kind": kind, "root_inputs": roots, "divergent_turns": 0}
             for kind, roots in observations()["roots"].items()]
    return {"kinds": kinds,
            "frames": {"inputs": {"open": 3, "frame": 5, "close": 3}, "unchanged": 11, "changed": 0, "skipped": 0,
                       "sent": {"prod": 17, "fork": 17}, "send_now": {"recorded": 3, "modeled": 0}, "items": []},
            "grounding": [{"kind": "crypto.hmac-sha256", "method": "", "host": "compat-key", "route": "", "exact": 1},
                          {"kind": "http.fetch", "method": "GET", "host": "127.0.0.1", "route": "/document",
                           "exact": 1, "approximate": 0, "synthetic": 0, "live": 0, "forked": 0}]}


class ReplayCoverageTest(unittest.TestCase):
    """An identity replay of a v0.5.0 corpus covers its blob and connection turns."""

    def test_a_replay_of_every_turn_from_the_recordings_passes(self):
        CORPUS["check_replay_coverage"](diff(), observations())

    def check_fails(self, change):
        replayed = diff()
        change(replayed)
        with self.assertRaises(REASON):
            CORPUS["check_replay_coverage"](replayed, observations())

    def test_a_kind_without_all_its_roots_fails(self):
        self.check_fails(lambda d: d["kinds"].pop())
        self.check_fails(lambda d: d["kinds"][2].update(root_inputs=8))

    def test_a_divergent_turn_fails(self):
        self.check_fails(lambda d: d["kinds"][3].update(divergent_turns=1))

    def test_a_missing_connection_input_or_a_changed_frame_fails(self):
        self.check_fails(lambda d: d["frames"]["inputs"].update(frame=4))
        self.check_fails(lambda d: d["frames"].update(changed=1))
        self.check_fails(lambda d: d["frames"]["sent"].update(fork=16))

    def test_a_send_now_that_the_replay_did_not_answer_from_its_recording_fails(self):
        self.check_fails(lambda d: d["frames"]["send_now"].update(recorded=2, modeled=1))

    def test_a_fetch_that_was_not_answered_from_its_recording_fails(self):
        self.check_fails(lambda d: d["grounding"].pop())
        self.check_fails(lambda d: d["grounding"][1].update(exact=0, live=1))


class ObservationsTest(unittest.TestCase):
    """A manifest's scenario follows its release."""

    def manifest(self, release, **extra):
        return {"release": release, "observations": {"counter": {}, "notes": {}, "sink": {}, "hmac": "x", **extra}}

    def test_an_older_release_has_no_blobs_or_connections(self):
        self.assertFalse(CORPUS["check_observations"](self.manifest("v0.4.1")))
        claimed = self.manifest("v0.4.1")
        claimed["scenarios"] = CORPUS["SCENARIOS"]
        for manifest in (claimed, self.manifest("v0.4.1", blobs={})):
            with self.subTest(manifest=manifest), self.assertRaisesRegex(REASON, "no blobs or connections"):
                CORPUS["check_observations"](manifest)

    def test_from_v0_5_0_a_manifest_says_what_its_blobs_and_connections_were(self):
        manifest = self.manifest("v0.5.0", roots={}, blobs={}, connections={})
        manifest["scenarios"] = CORPUS["SCENARIOS"]
        self.assertTrue(CORPUS["check_observations"](manifest))
        for change in (lambda m: m.pop("scenarios"), lambda m: m["observations"].pop("connections"),
                       lambda m: m.update(scenarios=["counter", "notes"])):
            changed = copy.deepcopy(manifest)
            change(changed)
            with self.subTest(changed=changed), self.assertRaisesRegex(REASON, "records blobs and connections"):
                CORPUS["check_observations"](changed)

    def test_a_manifest_names_its_release(self):
        for manifest in ({"observations": {}}, {"release": "0.5.0", "observations": {}}, {"release": "v0.5.0"}):
            with self.subTest(manifest=manifest), self.assertRaises(REASON):
                CORPUS["check_observations"](manifest)


if __name__ == "__main__":
    unittest.main()
