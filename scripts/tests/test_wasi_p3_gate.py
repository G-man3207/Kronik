"""Offline tests of scripts/check-wasi-p3-gate.py with canned inputs.

Nothing here touches the network: the script's fetcher is replaced by a table
of canned responses, and the HTTP layer by a fake opener. The inputs are
short, synthetic imitations of the upstream files, not copies of them.
"""
import contextlib
import datetime
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
GATE = runpy.run_path(str(ROOT / "scripts/check-wasi-p3-gate.py"))
RAW, NPM = GATE["RAW"], GATE["NPM"]
FormatError, FetchError = GATE["FormatError"], GATE["FetchError"]
NOW = datetime.datetime(2026, 11, 7, 12, 0, 0, tzinfo=datetime.timezone.utc)

BANNER_HEAD = """\
//! Experimental, unstable and incomplete implementation of wasip3 version of WASI.
//!
//! This module is under heavy development.
//! It is not compliant with semver and is not ready
//! for production use.
//!
//! Bug and security fixes limited to wasip3 will not be given patch releases.
//!
//! Documentation of this module may be incorrect or out-of-sync with the implementation.
"""
LIFTED_HEAD = """\
//! Implementation of the WASI 0.3 interfaces.
//!
//! Fixes for this module are included in patch releases.
"""
ITEMS = """
pub mod bindings;
pub mod cli;

use core::pin::Pin;

/// Like `add_to_linker`, but with the ability to enable unstable features.
pub fn add_to_linker_with_options() {}
"""
ALL_MARKERS = ("experimental", "unstable", "incomplete", "heavy development",
               "not compliant with semver", "not ready for production", "no patch releases")


def tiers_document(tier1="", tier2="", tier3="", matrix=""):
    """A stability-tiers document; the arguments are extra table rows."""
    return f"""# Tiers of Support in Wasmtime

## Current Tier Status

#### Tier 1

| Category             | Description                                |
|----------------------|--------------------------------------------|
| Target               | `x86_64-unknown-linux-gnu`                 |
| WebAssembly Proposal | [`component-model`]                        |
| WASI Proposal        | [`wasi-io`]                                |
| WASI Proposal        | [`wasi-http`]                              |
{tier1}
[`wasi-http`]: https://example.org/wasi-http

#### Tier 2

| Category             | Description                | Missing Tier 1 Requirements |
|----------------------|----------------------------|-----------------------------|
| Target               | `aarch64-unknown-linux-gnu`| Continuous fuzzing          |
{tier2}

#### Tier 3

| Category             | Description                       | Missing Tier 2 Requirements |
|----------------------|-----------------------------------|-----------------------------|
| WASI Proposal        | [`wasi-nn`]                       | More expansive CI testing   |
{tier3}

#### Under consideration

| Category             | Description                         |
|----------------------|-------------------------------------|
| WebAssembly Proposal | [`component-model-async`] (planned) |

#### Compiler Support

| Feature                                 | x86\\_64 | aarch64 |
|-----------------------------------------|----------|---------|
| [`simd`]                                | yes      | yes     |
{matrix}

## Tier Details

#### Tier 1 - Production Ready

Prose about component-model-async that is not a table row.
"""


CMA = "| WebAssembly Proposal | [`component-model-async`]                  |"
P3_ROW = "| WASI Proposal        | [`wasip3`]                                 |"
MATRIX_CMA = "| [`component-model-async`]               | yes      | yes     |"


def npm_document(readme="Builds components for `wasi:http/incoming-handler@0.2.0`.", latest="0.23.0",
                 dependencies=None, description="ESM to WebAssembly Component creator", extra_versions=None):
    versions = {"0.22.0": {"version": "0.22.0", "description": "an older release"},
                latest: {"version": latest, "description": description,
                         "dependencies": dependencies or {"oxc-parser": "^0.76.0"}}}
    versions.update(extra_versions or {})
    return json.dumps({"name": "@bytecodealliance/componentize-js", "dist-tags": {"latest": latest},
                       "readme": readme, "versions": versions,
                       "time": {"0.22.0": "2026-07-31T08:24:01.526Z", latest: "2026-09-21T09:47:38.951Z"}})


def canned(release=50, **overrides):
    """Responses for a closed gate: banners everywhere, component-model-async tier 1 on main only."""
    table = {}
    for ref in ("main", f"release-{release}.0.0"):
        table[f"{RAW}/{ref}/crates/wasi/src/p3/mod.rs"] = (200, BANNER_HEAD + ITEMS)
        table[f"{RAW}/{ref}/crates/wasi-http/src/p3/mod.rs"] = (200, BANNER_HEAD + ITEMS)
        table[f"{RAW}/{ref}/docs/stability-tiers.md"] = (
            200, tiers_document(tier1=CMA if ref == "main" else "", matrix=MATRIX_CMA))
    for major in range(50, release + 1):
        table[f"{RAW}/v{major}.0.0/README.md"] = (200, "readme")
    table[f"{RAW}/v{release + 1}.0.0/README.md"] = (404, "")
    table[NPM] = (200, npm_document())
    table.update(overrides)
    return table


def open_gate(release=50):
    """Responses where every condition holds on main and in the release."""
    lifted = (200, LIFTED_HEAD + ITEMS)
    tiers = (200, tiers_document(tier1=CMA + "\n" + P3_ROW))
    overrides = {NPM: (200, npm_document(readme="Targets `wasi:http/handler@0.3.0`.", latest="0.24.0"))}
    for ref in ("main", f"release-{release}.0.0"):
        overrides[f"{RAW}/{ref}/crates/wasi/src/p3/mod.rs"] = lifted
        overrides[f"{RAW}/{ref}/crates/wasi-http/src/p3/mod.rs"] = lifted
        overrides[f"{RAW}/{ref}/docs/stability-tiers.md"] = tiers
    return canned(release, **overrides)


def run(table, *args, root=None):
    """Runs main() against canned responses: (exit status, stdout, requested URLs)."""
    requested = []

    def fetch(url, accept="*/*"):
        requested.append(url)
        response = table[url]  # a URL the test did not expect is a KeyError
        if isinstance(response, Exception):
            raise response
        return response

    out = io.StringIO()
    with tempfile.TemporaryDirectory() as empty, contextlib.redirect_stdout(out):
        status = GATE["main"](list(args), fetch=fetch, root=root or Path(empty), now=NOW)
    return status, out.getvalue(), requested


class BannerTest(unittest.TestCase):
    def test_every_phrase_of_the_banner_is_found_even_when_it_wraps_over_lines(self):
        self.assertEqual(GATE["banner"](BANNER_HEAD + ITEMS), ALL_MARKERS)

    def test_the_same_words_below_the_first_item_are_not_the_banner(self):
        self.assertEqual(GATE["banner"](LIFTED_HEAD + ITEMS), ())

    def test_a_banner_that_is_only_partly_lifted_is_still_a_banner(self):
        head = "//! Bug and security fixes limited to wasip3 will not be given patch releases.\n"
        self.assertEqual(GATE["banner"](head + ITEMS), ("no patch releases",))

    def test_a_block_comment_banner_is_found(self):
        head = "/*! Experimental implementation.\n * Not ready for production use.\n */\n"
        self.assertEqual(GATE["banner"](head + ITEMS), ("experimental", "not ready for production"))

    def test_attributes_and_plain_comments_before_the_doc_block_are_skipped(self):
        head = "// Licensed under the Apache License.\n#![deny(missing_docs)]\n//! Experimental.\n"
        self.assertEqual(GATE["banner"](head + ITEMS), ("experimental",))

    def test_a_file_without_a_module_declaration_is_a_format_error(self):
        for text in ("", "404: Not Found", "<!DOCTYPE html><title>Not Found</title>"):
            with self.assertRaises(FormatError):
                GATE["banner"](text)


class TiersTest(unittest.TestCase):
    def facts(self, **rows):
        return GATE["tier_facts"](tiers_document(**rows))

    def test_component_model_async_is_read_from_the_tier_tables_with_its_lowest_tier(self):
        self.assertIsNone(self.facts(matrix=MATRIX_CMA).component_model_async)  # a compiler matrix is no tier
        self.assertEqual(self.facts(tier1=CMA).component_model_async, 1)
        self.assertEqual(self.facts(tier2=CMA).component_model_async, 2)
        self.assertEqual(self.facts(tier3=CMA).component_model_async, 3)
        self.assertEqual(self.facts(tier2=CMA, tier3=CMA).component_model_async, 2)

    def test_the_wasi_http_row_of_wasi_0_2_is_not_wasip3(self):
        facts = self.facts()
        self.assertIsNone(facts.wasip3)
        self.assertEqual(facts.mentions, ())

    def test_wasip3_rows_are_found_by_their_wasi_category_and_a_p3_description(self):
        self.assertEqual(self.facts(tier2=P3_ROW).wasip3, 2)
        self.assertEqual(self.facts(tier1="| WASI Proposal | [`wasi-http`] (WASI 0.3) |").wasip3, 1)
        self.assertEqual(self.facts(tier3="| WASI Proposal | `wasi-p3` | unstable |").wasip3, 3)
        self.assertEqual(self.facts(tier1="| WASI Proposal | WASI Preview 3 |").wasip3, 1)

    def test_a_compile_target_named_wasip3_is_not_wasi_support_but_is_mentioned(self):
        facts = self.facts(tier3="| Target | `wasm32-wasip3` | full-time maintainer |")
        self.assertIsNone(facts.wasip3)
        self.assertIn("wasm32-wasip3", facts.mentions[0])

    def test_a_version_that_merely_contains_the_digits_is_not_wasi_0_3(self):
        self.assertIsNone(self.facts(tier1="| WASI Proposal | `wasi-clocks` 10.3 and 0.2.3 |").wasip3)

    def test_a_document_without_tier_one_rows_is_a_format_error(self):
        for text in ("", "# Tiers\n\nNothing here.\n", "#### Tier 1 - Production Ready\n| Category | Description |\n"):
            with self.assertRaises(FormatError):
                GATE["tier_facts"](text)


class NpmTest(unittest.TestCase):
    def test_a_latest_release_that_only_knows_wasi_0_2_has_no_evidence(self):
        facts = GATE["npm_facts"](npm_document(), pinned="0.23.0")
        self.assertEqual((facts.latest, facts.strong, facts.weak), ("0.23.0", (), ()))
        self.assertEqual(facts.published, "2026-09-21T09:47:38.951Z")
        self.assertEqual(facts.pinned, "0.23.0")

    def test_dependency_versions_and_specs_are_not_read_only_their_names(self):
        document = npm_document(dependencies={"@bytecodealliance/weval": "^0.3.1", "wizer": "0.3.0",
                                              "shim": "npm:other-shim-preview3@1.0.0",
                                              "fork": "git+https://example.org/wasip3-fork.git"})
        facts = GATE["npm_facts"](document)
        self.assertEqual((facts.strong, facts.weak), ((), ()))

    def test_wasi_http_0_3_in_the_readme_is_strong_evidence(self):
        for text in ("Targets wasi:http@0.3.0.", "exports `wasi:http/handler@0.3.0-rc-2026-01-01`",
                     "imports WASI:HTTP/client@0.3"):
            facts = GATE["npm_facts"](npm_document(readme=text))
            self.assertTrue(facts.strong, text)

    def test_other_words_for_wasi_0_3_are_only_a_hint(self):
        for text, hint in (("Experimental wasip3 support.", "wasip3"), ("Runs on WASI 0.3.", "wasi 0.3"),
                           ("Uses wasi:cli@0.3.0.", "wasi:cli@0.3.0")):
            facts = GATE["npm_facts"](npm_document(readme=text))
            self.assertEqual((facts.strong, facts.weak), ((), (hint,)), text)

    def test_a_preview3_dependency_name_is_a_hint(self):
        facts = GATE["npm_facts"](npm_document(dependencies={"@bytecodealliance/preview3-shim": "^0.13.0"}))
        self.assertEqual((facts.strong, facts.weak), ((), ("preview3",)))

    def test_only_the_release_tagged_latest_is_read(self):
        older = {"0.25.0-rc.0": {"version": "0.25.0-rc.0", "description": "targets wasi:http@0.3"}}
        facts = GATE["npm_facts"](npm_document(extra_versions=older))
        self.assertEqual(facts.strong, ())

    def test_a_document_of_another_shape_is_a_format_error(self):
        for text in ("", "not json", "[]", "{}", json.dumps({"dist-tags": {"latest": "1.0.0"}, "versions": {}}),
                     json.dumps({"dist-tags": {"latest": 1}, "versions": {"1": {}}}),
                     json.dumps({"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": "x"}})):
            with self.assertRaises(FormatError, msg=text):
                GATE["npm_facts"](text)

    def test_the_pinned_version_is_read_from_the_sdk_lockfile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(GATE["pinned_componentize"](root))
            (root / "sdk/ts").mkdir(parents=True)
            lock = root / "sdk/ts/package-lock.json"
            lock.write_text("{")
            self.assertIsNone(GATE["pinned_componentize"](root))
            lock.write_text(json.dumps({"packages": {GATE["COMPONENTIZE"]: {"version": "0.23.0"}}}))
            self.assertEqual(GATE["pinned_componentize"](root), "0.23.0")
            lock.write_text(json.dumps({"packages": {GATE["COMPONENTIZE"]: {"version": 23}}}))
            self.assertIsNone(GATE["pinned_componentize"](root))

    def test_versions_compare_like_semver_with_prereleases_below_releases(self):
        parse = GATE["parse_version"]
        self.assertLess(parse("0.23.0"), parse("0.24.0"))
        self.assertLess(parse("0.24.0-rc.0"), parse("0.24.0"))
        self.assertLess(parse("0.9.9"), parse("0.10.0"))
        self.assertIsNone(parse("latest"))


class ReleaseDiscoveryTest(unittest.TestCase):
    def tags(self, existing, status_for_others=404):
        def fetch(url, accept="*/*"):
            major = int(url.rsplit("/v", 1)[1].split(".")[0])
            return (200, "readme") if major in existing else (status_for_others, "")
        return fetch

    def test_the_newest_major_with_a_final_tag_is_the_release(self):
        self.assertEqual(GATE["newest_released_major"](self.tags({50})), 50)
        self.assertEqual(GATE["newest_released_major"](self.tags({50, 51})), 51)
        self.assertEqual(GATE["newest_released_major"](self.tags({50, 51, 52, 53})), 53)

    def test_only_final_tags_are_probed_so_a_release_candidate_does_not_count(self):
        probed = []

        def fetch(url, accept="*/*"):
            probed.append(url)
            return (200, "readme") if url.endswith("/v50.0.0/README.md") else (404, "")

        self.assertEqual(GATE["newest_released_major"](fetch), 50)
        self.assertEqual(probed, [f"{RAW}/v50.0.0/README.md", f"{RAW}/v51.0.0/README.md"])

    def test_a_missing_first_tag_is_a_format_error(self):
        with self.assertRaises(FormatError):
            GATE["newest_released_major"](self.tags(set()))

    def test_an_unexpected_status_is_a_fetch_error(self):
        with self.assertRaises(FetchError):
            GATE["newest_released_major"](self.tags(set(), status_for_others=403))

    def test_a_server_that_has_every_tag_is_a_format_error(self):
        with self.assertRaises(FormatError):
            GATE["newest_released_major"](lambda url, accept="*/*": (200, "readme"))


class Response:
    def __init__(self, status, body=b""):
        self.status, self.body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


class HttpGetTest(unittest.TestCase):
    def opener(self, *outcomes):
        """An opener that answers each call with the next outcome (a Response or an exception)."""
        calls, outcomes = [], list(outcomes)

        def open_url(request, timeout):
            calls.append((request, timeout))
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        open_url.calls = calls
        return open_url

    def get(self, *outcomes, **options):
        sleeps = []
        opener = self.opener(*outcomes)
        try:
            result = GATE["http_get"]("https://example.org/x", opener=opener, sleep=sleeps.append, **options)
        except FetchError as error:
            result = error
        return result, opener, sleeps

    def http_error(self, status, body=b"missing"):
        return urllib.error.HTTPError("https://example.org/x", status, "text", {}, io.BytesIO(body))

    def test_a_successful_get_sends_a_user_agent_and_no_credentials(self):
        (result, opener, sleeps) = self.get(Response(200, "caf\u00e9".encode()), accept="application/json", timeout=7)
        self.assertEqual(result, (200, "caf\u00e9"))
        request, timeout = opener.calls[0]
        self.assertEqual(timeout, 7)
        headers = {name.lower(): value for name, value in request.header_items()}
        self.assertEqual(set(headers), {"user-agent", "accept"})
        self.assertEqual(headers["accept"], "application/json")
        self.assertIn("kronik", headers["user-agent"].lower())
        self.assertTrue(headers["user-agent"].isascii())
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(sleeps, [])

    def test_a_404_is_an_answer_not_an_error(self):
        (result, opener, sleeps) = self.get(self.http_error(404))
        self.assertEqual(result, (404, "missing"))
        self.assertEqual(len(opener.calls), 1)

    def test_a_server_error_is_tried_again_and_then_succeeds(self):
        (result, opener, sleeps) = self.get(self.http_error(503), Response(200, b"ok"))
        self.assertEqual(result, (200, "ok"))
        self.assertEqual(len(opener.calls), 2)
        self.assertEqual(sleeps, [GATE["RETRY_DELAY"]])

    def test_rate_limiting_and_network_errors_end_in_a_fetch_error_after_the_attempts(self):
        failures = (lambda: self.http_error(429), lambda: self.http_error(500),
                    lambda: urllib.error.URLError("no route"), lambda: TimeoutError("timed out"),
                    lambda: ConnectionResetError("reset"))
        for failure in failures:
            attempts = GATE["ATTEMPTS"]
            (result, opener, sleeps) = self.get(*[failure() for _ in range(attempts)])
            self.assertIsInstance(result, FetchError, failure())
            self.assertIn("https://example.org/x", str(result))
            self.assertEqual(len(opener.calls), attempts)

    def test_a_response_larger_than_the_limit_is_refused(self):
        (result, _, _) = self.get(Response(200, b"x" * (GATE["MAX_BYTES"] + 1)))
        self.assertIsInstance(result, FetchError)

    def test_only_https_urls_are_fetched(self):
        for url in ("http://example.org/x", "file:///etc/passwd", "ftp://example.org/x"):
            with self.assertRaises(ValueError):
                GATE["http_get"](url, opener=self.opener())


class GateTest(unittest.TestCase):
    def test_a_closed_gate_exits_zero_and_shows_the_early_warning_for_main(self):
        status, out, _ = run(canned())
        self.assertEqual(status, 0)
        self.assertIn("Gate: CLOSED (exit status 0)", out)
        self.assertIn("release-50.0.0", out)
        row = next(line for line in out.splitlines() if line.startswith("(b1)"))
        self.assertEqual(row.split(),
                         "(b1) component-model-async tier, needs: 1 or 2 Tier 1 not listed main only".split())
        self.assertIn("newest Wasmtime release: 50", out)
        self.assertIn("(b1) holds on main but not in a release yet", out)

    def test_a_released_component_model_async_alone_does_not_open_the_gate(self):
        table = canned(51)
        table[f"{RAW}/release-51.0.0/docs/stability-tiers.md"] = (200, tiers_document(tier1=CMA))
        status, out, _ = run(table)
        self.assertEqual(status, 0)
        self.assertIn("newest Wasmtime release: 51", out)
        self.assertEqual(next(line for line in out.splitlines() if line.startswith("(b1)")).split()[-3:],
                         ["Tier", "1", "met"])

    def test_tier_3_is_listed_but_does_not_satisfy_the_gate(self):
        table = open_gate()
        for ref in ("main", "release-50.0.0"):
            table[f"{RAW}/{ref}/docs/stability-tiers.md"] = (
                200, tiers_document(tier3=CMA + "\n" + P3_ROW))
        status, out, _ = run(table)
        self.assertEqual(status, 0)
        row = next(line for line in out.splitlines() if line.startswith("(b1)"))
        self.assertEqual(row.split()[-6:], "Tier 3 Tier 3 not met".split())
        self.assertIn("Gate: CLOSED", out)

    def test_all_three_conditions_in_a_release_exit_one(self):
        status, out, _ = run(open_gate())
        self.assertEqual(status, 1)
        self.assertIn("Gate: OPEN (exit status 1)", out)
        self.assertNotIn("not met", out)

    def test_conditions_that_hold_only_on_main_keep_the_gate_closed(self):
        table = open_gate()
        for name in ("crates/wasi/src/p3/mod.rs", "crates/wasi-http/src/p3/mod.rs", "docs/stability-tiers.md"):
            table[f"{RAW}/release-50.0.0/{name}"] = canned()[f"{RAW}/release-50.0.0/{name}"]
        status, out, _ = run(table)
        self.assertEqual(status, 0)
        self.assertEqual(out.count("main only"), 4)  # the status of a1, a2, b1 and b2
        self.assertIn("(a1) holds on main but not in a release yet", out)

    def test_a_and_b_without_c_stay_closed_and_say_what_the_rust_vehicle_needs(self):
        table = open_gate()
        table[NPM] = (200, npm_document())
        status, out, _ = run(table)
        self.assertEqual(status, 0)
        self.assertIn("only (c) is open", out)
        self.assertIn("Rust guest", out)

    def test_a_weak_hint_for_c_is_shown_but_does_not_satisfy_it(self):
        table = open_gate()
        table[NPM] = (200, npm_document(readme="Experimental wasip3 support.", latest="0.24.0"))
        status, out, _ = run(table)
        self.assertEqual(status, 0)
        self.assertIn("other words, which does not satisfy (c): wasip3", out)
        self.assertIn("only (c) is open", out)

    def test_c_without_the_wasmtime_conditions_stays_closed(self):
        table = canned()
        table[NPM] = (200, npm_document(readme="Targets wasi:http@0.3.0", latest="0.24.0"))
        status, out, _ = run(table)
        self.assertEqual(status, 0)
        self.assertNotIn("only (c) is open", out)

    def test_a_partly_lifted_banner_is_reported_with_what_it_still_says(self):
        table = canned()
        table[f"{RAW}/main/crates/wasi/src/p3/mod.rs"] = (200, "//! Not ready for production.\n" + ITEMS)
        status, out, _ = run(table)
        self.assertEqual(status, 0)
        self.assertIn("main wasmtime-wasi p3 module: the banner is partly lifted and still says: "
                      "not ready for production", out)

    def test_a_tiers_document_that_mentions_wasip3_without_a_row_is_flagged(self):
        table = canned()
        table[f"{RAW}/main/docs/stability-tiers.md"] = (
            200, tiers_document(tier1=CMA, tier3="| Target | `wasm32-wasip3` | full-time maintainer |"))
        status, out, _ = run(table)
        self.assertEqual(status, 0)
        self.assertIn("main stability tiers mention WASI 0.3 or p3 but list no tier 1 or 2 row", out)

    def test_a_new_componentize_js_release_without_a_hint_is_flagged_for_a_manual_read(self):
        table = canned()
        table[NPM] = (200, npm_document(latest="0.24.0"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sdk/ts").mkdir(parents=True)
            (root / "sdk/ts/package-lock.json").write_text(
                json.dumps({"packages": {GATE["COMPONENTIZE"]: {"version": "0.23.0"}}}))
            status, out, _ = run(table, root=root)
        self.assertEqual(status, 0)
        self.assertIn("componentize-js 0.24.0 is newer than the pinned 0.23.0", out)
        self.assertIn("pinned by the TypeScript SDK: 0.23.0", out)

    def test_any_unreadable_source_makes_the_result_undetermined(self):
        failures = {
            "npm down": {NPM: FetchError(f"{NPM}: HTTP 503")},
            "npm not json": {NPM: (200, "<html>")},
            "main tiers moved": {f"{RAW}/main/docs/stability-tiers.md": (404, "")},
            "release banner moved": {f"{RAW}/release-50.0.0/crates/wasi/src/p3/mod.rs": (404, "")},
            "tiers of another shape": {f"{RAW}/release-50.0.0/docs/stability-tiers.md": (200, "# Tiers\n")},
            "not rust": {f"{RAW}/main/crates/wasi-http/src/p3/mod.rs": (200, "<html>Not Found</html>")},
            "tag probe fails": {f"{RAW}/v50.0.0/README.md": FetchError("timed out")},
            "tags renamed": {f"{RAW}/v50.0.0/README.md": (404, "")},
        }
        for name, change in failures.items():
            with self.subTest(name):
                table = canned()
                table.update(change)
                status, out, _ = run(table)
                self.assertEqual(status, 2)
                self.assertIn("Gate: UNDETERMINED (exit status 2)", out)
                self.assertIn("error:", out)

    def test_what_can_be_read_is_still_shown_when_a_source_fails(self):
        table = canned()
        table[NPM] = FetchError(f"{NPM}: HTTP 503")
        status, out, _ = run(table)
        self.assertEqual(status, 2)
        self.assertIn("banner", out)
        self.assertIn("error: npm: ", out)

    def test_only_the_named_sources_are_requested_and_only_once(self):
        _, _, requested = run(canned())
        self.assertEqual(len(requested), len(set(requested)))
        self.assertEqual(sorted(url for url in requested if url.startswith(RAW + "/main/")),
                         sorted(f"{RAW}/main/{path}" for path in
                                ("crates/wasi/src/p3/mod.rs", "crates/wasi-http/src/p3/mod.rs",
                                 "docs/stability-tiers.md")))
        for url in requested:
            self.assertTrue(url.startswith(RAW + "/") or url == NPM, url)
        self.assertNotIn("api.github.com", " ".join(requested))

    def test_the_markdown_table_is_appended_to_the_given_file(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            summary.write_text("earlier step\n")
            status, out, _ = run(canned(), "--markdown", str(summary))
            text = summary.read_text()
        self.assertEqual(status, 0)
        self.assertTrue(text.startswith("earlier step\n### WASI 0.3 gate: CLOSED\n"))
        self.assertIn("| Condition | main | `release-50.0.0` | Status |", text)
        self.assertIn("| (b1) `component-model-async` tier, needs: 1 or 2 | Tier 1 | not listed | main only |", text)
        self.assertIn("| (a1) wasmtime-wasi p3 banner, needs: gone | present | present | not met |", text)
        self.assertIn("(c) componentize-js targets `wasi:http@0.3` (heuristic)", text)
        self.assertIn("heuristic over npm metadata", text)

    def test_a_markdown_file_that_cannot_be_written_only_warns(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()) as err:
            status, _, _ = run(canned(), "--markdown", directory)  # a directory cannot be opened for append
        self.assertEqual(status, 0)
        self.assertIn("warning: cannot append the Markdown table", err.getvalue())


if __name__ == "__main__":
    unittest.main()
