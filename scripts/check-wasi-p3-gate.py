#!/usr/bin/env python3
"""Reports whether the reopening gate of ADR 0070 section 5 (WASI 0.3) has opened.

Usage: python3 scripts/check-wasi-p3-gate.py [--markdown FILE] [--timeout SECONDS]

M22's third criterion (components for WASI 0.3 pass the determinism test and
identity replay) is deferred until three upstream conditions hold. The script
reads public sources, prints a table of the conditions and changes nothing.

  (a) Both p3 modules of Wasmtime, crates/wasi/src/p3/mod.rs and
      crates/wasi-http/src/p3/mod.rs, have lost the banner that calls them
      experimental, unstable, incomplete, not ready for production and
      without patch releases. Only the comment block at the top of each file
      is read: the same words appear elsewhere in the files.
  (b) docs/stability-tiers.md lists component-model-async (b1) and WASIp3 (b2)
      at tier 1 or 2. ADR 0070 writes "WASIp3 / component-model-async"; its
      amendment of 2026-11-07 reads that as both, and the table shows each row.
  (c) A componentize-js release targets wasi:http@0.3. This is a HEURISTIC:
      the npm registry has no such field, so the README, the descriptions and
      the dependency names of the release tagged `latest` are searched for
      wasi:http@0.3 (dependency versions are not read).

(a) and (b) count when they hold on the newest released Wasmtime branch,
release-N.0.0, where N is the highest major whose final tag vN.0.0 exists
(release candidates are tagged vN.0.0-rc.K and do not count). A condition that
holds only on main is shown as "main only": it reaches a release with the next
major version.

Exit status: 0 the gate is still closed; 1 all three conditions hold, which is
a prompt to check each one by hand as ADR 0070 describes, not proof; 2 not
determined (a network or format error: the table shows what could be read).

Only plain HTTPS GETs of raw.githubusercontent.com and registry.npmjs.org are
made, with no token and a descriptive User-Agent. Python 3 standard library
only. The script is informational: nothing in CI depends on its result.
"""

import argparse
import datetime
import http.client
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request
from typing import NamedTuple, Optional

RAW = "https://raw.githubusercontent.com/bytecodealliance/wasmtime"
NPM = "https://registry.npmjs.org/@bytecodealliance%2fcomponentize-js"
USER_AGENT = ("kronik-check-wasi-p3-gate/1 (informational read-only check; "
              "+https://github.com/G-man3207/Kronik)")
TIMEOUT = 15  # seconds per request
ATTEMPTS = 2  # per URL: network errors, HTTP 429 and 5xx are tried again
RETRY_DELAY = 3  # seconds before another attempt
MAX_BYTES = 4 << 20  # the largest document is the npm one, about 160 KiB
FIRST_MAJOR = 50  # the Wasmtime major ADR 0070 was written against
MAX_PROBES = 40  # tags probed above FIRST_MAJOR before giving up

WASI_P3 = "crates/wasi/src/p3/mod.rs"
HTTP_P3 = "crates/wasi-http/src/p3/mod.rs"
TIERS = "docs/stability-tiers.md"
LOCKFILE = "sdk/ts/package-lock.json"
COMPONENTIZE = "node_modules/@bytecodealliance/componentize-js"
MODULES = {"wasi": "wasmtime-wasi", "http": "wasmtime-wasi-http"}

# What the banner at the top of a p3 module says today. Any one of them left in
# the leading comment block keeps condition (a) unmet, so a partly lifted
# banner is not mistaken for a lifted one.
BANNER_MARKERS = (
    ("experimental", re.compile(r"\bexperimental\b", re.I)),
    ("unstable", re.compile(r"\bunstable\b", re.I)),
    ("incomplete", re.compile(r"\bincomplete\b", re.I)),
    ("heavy development", re.compile(r"heavy\s+development", re.I)),
    ("not compliant with semver", re.compile(r"not\s+compliant\s+with\s+semver", re.I)),
    ("not ready for production", re.compile(r"not\s+ready\s+for\s+production", re.I)),
    ("no patch releases", re.compile(r"not\s+be\s+given\s+patch\s+releases|no\s+patch\s+releases", re.I)),
)
RUST_ITEM = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:mod|use)\s", re.M)
COMMENT_MARKS = re.compile(r"//[!/]?|/\*[!*]?|\*/|^\*")

TIER_HEADING = re.compile(r"^#{1,6}\s*Tier\s+([123])\s*$", re.I)
WASIP3_ROW = re.compile(r"wasi[\s_-]*p3|\bp3\b|preview[\s_-]*3|\b0\.3(?:\.\d+)?\b", re.I)
WASIP3_MENTION = re.compile(r"wasi[\s_-]*p3|\bp3\b|preview[\s_-]*3|wasi\S*\s*@?0\.3", re.I)

# wasi:<package>[/<interface>]@0.3 and the other ways a package could say that
# it targets WASI 0.3. A match that names wasi:http is the evidence (c) needs;
# the rest is a hint that is shown but does not satisfy it.
P3_EVIDENCE = re.compile(
    r"wasi:[a-z][a-z0-9-]*(?:/[a-z][a-z0-9-]*)?@0\.3(?:\.\d+)?"
    r"|wasi[\s_-]*p3|wasi\s+(?:preview\s*3|0\.3)|preview[\s_-]*3",
    re.I)
CODE_TOKEN = re.compile(r"wasi:[\w/-]+@[\d.]+|release-\d+\.0\.0|v\d+\.0\.0|component-model-async")


class FetchError(Exception):
    """A source could not be read: network error, timeout or unexpected status."""


class FormatError(Exception):
    """A source was read but is not in the shape this script expects."""


class Unknown(NamedTuple):
    """An input that could not be read."""
    why: str


class Tiers(NamedTuple):
    component_model_async: Optional[int]  # lowest tier that lists it; None: not listed
    wasip3: Optional[int]
    mentions: tuple  # lines of the document that mention WASI 0.3 or p3


class Ref(NamedTuple):
    name: str
    wasi: object  # tuple of the banner markers still present (empty: gone), or Unknown
    http: object
    tiers: object  # Tiers or Unknown


class Npm(NamedTuple):
    latest: str
    published: Optional[str]
    pinned: Optional[str]
    strong: tuple  # wasi:http@0.3 mentions
    weak: tuple  # other mentions of WASI 0.3


class Row(NamedTuple):
    label: str
    main: str
    release: str
    status: str  # met, main only, not met or unknown


class Report(NamedTuple):
    when: str
    release_name: str
    rows: list
    notes: list
    verdict: str  # CLOSED, OPEN or UNDETERMINED


# --- Fetching ---------------------------------------------------------------


def request_once(request, timeout, opener):
    try:
        with opener(request, timeout=timeout) as response:
            return response.status, response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as error:
        try:
            return error.code, error.read(MAX_BYTES + 1)
        finally:
            error.close()


def http_get(url, accept="*/*", timeout=TIMEOUT, attempts=ATTEMPTS,
             opener=urllib.request.urlopen, sleep=time.sleep):
    """GET url and return (status, text); no token is ever sent.

    Every HTTP status below 500 except 429 is returned, so that a caller can
    treat 404 as an answer. Network errors, timeouts, 429 and 5xx are tried
    again and then raise FetchError.
    """
    if not url.startswith("https://"):
        raise ValueError(f"refusing a URL that is not HTTPS: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    reason = "no attempt was made"
    for number in range(attempts):
        if number:
            sleep(RETRY_DELAY * number)
        try:
            status, body = request_once(request, timeout, opener)
        except (OSError, http.client.HTTPException) as error:
            reason = f"{type(error).__name__}: {getattr(error, 'reason', None) or error}"
            continue
        if status == 429 or status >= 500:
            reason = f"HTTP {status}"
            continue
        if len(body) > MAX_BYTES:
            raise FetchError(f"{url}: more than {MAX_BYTES} bytes")
        return status, body.decode("utf-8", errors="replace")
    raise FetchError(f"{url}: {reason}")


def get_text(fetch, url, accept="text/plain"):
    status, text = fetch(url, accept)
    if status != 200:
        raise FetchError(f"{url}: HTTP {status}")
    return text


def read_or_unknown(function):
    """The function's result, or Unknown when a source cannot be read."""
    try:
        return function()
    except (FetchError, FormatError) as error:
        return Unknown(str(error))


# --- Parsers ----------------------------------------------------------------


def module_head(source):
    """The comment block at the top of a Rust file, up to its first item, as plain words.

    A phrase can wrap over two lines, so the comment markers go and the white
    space is collapsed before the banner phrases are looked for.
    """
    head, in_block = [], False
    for line in source.splitlines():
        text = line.strip()
        if in_block:
            in_block = "*/" not in text
        elif text.startswith("/*"):
            in_block = "*/" not in text[2:]
        elif text and not text.startswith(("//", "#!")):
            break
        head.append(COMMENT_MARKS.sub(" ", text))
    return re.sub(r"\s+", " ", " ".join(head)).strip()


def banner(source):
    """The banner markers left in a p3 module's leading comment block."""
    if not RUST_ITEM.search(source):
        raise FormatError("the file is not a Rust module (it has no mod or use item)")
    head = module_head(source)
    return tuple(name for name, pattern in BANNER_MARKERS if pattern.search(head))


def tier_rows(markdown):
    """(tier, category, description) for each row of the `Tier N` tables."""
    rows, tier = [], None
    for line in markdown.splitlines():
        text = line.strip()
        if text.startswith("#"):
            heading = TIER_HEADING.match(text)
            tier = int(heading.group(1)) if heading else None
        elif tier and text.startswith("|"):
            cells = [cell.strip() for cell in text.strip("|").split("|")]
            if len(cells) >= 2 and cells[0].lower() != "category" and cells[0].strip("-: "):
                rows.append((tier, cells[0], cells[1]))
    if not any(tier == 1 for tier, _, _ in rows):
        raise FormatError("no tier 1 table rows in the stability tiers document")
    return rows


def is_component_model_async(category, description):
    return "component-model-async" in description.lower()


def is_wasip3(category, description):
    # A target row such as a wasm32-wasip3 compile target is not WASI support.
    return "wasi" in category.lower() and bool(WASIP3_ROW.search(description))


def lowest_tier(rows, matches):
    tiers = [tier for tier, category, description in rows if matches(category, description)]
    return min(tiers) if tiers else None


def tier_facts(markdown):
    rows = tier_rows(markdown)
    mentions = [line.strip()[:100] for line in markdown.splitlines() if WASIP3_MENTION.search(line)]
    return Tiers(lowest_tier(rows, is_component_model_async), lowest_tier(rows, is_wasip3),
                 tuple(mentions[:3]))


def parse_version(version):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-(.+))?", version or "")
    if match is None:
        return None
    major, minor, patch, pre = match.groups()
    return int(major), int(minor), int(patch), pre is None, pre or ""


def pinned_componentize(root):
    """The componentize-js version the TypeScript SDK installs, or None."""
    try:
        packages = json.loads((root / LOCKFILE).read_text(encoding="utf-8"))["packages"]
        version = packages[COMPONENTIZE]["version"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return version if isinstance(version, str) else None


def npm_facts(document, pinned=None):
    """The `latest` componentize-js release and its WASI 0.3 evidence."""
    try:
        package = json.loads(document)
        latest = package["dist-tags"]["latest"]
        release = package["versions"][latest]
    except (ValueError, KeyError, TypeError) as error:
        raise FormatError(f"unexpected npm document: {type(error).__name__}: {error}") from error
    if not isinstance(latest, str) or not isinstance(release, dict):
        raise FormatError("unexpected npm document: `latest` does not name a release")
    texts = [package.get("readme"), package.get("description"), release.get("description")]
    keywords = release.get("keywords")
    texts.append(" ".join(keywords) if isinstance(keywords, list) else None)
    for field in ("dependencies", "peerDependencies", "optionalDependencies"):
        dependencies = release.get(field)  # the names only: a version such as ^0.3.1 says nothing
        texts.append(" ".join(dependencies) if isinstance(dependencies, dict) else None)
    found = {match.group(0).lower() for text in texts if isinstance(text, str)
             for match in P3_EVIDENCE.finditer(text)}
    times = package.get("time")
    published = times.get(latest) if isinstance(times, dict) else None
    return Npm(latest, published if isinstance(published, str) else None, pinned,
               tuple(sorted(item for item in found if item.startswith("wasi:http")))[:5],
               tuple(sorted(item for item in found if not item.startswith("wasi:http")))[:5])


def newest_released_major(fetch):
    """The highest Wasmtime major whose final tag, vN.0.0, exists."""
    def tagged(major):
        url = f"{RAW}/v{major}.0.0/README.md"
        status, _ = fetch(url, "text/plain")
        if status not in (200, 404):
            raise FetchError(f"{url}: HTTP {status}")
        return status == 200

    if not tagged(FIRST_MAJOR):
        raise FormatError(f"tag v{FIRST_MAJOR}.0.0 does not exist: Wasmtime's release tags may be renamed")
    major = FIRST_MAJOR
    for _ in range(MAX_PROBES):
        if not tagged(major + 1):
            return major
        major += 1
    raise FormatError(f"tags exist up to v{major}.0.0: raise FIRST_MAJOR in this script")


def read_ref(fetch, name):
    """What one Wasmtime ref says about (a) and (b); a part that cannot be read is Unknown."""
    base = f"{RAW}/{name}"
    return Ref(name,
               read_or_unknown(lambda: banner(get_text(fetch, f"{base}/{WASI_P3}"))),
               read_or_unknown(lambda: banner(get_text(fetch, f"{base}/{HTTP_P3}"))),
               read_or_unknown(lambda: tier_facts(get_text(fetch, f"{base}/{TIERS}"))))


def gather(fetch, root):
    """Reads every source; one that cannot be read becomes Unknown and the run goes on."""
    major = read_or_unknown(lambda: newest_released_major(fetch))
    release = None if isinstance(major, Unknown) else read_ref(fetch, f"release-{major}.0.0")
    npm = read_or_unknown(lambda: npm_facts(get_text(fetch, NPM, "application/json"),
                                            pinned_componentize(root)))
    return major, read_ref(fetch, "main"), release, npm


# --- The gate ---------------------------------------------------------------


def banner_gone(markers):
    return not markers


def tier_listed(tier):
    return tier is not None and tier <= 2


def banner_cell(markers):
    return "?" if isinstance(markers, Unknown) else "present" if markers else "gone"


def tier_cell(tier):
    return "?" if isinstance(tier, Unknown) else "not listed" if tier is None else f"Tier {tier}"


def tier_value(ref, field):
    return ref.tiers if isinstance(ref.tiers, Unknown) else getattr(ref.tiers, field)


def status_of(main_value, release_value, holds):
    """met in the release, main only, not met, or unknown when either side cannot be read."""
    if isinstance(main_value, Unknown) or isinstance(release_value, Unknown):
        return "unknown"
    return "met" if holds(release_value) else "main only" if holds(main_value) else "not met"


def npm_notes(npm):
    notes = [f"componentize-js on npm: latest {npm.latest}"
             + (f", published {npm.published[:10]}" if npm.published else "")
             + (f", pinned by the TypeScript SDK: {npm.pinned}" if npm.pinned else "")
             + "; wasi:http@0.3 in its README, descriptions and dependency names: "
             + (", ".join(npm.strong) if npm.strong else "none")]
    if npm.weak:
        notes.append("componentize-js mentions WASI 0.3 in other words, which does not satisfy (c): "
                     + ", ".join(npm.weak))
    latest, pinned = parse_version(npm.latest), parse_version(npm.pinned)
    if latest and pinned and latest > pinned and not npm.strong:
        notes.append(f"componentize-js {npm.latest} is newer than the pinned {npm.pinned} and no hint was found; "
                     "the heuristic is weak, so read its release notes by hand")
    return notes


def evaluate(main_ref, release_ref, npm, major, when):
    """The table rows, notes and verdict for the facts gathered."""
    notes = []
    if release_ref is None:
        release_ref = Ref("release", *([Unknown("no released branch")] * 3))
        notes.append(f"error: the newest released Wasmtime branch is unknown: {major.why}")
    else:
        notes.append(f"newest Wasmtime release: {major} (tag v{major}.0.0 exists, v{major + 1}.0.0 does not); "
                     f"the release column is branch {release_ref.name}")
    rows = []
    for label, field in (("(a1) wasmtime-wasi p3 banner, needs: gone", "wasi"),
                         ("(a2) wasmtime-wasi-http p3 banner, needs: gone", "http")):
        main_value, release_value = getattr(main_ref, field), getattr(release_ref, field)
        rows.append(Row(label, banner_cell(main_value), banner_cell(release_value),
                        status_of(main_value, release_value, banner_gone)))
        for ref, markers in ((main_ref, main_value), (release_ref, release_value)):
            if isinstance(markers, Unknown):
                notes.append(f"error: {ref.name} {MODULES[field]} p3 module: {markers.why}")
            elif markers and len(markers) < len(BANNER_MARKERS):
                notes.append(f"{ref.name} {MODULES[field]} p3 module: the banner is partly lifted and still "
                             "says: " + ", ".join(markers))
    for label, field in (("(b1) component-model-async tier, needs: 1 or 2", "component_model_async"),
                         ("(b2) WASIp3 tier, needs: 1 or 2", "wasip3")):
        main_value, release_value = tier_value(main_ref, field), tier_value(release_ref, field)
        rows.append(Row(label, tier_cell(main_value), tier_cell(release_value),
                        status_of(main_value, release_value, tier_listed)))
    for ref in (main_ref, release_ref):
        if isinstance(ref.tiers, Unknown):
            notes.append(f"error: {ref.name} stability tiers: {ref.tiers.why}")
        elif ref.tiers.wasip3 is None and ref.tiers.mentions:
            notes.append(f"{ref.name} stability tiers mention WASI 0.3 or p3 but list no tier 1 or 2 row for "
                         f"it; read the document by hand: {ref.tiers.mentions[0].replace('`', '')}")
    if isinstance(npm, Unknown):
        rows.append(Row("(c) componentize-js targets wasi:http@0.3 (heuristic)", "n/a", "n/a", "unknown"))
        notes.append(f"error: npm: {npm.why}")
    else:
        rows.append(Row("(c) componentize-js targets wasi:http@0.3 (heuristic)", "n/a", "n/a",
                        "met" if npm.strong else "not met"))
        notes.extend(npm_notes(npm))
    notes.extend(f"{row.label[:4]} holds on main but not in a release yet: it reaches one with the next "
                 "Wasmtime major version" for row in rows if row.status == "main only")
    statuses = [row.status for row in rows]
    if "unknown" in statuses:
        verdict = "UNDETERMINED"
    elif all(status == "met" for status in statuses):
        verdict = "OPEN"
    else:
        verdict = "CLOSED"
        if statuses == ["met"] * 4 + ["not met"]:
            notes.append("(a) and (b) hold in a release and only (c) is open. The vehicle ADR 0070 plans for the "
                         "criterion is a Rust guest, which does not need (c); the gate stays three-part until "
                         "the maintainers decide otherwise")
    return Report(when, release_ref.name, rows, notes, verdict)


# --- Output -----------------------------------------------------------------

VERDICT_TEXT = {
    "CLOSED": "Gate: CLOSED (exit status 0). At least one condition is not met.",
    "OPEN": "Gate: OPEN (exit status 1). All three conditions hold: check each by hand as ADR 0070 describes, "
            "then plan the reopening work.",
    "UNDETERMINED": "Gate: UNDETERMINED (exit status 2). At least one source could not be read.",
}


def render_text(report):
    table = [("condition", "main", report.release_name, "status")] + [tuple(row) for row in report.rows]
    widths = [max(len(line[column]) for line in table) for column in range(4)]
    lines = [f"WASI 0.3 gate for M22 criterion 3 (ADR 0070 section 5), checked {report.when}", ""]
    for index, line in enumerate(table):
        lines.append("  ".join(cell.ljust(width) for cell, width in zip(line, widths)).rstrip())
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    lines += [""] + [f"- {note}" for note in report.notes] + ["", VERDICT_TEXT[report.verdict]]
    return "\n".join(lines) + "\n"


def render_markdown(report):
    def code(text):  # keeps GitHub from turning wasi:http@0.3 into a mail link
        return CODE_TOKEN.sub(lambda match: f"`{match.group(0)}`", text)

    lines = [f"### WASI 0.3 gate: {report.verdict}", "",
             f"Informational check of ADR 0070 section 5, {report.when}.", "",
             f"| Condition | main | `{report.release_name}` | Status |", "| --- | --- | --- | --- |"]
    lines += [f"| {code(row.label)} | {row.main} | {row.release} | {row.status} |" for row in report.rows]
    lines += [""] + [f"- {code(note)}" for note in report.notes]
    lines += ["", f"**{VERDICT_TEXT[report.verdict]}**", "",
              "Condition (c) is a heuristic over npm metadata. A result of OPEN is a prompt to check by hand, "
              "not proof.", ""]
    return "\n".join(lines)


def main(argv=None, fetch=None, root=None, now=None):
    parser = argparse.ArgumentParser(
        description="Report whether the WASI 0.3 reopening gate of ADR 0070 section 5 has opened.",
        epilog="Exit status: 0 gate still closed, 1 all three conditions hold, 2 not determined.")
    parser.add_argument("--markdown", metavar="FILE",
                        help="also append the table as Markdown to FILE (in GitHub Actions: $GITHUB_STEP_SUMMARY)")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, metavar="SECONDS",
                        help=f"timeout of each request (default {TIMEOUT})")
    args = parser.parse_args(argv)
    if fetch is None:
        def fetch(url, accept="*/*"):
            return http_get(url, accept, timeout=args.timeout)
    root = root or pathlib.Path(__file__).resolve().parent.parent
    when = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    major, main_ref, release_ref, npm = gather(fetch, root)
    report = evaluate(main_ref, release_ref, npm, major, when)
    sys.stdout.write(render_text(report))
    if args.markdown:
        try:
            with open(args.markdown, "a", encoding="utf-8") as summary:
                summary.write(render_markdown(report))
        except OSError as error:
            print(f"warning: cannot append the Markdown table to {args.markdown}: {error}", file=sys.stderr)
    return {"CLOSED": 0, "OPEN": 1, "UNDETERMINED": 2}[report.verdict]


if __name__ == "__main__":
    sys.exit(main())
