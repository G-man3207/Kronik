#!/usr/bin/env python3
"""Move every version site of the repository from one version to another.

    scripts/set-version.py --from 0.5.0-dev --to 0.5.0     # the release commit
    scripts/set-version.py --from 0.5.0 --to 0.6.0-dev     # main after the tag
    scripts/set-version.py --check                         # every site agrees

Run it from the repository root. It edits exactly these sites, checks each,
and refuses a site at any other version; a site already at the new version is
left as it is, so a second run changes nothing:

- Cargo.toml [workspace.package] and Cargo.lock: every workspace member (the
  packages of crates/*, which have no `source` in the lockfile).
- examples/Cargo.toml [workspace.package], sdk/rust/Cargo.toml [package] and
  examples/Cargo.lock: the examples workspace and kronik-sdk
  (examples/kronik-sdk is a link to sdk/rust).
- The standalone examples' [package] and their Cargo.lock.
- sdk/ts/package.json, sdk/ts/package-lock.json (its top level and
  packages[""]) and examples/package-lock.json (packages["../sdk/ts"]).
- The /v1/health example of docs/design/m1-core.md.
- info.version of docs/reference/openapi.json, which kronik-api's `openapi`
  example generates from the workspace version: regenerate it afterwards
  to check (it must not change).

It then lists the tracked text that still names the old version, for review:
historical prose (the changelog, ADRs, the evidence in the guides) and the
binary fixtures keep the version they were written with.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-dev)?")
# Examples with a manifest and a lockfile of their own.
STANDALONE = ("fake-payments", "foreign-echo", "foreign-pg", "foreign-probe")


class Refused(Exception):
    """A site is not at the version it should be, or not where it should be."""


def manifest_version(path, table, old, new, write):
    """Sets `version` in `[table]` of a Cargo manifest."""
    text = path.read_text()
    header = re.search(rf"^\[{re.escape(table)}\][ \t]*$", text, re.M)
    if header is None:
        raise Refused(f"{path}: no [{table}]")
    end = re.search(r"^\[", text[header.end():], re.M)
    stop = header.end() + (end.start() if end else len(text) - header.end())
    found = list(re.finditer(r'^version = "([^"]+)"[ \t]*$', text[header.end():stop], re.M))
    if len(found) != 1:
        raise Refused(f"{path}: [{table}] has {len(found)} version lines")
    current = found[0].group(1)
    if current == new:
        return
    if current != old:
        raise Refused(f"{path}: [{table}] is at {current}, not {old}")
    start = header.end() + found[0].start(1)
    if write:
        path.write_text(text[:start] + new + text[start + len(current):])


def package_name(manifest):
    return re.search(r'^name = "([^"]+)"', manifest.read_text(), re.M).group(1)


def lock_versions(path, names, old, new, write):
    """Sets the version of the packages `names`, which have no `source`, in a
    Cargo.lock. A registry package at the same version is not one of them."""
    parts = path.read_text().split("\n[[package]]\n")
    done = set()
    for i, block in enumerate(parts[1:], start=1):
        name = re.search(r'^name = "([^"]+)"$', block, re.M).group(1)
        if name not in names or re.search(r"^source = ", block, re.M):
            continue
        version = re.search(r'^version = "([^"]+)"$', block, re.M)
        if version.group(1) not in (old, new):
            raise Refused(f"{path}: {name} is at {version.group(1)}, not {old}")
        parts[i] = block[:version.start(1)] + new + block[version.end(1):]
        done.add(name)
    if done != set(names):
        raise Refused(f"{path}: no {', '.join(sorted(set(names) - done))}")
    if write:
        path.write_text("\n[[package]]\n".join(parts))
    return len(done)


def json_file(path):
    raw = path.read_text()
    data = json.loads(raw)
    # npm and serde_json write JSON with two spaces and a final newline;
    # a file in another layout would be rewritten whole, so it is refused.
    if json.dumps(data, indent=2, ensure_ascii=False) + "\n" != raw:
        raise Refused(f"{path}: not in the two-space layout this script writes")
    return data


def json_versions(path, keys, old, new, write):
    data = json_file(path)
    for key in keys:
        node = data
        for part in key[:-1]:
            node = node[part]
        if node.get(key[-1]) not in (old, new):
            raise Refused(f"{path}: {'/'.join(key) or '(top)'} is at {node.get(key[-1])}, not {old}")
        node[key[-1]] = new
    if write:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def one_text(path, before, after, write):
    text = path.read_text()
    if before == after or (before not in text and text.count(after) == 1):
        if text.count(after) != 1:
            raise Refused(f"{path}: {after!r} occurs {text.count(after)} times")
        return
    if text.count(before) != 1:
        raise Refused(f"{path}: {before!r} occurs {text.count(before)} times")
    if write:
        path.write_text(text.replace(before, after))


def bump(root, old, new, write=True):
    """Moves every site under `root` from `old` to `new`; returns what it set.
    With `write` false it only checks that every site is at `old` or `new`."""
    done = []
    members = [package_name(m) for m in sorted(root.glob("crates/*/Cargo.toml"))]
    manifest_version(root / "Cargo.toml", "workspace.package", old, new, write)
    count = lock_versions(root / "Cargo.lock", members, old, new, write)
    done.append(f"Cargo.toml, Cargo.lock ({count} workspace members)")

    examples = root / "examples"
    manifest_version(examples / "Cargo.toml", "workspace.package", old, new, write)
    manifest_version(root / "sdk/rust/Cargo.toml", "package", old, new, write)
    names = [package_name(root / "sdk/rust/Cargo.toml")]
    workspace = re.search(r"^members = \[([^\]]*)\]", (examples / "Cargo.toml").read_text(), re.M)
    for member in re.findall(r'"([^"]+)"', workspace.group(1)):
        manifest = examples / member / "Cargo.toml"
        if package_name(manifest) in names:
            continue
        if not re.search(r"^version\.workspace = true$", manifest.read_text(), re.M):
            raise Refused(f"{manifest}: does not take the workspace's version")
        names.append(package_name(manifest))
    count = lock_versions(examples / "Cargo.lock", names, old, new, write)
    done.append(f"examples/Cargo.toml, sdk/rust/Cargo.toml, examples/Cargo.lock ({count} packages)")

    for example in STANDALONE:
        directory = examples / example
        manifest_version(directory / "Cargo.toml", "package", old, new, write)
        lock_versions(directory / "Cargo.lock", [package_name(directory / "Cargo.toml")], old, new, write)
        done.append(f"examples/{example}/Cargo.toml, Cargo.lock")

    json_versions(root / "sdk/ts/package.json", [("version",)], old, new, write)
    json_versions(root / "sdk/ts/package-lock.json", [("version",), ("packages", "", "version")], old, new, write)
    json_versions(examples / "package-lock.json", [("packages", "../sdk/ts", "version")], old, new, write)
    done.append("sdk/ts/package.json, sdk/ts/package-lock.json, examples/package-lock.json")

    one_text(root / "docs/design/m1-core.md", f'"version":"{old}"', f'"version":"{new}"', write)
    json_versions(root / "docs/reference/openapi.json", [("info", "version")], old, new, write)
    done.append("docs/design/m1-core.md, docs/reference/openapi.json")
    return done


def workspace_version(root):
    text = (root / "Cargo.toml").read_text()
    header = re.search(r"^\[workspace\.package\][ \t]*$", text, re.M)
    return re.search(r'^version = "([^"]+)"', text[header.end():], re.M).group(1)


def remaining(root, old):
    """Tracked text that still names `old`: prose to review, not to edit."""
    out = subprocess.run(["git", "grep", "-n", "-I", "-F", "-e", old], cwd=root,
                         capture_output=True, text=True, check=False)
    return out.stdout.splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from", dest="old")
    parser.add_argument("--to", dest="new")
    parser.add_argument("--check", action="store_true",
                        help="only check that every site is at the workspace's version")
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.check:
            if args.old or args.new:
                parser.error("--check takes no --from or --to")
            version = workspace_version(root)
            bump(root, version, version, write=False)
            print(f"every version site is at {version}")
            return
        if not args.old or not args.new:
            parser.error("give --from and --to, or --check")
        for value in (args.old, args.new):
            if not VERSION.fullmatch(value):
                parser.error(f"{value!r} is not a version such as 0.5.0 or 0.6.0-dev")
        # Check every site first, so that a refusal leaves nothing half done.
        bump(root, args.old, args.new, write=False)
        for line in bump(root, args.old, args.new):
            print("set:", line)
    except Refused as error:
        print(f"refused: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"tracked text that still names {args.old} (historical prose keeps it; review the rest):")
    for line in remaining(root, args.old):
        print("  " + line[:160])


if __name__ == "__main__":
    main()
