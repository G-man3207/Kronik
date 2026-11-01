#!/usr/bin/env python3
"""Promote reviewed dummy producer JSON lines without mounting writable host output."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys

MAX_FILE = 2 << 20
MAX_TOTAL = 32 << 20
MAX_LINE = 3 << 20
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def write_entry(root_fd, relative, data):
    if not isinstance(relative, str) or len(relative) > 1024:
        raise ValueError("invalid corpus path")
    parts = relative.split("/")
    if any(not part or part in (".", "..") or "\\" in part or "\x00" in part for part in parts):
        raise ValueError("corpus paths must have normal relative components")
    if relative != "manifest.json" and (len(parts) < 2 or parts[0] != "data"):
        raise ValueError("only manifest.json and data/ entries may be promoted")
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def promote(stream, destination, release, producer_sha256):
    # A new destination is mandatory: immutable producer fixtures are never
    # silently regenerated or overwritten with another encoder's bytes.
    destination.mkdir(mode=0o700)
    root = os.open(destination, DIRECTORY_FLAGS)
    files = {}
    manifest = None
    total = 0
    try:
        while True:
            line = stream.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE:
                raise ValueError("proof line exceeds 3 MiB")
            if not line.lstrip().startswith(b"{"):
                continue
            record = json.loads(line, object_pairs_hook=unique_object)
            if not isinstance(record, dict) or record.get("format") != "kronik.corpus-file/v1":
                continue
            if record.get("release") != release:
                continue
            if set(record) != {"format", "release", "path", "sha256", "base64"}:
                raise ValueError("unsupported corpus export fields")
            relative = record["path"]
            if not isinstance(relative, str) or relative in files:
                raise ValueError("invalid or duplicate corpus file")
            encoded = record["base64"]
            if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_FILE + 2) // 3):
                raise ValueError("encoded corpus file exceeds 2 MiB payload limit")
            data = base64.b64decode(encoded, validate=True)
            actual_sha = hashlib.sha256(data).hexdigest()
            if len(data) > MAX_FILE or actual_sha != record["sha256"]:
                raise ValueError("corpus payload size/digest mismatch")
            total += len(data)
            if total > MAX_TOTAL or len(files) >= 513:
                raise ValueError("corpus exceeds 32 MiB / 513-file bound")
            if relative == "manifest.json":
                manifest = json.loads(data, object_pairs_hook=unique_object)
                if (manifest.get("format") != "kronik.compatibility-corpus/v1" or
                    manifest.get("release") != release or
                    manifest.get("producer_binary_sha256") != producer_sha256 or
                    manifest.get("dummy_master_key") != "44" * 32):
                    raise ValueError("not the expected pinned dummy producer manifest")
            write_entry(root, relative, data)
            files[relative] = {"bytes": len(data), "sha256": actual_sha}
        if manifest is None:
            raise ValueError("no producer manifest was exported")
        entries = manifest.get("files")
        if not isinstance(entries, list) or not entries:
            raise ValueError("producer manifest has no file inventory")
        expected = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
                raise ValueError("invalid producer inventory entry")
            relative = "data/" + entry["path"]
            if relative in expected:
                raise ValueError("duplicate producer inventory path")
            expected[relative] = {"bytes": entry["bytes"], "sha256": entry["sha256"]}
        actual = {path: value for path, value in files.items() if path != "manifest.json"}
        if actual != expected:
            raise ValueError("exported data does not exactly match the producer inventory")
        os.fsync(root)
        return {"release": release, "files": len(files), "bytes": total,
                "manifest_sha256": files["manifest.json"]["sha256"], "promoted": True}
    finally:
        os.close(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True, help="new owned directory only")
    parser.add_argument("--release", choices=("v0.1.0", "v0.3.0"), required=True)
    parser.add_argument("--producer-sha256", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.producer_sha256):
        parser.error("producer-sha256 must be the actual pinned release binary digest")
    os.umask(0o077)
    result = promote(sys.stdin.buffer, args.destination, args.release, args.producer_sha256)
    print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"corpus promotion: {error}; preserve any partial directory for inspection", file=sys.stderr)
        sys.exit(1)
