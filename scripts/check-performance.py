#!/usr/bin/env python3
"""Compare local kronik.benchmark/v1 reports; no benchmark or baseline fetching.

Usage: python3 scripts/check-performance.py baseline.json candidate.json
Exit 0: comparable and within 10%; 1: regression, measurement errors or
incomparable reports; 2: invalid input/usage. Exact 10% boundaries pass.
Inputs are limited to 1 MiB, 128 measurements, 128-character numeric tokens,
and rig nesting of 16 levels (128 members per container). Units are closed:
turns/s, requests/s, ms, bytes, ratio. Source revisions are Git SHA-1 hex;
binary/guest digests are SHA-256 hex. Only the guest digest must match.
"""

import argparse
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import json
import math
from pathlib import Path
import re
import sys

MAX_BYTES = 1024 * 1024
MAX_MEASUREMENTS = 128
UNITS = {"turns/s", "requests/s", "ms", "bytes", "ratio"}


def fields(value, expected, label):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError(f"{label} must contain exactly {', '.join(expected)}")


def text(value, label, maximum=128, empty=False):
    if (type(value) is not str or len(value) > maximum
            or (not empty and not value.strip()) or not value.isprintable() and value != ""):
        raise ValueError(f"{label} must be printable text of at most {maximum} characters")


def number(token):
    if len(token) > 128:
        raise ValueError("numeric token exceeds 128 characters")
    value = Decimal(token)
    if not value.is_finite() or not math.isfinite(float(value)):
        raise ValueError("numbers must be finite")
    if value != 0 and float(value) == 0:
        raise ValueError("number is too small to represent")
    return value


def integer(token):
    number(token)
    return int(token)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def reject_constant(token):
    raise ValueError(f"nonfinite JSON constant: {token}")


def rig_identity(value, depth=0):
    """Validate bounded rig settings and preserve booleans versus numbers."""
    if depth > 16:
        raise ValueError("rig nesting exceeds 16 levels")
    if type(value) is dict:
        if len(value) > 128:
            raise ValueError("rig object exceeds 128 members")
        for key in value:
            text(key, "rig key")
        return ("object", tuple((key, rig_identity(item, depth + 1))
                                for key, item in sorted(value.items())))
    if type(value) is list:
        if len(value) > 128:
            raise ValueError("rig array exceeds 128 members")
        return ("array", tuple(rig_identity(item, depth + 1) for item in value))
    if type(value) is str:
        text(value, "rig string", maximum=1024, empty=True)
        return ("string", value)
    if type(value) is bool or value is None:
        return (type(value).__name__, value)
    return ("number", value)


def load_report(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{path}: report exceeds {MAX_BYTES} bytes")
    try:
        report = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                            parse_float=number, parse_int=integer,
                            parse_constant=reject_constant)
        fields(report, ("format", "profile", "rig", "measurements", "source"), "report")
        if report["format"] != "kronik.benchmark/v1":
            raise ValueError("unsupported report format")
        text(report["profile"], "profile")
        if type(report["rig"]) is not dict or not report["rig"]:
            raise ValueError("rig must be a nonempty object")
        rig_identity(report["rig"])
        source = report["source"]
        fields(source, ("revision", "binary_sha256", "guest_sha256"), "source")
        for key, length in (("revision", 40), ("binary_sha256", 64), ("guest_sha256", 64)):
            if (type(source[key]) is not str
                    or re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", source[key]) is None):
                raise ValueError(f"source.{key} must be {length} hexadecimal characters")
        measurements = report["measurements"]
        if type(measurements) is not list or not 1 <= len(measurements) <= MAX_MEASUREMENTS:
            raise ValueError(f"measurements must contain 1 to {MAX_MEASUREMENTS} results")
        names = set()
        for item in measurements:
            fields(item, ("name", "unit", "direction", "value", "errors"), "measurement")
            text(item["name"], "measurement.name")
            if item["name"] in names:
                raise ValueError(f"duplicate measurement name: {item['name']!r}")
            names.add(item["name"])
            if type(item["unit"]) is not str or item["unit"] not in UNITS:
                raise ValueError("measurement.unit must be turns/s, requests/s, ms, bytes or ratio")
            if type(item["direction"]) is not str or item["direction"] not in ("higher", "lower"):
                raise ValueError("measurement.direction must be higher or lower")
            if type(item["value"]) not in (int, Decimal) or item["value"] <= 0:
                raise ValueError("measurement.value must be a positive finite number")
            if type(item["errors"]) is not int or item["errors"] < 0:
                raise ValueError("measurement.errors must be a nonnegative integer")
        return report
    except (ValueError, InvalidOperation, RecursionError) as error:
        raise ValueError(f"{path}: {error}") from error


def compare(baseline, candidate):
    mismatches = []
    for key in ("profile", "rig"):
        old = rig_identity(baseline[key]) if key == "rig" else baseline[key]
        new = rig_identity(candidate[key]) if key == "rig" else candidate[key]
        if old != new:
            mismatches.append(f"{key} differs")
    if baseline["source"]["guest_sha256"].lower() != candidate["source"]["guest_sha256"].lower():
        mismatches.append("guest_sha256 differs (workload changed)")
    old_results = {item["name"]: item for item in baseline["measurements"]}
    new_results = {item["name"]: item for item in candidate["measurements"]}
    for name in sorted(old_results.keys() - new_results.keys()):
        mismatches.append(f"missing candidate scenario: {name}")
    for name in sorted(new_results.keys() - old_results.keys()):
        mismatches.append(f"unexpected candidate scenario: {name}")
    for name in sorted(old_results.keys() & new_results.keys()):
        for key in ("unit", "direction"):
            if old_results[name][key] != new_results[name][key]:
                mismatches.append(f"{name}: {key} differs")
    if mismatches:
        for message in mismatches:
            print(f"incomparable: {message}", file=sys.stderr)
        return 1

    failed = False
    for name in sorted(old_results):
        old, new = old_results[name], new_results[name]
        before, after = Fraction(old["value"]), Fraction(new["value"])
        regression = (after * 10 < before * 9 if old["direction"] == "higher"
                      else after * 10 > before * 11)
        errors = old["errors"] > 0 or new["errors"] > 0
        change = (Decimal(new["value"]) / Decimal(old["value"]) - 1) * 100
        status = "ERROR" if errors else "REGRESSION" if regression else "PASS"
        print(f"{name}: old={old['value']} new={new['value']} {old['unit']} "
              f"change={change:+.6g}% direction={old['direction']} {status} "
              f"errors={old['errors']}/{new['errors']}")
        failed |= regression or errors
    return int(failed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="local baseline JSON report")
    parser.add_argument("candidate", help="local candidate JSON report")
    args = parser.parse_args(argv)
    try:
        baseline = load_report(args.baseline)
        candidate = load_report(args.candidate)
    except (OSError, ValueError) as error:
        print(f"invalid report: {error}", file=sys.stderr)
        return 2
    return compare(baseline, candidate)


if __name__ == "__main__":
    sys.exit(main())
