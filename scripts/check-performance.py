#!/usr/bin/env python3
"""Compare local kronik.benchmark/v1 reports; no benchmark or baseline fetching.

Usage: python3 scripts/check-performance.py baseline.json candidate.json
Exit 0: comparable and within 10%; 1: regression, measurement errors or
incomparable reports; 2: invalid input/usage. Exact 10% boundaries pass.
Units are closed: turns/s, requests/s, ms, bytes, ratio. Only the guest digest
must match.
"""

import argparse
from decimal import Decimal
from fractions import Fraction
import json
import sys

UNITS = {"turns/s", "requests/s", "ms", "bytes", "ratio"}


def reject_constant(token):
    raise ValueError(f"nonfinite JSON constant: {token}")


def rig_identity(value):
    """A rig as text: key order does not matter, and true differs from 1."""
    return json.dumps(value, sort_keys=True, default=str)


def load_report(path):
    with open(path, encoding="utf-8") as stream:
        report = json.load(stream, parse_float=Decimal, parse_constant=reject_constant)
    if type(report) is not dict or report.get("format") != "kronik.benchmark/v1":
        raise ValueError(f"{path}: unsupported report format")
    measurements = report["measurements"]
    if type(measurements) is not list or not measurements:
        raise ValueError(f"{path}: measurements must be a nonempty list")
    names = [item["name"] for item in measurements]
    if len(set(names)) != len(names):
        raise ValueError(f"{path}: duplicate measurement name")
    for item in measurements:
        if item["unit"] not in UNITS or item["direction"] not in ("higher", "lower"):
            raise ValueError(f"{path}: {item['name']}: unknown unit or direction")
        if type(item["value"]) not in (int, Decimal) or item["value"] <= 0:
            raise ValueError(f"{path}: {item['name']}: value must be a positive number")
        if type(item["errors"]) is not int or item["errors"] < 0:
            raise ValueError(f"{path}: {item['name']}: errors must be a nonnegative integer")
    if type(report["source"]["guest_sha256"]) is not str:
        raise ValueError(f"{path}: source.guest_sha256 must be a string")
    return report


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
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print(f"invalid report: {error}", file=sys.stderr)
        return 2
    return compare(baseline, candidate)


if __name__ == "__main__":
    sys.exit(main())
