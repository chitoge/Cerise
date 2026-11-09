#!/usr/bin/env python3
"""Check that a toolchain flag manifest matches the reviewed golden."""

import argparse
import difflib
import json
import os
import sys
import tempfile


def load_json(path):
    with open(path) as f:
        return json.load(f)


def render(obj):
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def run_check(actual_path, golden_path):
    actual = load_json(actual_path)
    golden = load_json(golden_path)
    if actual != golden:
        actual_rendered = render(actual).splitlines(keepends=True)
        golden_rendered = render(golden).splitlines(keepends=True)
        return False, "".join(
            difflib.unified_diff(
                golden_rendered,
                actual_rendered,
                fromfile=golden_path,
                tofile=actual_path,
            )
        )
    return True, ""


def self_test():
    print("Running self-test fixtures for flag_manifest_golden_test...")
    tmpdir = tempfile.mkdtemp()
    try:
        golden_path = os.path.join(tmpdir, "golden.json")
        actual_path = os.path.join(tmpdir, "actual.json")

        good_obj = {
            "asmopts": [],
            "copts": ["-ffreestanding", "-m64"],
            "cpu": "x64",
            "cxxopts": [],
            "defines": ["LK"],
            "environment": "kernel",
            "feature_docs": {"env.kernel": "Kernel environment definitions."},
            "features": ["env.kernel"],
            "linkopts": ["-nostdlib"],
            "name": "zircon.x64.kernel",
        }
        with open(golden_path, "w") as f:
            json.dump(good_obj, f)
        with open(actual_path, "w") as f:
            json.dump(good_obj, f)

        ok, diff = run_check(actual_path, golden_path)
        if not ok:
            print("SELF-TEST ERROR: [FIXTURE-GOOD] check rejected matching JSON:", file=sys.stderr)
            print(diff, file=sys.stderr)
            return 1
        print("  [FIXTURE-GOOD] known-good input accepted OK")

        bad_obj = dict(good_obj)
        bad_obj["defines"] = ["LK", "MUTATED"]
        with open(actual_path, "w") as f:
            json.dump(bad_obj, f)

        ok, diff = run_check(actual_path, golden_path)
        if ok:
            print(
                "SELF-TEST ERROR: [FIXTURE-BAD] check accepted mutated JSON "
                "(it should have rejected it).",
                file=sys.stderr,
            )
            return 1
        print("  [FIXTURE-BAD]  known-bad input rejected OK")
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
    print("Self-test passed.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actual", help="Path to the generated flag manifest.")
    parser.add_argument("--golden", help="Path to the reviewed flag-manifest golden.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if not args.actual or not args.golden:
        print("ERROR: --actual and --golden are required unless --self-test is given.", file=sys.stderr)
        return 1

    ok, diff = run_check(args.actual, args.golden)
    if not ok:
        print("FLAG MANIFEST VIOLATION(S) DETECTED:", file=sys.stderr)
        if diff:
            print(diff, file=sys.stderr)
        return 1

    print("Flag manifest OK: {} matches {}".format(args.actual, args.golden))
    return 0


if __name__ == "__main__":
    sys.exit(main())
