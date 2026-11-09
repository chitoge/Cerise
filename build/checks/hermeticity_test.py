#!/usr/bin/env python3
""" shape check: image-layer BUILD files must be hermetic.

Scans for attributes that disable sandboxing or grant network access:
  local = True
  "no-sandbox" in tags
  "requires-network" in tags
"""

import argparse
import os
import re
import sys
import tempfile


_FORBIDDEN_PATTERNS = [
    (r"\blocal\s*=\s*True\b", "local = True disables sandboxing"),
    (r'"no-sandbox"', '"no-sandbox" tag disables sandboxing'),
    (r'"requires-network"', '"requires-network" tag grants network access'),
]


def scan_file(path):
    with open(path) as f:
        lines = f.readlines()
    failures = []
    for lineno, line in enumerate(lines, start=1):
        for pattern, reason in _FORBIDDEN_PATTERNS:
            if re.search(pattern, line):
                failures.append("{}:{}: hermeticity violation — {}".format(path, lineno, reason))
    return failures


def self_test():
    print("Running self-test fixtures for hermeticity_test...")
    tmpdir = tempfile.mkdtemp()
    try:
        good_path = os.path.join(tmpdir, "BUILD.good.bazel")
        bad_path = os.path.join(tmpdir, "BUILD.bad.bazel")
        with open(good_path, "w") as f:
            f.write('load(":zbi.bzl", "zbi_image")\nzbi_image(name = "boot_zbi", input_zbis = [])\n')
        with open(bad_path, "w") as f:
            f.write('genrule(name = "bad", outs = ["x"], local = True, cmd = "touch $@")\n')

        if scan_file(good_path):
            print("SELF-TEST ERROR: [FIXTURE-GOOD] rejected clean BUILD file", file=sys.stderr)
            return 1
        print("  [FIXTURE-GOOD] known-good input accepted OK")

        bad_failures = scan_file(bad_path)
        if not bad_failures:
            print("SELF-TEST ERROR: [FIXTURE-BAD] accepted BUILD file with local=True", file=sys.stderr)
            return 1
        print("  [FIXTURE-BAD]  known-bad input rejected OK")
    finally:
        try:
            for name in os.listdir(tmpdir):
                os.unlink(os.path.join(tmpdir, name))
            os.rmdir(tmpdir)
        except OSError:
            pass
    print("Self-test passed.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("files", nargs="*", help="BUILD file paths to scan")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if not args.files:
        print("ERROR: no BUILD files specified to scan", file=sys.stderr)
        return 1

    failures = []
    for path in args.files:
        failures.extend(scan_file(path))

    if failures:
        print("HERMETICITY VIOLATION(S) DETECTED:", file=sys.stderr)
        for msg in failures:
            print(msg, file=sys.stderr)
        return 1

    print("Hermeticity scan OK: {} files".format(len(args.files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
