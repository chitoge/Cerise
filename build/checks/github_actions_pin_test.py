#!/usr/bin/env python3
"""Reject mutable third-party action references in GitHub workflows."""

import argparse
import os
import re
import sys
import tempfile


_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
_ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.\-/]+@[0-9a-f]{40}$")
_CONTAINER_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def scan_file(path):
    failures = []
    with open(path, encoding="utf-8") as workflow:
        for lineno, line in enumerate(workflow, start=1):
            match = _USES_RE.match(line)
            if not match:
                continue
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            if _ACTION_RE.fullmatch(reference) or _CONTAINER_RE.fullmatch(reference):
                continue
            failures.append(
                "{}:{}: action reference must use a full commit SHA: {}".format(
                    path, lineno, reference
                )
            )
    return failures


def self_test():
    fixtures = {
        "good.yml": "steps:\n  - uses: actions/checkout@{}\n  - uses: ./local-action\n".format(
            "1" * 40
        ),
        "bad-tag.yml": "steps:\n  - uses: actions/checkout@v4\n",
        "bad-branch.yml": "steps:\n  - uses: owner/action@main\n",
    }
    with tempfile.TemporaryDirectory() as directory:
        paths = {}
        for name, contents in fixtures.items():
            path = os.path.join(directory, name)
            with open(path, "w", encoding="utf-8") as fixture:
                fixture.write(contents)
            paths[name] = path

        if scan_file(paths["good.yml"]):
            print("SELF-TEST ERROR: rejected immutable/local references", file=sys.stderr)
            return 1
        for name in ("bad-tag.yml", "bad-branch.yml"):
            if not scan_file(paths[name]):
                print("SELF-TEST ERROR: accepted {}".format(name), file=sys.stderr)
                return 1
    print("GitHub Actions pin self-test passed.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--directory-of",
        metavar="WORKFLOW",
        help="scan every YAML workflow alongside this runfiles path",
    )
    parser.add_argument("workflows", nargs="*")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    workflows = list(args.workflows)
    if args.directory_of:
        directory = os.path.dirname(args.directory_of)
        workflows.extend(
            os.path.join(directory, name)
            for name in sorted(os.listdir(directory))
            if name.endswith((".yml", ".yaml"))
        )
    if not workflows:
        print("ERROR: no workflows specified", file=sys.stderr)
        return 1

    failures = []
    for path in workflows:
        failures.extend(scan_file(path))
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("GitHub Actions pin scan OK: {} workflows".format(len(workflows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
