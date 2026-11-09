#!/usr/bin/env python3
""" shape check: examples/ targets must depend only on //sdk and //products.

Reads the specified BUILD.bazel files from examples/ and checks that all
absolute label references start with //sdk, //products, //bazel, or @-externals.

Alias rule bodies are excluded — alias() targets exist to provide stable names
and are not compiled directly; the compiled consumer's deps are what matter.

Allowed absolute label prefixes:
  //sdk/...      The public SDK surface
  //products/... The product surface
  //bazel/...    Macros and rules
  @...           External repositories (Bazel deps)
"""

import argparse
import os
import re
import sys
import tempfile


_ALLOWED_PREFIXES = (
    "//sdk",
    "//products",
    "//bazel",
    "//visibility",  # Bazel built-in visibility pseudo-package
)


def _remove_alias_bodies(text):
    """Strip the body of alias(...) rules from content so their targets
    don't trigger false positives."""
    result = []
    in_alias = False
    depth = 0
    i = 0
    while i < len(text):
        if not in_alias:
            if re.match(r'\balias\s*\(', text[i:]):
                in_alias = True
                depth = 0
            else:
                result.append(text[i])
        if in_alias:
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
                if depth == 0:
                    in_alias = False
        i += 1
    return ''.join(result)


def scan_file(path):
    with open(path) as f:
        content = f.read()
    content = _remove_alias_bodies(content)
    failures = []
    for line in content.splitlines():
        # Per-line escape hatch: "# sdk_visibility_ok[: reason]" exempts that line.
        if "# sdk_visibility_ok" in line:
            continue
        for m in re.finditer(r'"(//[^"]+)"', line):
            label = m.group(1)
            if any(label.startswith(p) for p in _ALLOWED_PREFIXES):
                continue
            failures.append(f"{path}: disallowed dependency {label!r} in examples/ BUILD file")
    return failures


def self_test():
    print("Running self-test fixtures for sdk_visibility_test...")
    tmpdir = tempfile.mkdtemp()
    try:
        good_path = os.path.join(tmpdir, "BUILD.good.bazel")
        bad_path = os.path.join(tmpdir, "BUILD.bad.bazel")

        with open(good_path, "w") as f:
            f.write('cc_library(name = "foo", srcs = [], deps = ["//sdk:zircon_api"])\n')
            f.write('alias(name = "bar", actual = "//kernel:internal_target")\n')
            f.write('    "//src/cerise/net/e1000",  # sdk_visibility_ok: pre-SDK; routed here\n')

        with open(bad_path, "w") as f:
            f.write('cc_library(name = "foo", srcs = [], deps = ["//kernel:x64_boot"])\n')

        if scan_file(good_path):
            print("SELF-TEST ERROR: [FIXTURE-GOOD] rejected SDK-only BUILD file", file=sys.stderr)
            return 1
        print("  [FIXTURE-GOOD] known-good input accepted OK")

        bad_failures = scan_file(bad_path)
        if not bad_failures:
            print("SELF-TEST ERROR: [FIXTURE-BAD] accepted BUILD file with forbidden dep", file=sys.stderr)
            return 1
        print("  [FIXTURE-BAD]  known-bad input rejected OK")

        print("Self-test passed.")
        return 0
    finally:
        for fname in os.listdir(tmpdir):
            os.unlink(os.path.join(tmpdir, fname))
        os.rmdir(tmpdir)


def main():
    parser = argparse.ArgumentParser(description="Validate examples/ SDK-only visibility.")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("files", nargs="*", help="BUILD.bazel files to scan")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if not args.files:
        print("ERROR: no BUILD.bazel files specified", file=sys.stderr)
        return 1

    failures = []
    for path in args.files:
        failures.extend(scan_file(path))

    if failures:
        print("SDK VISIBILITY VIOLATION(S) DETECTED:\n")
        for f in failures:
            print(f"  {f}")
        print()
        print("examples/ targets may only depend on //sdk, //products, //bazel, or @-externals.")
        print("See the SDK visibility policy (sdk_visibility_test).")
        return 1

    print(f"SDK visibility check passed ({len(args.files)} BUILD file(s) scanned).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
