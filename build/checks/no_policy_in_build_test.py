#!/usr/bin/env python3
"""Check that component BUILD files do not carry policy attrs."""

import argparse
import os
import re
import sys
import tempfile


FORBIDDEN = (
    # C/C++ policy attrs (toolchain-layer only)
    "copts", "linkopts", "defines", "local_defines", "conlyopts", "cxxopts",
    # Rust policy attrs (toolchain-layer only;)
    "rustc_flags", "rust_env", "linker_script",
)
TARGET_DIRS = (
    "zircon/kernel",
    "zircon/system",
    "src/zircon/lib/zircon",
    "src/cerise",
)


def scan_file(path):
    with open(path) as f:
        lines = f.readlines()
    failures = []
    for lineno, line in enumerate(lines, start=1):
        for attr in FORBIDDEN:
            if re.search(r"\b{}\b".format(re.escape(attr)), line):
                failures.append("{}:{}: forbidden BUILD policy attr {}".format(path, lineno, attr))
    return failures


def run_check(paths):
    failures = []
    for path in paths:
        failures.extend(scan_file(path))
    return failures


def self_test():
    print("Running self-test fixtures for no_policy_in_build_test...")
    tmpdir = tempfile.mkdtemp()
    try:
        good_path = os.path.join(tmpdir, "BUILD.good.bazel")
        bad_cc_path = os.path.join(tmpdir, "BUILD.bad_cc.bazel")
        bad_rust_path = os.path.join(tmpdir, "BUILD.bad_rust.bazel")
        with open(good_path, "w") as f:
            f.write('cc_library(name = "ok", srcs = ["ok.cc"])\n')
            f.write('rust_library(name = "ok_rs", srcs = ["ok.rs"], edition = "2021")\n')
        with open(bad_cc_path, "w") as f:
            f.write('cc_library(name = "bad", srcs = ["bad.cc"], copts = ["-std=c++20"])\n')
        with open(bad_rust_path, "w") as f:
            f.write('rust_library(name = "bad_rs", srcs = ["bad.rs"], rustc_flags = ["-C opt-level=2"])\n')

        if run_check([good_path]):
            print("SELF-TEST ERROR: [FIXTURE-GOOD] rejected clean BUILD file", file=sys.stderr)
            return 1
        print("  [FIXTURE-GOOD] known-good input accepted OK")

        bad_cc_failures = run_check([bad_cc_path])
        if not bad_cc_failures:
            print("SELF-TEST ERROR: [FIXTURE-BAD-CC] accepted BUILD file with copts", file=sys.stderr)
            return 1
        print("  [FIXTURE-BAD-CC]  known-bad C++ input rejected OK")

        bad_rust_failures = run_check([bad_rust_path])
        if not bad_rust_failures:
            print("SELF-TEST ERROR: [FIXTURE-BAD-RUST] accepted BUILD file with rustc_flags", file=sys.stderr)
            return 1
        print("  [FIXTURE-BAD-RUST] known-bad Rust input rejected OK")
    finally:
        try:
            for name in os.listdir(tmpdir):
                os.unlink(os.path.join(tmpdir, name))
            os.rmdir(tmpdir)
        except OSError:
            pass
    print("Self-test passed.")
    return 0


def discover_build_files(runfiles_root):
    paths = []
    for prefix in ("cerise", "_main"):
        root = os.path.join(runfiles_root, prefix)
        if not os.path.isdir(root):
            continue
        for rel_dir in TARGET_DIRS:
            candidate = os.path.join(root, rel_dir)
            if not os.path.isdir(candidate):
                continue
            for dirpath, _, filenames in os.walk(candidate):
                if "BUILD.bazel" in filenames:
                    paths.append(os.path.join(dirpath, "BUILD.bazel"))
    return sorted(set(paths))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    runfiles = os.environ.get("RUNFILES_DIR") or os.environ.get("TEST_SRCDIR")
    if not runfiles:
        print("ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set", file=sys.stderr)
        return 1

    paths = discover_build_files(runfiles)
    if not paths:
        print("ERROR: could not discover any BUILD.bazel files to scan", file=sys.stderr)
        print("RUNFILES_DIR={}".format(runfiles), file=sys.stderr)
        return 1

    failures = run_check(paths)
    if failures:
        print("NO_POLICY BUILD VIOLATION(S) DETECTED:", file=sys.stderr)
        for msg in failures:
            print(msg, file=sys.stderr)
        return 1

    print("No-policy BUILD scan OK: {} files".format(len(paths)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
