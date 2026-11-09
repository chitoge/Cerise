#!/usr/bin/env python3
"""Validate that kernel toolchain ambient -isystem paths match the reviewed golden.

Reads toolchain/ambient-includes.json (the golden) and checks that the
kernel_c_stdlib_flags cc_args target in toolchain/BUILD.bazel contains exactly
and only those paths as -isystem entries.  Any path present in the toolchain
but absent from the golden is a silent layering-check bypass; any path in the
golden but absent from the toolchain is a broken assumption.
"""

import argparse
import json
import re
import sys
import tempfile
import os


def extract_isystem_paths(build_bazel_text):
    """Extract the -isystem path list from kernel_c_stdlib_flags args."""
    # Find the kernel_c_stdlib_flags block
    block_match = re.search(
        r'name\s*=\s*"kernel_c_stdlib_flags".*?(?=\ncc_args|\Z)',
        build_bazel_text,
        re.DOTALL,
    )
    if not block_match:
        return None, "could not locate kernel_c_stdlib_flags block"

    block = block_match.group(0)
    args_match = re.search(r'args\s*=\s*\[(.*?)\]', block, re.DOTALL)
    if not args_match:
        return None, "could not locate args list in kernel_c_stdlib_flags"

    args_text = args_match.group(1)
    tokens = re.findall(r'"([^"]*)"', args_text)

    paths = []
    i = 0
    while i < len(tokens):
        if tokens[i] == "-isystem" and i + 1 < len(tokens):
            paths.append(tokens[i + 1])
            i += 2
        else:
            i += 1
    return paths, None


def load_golden(golden_path):
    with open(golden_path) as f:
        data = json.load(f)
    return [entry["path"] for entry in data["stdlib_resolution_closure"]]


def run_check(build_bazel_path, golden_path):
    with open(build_bazel_path) as f:
        build_text = f.read()

    actual_paths, err = extract_isystem_paths(build_text)
    if err:
        return False, [f"Parse error: {err}"]

    golden_paths = load_golden(golden_path)
    golden_set = set(golden_paths)
    actual_set = set(actual_paths)

    violations = []
    for p in sorted(actual_set - golden_set):
        violations.append(f"EXTRA (not in golden, bypasses layering): {p}")
    for p in sorted(golden_set - actual_set):
        violations.append(f"MISSING (in golden but absent from toolchain): {p}")
    return len(violations) == 0, violations


def self_test():
    print("Running self-test fixtures for toolchain_ambient_include_test...")
    tmpdir = tempfile.mkdtemp()
    try:
        golden = {"stdlib_resolution_closure": [{"path": "zircon/kernel/lib/ktl/include", "why": "ktl"}]}
        golden_path = os.path.join(tmpdir, "golden.json")
        with open(golden_path, "w") as f:
            json.dump(golden, f)

        good_build = '''
cc_args(
    name = "kernel_c_stdlib_flags",
    args = [
        "-nostdlibinc",
        "-isystem",
        "zircon/kernel/lib/ktl/include",
    ],
)
'''
        bad_build = '''
cc_args(
    name = "kernel_c_stdlib_flags",
    args = [
        "-nostdlibinc",
        "-isystem",
        "zircon/kernel/lib/ktl/include",
        "-isystem",
        "zircon/kernel/vm/include",
    ],
)
'''
        good_path = os.path.join(tmpdir, "BUILD.good.bazel")
        bad_path = os.path.join(tmpdir, "BUILD.bad.bazel")
        with open(good_path, "w") as f:
            f.write(good_build)
        with open(bad_path, "w") as f:
            f.write(bad_build)

        ok, violations = run_check(good_path, golden_path)
        if not ok:
            print(f"SELF-TEST ERROR: [FIXTURE-GOOD] rejected clean toolchain: {violations}", file=sys.stderr)
            return 1
        print("  [FIXTURE-GOOD] known-good toolchain accepted OK")

        ok, violations = run_check(bad_path, golden_path)
        if ok:
            print("SELF-TEST ERROR: [FIXTURE-BAD] accepted toolchain with extra -isystem path", file=sys.stderr)
            return 1
        if not any("zircon/kernel/vm/include" in v for v in violations):
            print(f"SELF-TEST ERROR: [FIXTURE-BAD] wrong violation detected: {violations}", file=sys.stderr)
            return 1
        print("  [FIXTURE-BAD]  known-bad toolchain rejected OK")
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    print("Self-test passed.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-bazel", help="Path to toolchain/BUILD.bazel")
    parser.add_argument("--golden", help="Path to toolchain/ambient-includes.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if not args.build_bazel or not args.golden:
        print("ERROR: --build-bazel and --golden are required", file=sys.stderr)
        return 1

    ok, violations = run_check(args.build_bazel, args.golden)
    if not ok:
        print("TOOLCHAIN AMBIENT INCLUDE VIOLATION(S):", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        print(
            "\nTo fix: either update toolchain/ambient-includes.json (requires user approval at a named gate)",
            file=sys.stderr,
        )
        print("or remove the extra -isystem path from kernel_c_stdlib_flags in toolchain/BUILD.bazel.", file=sys.stderr)
        return 1

    print(f"Toolchain ambient include check OK: {len(load_golden(args.golden))} stdlib paths verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
