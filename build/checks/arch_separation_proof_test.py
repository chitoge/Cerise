#!/usr/bin/env python3
"""Validate the arch-neutral partition and the proof tier files.

Checks:
  1. arch-neutral-set.txt: all labels are valid //... format, no duplicates.
  2. arch-proven-set.txt: all entries are a subset of arch-neutral-set.txt.
  3. Known arch-specific targets are absent from arch-neutral-set.txt.
  4. Known arch-aware targets are absent from arch-neutral-set.txt.
"""

import argparse
import os
import sys
import tempfile

# Targets that were reclassified out of the arch-neutral tier.
# These must never re-appear in arch-neutral-set.txt.
ARCH_SPECIFIC = {
    "//zircon/kernel/dev/hw_rng:hw_rng",
}
ARCH_AWARE = {
    "//zircon/kernel/lib/libc:libc",
    "//zircon/kernel/vm:vm",
}
BUILD_ISSUE = {
    "//src/zircon/lib/zircon:zircon",
}
EXCLUDED = ARCH_SPECIFIC | ARCH_AWARE | BUILD_ISSUE


def read_labels(path):
    labels = []
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                labels.append(stripped)
    return labels


def validate_neutral_set(labels):
    failures = []
    bad = [l for l in labels if not l.startswith("//")]
    if bad:
        failures.append("non-repo labels in arch-neutral-set.txt: {}".format(", ".join(bad[:5])))
    dups = [l for l in labels if labels.count(l) > 1]
    seen = set()
    unique_dups = [l for l in dups if l not in seen and not seen.add(l)]
    if unique_dups:
        failures.append("duplicate labels in arch-neutral-set.txt: {}".format(", ".join(unique_dups)))
    leaked = EXCLUDED & set(labels)
    if leaked:
        failures.append(
            "reclassified targets found in arch-neutral-set.txt (must be removed): {}".format(
                ", ".join(sorted(leaked))
            )
        )
    return failures


def validate_proven_set(proven_labels, neutral_labels):
    failures = []
    neutral_set = set(neutral_labels)
    bad = [l for l in proven_labels if not l.startswith("//")]
    if bad:
        failures.append("non-repo labels in arch-proven-set.txt: {}".format(", ".join(bad[:5])))
    not_subset = [l for l in proven_labels if l not in neutral_set]
    if not_subset:
        failures.append(
            "arch-proven-set.txt entries absent from arch-neutral-set.txt: {}".format(
                ", ".join(not_subset[:5])
            )
        )
    dups = [l for l in proven_labels if proven_labels.count(l) > 1]
    seen = set()
    unique_dups = [l for l in dups if l not in seen and not seen.add(l)]
    if unique_dups:
        failures.append("duplicate labels in arch-proven-set.txt: {}".format(", ".join(unique_dups)))
    return failures


def run_check(neutral_path, proven_path):
    neutral = read_labels(neutral_path)
    proven = read_labels(proven_path)
    failures = validate_neutral_set(neutral)
    failures += validate_proven_set(proven, neutral)
    return failures


def self_test():
    print("Running self-test fixtures for arch_separation_proof_test...")
    tmpdir = tempfile.mkdtemp()
    try:
        neutral_path = os.path.join(tmpdir, "arch-neutral-set.txt")
        proven_path = os.path.join(tmpdir, "arch-proven-set.txt")

        with open(neutral_path, "w") as f:
            f.write("# comment\n//zircon/system/ulib/fbl:fbl\n//zircon/system/ulib/ffl:ffl\n")
        with open(proven_path, "w") as f:
            f.write("//zircon/system/ulib/fbl:fbl\n")

        failures = run_check(neutral_path, proven_path)
        if failures:
            print("SELF-TEST ERROR: good fixture was rejected: {}".format(failures), file=sys.stderr)
            return 1
        print("  [FIXTURE-GOOD] known-good input accepted OK")

        with open(neutral_path, "w") as f:
            f.write("//zircon/system/ulib/fbl:fbl\n//zircon/kernel/dev/hw_rng:hw_rng\n")

        failures = run_check(neutral_path, proven_path)
        if not failures:
            print("SELF-TEST ERROR: bad fixture (arch-specific leak) was not rejected", file=sys.stderr)
            return 1
        print("  [FIXTURE-BAD]  arch-specific leak rejected OK")

        with open(neutral_path, "w") as f:
            f.write("//zircon/system/ulib/fbl:fbl\n")
        with open(proven_path, "w") as f:
            f.write("//zircon/system/ulib/ffl:ffl\n")

        failures = run_check(neutral_path, proven_path)
        if not failures:
            print(
                "SELF-TEST ERROR: bad fixture (proven not subset of neutral) was not rejected",
                file=sys.stderr,
            )
            return 1
        print("  [FIXTURE-BAD]  proven-not-subset rejected OK")

    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
    print("Self-test passed.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--neutral-set", help="Path to arch-neutral-set.txt")
    parser.add_argument("--proven-set", help="Path to arch-proven-set.txt")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if not args.neutral_set or not args.proven_set:
        print("ERROR: --neutral-set and --proven-set are required unless --self-test.", file=sys.stderr)
        return 1

    failures = run_check(args.neutral_set, args.proven_set)
    if failures:
        print("ARCH SEPARATION PROOF VIOLATION(S):", file=sys.stderr)
        for f in failures:
            print("  " + f, file=sys.stderr)
        return 1

    print("Arch separation proof structure OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
