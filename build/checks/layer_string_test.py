#!/usr/bin/env python3
"""Check that no ARCH-NEUTRAL package's BUILD file names an architecture.

WHAT THIS USED TO BE, AND WHY IT WAS REPLACED. This check used to scan a list of
BUILD files for the word-boundary tokens x64/x86_64/arm64/kernel/phys/efi and
report a violation outside the "sanctioned" composition layer (platforms/,
toolchain/, products/, boards/, bundles/, validation/). It was 100% vacuous: all
four files it was given were sanctioned, `scan_files` skips sanctioned paths, so
the loop read zero bytes and returned []. Worse, the pass line counted its
ARGUMENTS ("4 file(s) scanned"), which is what hid it, and its self-test passed
because the self-test fabricated a NON-sanctioned input — a shape the real test
never had.

Pointing the old check at real files was not an option: the policy it stated is
not this tree's policy. Measured 2026-07-26 over every non-vendored BUILD file
outside the sanctioned layers: 426 files, of which **140 contain those tokens**
(kernel 79, x86_64 47, x64 36, phys 29, arm64 13, efi 13) — mostly because every
label under //zircon/kernel/... contains the word "kernel". A check whose stated
policy is violated 140 times cannot be turned on, which is presumably how it
ended up pointed at a list of files it can only skip.

WHAT IT CHECKS NOW. The tree already declares a three-way architecture partition
(build/checks/arch-neutral-set.txt, generated from build/partition/components.json,
and consumed by :arch_separation_proof_test): arch-specific, arch-aware, and
arch-neutral. "Arch-neutral" is a claim, and it is checkable at the BUILD level:
a package that is genuinely arch-neutral does not name an architecture in its own
build rules. So this check scans exactly the packages declared arch-neutral, and
fails when one of them references an architecture — a dependency on an arch/<cpu>
package, an @platforms//cpu: constraint, an arch-keyed //platforms: label, an
-march=/-mcpu=/--target= flag, or a bare arch token.

THREE PROPERTIES THAT KEEP IT FROM GOING VACUOUS AGAIN:

  * COVERAGE IS ASSERTED, NOT ASSUMED. The set of files to scan is not a
    hand-picked list this check trusts: every package named in
    arch-neutral-set.txt must appear among the inputs, or the check fails. The
    input list cannot be quietly narrowed, which is the failure mode that made
    the old version report a green "4 file(s) scanned" while reading nothing.

  * AN INPUT THAT CAN ONLY BE SKIPPED IS AN ERROR. Passing a sanctioned
    composition-layer file is now a hard failure rather than a silent skip. That
    is precisely the state the old check was in.

  * IT COUNTS BYTES IT ACTUALLY READ, and fails on zero.

KNOWN_ARCH_REFERENCES is a standing known-bad input inside the real check, not
just in the self-test: each entry must STILL be detected on every run. If the
scanner ever stops seeing an architecture reference it is known to be looking at,
the run goes red instead of quietly reporting that everything is clean.
"""

import argparse
import os
import re
import sys
import tempfile

#: The composition layer (§3), where product, board and hardware-bundle names
#: legitimately carry an arch token. Files here are not scannable inputs at all;
#: passing one is an error, not a skip.
SANCTIONED_PREFIXES = (
    "platforms/",
    "toolchain/",
    "products/",
    "boards/",
    "bundles/",
    "validation/",
)

#: Each entry: (class name, compiled pattern). Applied to comment-stripped text,
#: so a comment that merely MENTIONS arch/x86 (as backtrace's and ram-crashlog's
#: do, explaining which headers they pull in) is not a violation — the rules are.
ARCH_PATTERNS = (
    # A dependency on an architecture's own package: the strongest form of an
    # arch-neutral package not being arch-neutral.
    ("arch-package label", re.compile(r"//[\w./-]*\barch/(?:x86|x86_64|arm64|aarch64|riscv64)[\w/:.-]*")),
    # A CPU constraint pins the rule to one architecture.
    ("cpu constraint", re.compile(r"@platforms//cpu:\w+")),
    # An arch-keyed platform or config label.
    ("arch platform label", re.compile(r"//(?:platforms|config):[\w-]*(?:x64|x86|arm64|aarch64)[\w-]*")),
    # Compiler/linker flags that name a target architecture.
    ("arch flag", re.compile(r"-march=\S+|-mcpu=\S+|--target=(?:x86_64|x86|i386|i686|aarch64|arm64|riscv64)[\w.-]*")),
    # A bare architecture token anywhere else (a file name, a target name, a
    # select() key, a string literal).
    ("arch token", re.compile(r"\b(?:x86_64|x86_32|x86|x64|arm64|aarch64|riscv64)\b")),
)

#: Arch references that EXIST TODAY in packages arch-neutral-set.txt declares
#: neutral. Each is a real, recorded discrepancy between the declaration and the
#: BUILD file, kept here with a reason so it cannot rot — and asserted to still
#: be DETECTED on every run, which is what proves the scanner still works.
#:
#: To remove an entry: make the reference go away, then delete the entry (the
#: check fails on a stale entry, so the two cannot drift).
#: To add one: it needs the same thing this one has — a reason, and a date.
KNOWN_ARCH_REFERENCES = {
    "zircon/kernel/hypervisor/BUILD.bazel": {
        "findings": {
            "//zircon/kernel/arch/x86/hypervisor:hypervisor",
            "//zircon/kernel/arch/x86/hypervisor:kernel-tests",
            "x86",
        },
        # Recorded 2026-07-26. The arch-neutral set lists
        # //zircon/kernel/hypervisor:hypervisor as neutral, but its `hypervisor`
        # and `kernel-tests` filegroups splice the x86 backend in directly rather
        # than through a select() or a board-level choice. Until an arm64
        # hypervisor backend exists there is nothing to select BETWEEN, so this
        # is a known, deliberate gap in the neutrality claim rather than an
        # accident — but it IS a gap, and it is the reason this file cannot be
        # said to have proven the neutral set clean.
        "reason": "arch-neutral-set.txt claims neutrality this BUILD file does not have",
    },
}


def _package_of(build_file_path):
    """'zircon/kernel/vm/BUILD.bazel' -> 'zircon/kernel/vm'."""
    return os.path.dirname(os.path.normpath(build_file_path).replace("\\", "/"))


def _is_sanctioned(rel):
    padded = "/{}/".format(rel)
    return rel.startswith(SANCTIONED_PREFIXES) or any(
        "/{}/".format(prefix.rstrip("/")) in padded for prefix in SANCTIONED_PREFIXES
    )


def strip_comments(text):
    """Removes Starlark line comments. A comment cannot make a build rule
    arch-specific, and two neutral packages have comments that name arch/x86 and
    arm64 while their rules do not."""
    return re.sub(r"#[^\n]*", "", text)


def parse_neutral_set(path):
    """The package paths named by arch-neutral-set.txt ('//pkg:target' lines)."""
    packages = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("//"):
                raise AssertionError(
                    "{}: unexpected line {!r}; expected '//package:target'".format(path, line)
                )
            packages.append(line[2:].split(":", 1)[0])
    if not packages:
        raise AssertionError("{} declares no arch-neutral packages".format(path))
    return packages


def find_arch_references(text):
    """Returns {matched string: class name} for every architecture reference."""
    found = {}
    for name, rx in ARCH_PATTERNS:
        for m in rx.finditer(text):
            found.setdefault(m.group(0), name)
    return found


def check(neutral_packages, build_files):
    """Returns (failures, scanned_files, scanned_bytes, known_seen)."""
    failures = []
    by_package = {}
    for path in build_files:
        rel = os.path.normpath(path).replace("\\", "/")
        if not rel.endswith("BUILD.bazel"):
            failures.append("not a BUILD file: {}".format(rel))
            continue
        if _is_sanctioned(rel):
            # This is the exact state the old version of this check was in: every
            # input skipped, zero bytes read, a green line counting arguments.
            failures.append(
                "{} is in the sanctioned composition layer, so this check can only "
                "skip it; passing it as an input is what made this check vacuous".format(rel)
            )
            continue
        by_package[_package_of(rel)] = rel

    # COVERAGE: the inputs must cover the declared neutral set exactly, so the
    # scan set cannot be narrowed without the check saying so.
    for pkg in neutral_packages:
        if pkg not in by_package:
            failures.append(
                "arch-neutral-set.txt declares //{} arch-neutral but its BUILD file was "
                "not given to this check; add it to :arch_neutral_build_files".format(pkg)
            )

    scanned_files = 0
    scanned_bytes = 0
    known_seen = 0
    for pkg in neutral_packages:
        rel = by_package.get(pkg)
        if rel is None:
            continue
        if not os.path.exists(rel):
            failures.append("missing BUILD file: {}".format(rel))
            continue
        with open(rel) as f:
            raw = f.read()
        scanned_files += 1
        scanned_bytes += len(raw)
        found = find_arch_references(strip_comments(raw))
        known = KNOWN_ARCH_REFERENCES.get(rel, {}).get("findings", set())
        unexpected = sorted(set(found) - known)
        if unexpected:
            failures.append(
                "{} is declared ARCH-NEUTRAL but its build rules name an architecture: "
                "{}".format(rel, ", ".join("{} ({})".format(m, found[m]) for m in unexpected))
            )
        # The standing known-bad input: a scanner that stopped working would stop
        # seeing these, and would otherwise look perfectly healthy.
        stale = sorted(known - set(found))
        if stale:
            failures.append(
                "{} no longer contains the known arch reference(s) {} — good, but the "
                "entry in KNOWN_ARCH_REFERENCES is now stale and must be deleted, "
                "otherwise this check is asserting a property nothing has".format(
                    rel, ", ".join(stale)
                )
            )
        known_seen += len(known & set(found))

    if scanned_files == 0 or scanned_bytes == 0:
        failures.append(
            "read {} byte(s) from {} file(s): this check observed NOTHING. A run that "
            "scans nothing is a failure, not a pass.".format(scanned_bytes, scanned_files)
        )
    return failures, scanned_files, scanned_bytes, known_seen


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def self_test():
    print("Running self-test fixtures for layer_string_test...")
    tmpdir = tempfile.mkdtemp()
    cwd = os.getcwd()
    try:
        os.chdir(tmpdir)
        good = _write("zircon/kernel/lib/btree/BUILD.bazel", 'cc_library(name = "btree")\n')
        bad = _write(
            "zircon/kernel/lib/sched/BUILD.bazel",
            'cc_library(name = "sched", deps = ["//zircon/kernel/arch/x86:x86"])\n',
        )
        commented = _write(
            "zircon/system/ulib/affine/BUILD.bazel",
            '# arch/x86 headers come in via the toolchain\ncc_library(name = "affine")\n',
        )
        sanctioned = _write("products/BUILD.bazel", 'product(name = "x64-smoke")\n')

        pkgs = ["zircon/kernel/lib/btree"]
        failures, files, nbytes, known = check(pkgs, [good])
        if failures or files != 1 or nbytes <= 0:
            print("SELF-TEST ERROR: [FIXTURE-GOOD] rejected a clean neutral BUILD file: "
                  "{}".format(failures), file=sys.stderr)
            return 1
        print("  [FIXTURE-GOOD]     clean arch-neutral BUILD file accepted "
              "({} bytes actually read)".format(nbytes))

        failures, _, _, _ = check(["zircon/kernel/lib/sched"], [bad])
        if not any("name an architecture" in f for f in failures):
            print("SELF-TEST ERROR: [FIXTURE-BAD] accepted an arch dependency in a neutral "
                  "package: {}".format(failures), file=sys.stderr)
            return 1
        print("  [FIXTURE-BAD]      arch dependency in an arch-neutral package rejected")

        failures, _, _, _ = check(["zircon/system/ulib/affine"], [commented])
        if failures:
            print("SELF-TEST ERROR: [FIXTURE-COMMENT] a comment naming arch/x86 was treated "
                  "as a violation: {}".format(failures), file=sys.stderr)
            return 1
        print("  [FIXTURE-COMMENT]  a comment naming arch/x86 is not a violation")

        failures, _, _, _ = check(["products"], [sanctioned])
        if not any("sanctioned composition layer" in f for f in failures):
            print("SELF-TEST ERROR: [FIXTURE-SKIPPABLE] a sanctioned input was silently "
                  "skipped instead of failing: {}".format(failures), file=sys.stderr)
            return 1
        print("  [FIXTURE-SKIPPABLE] an input this check can only skip is an error")

        failures, _, _, _ = check(["zircon/kernel/lib/btree", "zircon/kernel/vm"], [good])
        if not any("was not given to this check" in f for f in failures):
            print("SELF-TEST ERROR: [FIXTURE-COVERAGE] a declared neutral package missing "
                  "from the inputs did not fail: {}".format(failures), file=sys.stderr)
            return 1
        print("  [FIXTURE-COVERAGE] a declared neutral package missing from the inputs fails")

        failures, _, _, _ = check([], [])
        if not any("observed NOTHING" in f for f in failures):
            print("SELF-TEST ERROR: [FIXTURE-EMPTY] scanning nothing was reported as a pass: "
                  "{}".format(failures), file=sys.stderr)
            return 1
        print("  [FIXTURE-EMPTY]    scanning zero bytes is a failure, not a pass")

        # The standing known-bad entry: a scanner that sees nothing must not pass.
        key = "zircon/kernel/lib/btree/BUILD.bazel"
        saved = KNOWN_ARCH_REFERENCES.get(key)
        KNOWN_ARCH_REFERENCES[key] = {"findings": {"x86_64"}, "reason": "self-test"}
        try:
            failures, _, _, _ = check(["zircon/kernel/lib/btree"], [good])
        finally:
            if saved is None:
                KNOWN_ARCH_REFERENCES.pop(key, None)
            else:
                KNOWN_ARCH_REFERENCES[key] = saved
        if not any("stale" in f for f in failures):
            print("SELF-TEST ERROR: [FIXTURE-STALE] a known arch reference that is no longer "
                  "detected did not fail: {}".format(failures), file=sys.stderr)
            return 1
        print("  [FIXTURE-STALE]    a known-bad input that stopped being detected fails")
    finally:
        os.chdir(cwd)
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
    print("Self-test passed.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--neutral-set", help="path to arch-neutral-set.txt")
    parser.add_argument("files", nargs="*", help="BUILD.bazel files of the neutral packages")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if not args.neutral_set:
        print("--neutral-set is required", file=sys.stderr)
        return 2

    neutral_packages = parse_neutral_set(args.neutral_set)
    failures, files, nbytes, known = check(neutral_packages, args.files)
    if failures:
        print("LAYER STRING VIOLATION(S) DETECTED:", file=sys.stderr)
        for msg in failures:
            print("\n{}".format(msg), file=sys.stderr)
        return 1

    print(
        "Layer string check OK: {} of {} declared arch-neutral package(s) scanned, "
        "{} bytes actually read, {} known arch reference(s) still detected.".format(
            files, len(neutral_packages), nbytes, known
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
