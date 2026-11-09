#!/usr/bin/env bash
# Canonical "all checks" gate for Cerise: runs LOCALLY, in one command, exactly
# the target set CI's `checks` job runs — read out of .github/workflows/ci.yml
# itself, so this script and CI cannot drift apart.
#
#     build/checks/run-all.sh [extra bazel flags...]
#
# WHAT HAPPENED TO STEP 2. This script used to run a second, mandatory step,
# `bazel run //build/checks:vendored_divergence_scan`, and its header claimed
# that `bazel test //build/checks:all` alone would miss a silent patch to
# vendored upstream. That target was removed (build/checks/BUILD.bazel:9-13:
# "Cerise borrows Fuchsia constructs directly rather than tracking against a
# frozen upstream import"), and under `set -euo pipefail` the script therefore
# died at step 2 and could NEVER print its own success line — measured
# 2026-07-26: 27 tests pass, then `no such target`, exit 1.
#
# So the property is gone, not merely unchecked here, and the honest thing is to
# say so rather than to delete the step and leave the header's claim standing:
#
#     THERE IS NO WHOLE-TREE VENDORED-DIVERGENCE CHECK IN THIS TREE. A silent
#     patch to a vendored upstream source is not caught by this script, by
#     //build/checks:all, or by CI. Reinstating one means reinstating the
#     import-baseline hash manifest it needs.
#
# WHY THE TARGET LIST IS PARSED, NOT COPIED. A copy is a second list, and a
# second list is a list that goes stale. This script has no list of its own: it
# extracts the `//...` targets from the `checks` job in
# .github/workflows/ci.yml and refuses to run if that extraction yields
# implausibly few, so a reformat that breaks the parse fails loudly instead of
# quietly running a subset.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

CI_YML=".github/workflows/ci.yml"
if [[ ! -f "${CI_YML}" ]]; then
  echo "ERROR: ${CI_YML} not found; this script takes its target set from CI." >&2
  exit 2
fi

# Minimum plausible size of CI's checks set. It is 12 today. A parse that finds
# fewer than this has almost certainly broken, and running a silent subset while
# printing "ALL CHECKS GREEN" is the exact failure this file exists to not have.
MIN_TARGETS=10

mapfile -t TARGETS < <(python3 - "${CI_YML}" <<'PY'
import re, sys

text = open(sys.argv[1]).read()
# The `checks` job's steps, up to the next top-level job key.
m = re.search(r"\n  checks:\n(.*?)(?=\n  \w[\w-]*:\n)", text, re.S)
if not m:
    sys.exit("could not find the `checks` job in " + sys.argv[1])
job = m.group(1)
targets = re.findall(r"(//[\w./@+-]+(?::[\w./+-]+)?)", job)
if not targets:
    sys.exit("the `checks` job names no //targets; the parse is broken")
seen, out = set(), []
for t in targets:
    if t not in seen:
        seen.add(t)
        out.append(t)
print("\n".join(out))
PY
)

if (( ${#TARGETS[@]} < MIN_TARGETS )); then
  echo "ERROR: parsed only ${#TARGETS[@]} target(s) from ${CI_YML} (expected >= ${MIN_TARGETS})." >&2
  printf '  %s\n' "${TARGETS[@]}" >&2
  echo "Refusing to report a green run over a set this small." >&2
  exit 2
fi

echo "== running CI's checks set (${#TARGETS[@]} targets, parsed from ${CI_YML}) =="
printf '  %s\n' "${TARGETS[@]}"
echo
bazel test --keep_going "${TARGETS[@]}" "$@"

echo "ALL CHECKS GREEN (${#TARGETS[@]} CI check targets)"
echo "NOTE: no vendored-divergence scan exists in this tree; see the header."
