#!/usr/bin/env bash
# sh_test wrapper for build_id_store_test.py (this tree has no rules_python;
# stdlib-only python is run via python3, matching build/checks/*_test).
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "$RUNFILES" ]]; then
  echo "ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set" >&2
  exit 1
fi

SCRIPT=""
for candidate in \
    "$RUNFILES/cerise/validation/build_id_store_test.py" \
    "$RUNFILES/_main/validation/build_id_store_test.py"; do
  if [[ -f "$candidate" ]]; then SCRIPT="$candidate"; break; fi
done
if [[ -z "$SCRIPT" ]]; then
  echo "ERROR: could not find build_id_store_test.py in runfiles ($RUNFILES)" >&2
  exit 1
fi

exec python3 "$SCRIPT" "$@"
