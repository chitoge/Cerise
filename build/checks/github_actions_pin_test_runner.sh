#!/usr/bin/env bash
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "${RUNFILES}" ]]; then
  echo "ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set" >&2
  exit 1
fi

SCRIPT=""
for candidate in \
  "$RUNFILES/cerise/build/checks/github_actions_pin_test.py" \
  "$RUNFILES/_main/build/checks/github_actions_pin_test.py"; do
  if [[ -f "$candidate" ]]; then
    SCRIPT="$candidate"
    break
  fi
done

if [[ -z "${SCRIPT}" ]]; then
  echo "ERROR: could not find github_actions_pin_test.py in runfiles ($RUNFILES)" >&2
  exit 1
fi

exec python3 "${SCRIPT}" "$@"
