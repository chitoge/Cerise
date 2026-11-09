#!/usr/bin/env bash
set -euo pipefail

runfiles="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "$runfiles" ]]; then
  echo "efi timestamp check: runfiles directory is unset" >&2
  exit 1
fi

script=""
for candidate in \
    "$runfiles/cerise/build/phys/efi_timestamp_test.py" \
    "$runfiles/_main/build/phys/efi_timestamp_test.py"; do
  if [[ -f "$candidate" ]]; then
    script="$candidate"
    break
  fi
done
if [[ -z "$script" ]]; then
  echo "efi timestamp check: test script not found" >&2
  exit 1
fi

exec python3 "$script" "$@"
