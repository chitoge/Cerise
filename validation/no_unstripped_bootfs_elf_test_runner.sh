#!/usr/bin/env bash
# sh_test wrapper for no_unstripped_bootfs_elf_test.py (stdlib-only python via
# python3, matching build_id_store_test / build/checks/*_test convention).
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "$RUNFILES" ]]; then
  echo "ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set" >&2
  exit 1
fi

SCRIPT=""
for candidate in \
    "$RUNFILES/cerise/validation/no_unstripped_bootfs_elf_test.py" \
    "$RUNFILES/_main/validation/no_unstripped_bootfs_elf_test.py"; do
  if [[ -f "$candidate" ]]; then SCRIPT="$candidate"; break; fi
done
if [[ -z "$SCRIPT" ]]; then
  echo "ERROR: could not find no_unstripped_bootfs_elf_test.py in runfiles ($RUNFILES)" >&2
  exit 1
fi

exec python3 "$SCRIPT" "$@"
