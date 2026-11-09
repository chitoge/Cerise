#!/usr/bin/env bash
# sh_test wrapper for driver_export_surface_test.py (stdlib-only python via
# python3, matching no_unstripped_bootfs_elf_test / build_id_store_test).
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "$RUNFILES" ]]; then
  echo "ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set" >&2
  exit 1
fi

SCRIPT=""
for candidate in \
    "$RUNFILES/cerise/validation/driver_export_surface_test.py" \
    "$RUNFILES/_main/validation/driver_export_surface_test.py"; do
  if [[ -f "$candidate" ]]; then SCRIPT="$candidate"; break; fi
done
if [[ -z "$SCRIPT" ]]; then
  echo "ERROR: could not find driver_export_surface_test.py in runfiles ($RUNFILES)" >&2
  exit 1
fi

exec python3 "$SCRIPT" "$@"
