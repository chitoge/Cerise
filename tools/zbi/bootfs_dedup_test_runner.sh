#!/usr/bin/env bash
# Locates the dedup test + its two inputs (simple_zbi.py under test and
# bootfs_diff.py's parser) in runfiles, then runs the test.
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "${RUNFILES}" ]]; then
  echo "ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set" >&2
  exit 1
fi

find_file() {
  local rel="$1"
  for prefix in cerise _main; do
    local candidate="${RUNFILES}/${prefix}/${rel}"
    if [[ -f "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done
  echo "ERROR: could not find ${rel} in runfiles (${RUNFILES})" >&2
  return 1
}

TEST_PY="$(find_file tools/zbi/bootfs_dedup_test.py)"
SIMPLE_ZBI="$(find_file tools/zbi/simple_zbi.py)"
BOOTFS_DIFF="$(find_file assembly/tools/bootfs_diff.py)"
ZSTD_CLI="$(find_file tools/zstd/zstd_cli)"

exec python3 "${TEST_PY}" \
  --simple-zbi "${SIMPLE_ZBI}" \
  --bootfs-diff "${BOOTFS_DIFF}" \
  --zstd-tool "${ZSTD_CLI}"
