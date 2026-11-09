#!/usr/bin/env bash
# Cerise gRPC gate service integration live-boot test wrapper (sh_test — rules_python's py_test
# is not a direct dep here). Resolves the QEMU binary, boot shim, ZBI, and the QEMU
# data dir from runfiles, then execs the direct-kernel boot + gRPC Stat test.
set -euo pipefail

# $1..$3 are $(rootpath ...) runfiles-relative paths; resolve against the runfiles root.
RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "${RUNFILES}" ]]; then
  # Fall back to the conventional <binary>.runfiles dir.
  RUNFILES="${0}.runfiles"
fi

resolve() {
  # Try a few layouts: direct under runfiles root, or under the main-repo subdir.
  for base in "${RUNFILES}" "${RUNFILES}/_main" "${RUNFILES}/cerise"; do
    if [[ -e "${base}/$1" ]]; then echo "${base}/$1"; return 0; fi
  done
  # Last resort: search.
  find "${RUNFILES}" -path "*/$1" -print -quit 2>/dev/null
}

QEMU="$(resolve "$1")"
SHIM="$(resolve "$2")"
ZBI="$(resolve "$3")"
# The qemu data dir: find bios-256k.bin anywhere in runfiles and take its parent.
BIOS="$(find "${RUNFILES}" -name bios-256k.bin -print -quit 2>/dev/null)"
DATADIR="$(dirname "${BIOS}")"

TEST="$(resolve "$4")"

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --shim="${SHIM}" \
  --zbi="${ZBI}" \
  --qemu-data-dir="${DATADIR}"
