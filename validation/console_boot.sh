#!/usr/bin/env bash
# Cerise status-console storage-backed integration live-boot wrapper (sh_test). Resolves the QEMU binary,
# boot shim, ZBI, and the QEMU data dir from runfiles, then execs the combined
# fileserver + console boot + QMP screendump test.
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "${RUNFILES}" ]]; then
  RUNFILES="${0}.runfiles"
fi

resolve() {
  for base in "${RUNFILES}" "${RUNFILES}/_main" "${RUNFILES}/cerise"; do
    if [[ -e "${base}/$1" ]]; then echo "${base}/$1"; return 0; fi
  done
  find "${RUNFILES}" -path "*/$1" -print -quit 2>/dev/null
}

QEMU="$(resolve "$1")"
SHIM="$(resolve "$2")"
ZBI="$(resolve "$3")"
BIOS="$(find "${RUNFILES}" -name bios-256k.bin -print -quit 2>/dev/null)"
DATADIR="$(dirname "${BIOS}")"
TEST="$(resolve "$4")"
# The renderer's own 8x8 glyph table, parsed by the test so its idea of what a digit
# looks like cannot drift from what the console draws.
FONT="$(resolve "$5")"

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --shim="${SHIM}" \
  --zbi="${ZBI}" \
  --qemu-data-dir="${DATADIR}" \
  --font="${FONT}"
