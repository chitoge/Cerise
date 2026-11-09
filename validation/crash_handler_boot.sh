#!/usr/bin/env bash
# Cerise crash-handler live-boot wrapper (sh_test — mirrors shutdown_boot.sh,
# plus the host-side symbolize inputs). Resolves the QEMU binary, boot shim, ZBI,
# QEMU data dir, the symbolize tool, the .build-id store, and llvm-symbolizer from
# runfiles, then execs the boot + crash-observation + symbolization test.
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
SYMBOLIZE="$(resolve "$5")"
STORE="$(resolve "$6")"
LLVM_SYMBOLIZER="$(resolve "$7")"

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --shim="${SHIM}" \
  --zbi="${ZBI}" \
  --qemu-data-dir="${DATADIR}" \
  --symbolize="${SYMBOLIZE}" \
  --build-id-dir="${STORE}" \
  --llvm-symbolizer="${LLVM_SYMBOLIZER}"
