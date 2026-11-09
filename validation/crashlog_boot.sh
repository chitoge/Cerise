#!/usr/bin/env bash
# Cerise crashlog-across-warm-reboot live-boot wrapper (sh_test — mirrors
# shutdown_boot.sh). Resolves the QEMU binary, boot shim, ZBI, and the QEMU data
# dir from runfiles, then execs the direct-kernel boot + crashlog-recovery
# assertion test.
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
# host-side symbolize inputs (tool, kernel .build-id store,
# llvm-symbolizer) so the recovered crashlog + any failing tail print symbolized.
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
