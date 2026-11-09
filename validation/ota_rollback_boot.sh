#!/usr/bin/env bash
# OTA A/B rollback gate wrapper (sh_test). Resolves the QEMU binary, its data
# dir, the pinned OVMF CODE/VARS, and the ota-rollback GPT disk image from
# runfiles, then execs the ordered-marker rollback test.
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
DISK="$(resolve "$2")"
TEST="$(resolve "$3")"
BIOS="$(find "${RUNFILES}" -name bios-256k.bin -print -quit 2>/dev/null)"
DATADIR="$(dirname "${BIOS}")"
OVMF_CODE="$(find "${RUNFILES}" -name OVMF_CODE_4M.fd -print -quit 2>/dev/null)"
OVMF_VARS="$(find "${RUNFILES}" -name OVMF_VARS_4M.fd -print -quit 2>/dev/null)"

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --qemu-data-dir="${DATADIR}" \
  --ovmf-code="${OVMF_CODE}" \
  --ovmf-vars="${OVMF_VARS}" \
  --disk="${DISK}"
