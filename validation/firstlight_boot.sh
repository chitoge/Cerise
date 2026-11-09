#!/usr/bin/env bash
# Real-hardware first-light UEFI boot wrapper (sh_test). Resolves the QEMU binary,
# its data dir, the pinned OVMF CODE/VARS, and the firstlight GPT disk image from
# runfiles, then execs the ordered-marker + QMP-screendump test.
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
# The renderer's own 8x8 glyph table, parsed by the test so its idea of what a digit
# looks like cannot drift from what the console draws.
FONT="$(resolve "$4")"
shift 4
# Any remaining args are passed through verbatim to the test (e.g. the cf-sz5
# gate's --pio-serial=0xf0a0:19 --label=cf-sz5-firstlight).
BIOS="$(find "${RUNFILES}" -name bios-256k.bin -print -quit 2>/dev/null)"
DATADIR="$(dirname "${BIOS}")"
OVMF_CODE="$(find "${RUNFILES}" -name OVMF_CODE_4M.fd -print -quit 2>/dev/null)"
OVMF_VARS="$(find "${RUNFILES}" -name OVMF_VARS_4M.fd -print -quit 2>/dev/null)"

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --qemu-data-dir="${DATADIR}" \
  --ovmf-code="${OVMF_CODE}" \
  --ovmf-vars="${OVMF_VARS}" \
  --disk="${DISK}" \
  --font="${FONT}" \
  "$@"
