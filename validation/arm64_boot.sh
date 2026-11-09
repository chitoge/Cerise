#!/usr/bin/env bash
# Cerise arm64 live-boot wrapper (sh_test — mirrors posix_probe_boot.sh).
# Resolves the pinned qemu-system-aarch64, the arm64 boot shim, the product ZBI,
# the markers-contract JSON, and the python driver from runfiles, then execs the
# arm64 direct-kernel boot (qemu-system-aarch64 -machine virt -kernel <shim>
# -initrd <zbi>). Unlike the x86 UEFI gates this needs NO firmware/BIOS or qemu
# data dir: with `-net none` no option-ROM blobs are touched.
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
MARKERS="$(resolve "$4")"
TEST="$(resolve "$5")"

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --shim="${SHIM}" \
  --zbi="${ZBI}" \
  --markers="${MARKERS}"
