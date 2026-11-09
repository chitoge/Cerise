#!/usr/bin/env bash
# Runfiles resolver for the direct-kernel ZBI boot harness (sh_test wrapper).
# Resolves the QEMU binary, boot shim, ZBI, harness, and QEMU data dir from
# runfiles, then execs zbi_boot_test.py forwarding any remaining flags verbatim.
#
# Modeled on validation/fileserver_grpc_boot.sh.
#
# argv: $1=qemu $2=shim $3=zbi $4=harness.py [assert flags...]
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
TEST="$(resolve "$4")"
shift 4

# The QEMU data dir: find bios-256k.bin anywhere in runfiles and take its parent.
BIOS="$(find "${RUNFILES}" -name bios-256k.bin -print -quit 2>/dev/null)"
DATADIR="$(dirname "${BIOS}")"

exec python3 "${TEST}" \
  --qemu="${QEMU}" --shim="${SHIM}" --zbi="${ZBI}" --qemu-data-dir="${DATADIR}" "$@"
