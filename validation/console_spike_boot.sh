#!/usr/bin/env bash
# Cerise status-console initial prototype live-boot wrapper (sh_test — mirrors
# fileserver_grpc_boot.sh). Resolves the QEMU binary, boot shim, ZBI, and the QEMU
# data dir from runfiles, then execs the direct-kernel boot + QMP screendump test.
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
# The guest component's own source: the expected frame is reconstructed from it, so
# the gate's picture of the pattern cannot drift from the one the spike paints.
FB_SPIKE_RS="$(resolve "$5")"

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --shim="${SHIM}" \
  --zbi="${ZBI}" \
  --qemu-data-dir="${DATADIR}" \
  --fb-spike-rs="${FB_SPIKE_RS}"
