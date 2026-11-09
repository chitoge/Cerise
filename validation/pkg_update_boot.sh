#!/usr/bin/env bash
# Cerise packages live-boot test wrapper (sh_test — same shape as
# fileserver_grpc_boot.sh / pkg-boot). Resolves QEMU/shim/ZBI/data-dir from runfiles, assembles the
# v2 download payload into a temp dir (manifest.json + meta.far + blob_<i>, the names the host server
# expects), then execs the two-boot updatable-packages test.
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

# v2 download payload: $5 manifest, $6 meta.far, $7..$10 blob_0..3, then the SIGNED entries:
# $11 entry.json (genuine), $12 entry_bad.json (tampered sig), $13 entry_evil.json (signed, lying id).
V2_MANIFEST="$(resolve "$5")"
V2_META_FAR="$(resolve "$6")"
V2_BLOB_0="$(resolve "$7")"
V2_BLOB_1="$(resolve "$8")"
V2_BLOB_2="$(resolve "$9")"
V2_BLOB_3="$(resolve "${10}")"
V2_ENTRY="$(resolve "${11}")"
V2_ENTRY_BAD="$(resolve "${12}")"
V2_ENTRY_EVIL="$(resolve "${13}")"

V2DIR="${TEST_TMPDIR:-/tmp}/v2"
mkdir -p "${V2DIR}"
cp -f "${V2_MANIFEST}" "${V2DIR}/manifest.json"
cp -f "${V2_META_FAR}" "${V2DIR}/meta.far"
cp -f "${V2_BLOB_0}" "${V2DIR}/blob_0"
cp -f "${V2_BLOB_1}" "${V2DIR}/blob_1"
cp -f "${V2_BLOB_2}" "${V2DIR}/blob_2"
cp -f "${V2_BLOB_3}" "${V2DIR}/blob_3"
cp -f "${V2_ENTRY}" "${V2DIR}/entry.json"
cp -f "${V2_ENTRY_BAD}" "${V2DIR}/entry_bad.json"
cp -f "${V2_ENTRY_EVIL}" "${V2DIR}/entry_evil.json"

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --shim="${SHIM}" \
  --zbi="${ZBI}" \
  --qemu-data-dir="${DATADIR}" \
  --v2-dir="${V2DIR}"
