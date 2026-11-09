#!/usr/bin/env bash
# Cerise packages (post-storage app tier) live-boot wrapper. Resolves QEMU/shim/ZBI/data-dir
# from runfiles, assembles the fileserver-package download payload into a temp dir (manifest.json +
# meta.far + blob_<i>, the names the host server expects), then execs the two-boot app-tier gate.
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

# fileserver package payload: $5 manifest, $6 meta.far, $7..$10 blob_0..3.
PKG_MANIFEST="$(resolve "$5")"
PKG_META_FAR="$(resolve "$6")"
PKG_BLOB_0="$(resolve "$7")"
PKG_BLOB_1="$(resolve "$8")"
PKG_BLOB_2="$(resolve "$9")"
PKG_BLOB_3="$(resolve "${10}")"

PKGDIR="${TEST_TMPDIR:-/tmp}/fileserver_pkg"
mkdir -p "${PKGDIR}"
cp -f "${PKG_MANIFEST}" "${PKGDIR}/manifest.json"
cp -f "${PKG_META_FAR}" "${PKGDIR}/meta.far"
cp -f "${PKG_BLOB_0}" "${PKGDIR}/blob_0"
cp -f "${PKG_BLOB_1}" "${PKGDIR}/blob_1"
cp -f "${PKG_BLOB_2}" "${PKGDIR}/blob_2"
cp -f "${PKG_BLOB_3}" "${PKGDIR}/blob_3"

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --shim="${SHIM}" \
  --zbi="${ZBI}" \
  --qemu-data-dir="${DATADIR}" \
  --pkg-dir="${PKGDIR}"
