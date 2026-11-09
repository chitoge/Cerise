#!/usr/bin/env bash
# OS-self-OTA update gate wrapper (sh_test). Resolves the QEMU binary, its data dir, the
# pinned OVMF CODE/VARS, the ota-update GPT disk image, the v2 ZBI (host-served update
# payload) and the build-time SIGNED manifest for it from runfiles, then execs the test.
#
# Shared by two targets. //validation:ota-update-boot passes the genuine manifest and
# runs the positive two-launch gate. //validation:ota-update-tamper-boot passes the
# corrupt-signature manifest plus --tamper-manifest (arg 6) and runs the one-launch
# refusal gate. One wrapper and one harness on purpose: the negative target must exercise
# the same code path as the positive one, or it proves something about a different gate.
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
V2_ZBI="$(resolve "$4")"
MANIFEST="$(resolve "$5")"
MODE="${6:-}"
BIOS="$(find "${RUNFILES}" -name bios-256k.bin -print -quit 2>/dev/null)"
DATADIR="$(dirname "${BIOS}")"
OVMF_CODE="$(find "${RUNFILES}" -name OVMF_CODE_4M.fd -print -quit 2>/dev/null)"
OVMF_VARS="$(find "${RUNFILES}" -name OVMF_VARS_4M.fd -print -quit 2>/dev/null)"

# Only ever "--tamper-manifest" or empty: a typo'd sixth argument must not silently
# select the positive gate, because that gate would then pass and be believed.
if [[ -n "${MODE}" && "${MODE}" != "--tamper-manifest" ]]; then
  echo "unknown mode argument: ${MODE}" >&2
  exit 1
fi

exec python3 "${TEST}" \
  --qemu="${QEMU}" \
  --qemu-data-dir="${DATADIR}" \
  --ovmf-code="${OVMF_CODE}" \
  --ovmf-vars="${OVMF_VARS}" \
  --disk="${DISK}" \
  --v2-zbi="${V2_ZBI}" \
  --manifest="${MANIFEST}" \
  ${MODE}
