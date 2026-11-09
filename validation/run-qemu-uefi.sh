#!/usr/bin/env bash
# Full UEFI boot path: OVMF firmware -> efi-boot-shim (\EFI\BOOT\BOOTX64.EFI)
# -> loads bootx64.zbi from the ESP root -> Zircon kernel -> userspace.
#
# This is the UEFI counterpart to run-qemu.sh (which uses the multiboot
# -kernel/-initrd boot-shim path). It stages a FAT EFI System Partition with
# the efi-boot-shim as the removable-media boot file and the product ZBI as
# bootx64.zbi, then boots it under OVMF and checks the smoke markers.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BAZEL_BIN="${BAZEL_BIN:-bazel}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-180}"
SERIAL_LOG="${SERIAL_LOG:-$(mktemp -t zircon-uefi-serial.XXXXXX.log)}"
HOSTFWD_PORT="${HOSTFWD_PORT:-8080}"
PRODUCT="${PRODUCT:-x64-smoke}"
# Unified OVMF firmware (usable via -bios); override for split CODE/VARS hosts.
OVMF_FW="${OVMF_FW:-/usr/share/ovmf/OVMF.fd}"
WORK_DIR="${WORK_DIR:-$(mktemp -d -t zircon-uefi-esp.XXXXXX)}"
ESP_IMG="${WORK_DIR}/esp.img"

SHIM_LABEL="//zircon/kernel/phys/boot-shim:efi-boot-shim"
SHIM_EFI="${ROOT_DIR}/bazel-bin/zircon/kernel/phys/boot-shim/efi-boot-shim.efi"
PRODUCT_ZBI="${ROOT_DIR}/bazel-bin/products/${PRODUCT}.zbi"

required_markers=(
  "efi-boot-shim: Loading ZBI from file"
  "welcome to Zircon"
  "starting user space"
  "userboot: CMDLINE bootloader.name=efi-boot-shim"
  "userboot-smoke: starting freestanding lwIP/e1000 HTTP echo"
  "userboot-smoke: HTTP echo listening on 10.0.2.15:80"
)
forbidden_markers=(
  "panic"
  "triple fault"
  "KERNEL FAULT"
  "FATAL ERROR"
)

build_target() {
  "$BAZEL_BIN" build "//products:${PRODUCT}" "$SHIM_LABEL"
}

stage_esp() {
  # FAT ESP: \EFI\BOOT\BOOTX64.EFI (firmware removable-media autoboot) plus
  # \bootx64.zbi at the volume root (efi-boot-shim opens it from EfiRootDir()).
  rm -f "$ESP_IMG"
  dd if=/dev/zero of="$ESP_IMG" bs=1M count=64 status=none
  mformat -i "$ESP_IMG" -F ::
  mmd -i "$ESP_IMG" ::/EFI ::/EFI/BOOT
  mcopy -i "$ESP_IMG" "$SHIM_EFI" ::/EFI/BOOT/BOOTX64.EFI
  mcopy -i "$ESP_IMG" "$PRODUCT_ZBI" ::/bootx64.zbi
}

boot_image() {
  "$QEMU_BIN" \
    -machine q35 \
    -m 2048 \
    -no-reboot \
    -no-shutdown \
    -display none \
    -monitor none \
    -bios "$OVMF_FW" \
    -drive "format=raw,file=${ESP_IMG}" \
    -serial "file:${SERIAL_LOG}" \
    -netdev "user,id=net0,hostfwd=tcp::${HOSTFWD_PORT}-:80" \
    -device "e1000,netdev=net0" \
    >"${SERIAL_LOG}.qemu.stdout" 2>"${SERIAL_LOG}.qemu.stderr" &
  echo $!
}

check_log() {
  local log_file="$1"
  if [[ ! -s "$log_file" ]]; then
    return 1
  fi
  for marker in "${required_markers[@]}"; do
    if ! grep -aFq "$marker" "$log_file"; then
      return 1
    fi
  done
  for marker in "${forbidden_markers[@]}"; do
    if grep -aFiq "$marker" "$log_file"; then
      return 1
    fi
  done
}

http_probe() {
  local port="$1"
  local payload="cerise-uefi-probe-$(date +%s)"
  local response
  response="$(curl --silent --max-time 10 --data "$payload" \
    "http://127.0.0.1:${port}/" 2>&1)" || return 1
  if printf '%s' "$response" | grep -qF "$payload"; then
    echo "http probe: echo verified (payload present in response)"
    return 0
  fi
  echo "http probe: echo mismatch — response did not contain payload" >&2
  printf 'response: %s\n' "$response" >&2
  return 1
}

main() {
  echo "qemu version: $("$QEMU_BIN" --version | head -n 1)"
  echo "firmware: ${OVMF_FW}"
  echo "product: ${PRODUCT}"
  echo "esp image: ${ESP_IMG}"
  echo "serial log: $SERIAL_LOG"
  echo "hostfwd: 127.0.0.1:${HOSTFWD_PORT} -> guest:80"
  echo "timeout: ${TIMEOUT_SECONDS}s"
  if [[ ! -f "$OVMF_FW" ]]; then
    echo "ERROR: OVMF firmware not found at ${OVMF_FW} (set OVMF_FW)" >&2
    return 1
  fi
  build_target
  stage_esp
  local qemu_pid
  qemu_pid="$(boot_image)"

  local elapsed=0
  local interval=1
  while (( elapsed < TIMEOUT_SECONDS )); do
    if check_log "$SERIAL_LOG"; then
      echo "markers: satisfied"
      echo "running HTTP probe against 127.0.0.1:${HOSTFWD_PORT}..."
      if ! http_probe "$HOSTFWD_PORT"; then
        kill "$qemu_pid" >/dev/null 2>&1 || true
        wait "$qemu_pid" >/dev/null 2>&1 || true
        echo "HTTP probe failed"
        return 1
      fi
      kill "$qemu_pid" >/dev/null 2>&1 || true
      wait "$qemu_pid" >/dev/null 2>&1 || true
      echo "UEFI boot OK"
      return 0
    fi
    if ! kill -0 "$qemu_pid" >/dev/null 2>&1; then
      wait "$qemu_pid" || true
      echo "qemu exited before required markers appeared"
      break
    fi
    sleep "$interval"
    elapsed=$((elapsed + interval))
  done

  kill "$qemu_pid" >/dev/null 2>&1 || true
  wait "$qemu_pid" >/dev/null 2>&1 || true

  echo "serial log tail:"
  tail -n 40 "$SERIAL_LOG" || true
  echo "stderr tail:"
  tail -n 20 "${SERIAL_LOG}.qemu.stderr" || true
  echo "marker check failed"
  return 1
}

main "$@"
