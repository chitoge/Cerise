#!/usr/bin/env python3
"""Cerise arm64 kernel live-boot proof.

Converts the arm64 kernel/phys layer from "exists" to "PROVEN by a bazel test".
Boots a product ZBI on the pinned qemu-system-aarch64 via the DIRECT-KERNEL path
(the arm64 analogue of the x86 `-kernel <shim> -initrd <zbi>` recipe), then asserts
the marker contract in validation/goldens/arm64-*-markers.json against real serial.

Boot chain (NOT UEFI — that is a later phase):
  qemu-system-aarch64 -machine virt loads build/phys/qemu_arm64_boot_shim as a
  Linux arm64 Image (-kernel); QEMU places the product ZBI as -initrd at ~0x48000000;
  the shim scans RAM for the ZBI container and jumps to physload _start at
  container_base + zbi_kernel_t.entry (the ZBI ARM64 boot protocol); physload ->
  physboot -> the Zircon kernel bring the machine up on the QEMU virt PL011 UART
  (kernel.serial=qemu -> pl011 @ 0x09000000 -> QEMU serial0 -> our -serial file).

QEMU config rationale:
  -machine virt,gic-version=2  the product's ZBI carries a GICv2 (ZBI_KERNEL_DRIVER_
                               ARM_GIC_V2) driver item; the golden asserts "GICv2
                               detected", so pin gic-version=2 (virt's default is
                               version/CPU dependent).
  -cpu cortex-a53              a plain ARMv8-A core; GICv2-compatible.
  -m 2048M                     matches the product mem_config 0x40000000,0x80000000
                               (DRAM 0x40000000..0xC0000000) and the shim's RAM-scan
                               upper bound.
  -net none                   no default NIC -> no efi-virtio.rom option ROM -> no
                               qemu data dir / firmware needed at all.
  -no-reboot                  a kernel-only smoke ends by exiting the root job ->
                               reboot; with no PSCI item that becomes a benign HALT,
                               so we assert the markers, not a clean guest exit.

Emulation is pure TCG (no nested KVM for arm64 on an x86 host); the smoke markers
appear within the first few seconds regardless.
"""
from __future__ import annotations
import argparse, json, os, pathlib, subprocess, sys, time


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _read(serial: pathlib.Path) -> str:
    return serial.read_text(errors="replace") if serial.exists() else ""


def _first_forbidden(txt: str, forbidden) -> str | None:
    # Case-sensitive substring match: the golden's forbidden entries are exact-case
    # crash signatures (e.g. "ZIRCON KERNEL PANIC") chosen NOT to collide with
    # benign lines (a case-insensitive "fatal" would false-match "fatal threshold").
    for f in forbidden:
        if f and f in txt:
            return f
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--shim", required=True)
    ap.add_argument("--zbi", required=True)
    ap.add_argument("--markers", required=True)
    ns = ap.parse_args()

    qemu = _need(ns.qemu, "qemu-system-aarch64")
    shim = _need(ns.shim, "arm64 boot shim")
    zbi = _need(ns.zbi, "product ZBI")
    contract = json.loads(pathlib.Path(_need(ns.markers, "markers json")).read_text())

    required = [m for m in contract.get("required_markers", []) if m]
    forbidden = [m for m in contract.get("forbidden_markers", []) if m]
    timeout_s = float(contract.get("timeout_seconds", 180))
    require_non_empty = bool(contract.get("non_empty_serial", True))

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    outdir = pathlib.Path(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR", str(tmp)))
    outdir.mkdir(parents=True, exist_ok=True)
    serial = outdir / "arm64-serial.log"
    if serial.exists():
        serial.unlink()

    cmd = [
        qemu,
        "-machine", "virt,gic-version=2",
        "-cpu", "cortex-a53",
        "-m", "2048M",
        "-no-reboot",
        "-net", "none",
        "-display", "none",
        "-monitor", "none",
        "-serial", f"file:{serial}",
        "-kernel", shim,
        "-initrd", zbi,
    ]
    print(f"[arm64-boot] qemu: {subprocess.run([qemu, '--version'], capture_output=True, text=True).stdout.splitlines()[0]}",
          flush=True)
    print(f"[arm64-boot] booting {pathlib.Path(zbi).name} (direct-kernel via arm64 shim)", flush=True)
    print(f"[arm64-boot] required markers: {required}", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)

    exit_reason = "unknown"
    try:
        deadline = time.time() + timeout_s
        matched: list[str] = []
        while time.time() < deadline:
            txt = _read(serial)
            hit = _first_forbidden(txt, forbidden)
            if hit is not None:
                i = txt.find(hit)
                exit_reason = f"forbidden_marker:{hit}"
                raise AssertionError(
                    f"forbidden marker {hit!r} on serial:\n...{txt[max(0, i-120):i+200]!r}")
            matched = [m for m in required if m in txt]
            if len(matched) == len(required):
                exit_reason = "success"
                break
            if proc.poll() is not None:
                # QEMU exited before all markers appeared. For a kernel-only smoke a
                # clean exit is possible AFTER the markers; re-read once and re-check.
                txt = _read(serial)
                matched = [m for m in required if m in txt]
                if len(matched) == len(required) and _first_forbidden(txt, forbidden) is None:
                    exit_reason = "success"
                    break
                exit_reason = "qemu_exited_early"
                raise AssertionError(
                    f"QEMU exited (rc={proc.returncode}) before all markers; "
                    f"matched {matched}, missing {[m for m in required if m not in matched]}")
            time.sleep(2)
        else:
            missing = [m for m in required if m not in _read(serial)]
            exit_reason = "timeout"
            raise AssertionError(
                f"timed out after {timeout_s}s; matched {matched}, missing {missing}")

        txt = _read(serial)
        if require_non_empty and not txt.strip():
            raise AssertionError("serial log is empty")

        print(f"[arm64-boot] PASS: all {len(required)} markers present, no forbidden marker",
              flush=True)
        return 0
    except AssertionError as e:
        print(f"[arm64-boot] FAIL ({exit_reason}): {e}", flush=True)
        tail = _read(serial).splitlines()[-40:]
        print("[arm64-boot] serial tail:", flush=True)
        for line in tail:
            print("  " + line, flush=True)
        return 1
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
