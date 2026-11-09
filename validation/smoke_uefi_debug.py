#!/usr/bin/env python3
"""(debugging, D3): UEFI/ESP-path gdb attach for the smoke boot.

The direct-kernel gates already have gdb attach parity via `validation/run-qemu.sh
--gdb`. The ESP path (rules_ostest `smoke-uefi-boot`) had no debug
variant. This MANUAL target boots the same smoke ESP disk under rules_ostest's own
gdb support (`gdb=True`) with the guest FROZEN at start (`pause_at_start` = QEMU
`-S`), then prints the gdbstub attach line + a ready gdb-init snippet (symbol-file
kernel ELF + `set debug-file-directory <store>` + `target remote`) and HOLDS the
guest for a human to attach — the ESP-path analogue of run-qemu.sh --gdb.

Run:  bazel run //validation:smoke-uefi-debug
Then in another shell: gdb -x <printed gdbinit>   (or follow the printed lines).
Hold time is CERISE_GDB_HOLD_SECONDS (default 1800); the frozen guest waits for a
gdb `continue`.
"""
from __future__ import annotations
import argparse, os, pathlib, sys, time

from ostest.python.qemu import QemuSession, UefiQemuConfig, add_uefi_qemu_arguments


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel-elf", default="", help="unstripped kernel ELF for symbol-file")
    parser.add_argument("--build-id-store", default="", help=".build-id store for debug-file-directory")
    add_uefi_qemu_arguments(parser)
    args = parser.parse_args()

    config = UefiQemuConfig.from_namespace(args)
    outdir = pathlib.Path(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR",
                                         os.environ.get("TEST_TMPDIR", ".")))
    outdir.mkdir(parents=True, exist_ok=True)
    hold_s = float(os.environ.get("CERISE_GDB_HOLD_SECONDS", "1800"))

    with QemuSession(config) as vm:
        host, port = vm.gdb_address
        gdbinit = outdir / "smoke-uefi-debug.gdbinit"
        lines = [
            "set pagination off",
            "set confirm off",
        ]
        if args.kernel_elf and os.path.exists(args.kernel_elf):
            lines.append("symbol-file %s" % os.path.abspath(args.kernel_elf))
        if args.build_id_store and os.path.isdir(args.build_id_store):
            lines.append("set debug-file-directory %s" % os.path.abspath(args.build_id_store))
        lines.append("target remote %s:%d" % (host, port))
        gdbinit.write_text("\n".join(lines) + "\n", encoding="utf-8")

        print("=" * 72, flush=True)
        print("[smoke-uefi-debug] ESP-path guest FROZEN at start; gdbstub listening.", flush=True)
        print("[smoke-uefi-debug] attach:  gdb -x %s" % gdbinit, flush=True)
        print("[smoke-uefi-debug]     or:  gdb -ex 'target remote %s:%d'" % (host, port), flush=True)
        print("[smoke-uefi-debug] holding %.0fs (override CERISE_GDB_HOLD_SECONDS)." % hold_s, flush=True)
        print("=" * 72, flush=True)

        deadline = time.time() + hold_s
        while time.time() < deadline:
            time.sleep(2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
