#!/usr/bin/env python3
"""Structural gate: no staged bootfs ELF ships a non-allocated symbol table.

Every ELF staged into the product bootfs is
supposed to go through `fuchsia_stripped` (objcopy --strip-all), which removes
the non-allocated .symtab/.strtab while KEEPING the allocated .dynsym/.dynstr
(so dlopen/-rdynamic/the DFv2 loader still work). Before this task,
platform-bus-x86.so shipped fully unstripped (162 MB, 91.5 MB of .symtab) and
libc.so/libc++.so.1/the libm stub were staged via `fuchsia_artifact` (no strip)
— all of them carried a .symtab. This gate parses the actual STORAGE_BOOTFS of a
built ZBI (reusing assembly/tools/bootfs_diff.py) and fails if any staged ELF
still carries an SHT_SYMTAB section.

ALLOWLIST: `bin/userboot*` — the userboot payload is built by the Zircon x64-user
toolchain (not the fuchsia target), is outside the fuchsia_stripped staging path,
is a protected-golden artifact (debugging-status.md), and is ~4 KB. Its own
build-id handling is a separate debugging follow-up.
"""
import argparse
import importlib.util
import struct
import sys

# Paths (relative to bootfs root) whose ELFs are permitted to keep a .symtab.
ALLOWLIST_PREFIXES = ("bin/userboot",)


def load_bootfs_diff(path):
    spec = importlib.util.spec_from_file_location("bootfs_diff", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def has_symtab(data):
    """Return True iff `data` is an ELF64 carrying an SHT_SYMTAB section."""
    if data[:4] != b"\x7fELF" or len(data) < 64 or data[4] != 2:  # ELFCLASS64
        return False
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    if e_shoff == 0 or e_shnum == 0:
        return False
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + 8 > len(data):
            return False
        if struct.unpack_from("<I", data, off + 4)[0] == 2:  # SHT_SYMTAB
            return True
    return False


def is_elf(data):
    return data[:4] == b"\x7fELF"


def allowlisted(name):
    return any(name.startswith(p) for p in ALLOWLIST_PREFIXES)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zbi", required=True)
    ap.add_argument("--bootfs-diff", required=True)
    ap.add_argument("--zstd-tool", default=None,
                    help="Host zstd CLI to decompress a compressed STORAGE_BOOTFS "
                         "(x86_64 products) so its ELFs are scanned.")
    args = ap.parse_args()

    bd = load_bootfs_diff(args.bootfs_diff)
    if args.zstd_tool:
        bd.ZSTD_CLI = args.zstd_tool

    elf_count = 0
    offenders = []
    allowed = []
    for item_type, payload in bd.iter_items(bd.read_container_payload(args.zbi)):
        if item_type != bd.ZBI_TYPE_STORAGE_BOOTFS:
            continue
        entries = bd.parse_bootfs(payload)
        if entries is None:
            continue
        for name, data in entries:
            data = bytes(data)
            if not is_elf(data):
                continue
            elf_count += 1
            if has_symtab(data):
                (allowed if allowlisted(name) else offenders).append((name, len(data)))

    print("scanned %d staged ELF(s) in %s" % (elf_count, args.zbi))
    for name, size in sorted(allowed):
        print("  allowlisted (kept .symtab): %s (%d bytes)" % (name, size))
    if offenders:
        print("\nFAIL: %d staged ELF(s) carry a .symtab (should be fuchsia_stripped):"
              % len(offenders))
        for name, size in sorted(offenders):
            print("  %10d  %s" % (size, name))
        return 1
    print("OK: no staged bootfs ELF carries .symtab (outside the userboot allowlist)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
