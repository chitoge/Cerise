#!/usr/bin/env python3
"""Structural gate: every leaf DFv2 driver .so exports ONLY its registration symbol.

A DFv2 driver .so is dlopen'd
into a driver_host, which resolves exactly one exported symbol from it —
`__fuchsia_driver_registration__` (the FUCHSIA_DRIVER_EXPORT2-placed const the
in-process loader `dlsym`s, see src/cerise/dfv2_inproc_loader/loader.cc). Nothing
binds against any OTHER symbol a driver defines. So every leaf driver .so is built
with a linker version-script (`{ global: __fuchsia_driver_registration__; local: *; }`)
that hides everything else, collapsing its `.dynsym`/`.dynstr` to a handful of KB
(the residue is UND imports, which a version-script cannot remove).

This gate parses the actual STORAGE_BOOTFS of a built ZBI (reusing
assembly/tools/bootfs_diff.py) and fails if any staged driver .so that exports
`__fuchsia_driver_registration__` also exports ANYTHING ELSE — i.e. its
version-script regressed to export-everything (`-rdynamic`/`--export-dynamic`),
which is what re-inflates `.dynstr` into the tens of MB (platform-bus.so ships
202k exports / 30.9 MB `.dynstr` today — see ALLOWLIST).

It asserts a SYMBOL invariant (exactly `__fuchsia_driver_registration__`), not a
byte threshold, so it is robust to UND-import drift as drivers change.

ALLOWLIST (driver .so's whose exported surface is intentionally larger than the
lone registration symbol):
  * pkg/*/lib/platform-bus.so — the DFv2 root driver still built `--export-dynamic`
    (202k exports, 30.9 MB .dynstr). Trimming it is the deferred "30 MB prize"
    because it is the everything-exporting host end of the
    host<->driver dynamic binding, out of scope for the leaf-driver diet. Listed
    so a future trim tightens this gate rather than being blocked by it.
  * pkg/*/lib/compat.so — the DFv1 compat shim exports a small CURATED ABI
    (`device_add_from_driver`, `get_*_resource`, driver_log*, ~29 symbols; see
    src/upstream/fuchsia/src/devices/misc/drivers/compat/compat.ld) that the
    legacy .so's it hosts bind against. Intentional, not export-everything.

Drivers that register via the DFv1 `__zircon_driver_rec__`/`__zircon_driver_note__`
pair (bus-pci.so, platform-bus-x86.so) do NOT export `__fuchsia_driver_registration__`
and so are outside this gate's selection; they carry their own version-scripts.
"""
import argparse
import importlib.util
import struct
import sys

REGISTRATION_SYMBOL = "__fuchsia_driver_registration__"

# .so basenames whose exported surface is intentionally larger than {registration}.
ALLOWLIST_BASENAMES = ("platform-bus.so", "compat.so")


def load_bootfs_diff(path):
    spec = importlib.util.spec_from_file_location("bootfs_diff", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def exported_dyn_globals(data):
    """Return the sorted list of GLOBAL/WEAK *defined* dynamic-symbol names of an
    ELF64, or None if it is not an ELF64 with a .dynsym/.dynstr."""
    if data[:4] != b"\x7fELF" or len(data) < 64 or data[4] != 2:  # ELFCLASS64
        return None
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if e_shoff == 0 or e_shnum == 0:
        return None
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        if o + e_shentsize > len(data):
            return None
        sh_name, sh_type, _fl, _ad, sh_off, sh_size, _lk, _in, _al, sh_ent = \
            struct.unpack_from("<IIQQQQIIQQ", data, o)
        secs.append((sh_name, sh_type, sh_off, sh_size, sh_ent))
    shstr_off = secs[e_shstrndx][2]

    def cstr(base, n):
        end = data.index(b"\0", base + n)
        return data[base + n:end].decode("utf-8", "replace")

    dynsym = dynstr_off = None
    for sh_name, sh_type, sh_off, sh_size, sh_ent in secs:
        nm = cstr(shstr_off, sh_name)
        if nm == ".dynsym":
            dynsym = (sh_off, sh_size, sh_ent)
        elif nm == ".dynstr":
            dynstr_off = sh_off
    if not dynsym or dynstr_off is None or dynsym[2] == 0:
        return None

    off, size, ent = dynsym
    out = []
    for i in range(size // ent):
        so = off + i * ent
        st_name, st_info, _oth, st_shndx, _val, _sz = struct.unpack_from(
            "<IBBHQQ", data, so)
        if st_shndx == 0:  # SHN_UNDEF -> an import, not an export
            continue
        bind = st_info >> 4
        if bind in (1, 2):  # STB_GLOBAL, STB_WEAK
            out.append(cstr(dynstr_off, st_name))
    return sorted(out)


def allowlisted(name):
    return name.rsplit("/", 1)[-1] in ALLOWLIST_BASENAMES


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

    checked = []
    allowed = []
    offenders = []
    for item_type, payload in bd.iter_items(bd.read_container_payload(args.zbi)):
        if item_type != bd.ZBI_TYPE_STORAGE_BOOTFS:
            continue
        entries = bd.parse_bootfs(payload)
        if entries is None:
            continue
        for name, data in entries:
            data = bytes(data)
            exports = exported_dyn_globals(data)
            if exports is None or REGISTRATION_SYMBOL not in exports:
                continue
            if allowlisted(name):
                allowed.append((name, len(exports)))
                continue
            if exports == [REGISTRATION_SYMBOL]:
                checked.append(name)
            else:
                extra = [s for s in exports if s != REGISTRATION_SYMBOL]
                offenders.append((name, extra))

    for name in sorted(checked):
        print("  OK (exports only %s): %s" % (REGISTRATION_SYMBOL, name))
    for name, n in sorted(allowed):
        print("  allowlisted (curated/host export surface, %d exports): %s" % (n, name))

    if not checked:
        print("\nFAIL: no leaf driver .so exporting %s was found in %s — the gate "
              "selected nothing (parser or ZBI-layout regression)."
              % (REGISTRATION_SYMBOL, args.zbi))
        return 1

    if offenders:
        print("\nFAIL: %d driver .so(s) export more than %s (version-script "
              "regressed to export-everything, re-inflating .dynstr):"
              % (len(offenders), REGISTRATION_SYMBOL))
        for name, extra in sorted(offenders):
            print("  %s  (+%d extra exports, e.g. %s)"
                  % (name, len(extra), ", ".join(extra[:5])))
        return 1

    print("\nOK: all %d leaf driver .so(s) export only %s"
          % (len(checked), REGISTRATION_SYMBOL))
    return 0


if __name__ == "__main__":
    sys.exit(main())
