#!/usr/bin/env python3
"""Store-coverage + integrity gate for the .build-id debug-symbol store.

Enforces the design invariants:

  1. Integrity — every ELF materialised at .build-id/<xx>/<rest>.debug actually
     carries the NT_GNU_BUILD_ID note <xx><rest> (via llvm-readelf), and every
     manifest entry points at a file present in the store.
  2. Non-empty — the smoke store carries at least the four modules a smoke boot
     symbolizes (physload, physboot, vmzircon, libzircon).
  3. Coverage — every ELF STORAGE_BOOTFS entry of the product ZBI that carries a
     build-id note has that id present in the store (store completeness — the
     real gate for products that stage drivers/components). Bootfs ELFs with NO
     build-id note are the freestanding userboot payload (linked by the Zircon
     x64-user toolchain, outside the fuchsia build-id policy this store keys on);
     they are WARNED about, not failed, so the gate does not depend on the
     protected x64_user flag-manifest golden. Giving link.user a build-id (and
     regenerating that golden) is a clean follow-up.

stdlib-only; reuses assembly/tools/bootfs_diff.py's STORAGE_BOOTFS parser.
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys

ELF_MAGIC = b"\x7fELF"

# A GNU build-id note: namesz=4, descsz=20, type=NT_GNU_BUILD_ID(3), name="GNU\0",
# desc = the 20-byte sha1. Search the raw ELF for this fixed prefix.
_BUILD_ID_NOTE_PREFIX = (
    b"\x04\x00\x00\x00"  # namesz = 4
    b"\x14\x00\x00\x00"  # descsz = 20
    b"\x03\x00\x00\x00"  # type   = NT_GNU_BUILD_ID
    b"GNU\x00"
)


def build_id_from_bytes(blob):
    """Extract the sha1 build-id (lowercase hex) from raw ELF bytes, or None."""
    i = blob.find(_BUILD_ID_NOTE_PREFIX)
    if i < 0:
        return None
    desc = blob[i + len(_BUILD_ID_NOTE_PREFIX):i + len(_BUILD_ID_NOTE_PREFIX) + 20]
    if len(desc) != 20:
        return None
    return desc.hex()


def build_id_via_readelf(readelf, path):
    """Extract the build-id of an on-disk ELF via llvm-readelf -n."""
    # stdout=PIPE (not capture_output=) for python 3.6 remote-executor compat.
    out = subprocess.run(
        [readelf, "-n", path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True, check=False,
    ).stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Build ID:"):
            return line.split(":", 1)[1].strip().lower()
    return None


def load_bootfs_module(path):
    spec = importlib.util.spec_from_file_location("bootfs_diff", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", required=True, help=".build-id store directory")
    ap.add_argument("--zbi", required=True, help="product ZBI to check coverage against")
    ap.add_argument("--readelf", required=True, help="llvm-readelf")
    ap.add_argument("--bootfs-diff", required=True, help="assembly/tools/bootfs_diff.py")
    # (debugging, D2): a rich cerise_product ships a zstd-compressed
    # STORAGE_BOOTFS; pass the host zstd CLI so the staged ELFs are actually parsed
    # (and thus coverage is enforced), not skipped. Also allow raising the non-empty
    # floor: a rich product's aspect-built store must carry many more than 4 modules.
    ap.add_argument("--zstd-tool", default=None,
                    help="host zstd CLI to decompress a compressed STORAGE_BOOTFS")
    ap.add_argument("--min-entries", type=int, default=4,
                    help="minimum store entries expected (smoke=4; a rich product is higher)")
    args = ap.parse_args()

    failures = []

    with open(os.path.join(args.store, "manifest.json")) as f:
        manifest = json.load(f)  # {build_id: ".build-id/xx/rest.debug"}

    # 1. Integrity: manifest entries exist, and the on-disk ELF's real build-id
    #    matches both its manifest key and its store path.
    store_ids = set()
    for bid, rel in manifest.items():
        abspath = os.path.join(args.store, rel)
        if not os.path.isfile(abspath):
            failures.append("manifest id %s -> %s: file missing from store" % (bid, rel))
            continue
        actual = build_id_via_readelf(args.readelf, abspath)
        if actual != bid:
            failures.append(
                "store file %s carries build-id %s but is keyed as %s" % (rel, actual, bid))
        expect_rel = ".build-id/%s/%s.debug" % (bid[:2], bid[2:])
        if rel != expect_rel:
            failures.append("id %s stored at %s, expected %s" % (bid, rel, expect_rel))
        store_ids.add(bid)

    # 2. Non-empty: at least the expected floor of modules.
    if len(store_ids) < args.min_entries:
        failures.append(
            "store has %d entries; expected >= %d" % (len(store_ids), args.min_entries))

    # 3. Coverage: every ELF STORAGE_BOOTFS entry's build-id is in the store.
    bootfs_diff = load_bootfs_module(args.bootfs_diff)
    if args.zstd_tool:
        # bootfs_diff decompresses a zstd STORAGE_BOOTFS via this CLI (matches
        # no_unstripped_bootfs_elf_test); without it a compressed bootfs parses as
        # None and coverage is silently vacuous.
        bootfs_diff.ZSTD_CLI = args.zstd_tool
    checked_bootfs = 0
    no_note = []
    for item_type, payload in bootfs_diff.iter_items(
            bootfs_diff.read_container_payload(args.zbi)):
        if item_type != bootfs_diff.ZBI_TYPE_STORAGE_BOOTFS:
            continue
        entries = bootfs_diff.parse_bootfs(payload)
        if entries is None:
            continue
        for name, data in entries:
            if not data.startswith(ELF_MAGIC):
                continue
            checked_bootfs += 1
            bid = build_id_from_bytes(data)
            if bid is None:
                # Freestanding payload (userboot) outside the fuchsia build-id
                # policy — warn, do not fail (see module docstring).
                no_note.append(name)
            elif bid not in store_ids:
                failures.append(
                    "bootfs ELF %r build-id %s absent from the .build-id store" % (name, bid))

    for name in no_note:
        print("WARN: bootfs ELF %r has no build-id note (freestanding payload; "
              "not symbolizable via the store)" % name, file=sys.stderr)

    if failures:
        print("FAIL: .build-id store gate:", file=sys.stderr)
        for msg in failures:
            print("  - " + msg, file=sys.stderr)
        return 1

    print("OK: .build-id store integrity verified for %d store entries; "
          "%d bootfs ELF(s) covered." % (len(store_ids), checked_bootfs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
