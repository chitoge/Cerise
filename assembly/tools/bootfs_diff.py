#!/usr/bin/env python3
"""List or diff the STORAGE_BOOTFS contents of ZBI images.

A general bootfs-equivalence tool: compare two ZBIs by every bootfs entry
(path -> content hash), independent of item ordering. Its original job — proving
each cerise_product ZBI bootfs-equivalent to the legacy zircon_system proof-gate
image it re-expressed — is done, and the duplicated product list has been retired.
It stays in-tree for any future equivalence check: a refactor's before/after,
a third-party board's re-expression, or confirming a product's dormant-superset
delta over a reference image.

  list  <zbi>                  print "sha256  size  path" for every bootfs entry
  diff  <zbi_a> <zbi_b>        print entries only-in-A, only-in-B, and content
                               mismatches; exit non-zero if any difference

Parses STORAGE_BOOTFS items in the format tools/zbi/simple_zbi.py emits. A
zstd-compressed STORAGE_BOOTFS payload (ZBI_FLAGS_STORAGE_COMPRESSED, i.e. a zstd
frame — x86_64 products) is transparently decompressed before
parsing WHEN a host zstd CLI is available: set the module global ZSTD_CLI (or the
$ZSTD_CLI env var) to //tools/zstd:zstd_cli, or pass --zstd-tool. Without a tool,
a compressed payload is reported and skipped.
"""

import argparse
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

ZBI_ALIGNMENT = 8
ZBI_CONTAINER_MAGIC = 0x868CF7E6
ZBI_ITEM_MAGIC = 0xB5781729
ZBI_ITEM_NO_CRC32 = 0x4A87E8D6
ZBI_FLAGS_VERSION = 1 << 16
ZBI_TYPE_CONTAINER = 0x544F4F42
ZBI_TYPE_STORAGE_BOOTFS = 0x42534642
ZBI_BOOTFS_MAGIC = 0xA56D3FF9
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# Path to the host zstd CLI (//tools/zstd:zstd_cli) used to decompress a
# compressed STORAGE_BOOTFS before parsing. Defaults to $ZSTD_CLI; callers that
# import this module may set it directly, or override via --zstd-tool.
ZSTD_CLI = os.environ.get("ZSTD_CLI")


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def zstd_decompress(frame):
    """Decompress a zstd frame via ZSTD_CLI. Returns None if no tool is set."""
    if not ZSTD_CLI:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "in.zst")
        dst = os.path.join(tmp, "out")
        with open(src, "wb") as f:
            f.write(frame)
        subprocess.run([ZSTD_CLI, "decompress", src, dst], check=True)
        with open(dst, "rb") as f:
            return f.read()


def read_container_payload(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 32:
        raise ValueError("%s: too small for ZBI container" % path)
    item_type, payload_length, extra = struct.unpack_from("<III", data, 0)
    if item_type != ZBI_TYPE_CONTAINER or extra != ZBI_CONTAINER_MAGIC:
        raise ValueError("%s: expected ZBI container header" % path)
    payload_end = 32 + align(payload_length, ZBI_ALIGNMENT)
    return data[32:payload_end]


def iter_items(blob):
    off, n = 0, len(blob)
    while off + 32 <= n:
        item_type, plen = struct.unpack_from("<II", blob, off)
        total = 32 + align(plen, ZBI_ALIGNMENT)
        yield item_type, blob[off + 32:off + 32 + plen]
        off += total


def parse_bootfs(payload):
    entries = []
    # A compressed STORAGE_BOOTFS payload is a zstd frame; decompress it first
    # (transparently) when a host zstd CLI is configured.
    if payload[:4] == ZSTD_MAGIC:
        payload = zstd_decompress(payload)
        if payload is None:
            return None  # compressed but no zstd tool available -> skip
    if len(payload) < 16 or struct.unpack_from("<I", payload, 0)[0] != ZBI_BOOTFS_MAGIC:
        return None  # not an uncompressed bootfs (empty or compressed)
    dir_size = struct.unpack_from("<I", payload, 4)[0]
    off, end = 16, 16 + dir_size
    while off + 12 <= end:
        namelen, dlen, doff = struct.unpack_from("<III", payload, off)
        name = payload[off + 12:off + 12 + namelen].split(b"\0")[0].decode("utf-8")
        entries.append((name, payload[doff:doff + dlen]))
        off += align(12 + namelen, 4)
    return entries


def bootfs_map(path):
    """Return {name: (sha256, size)} aggregated over all STORAGE_BOOTFS items."""
    result = {}
    skipped = 0
    for item_type, payload in iter_items(read_container_payload(path)):
        if item_type != ZBI_TYPE_STORAGE_BOOTFS:
            continue
        entries = parse_bootfs(payload)
        if entries is None:
            skipped += 1
            continue
        for name, data in entries:
            result[name] = (hashlib.sha256(data).hexdigest(), len(data))
    if skipped:
        sys.stderr.write(
            "note: %s: skipped %d compressed/unparseable STORAGE_BOOTFS item(s)\n"
            % (path, skipped))
    return result


def cmd_list(path):
    m = bootfs_map(path)
    for name in sorted(m):
        digest, size = m[name]
        print("%s  %10d  %s" % (digest, size, name))
    print("# %d bootfs entries" % len(m), file=sys.stderr)
    return 0


def cmd_diff(a, b):
    ma, mb = bootfs_map(a), bootfs_map(b)
    only_a = sorted(set(ma) - set(mb))
    only_b = sorted(set(mb) - set(ma))
    mismatch = sorted(k for k in set(ma) & set(mb) if ma[k][0] != mb[k][0])

    print("A = %s  (%d entries)" % (a, len(ma)))
    print("B = %s  (%d entries)" % (b, len(mb)))
    if only_a:
        print("\nonly in A (%d):" % len(only_a))
        for k in only_a:
            print("  + %s" % k)
    if only_b:
        print("\nonly in B (%d):" % len(only_b))
        for k in only_b:
            print("  - %s" % k)
    if mismatch:
        print("\ncontent differs (%d):" % len(mismatch))
        for k in mismatch:
            print("  ! %s  (A=%s… B=%s…)" % (k, ma[k][0][:12], mb[k][0][:12]))
    if not (only_a or only_b or mismatch):
        print("\nIDENTICAL: bootfs contents match exactly.")
        return 0
    print("\nDIFFERENT: %d only-in-A, %d only-in-B, %d content mismatch."
          % (len(only_a), len(only_b), len(mismatch)))
    return 1


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--zstd-tool", default=None,
                   help="Host zstd CLI (//tools/zstd:zstd_cli) to decompress "
                        "compressed STORAGE_BOOTFS payloads (default: $ZSTD_CLI).")
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("list")
    pl.add_argument("zbi")
    pd = sub.add_parser("diff")
    pd.add_argument("zbi_a")
    pd.add_argument("zbi_b")
    args = p.parse_args()
    if args.zstd_tool:
        global ZSTD_CLI
        ZSTD_CLI = args.zstd_tool
    if args.cmd == "list":
        return cmd_list(args.zbi)
    return cmd_diff(args.zbi_a, args.zbi_b)


if __name__ == "__main__":
    sys.exit(main())
