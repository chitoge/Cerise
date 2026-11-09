#!/usr/bin/env python3
"""Emit a Cerise A/B \\abr slot-metadata record (the 16-byte simplified ABR).

This is the SAME 16-byte little-endian layout the boot shim reads/writes
(zircon/kernel/phys/boot-shim/efi-boot-shim.cc) and the in-OS updater writes
(src/cerise/ota_updater). Kept in one place so the shim, the updater, and the
validation harness agree byte-for-byte.

Layout:
  off 0  magic[4]      = b"CABR"
  off 4  version u8    = 1
  off 5  active u8     0 = slot A, 1 = slot B
  off 6  tries[A] u8
  off 7  tries[B] u8
  off 8  successful[A] u8   (0/1)
  off 9  successful[B] u8   (0/1)
  off 10 reserved[6]   zero

No CRC: a torn/corrupt record fails the shim's magic/version check and is
treated as absent (safe single-slot fallback).
"""
import argparse
import sys

MAGIC = b"CABR"
VERSION = 1


def build(active, tries_a, succ_a, tries_b, succ_b):
    slot = {"A": 0, "B": 1}[active.upper()]
    rec = bytearray(16)
    rec[0:4] = MAGIC
    rec[4] = VERSION
    rec[5] = slot
    rec[6] = tries_a & 0xFF
    rec[7] = tries_b & 0xFF
    rec[8] = 1 if succ_a else 0
    rec[9] = 1 if succ_b else 0
    # rec[10:16] left zero (reserved).
    return bytes(rec)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--active", required=True, choices=["A", "B", "a", "b"])
    ap.add_argument("--tries-a", type=int, default=0)
    ap.add_argument("--tries-b", type=int, default=0)
    ap.add_argument("--succ-a", type=int, default=0, choices=[0, 1])
    ap.add_argument("--succ-b", type=int, default=0, choices=[0, 1])
    ap.add_argument("--out", required=True)
    ns = ap.parse_args()
    rec = build(ns.active, ns.tries_a, ns.succ_a, ns.tries_b, ns.succ_b)
    assert len(rec) == 16
    with open(ns.out, "wb") as f:
        f.write(rec)
    return 0


if __name__ == "__main__":
    sys.exit(main())
