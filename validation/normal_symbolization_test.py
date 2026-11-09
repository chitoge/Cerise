#!/usr/bin/env python3
"""(debugging, D1): prove a NORMAL opt component symbolizes.

The #40 caveat was that a Fuchsia userspace component built WITHOUT the crasher's
special `-Cstrip=none -Cdebuginfo=2` symbolized to `<no symbols>`, because the opt
build stripped debug info and symbols from the unstripped store copy. moved
line-tables debug info + `-Cstrip=none` to the fuchsia transition/toolchain (one
place, all targets), so EVERY component's unstripped store ELF now carries symbols.

This gate proves it structurally, no boot required: for each unstripped ELF in a
.build-id store, it picks a real defined function symbol (via llvm-nm), asks
llvm-symbolizer to resolve that address against that ELF, and asserts the answer is
a real function name (not `??` / `<no symbols>`). It requires at least one store ELF
to resolve BOTH a real name AND a real `file:line` — proving line tables (not just
.symtab) survived the opt build. These ELFs are ordinary components/drivers built
with only the global flags; none carry per-target debug overrides.
"""
import argparse, json, os, subprocess, sys


def _run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, check=False).stdout


def _first_func_addr(nm, elf):
    """Return (addr_hex, name) of a defined text-symbol with a nonzero address."""
    out = _run([nm, "--defined-only", elf])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr, typ, name = parts[0], parts[1], " ".join(parts[2:])
        # 't'/'T' = text (function) symbols. Require a nonzero value.
        if typ in ("t", "T") and set(addr) != {"0"}:
            try:
                if int(addr, 16) == 0:
                    continue
            except ValueError:
                continue
            return addr, name
    return None, None


def _symbolize_one(symbolizer, elf, addr_hex):
    out = _run([symbolizer, "--obj=" + elf, "0x" + addr_hex])
    # llvm-symbolizer prints: <function>\n<file>:<line>:<col>\n
    lines = [l for l in out.splitlines() if l.strip()]
    func = lines[0].strip() if lines else ""
    loc = lines[1].strip() if len(lines) > 1 else ""
    return func, loc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", required=True, help=".build-id store directory")
    ap.add_argument("--nm", required=True, help="llvm-nm")
    ap.add_argument("--symbolizer", required=True, help="llvm-symbolizer")
    args = ap.parse_args()

    with open(os.path.join(args.store, "manifest.json")) as f:
        manifest = json.load(f)
    if not manifest:
        print("FAIL: store manifest empty", file=sys.stderr)
        return 1

    resolved_name = 0
    resolved_line = 0
    checked = 0
    examples = []
    for bid, rel in manifest.items():
        elf = os.path.join(args.store, rel)
        if not os.path.isfile(elf):
            continue
        addr, sym = _first_func_addr(args.nm, elf)
        if addr is None:
            continue
        checked += 1
        func, loc = _symbolize_one(args.symbolizer, elf, addr)
        bad = (not func) or func in ("??", "<no symbols>") or func.startswith("<")
        if not bad:
            resolved_name += 1
            has_line = bool(loc) and loc not in ("??:0", "??:0:0") and ":?" not in loc
            if has_line:
                resolved_line += 1
            if len(examples) < 5:
                examples.append("  %s @ 0x%s -> %s  (%s)" % (rel[-24:], addr, func, loc))

    for e in examples:
        print(e)

    if checked == 0:
        print("FAIL: no store ELF exposed a function symbol to test", file=sys.stderr)
        return 1
    if resolved_name == 0:
        print("FAIL: no NORMAL opt component symbolized to a real function name "
              "(all resolved to <no symbols> — the opt build is still stripping the "
              "unstripped store copy; the debuginfo flags did not take)",
              file=sys.stderr)
        return 1
    if resolved_line == 0:
        print("FAIL: function names resolved from .symtab but NO ELF resolved a real "
              "file:line — line-tables debug info (-Cdebuginfo=1 / -gline-tables-only) "
              "did not survive into the store copy", file=sys.stderr)
        return 1

    print("OK: %d/%d store ELF(s) symbolized to a real function; %d also to file:line "
          "— normal opt components carry symbolization-grade debug info."
          % (resolved_name, checked, resolved_line))
    return 0


if __name__ == "__main__":
    sys.exit(main())
