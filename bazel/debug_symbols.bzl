"""The Cerise `.build-id` debug-symbol store.

`cerise_debug_symbols` collects the UNSTRIPPED ELF of every binary that a boot
carries — kernel, phys (physload/physboot), the vDSO, and userspace
components/drivers/shared libs — into the standard hashed layout every symbol
tool already understands:

    .build-id/<xx>/<rest>.debug

where `<xx><rest>` is the lowercase-hex NT_GNU_BUILD_ID note of the ELF (emitted
by `-Wl,--build-id=sha1`, added to the kernel/phys links and — via
`fuchsia_link_args` — to every userspace link). gdb (`set
debug-file-directory`), lldb, `llvm-symbolizer`, `llvm-addr2line`, debuginfod
and //src/cerise/tools/symbolize all resolve an address to source by looking the
module's build-id up in this tree.

Because build-ids are content hashes only knowable after the link, the store is
materialised inside a build action (llvm-readelf reads the note); it cannot be
computed at analysis time.

Two kinds of input target are accepted uniformly:
  * a target exposing `CeriseUnstrippedInfo` (e.g. `fuchsia_stripped`) — its
    unstripped ELF is used (the staged/bootfs artifact is stripped, but
    `--strip-all` preserves the allocated build-id note, so the ids match);
  * any other target — its single DefaultInfo output ELF is used directly
    (kernel/phys/vdso rules already emit unstripped ELFs for their platform).

Outputs:
  * `<name>/` (directory)  — the `.build-id/xx/rest.debug` tree.
  * `<name>.manifest.json` — {build_id: staged_path} for every collected ELF,
    consumed by the //validation store-coverage test.
"""

CeriseUnstrippedInfo = provider(
    doc = "The unstripped ELF of a target whose staged/bootfs artifact is stripped.",
    fields = {
        "unstripped": "File: the unstripped ELF carrying the full symbol/debug data and the build-id note.",
    },
)

CeriseDebugSymbolsInfo = provider(
    doc = "A materialised .build-id debug-symbol store.",
    fields = {
        "store_dir": "File (directory): the store root, containing `.build-id/xx/rest.debug` " +
                     "plus a `manifest.json` ({build_id: staged_path}).",
    },
)

# (debugging, follow-up): store auto-discovery. Rather than a
# hand-maintained `binaries` list, a `cerise_debug_symbols(product = ...)` walks the
# product's whole dependency graph and collects the UNSTRIPPED ELF of every target
# that exposes CeriseUnstrippedInfo (every fuchsia_stripped userspace component,
# driver and shared lib staged into the bootfs). ProductBundleInfo keeps only staged
# `File`s, not the providers (assembly/providers.bzl), so this can only be done with
# an aspect over the graph — the note's recorded design.
CeriseUnstrippedCollectionInfo = provider(
    doc = "Transitive set of unstripped ELFs collected from a dep graph by the aspect.",
    fields = {
        "unstripped": "depset[File] of every CeriseUnstrippedInfo.unstripped reachable below this target.",
    },
)

def _collect_unstripped_aspect_impl(_target, ctx):
    direct = []
    if CeriseUnstrippedInfo in _target:
        direct.append(_target[CeriseUnstrippedInfo].unstripped)

    # Walk every dependency attribute (attr_aspects = ["*"]) and union the
    # collections the aspect already produced on them. Scanning ctx.rule.attr is the
    # standard "propagate along all edges" idiom: each value is a Target or a list of
    # Targets (other attr types are ignored).
    transitive = []
    for attr_name in dir(ctx.rule.attr):
        value = getattr(ctx.rule.attr, attr_name)
        candidates = value if type(value) == "list" else [value]
        for dep in candidates:
            if type(dep) == "Target" and CeriseUnstrippedCollectionInfo in dep:
                transitive.append(dep[CeriseUnstrippedCollectionInfo].unstripped)

    return [CeriseUnstrippedCollectionInfo(
        unstripped = depset(direct = direct, transitive = transitive),
    )]

_collect_unstripped_aspect = aspect(
    implementation = _collect_unstripped_aspect_impl,
    attr_aspects = ["*"],
    doc = "Collects the unstripped ELF of every CeriseUnstrippedInfo target in a graph.",
)

# Non-ELF companion outputs some binary rules also emit (generated headers, dep
# files, maps, manifests). Filtered out so a rule that returns "the ELF + some
# headers" (e.g. the vDSO, which also emits vdso-code.h) still resolves to one ELF.
_NON_ELF_SUFFIXES = [".h", ".json", ".txt", ".d", ".map", ".bindbc", ".cm", ".cml", ".rsp"]

def _is_elf_candidate(f):
    for suffix in _NON_ELF_SUFFIXES:
        if f.basename.endswith(suffix):
            return False
    return True

def _elf_of(target):
    """The unstripped ELF File to collect for a store input target."""
    if CeriseUnstrippedInfo in target:
        return target[CeriseUnstrippedInfo].unstripped
    files = target[DefaultInfo].files.to_list()
    elves = [f for f in files if _is_elf_candidate(f)]
    if len(elves) != 1:
        fail(("cerise_debug_symbols: %s produces %d ELF-candidate file(s) " +
              "(of %d total); expected exactly one. Wrap it (fuchsia_stripped/" +
              "fuchsia_artifact) or expose CeriseUnstrippedInfo so a single ELF " +
              "is surfaced. Candidates: %s") %
             (target.label, len(elves), len(files), [f.basename for f in elves]))
    return elves[0]

def _cerise_debug_symbols_impl(ctx):
    # Explicit list (kernel/phys/vdso, or the whole smoke set): one ELF per target.
    elves = [_elf_of(t) for t in ctx.attr.binaries]

    # Auto-discovered userspace: the aspect walked `product`'s dep graph and
    # collected every fuchsia_stripped target's unstripped ELF. `binaries` and
    # `product` compose — a rich store names the product (userspace auto) PLUS the
    # kernel/phys/vdso in `binaries` (those ELF targets are not in the product graph;
    # only the assembled kernel/physload ZBIs are).
    product_elves = []
    if ctx.attr.product:
        product_elves = ctx.attr.product[CeriseUnstrippedCollectionInfo].unstripped.to_list()

    all_elves = elves + product_elves

    store = ctx.actions.declare_directory(ctx.label.name)

    args = ctx.actions.args()
    args.add(ctx.executable._readelf.path)
    args.add(store.path)
    args.add_all([e.path for e in all_elves])

    ctx.actions.run_shell(
        outputs = [store],
        inputs = all_elves,
        tools = [ctx.executable._readelf],
        arguments = [args],
        mnemonic = "CeriseBuildIdStore",
        progress_message = "Building .build-id store %s (%d ELFs)" % (ctx.label.name, len(all_elves)),
        command = _STORE_SH,
    )

    return [
        DefaultInfo(files = depset([store])),
        CeriseDebugSymbolsInfo(store_dir = store),
    ]

# Portable POSIX-sh store builder. $1 readelf, $2 store dir, $3.. ELFs.
# The store dir contains a real `.build-id/` subtree, so `set debug-file-directory
# <store>` works in gdb/lldb unchanged, and //src/cerise/tools/symbolize is pointed
# at `<store>/.build-id`. A `manifest.json` ({build_id: relpath}) is written at the
# store root for the coverage gate; its paths are relative to the store dir.
_STORE_SH = r"""
set -eu
readelf="$1"; store="$2"; shift 2
mkdir -p "$store/.build-id"
manifest="$store/manifest.json"
printf '{\n' > "$manifest"
first=1
for elf in "$@"; do
  # NT_GNU_BUILD_ID note -> lowercase hex, no separators.
  id="$("$readelf" -n "$elf" 2>/dev/null \
        | sed -n 's/.*Build ID: *\([0-9a-fA-F][0-9a-fA-F]*\).*/\1/p' \
        | head -n1 | tr 'A-F' 'a-f')"
  if [ -z "$id" ]; then
    echo "cerise_debug_symbols: $elf has no NT_GNU_BUILD_ID note (was it linked with --build-id=sha1?)" >&2
    exit 1
  fi
  xx="$(printf '%s' "$id" | cut -c1-2)"
  rest="$(printf '%s' "$id" | cut -c3-)"
  mkdir -p "$store/.build-id/$xx"
  cp -f "$elf" "$store/.build-id/$xx/$rest.debug"
  if [ "$first" = 1 ]; then first=0; else printf ',\n' >> "$manifest"; fi
  printf '  "%s": ".build-id/%s/%s.debug"' "$id" "$xx" "$rest" >> "$manifest"
done
printf '\n}\n' >> "$manifest"
"""

cerise_debug_symbols = rule(
    implementation = _cerise_debug_symbols_impl,
    attrs = {
        "binaries": attr.label_list(
            allow_files = True,
            doc = "Targets whose unstripped ELF is collected into the store. Each must " +
                  "produce exactly one ELF for its own platform, or expose " +
                  "CeriseUnstrippedInfo (e.g. fuchsia_stripped). Kernel/phys/vdso rules " +
                  "already emit a single unstripped ELF; wrap fuchsia userspace binaries " +
                  "via fuchsia_stripped/fuchsia_artifact so they are built for the " +
                  "fuchsia target before collection.",
        ),
        "product": attr.label(
            mandatory = False,
            aspects = [_collect_unstripped_aspect],
            doc = "Optional cerise_product (or any target): the aspect walks its whole " +
                  "dep graph and adds the unstripped ELF of every CeriseUnstrippedInfo " +
                  "target (all staged userspace components/drivers/libs) to the store — " +
                  "no hand-maintained list. Composes with `binaries` (use `binaries` for " +
                  "the kernel/phys/vdso ELF targets, which are not in the product graph).",
        ),
        "_readelf": attr.label(
            default = "//toolchain:llvm_readelf",
            cfg = "exec",
            executable = True,
            allow_single_file = True,
        ),
    },
    provides = [CeriseDebugSymbolsInfo],
    doc = "Collect the unstripped ELFs of a product's binaries into a .build-id store.",
)
