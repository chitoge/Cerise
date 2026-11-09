"""Build a target under //platforms:x64-fuchsia, regardless of the parent config.

Products assemble bootfs from the default (exec) config; the dynamically-linked
Fuchsia userspace binaries (and libc.so) must be built for the fuchsia target.
fuchsia_artifact wraps a label with a platform transition so it is built for
x86_64-unknown-fuchsia, then re-exports its files for extra_bootfs.
"""

load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain", "use_cpp_toolchain")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("//assembly:providers.bzl", "ArtifactArchitectureInfo")
load("//bazel:debug_symbols.bzl", "CeriseUnstrippedInfo")

def _to_fuchsia_impl(settings, attr):
    # Force `opt` for every Fuchsia-target ELF
    # staged into a bootfs/ZBI. This is the single biggest size lever — the whole
    # userspace was -O0 fastbuild (no `compilation_mode` set here). `opt` covers
    # BOTH languages uniformly: rules_rust reads compilation_mode to pick rustc
    # opt-level, and the cc opt mode enables -DNDEBUG (the fuchsia cc toolchain's
    # `fuchsia_opt_size` feature then overrides the legacy -O2 with -Oz — see
    # toolchain/fuchsia/BUILD.bazel). Measured on cerise_pci_probe.so (C++):
    # -O0 ~50 MB .text; -c opt -O2 = 44.7 MB; -c opt -Oz = 14.2 MB (stripped
    # 61.5 -> 22.6 MB). Rust opt-level=z ~= default opt (negligible), so we let
    # compilation_mode=opt drive rustc and spend the size lever on cc -Oz.
    #
    # Scope: this transition is used ONLY by fuchsia_artifact/fuchsia_stripped/
    # fuchsia_link_sysroot (the bootfs-staging wrappers). The kernel/phys/efi/
    # x64-user (Zircon) toolchains have their OWN transitions and are untouched;
    # their flag-manifest goldens must not change. `--config=debug` (-c dbg) still
    # governs HOST tools — the fuchsia target is deliberately always opt now.
    #
    # (debugging, payoff): symbolization-grade DWARF on the
    # UNSTRIPPED store copy of every Fuchsia-target Rust binary, WITHOUT changing
    # the stripped bootfs copy's code/data. rules_rust's opt compilation_mode_opts
    # default is `debug_info=0, strip_level=debuginfo` (rustc `-Cdebuginfo=0
    # -Cstrip=debuginfo`) — the unstripped rust output then carries neither DWARF
    # nor (with strip=debuginfo dropping it in this toolchain) usable symbols, so
    # it symbolizes to `<no symbols>` (the #40 caveat). We append, ONLY for the
    # fuchsia target config, `-Cdebuginfo=1 -Cstrip=none` via the global
    # `extra_rustc_flags` setting: rules_rust adds it AFTER the compilation_mode
    # codegen flags, and rustc honors the last `-Cdebuginfo`/`-Cstrip`, so it wins.
    # The setting is applied in NON-exec config only (rules_rust guards it), so host
    # tools are untouched; the transition scopes it to fuchsia-target deps. We chose
    # `=1` (line-tables-only) over `=2`: it resolves function name + file:line for
    # every frame (the crash-handler gate asserts crasher::main, resolved from
    # .symtab + line tables) at a fraction of the store cost. `-Cstrip=none` keeps
    # .symtab so names resolve even where line tables are absent.
    #
    # This does NOT change the STAGED bootfs ELF's code/data: debug info never
    # alters codegen, and fuchsia_stripped --strip-all removes .debug_*/.symtab.
    # The one propagated side effect is the 20-byte NT_GNU_BUILD_ID note: LLD's
    # `--build-id=sha1` hashes the whole output incl. .debug_*, so adding DWARF
    # ROTATES the note. The staged copy therefore stays byte-identical EXCEPT that
    # note — ZBI size is unchanged, allocated content is unchanged, and the staged
    # and store copies still share one build-id (the property symbolization needs).
    # The cc side gets `-gline-tables-only` at the toolchain level (toolchain/
    # fuchsia/BUILD.bazel), the one-place cc analogue.
    return {
        "//command_line_option:platforms": "//platforms:x64-fuchsia",
        "//command_line_option:compilation_mode": "opt",
        "@rules_rust//rust/settings:extra_rustc_flags": ["-Cdebuginfo=1", "-Cstrip=none"],
    }

_to_fuchsia = transition(
    implementation = _to_fuchsia_impl,
    inputs = [],
    outputs = [
        "//command_line_option:platforms",
        "//command_line_option:compilation_mode",
        "@rules_rust//rust/settings:extra_rustc_flags",
    ],
)

def _fuchsia_artifact_impl(ctx):
    return [
        DefaultInfo(files = ctx.attr.src[0][DefaultInfo].files),
        ArtifactArchitectureInfo(arch = "x86_64", kind = "userspace"),
    ]

fuchsia_artifact = rule(
    implementation = _fuchsia_artifact_impl,
    attrs = {
        "src": attr.label(mandatory = True, cfg = _to_fuchsia),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    doc = "Re-exports `src` built for //platforms:x64-fuchsia.",
)

def _fuchsia_stripped_impl(ctx):
    # Strip debug info AND the non-allocated symbol tables (.symtab/.strtab) from a
    # Fuchsia-target binary before it is staged into a bootfs/ZBI. The DFv2 driver
    # binaries are cc_binary(-shared) / rust_binary(-rdynamic) that whole-archive the
    # framework+FIDL closure and carry a huge .symtab/.strtab; staging them unstripped
    # produced a ~585 MB ZBI that OOMs userboot at boot.
    #
    # We use `objcopy --strip-all`, NOT `--strip-debug`: in this tree the DWARF is
    # tiny (~1 MB) while .symtab/.strtab are tens of MB, so only --strip-all shrinks
    # meaningfully. Crucially, --strip-all on an ELF that has a .dynsym leaves the
    # ALLOCATED .dynsym/.dynstr intact, so:
    #   * the driver .so keeps __fuchsia_driver_registration__ exported (loader dlsym),
    #   * the -rdynamic driver host keeps its exported symbols (the dlopen'd driver
    #     binds its UND fdf/libc++/fuchsia_logging refs against them),
    #   * all UND imports stay UND.
    # i.e. the dynamic-linking behavior is byte-for-byte unchanged; only non-runtime
    # symbol/debug data is removed.
    srcs = ctx.attr.src[0][DefaultInfo].files.to_list()
    outs = []
    for src in srcs:
        out = ctx.actions.declare_file(ctx.label.name + "/" + src.basename)
        ctx.actions.run(
            outputs = [out],
            inputs = [src],
            executable = ctx.executable._objcopy,
            # also drop .debug_gdb_scripts — a small ALLOCATED (`AMS`)
            # section rustc emits whenever -Cdebuginfo>0 (now global via the fuchsia
            # transition) that --strip-all therefore keeps. It only names gdb
            # pretty-printer scripts; gdb consumes it from the UNSTRIPPED store copy,
            # so it is pure dead weight in the guest. Removing it keeps the staged
            # bootfs ELF byte-identical to a no-debuginfo build EXCEPT the rotated
            # 20-byte build-id note (LLD hashes .debug_* into --build-id=sha1).
            arguments = [
                "--strip-all",
                "--remove-section=.debug_gdb_scripts",
                src.path,
                out.path,
            ],
            mnemonic = "FuchsiaStrip",
            progress_message = "Stripping %s for bootfs" % src.short_path,
        )
        outs.append(out)
    providers = [
        DefaultInfo(files = depset(outs)),
        ArtifactArchitectureInfo(arch = "x86_64", kind = "userspace"),
    ]

    # Expose the UNSTRIPPED input ELF for the .build-id store (cerise_debug_symbols):
    # the staged `out` is --strip-all'd (no .symtab/DWARF) but keeps the allocated
    # build-id note, so `out` and `src` share a build-id — the store keys on that id
    # and serves the fully-symboled `src`. Only meaningful for single-ELF targets
    # (drivers/components/libs); a multi-file target carries no single unstripped ELF.
    if len(srcs) == 1:
        providers.append(CeriseUnstrippedInfo(unstripped = srcs[0]))
    return providers

fuchsia_stripped = rule(
    implementation = _fuchsia_stripped_impl,
    attrs = {
        "src": attr.label(mandatory = True, cfg = _to_fuchsia),
        # llvm-objcopy runs on the exec platform (it's a build tool). The cc
        # toolchain's objcopy_executable is empty in this tree, so depend on the
        # prebuilt LLVM objcopy alias directly.
        "_objcopy": attr.label(
            default = "//toolchain:linux_x86_64/bin/llvm-objcopy.prebuilt",
            cfg = "exec",
            executable = True,
            allow_single_file = True,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    doc = "Re-exports `src` built for //platforms:x64-fuchsia, with debug info and " +
          "non-allocated symbol tables stripped (objcopy --strip-all). The dynamic " +
          "symbol table (.dynsym/.dynstr) is preserved so dlsym/-rdynamic still work.",
)

def _to_cerise_impl(settings, attr):
    return {"//command_line_option:platforms": "//platforms:x64-user"}

_to_cerise = transition(
    implementation = _to_cerise_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _cerise_artifact_impl(ctx):
    return [
        DefaultInfo(files = ctx.attr.src[0][DefaultInfo].files),
        ArtifactArchitectureInfo(arch = "x86_64", kind = "userspace"),
    ]

cerise_artifact = rule(
    implementation = _cerise_artifact_impl,
    attrs = {
        "src": attr.label(mandatory = True, cfg = _to_cerise),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    doc = "Re-exports `src` built for //platforms:x64-user (Cerise userspace static PIE).",
)

# --- assemble a link sysroot for Fuchsia binaries ---
# rustc's fuchsia target spec emits `Scrt1.o -lc -lzircon -lfdio` for binary links;
# C++ binaries additionally need -lc++ -lm and libclang_rt.builtins.a.
# This rule builds a sysroot directory tree:
#   lib/Scrt1.o                                   - CRT startup
#   lib/libc.so, libzircon.so, ...                - shared libs
#   lib/clang/22/lib/x86_64-unknown-fuchsia/      - clang resource libs
#     libclang_rt.builtins.a
def _link_sysroot_impl(ctx):
    cc_toolchain = find_cpp_toolchain(ctx)
    out = ctx.actions.declare_directory(ctx.label.name)

    crt1_a = None
    for li in ctx.attr.crt1[0][CcInfo].linking_context.linker_inputs.to_list():
        for lib in li.libraries:
            a = lib.pic_static_library or lib.static_library
            if a:
                crt1_a = a
    if not crt1_a:
        fail("crt1 provides no static library")

    sos = [t[DefaultInfo].files.to_list()[0] for t in ctx.attr.shared_libs]

    # Gather static libs (e.g. libclang_rt.builtins.a) from the CcInfo of each
    # static_libs label. These go to the clang resource directory inside the sysroot.
    static_lib_files = []
    for dep in ctx.attr.static_libs:
        for li in dep[CcInfo].linking_context.linker_inputs.to_list():
            for lib in li.libraries:
                a = lib.pic_static_library or lib.static_library
                if a:
                    static_lib_files.append(a)

    cp_sos = " ".join([s.path for s in sos])
    cp_statics = " ".join([a.path for a in static_lib_files])

    # rustc's fuchsia spec force-links Scrt1.o as a pre-link object; ld reads the ar
    # magic and pulls crt1.o (which defines _start). Copying the archive as Scrt1.o
    # avoids needing an out-of-line `ar x` (the toolchain ar path isn't usable raw).
    #
    # libclang_rt.builtins.a goes at the path clang -resource-dir expects:
    #   lib/clang/<major>/lib/x86_64-unknown-fuchsia/libclang_rt.builtins.a
    # The LLVM version is 22; hardcoded here (matches our zr_llvm_toolchain).
    clang_rt_dir = "{out}/lib/clang/22/lib/x86_64-unknown-fuchsia".format(out = out.path)
    cp_statics_cmd = ""
    if static_lib_files:
        # compiler-rt builtins are compiled as libbuiltins.a (from cc_library name "builtins")
        # but clang auto-links them as libclang_rt.builtins.a from the resource dir.
        # Rename on copy so clang finds them at the expected path.
        rename_cmds = []
        for a in static_lib_files:
            dest_name = a.basename.replace("libbuiltins.a", "libclang_rt.builtins.a")
            rename_cmds.append("cp {src} {rt_dir}/{dest}".format(
                src = a.path, rt_dir = clang_rt_dir, dest = dest_name,
            ))
        cp_statics_cmd = "mkdir -p {rt_dir}; {cmds};".format(
            rt_dir = clang_rt_dir,
            cmds = "; ".join(rename_cmds),
        )

    cmd = (
        "set -e; mkdir -p {out}/lib; cp {sos} {out}/lib/; cp {crt1} {out}/lib/Scrt1.o; {cp_statics}"
    ).format(
        out = out.path,
        sos = cp_sos,
        crt1 = crt1_a.path,
        cp_statics = cp_statics_cmd,
    )
    ctx.actions.run_shell(
        outputs = [out],
        inputs = depset([crt1_a] + sos + static_lib_files),
        command = cmd,
        mnemonic = "FuchsiaLinkSysroot",
        progress_message = "Assembling Fuchsia link sysroot %s" % out.short_path,
    )
    return [DefaultInfo(files = depset([out]))]

fuchsia_link_sysroot = rule(
    implementation = _link_sysroot_impl,
    attrs = {
        "crt1": attr.label(mandatory = True, cfg = _to_fuchsia, providers = [CcInfo]),
        "shared_libs": attr.label_list(mandatory = True, cfg = _to_fuchsia),
        "static_libs": attr.label_list(
            default = [],
            cfg = _to_fuchsia,
            providers = [CcInfo],
            doc = "Static libs (e.g. libclang_rt.builtins.a) placed under lib/clang/22/lib/x86_64-unknown-fuchsia/.",
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    toolchains = use_cpp_toolchain(),
    doc = "Assembles a Fuchsia link sysroot (Scrt1.o + shared libs + compiler-rt) for fuchsia.",
)
