"""Starlark rules for Bazel-native phys binary packaging.

Physload, physboot, and boot_shim each link cc_library deps under a phys
platform transition, then post-process the ELF (objcopy) to produce the
final artifact.
"""

load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("//bazel:debug_symbols.bzl", "CeriseUnstrippedInfo")

# Provider to pass physload ELF between rules (needed by physboot interp step).
_PhysElfInfo = provider(
    doc = "Physload ELF file exposed for interp-object generation",
    fields = {"elf": "File: physload ELF"},
)

def _x64_phys_transition_impl(settings, attr):
    return {"//command_line_option:platforms": "//platforms:x64-phys"}

_x64_phys_transition = transition(
    implementation = _x64_phys_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _x86_32_phys_transition_impl(settings, attr):
    return {"//command_line_option:platforms": "//platforms:x86_32-phys"}

_x86_32_phys_transition = transition(
    implementation = _x86_32_phys_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _arm64_phys_transition_impl(settings, attr):
    return {"//command_line_option:platforms": "//platforms:arm64-phys"}

_arm64_phys_transition = transition(
    implementation = _arm64_phys_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _collect_static_libs(deps):
    seen = {}
    libs = []
    for dep in deps:
        if CcInfo in dep:
            for li in dep[CcInfo].linking_context.linker_inputs.to_list():
                for lib in li.libraries:
                    f = lib.static_library or lib.pic_static_library
                    if f and f.path not in seen:
                        seen[f.path] = True
                        libs.append(f)
    return libs

# ---------- physload -------------------------------------------------------
# Links cc_library deps for the x64-phys platform, then extracts ZBI binary.
# Also exposes the intermediate ELF via _PhysElfInfo for physboot interp use.

def _zircon_physload_impl(ctx):
    libs = _collect_static_libs(ctx.attr.deps)
    ld_scripts = ctx.files.linker_scripts

    elf = ctx.actions.declare_file(ctx.label.name + ".elf")

    args = ctx.actions.args()
    args.add("--pie")
    args.add("--no-dynamic-linker")
    args.add("--build-id")
    args.add("-z", "max-page-size=4096")
    args.add("-z", "start-stop-visibility=hidden")
    for ls in ld_scripts:
        args.add("-T", ls)
    args.add("-defsym=PHYS_LOAD_ADDRESS=0")
    args.add("-o", elf)
    args.add("--whole-archive")
    args.add_all(libs)
    args.add("--no-whole-archive")

    ctx.actions.run(
        outputs = [elf],
        inputs = depset(libs + ld_scripts),
        executable = ctx.executable._ld,
        arguments = [args],
        mnemonic = "PhysloadLink",
    )

    zbi = ctx.actions.declare_file(ctx.label.name + ".zbi")
    ctx.actions.run(
        outputs = [zbi],
        inputs = [elf],
        executable = ctx.executable._objcopy,
        arguments = ["-O", "binary", elf.path, zbi.path],
        mnemonic = "PhysloadZBI",
    )

    return [
        DefaultInfo(files = depset([zbi])),
        _PhysElfInfo(elf = elf),
        # Unstripped ELF (with symbols + build-id note) for the .build-id store
        # (cerise_debug_symbols); the DefaultInfo .zbi is a raw binary with no note.
        CeriseUnstrippedInfo(unstripped = elf),
    ]

zircon_physload = rule(
    implementation = _zircon_physload_impl,
    attrs = {
        "deps": attr.label_list(providers = [CcInfo], cfg = _x64_phys_transition),
        "linker_scripts": attr.label_list(allow_files = True, cfg = _x64_phys_transition),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
        "_objcopy": attr.label(
            default = "//toolchain:llvm_objcopy",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ---------- phys_build_id_interp -------------------------------------------
# Converts physload ELF build-ID to a .S + assembles to .o for physboot link.
# Uses elf_build_id_to_interp.py which embeds the build ID in PT_INTERP.

def _phys_build_id_interp_impl(ctx):
    physload_elf = ctx.attr.physload[_PhysElfInfo].elf

    interp_s = ctx.actions.declare_file(ctx.label.name + ".S")
    ctx.actions.run_shell(
        outputs = [interp_s],
        inputs = [physload_elf, ctx.file._script],
        command = "python3 {script} --input {elf} --output {out}".format(
            script = ctx.file._script.path,
            elf = physload_elf.path,
            out = interp_s.path,
        ),
        mnemonic = "PhysBuildIdInterp",
    )

    interp_o = ctx.actions.declare_file(ctx.label.name + ".o")
    ctx.actions.run(
        outputs = [interp_o],
        inputs = [interp_s],
        executable = ctx.executable._clang,
        arguments = ["--target=" + ctx.attr.target_triple, "-c", interp_s.path, "-o", interp_o.path],
        mnemonic = "PhysInterpAssemble",
    )

    return [DefaultInfo(files = depset([interp_o]))]

phys_build_id_interp = rule(
    implementation = _phys_build_id_interp_impl,
    attrs = {
        "physload": attr.label(providers = [_PhysElfInfo], mandatory = True),
        "target_triple": attr.string(default = "x86_64-unknown-linux-gnu"),
        "_script": attr.label(
            default = "//tools/zbi:elf_build_id_to_interp.py",
            allow_single_file = True,
        ),
        "_clang": attr.label(
            default = "//toolchain:prebuilt_clang",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ---------- physboot -------------------------------------------------------
# Links cc_library deps + interp .o into a shared-module ELF, then strips.

def _zircon_physboot_impl(ctx):
    libs = _collect_static_libs(ctx.attr.deps)
    interp_objects = ctx.files.interp_objects
    ld_scripts = ctx.files.linker_scripts

    elf = ctx.actions.declare_file(ctx.label.name + ".elf")

    args = ctx.actions.args()
    args.add("--shared")
    args.add("--build-id")
    args.add("--gc-sections")
    args.add("-z", "max-page-size=4096")
    args.add("-z", "start-stop-visibility=hidden")
    for ls in ld_scripts:
        args.add("-T", ls)
    args.add("--entry=PhysLoadHandoff")
    args.add("--export-dynamic-symbol=__cfi_check")
    args.add("-o", elf)
    args.add_all(interp_objects)
    args.add("--whole-archive")
    args.add_all(libs)
    args.add("--no-whole-archive")

    ctx.actions.run(
        outputs = [elf],
        inputs = depset(libs + interp_objects + ld_scripts),
        executable = ctx.executable._ld,
        arguments = [args],
        mnemonic = "PhysbootLink",
    )

    stripped = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run(
        outputs = [stripped],
        inputs = [elf],
        executable = ctx.executable._objcopy,
        arguments = ["--strip-sections", elf.path, stripped.path],
        mnemonic = "PhysbootStrip",
    )

    return [
        DefaultInfo(files = depset([stripped])),
        # Unstripped ELF (symbols + DWARF + build-id note) for the .build-id store;
        # the DefaultInfo output is --strip-sections'd for staging.
        CeriseUnstrippedInfo(unstripped = elf),
    ]

zircon_physboot = rule(
    implementation = _zircon_physboot_impl,
    attrs = {
        "deps": attr.label_list(providers = [CcInfo], cfg = _x64_phys_transition),
        "interp_objects": attr.label_list(allow_files = True),
        "linker_scripts": attr.label_list(allow_files = True, cfg = _x64_phys_transition),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
        "_objcopy": attr.label(
            default = "//toolchain:llvm_objcopy",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ---------- zircon_boot_shim_x64 ------------------------------------------
# Links a Linux x86-64 boot shim ELF and extracts raw binary.

def _zircon_boot_shim_x64_impl(ctx):
    libs = _collect_static_libs(ctx.attr.deps)
    ld_scripts = ctx.files.linker_scripts

    elf = ctx.actions.declare_file(ctx.label.name + ".elf")

    args = ctx.actions.args()
    args.add("-pie")
    args.add("--emit-relocs")
    args.add("--discard-none")
    args.add("--build-id=sha1")
    args.add("--gc-sections")
    args.add("-z", "start-stop-visibility=hidden")
    args.add("-z", "max-page-size=4096")
    for ls in ld_scripts:
        args.add("-T", ls)
    args.add("-o", elf)
    args.add("--whole-archive")
    args.add_all(libs)
    args.add("--no-whole-archive")

    ctx.actions.run(
        outputs = [elf],
        inputs = depset(libs + ld_scripts),
        executable = ctx.executable._ld,
        arguments = [args],
        mnemonic = "BootShimX64Link",
    )

    binary = ctx.actions.declare_file(ctx.label.name + ".bin")
    ctx.actions.run(
        outputs = [binary],
        inputs = [elf],
        executable = ctx.executable._objcopy,
        arguments = ["-O", "binary", elf.path, binary.path],
        mnemonic = "BootShimX64Extract",
    )

    return [DefaultInfo(files = depset([binary]))]

zircon_boot_shim_x64 = rule(
    implementation = _zircon_boot_shim_x64_impl,
    attrs = {
        "deps": attr.label_list(providers = [CcInfo], cfg = _x64_phys_transition),
        "linker_scripts": attr.label_list(allow_files = True, cfg = _x64_phys_transition),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
        "_objcopy": attr.label(
            default = "//toolchain:llvm_objcopy",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ---------- zircon_boot_shim_x86_32 ----------------------------------------
# Links a Linux x86-32 boot shim ELF and extracts raw binary.

def _zircon_boot_shim_x86_32_impl(ctx):
    libs = _collect_static_libs(ctx.attr.deps)
    ld_scripts = ctx.files.linker_scripts

    elf = ctx.actions.declare_file(ctx.label.name + ".elf")

    args = ctx.actions.args()
    args.add("-m", "elf_i386")
    args.add("--emit-relocs")
    args.add("--discard-none")
    args.add("--build-id=sha1")
    args.add("--gc-sections")
    args.add("-z", "start-stop-visibility=hidden")
    args.add("-z", "max-page-size=4096")
    for ls in ld_scripts:
        args.add("-T", ls)
    args.add("-o", elf)
    args.add("--whole-archive")
    args.add_all(libs)
    args.add("--no-whole-archive")

    ctx.actions.run(
        outputs = [elf],
        inputs = depset(libs + ld_scripts),
        executable = ctx.executable._ld,
        arguments = [args],
        mnemonic = "BootShimX8632Link",
    )

    binary = ctx.actions.declare_file(ctx.label.name + ".bin")
    ctx.actions.run(
        outputs = [binary],
        inputs = [elf],
        executable = ctx.executable._objcopy,
        arguments = ["-O", "binary", elf.path, binary.path],
        mnemonic = "BootShimX8632Extract",
    )

    return [DefaultInfo(files = depset([binary]))]

zircon_boot_shim_x86_32 = rule(
    implementation = _zircon_boot_shim_x86_32_impl,
    attrs = {
        "deps": attr.label_list(providers = [CcInfo], cfg = _x86_32_phys_transition),
        "linker_scripts": attr.label_list(allow_files = True, cfg = _x86_32_phys_transition),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
        "_objcopy": attr.label(
            default = "//toolchain:llvm_objcopy",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ---------- zircon_arm64_physload ------------------------------------------
# Links cc_library deps for the arm64-phys platform, extracts ZBI binary.

def _zircon_arm64_physload_impl(ctx):
    libs = _collect_static_libs(ctx.attr.deps)
    ld_scripts = ctx.files.linker_scripts

    elf = ctx.actions.declare_file(ctx.label.name + ".elf")

    args = ctx.actions.args()
    args.add("--pie")
    args.add("--no-dynamic-linker")
    args.add("--build-id")
    args.add("-z", "max-page-size=4096")
    args.add("-z", "start-stop-visibility=hidden")
    for ls in ld_scripts:
        args.add("-T", ls)
    args.add("-defsym=PHYS_LOAD_ADDRESS=0")
    args.add("-defsym=PHYS_GOT_LIMIT=32")  # ARM64 PIE uses R_AARCH64_RELATIV GOT entries
    args.add("-o", elf)
    args.add("--whole-archive")
    args.add_all(libs)
    args.add("--no-whole-archive")

    ctx.actions.run(
        outputs = [elf],
        inputs = depset(libs + ld_scripts),
        executable = ctx.executable._ld,
        arguments = [args],
        mnemonic = "Arm64PhysloadLink",
    )

    zbi = ctx.actions.declare_file(ctx.label.name + ".zbi")
    ctx.actions.run(
        outputs = [zbi],
        inputs = [elf],
        executable = ctx.executable._objcopy,
        arguments = ["-O", "binary", elf.path, zbi.path],
        mnemonic = "Arm64PhysloadZBI",
    )

    return [
        DefaultInfo(files = depset([zbi])),
        _PhysElfInfo(elf = elf),
        # Unstripped ELF (with symbols + build-id note) for the .build-id store
        # (cerise_debug_symbols); the DefaultInfo .zbi is a raw binary with no note.
        CeriseUnstrippedInfo(unstripped = elf),
    ]

zircon_arm64_physload = rule(
    implementation = _zircon_arm64_physload_impl,
    attrs = {
        "deps": attr.label_list(providers = [CcInfo], cfg = _arm64_phys_transition),
        "linker_scripts": attr.label_list(allow_files = True, cfg = _arm64_phys_transition),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
        "_objcopy": attr.label(
            default = "//toolchain:llvm_objcopy",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ---------- zircon_arm64_physboot ------------------------------------------

def _zircon_arm64_physboot_impl(ctx):
    libs = _collect_static_libs(ctx.attr.deps)
    interp_objects = ctx.files.interp_objects
    ld_scripts = ctx.files.linker_scripts

    elf = ctx.actions.declare_file(ctx.label.name + ".elf")

    args = ctx.actions.args()
    args.add("--shared")
    args.add("--build-id")
    args.add("--gc-sections")
    args.add("-z", "max-page-size=4096")
    args.add("-z", "start-stop-visibility=hidden")
    for ls in ld_scripts:
        args.add("-T", ls)
    args.add("--entry=PhysLoadHandoff")
    args.add("--export-dynamic-symbol=__cfi_check")
    args.add("-o", elf)
    args.add_all(interp_objects)
    args.add("--whole-archive")
    args.add_all(libs)
    args.add("--no-whole-archive")

    ctx.actions.run(
        outputs = [elf],
        inputs = depset(libs + interp_objects + ld_scripts),
        executable = ctx.executable._ld,
        arguments = [args],
        mnemonic = "Arm64PhysbootLink",
    )

    stripped = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run(
        outputs = [stripped],
        inputs = [elf],
        executable = ctx.executable._objcopy,
        arguments = ["--strip-sections", elf.path, stripped.path],
        mnemonic = "Arm64PhysbootStrip",
    )

    return [
        DefaultInfo(files = depset([stripped])),
        # Unstripped ELF (symbols + DWARF + build-id note) for the .build-id store;
        # the DefaultInfo output is --strip-sections'd for staging.
        CeriseUnstrippedInfo(unstripped = elf),
    ]

zircon_arm64_physboot = rule(
    implementation = _zircon_arm64_physboot_impl,
    attrs = {
        "deps": attr.label_list(providers = [CcInfo], cfg = _arm64_phys_transition),
        "interp_objects": attr.label_list(allow_files = True),
        "linker_scripts": attr.label_list(allow_files = True, cfg = _arm64_phys_transition),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
        "_objcopy": attr.label(
            default = "//toolchain:llvm_objcopy",
            executable = True,
            cfg = "exec",
        ),
    },
)
