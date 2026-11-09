"""zircon_kernel: links all kernel cc_library components into the kernel ELF."""

load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _x64_kernel_transition_impl(settings, attr):
    return {"//command_line_option:platforms": "//platforms:x64-kernel"}

_x64_kernel_transition = transition(
    implementation = _x64_kernel_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _arm64_kernel_transition_impl(settings, attr):
    return {"//command_line_option:platforms": "//platforms:arm64-kernel"}

_arm64_kernel_transition = transition(
    implementation = _arm64_kernel_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _zircon_kernel_impl(ctx):
    elf = ctx.actions.declare_file(ctx.label.name)

    # Collect all static libraries from transitive deps (deduplicated by path)
    seen = {}
    libs = []
    for dep in ctx.attr.deps:
        if CcInfo in dep:
            for linker_input in dep[CcInfo].linking_context.linker_inputs.to_list():
                for lib in linker_input.libraries:
                    f = lib.static_library or lib.pic_static_library
                    if f and f.path not in seen:
                        seen[f.path] = True
                        libs.append(f)

    linker_scripts = ctx.files.linker_scripts

    args = ctx.actions.args()
    args.add("--pie")
    # Use a 40-char placeholder interp; kernel_storage_zbi overwrites it
    # with physboot's actual SHA-1 build ID (also 40 hex chars).
    args.add("--dynamic-linker=0000000000000000000000000000000000000000")
    args.add("--build-id=sha1")
    args.add("--gc-sections")
    args.add("-z", "start-stop-visibility=hidden")
    args.add("-z", "max-page-size=4096")
    args.add("--entry", ctx.attr.entry)
    args.add("-defsym=SMP_MAX_CPUS=32")
    args.add("-defsym=KERNEL_GOT_TOLERANCE=0")
    args.add("-defsym=KERNEL_BASE_ADDRESS=0")
    for ls in linker_scripts:
        args.add("-T", ls)
    args.add("-o", elf)
    args.add("--whole-archive")
    args.add_all(libs)
    args.add("--no-whole-archive")

    ctx.actions.run(
        outputs = [elf],
        inputs = depset(libs + linker_scripts),
        executable = ctx.executable._ld,
        arguments = [args],
        mnemonic = "ZirconKernelLink",
    )

    return [DefaultInfo(files = depset([elf]))]

zircon_kernel = rule(
    implementation = _zircon_kernel_impl,
    attrs = {
        "deps": attr.label_list(providers = [CcInfo], cfg = _x64_kernel_transition),
        "linker_scripts": attr.label_list(allow_files = True, cfg = _x64_kernel_transition),
        "entry": attr.string(default = "kZirconAbiSpec"),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _zircon_arm64_kernel_impl(ctx):
    elf = ctx.actions.declare_file(ctx.label.name)

    seen = {}
    libs = []
    for dep in ctx.attr.deps:
        if CcInfo in dep:
            for linker_input in dep[CcInfo].linking_context.linker_inputs.to_list():
                for lib in linker_input.libraries:
                    f = lib.static_library or lib.pic_static_library
                    if f and f.path not in seen:
                        seen[f.path] = True
                        libs.append(f)

    linker_scripts = ctx.files.linker_scripts

    args = ctx.actions.args()
    args.add("--pie")
    # Use a 40-char placeholder interp; the arm64_kernel_storage_zbi genrule
    # overwrites it with physboot's actual SHA-1 build ID (also 40 hex chars).
    args.add("--dynamic-linker=0000000000000000000000000000000000000000")
    args.add("--build-id=sha1")
    args.add("--gc-sections")
    args.add("-z", "start-stop-visibility=hidden")
    args.add("-z", "max-page-size=4096")
    args.add("--entry", ctx.attr.entry)
    # arm64 compile flags use SMP_MAX_CPUS=16 (see toolchain/BUILD.bazel:kernel_arm64_define_flags)
    args.add("-defsym=SMP_MAX_CPUS=16")
    # arm64 PIE generates GOT entries (current size ~840 B / 105 entries);
    # allow up to 4KB (512 entries) with room to grow.
    args.add("-defsym=KERNEL_GOT_TOLERANCE=4096")
    args.add("-defsym=KERNEL_BASE_ADDRESS=0")
    # PhysbootHandoff is the physboot->kernel entrypoint alias (lk_main on all arches).
    args.add("-defsym=PhysbootHandoff=lk_main")
    for ls in linker_scripts:
        args.add("-T", ls)
    args.add("-o", elf)
    args.add("--whole-archive")
    args.add_all(libs)
    args.add("--no-whole-archive")

    ctx.actions.run(
        outputs = [elf],
        inputs = depset(libs + linker_scripts),
        executable = ctx.executable._ld,
        arguments = [args],
        mnemonic = "ZirconArm64KernelLink",
    )

    return [DefaultInfo(files = depset([elf]))]

zircon_arm64_kernel = rule(
    implementation = _zircon_arm64_kernel_impl,
    attrs = {
        "deps": attr.label_list(providers = [CcInfo], cfg = _arm64_kernel_transition),
        "linker_scripts": attr.label_list(allow_files = True, cfg = _arm64_kernel_transition),
        "entry": attr.string(default = "kZirconAbiSpec"),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
    },
)
