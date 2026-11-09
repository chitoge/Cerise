ZirconToolchainInfo = provider(
    doc = "Zircon build-environment configuration selected through a Bazel toolchain.",
    fields = {
        "asmopts": "Assembler options for this environment.",
        "copts": "C/C++ compiler options for this environment.",
        "cpu": "Zircon CPU architecture name.",
        "cxxopts": "C++-only compiler options for this environment.",
        "defines": "Preprocessor definitions without the -D prefix.",
        "environment": "Zircon build environment such as kernel, phys, or efi.",
        "feature_docs": "Documentation strings for the selected feature names.",
        "features": "Ordered feature names that produced this configuration.",
        "linkopts": "Linker options for this environment.",
        "manifest": "Generated audit manifest file for this configuration.",
        "name": "Stable configuration name.",
        "stdlib_include_dirs": "Hermetic standard-header include directories for this environment.",
    },
)

ZIRCON_KERNEL_TOOLCHAIN_TYPE = "//toolchain:zircon_kernel_toolchain_type"
ZIRCON_PHYS_TOOLCHAIN_TYPE = "//toolchain:zircon_phys_toolchain_type"
ZIRCON_EFI_TOOLCHAIN_TYPE = "//toolchain:zircon_efi_toolchain_type"
ZIRCON_USER_TOOLCHAIN_TYPE = "//toolchain:zircon_user_toolchain_type"

def _feature(doc, copts = [], cxxopts = [], asmopts = [], defines = [], linkopts = [], stdlib_include_dirs = []):
    return struct(
        asmopts = asmopts,
        copts = copts,
        cxxopts = cxxopts,
        defines = defines,
        doc = doc,
        linkopts = linkopts,
        stdlib_include_dirs = stdlib_include_dirs,
    )

_ZIRCON_FEATURES = {
    "cpu.x64.common": _feature(
        doc = "Common x64 freestanding code-generation constraints.",
        copts = [
            "--target=x86_64-unknown-linux-gnu",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-m64",
            "-mcx16",
            "-mno-mmx",
            "-mno-sse",
            "-mno-sse2",
        ],
    ),
    "cpu.x86_32.common": _feature(
        doc = "Common x86_32 freestanding code-generation constraints.",
        copts = [
            "--target=i386-unknown-linux-gnu",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-m32",
            "-march=i686",
            "-mno-mmx",
            "-mno-sse",
            "-mno-sse2",
        ],
    ),
    "cpu.x64.efi": _feature(
        doc = "x64 EFI code-generation constraints.",
        copts = [
            "--target=x86_64-unknown-uefi",
            "-m64",
        ],
    ),
    "cpu.x64.user": _feature(
        doc = "x64 userboot code-generation constraints.",
        copts = [
            "--target=x86_64-unknown-linux-gnu",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fPIE",
            "-fPIC",
        ],
    ),
    "abi.x64.kernel": _feature(
        doc = "x64 kernel virtual-address ABI and hidden-section code model.",
        copts = [
            "-fdata-sections",
            "-ffunction-sections",
            "-fPIE",
            "-fvisibility=hidden",
            "-mcmodel=kernel",
            "-mno-red-zone",
            "-fasynchronous-unwind-tables",
        ],
    ),
    "abi.x64.phys": _feature(
        doc = "x64 physical-address bootstrap ABI.",
        copts = [
            "-fdata-sections",
            "-ffunction-sections",
            "-fPIC",
            "-fvisibility=hidden",
            "-mcmodel=small",
            "-mno-red-zone",
        ],
    ),
    "abi.x86_32.phys": _feature(
        doc = "x86_32 physical-address bootstrap ABI.",
        copts = [
            "-fdata-sections",
            "-ffunction-sections",
            "-fno-pic",
            "-fno-pie",
            "-fvisibility=hidden",
            "-funwind-tables",
        ],
    ),
    "abi.x64.efi": _feature(
        doc = "x64 UEFI ABI details that differ from the kernel environment.",
        copts = [
            "-fshort-wchar",
        ],
    ),
    # arm64 features
    "cpu.arm64.common": _feature(
        doc = "Common arm64 freestanding code-generation constraints.",
        copts = [
            "--target=aarch64-unknown-elf",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-mgeneral-regs-only",
            # -mstrict-align: arm64 kernel + phys early boot runs with the MMU OFF
            # (Device-nGnRnE memory), where unaligned accesses alignment-fault
            # regardless of SCTLR_ELx.A. Without it clang emits unaligned
            # halfword/word accesses that fault before paging is enabled (observed
            # as a physload alignment Data Abort). No x64 counterpart;
            # mirrors the cc_args `kernel_arm64_freestanding_flags` /
            # `arm64_phys_common_flags` in toolchain/BUILD.bazel.
            "-mstrict-align",
        ],
    ),
    "abi.arm64.kernel": _feature(
        doc = "arm64 kernel ABI: small code model, SCS instrumentation, fixed-x18.",
        copts = [
            "-fdata-sections",
            "-ffunction-sections",
            "-fPIE",
            "-fvisibility=hidden",
            "-mcmodel=small",
            "-fasynchronous-unwind-tables",
            "-ffixed-x18",
            "-fsanitize=shadow-call-stack",
        ],
    ),
    "abi.arm64.phys": _feature(
        doc = "arm64 physical-address bootstrap ABI.",
        copts = [
            "-fdata-sections",
            "-ffunction-sections",
            "-fPIC",
            "-fvisibility=hidden",
            "-mcmodel=small",
        ],
    ),
    "cpu.arm64.user": _feature(
        doc = "arm64 userboot code-generation constraints.",
        copts = [
            "--target=aarch64-unknown-elf",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fPIE",
            "-fPIC",
        ],
    ),
    "env.kernel": _feature(
        doc = "Kernel environment definitions shared by kernel component rules.",
        defines = [
            "LK",
            "ZIRCON_TOOLCHAIN",
            "_KERNEL",
        ],
    ),
    "env.phys": _feature(
        doc = "Phys environment definitions for early boot components.",
        defines = [
            "LK",
            "ZIRCON_TOOLCHAIN",
            "_KERNEL",
            "_PHYS",
        ],
    ),
    "env.efi": _feature(
        doc = "UEFI environment definitions for EFI boot components.",
        defines = [
            "ZIRCON_TOOLCHAIN",
            "_EFI",
            "__PE_COFF__",
        ],
    ),
    "env.user": _feature(
        doc = "User environment definitions for userboot and userspace components.",
        defines = [
            "ZIRCON_TOOLCHAIN",
        ],
    ),
    "lang.kernel_cxx": _feature(
        doc = "C++ restrictions expected by Zircon freestanding code.",
        cxxopts = [
            "-fnew-alignment=8",
            "-fno-exceptions",
            "-fno-rtti",
        ],
    ),
    "lang.phys_cxx": _feature(
        doc = "C++ restrictions expected by Zircon phys code.",
        cxxopts = [
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-threadsafe-statics",
        ],
    ),
    "lang.user_cxx": _feature(
        doc = "C++ restrictions expected by Zircon userboot and userland code.",
        cxxopts = [
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-threadsafe-statics",
        ],
    ),
    "lang.user_cxx_std": _feature(
        doc = "C++ language mode for Zircon userboot and userland code.",
        cxxopts = [
            "-std=c++20",
        ],
    ),
    "stdlib.cxx_headers": _feature(
        doc = "Hermetic libc++ headers provided by the vendored LLVM overlay.",
        cxxopts = [
            "-nostdinc++",
        ],
        stdlib_include_dirs = [
            "@llvm-project//libcxx:libcxx_headers_include_search_directory",
        ],
    ),
    "stdlib.c_headers": _feature(
        doc = "Hermetic C headers provided by the Zircon toolchain environment.",
        copts = [
            "-nostdlibinc",
        ],
    ),
    "debug.kernel_level_2": _feature(
        doc = "Current kernel debug-level defines used by the x64 boot graph.",
        defines = [
            "DEBUG_PRINT_LEVEL=2",
            "LK_DEBUGLEVEL=2",
        ],
    ),
    "debug.kernel_level_1": _feature(
        doc = "Reduced kernel debug-level defines used when the build setting lowers verbosity.",
        defines = [
            "DEBUG_PRINT_LEVEL=1",
            "LK_DEBUGLEVEL=1",
        ],
    ),
    "link.freestanding": _feature(
        doc = "Freestanding link baseline: no host startup files or default libraries.",
        linkopts = [
            "-nostdlib",
            "-nodefaultlibs",
            "-nostartfiles",
        ],
    ),
    "link.user": _feature(
        doc = "Userboot link baseline for the freestanding user payload.",
        linkopts = [
            "-nostdlib",
            "-nodefaultlibs",
            "-nostartfiles",
            "-pie",
            "-Wl,--no-dynamic-linker",
            "-Wl,--gc-sections",
            "-Wl,-z,max-page-size=4096",
            "-Wl,-z,stack-size=0x100000",
            "-Wl,--entry=_start",
        ],
    ),
}

def _dedupe(values):
    seen = {}
    result = []
    for value in values:
        if value not in seen:
            seen[value] = True
            result.append(value)
    return result

def _merge_field(features, field):
    values = []
    for feature_name in features:
        feature = _ZIRCON_FEATURES.get(feature_name)
        if feature == None:
            fail("unknown Zircon toolchain feature '{}'; known features are {}".format(
                feature_name,
                sorted(_ZIRCON_FEATURES.keys()),
            ))
        values.extend(getattr(feature, field))
    return _dedupe(values)

def _feature_docs(features):
    docs = {}
    for feature_name in features:
        docs[feature_name] = _ZIRCON_FEATURES[feature_name].doc
    return docs

def _zircon_environment_toolchain_impl(ctx):
    features = ctx.attr.feature_names
    manifest = ctx.actions.declare_file(ctx.label.name + ".manifest.json")
    info = ZirconToolchainInfo(
        asmopts = _merge_field(features, "asmopts"),
        copts = _merge_field(features, "copts"),
        cpu = ctx.attr.cpu,
        cxxopts = _merge_field(features, "cxxopts"),
        defines = _merge_field(features, "defines"),
        environment = ctx.attr.environment,
        feature_docs = _feature_docs(features),
        features = features,
        linkopts = _merge_field(features, "linkopts"),
        manifest = manifest,
        name = ctx.attr.config_name or ctx.label.name,
        stdlib_include_dirs = _merge_field(features, "stdlib_include_dirs"),
    )

    ctx.actions.write(
        output = manifest,
        content = json.encode_indent({
            "asmopts": info.asmopts,
            "copts": info.copts,
            "cpu": info.cpu,
            "cxxopts": info.cxxopts,
            "defines": info.defines,
            "environment": info.environment,
            "feature_docs": info.feature_docs,
            "features": info.features,
            "linkopts": info.linkopts,
            "name": info.name,
            "stdlib_include_dirs": info.stdlib_include_dirs,
        }) + "\n",
    )

    return [
        DefaultInfo(files = depset([manifest])),
        info,
        platform_common.ToolchainInfo(zircon = info),
    ]

zircon_environment_toolchain = rule(
    implementation = _zircon_environment_toolchain_impl,
    doc = "Composes named Zircon build-environment features for Bazel toolchain resolution.",
    attrs = {
        "config_name": attr.string(doc = "Stable audit name; defaults to the target name."),
        "cpu": attr.string(mandatory = True),
        "environment": attr.string(mandatory = True),
        "feature_names": attr.string_list(mandatory = True),
    },
)

def _write_probe_manifest(ctx, toolchain_type):
    info = ctx.toolchains[toolchain_type].zircon
    output = ctx.actions.declare_file(ctx.attr.out or (ctx.label.name + ".resolved.json"))
    ctx.actions.write(
        output = output,
        content = json.encode_indent({
            "copts": info.copts,
            "cpu": info.cpu,
            "cxxopts": info.cxxopts,
            "defines": info.defines,
            "environment": info.environment,
            "features": info.features,
            "linkopts": info.linkopts,
            "name": info.name,
            "stdlib_include_dirs": info.stdlib_include_dirs,
            "toolchain_type": toolchain_type,
        }) + "\n",
    )
    return [DefaultInfo(files = depset([output]))]

def _zircon_kernel_toolchain_probe_impl(ctx):
    return _write_probe_manifest(ctx, ZIRCON_KERNEL_TOOLCHAIN_TYPE)

def _zircon_phys_toolchain_probe_impl(ctx):
    return _write_probe_manifest(ctx, ZIRCON_PHYS_TOOLCHAIN_TYPE)

def _zircon_efi_toolchain_probe_impl(ctx):
    return _write_probe_manifest(ctx, ZIRCON_EFI_TOOLCHAIN_TYPE)

def _zircon_user_toolchain_probe_impl(ctx):
    return _write_probe_manifest(ctx, ZIRCON_USER_TOOLCHAIN_TYPE)

_probe_attrs = {
    "out": attr.string(),
}

zircon_kernel_toolchain_probe = rule(
    implementation = _zircon_kernel_toolchain_probe_impl,
    attrs = _probe_attrs,
    toolchains = [ZIRCON_KERNEL_TOOLCHAIN_TYPE],
)

zircon_phys_toolchain_probe = rule(
    implementation = _zircon_phys_toolchain_probe_impl,
    attrs = _probe_attrs,
    toolchains = [ZIRCON_PHYS_TOOLCHAIN_TYPE],
)

zircon_efi_toolchain_probe = rule(
    implementation = _zircon_efi_toolchain_probe_impl,
    attrs = _probe_attrs,
    toolchains = [ZIRCON_EFI_TOOLCHAIN_TYPE],
)

zircon_user_toolchain_probe = rule(
    implementation = _zircon_user_toolchain_probe_impl,
    attrs = _probe_attrs,
    toolchains = [ZIRCON_USER_TOOLCHAIN_TYPE],
)
