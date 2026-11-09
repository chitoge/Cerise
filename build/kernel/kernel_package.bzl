"""Kernel image packaging rules.

kernel_image: strips the kernel ELF and extracts the .code-patches section.
kernel_user_copy_patches: compiles user-copy.S four ways and extracts raw .text blobs.
kernel_package: assembles the partial vmzircon package tree (kernel portions only;
  physboot/userboot/vdso are added later).
"""

_KERNEL_COPTS = [
    "--target=x86_64-unknown-linux-gnu",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-m64",
    "-mcx16",
    "-mno-mmx",
    "-mno-sse",
    "-mno-sse2",
    "-fPIE",
    "-ffunction-sections",
    "-fdata-sections",
    "-fvisibility=hidden",
    "-mcmodel=kernel",
    "-mno-red-zone",
]

_USER_COPY_VARIANTS = [
    {"name": "_x86_copy_to_or_from_user_movsb", "defines": ["MOVSB"]},
    {"name": "_x86_copy_to_or_from_user_movsb_smap", "defines": ["MOVSB", "SMAP"]},
    {"name": "_x86_copy_to_or_from_user_movsq", "defines": []},
    {"name": "_x86_copy_to_or_from_user_movsq_smap", "defines": ["SMAP"]},
]

# ─── kernel_image ─────────────────────────────────────────────────────────────

def _kernel_image_impl(ctx):
    kernel_elf = ctx.file.kernel
    objcopy = ctx.executable._objcopy

    # Namespace outputs under the target name so multiple kernel_image targets
    # (e.g. vmzircon_image and vmzircon_utest_image) can coexist in one build
    # graph under the same configuration without conflicting on these fixed
    # basenames. Consumers (kernel_package) match by basename, which the
    # subdirectory preserves.
    image_elf = ctx.actions.declare_file(ctx.label.name + "/image.elf")
    ctx.actions.run(
        executable = objcopy,
        arguments = ["--strip-sections", kernel_elf.path, image_elf.path],
        inputs = [kernel_elf],
        outputs = [image_elf],
        mnemonic = "KernelStrip",
        progress_message = "Stripping kernel sections → image.elf",
    )

    code_patches_bin = ctx.actions.declare_file(ctx.label.name + "/code-patches.bin")
    ctx.actions.run(
        executable = objcopy,
        # Writes the section data to the named file; /dev/null discards the ELF.
        arguments = [
            "--dump-section=.code-patches=" + code_patches_bin.path,
            kernel_elf.path,
            "/dev/null",
        ],
        inputs = [kernel_elf],
        outputs = [code_patches_bin],
        mnemonic = "KernelCodePatches",
        progress_message = "Extracting .code-patches → code-patches.bin",
    )

    return [DefaultInfo(files = depset([image_elf, code_patches_bin]))]

kernel_image = rule(
    implementation = _kernel_image_impl,
    attrs = {
        "kernel": attr.label(allow_single_file = True, mandatory = True),
        "_objcopy": attr.label(
            default = "//toolchain:llvm_objcopy",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ─── kernel_user_copy_patches ─────────────────────────────────────────────────

def _kernel_user_copy_patches_impl(ctx):
    src = ctx.file.src
    clang = ctx.executable._clang
    objcopy = ctx.executable._objcopy
    hdrs = ctx.files.hdrs

    patches = []
    for v in _USER_COPY_VARIANTS:
        name = v["name"]
        defines = v["defines"]

        obj = ctx.actions.declare_file("user_copy_objs/{}.o".format(name))
        compile_args = ctx.actions.args()
        compile_args.add_all(_KERNEL_COPTS)
        compile_args.add("-DFUNCTION_NAME={}".format(name))
        for d in defines:
            compile_args.add("-D{}".format(d))
        compile_args.add("-I", "zircon/kernel/lib/arch/include")
        compile_args.add("-I", "zircon/system/public")
        compile_args.add("-I", "zircon/public")
        compile_args.add("-c", src.path)
        compile_args.add("-o", obj.path)
        ctx.actions.run(
            executable = clang,
            arguments = [compile_args],
            inputs = depset([src] + hdrs),
            outputs = [obj],
            mnemonic = "UserCopyPatchCompile",
            progress_message = "Compiling user-copy patch {}".format(name),
        )

        patch = ctx.actions.declare_file("code-patches/{}".format(name))
        extract_args = ctx.actions.args()
        extract_args.add("-O", "binary")
        extract_args.add("--only-section=.text")
        extract_args.add(obj.path)
        extract_args.add(patch.path)
        ctx.actions.run(
            executable = objcopy,
            arguments = [extract_args],
            inputs = [obj],
            outputs = [patch],
            mnemonic = "UserCopyPatchExtract",
            progress_message = "Extracting .text → {}".format(name),
        )
        patches.append(patch)

    return [DefaultInfo(files = depset(patches))]

kernel_user_copy_patches = rule(
    implementation = _kernel_user_copy_patches_impl,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "hdrs": attr.label_list(allow_files = True),
        "_clang": attr.label(
            default = "//toolchain:prebuilt_clang",
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

# ─── kernel_package ───────────────────────────────────────────────────────────

def _kernel_package_impl(ctx):
    # Expected inputs: kernel_image outputs (image.elf, code-patches.bin),
    # user_copy_patches outputs (code-patches/<name> × 4), version_string output.
    image_elf = None
    code_patches_bin = None
    user_copy_patches = {}
    version_string = None

    for f in ctx.files.kernel_image:
        if f.basename == "image.elf":
            image_elf = f
        elif f.basename == "code-patches.bin":
            code_patches_bin = f

    for f in ctx.files.user_copy_patches:
        user_copy_patches[f.basename] = f

    for f in ctx.files.version_string:
        version_string = f

    pkg = ctx.attr.package_dir

    outs = []

    def copy(src, rel):
        out = ctx.actions.declare_file("{}/{}".format(pkg, rel))
        ctx.actions.run_shell(
            inputs = [src],
            outputs = [out],
            command = "cp $1 $2",
            arguments = [src.path, out.path],
            mnemonic = "KernelPackageCopy",
        )
        outs.append(out)
        return out

    if image_elf:
        copy(image_elf, "zircon/vmzircon/image.elf")
    if code_patches_bin:
        copy(code_patches_bin, "zircon/vmzircon/code-patches.bin")
    for name, f in user_copy_patches.items():
        copy(f, "zircon/vmzircon/code-patches/{}".format(name))
    if version_string:
        copy(version_string, "zircon/version-string.txt")

    return [DefaultInfo(files = depset(outs))]

kernel_package = rule(
    implementation = _kernel_package_impl,
    attrs = {
        "kernel_image": attr.label(mandatory = True),
        "user_copy_patches": attr.label(mandatory = False),
        "version_string": attr.label(allow_files = True, mandatory = True),
        "package_dir": attr.string(default = "vmzircon_package"),
    },
)
