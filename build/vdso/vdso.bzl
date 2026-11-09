"""zircon_vdso: builds libzircon.so (the Zircon vDSO / system call ABI).

Produces four outputs:
  libzircon.so        — the vDSO ELF (shared library)
  vdso-code.h         — CODE_*/DATA_*/ENTRY/DYNSYM_* address macros
  vdso-valid-sysret.h — VDso::ValidSyscallPC per-syscall methods
  sysret-offsets.h    — kSysretOffsets[] array
"""

_VDSO_ELF_CXX_COPTS = [
    "--target=x86_64-unknown-linux-gnu",
    "-fPIC",
    "-fvisibility=hidden",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-exceptions",
    "-fno-rtti",
    "-fdata-sections",
    "-ffunction-sections",
    "-nostdinc++",
    "-DVDSO_MAX_PAGE_SIZE=4096",
    "-DFUCHSIA_UNSUPPORTED_ALLOW_SYSCALLS_NEXT_ON_HOST",
    "-std=c++20",
    "-Wall",
    "-Werror",
    "-Wno-ignored-attributes",
    "-Wno-macro-redefined",
    "-Wno-unused-function",
    "-Wno-unused-variable",
]

_VDSO_ELF_ASM_COPTS = [
    "--target=x86_64-unknown-linux-gnu",
    "-fPIC",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-DVDSO_MAX_PAGE_SIZE=4096",
    "-DFUCHSIA_UNSUPPORTED_ALLOW_SYSCALLS_NEXT_ON_HOST",
]

_VDSO_WORKSPACE_INCLUDE_DIRS = [
    "zircon/public",
    "zircon/system/public",
    "src/zircon/lib/zircon/include",
    "zircon/kernel/lib/userabi/include",
    "zircon/kernel/lib/fasttime/include",
    "zircon/kernel/lib/page/include",
    "zircon/kernel/lib/arch/x86/include",
    "zircon/kernel/lib/arch/include",
    "zircon/kernel/arch/x86/include",
    "zircon/system/ulib/affine/include",
    "zircon/system/ulib/concurrent/include",
    "sdk/lib/stdcompat/include",
    "tools/fidl/include",
]

_VDSO_ARM64_ELF_CXX_COPTS = [
    "--target=aarch64-unknown-linux-gnu",
    "-fPIC",
    "-fvisibility=hidden",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-exceptions",
    "-fno-rtti",
    "-fdata-sections",
    "-ffunction-sections",
    "-nostdinc++",
    "-DVDSO_MAX_PAGE_SIZE=4096",
    "-DFUCHSIA_UNSUPPORTED_ALLOW_SYSCALLS_NEXT_ON_HOST",
    "-std=c++20",
    "-Wall",
    "-Werror",
    "-Wno-ignored-attributes",
    "-Wno-macro-redefined",
    "-Wno-unused-function",
    "-Wno-unused-variable",
]

_VDSO_ARM64_ELF_ASM_COPTS = [
    "--target=aarch64-unknown-linux-gnu",
    "-fPIC",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-DVDSO_MAX_PAGE_SIZE=4096",
    "-DFUCHSIA_UNSUPPORTED_ALLOW_SYSCALLS_NEXT_ON_HOST",
]

_VDSO_ARM64_WORKSPACE_INCLUDE_DIRS = [
    "zircon/public",
    "zircon/system/public",
    "src/zircon/lib/zircon/include",
    "zircon/kernel/lib/userabi/include",
    "zircon/kernel/lib/fasttime/include",
    "zircon/kernel/lib/page/include",
    "zircon/kernel/lib/arch/arm64/include",
    "zircon/kernel/lib/arch/include",
    "zircon/kernel/arch/arm64/include",
    "zircon/system/ulib/affine/include",
    "zircon/system/ulib/concurrent/include",
    "sdk/lib/stdcompat/include",
    "tools/fidl/include",
]

def _zircon_vdso_impl(ctx):
    # System header directory artifacts (TreeArtifacts from copy_to_directory).
    libcxx_dir = ctx.attr._libcxx_hdrs[DefaultInfo].files.to_list()[0]
    glibc_dir = ctx.attr._glibc_hdrs[DefaultInfo].files.to_list()[0]
    linux_hdrs_dir = ctx.attr._linux_kernel_hdrs[DefaultInfo].files.to_list()[0]

    # Syscall generated files (individual files, all under <gen_dir>/lib/syscalls/).
    # Compute the gen_dir path from the first file's path.
    syscall_files = ctx.attr.syscall_headers[DefaultInfo].files.to_list()
    # Each file is at "<gen_dir>/lib/syscalls/<name>"; strip "/lib/syscalls/<name>"
    # to get the gen_dir path we pass as -I.
    # e.g. "bazel-out/.../abi/zx_syscall_headers_generated.gen/lib/syscalls/kernel.inc"
    #  → "bazel-out/.../abi/zx_syscall_headers_generated.gen"
    syscall_gen_path = syscall_files[0].dirname[:-len("/lib/syscalls")]

    # All header inputs for sandboxing.
    system_hdrs = [libcxx_dir, glibc_dir, linux_hdrs_dir] + syscall_files
    workspace_hdrs = ctx.files.hdrs

    def _compile(src, copts, compiler):
        obj_name = src.path.replace("/", "_").replace(".", "_") + ".o"
        obj = ctx.actions.declare_file("vdso_objs/{}".format(obj_name))
        args = ctx.actions.args()
        args.add_all(copts)
        args.add("-isystem", libcxx_dir.path)
        args.add("-isystem", glibc_dir.path)
        args.add("-isystem", linux_hdrs_dir.path)
        args.add("-I", syscall_gen_path)
        for inc in _VDSO_WORKSPACE_INCLUDE_DIRS:
            args.add("-I", inc)
        args.add("-c", src)
        args.add("-o", obj)
        ctx.actions.run(
            executable = compiler,
            arguments = [args],
            inputs = depset([src] + system_hdrs + workspace_hdrs),
            outputs = [obj],
            mnemonic = "VDsoCompile",
            progress_message = "Compiling vDSO {}".format(src.basename),
        )
        return obj

    objs = []
    for src in ctx.files.cxx_srcs:
        objs.append(_compile(src, _VDSO_ELF_CXX_COPTS, ctx.executable._clangpp))
    for src in ctx.files.asm_srcs:
        objs.append(_compile(src, _VDSO_ELF_ASM_COPTS, ctx.executable._clang))

    # Link libzircon.so
    linker_script = ctx.file.linker_script
    libzircon = ctx.actions.declare_file("libzircon.so")
    link_args = ctx.actions.args()
    link_args.add("--shared")
    link_args.add("-soname", "libzircon.so")
    link_args.add("-e", "_zx_process_exit")
    link_args.add("-z", "max-page-size=4096")
    link_args.add("-z", "separate-code")
    link_args.add("-z", "rodynamic")
    link_args.add("--gc-sections")
    link_args.add("--build-id=sha1")
    link_args.add("-o", libzircon)
    link_args.add_all(objs)
    link_args.add(linker_script)
    ctx.actions.run(
        executable = ctx.executable._ld,
        arguments = [link_args],
        inputs = depset(objs + [linker_script]),
        outputs = [libzircon],
        mnemonic = "VDsoLink",
        progress_message = "Linking libzircon.so",
    )

    # Find generation scripts from the filegroup.
    gen_rodso = None
    gen_valid_sysret = None
    gen_sysret_offsets = None
    for f in ctx.attr._gen_scripts[DefaultInfo].files.to_list():
        if f.basename == "gen-rodso-code.sh":
            gen_rodso = f
        elif f.basename == "gen-vdso-valid-sysret.sh":
            gen_valid_sysret = f
        elif f.basename == "gen-sysret-offsets.sh":
            gen_sysret_offsets = f

    nm = ctx.executable._nm
    readelf = ctx.executable._readelf

    # gen-rodso-code.sh NM READELF outfile.h NAME dso
    vdso_code_h = ctx.actions.declare_file("vdso-headers/vdso-code.h")
    ctx.actions.run_shell(
        inputs = [libzircon, gen_rodso, nm, readelf],
        outputs = [vdso_code_h],
        command = "bash {gen} {nm} {re} {out} VDSO {dso}".format(
            gen = gen_rodso.path,
            nm = nm.path,
            re = readelf.path,
            out = vdso_code_h.path,
            dso = libzircon.path,
        ),
        mnemonic = "VDsoRodsoCode",
        progress_message = "Generating vdso-code.h",
    )

    # gen-vdso-valid-sysret.sh vdso-code.h vdso-valid-sysret.h
    vdso_valid_sysret_h = ctx.actions.declare_file("vdso-headers/vdso-valid-sysret.h")
    ctx.actions.run_shell(
        inputs = [vdso_code_h, gen_valid_sysret],
        outputs = [vdso_valid_sysret_h],
        command = "bash {gen} {inp} {out}".format(
            gen = gen_valid_sysret.path,
            inp = vdso_code_h.path,
            out = vdso_valid_sysret_h.path,
        ),
        mnemonic = "VDsoValidSysret",
        progress_message = "Generating vdso-valid-sysret.h",
    )

    # gen-sysret-offsets.sh vdso-code.h sysret-offsets.h
    sysret_offsets_h = ctx.actions.declare_file("vdso-headers/sysret-offsets.h")
    ctx.actions.run_shell(
        inputs = [vdso_code_h, gen_sysret_offsets],
        outputs = [sysret_offsets_h],
        command = "bash {gen} {inp} {out}".format(
            gen = gen_sysret_offsets.path,
            inp = vdso_code_h.path,
            out = sysret_offsets_h.path,
        ),
        mnemonic = "VDsoSysretOffsets",
        progress_message = "Generating sysret-offsets.h",
    )

    return [DefaultInfo(files = depset([libzircon, vdso_code_h, vdso_valid_sysret_h, sysret_offsets_h]))]

_USERBOOT_PAYLOAD_CXX_COPTS = [
    "--target=x86_64-unknown-linux-gnu",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-sanitize=safe-stack",
    "-fPIC",
    "-fvisibility=hidden",
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-exceptions",
    "-fno-rtti",
    "-fno-threadsafe-statics",
    "-fno-use-cxa-atexit",
    "-nostdinc++",
    "-D_ALL_SOURCE",
    "-DFUCHSIA_UNSUPPORTED_ALLOW_SYSCALLS_NEXT_ON_HOST",
    "-DZSTD_STATIC_LINKING_ONLY",
    "-DXXH_NAMESPACE=ZSTD_",
    "-DZDICTLIB_VISIBILITY=",
    "-DZSTDERRORLIB_VISIBILITY=",
    "-DZSTDLIB_HIDDEN=",
    "-DZSTDLIB_VISIBILITY=",
    "-DZSTDLIB_VISIBLE=",
    "-DPLATFORM_POSIX_VERSION=200112L",
    "-DZSTD_SETPRIORITY_SUPPORT=0",
    "-DHUF_FORCE_DECOMPRESS_X2",
    "-DZSTD_DEPS_MALLOC",
    "-DZSTD_malloc(s)=((void)(s),NULL)",
    "-DZSTD_calloc(n,s)=((void)((n)*(s)),NULL)",
    "-DZSTD_free(p)=(void)(p)",
    "-DZSTD_NO_TRACE",
    "-DBOOT_TEST_SUCCESS_STRING=\"***Boot-test-successful!-MDd7/O65SuVZ23yGAaQG4CedYQGH9E1/58r73pSAVK0=***\"",
    "-std=c++20",
    "-Wall",
    "-Werror",
    "-Wno-ignored-attributes",
    "-Wno-invalid-offsetof",
    "-Wno-macro-redefined",
    "-Wno-unused-function",
    "-Wno-unused-variable",
]

_USERBOOT_PAYLOAD_C_COPTS = [
    "--target=x86_64-unknown-linux-gnu",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-sanitize=safe-stack",
    "-fPIC",
    "-fvisibility=hidden",
    "-ffunction-sections",
    "-fdata-sections",
    "-D_ALL_SOURCE",
    "-DFUCHSIA_UNSUPPORTED_ALLOW_SYSCALLS_NEXT_ON_HOST",
    "-DZSTD_STATIC_LINKING_ONLY",
    "-DXXH_NAMESPACE=ZSTD_",
    "-DZDICTLIB_VISIBILITY=",
    "-DZSTDERRORLIB_VISIBILITY=",
    "-DZSTDLIB_HIDDEN=",
    "-DZSTDLIB_VISIBILITY=",
    "-DZSTDLIB_VISIBLE=",
    "-DPLATFORM_POSIX_VERSION=200112L",
    "-DZSTD_SETPRIORITY_SUPPORT=0",
    "-DHUF_FORCE_DECOMPRESS_X2",
    "-DZSTD_DEPS_MALLOC",
    "-DZSTD_malloc(s)=((void)(s),NULL)",
    "-DZSTD_calloc(n,s)=((void)((n)*(s)),NULL)",
    "-DZSTD_free(p)=(void)(p)",
    "-DZSTD_NO_TRACE",
    "-std=c11",
    "-Wall",
    "-Werror",
    "-Wno-macro-redefined",
    "-Wno-unknown-warning-option",
    "-Wno-conversion",
    "-Wno-unused-but-set-variable",
    "-Wno-bitwise-instead-of-logical",
    "-Wno-implicit-fallthrough",
]

_USERBOOT_PAYLOAD_ASM_COPTS = [
    "--target=x86_64-unknown-linux-gnu",
    "-fPIC",
    "-fvisibility=hidden",
]

_USERBOOT_PAYLOAD_WORKSPACE_INCLUDE_DIRS = [
    "zircon/kernel/lib/userabi/userboot",
    "zircon/kernel/phys/include",
    "zircon/kernel/lib/acpi_lite/include",
    "zircon/kernel/lib/arch/include",
    "zircon/kernel/lib/arch/x86/include",
    "zircon/kernel/arch/x86/phys/include",
    "zircon/kernel/lib/crypto/include",
    "zircon/kernel/lib/devicetree/include",
    "zircon/kernel/phys/lib/memalloc/include",
    "src/lib/elfldltl/test",
    "src/lib/elfldltl/include",
    "src/lib/zbitl/include",
    "third_party/zstd/include",
    "third_party/zstd/src/lib",
    "third_party/zstd/src/lib/common",
    "third_party/zstd/src/lib/decompress",
    "sdk/lib/fidl_base/include",
    "sdk/lib/fidl/include",
    "sdk/lib/fit/include",
    "sdk/lib/stdcompat/include",
    "sdk/lib/zbi-format/include",
    "src/zircon/lib/zircon/include",
    "zircon/kernel/lib/instrumentation/include",
    "zircon/kernel/lib/boot-options/include",
    "zircon/kernel/lib/userabi/include",
    "zircon/public",
    "zircon/system/public",
    "zircon/system/ulib/fbl/include",
    "zircon/system/ulib/hwreg/include",
    "zircon/system/ulib/ldmsg/include",
    "zircon/system/ulib/mmio-ptr/include",
    "zircon/system/ulib/uart/include",
    "zircon/system/ulib/zx/include",
    "zircon/system/ulib/zircon-internal/include",
    "zircon/third_party/ulib/cksum/include",
]

def _userboot_payload_impl(ctx):
    libcxx_dir = ctx.attr._libcxx_hdrs[DefaultInfo].files.to_list()[0]
    glibc_dir = ctx.attr._glibc_hdrs[DefaultInfo].files.to_list()[0]
    linux_hdrs_dir = ctx.attr._linux_kernel_hdrs[DefaultInfo].files.to_list()[0]
    system_hdrs = [libcxx_dir, glibc_dir, linux_hdrs_dir]
    workspace_hdrs = ctx.files.hdrs

    def _compile(src, copts, compiler):
        obj_name = src.path.replace("/", "_").replace(".", "_") + ".o"
        obj = ctx.actions.declare_file("userboot_objs/{}".format(obj_name))
        args = ctx.actions.args()
        args.add_all(copts)
        args.add("-isystem", libcxx_dir.path)
        args.add("-isystem", glibc_dir.path)
        args.add("-isystem", linux_hdrs_dir.path)
        for inc in _USERBOOT_PAYLOAD_WORKSPACE_INCLUDE_DIRS:
            args.add("-I", inc)
        args.add("-c", src)
        args.add("-o", obj)
        ctx.actions.run(
            executable = compiler,
            arguments = [args],
            inputs = depset([src] + system_hdrs + workspace_hdrs),
            outputs = [obj],
            mnemonic = "UserbootCompile",
            progress_message = "Compiling userboot {}".format(src.basename),
        )
        return obj

    objs = []
    for src in ctx.files.cxx_srcs:
        objs.append(_compile(src, _USERBOOT_PAYLOAD_CXX_COPTS, ctx.executable._clangpp))
    for src in ctx.files.c_srcs:
        objs.append(_compile(src, _USERBOOT_PAYLOAD_C_COPTS, ctx.executable._clang))
    for src in ctx.files.asm_srcs:
        objs.append(_compile(src, _USERBOOT_PAYLOAD_ASM_COPTS, ctx.executable._clang))

    linker_script = ctx.file.linker_script
    userboot_elf = ctx.actions.declare_file("userboot.elf")
    link_args = ctx.actions.args()
    link_args.add("--shared")
    link_args.add("--no-dynamic-linker")
    link_args.add("--build-id=sha1")
    link_args.add("-Bsymbolic")
    link_args.add("--gc-sections")
    link_args.add("-z", "max-page-size=4096")
    link_args.add("-z", "stack-size=0x100000")
    link_args.add("-T", linker_script)
    link_args.add("--entry=_start")
    link_args.add("--export-dynamic-symbol=__cfi_check")
    link_args.add("-o", userboot_elf)
    link_args.add_all(objs)
    ctx.actions.run(
        executable = ctx.executable._ld,
        arguments = [link_args],
        inputs = depset(objs + [linker_script]),
        outputs = [userboot_elf],
        mnemonic = "UserbootLink",
        progress_message = "Linking userboot",
    )

    userboot = ctx.actions.declare_file("userboot")
    strip_args = ctx.actions.args()
    strip_args.add("--strip-sections")
    strip_args.add(userboot_elf)
    strip_args.add(userboot)
    ctx.actions.run(
        executable = ctx.executable._objcopy,
        arguments = [strip_args],
        inputs = [userboot_elf],
        outputs = [userboot],
        mnemonic = "UserbootStrip",
        progress_message = "Stripping userboot",
    )
    return [DefaultInfo(files = depset([userboot]))]

userboot_payload = rule(
    implementation = _userboot_payload_impl,
    attrs = {
        "cxx_srcs": attr.label_list(allow_files = True),
        "c_srcs": attr.label_list(allow_files = True),
        "asm_srcs": attr.label_list(allow_files = True),
        "linker_script": attr.label(allow_single_file = True, mandatory = True),
        "hdrs": attr.label_list(allow_files = True),
        "_clangpp": attr.label(
            default = "//toolchain:prebuilt_clang_pp",
            executable = True,
            cfg = "exec",
        ),
        "_clang": attr.label(
            default = "//toolchain:prebuilt_clang",
            executable = True,
            cfg = "exec",
        ),
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
        "_libcxx_hdrs": attr.label(
            default = "@@llvm++llvm+llvm-project//libcxx:libcxx_headers_include_search_directory",
        ),
        "_glibc_hdrs": attr.label(
            default = "@@llvm++glibc+glibc_headers_x86_64-linux-gnu.2.28//:glibc_headers_directory",
        ),
        "_linux_kernel_hdrs": attr.label(
            default = "@@llvm++kernel_headers+linux_kernel_headers_x86.4.19.325//:kernel_headers_directory",
        ),
    },
)

zircon_vdso = rule(
    implementation = _zircon_vdso_impl,
    attrs = {
        "cxx_srcs": attr.label_list(allow_files = True),
        "asm_srcs": attr.label_list(allow_files = True),
        "linker_script": attr.label(allow_single_file = True, mandatory = True),
        "syscall_headers": attr.label(mandatory = True),
        # Header filegroups for sandboxing (include dirs are workspace-relative, so
        # headers declared here are symlinked into the sandbox at their real paths).
        "hdrs": attr.label_list(allow_files = True),
        "_clangpp": attr.label(
            default = "//toolchain:prebuilt_clang_pp",
            executable = True,
            cfg = "exec",
        ),
        "_clang": attr.label(
            default = "//toolchain:prebuilt_clang",
            executable = True,
            cfg = "exec",
        ),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
        "_nm": attr.label(
            default = "//toolchain:llvm_nm",
            executable = True,
            cfg = "exec",
        ),
        "_readelf": attr.label(
            default = "@llvm-project//llvm:llvm-readelf",
            executable = True,
            cfg = "exec",
        ),
        "_libcxx_hdrs": attr.label(
            default = "@@llvm++llvm+llvm-project//libcxx:libcxx_headers_include_search_directory",
        ),
        "_glibc_hdrs": attr.label(
            default = "@@llvm++glibc+glibc_headers_x86_64-linux-gnu.2.28//:glibc_headers_directory",
        ),
        "_linux_kernel_hdrs": attr.label(
            default = "@@llvm++kernel_headers+linux_kernel_headers_x86.4.19.325//:kernel_headers_directory",
        ),
        "_gen_scripts": attr.label(
            default = "//zircon/kernel/lib/userabi:vdso_generation_scripts",
        ),
    },
)

def _zircon_vdso_arm64_impl(ctx):
    libcxx_dir = ctx.attr._libcxx_hdrs[DefaultInfo].files.to_list()[0]
    glibc_dir = ctx.attr._glibc_hdrs[DefaultInfo].files.to_list()[0]
    linux_hdrs_dir = ctx.attr._linux_kernel_hdrs[DefaultInfo].files.to_list()[0]

    syscall_files = ctx.attr.syscall_headers[DefaultInfo].files.to_list()
    syscall_gen_path = syscall_files[0].dirname[:-len("/lib/syscalls")]

    system_hdrs = [libcxx_dir, glibc_dir, linux_hdrs_dir] + syscall_files
    workspace_hdrs = ctx.files.hdrs

    def _compile(src, copts, compiler):
        obj_name = src.path.replace("/", "_").replace(".", "_") + ".o"
        obj = ctx.actions.declare_file("vdso_arm64_objs/{}".format(obj_name))
        args = ctx.actions.args()
        args.add_all(copts)
        args.add("-isystem", libcxx_dir.path)
        args.add("-isystem", glibc_dir.path)
        args.add("-isystem", linux_hdrs_dir.path)
        args.add("-I", syscall_gen_path)
        for inc in _VDSO_ARM64_WORKSPACE_INCLUDE_DIRS:
            args.add("-I", inc)
        args.add("-c", src)
        args.add("-o", obj)
        ctx.actions.run(
            executable = compiler,
            arguments = [args],
            inputs = depset([src] + system_hdrs + workspace_hdrs),
            outputs = [obj],
            mnemonic = "VDsoArm64Compile",
            progress_message = "Compiling arm64 vDSO {}".format(src.basename),
        )
        return obj

    objs = []
    for src in ctx.files.cxx_srcs:
        objs.append(_compile(src, _VDSO_ARM64_ELF_CXX_COPTS, ctx.executable._clangpp))
    for src in ctx.files.asm_srcs:
        objs.append(_compile(src, _VDSO_ARM64_ELF_ASM_COPTS, ctx.executable._clang))

    linker_script = ctx.file.linker_script
    libzircon = ctx.actions.declare_file("arm64/libzircon.so")
    link_args = ctx.actions.args()
    link_args.add("--shared")
    link_args.add("-soname", "libzircon.so")
    link_args.add("-e", "_zx_process_exit")
    link_args.add("-z", "max-page-size=4096")
    link_args.add("-z", "separate-code")
    link_args.add("-z", "rodynamic")
    link_args.add("--gc-sections")
    link_args.add("--build-id=sha1")
    link_args.add("-o", libzircon)
    link_args.add_all(objs)
    link_args.add(linker_script)
    ctx.actions.run(
        executable = ctx.executable._ld,
        arguments = [link_args],
        inputs = depset(objs + [linker_script]),
        outputs = [libzircon],
        mnemonic = "VDsoArm64Link",
        progress_message = "Linking arm64 libzircon.so",
    )

    return [DefaultInfo(files = depset([libzircon]))]

zircon_vdso_arm64 = rule(
    implementation = _zircon_vdso_arm64_impl,
    attrs = {
        "cxx_srcs": attr.label_list(allow_files = True),
        "asm_srcs": attr.label_list(allow_files = True),
        "linker_script": attr.label(allow_single_file = True, mandatory = True),
        "syscall_headers": attr.label(mandatory = True),
        "hdrs": attr.label_list(allow_files = True),
        "_clangpp": attr.label(
            default = "//toolchain:prebuilt_clang_pp",
            executable = True,
            cfg = "exec",
        ),
        "_clang": attr.label(
            default = "//toolchain:prebuilt_clang",
            executable = True,
            cfg = "exec",
        ),
        "_ld": attr.label(
            default = "//toolchain:prebuilt_ld_lld",
            executable = True,
            cfg = "exec",
        ),
        "_libcxx_hdrs": attr.label(
            default = "@@llvm++llvm+llvm-project//libcxx:libcxx_headers_include_search_directory",
        ),
        "_glibc_hdrs": attr.label(
            default = "@@llvm++glibc+glibc_headers_aarch64-linux-gnu.2.28//:glibc_headers_directory",
        ),
        "_linux_kernel_hdrs": attr.label(
            default = "@@llvm++kernel_headers+linux_kernel_headers_arm64.4.19.325//:kernel_headers_directory",
        ),
    },
)
