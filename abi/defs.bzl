load("//bazel:providers.bzl", "ZirconAbiInfo")


def _zircon_abi_boundary_impl(ctx):
    manifest = ctx.actions.declare_file(ctx.label.name + ".json")
    fidl_list = ctx.actions.declare_file(ctx.label.name + ".fidl_list.txt")
    header_list = ctx.actions.declare_file(ctx.label.name + ".headers_list.txt")
    fidlc_response = ctx.actions.declare_file(ctx.label.name + ".fidlc.rsp")
    library_manifest = ctx.actions.declare_file(ctx.label.name + ".libraries.json")
    staged_fidl = ctx.actions.declare_directory(ctx.label.name + ".fidl_inputs")
    staged_headers = ctx.actions.declare_directory(ctx.label.name + ".public_headers")

    args = ctx.actions.args()
    args.add(ctx.file._script.path)
    args.add("--manifest", manifest.path)
    args.add("--fidl-list", fidl_list.path)
    args.add("--header-list", header_list.path)
    args.add("--fidlc-response", fidlc_response.path)
    args.add("--library-manifest", library_manifest.path)
    args.add("--staged-fidl-dir", staged_fidl.path)
    args.add("--staged-header-dir", staged_headers.path)
    args.add("--main-library", ctx.attr.main_library)
    args.add_all(ctx.files.fidl_sources, before_each = "--fidl")
    args.add_all(ctx.files.public_headers, before_each = "--header")

    inputs = depset(direct = [ctx.file._script] + ctx.files.fidl_sources + ctx.files.public_headers)

    ctx.actions.run_shell(
        inputs = inputs,
        outputs = [manifest, fidl_list, header_list, fidlc_response, library_manifest, staged_fidl, staged_headers],
        arguments = [args],
        command = "/usr/bin/python3 \"$@\"",
        mnemonic = "ZirconAbiBoundary",
        progress_message = "Generating ABI boundary for {}".format(ctx.label.name),
    )

    return [
        DefaultInfo(files = depset([
            manifest,
            fidl_list,
            header_list,
            fidlc_response,
            library_manifest,
            staged_fidl,
            staged_headers,
        ])),
        OutputGroupInfo(
            manifest = depset([manifest]),
            ordered_fidl = depset([fidl_list]),
            ordered_headers = depset([header_list]),
            fidlc_response = depset([fidlc_response]),
            library_manifest = depset([library_manifest]),
            staged_fidl = depset([staged_fidl]),
            staged_headers = depset([staged_headers]),
        ),
        ZirconAbiInfo(
            headers = depset(ctx.files.public_headers),
            manifest = manifest,
            vdso_inputs = depset([fidlc_response, library_manifest, staged_fidl, staged_headers]),
            fidlc_response = fidlc_response,
            library_manifest = library_manifest,
            staged_fidl = staged_fidl,
            staged_headers = staged_headers,
        ),
    ]


zircon_abi_boundary = rule(
    implementation = _zircon_abi_boundary_impl,
    attrs = {
        "fidl_sources": attr.label_list(allow_files = True, mandatory = True),
        "main_library": attr.string(mandatory = True),
        "public_headers": attr.label_list(allow_files = True, mandatory = True),
        "_script": attr.label(
            allow_single_file = True,
            default = "//abi:make_manifest.py",
        ),
    },
)

zircon_abi_manifest = zircon_abi_boundary


def _zircon_abi_fidl_ir_impl(ctx):
    abi = ctx.attr.abi[ZirconAbiInfo]
    fidl_ir = ctx.actions.declare_file(ctx.attr.output_name)
    merged_response = ctx.actions.declare_file(ctx.label.name + ".fidlc.rsp")

    ctx.actions.run_shell(
        inputs = depset([
            abi.fidlc_response,
            abi.staged_fidl,
        ]),
        outputs = [fidl_ir, merged_response],
        tools = [ctx.executable.fidlc],
        arguments = [
            fidl_ir.path,
            merged_response.path,
            abi.fidlc_response.path,
            abi.staged_fidl.path,
            ctx.executable.fidlc.path,
        ],
        command = """
set -euo pipefail

    exec_root="$PWD"
    fidl_ir="$exec_root/$1"
    merged_response="$exec_root/$2"
    boundary_response="$exec_root/$3"
    staged_fidl_dir="$exec_root/$4"
    fidlc="$exec_root/$5"

{
  printf '%s\n%s\n' --json "$fidl_ir"
    printf '%s\n' --available fuchsia:HEAD
    printf '%s\n%s\n' --experimental zx_c_types
  cat "$boundary_response"
} > "$merged_response"

cd "$staged_fidl_dir"
"$fidlc" @"$merged_response"
""",
        mnemonic = "ZirconAbiFidlIr",
        progress_message = "Generating ABI FIDL IR for {}".format(ctx.label.name),
    )

    return [
        DefaultInfo(files = depset([fidl_ir])),
        OutputGroupInfo(
            fidl_ir = depset([fidl_ir]),
            fidlc_response = depset([merged_response]),
        ),
    ]


zircon_abi_fidl_ir = rule(
    implementation = _zircon_abi_fidl_ir_impl,
    attrs = {
        "abi": attr.label(mandatory = True, providers = [ZirconAbiInfo]),
        "fidlc": attr.label(
            executable = True,
            cfg = "exec",
            mandatory = True,
        ),
        "output_name": attr.string(default = "zx.fidl.json"),
    },
)


def _zircon_abi_zither_kernel_sources_impl(ctx):
    abi = ctx.attr.abi[ZirconAbiInfo]
    output_root = ctx.label.name + ".gen"
    manifest = ctx.actions.declare_file(output_root + "/outputs.json")
    generated_files = [
        ctx.actions.declare_file(output_root + "/lib/syscalls/category.inc"),
        ctx.actions.declare_file(output_root + "/lib/syscalls/kernel.inc"),
        ctx.actions.declare_file(output_root + "/lib/syscalls/kernel-wrappers.inc"),
        ctx.actions.declare_file(output_root + "/lib/syscalls/syscalls.inc"),
        ctx.actions.declare_file(output_root + "/lib/syscalls/zx-syscall-numbers.h"),
    ]

    args = ctx.actions.args()
    args.add("-ir", ctx.file.fidl_ir.path)
    args.add("-source-dir", abi.staged_fidl.path)
    args.add("-output-dir", manifest.dirname)
    args.add("-output-manifest", manifest.path)

    ctx.actions.run(
        inputs = depset([ctx.file.fidl_ir, abi.staged_fidl]),
        outputs = generated_files + [manifest],
        executable = ctx.executable.zither,
        arguments = [args],
        mnemonic = "ZirconAbiZitherKernel",
        progress_message = "Generating zither kernel syscall headers for {}".format(ctx.label.name),
    )

    return [
        DefaultInfo(files = depset(generated_files)),
        OutputGroupInfo(
            headers = depset(generated_files),
            manifest = depset([manifest]),
        ),
    ]


zircon_abi_zither_kernel_sources = rule(
    implementation = _zircon_abi_zither_kernel_sources_impl,
    attrs = {
        "abi": attr.label(mandatory = True, providers = [ZirconAbiInfo]),
        "fidl_ir": attr.label(allow_single_file = True, mandatory = True),
        "zither": attr.label(
            executable = True,
            cfg = "exec",
            mandatory = True,
        ),
    },
)
