"""Starlark rule for linking a UEFI EFI binary (.efi) from cc_library deps.

Compiles deps under the x64-efi platform (x86_64-unknown-uefi toolchain with
lld-link), then links the resulting COFF archives into a PE/COFF EFI application.
Mirrors the structure of zircon_physload in phys_rules.bzl.
"""

load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _x64_efi_transition_impl(settings, attr):
    return {"//command_line_option:platforms": "//platforms:x64-efi"}

_x64_efi_transition = transition(
    implementation = _x64_efi_transition_impl,
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

def _zircon_efi_binary_impl(ctx):
    libs = _collect_static_libs(ctx.attr.deps)
    efi = ctx.actions.declare_file(ctx.label.name + ".efi")

    args = ctx.actions.args()
    args.add("/subsystem:efi_application")
    args.add("/entry:EfiMain")
    args.add("/nodefaultlib")
    args.add("/debug:dwarf")
    # PE/COFF timestamps are part of the image bytes. `/Brepro` replaces the
    # wall-clock value with a hash of the image, including the debug directory
    # timestamp, so content-addressed EFI fixtures remain stable on rebuild.
    args.add("/Brepro")
    args.add("/out:" + efi.path)
    # /wholearchive pulls in all symbols from static archives, matching
    # alwayslink = True semantics used by phys and other freestanding libs.
    args.add("/wholearchive")
    args.add_all(libs)

    ctx.actions.run(
        outputs = [efi],
        inputs = depset(libs),
        executable = ctx.executable._lld_link,
        arguments = [args],
        mnemonic = "EfiLink",
        progress_message = "Linking EFI binary %{output}",
    )

    return [DefaultInfo(files = depset([efi]))]

zircon_efi_binary = rule(
    implementation = _zircon_efi_binary_impl,
    attrs = {
        "deps": attr.label_list(providers = [CcInfo], cfg = _x64_efi_transition),
        "_lld_link": attr.label(
            default = "//toolchain:prebuilt_lld_link",
            executable = True,
            cfg = "exec",
        ),
    },
)
