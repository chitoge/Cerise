"""Rust toolchain manifest rule — generates a JSON summary of a Rust
toolchain target for policy enforcement testing.

The manifest captures edition, target_triple, and extra_rustc_flags.
Any drift from the committed golden breaks the flag_manifest_golden_test,
enforcing the policy that per-rule rustc_flags never appear in BUILD files.

Usage:
    rust_toolchain_manifest(
        name = "cerise_rust_x64_user_manifest",
        toolchain = "@rust_linux_x86_64__x86_64-unknown-none__stable_tools//:rust_toolchain",
    )
"""

def _rust_toolchain_manifest_impl(ctx):
    tc = ctx.attr.toolchain[platform_common.ToolchainInfo]
    manifest = ctx.actions.declare_file(ctx.label.name + ".json")
    target_triple = tc.target_triple.str if tc.target_triple else ""
    content = json.encode_indent(
        {
            "default_edition": tc.default_edition,
            "extra_exec_rustc_flags": tc.extra_exec_rustc_flags,
            "extra_rustc_flags": tc.extra_rustc_flags,
            "target_triple": target_triple,
        },
        indent = "\t",
    )
    ctx.actions.write(manifest, content + "\n")
    return [DefaultInfo(files = depset([manifest]))]

rust_toolchain_manifest = rule(
    implementation = _rust_toolchain_manifest_impl,
    attrs = {
        "toolchain": attr.label(
            mandatory = True,
            providers = [platform_common.ToolchainInfo],
            doc = "The rust_toolchain target to generate a manifest for.",
        ),
    },
    doc = "Generate a JSON manifest of a Rust toolchain configuration.",
)
