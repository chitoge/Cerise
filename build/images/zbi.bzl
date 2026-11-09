"""zbi_image: Starlark-native ZBI container assembly rule.

Wraps tools/zbi/simple_zbi.py as a sandboxed ctx.actions.run_shell action
so the image assembly layer is genrule-free (requirement).

The ZBI action itself is registered by the shared `emit_zbi` helper in
//bazel:zbi_assembly.bzl, which the composition-layer `cerise_product` rule
also uses — one code path from (cmdline, mem_config, bootfs) to a ZBI.
"""

load("//bazel:zbi_assembly.bzl", "emit_zbi")

def _zbi_image_impl(ctx):
    output = ctx.actions.declare_file(ctx.attr.name + ".zbi")

    # Use ctx.attr (list of Target) instead of ctx.files (depset) to avoid
    # Bazel deduplicating entries that share an underlying file (e.g. when
    # the same library appears in both pkg/<name>/lib/ and top-level lib/).
    extra_src_targets = ctx.attr.extra_bootfs_srcs
    dests = ctx.attr.extra_bootfs_dests
    extra_src_files = [t.files.to_list()[0] for t in extra_src_targets]

    emit_zbi(
        ctx,
        output = output,
        input_zbi_files = ctx.files.input_zbis,
        simple_zbi_file = ctx.file._simple_zbi,
        cmdline = ctx.attr.cmdline,
        mem_config = ctx.attr.mem_config,
        dests = dests,
        src_files = extra_src_files,
        nvram = ctx.attr.nvram,
    )
    return [DefaultInfo(files = depset([output]))]

zbi_image = rule(
    implementation = _zbi_image_impl,
    attrs = {
        "input_zbis": attr.label_list(
            allow_files = True,
            doc = "Input ZBI containers to merge in order.",
        ),
        "cmdline": attr.string_list(
            default = [],
            doc = "Extra kernel cmdline items to append as CMDLINE items.",
        ),
        "mem_config": attr.string_list(
            default = [],
            doc = "Memory config items as PADDR,SIZE,TYPE strings (hex or decimal); generates ZBI_TYPE_MEM_CONFIG items.",
        ),
        "nvram": attr.string_list(
            default = [],
            doc = "Persistent-RAM regions as BASE,SIZE strings (hex or decimal); generates ZBI_TYPE_NVRAM items (ram-crashlog / warm-reboot survival region).",
        ),
        "extra_bootfs_dests": attr.string_list(
            default = [],
            doc = "Bootfs destination paths for extra_bootfs_srcs (parallel list).",
        ),
        "extra_bootfs_srcs": attr.label_list(
            allow_files = True,
            default = [],
            doc = "Source files to add to STORAGE_BOOTFS (parallel to extra_bootfs_dests).",
        ),
        "_simple_zbi": attr.label(
            default = "//tools/zbi:simple_zbi.py",
            allow_single_file = True,
        ),
    },
    doc = "Assemble a ZBI image from input ZBI containers and optional cmdline items.",
)
