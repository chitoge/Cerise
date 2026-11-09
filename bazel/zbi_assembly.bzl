"""emit_zbi: the shared ZBI-assembly action helper.

Both the low-level `zbi_image` rule (build/images/zbi.bzl, driven by the legacy
`zircon_system` macro) and the composition-layer `cerise_product` rule
(assembly/defs.bzl) register the exact same `tools/zbi/simple_zbi.py` action
through this one function, so there is a single place that knows how to turn a
(cmdline, mem_config, bootfs) triple into a bootable ZBI.

The action construction here is byte-for-byte identical to the original inline
body in zbi_image, so existing ZBIs are unperturbed by the refactor.
"""

def emit_zbi(
        ctx,
        output,
        input_zbi_files,
        simple_zbi_file,
        cmdline,
        mem_config,
        dests,
        src_files,
        kernel_drivers = [],
        zstd_tool = None,
        nvram = []):
    """Register a simple_zbi.py action that assembles `output`.

    Args:
      ctx:             the calling rule's ctx (used for ctx.actions).
      output:          the declared ZBI output File.
      input_zbi_files: list[File] of input ZBI containers, merged in order.
      simple_zbi_file: the simple_zbi.py File.
      cmdline:         list[str] of kernel cmdline items to append.
      mem_config:      list[str] of PADDR,SIZE,TYPE memory-config items.
      dests:           list[str] bootfs destination paths (parallel to src_files).
      src_files:       list[File] bootfs source files (parallel to dests). This is
                       a plain list, NOT a depset, so a file that is staged at two
                       destinations is emitted twice (no dedup).
      kernel_drivers:  list[str] of arch kernel-driver ZBI items ("DRIVER_TYPE=HEXPAYLOAD"),
                       BOARD DATA passed verbatim to simple_zbi.py --kernel-driver.
                       Empty (the default) emits no such item, so callers that pass
                       nothing produce byte-identical ZBIs.
      zstd_tool:       optional host zstd CLI File (//tools/zstd:zstd_cli). When
                       set, the STORAGE_BOOTFS payload is zstd-compressed
                       (ZBI_FLAGS_STORAGE_COMPRESSED); userboot decompresses it at
                       runtime. None (the default) => raw bootfs, byte-identical to
                       before. Callers gate this per-arch (x86_64 only today; arm64
                       userboot zstd is unverified and has no boot gate).
      nvram:           list[str] of "BASE,SIZE" persistent-RAM regions emitted as
                       ZBI_TYPE_NVRAM items (the ram-crashlog / warm-reboot survival
                       region). Empty (the default) emits no such item, so callers
                       that pass nothing produce byte-identical ZBIs.
    """
    if len(dests) != len(src_files):
        fail("emit_zbi: dests and src_files must have the same length (%d vs %d)" %
             (len(dests), len(src_files)))

    args = ctx.actions.args()
    args.add("--output", output)
    for src in input_zbi_files:
        args.add("--input-zbi", src)
    for cmdline_str in cmdline:
        args.add("--cmdline", cmdline_str)
    for mem_config_str in mem_config:
        args.add("--mem-config", mem_config_str)
    for kernel_driver_str in kernel_drivers:
        args.add("--kernel-driver", kernel_driver_str)
    for nvram_str in nvram:
        args.add("--nvram", nvram_str)
    for dest, src in zip(dests, src_files):
        args.add("--bootfs-file", dest + "=" + src.path)

    tool_inputs = []
    if zstd_tool:
        args.add("--compress-bootfs")
        args.add("--zstd-tool", zstd_tool.path)
        tool_inputs = [zstd_tool]

    ctx.actions.run_shell(
        inputs = input_zbi_files + [simple_zbi_file] + src_files + tool_inputs,
        outputs = [output],
        command = "python3 " + simple_zbi_file.path + ' "$@"',
        arguments = [args],
        mnemonic = "ZbiImage",
        progress_message = "Assembling ZBI " + output.short_path,
    )
