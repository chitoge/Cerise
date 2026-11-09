"""Cerise measure-tape codegen rule (Phase 2 logging: Archivist).

Reproduces upstream Fuchsia's `measure_tape()` GN template
(//tools/fidl/measure-tape/measure_tape.gni) for the `rust` target binding as a
Bazel rule. It runs the vendored measure-tape host tool over one or more FIDL
libraries' JSON IR to emit a Rust module that computes the exact max-encoded
("measuring tape") size of the requested target types. Archivist uses this for
fuchsia.logger/LogMessage buffer sizing.

The emitted `.rs` is wrapped in a `rust_library` by the caller (deps: the FIDL
Rust bindings for the measured libraries, `fidl`, and `zx-types`), mirroring the
`rustc_library` the gni's rust branch declares.
"""

load("//build/fidl:fidl.bzl", "FidlInfo")

def _measure_tape_rust_impl(ctx):
    out_rs = ctx.actions.declare_file(ctx.label.name + ".rs")

    args = ctx.actions.args()
    args.add("--target-binding", "rust")
    args.add("--out-rs", out_rs.path)
    for t in ctx.attr.target_types:
        args.add("--target-types", t)

    irs = [dep[FidlInfo].ir for dep in ctx.attr.fidls]
    for ir in irs:
        args.add("--json", ir.path)

    ctx.actions.run(
        executable = ctx.executable._measure_tape,
        arguments = [args],
        inputs = irs,
        outputs = [out_rs],
        mnemonic = "MeasureTapeRust",
        progress_message = "Generating measure-tape Rust module %s" % ctx.label.name,
    )
    return [DefaultInfo(files = depset([out_rs]))]

measure_tape_rust = rule(
    implementation = _measure_tape_rust_impl,
    attrs = {
        # FIDL libraries (fidl_library targets) whose IR to feed the tool. One
        # `--json` is emitted per dep, mirroring the gni's `foreach(fidl, fidls)`.
        "fidls": attr.label_list(providers = [FidlInfo], mandatory = True),
        # Fully-qualified FIDL types to measure, e.g. "fuchsia.logger/LogMessage".
        "target_types": attr.string_list(mandatory = True),
        "_measure_tape": attr.label(
            default = "//src/upstream/fuchsia/tools/fidl/measure-tape/src:measure-tape",
            executable = True,
            cfg = "exec",
        ),
    },
)
