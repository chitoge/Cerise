"""QEMU boot validation test rule."""

load("//bazel:providers.bzl", "QemuBootTestInfo")

def _runfiles_path(file):
    parts = []
    for part in file.short_path.split("/"):
        if part == "..":
            continue
        parts.append(part)
    return "/".join(parts)

def _qemu_boot_test_impl(ctx):
    executable = ctx.actions.declare_file(ctx.label.name)

    serial_log = _runfiles_path(ctx.file.serial_log)
    markers_json = _runfiles_path(ctx.file.markers)
    runner_path = _runfiles_path(ctx.file._runner)
    image_path = None
    if ctx.file.image:
        image_path = _runfiles_path(ctx.file.image)

    # on the FAILURE path only, pipe the serial log through
    # //src/cerise/tools/symbolize against the product's .build-id store so the
    # test output ends with a symbolized backtrace, not raw {{{bt}}} hex. Both are
    # optional and must be supplied together; the pass path is untouched.
    symbolizer_path = ""
    build_id_dir = ""
    llvm_symbolizer_path = ""
    if ctx.executable.symbolizer:
        symbolizer_path = _runfiles_path(ctx.executable.symbolizer)
        # The symbolize tool shells out to llvm-symbolizer; the sandbox has no PATH
        # to it, so resolve it here and pass it explicitly.
        llvm_symbolizer_path = _runfiles_path(ctx.file._llvm_symbolizer)
    if ctx.file.build_id_store:
        build_id_dir = _runfiles_path(ctx.file.build_id_store)

    ctx.actions.write(
        output = executable,
        is_executable = True,
        content = (
            """#!/bin/sh
set -eu

serial_log="__SERIAL_LOG__"
markers_json="__MARKERS_JSON__"
image_path="__IMAGE_PATH__"
runner="__RUNNER__"
symbolizer="__SYMBOLIZER__"
build_id_store="__BUILD_ID_STORE__"
llvm_symbolizer="__LLVM_SYMBOLIZER__"
default_report="${TEST_UNDECLARED_OUTPUTS_DIR:-.}/__REPORT_NAME__"

exec python3 "$runner" \
  --serial-log "$serial_log" \
  --markers-json "$markers_json" \
  --report "$default_report" \
  --image "$image_path" \
  --symbolizer "$symbolizer" \
  --build-id-store "$build_id_store" \
  --llvm-symbolizer "$llvm_symbolizer" \
  "$@"
"""
            .replace("__SERIAL_LOG__", serial_log)
            .replace("__MARKERS_JSON__", markers_json)
            .replace("__IMAGE_PATH__", image_path or "")
            .replace("__RUNNER__", runner_path)
            .replace("__SYMBOLIZER__", symbolizer_path)
            .replace("__BUILD_ID_STORE__", build_id_dir)
            .replace("__LLVM_SYMBOLIZER__", llvm_symbolizer_path)
            .replace("__REPORT_NAME__", ctx.label.name + ".report.json")
        ),
    )

    runfiles = ctx.runfiles(
        files = [ctx.file.serial_log, ctx.file.markers, ctx.file._runner],
    )
    if ctx.file.image:
        runfiles = runfiles.merge(ctx.runfiles(files = [ctx.file.image]))
    if ctx.executable.symbolizer:
        runfiles = runfiles.merge(ctx.attr.symbolizer[DefaultInfo].default_runfiles)
        runfiles = runfiles.merge(ctx.runfiles(files = [ctx.executable.symbolizer]))
        runfiles = runfiles.merge(ctx.runfiles(files = [ctx.file._llvm_symbolizer]))
    if ctx.file.build_id_store:
        runfiles = runfiles.merge(ctx.runfiles(files = [ctx.file.build_id_store]))

    return [
        DefaultInfo(
            executable = executable,
            files = depset([executable]),
            runfiles = runfiles,
        ),
        QemuBootTestInfo(
            serial_log = ctx.file.serial_log,
            report = ctx.label.name + ".report.json",
            exit_reason = "unknown",
        ),
    ]

qemu_boot_test = rule(
    implementation = _qemu_boot_test_impl,
    test = True,
    attrs = {
        "serial_log": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "markers": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "image": attr.label(
            allow_single_file = True,
            mandatory = False,
        ),
        "symbolizer": attr.label(
            executable = True,
            cfg = "exec",
            mandatory = False,
            doc = "Optional //src/cerise/tools/symbolize host tool; on the failure " +
                  "path the serial log is piped through it. Pass together " +
                  "with build_id_store.",
        ),
        "build_id_store": attr.label(
            allow_single_file = True,
            mandatory = False,
            doc = "Optional cerise_debug_symbols store directory (contains .build-id/); " +
                  "the symbolizer resolves module frames against it.",
        ),
        "_llvm_symbolizer": attr.label(
            default = "//toolchain:llvm_symbolizer",
            allow_single_file = True,
            doc = "llvm-symbolizer the symbolize tool shells out to (no PATH in the sandbox).",
        ),
        "_runner": attr.label(
            default = "//bazel:qemu_boot_test_runner.py",
            allow_single_file = True,
        ),
    },
)
