"""Executable wrapper rule that preserves a raw prebuilt tool path plus runfiles."""

def _runfiles_path(file):
    parts = []
    for part in file.short_path.split("/"):
        if part == "..":
            continue
        parts.append(part)
    return "/".join(parts)

def _raw_executable_tool_impl(ctx):
    executable = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.write(
        output = executable,
        is_executable = True,
        content = "#!/bin/sh\nexec \"$0.runfiles/{src}\" \"$@\"\n".format(
            src = _runfiles_path(ctx.file.src),
        ),
    )

    transitive_files = [ctx.attr.src[DefaultInfo].files]
    for dep in ctx.attr.data:
        transitive_files.append(dep[DefaultInfo].files)

    runfiles = ctx.runfiles(
        files = [executable],
        transitive_files = depset(transitive = transitive_files),
    )

    for dep in [ctx.attr.src] + ctx.attr.data:
        runfiles = runfiles.merge(dep[DefaultInfo].default_runfiles)

    return [
        DefaultInfo(
            files = depset([executable]),
            executable = executable,
            runfiles = runfiles,
        ),
    ]

raw_executable_tool = rule(
    implementation = _raw_executable_tool_impl,
    executable = True,
    attrs = {
        "src": attr.label(
            allow_single_file = True,
            cfg = "exec",
            mandatory = True,
        ),
        "data": attr.label_list(
            allow_files = True,
            cfg = "exec",
        ),
    },
)