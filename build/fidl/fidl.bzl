"""Cerise FIDL build rules.

fidl_library runs fidlc to produce a library's JSON IR. FIDL libraries form a DAG
(a library imports others), and fidlc compiles a library together with all its
transitive dependency sources: each library is one `--files` group, dependencies
first, the library itself last (its IR is what gets emitted). FidlInfo propagates
the transitive set of (library -> .fidl files) so dependents pass them through.

fidl_cpp runs fidlgen_cpp on a fidl_library's IR to generate the C++ wire+natural
bindings, then compiles them (cc_common) against the FIDL C++ binding runtime,
exposing a CcInfo dependents can link.

fidl_rust runs fidlgen_rust on a fidl_library's IR to produce a single generated
.rs source file. The caller wraps it in a rust_library with deps on the FIDL
Rust runtime.
"""

load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain")

FidlInfo = provider(
    doc = "A compiled FIDL library: its JSON IR + transitive source groups.",
    fields = {
        "ir": "The JSON IR File for this library.",
        "lib_groups": "depset of structs(files=[.fidl Files]) in dependency order.",
    },
)

def _fidl_library_impl(ctx):
    ir = ctx.actions.declare_file(ctx.label.name + ".fidl.json")

    # Transitive dependency source groups (deps first), then this library last.
    dep_groups = depset(
        direct = [struct(files = tuple(ctx.files.srcs))],
        transitive = [d[FidlInfo].lib_groups for d in ctx.attr.deps],
        order = "postorder",  # deps before self
    )
    groups = dep_groups.to_list()

    args = ctx.actions.args()
    args.add("--json", ir)
    # Fuchsia FIDL libraries are versioned (@available). The default level is 30:
    # symbols zxio/fdio use (e.g. fuchsia.io's OnOpen, @available(removed=NEXT))
    # still exist at 30 but are removed at NEXT/HEAD. Libraries whose own FIDL is
    # @available(added=HEAD) (e.g. fuchsia.component.internal) override this with
    # available = "fuchsia:HEAD" in their fidl_library rule.
    args.add("--available", ctx.attr.available)
    # The zx library (imported transitively by ~all fuchsia.* libraries) uses
    # experimental C types (experimental_pointer, usize64).
    args.add("--experimental", "zx_c_types")
    for g in groups:
        args.add("--files")
        args.add_all(g.files)

    dep_files = depset(
        direct = ctx.files.srcs,
        transitive = [depset([f for g in d[FidlInfo].lib_groups.to_list() for f in g.files]) for d in ctx.attr.deps],
    )
    ctx.actions.run(
        executable = ctx.executable._fidlc,
        arguments = [args],
        inputs = dep_files,
        outputs = [ir],
        mnemonic = "Fidlc",
        progress_message = "Compiling FIDL library %s" % ctx.label.name,
    )
    return [
        DefaultInfo(files = depset([ir])),
        FidlInfo(ir = ir, lib_groups = dep_groups),
    ]

fidl_library = rule(
    implementation = _fidl_library_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = [".fidl"], mandatory = True),
        "deps": attr.label_list(providers = [FidlInfo]),
        # API level passed to fidlc --available. Defaults to 30 (keeps OnOpen
        # in fuchsia.io for C++ zxio). Set to "fuchsia:HEAD" for libraries
        # whose FIDL is entirely @available(added=HEAD).
        "available": attr.string(default = "fuchsia:30"),
        "_fidlc": attr.label(
            default = "//src/upstream/fuchsia/tools/fidl/fidlc:fidlc",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _fidl_cpp_impl(ctx):
    info = ctx.attr.library[FidlInfo]
    gen = ctx.actions.declare_directory(ctx.label.name + "_gen")

    args = ctx.actions.args()
    args.add("-json", info.ir)
    args.add("-root", gen.path)
    ctx.actions.run(
        executable = ctx.executable._fidlgen_cpp,
        arguments = [args],
        inputs = [info.ir],
        outputs = [gen],
        mnemonic = "FidlgenCpp",
        progress_message = "Generating C++ FIDL bindings for %s" % ctx.label.name,
    )

    cc_toolchain = find_cc_toolchain(ctx)
    feature_configuration = cc_common.configure_features(
        ctx = ctx,
        cc_toolchain = cc_toolchain,
        requested_features = ctx.features,
        unsupported_features = ctx.disabled_features,
    )
    dep_ccinfos = [d[CcInfo] for d in ctx.attr.deps] + [ctx.attr._fidl_driver[CcInfo]]
    (comp_ctx, comp_out) = cc_common.compile(
        name = ctx.label.name,
        actions = ctx.actions,
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
        srcs = [gen],
        public_hdrs = [gen],
        includes = [gen.path],
        compilation_contexts = [d.compilation_context for d in dep_ccinfos],
    )
    (link_ctx, _link_out) = cc_common.create_linking_context_from_compilation_outputs(
        name = ctx.label.name,
        actions = ctx.actions,
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
        compilation_outputs = comp_out,
        linking_contexts = [d.linking_context for d in dep_ccinfos],
        # FIDL wire/natural bindings are out-of-line template instantiations
        # (wire_messaging.cc etc.) pulled in only when a consumer references them;
        # alwayslink so the generated method bodies reach the final executable.
        alwayslink = True,
    )
    return [
        DefaultInfo(files = depset([gen])),
        CcInfo(compilation_context = comp_ctx, linking_context = link_ctx),
    ]

fidl_cpp = rule(
    implementation = _fidl_cpp_impl,
    attrs = {
        "library": attr.label(providers = [FidlInfo], mandatory = True),
        "deps": attr.label_list(providers = [CcInfo]),
        "_fidlgen_cpp": attr.label(
            default = "//src/upstream/fuchsia/tools/fidl/fidlgen_cpp:fidlgen_cpp",
            executable = True,
            cfg = "exec",
        ),
        # The generated driver-transport bindings (driver/*Messaging) #include
        # <lib/fidl_driver/cpp/...> and reference fdf; every _cpp lib links it.
        "_fidl_driver": attr.label(
            default = "//src/upstream/fuchsia/sdk/lib/fidl_driver:fidl_driver",
            providers = [CcInfo],
        ),
    },
    toolchains = ["@bazel_tools//tools/cpp:toolchain_type"],
    fragments = ["cpp"],
)

def _fidl_hlcpp_impl(ctx):
    # HLCPP (high-level C++) bindings — the older C++ FIDL family still required by parts
    # of the DFv2 driver-component framework (e.g. fuchsia.io_hlcpp). fidlgen_hlcpp shares
    # lib/fidlgen_cpp's cmdline flags with fidlgen_cpp, so the invocation mirrors fidl_cpp.
    info = ctx.attr.library[FidlInfo]
    gen = ctx.actions.declare_directory(ctx.label.name + "_gen")

    args = ctx.actions.args()
    args.add("-json", info.ir)
    args.add("-root", gen.path)
    ctx.actions.run(
        executable = ctx.executable._fidlgen_hlcpp,
        arguments = [args],
        inputs = [info.ir],
        outputs = [gen],
        mnemonic = "FidlgenHlcpp",
        progress_message = "Generating HLCPP FIDL bindings for %s" % ctx.label.name,
    )

    cc_toolchain = find_cc_toolchain(ctx)
    feature_configuration = cc_common.configure_features(
        ctx = ctx,
        cc_toolchain = cc_toolchain,
        requested_features = ctx.features,
        unsupported_features = ctx.disabled_features,
    )
    dep_ccinfos = [d[CcInfo] for d in ctx.attr.deps]
    (comp_ctx, comp_out) = cc_common.compile(
        name = ctx.label.name,
        actions = ctx.actions,
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
        srcs = [gen],
        public_hdrs = [gen],
        includes = [gen.path],
        compilation_contexts = [d.compilation_context for d in dep_ccinfos],
    )
    (link_ctx, _link_out) = cc_common.create_linking_context_from_compilation_outputs(
        name = ctx.label.name,
        actions = ctx.actions,
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
        compilation_outputs = comp_out,
        linking_contexts = [d.linking_context for d in dep_ccinfos],
        alwayslink = True,
    )
    return [
        DefaultInfo(files = depset([gen])),
        CcInfo(compilation_context = comp_ctx, linking_context = link_ctx),
    ]

fidl_hlcpp = rule(
    implementation = _fidl_hlcpp_impl,
    attrs = {
        "library": attr.label(providers = [FidlInfo], mandatory = True),
        "deps": attr.label_list(providers = [CcInfo]),
        "_fidlgen_hlcpp": attr.label(
            default = "//src/upstream/fuchsia/tools/fidl/fidlgen_hlcpp:fidlgen_hlcpp",
            executable = True,
            cfg = "exec",
        ),
    },
    toolchains = ["@bazel_tools//tools/cpp:toolchain_type"],
    fragments = ["cpp"],
)

def _fidl_rust_impl(ctx):
    info = ctx.attr.library[FidlInfo]
    out_rs = ctx.actions.declare_file(ctx.label.name + ".fidl.rs")

    args = ctx.actions.args()
    args.add("-json", info.ir)
    args.add("-output-filename", out_rs.path)

    # Emit driver-transport (fdf) protocols too (e.g. fuchsia.driver.framework.Driver,
    # declared @transport("Driver")). The generated bindings reference the `fdf` and
    # `fidl_driver` crates, so any rust_library wrapping a fidl_rust output for a library
    # that has driver-transport protocols must depend on those crates. This is a no-op for
    # libraries without driver-transport protocols (zircon protocols are unchanged).
    args.add("-include-drivers")
    ctx.actions.run(
        executable = ctx.executable._fidlgen_rust,
        arguments = [args],
        inputs = [info.ir],
        outputs = [out_rs],
        mnemonic = "FidlgenRust",
        progress_message = "Generating Rust FIDL bindings for %s" % ctx.label.name,
    )
    return [DefaultInfo(files = depset([out_rs]))]

fidl_rust = rule(
    implementation = _fidl_rust_impl,
    attrs = {
        "library": attr.label(providers = [FidlInfo], mandatory = True),
        "_fidlgen_rust": attr.label(
            default = "//src/upstream/fuchsia/tools/fidl/fidlgen_rust:fidlgen_rust",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _fidl_banjo_c_impl(ctx):
    info = ctx.attr.library[FidlInfo]
    out_h = ctx.actions.declare_file(ctx.label.name + ".banjo.h")

    args = ctx.actions.args()
    args.add("--ir", info.ir)
    args.add("--backend", "c")
    args.add("--output", out_h.path)
    ctx.actions.run(
        executable = ctx.executable._fidlgen_banjo,
        arguments = [args],
        inputs = [info.ir],
        outputs = [out_h],
        mnemonic = "FidlgenBanjoC",
        progress_message = "Generating Banjo C bindings for %s" % ctx.label.name,
    )
    return [DefaultInfo(files = depset([out_h]))]

fidl_banjo_c = rule(
    implementation = _fidl_banjo_c_impl,
    attrs = {
        "library": attr.label(providers = [FidlInfo], mandatory = True),
        "_fidlgen_banjo": attr.label(
            default = "//src/upstream/fuchsia/src/devices/tools/fidlgen_banjo:fidlgen_banjo",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _fidl_banjo_cpp_impl(ctx):
    info = ctx.attr.library[FidlInfo]
    out_h = ctx.actions.declare_file(ctx.label.name + ".banjo.h")

    args = ctx.actions.args()
    args.add("--ir", info.ir)
    args.add("--backend", ctx.attr.backend)
    args.add("--output", out_h.path)
    ctx.actions.run(
        executable = ctx.executable._fidlgen_banjo,
        arguments = [args],
        inputs = [info.ir],
        outputs = [out_h],
        mnemonic = "FidlgenBanjoCpp",
        progress_message = "Generating Banjo %s bindings for %s" % (ctx.attr.backend, ctx.label.name),
    )
    return [DefaultInfo(files = depset([out_h]))]

# The C++ banjo "cpp" backend emits <.../cpp/banjo.h> (ddktl protocol/client classes),
# which #includes "banjo-internal.h" from the "cpp_internal" backend. So a C++ banjo
# consumer needs BOTH generated side by side. This rule generates one backend's header;
# instantiate it twice (backend="cpp" and "cpp_internal") and wrap both in one cc_library
# (with the C banjo lib + ddktl as deps). Like fidl_banjo_c, generation only — the BUILD
# does the genrule (canonical include path) + cc_library.
fidl_banjo_cpp = rule(
    implementation = _fidl_banjo_cpp_impl,
    attrs = {
        "library": attr.label(providers = [FidlInfo], mandatory = True),
        "backend": attr.string(default = "cpp", values = ["cpp", "cpp_internal", "cpp_mock"]),
        "_fidlgen_banjo": attr.label(
            default = "//src/upstream/fuchsia/src/devices/tools/fidlgen_banjo:fidlgen_banjo",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _bind_library_cpp_impl(ctx):
    out_h = ctx.actions.declare_file(ctx.label.name + ".h")
    args = ctx.actions.args()
    args.add("generate-cpp")
    args.add(ctx.file.src)
    args.add("--output", out_h.path)
    ctx.actions.run(
        executable = ctx.executable._bindc,
        arguments = [args],
        inputs = [ctx.file.src],
        outputs = [out_h],
        mnemonic = "BindcCpp",
        progress_message = "Generating bind library C++ for %s" % ctx.label.name,
    )
    return [DefaultInfo(files = depset([out_h]))]

# Runs bindc's generate-cpp on a .bind library file, producing a C++ header (the bind
# property/value constants used in driver bind code). Generation-only, like fidl_banjo_c;
# the BUILD wraps it in a genrule (canonical include path) + cc_library.
bind_library_cpp = rule(
    implementation = _bind_library_cpp_impl,
    attrs = {
        "src": attr.label(allow_single_file = [".bind"], mandatory = True),
        "_bindc": attr.label(
            default = "//src/upstream/fuchsia/tools/bindc:bindc",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _fidl_bind_library_cpp_impl(ctx):
    # A FIDL library auto-generates a bind library (its `_bindlib`): run the FIDL IR
    # through bindc generate-bind (IR -> .bind), then generate-cpp (.bind -> C++ header).
    info = ctx.attr.library[FidlInfo]
    bind_lib = ctx.actions.declare_file(ctx.label.name + ".bind")
    out_h = ctx.actions.declare_file(ctx.label.name + ".h")

    a1 = ctx.actions.args()
    a1.add("generate-bind")
    a1.add(info.ir)
    a1.add("--output", bind_lib.path)
    ctx.actions.run(
        executable = ctx.executable._bindc,
        arguments = [a1],
        inputs = [info.ir],
        outputs = [bind_lib],
        mnemonic = "BindcGenBind",
        progress_message = "Generating bind library from FIDL %s" % ctx.label.name,
    )

    a2 = ctx.actions.args()
    a2.add("generate-cpp")
    a2.add(bind_lib)
    a2.add("--output", out_h.path)
    ctx.actions.run(
        executable = ctx.executable._bindc,
        arguments = [a2],
        inputs = [bind_lib],
        outputs = [out_h],
        mnemonic = "BindcCpp",
        progress_message = "Generating bind C++ from FIDL %s" % ctx.label.name,
    )
    return [
        DefaultInfo(files = depset([out_h])),
        # Expose the intermediate .bind library so driver_bind_rules can `using` it.
        OutputGroupInfo(bindlib = depset([bind_lib])),
    ]

# The FIDL-derived bind library C++ (a FIDL protocol's `_bindlib_cpp`): chains bindc
# generate-bind (FIDL IR -> .bind) then generate-cpp (.bind -> C++ header). The BUILD
# wraps the header in a genrule + cc_library.
fidl_bind_library_cpp = rule(
    implementation = _fidl_bind_library_cpp_impl,
    attrs = {
        "library": attr.label(providers = [FidlInfo], mandatory = True),
        "_bindc": attr.label(
            default = "//src/upstream/fuchsia/tools/bindc:bindc",
            executable = True,
            cfg = "exec",
        ),
    },
)

# driver_bind_rules: compiles a driver's .bind rules to .bindbc bytecode (consumed
# by driver-index at runtime to match the driver to device nodes). Mirrors upstream
# `driver_bind_rules` (build/bind/bind.gni): bindc compile --lint --output <name>.bindbc
# --include-file <rsp> <rules.bind>, where the response file lists the dependency
# bind-library .bind source files (resolving `using fuchsia.pci;` etc.).
def _driver_bind_rules_impl(ctx):
    out = ctx.actions.declare_file(ctx.attr.output_name or (ctx.label.name + ".bindbc"))
    rsp = ctx.actions.declare_file(ctx.label.name + ".bind_includes.rsp")

    # Collect .bind files from includes via two paths:
    #   (a) Direct .bind file targets (ctx.files.includes, filtered to .bind extension) —
    #       existing DefaultInfo path; used by plain bind-library file exports (e.g.
    #       fuchsia.pci.bind). Filter to .bind only so that when a fidl_bind_library_cpp
    #       target is listed, its DefaultInfo .h file doesn't leak into bindc's include list.
    #   (b) Rule targets exposing OutputGroupInfo.bindlib — used by fidl_bind_library_cpp
    #       targets (e.g. fuchsia.hardware.pci_bindlib_cpp_gen) whose generated .bind file
    #       lives in the bindlib output group, NOT in DefaultInfo (DefaultInfo carries the .h).
    seen = {}
    include_files = []
    for f in ctx.files.includes:
        if f.extension == "bind" and f.path not in seen:
            seen[f.path] = True
            include_files.append(f)
    for dep in ctx.attr.includes:
        if OutputGroupInfo in dep:
            og = dep[OutputGroupInfo]
            if hasattr(og, "bindlib"):
                for f in og.bindlib.to_list():
                    if f.extension == "bind" and f.path not in seen:
                        seen[f.path] = True
                        include_files.append(f)

    ctx.actions.write(rsp, "\n".join([f.path for f in include_files]))
    args = ctx.actions.args()
    args.add("compile")
    args.add("--lint")
    args.add("--output", out)
    args.add("--include-file", rsp)
    if ctx.attr.disable_autobind:
        args.add("--disable-autobind")
    args.add(ctx.file.rules)
    ctx.actions.run(
        executable = ctx.executable._bindc,
        arguments = [args],
        inputs = depset([ctx.file.rules, rsp] + include_files),
        outputs = [out],
        mnemonic = "BINDC",
        progress_message = "Compiling bind rules %s" % ctx.label.name,
    )
    return [DefaultInfo(files = depset([out]))]

driver_bind_rules = rule(
    implementation = _driver_bind_rules_impl,
    attrs = {
        "rules": attr.label(allow_single_file = [".bind"], mandatory = True),
        "includes": attr.label_list(allow_files = True, doc = "dependency bind-library .bind sources or fidl_bind_library_cpp targets (OutputGroupInfo.bindlib)"),
        "output_name": attr.string(doc = "bindbc filename (default <name>.bindbc)"),
        "disable_autobind": attr.bool(default = False),
        "_bindc": attr.label(
            default = "//src/upstream/fuchsia/tools/bindc:bindc",
            executable = True,
            cfg = "exec",
        ),
    },
)
