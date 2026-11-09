"""Structured-config codegen rules for Cerise.

Faithfully reproduces upstream Fuchsia's `fuchsia_structured_config_cpp_elf_lib`
GN flow as Bazel rules:

  1. compiled_manifest:  cmc compile <cml> -> <name>.cm  (the component manifest,
     whose `config` schema is derived from the driver's `use: { config: ... }`).
  2. fuchsia_structured_config_cpp_elf_lib (macro):
       a. configc fidl  --cm <cm> -> cf.sc.internal.fidl  (internal FIDL schema)
       b. fidl_library + fidl_cpp on that .fidl -> <fidl/cf.sc.internal/cpp/fidl.h>
       c. configc cpp   --cm <cm> -> <namespace>.{h,cc}  (the CreateFromVmo wrapper)
       d. cc_library wrapping (c), depending on (b) + inspect + zx.

The two formatter inputs that upstream passes (clang-format for the C++ wrapper,
fidl-format for the FIDL schema) are post-processors that only pretty-print the
generated source; the output compiles identically without them. fidl-format is a
real tool (built from the fidlc lib). clang-format is stubbed-to-`empty` in the
minimal LLVM toolchain, so we route it through a passthrough no-op for now
(cosmetic-only; tracked to revisit -- see //build/structured_config:clang_format_noop).

Fxfs host work adds the parallel Rust path (`fuchsia_structured_config_rust_lib`,
mirroring upstream's real macro of the same name): configc's real, already-vendored
`rust` subcommand (client_rust.rs, GenerateRustSource) generates the `<name>::Config`
wrapper directly from the compiled manifest + an internal FIDL library (same
cf.sc.internal schema stage as the C++ path, fidl_rust instead of fidl_cpp). rustfmt
is a formatter-only post-processor same as clang-format above -- routed through an
analogous passthrough no-op (//build/structured_config:rustfmt_noop), cosmetic-only.
"""

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_rust//rust:defs.bzl", "rust_library")
load("//build/fidl:fidl.bzl", "fidl_cpp", "fidl_library", "fidl_rust")
load("//assembly:providers.bzl", "RootRealmInfo")

# ---------------------------------------------------------------------------
# Stage 1: cmc compile <cml> -> <name>.cm
# ---------------------------------------------------------------------------

def _compiled_manifest_impl(ctx):
    cm = ctx.actions.declare_file(ctx.attr.output_name or (ctx.label.name + ".cm"))
    args = ctx.actions.args()
    args.add("compile")
    args.add(ctx.file.src)
    args.add("--output", cm)
    # `//`-prefixed includes resolve against includeroot; relative ones against
    # the includepath search dirs.
    args.add("--includeroot", ctx.attr.includeroot)
    for ip in ctx.attr.includepaths:
        args.add("--includepath", ip)
    if ctx.attr.cml_features:
        args.add("--features")
        args.add_all(ctx.attr.cml_features)
    if ctx.attr.config_package_path:
        args.add("--config-package-path", ctx.attr.config_package_path)
    ctx.actions.run(
        executable = ctx.executable._cmc,
        arguments = [args],
        inputs = depset([ctx.file.src] + ctx.files.includes),
        outputs = [cm],
        mnemonic = "CMC",
        progress_message = "Compiling component manifest %s" % ctx.label,
    )
    return [
        DefaultInfo(files = depset([cm])),
        RootRealmInfo(
            required_boot_packages = ctx.attr.required_boot_packages,
            resolver_packages = ctx.attr.resolver_packages,
            indirect_packages = ctx.attr.indirect_packages,
            reachable_executables = ctx.attr.reachable_executables,
        ),
    ]

# ---------------------------------------------------------------------------
# Stage 4: configc cpp --cm <cm> -> <namespace>.{h,cc}  (CreateFromVmo wrapper)
# ---------------------------------------------------------------------------

def _sc_cpp_source_impl(ctx):
    ns = ctx.attr.namespace
    h = ctx.actions.declare_file(ns + ".h")
    cc = ctx.actions.declare_file(ns + ".cc")
    args = ctx.actions.args()
    args.add("cpp")
    args.add("--cm", ctx.file.cm)
    args.add("--h-output", h)
    args.add("--cc-output", cc)
    args.add("--namespace", ns)
    args.add("--fidl-library-name", ctx.attr.fidl_library_name)
    args.add("--clang-format", ctx.executable._clang_format)
    ctx.actions.run(
        executable = ctx.executable._configc,
        arguments = [args],
        inputs = [ctx.file.cm],
        tools = [ctx.executable._clang_format],
        outputs = [h, cc],
        mnemonic = "CONFIGCCPP",
        progress_message = "Generating structured-config C++ %s" % ctx.label,
    )
    return [
        DefaultInfo(files = depset([h, cc])),
        OutputGroupInfo(hdr = depset([h]), src = depset([cc])),
    ]

structured_config_cpp_source = rule(
    implementation = _sc_cpp_source_impl,
    attrs = {
        "cm": attr.label(allow_single_file = [".cm"], mandatory = True),
        "namespace": attr.string(mandatory = True),
        "fidl_library_name": attr.string(default = "cf.sc.internal"),
        "_configc": attr.label(
            default = "//src/upstream/fuchsia/tools/configc:configc",
            executable = True,
            cfg = "exec",
        ),
        "_clang_format": attr.label(
            default = "//build/structured_config:clang_format_noop",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ---------------------------------------------------------------------------
# Stage 2: configc fidl --cm <cm> -> <library_name>.fidl  (internal schema)
# ---------------------------------------------------------------------------

def _sc_fidl_source_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".fidl")
    args = ctx.actions.args()
    args.add("fidl")
    args.add("--cm", ctx.file.cm)
    args.add("--output", out)
    args.add("--library-name", ctx.attr.library_name)
    args.add("--fidl-format", ctx.executable._fidl_format)
    ctx.actions.run(
        executable = ctx.executable._configc,
        arguments = [args],
        inputs = [ctx.file.cm],
        tools = [ctx.executable._fidl_format],
        outputs = [out],
        mnemonic = "CONFIGCFIDL",
        progress_message = "Generating structured-config FIDL %s" % ctx.label,
    )
    return [DefaultInfo(files = depset([out]))]

structured_config_fidl_source = rule(
    implementation = _sc_fidl_source_impl,
    attrs = {
        "cm": attr.label(allow_single_file = [".cm"], mandatory = True),
        "library_name": attr.string(default = "cf.sc.internal"),
        "_configc": attr.label(
            default = "//src/upstream/fuchsia/tools/configc:configc",
            executable = True,
            cfg = "exec",
        ),
        "_fidl_format": attr.label(
            default = "//src/upstream/fuchsia/tools/fidl/fidlc:fidl-format",
            executable = True,
            cfg = "exec",
        ),
    },
)

compiled_manifest = rule(
    implementation = _compiled_manifest_impl,
    attrs = {
        "src": attr.label(allow_single_file = [".cml"], mandatory = True),
        "includes": attr.label_list(allow_files = True, doc = "include-shard files (.cml) referenced by src"),
        "includeroot": attr.string(default = "src/upstream/fuchsia"),
        "includepaths": attr.string_list(default = ["src/upstream/fuchsia/sdk/lib"]),
        "cml_features": attr.string_list(),
        "output_name": attr.string(),
        "config_package_path": attr.string(doc = "required by cmc when the manifest has a `config: {}` block"),
        "required_boot_packages": attr.string_list(
            doc = "Package names referenced by fuchsia-boot child URLs.",
        ),
        "resolver_packages": attr.string_list(),
        "indirect_packages": attr.string_list(),
        "reachable_executables": attr.string_list(
            doc = "Indirectly launched executable bootfs paths.",
        ),
        "_cmc": attr.label(
            default = "//src/upstream/fuchsia/tools/cmc:cmc",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ---------------------------------------------------------------------------
# Top-level macro: full cmc -> configc fidl -> fidl_cpp -> configc cpp -> cc_library
# pipeline, mirroring upstream `fuchsia_structured_config_cpp_elf_lib`.
# ---------------------------------------------------------------------------


def fuchsia_structured_config_cpp_elf_lib(
        name,
        manifest,
        namespace,
        include_prefix,
        includes = [],
        includeroot = "src/upstream/fuchsia",
        includepaths = ["src/upstream/fuchsia/sdk/lib"],
        cml_features = [],
        fidl_library_name = "cf.sc.internal",
        deps = [],
        visibility = None,
        **kwargs):
    """Generates a C++ structured-config client library (the `<namespace>::Config`
    `CreateFromVmo` wrapper) from a driver component manifest.

    Args:
      name: the cc_library target name.
      manifest: the .cml source (label) containing the `use: { config: ... }`.
      namespace: C++ namespace / generated header basename (e.g. "x86_config").
      include_prefix: virtual include prefix so the generated header resolves at
        e.g. "src/devices/board/drivers/x86/<namespace>.h".
      includes: include-shard files referenced by the manifest.
      includeroot/includepaths/cml_features: cmc compile knobs.
      fidl_library_name: internal FIDL library name (upstream default cf.sc.internal).
      deps: extra cc deps for the wrapper (e.g. inspect, zx headers).
    """
    compiled_manifest(
        name = name + ".cm",
        src = manifest,
        includes = includes,
        includeroot = includeroot,
        includepaths = includepaths,
        cml_features = cml_features,
        tags = ["manual"],
    )
    structured_config_fidl_source(
        name = name + "_fidl_src",
        cm = ":" + name + ".cm",
        library_name = fidl_library_name,
        tags = ["manual"],
    )
    # The generated cf.sc.internal schema is unversioned; compile it at HEAD.
    fidl_library(
        name = name + "_fidl",
        srcs = [":" + name + "_fidl_src"],
        available = "fuchsia:HEAD",
        tags = ["manual"],
    )
    fidl_cpp(
        name = name + "_fidl_cpp",
        library = ":" + name + "_fidl",
        tags = ["manual"],
    )
    structured_config_cpp_source(
        name = name + "_cppsrc",
        cm = ":" + name + ".cm",
        namespace = namespace,
        fidl_library_name = fidl_library_name,
        tags = ["manual"],
    )
    native.filegroup(
        name = name + "_h",
        srcs = [":" + name + "_cppsrc"],
        output_group = "hdr",
        tags = ["manual"],
    )
    native.filegroup(
        name = name + "_cc",
        srcs = [":" + name + "_cppsrc"],
        output_group = "src",
        tags = ["manual"],
    )
    cc_library(
        name = name,
        srcs = [":" + name + "_cc"],
        hdrs = [":" + name + "_h"],
        include_prefix = include_prefix,
        deps = [":" + name + "_fidl_cpp"] + deps,
        visibility = visibility,
        **kwargs
    )

# ---------------------------------------------------------------------------
# Stage 3 (Rust variant): configc rust --cm <cm> -> <crate_name>.rs
# ---------------------------------------------------------------------------

def _sc_rust_source_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".rs")
    args = ctx.actions.args()
    args.add("rust")
    args.add("--cm", ctx.file.cm)
    args.add("--output", out)
    args.add("--fidl-library-name", ctx.attr.fidl_library_name)
    args.add("--rustfmt", ctx.executable._rustfmt)
    args.add("--rustfmt-config", ctx.file._rustfmt_config)
    ctx.actions.run(
        executable = ctx.executable._configc,
        arguments = [args],
        inputs = [ctx.file.cm, ctx.file._rustfmt_config],
        tools = [ctx.executable._rustfmt],
        outputs = [out],
        mnemonic = "CONFIGCRUST",
        progress_message = "Generating structured-config Rust %s" % ctx.label,
    )
    return [DefaultInfo(files = depset([out]))]

structured_config_rust_source = rule(
    implementation = _sc_rust_source_impl,
    attrs = {
        "cm": attr.label(allow_single_file = [".cm"], mandatory = True),
        "fidl_library_name": attr.string(default = "cf.sc.internal"),
        "_configc": attr.label(
            default = "//src/upstream/fuchsia/tools/configc:configc",
            executable = True,
            cfg = "exec",
        ),
        "_rustfmt": attr.label(
            default = "//build/structured_config:rustfmt_noop",
            executable = True,
            cfg = "exec",
        ),
        "_rustfmt_config": attr.label(
            default = "//build/structured_config:rustfmt_empty.toml",
            allow_single_file = True,
        ),
    },
)

# ---------------------------------------------------------------------------
# Top-level macro: full cmc -> configc fidl -> fidl_rust -> configc rust -> rust_library
# pipeline, mirroring upstream `fuchsia_structured_config_rust_lib`.
# ---------------------------------------------------------------------------

def fuchsia_structured_config_rust_lib(
        name,
        manifest,
        crate_name,
        includes = [],
        includeroot = "src/upstream/fuchsia",
        includepaths = ["src/upstream/fuchsia/sdk/lib"],
        cml_features = [],
        fidl_library_name = "cf.sc.internal",
        config_package_path = "",
        deps = [],
        visibility = None,
        **kwargs):
    """Generates a Rust structured-config client library (the `<crate_name>::Config`
    `take_from_startup_handle` wrapper) from a component manifest.

    Args:
      name: the rust_library target name.
      manifest: the .cml source (label) containing the `config: { ... }` schema.
      crate_name: Rust crate name (e.g. "fshost_config").
      includes: include-shard files referenced by the manifest.
      includeroot/includepaths/cml_features: cmc compile knobs.
      fidl_library_name: internal FIDL library name (upstream default cf.sc.internal).
      config_package_path: cmc requires this when the manifest has a `config: {}`
        block (validates against a future package-relative .cvf path); a nominal
        string is sufficient, no real .cvf file needs to exist for codegen.
      deps: extra rust deps for the wrapper (e.g. fidl runtime, zx, diagnostics).
    """
    compiled_manifest(
        name = name + ".cm",
        src = manifest,
        includes = includes,
        includeroot = includeroot,
        includepaths = includepaths,
        cml_features = cml_features,
        config_package_path = config_package_path,
        tags = ["manual"],
    )
    fuchsia_structured_config_rust_lib_from_cm(
        name = name,
        cm = ":" + name + ".cm",
        crate_name = crate_name,
        fidl_library_name = fidl_library_name,
        deps = deps,
        visibility = visibility,
        **kwargs
    )

def fuchsia_structured_config_rust_lib_from_cm(
        name,
        cm,
        crate_name,
        fidl_library_name = "cf.sc.internal",
        deps = [],
        visibility = None,
        **kwargs):
    """Generates a Rust structured-config client library from an ALREADY-compiled
    component manifest (.cm).

    Prefer this over fuchsia_structured_config_rust_lib when the component's real
    delivered manifest is compiled elsewhere (e.g. a //src/cerise/realms
    cerise_component): generating the client crate from the SAME .cm that the
    delivered .cvf is generated against makes the config checksum match by
    construction — no parallel *_for_config_lib.cml schema copy to keep in sync.

    Args:
      name: the rust_library target name.
      cm: label of the compiled .cm carrying the `config` schema.
      crate_name: Rust crate name (e.g. "fshost_config").
      fidl_library_name: internal FIDL library name (upstream default cf.sc.internal).
      deps: extra rust deps for the wrapper (e.g. fidl runtime, zx, diagnostics).
    """
    structured_config_fidl_source(
        name = name + "_fidl_src",
        cm = cm,
        library_name = fidl_library_name,
        tags = ["manual"],
    )
    fidl_library(
        name = name + "_fidl",
        srcs = [":" + name + "_fidl_src"],
        available = "fuchsia:HEAD",
        tags = ["manual"],
    )
    fidl_rust(
        name = name + "_fidl_rs",
        library = ":" + name + "_fidl",
        tags = ["manual"],
    )
    rust_library(
        name = name + "_fidl_rust",
        srcs = [":" + name + "_fidl_rs"],
        crate_name = "fidl_" + fidl_library_name.replace(".", "_").replace("-", "_"),
        edition = "2021",
        tags = ["manual"],
        deps = [
            "//src/upstream/fuchsia/src/lib/fidl/rust/fidl:fidl",
            "@crates//:bitflags",
            "@crates//:futures",
            "//src/upstream/fuchsia/sdk/rust/zx-status:zx-status",
            "//src/upstream/fuchsia/sdk/rust/zx-types:zx-types",
        ] + select({
            "@platforms//os:fuchsia": ["//src/upstream/fuchsia/sdk/rust/zx:zx"],
            "//conditions:default": [],
        }),
    )
    structured_config_rust_source(
        name = name + "_rustsrc",
        cm = cm,
        fidl_library_name = fidl_library_name,
        tags = ["manual"],
    )
    rust_library(
        name = name,
        srcs = [":" + name + "_rustsrc"],
        crate_name = crate_name,
        edition = "2021",
        deps = [
            ":" + name + "_fidl_rust",
            "//src/upstream/fuchsia/src/lib/fidl/rust/fidl:fidl",
            "//src/upstream/fuchsia/src/lib/fuchsia-component/config:config",
            "//src/upstream/fuchsia/src/lib/diagnostics/inspect/rust:fuchsia-inspect",
        ] + deps + select({
            "@platforms//os:fuchsia": ["//src/upstream/fuchsia/sdk/rust/zx:zx"],
            "//conditions:default": [],
        }),
        visibility = visibility,
        **kwargs
    )
