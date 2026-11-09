"""cerise_component: the real cmc-native .cml -> .cm + structured-config .cvf pipeline.

It produces component manifests from `.cml` rather than building
`fidl_fuchsia_component_decl` literals in Rust. New Cerise
components declare a real `.cml`, which the vendored `cmc` compiles to a `.cm`,
and whose `config: {}` schema is delivered for real: `configc cvf` turns a JSON5
values file (or an inline dict) into a `meta/<name>.cvf` that component_manager's
config resolution loads as the component's config VMO at runtime.

Reuse, not reinvention: the `cmc compile` action is the `compiled_manifest` rule
already vendored in //build:structured_config.bzl (same `--includeroot` /
`--includepath` / `--config-package-path` knobs the fshost/netstack3 SC path
uses). This file adds only:

  * `_config_value_file` - the `configc cvf --cm <cm> --values <json5> --output`
    action (the one stage structured_config.bzl does NOT cover, because upstream's
    codegen macros produce the *client library* from the schema, never the values).
  * `cerise_component` - the user-facing macro wiring compile -> cvf -> a
    `ComponentInfo` provider carrying the bootfs placements a bundle/product
    stages into STORAGE_BOOTFS.

ComponentInfo.bootfs uses the same `struct(dest, file)` shape as
//assembly:providers.bzl's BoardInfo/AIBInfo `bootfs` field, so a
`cerise_assembly_input_bundle` can concatenate a component's placements directly.
It should later be folded into / consumed by AIBInfo (owned by the composition
layer) rather than duplicated; it is kept minimal and separate here to avoid
coupling the component and assembly rule modules.
"""

load("//build:structured_config.bzl", "compiled_manifest")

ComponentInfo = provider(
    doc = "A cmc-compiled Cerise component: its manifest (.cm), optional " +
          "structured-config values (.cvf), and the bootfs placements a bundle " +
          "or product stages to run it. Field shape aligns with " +
          "//assembly:providers.bzl AIBInfo.bootfs (struct(dest, file)).",
    fields = {
        "component_name": "String component identity (e.g. \"hello_cml\").",
        "manifest": "The compiled .cm File (fuchsia.component.decl.Component, persistent FIDL).",
        "config_values": "The compiled .cvf File (fuchsia.component.decl.ConfigValuesData), or None.",
        "bootfs": "list[struct(dest, file)] of this component's STORAGE_BOOTFS placements " +
                  "(pkg/<name>/meta/<name>.cm, pkg/<name>/meta/<name>.cvf, pkg/<name>/bin/<name>, libs...).",
    },
)

# ---------------------------------------------------------------------------
# configc cvf --cm <cm> --values <json5> --output <name>.cvf
#
# The stage structured_config.bzl deliberately omits: it produces the delivered
# structured-config VALUES from a JSON5 values object + the compiled schema in
# the .cm. `configc cvf` (tools/configc/src/cvf.rs -> GenerateValueFile) verifies
# each value against the schema field's type at build time, so a typo'd field or
# a wrong type is a build error, not a silent runtime mismatch.
# ---------------------------------------------------------------------------

def _config_value_file_impl(ctx):
    # Either an explicit JSON5 values file, or an inline dict serialized to JSON
    # by the macro (JSON is a strict subset of the JSON5 configc accepts).
    if ctx.file.values_file:
        values = ctx.file.values_file
    else:
        values = ctx.actions.declare_file(ctx.label.name + "_values.json")
        ctx.actions.write(values, ctx.attr.values_json)

    cvf = ctx.actions.declare_file(ctx.attr.output_name or (ctx.label.name + ".cvf"))
    args = ctx.actions.args()
    args.add("cvf")
    args.add("--cm", ctx.file.cm)
    args.add("--values", values)
    args.add("--output", cvf)
    ctx.actions.run(
        executable = ctx.executable._configc,
        arguments = [args],
        inputs = [ctx.file.cm, values],
        outputs = [cvf],
        mnemonic = "CONFIGCCVF",
        progress_message = "Generating structured-config values %s" % ctx.label,
    )
    return [DefaultInfo(files = depset([cvf]))]

_config_value_file = rule(
    implementation = _config_value_file_impl,
    attrs = {
        "cm": attr.label(allow_single_file = [".cm"], mandatory = True),
        "values_json": attr.string(doc = "Inline JSON (serialized dict) of config field -> value."),
        "values_file": attr.label(allow_single_file = [".json5", ".json"], doc = "A JSON5 values file (alternative to values_json)."),
        "output_name": attr.string(),
        "_configc": attr.label(
            default = "//src/upstream/fuchsia/tools/configc:configc",
            executable = True,
            cfg = "exec",
        ),
    },
)

# ---------------------------------------------------------------------------
# ComponentInfo assembler: gathers the .cm, .cvf and program bootfs placements.
# ---------------------------------------------------------------------------

def _cerise_component_impl(ctx):
    name = ctx.attr.component_name or ctx.label.name
    pkg = "pkg/" + name

    placements = []
    default_files = []

    cm = ctx.file.cm
    placements.append(struct(dest = "%s/meta/%s.cm" % (pkg, name), file = cm))
    default_files.append(cm)

    cvf = ctx.file.cvf
    if cvf:
        placements.append(struct(dest = "%s/meta/%s.cvf" % (pkg, name), file = cvf))
        default_files.append(cvf)

    if ctx.file.binary:
        placements.append(struct(dest = "%s/bin/%s" % (pkg, name), file = ctx.file.binary))
        default_files.append(ctx.file.binary)

    # libs: {label -> destination-within-package} (e.g. "lib/ld.so.1").
    for lib_target, relpath in ctx.attr.libs.items():
        f = lib_target.files.to_list()[0]
        placements.append(struct(dest = "%s/%s" % (pkg, relpath), file = f))
        default_files.append(f)

    return [
        ComponentInfo(
            component_name = name,
            manifest = cm,
            config_values = cvf,
            bootfs = placements,
        ),
        DefaultInfo(files = depset(default_files)),
    ]

_cerise_component = rule(
    implementation = _cerise_component_impl,
    attrs = {
        "component_name": attr.string(),
        "cm": attr.label(allow_single_file = [".cm"], mandatory = True),
        "cvf": attr.label(allow_single_file = [".cvf"]),
        "binary": attr.label(allow_single_file = True, doc = "The component's ELF binary (already fuchsia-platform transitioned)."),
        "libs": attr.label_keyed_string_dict(allow_files = True, doc = "{lib label: destination-within-package} extra bootfs files (shared libs)."),
    },
)

# ---------------------------------------------------------------------------
# cerise_component: the user-facing macro. compile -> (cvf) -> ComponentInfo.
# ---------------------------------------------------------------------------

def cerise_config_values(
        name,
        cm,
        values = None,
        values_file = None,
        output_name = None,
        visibility = None,
        **kwargs):
    """Standalone configc-generated structured-config values file (.cvf).

    For staging a component's config values OUTSIDE the cerise_product pipeline
    (the legacy zircon_system products stage these explicitly in extra_bootfs;
    cerise_product generates them from AIBInfo.configs instead).

    Args:
      name: target name; output is <output_name or name+".cvf">.
      cm: label of the compiled .cm whose ConfigSchema the values must satisfy.
      values: inline dict {field: value}. Mutually exclusive with values_file.
      values_file: a JSON5 values file label.
      output_name: the .cvf output filename (default <name>.cvf).
      visibility: target visibility.
    """
    if (values == None) == (values_file == None):
        fail("cerise_config_values %r: exactly one of values / values_file is required" % name)
    _config_value_file(
        name = name,
        cm = cm,
        values_json = json.encode(values) if values != None else "",
        values_file = values_file,
        output_name = output_name or (name + ".cvf"),
        visibility = visibility,
        **kwargs
    )

def cerise_component(
        name,
        manifest,
        binary = None,
        config_values = None,
        config_values_file = None,
        config_package_path = None,
        libs = {},
        includes = [],
        includeroot = "src/upstream/fuchsia",
        includepaths = ["src/upstream/fuchsia/sdk/lib"],
        cml_features = [],
        reachable_packages = [],
        resolver_packages = [],
        indirect_packages = [],
        reachable_executables = [],
        visibility = None,
        **kwargs):
    """Compiles a real .cml to a .cm (and, when the manifest has a `config: {}`
    stanza, delivers structured-config values as a .cvf) and packages the result
    as a ComponentInfo with STORAGE_BOOTFS placements.

    Args:
      name: target name; component identity. Manifest lands at pkg/<name>/meta/<name>.cm.
      manifest: the .cml source label (program + optional config + use/expose).
      binary: the component's ELF binary label (typically a fuchsia_stripped
        output, already platform-transitioned). Staged at pkg/<name>/bin/<name>.
      config_values: an inline dict {field: value} of structured-config values.
        Mutually exclusive with config_values_file. Presence of either signals
        the manifest has a `config: {}` block (so cmc is told the values path and
        a .cvf is produced).
      config_values_file: a JSON5 values file label (alternative to config_values).
      config_package_path: schema-only mode — the manifest has a `config: {}`
        block (cmc needs the package-relative .cvf path baked into the .cm's
        value_source) but the VALUES are delivered by someone else: a bundle's
        AIBInfo.configs entry or a standalone cerise_config_values target. No
        .cvf sub-target is produced here. Mutually exclusive with config_values
        and config_values_file.
      libs: {label: destination-within-package} extra bootfs files (e.g.
        {":libc.fuchsia": "lib/ld.so.1"}).
      includes: cml include-shard files referenced by the manifest.
      includeroot/includepaths/cml_features: cmc compile knobs (see compiled_manifest).
      reachable_packages: package names referenced by a root realm's child URLs.
      resolver_packages: package names referenced by fuchsia-pkg child URLs.
      indirect_packages: packages launched below a root child.
      reachable_executables: indirectly launched executable bootfs paths.
      visibility: target visibility.

    Produces (public sub-targets a bundle/test can reference):
      :<name>            -> ComponentInfo + DefaultInfo(.cm, .cvf, binary, libs).
      :<name>_manifest   -> the .cm File (single-file; use for $(location)).
      :<name>_cvf        -> the .cvf File (only when config values given).
    """
    has_config = config_values != None or config_values_file != None
    if has_config and config_package_path != None:
        fail("cerise_component %r: config_package_path (schema-only) is mutually " +
             "exclusive with config_values/config_values_file" % name)
    effective_config_package_path = config_package_path or (
        "meta/%s.cvf" % name if has_config else ""
    )

    compiled_manifest(
        name = name + "_manifest",
        src = manifest,
        includes = includes,
        includeroot = includeroot,
        includepaths = includepaths,
        cml_features = cml_features,
        required_boot_packages = reachable_packages,
        resolver_packages = resolver_packages,
        indirect_packages = indirect_packages,
        reachable_executables = reachable_executables,
        output_name = name + ".cm",
        config_package_path = effective_config_package_path,
        visibility = visibility,
        tags = ["manual"],
    )

    cvf_target = None
    if has_config:
        _config_value_file(
            name = name + "_cvf",
            cm = ":" + name + "_manifest",
            values_json = json.encode(config_values) if config_values != None else "",
            values_file = config_values_file,
            output_name = name + ".cvf",
            visibility = visibility,
            tags = ["manual"],
        )
        cvf_target = ":" + name + "_cvf"

    _cerise_component(
        name = name,
        component_name = name,
        cm = ":" + name + "_manifest",
        cvf = cvf_target,
        binary = binary,
        libs = libs,
        visibility = visibility,
        tags = ["manual"],
        **kwargs
    )
