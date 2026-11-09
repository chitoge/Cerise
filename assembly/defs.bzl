"""Cerise composition layer: cerise_board, cerise_assembly_input_bundle, cerise_product.

Realizes's board / bundle / product trichotomy natively in
Bazel analysis via typed providers (BoardInfo / AIBInfo / ProductBundleInfo) —
no external assembly tool.

  * cerise_board                 -> BoardInfo         (hardware identity + drivers)
  * cerise_assembly_input_bundle -> AIBInfo           (reusable component/package set)
  * cerise_product               -> ProductBundleInfo (board + bundles + config -> ZBI)

The product rule performs, entirely in analysis:
  0. Architecture validation: the board's declared architecture must match its
     physload, kernel-storage, and any tagged staged userspace artifacts.
  1. Feature resolution: every bundle.requires_features must be a subset of
     board.provided_features, else fail() naming the missing feature(s).
  2. bootfs merge: board + bundles + product placements are merged by
     destination path; a collision on the same dest is a fail() naming the path.
  2b. component structured config: bundles carry a component's config schema
     (its compiled .cm) + default values; the board injects boot_drivers where a
     bundle declared an injection field; the product merges value overrides
     (unknown component/key = fail()) and stages the configc-generated .cvf at
     pkg/<component>/meta/<component>.cvf for component_manager to deliver.
  3. cmdline concat: board -> bundles (in list order) -> product.
  4. ZBI emission via the shared emit_zbi helper (//bazel:zbi_assembly.bzl).

Each rule is fronted by a macro that accepts an ergonomic `bootfs = {dest: label}`
dict and splits it into the parallel (dests, srcs) lists the underlying rule
consumes — the same pattern zircon_system uses, which also sidesteps the
ctx.files dedup trap (a file staged at two dests must appear twice).
"""

load("//bazel:zbi_assembly.bzl", "emit_zbi")
load("//assembly:providers.bzl", "AIBInfo", "ArtifactArchitectureInfo", "BoardInfo", "ProductBundleInfo", "RootRealmInfo")

_DEFAULT_PHYSLOAD = "//build/phys:physload_artifact"
_DEFAULT_KERNEL_STORAGE = "//build/kernel:kernel_storage_zbi_artifact"

# The fixed bootfs destination the product's root realm is staged at. Product-owned
# (a first-class cerise_product attr), never a product_bootfs dict entry.
_ROOT_REALM_DEST = "pkg/root/meta/root.cm"
# component_manager is the userboot.next bootstrap selected by the component
# framework bundle; it is reached by the boot chain rather than a root child URL.
_BOOTSTRAP_EXECUTABLES = ["bin/component_manager"]

# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------

def _single_file(target, context):
    """Return a target's sole output, failing with an actionable error otherwise."""
    files = target.files.to_list()
    if len(files) != 1:
        fail("%s: %s must produce exactly one file, but produces %d" %
             (context, target.label, len(files)))
    return files[0]

def _artifact_architecture(target):
    """Return architecture metadata when a target deliberately exposes it."""
    if ArtifactArchitectureInfo in target:
        return target[ArtifactArchitectureInfo]
    return None

def _artifact_kind(dest):
    """Classify a STORAGE_BOOTFS path using its declared package layout.

    Bootfs package layout is an assembly contract: only files below a package's
    `bin/` directory are launchable executables. Everything else is data,
    libraries, or component metadata and is never a process entry point.
    """
    if dest.startswith("bin/") or "/bin/" in dest:
        return "executable"
    if dest.startswith("lib/") or "/lib/" in dest:
        return "library"
    if dest.endswith(".cm") or dest.endswith(".cml") or dest.endswith(".cvf"):
        return "metadata"
    return "data"

def _bootfs_pairs(dests, src_targets, context, validation = False):
    """Zip parallel (dests, src_targets) into typed bootfs placement records."""
    if len(dests) != len(src_targets):
        fail("bootfs_dests and bootfs_srcs must have the same length (%d vs %d)" %
             (len(dests), len(src_targets)))
    return [
        struct(
            dest = dests[i],
            file = _single_file(src_targets[i], "%s bootfs destination %r" % (context, dests[i])),
            artifact_architecture = _artifact_architecture(src_targets[i]),
            artifact_kind = _artifact_kind(dests[i]),
            validation = validation,
        )
        for i in range(len(dests))
    ]

def _validate_bootfs_architecture(product_name, board, pairs, origin_name):
    """Reject a tagged userspace artifact whose architecture differs from the board."""
    for p in pairs:
        artifact = p.artifact_architecture
        if not artifact:
            continue
        if artifact.kind != "userspace":
            fail(("cerise_product %r: %s bootfs artifact at %r is tagged %r; " +
                  "bootfs artifacts must use kind %r") %
                 (product_name, origin_name, p.dest, artifact.kind, "userspace"))
        if artifact.arch != board.arch:
            fail(("cerise_product %r: %s bootfs artifact at %r declares architecture %r, " +
                  "but board %r declares %r") %
                 (product_name, origin_name, p.dest, artifact.arch, board.board_name, board.arch))

def _validate_input_zbis(product_name, board, input_zbis):
    """Require one matching physload and kernel-storage ZBI for the board."""
    expected_kinds = ["physload", "kernel_storage"]
    if len(input_zbis) != len(expected_kinds):
        fail(("cerise_product %r: expected exactly %d input ZBIs (physload, kernel_storage), " +
              "but received %d") % (product_name, len(expected_kinds), len(input_zbis)))
    for i in range(len(expected_kinds)):
        target = input_zbis[i]
        artifact = _artifact_architecture(target)
        if not artifact:
            fail(("cerise_product %r: input ZBI %r must provide ArtifactArchitectureInfo; " +
                  "wrap it with cerise_architecture_artifact") % (product_name, target.label))
        if artifact.kind != expected_kinds[i]:
            fail(("cerise_product %r: input ZBI %r is tagged %r, but position %d requires %r") %
                 (product_name, target.label, artifact.kind, i + 1, expected_kinds[i]))
        if artifact.arch != board.arch:
            fail(("cerise_product %r: %s %r declares architecture %r, but board %r declares %r") %
                 (product_name, artifact.kind, target.label, artifact.arch, board.board_name, board.arch))

def _merge_into(product_name, merged, origin, pairs, origin_name):
    """Add bootfs pairs to `merged` (dest->File), failing on a dest collision."""
    for p in pairs:
        if p.dest in merged:
            fail(("cerise_product %r: bootfs collision at %r: %s and %s both place " +
                  "a file there. Each destination path must have exactly one home " +
                  "across the board, the bundles, and the product.") %
                 (product_name, p.dest, origin[p.dest], origin_name))
        merged[p.dest] = p.file
        origin[p.dest] = origin_name

def _cerise_architecture_artifact_impl(ctx):
    return [
        DefaultInfo(files = depset([ctx.file.src])),
        ArtifactArchitectureInfo(
            arch = ctx.attr.arch,
            kind = ctx.attr.kind,
        ),
    ]

cerise_architecture_artifact = rule(
    implementation = _cerise_architecture_artifact_impl,
    attrs = {
        "src": attr.label(mandatory = True, allow_single_file = True),
        "arch": attr.string(mandatory = True),
        "kind": attr.string(
            mandatory = True,
            values = ["physload", "kernel_storage", "userspace"],
        ),
    },
    provides = [ArtifactArchitectureInfo],
    doc = "Re-exports one staged artifact with its CPU architecture and assembly role.",
)

def _cerise_root_realm_impl(ctx):
    return [
        DefaultInfo(files = depset([ctx.file.cm])),
        RootRealmInfo(
            required_boot_packages = ctx.attr.required_boot_packages,
            resolver_packages = ctx.attr.resolver_packages,
            indirect_packages = ctx.attr.indirect_packages,
            reachable_executables = ctx.attr.reachable_executables,
        ),
    ]

cerise_root_realm = rule(
    implementation = _cerise_root_realm_impl,
    attrs = {
        "cm": attr.label(mandatory = True, allow_single_file = [".cm"]),
        "required_boot_packages": attr.string_list(mandatory = True),
        "resolver_packages": attr.string_list(),
        "indirect_packages": attr.string_list(),
        "reachable_executables": attr.string_list(),
    },
    provides = [RootRealmInfo],
    doc = "Annotates a compiled root realm with its launchable package inventory.",
)

def _config_entries(configs_dict, what):
    """Split an ergonomic {component: {...}} configs dict into parallel lists.

    Each value dict may carry:
      cm                 (label string, required) - the compiled .cm with the schema
      values             (dict, required)         - default config values
      cvf_dest           (string, optional)       - bootfs dest of the .cvf
                                                    (default pkg/<comp>/meta/<comp>.cvf)
      boot_drivers_field (string, optional)       - config field the product fills
                                                    with BoardInfo.boot_drivers
    Returns (components, cms, values_json, cvf_dests, boot_drivers_fields).
    """
    components = sorted(configs_dict.keys())
    cms = []
    values_json = []
    cvf_dests = []
    bd_fields = []
    for comp in components:
        entry = configs_dict[comp]
        for key in entry:
            if key not in ("cm", "values", "cvf_dest", "boot_drivers_field"):
                fail("%s: configs[%r] has unknown key %r (allowed: cm, values, cvf_dest, boot_drivers_field)" %
                     (what, comp, key))
        if "cm" not in entry:
            fail("%s: configs[%r] must name the compiled .cm label under 'cm'" % (what, comp))
        if "values" not in entry:
            fail("%s: configs[%r] must carry default 'values'" % (what, comp))
        cms.append(entry["cm"])
        values_json.append(json.encode(entry["values"]))
        cvf_dests.append(entry.get("cvf_dest", "pkg/%s/meta/%s.cvf" % (comp, comp)))
        bd_fields.append(entry.get("boot_drivers_field", ""))
    return components, cms, values_json, cvf_dests, bd_fields

# ---------------------------------------------------------------------------
# cerise_board.
# ---------------------------------------------------------------------------

def _board_impl(ctx):
    product_sources = [
        str(src.label)
        for src in ctx.attr.bootfs_srcs
        if src.label.package == "products" or src.label.package.startswith("products/")
    ]
    if product_sources:
        fail("cerise_board %r must not depend on product target(s): %s; stage board-owned artifacts instead" %
             (ctx.label.name, ", ".join(product_sources)))
    return [
        DefaultInfo(),
        BoardInfo(
            board_name = ctx.attr.board_name or ctx.label.name,
            platform = ctx.attr.platform,
            arch = ctx.attr.arch,
            provided_features = ctx.attr.provided_features,
            kernel_cmdline = ctx.attr.kernel_cmdline,
            kernel_drivers = ctx.attr.kernel_drivers,
            bootfs = _bootfs_pairs(ctx.attr.bootfs_dests, ctx.attr.bootfs_srcs, str(ctx.label)),
            boot_drivers = ctx.attr.boot_drivers,
        ),
    ]

_cerise_board = rule(
    implementation = _board_impl,
    attrs = {
        "board_name": attr.string(),
        "platform": attr.string(default = ""),
        "arch": attr.string(default = "x86_64"),
        "provided_features": attr.string_list(),
        "kernel_cmdline": attr.string_list(),
        "kernel_drivers": attr.string_list(
            doc = "Arch kernel-driver ZBI items (\"DRIVER_TYPE=HEXPAYLOAD\"), passed " +
                  "verbatim to simple_zbi.py --kernel-driver. BOARD DATA, not tool code.",
        ),
        "bootfs_dests": attr.string_list(),
        "bootfs_srcs": attr.label_list(allow_files = True),
        "boot_drivers": attr.string_list(
            doc = "Boot-driver component URLs the board's drivers register with the " +
                  "driver index (flow into the generated driver-index config values).",
        ),
    },
    provides = [BoardInfo],
    doc = "Hardware identity for a product family. Pairs with a Bazel platform().",
)

def cerise_board(
        name,
        provided_features = [],
        kernel_cmdline = [],
        kernel_drivers = [],
        bootfs = {},
        boot_drivers = [],
        platform = "",
        arch = "x86_64",
        **kwargs):
    """A hardware board: driver packages + provided features + kernel cmdline.

    Args:
      name:              board target name and identity.
      provided_features: list[str] of hardware feature tokens (e.g. "cerise::nvme").
      kernel_cmdline:    list[str] of board-contributed kernel cmdline fragments.
      kernel_drivers:    list[str] of arch kernel-driver ZBI items, each
                         "DRIVER_TYPE=HEXPAYLOAD" (e.g. an ARM GIC/generic-timer
                         register block). BOARD DATA passed verbatim to simple_zbi.py
                         --kernel-driver, so a new arch adds a board, not a tool edit.
      bootfs:            {dest: label} of driver/package bootfs placements.
      boot_drivers:      list[str] of boot-driver component URLs the board's drivers
                         register with the driver index. BOARD DATA, not code: the
                         product rule injects this list into the driver-index config
                         values (see cerise_assembly_input_bundle's configs).
      platform:          label string of the Bazel platform() this board pairs with.
      arch:              CPU arch token (e.g. "x86_64", "aarch64"); default "x86_64".
      **kwargs:          forwarded to the underlying rule (visibility, tags, ...).
    """
    dests = sorted(bootfs.keys())
    srcs = [bootfs[d] for d in dests]
    _cerise_board(
        name = name,
        board_name = name,
        platform = platform,
        arch = arch,
        provided_features = provided_features,
        kernel_cmdline = kernel_cmdline,
        kernel_drivers = kernel_drivers,
        bootfs_dests = dests,
        bootfs_srcs = srcs,
        boot_drivers = boot_drivers,
        **kwargs
    )

# ---------------------------------------------------------------------------
# cerise_assembly_input_bundle.
# ---------------------------------------------------------------------------

def _aib_impl(ctx):
    product_sources = [
        str(src.label)
        for src in ctx.attr.bootfs_srcs
        if src.label.package == "products" or src.label.package.startswith("products/")
    ]
    if product_sources:
        fail("cerise_assembly_input_bundle %r must not depend on product target(s): %s; stage bundle-owned artifacts instead" %
             (ctx.label.name, ", ".join(product_sources)))
    n = len(ctx.attr.config_components)
    if (len(ctx.attr.config_cms) != n or len(ctx.attr.config_values_json) != n or
        len(ctx.attr.config_cvf_dests) != n or len(ctx.attr.config_boot_drivers_fields) != n):
        fail("cerise_assembly_input_bundle %r: config_* attr lists must be parallel" %
             ctx.label.name)
    configs = [
        struct(
            component = ctx.attr.config_components[i],
            cm = _single_file(
                ctx.attr.config_cms[i],
                "%s config schema for %r" % (ctx.label, ctx.attr.config_components[i]),
            ),
            values = json.decode(ctx.attr.config_values_json[i]),
            cvf_dest = ctx.attr.config_cvf_dests[i],
            boot_drivers_field = ctx.attr.config_boot_drivers_fields[i],
        )
        for i in range(n)
    ]
    return [
        DefaultInfo(),
        AIBInfo(
            bundle_name = ctx.attr.bundle_name or ctx.label.name,
            requires_features = ctx.attr.requires_features,
            cmdline = ctx.attr.cmdline,
            bootfs = _bootfs_pairs(ctx.attr.bootfs_dests, ctx.attr.bootfs_srcs, str(ctx.label), ctx.attr.validation),
            configs = configs,
        ),
    ]

_cerise_aib = rule(
    implementation = _aib_impl,
    attrs = {
        "bundle_name": attr.string(),
        "requires_features": attr.string_list(),
        "cmdline": attr.string_list(),
        "bootfs_dests": attr.string_list(),
        "bootfs_srcs": attr.label_list(allow_files = True),
        "config_components": attr.string_list(),
        "config_cms": attr.label_list(allow_files = [".cm"]),
        "config_values_json": attr.string_list(),
        "config_cvf_dests": attr.string_list(),
        "config_boot_drivers_fields": attr.string_list(),
        "validation": attr.bool(default = False, doc = "This bundle's executable placements are validation tooling."),
    },
    provides = [AIBInfo],
    doc = "A reusable assembly input bundle (component/package set + required features).",
)

def cerise_assembly_input_bundle(
        name,
        requires_features = [],
        cmdline = [],
        bootfs = {},
        configs = {},
        validation = False,
        **kwargs):
    """A reusable named set of components/packages with bootfs placements.

    Args:
      name:              bundle target name and identity.
      requires_features: list[str] of hardware features the bundle needs from the board.
      cmdline:           list[str] of bundle-contributed kernel cmdline fragments.
      bootfs:            {dest: label} of component/package bootfs placements.
      configs:           {component: {...}} of component structured-config entries the
                         bundle carries. Each entry names the compiled .cm ('cm', whose
                         ConfigSchema the values must satisfy), the bundle-default
                         'values' dict, an optional 'cvf_dest' bootfs destination
                         (default pkg/<component>/meta/<component>.cvf), and an optional
                         'boot_drivers_field' — the name of a config field the product
                         rule fills with BoardInfo.boot_drivers. The product rule merges
                         product-level value overrides (unknown keys are analysis
                         errors), generates the .cvf via configc, and stages it.
      **kwargs:          forwarded to the underlying rule (visibility, tags, ...).
    """
    dests = sorted(bootfs.keys())
    srcs = [bootfs[d] for d in dests]
    components, cms, values_json, cvf_dests, bd_fields = _config_entries(
        configs,
        "cerise_assembly_input_bundle %r" % name,
    )
    _cerise_aib(
        name = name,
        bundle_name = name,
        requires_features = requires_features,
        cmdline = cmdline,
        bootfs_dests = dests,
        bootfs_srcs = srcs,
        config_components = components,
        config_cms = cms,
        config_values_json = values_json,
        config_cvf_dests = cvf_dests,
        config_boot_drivers_fields = bd_fields,
        validation = validation,
        **kwargs
    )

# ---------------------------------------------------------------------------
# cerise_product.
# ---------------------------------------------------------------------------

def _product_impl(ctx):
    board = ctx.attr.board[BoardInfo]
    bundles = [b[AIBInfo] for b in ctx.attr.bundles]
    if RootRealmInfo not in ctx.attr.root_realm:
        fail(("cerise_product %r: root_realm must provide RootRealmInfo; " +
              "use cerise_root_realm or a compiled cerise_component manifest") %
             ctx.label.name)
    root_realm = ctx.attr.root_realm[RootRealmInfo]
    provided = board.provided_features

    _validate_input_zbis(ctx.label.name, board, ctx.attr.input_zbis)

    # 1. Feature resolution: wanted subset-of provided, else analysis error.
    missing = []
    for b in bundles:
        for f in b.requires_features:
            if f not in provided:
                missing.append((b.bundle_name, f))
    if missing:
        lines = [
            "cerise_product %r: the board %r does not provide feature(s) required by its bundles:" %
            (ctx.label.name, board.board_name),
        ]
        for bundle_name, feature in missing:
            lines.append("  bundle %r requires %r" % (bundle_name, feature))
        lines.append("  board %r provides: %s" %
                     (board.board_name, ", ".join(provided) if provided else "<none>"))
        fail("\n".join(lines))

    # 2. bootfs merge (board -> bundles -> product), collision = analysis error.
    merged = {}
    origin = {}
    _merge_into(ctx.label.name, merged, origin, board.bootfs, "board " + board.board_name)
    for b in bundles:
        _merge_into(ctx.label.name, merged, origin, b.bootfs, "bundle " + b.bundle_name)
    product_pairs = _bootfs_pairs(
        ctx.attr.bootfs_dests,
        ctx.attr.bootfs_srcs,
        "%s product" % ctx.label,
    )
    _validate_bootfs_architecture(ctx.label.name, board, board.bootfs, "board " + board.board_name)
    for b in bundles:
        _validate_bootfs_architecture(ctx.label.name, board, b.bootfs, "bundle " + b.bundle_name)
    _validate_bootfs_architecture(ctx.label.name, board, product_pairs, "product " + ctx.label.name)
    _merge_into(ctx.label.name, merged, origin, product_pairs, "product " + ctx.label.name)

    # Root realm: product-owned, staged at the fixed pkg/root/meta/root.cm. It is a
    # first-class attr (not a product_bootfs entry) because the root realm wires the
    # product's specific children — it is product identity, not bundle data. Merged
    # through the same collision path, so a board/bundle also claiming that dest is a
    # named analysis error.
    _merge_into(
        ctx.label.name,
        merged,
        origin,
        [struct(dest = _ROOT_REALM_DEST, file = ctx.file.root_realm,
                artifact_architecture = None, artifact_kind = "metadata", validation = False)],
        "product %s root_realm" % ctx.label.name,
    )

    # 2b. Component structured config: bundles carry the schema (.cm) + default
    #     values; the board contributes boot_drivers where a bundle declared an
    #     injection field; the product may override values (unknown component or
    #     key = analysis error). The merged values become a configc-generated
    #     .cvf staged at pkg/<component>/meta/<component>.cvf (or the entry's
    #     explicit cvf_dest), where component_manager's boot resolver delivers
    #     it as the component's config VMO.
    config_index = {}  # component -> (entry, bundle_name)
    for b in bundles:
        for entry in b.configs:
            if entry.component in config_index:
                fail(("cerise_product %r: component %r has config entries in both " +
                      "bundle %r and bundle %r; exactly one bundle may carry a " +
                      "component's config.") %
                     (ctx.label.name, entry.component,
                      config_index[entry.component][1], b.bundle_name))
            config_index[entry.component] = (entry, b.bundle_name)

    overrides = {}
    if len(ctx.attr.config_override_components) != len(ctx.attr.config_override_values_json):
        fail("cerise_product %r: config_override_* attr lists must be parallel" %
             ctx.label.name)
    for i in range(len(ctx.attr.config_override_components)):
        comp = ctx.attr.config_override_components[i]
        if comp not in config_index:
            fail(("cerise_product %r: config_overrides names component %r, but no " +
                  "composed bundle carries a config for it. Components with configs: %s") %
                 (ctx.label.name, comp,
                  ", ".join(sorted(config_index.keys())) if config_index else "<none>"))
        overrides[comp] = json.decode(ctx.attr.config_override_values_json[i])

    product_configs = []
    for comp in sorted(config_index.keys()):
        entry, bundle_name = config_index[comp]
        values = dict(entry.values)
        if entry.boot_drivers_field:
            values[entry.boot_drivers_field] = board.boot_drivers
        known_keys = {k: None for k in values}
        for key, value in overrides.get(comp, {}).items():
            if key not in known_keys:
                fail(("cerise_product %r: config_overrides[%r] sets unknown key %r. " +
                      "Known keys (from bundle %r): %s") %
                     (ctx.label.name, comp, key, bundle_name,
                      ", ".join(sorted(known_keys.keys()))))
            values[key] = value

        values_file = ctx.actions.declare_file(
            "%s.%s.config_values.json" % (ctx.label.name, comp),
        )
        ctx.actions.write(values_file, json.encode(values))
        cvf = ctx.actions.declare_file("%s.%s.cvf" % (ctx.label.name, comp))
        args = ctx.actions.args()
        args.add("cvf")
        args.add("--cm", entry.cm)
        args.add("--values", values_file)
        args.add("--output", cvf)
        ctx.actions.run(
            executable = ctx.executable._configc,
            arguments = [args],
            inputs = [entry.cm, values_file],
            outputs = [cvf],
            mnemonic = "CONFIGCCVF",
            progress_message = "Generating structured-config values for %s in %s" %
                               (comp, ctx.label),
        )
        _merge_into(
            ctx.label.name,
            merged,
            origin,
            [struct(dest = entry.cvf_dest, file = cvf,
                    artifact_architecture = None, artifact_kind = "metadata", validation = False)],
            "config for component %s (bundle %s)" % (comp, bundle_name),
        )
        product_configs.append(struct(component = comp, dest = entry.cvf_dest, values = values))

    # Every staged package executable must either name a package launched by
    # the selected root realm or be explicitly marked validation tooling by a
    # composed validation bundle. This is analysis-time inventory, before ZBI
    # emission, so an accidentally dormant binary cannot hide in an image.
    staged_packages = {}
    for dest in merged:
        parts = dest.split("/")
        if len(parts) >= 3 and parts[0] == "pkg":
            staged_packages[parts[1]] = True
    missing_packages = [
        package
        for package in root_realm.required_boot_packages + root_realm.indirect_packages
        if package not in staged_packages
    ]
    if missing_packages:
        fail(("cerise_product %r: root_realm %r requires fuchsia-boot package(s) " +
              "not staged in bootfs: %s") %
             (ctx.label.name, ctx.attr.root_realm.label, ", ".join(sorted(missing_packages))))

    placements = [board.bootfs]
    placements.extend([b.bootfs for b in bundles])
    placements.append(product_pairs)
    reachable_packages = root_realm.required_boot_packages + root_realm.indirect_packages
    for source in placements:
        for placement in source:
            if placement.artifact_kind != "executable":
                continue
            dest = placement.dest
            if dest in _BOOTSTRAP_EXECUTABLES or dest in root_realm.reachable_executables:
                continue
            parts = dest.split("/")
            package = parts[1] if len(parts) >= 3 and parts[0] == "pkg" else ""
            if package in reachable_packages or placement.validation:
                continue
            fail(("cerise_product %r: executable %r (package %r) is not reachable " +
                  "from root_realm %r; put it under a declared child package or " +
                  "compose a validation bundle explicitly") %
                 (ctx.label.name, dest, package, ctx.attr.root_realm.label))

    # 3. cmdline concat: board, then bundles in list order, then product.
    cmdline = list(board.kernel_cmdline)
    for b in bundles:
        cmdline = cmdline + b.cmdline
    cmdline = cmdline + ctx.attr.cmdline

    # 4. Emit the ZBI. Sort by dest for a deterministic layout (matches the
    #    legacy zircon_system macro, which also sorts extra_bootfs by dest).
    dests = sorted(merged.keys())
    src_files = [merged[d] for d in dests]

    output = ctx.actions.declare_file(ctx.label.name + ".zbi")
    emit_zbi(
        ctx,
        output = output,
        input_zbi_files = ctx.files.input_zbis,
        simple_zbi_file = ctx.file._simple_zbi,
        cmdline = cmdline,
        mem_config = ctx.attr.mem_config,
        dests = dests,
        src_files = src_files,
        # Arch kernel-driver items are BOARD DATA (empty for x64: byte-identical).
        kernel_drivers = board.kernel_drivers,
        # zstd-compress STORAGE_BOOTFS on x86_64 (userboot decompresses it at
        # runtime). Gated to x86_64: arm64 userboot's zstd payload is unverified
        # and has no boot gate, so an aarch64 board emits a raw bootfs.
        zstd_tool = ctx.executable._zstd_tool if board.arch == "x86_64" else None,
    )

    return [
        DefaultInfo(files = depset([output])),
        ProductBundleInfo(
            product_name = ctx.label.name,
            board_name = board.board_name,
            bundle_names = [b.bundle_name for b in bundles],
            zbi = output,
            provided_features = provided,
            requested_features = [f for b in bundles for f in b.requires_features],
            configs = product_configs,
        ),
    ]

_cerise_product = rule(
    implementation = _product_impl,
    attrs = {
        "board": attr.label(mandatory = True, providers = [BoardInfo]),
        "root_realm": attr.label(
            mandatory = True,
            allow_single_file = [".cm"],
            doc = "The product's root-realm compiled .cm, staged at pkg/root/meta/root.cm. " +
                  "Product-owned: the root realm wires this product's specific children.",
        ),
        "bundles": attr.label_list(providers = [AIBInfo]),
        "cmdline": attr.string_list(),
        "mem_config": attr.string_list(),
        "bootfs_dests": attr.string_list(),
        "bootfs_srcs": attr.label_list(allow_files = True),
        "config_override_components": attr.string_list(),
        "config_override_values_json": attr.string_list(),
        "input_zbis": attr.label_list(
            allow_files = True,
            default = [_DEFAULT_PHYSLOAD, _DEFAULT_KERNEL_STORAGE],
            doc = "Input ZBI containers (physload + kernel storage), merged in order.",
        ),
        "_simple_zbi": attr.label(
            default = "//tools/zbi:simple_zbi.py",
            allow_single_file = True,
        ),
        "_configc": attr.label(
            default = "//src/upstream/fuchsia/tools/configc:configc",
            executable = True,
            cfg = "exec",
        ),
        "_zstd_tool": attr.label(
            default = "//tools/zstd:zstd_cli",
            executable = True,
            cfg = "exec",
        ),
    },
    provides = [ProductBundleInfo],
    doc = "Compose a board + bundles + product config into one bootable ZBI.",
)

def cerise_product(
        name,
        board,
        root_realm,
        bundles = [],
        cmdline = [],
        mem_config = [],
        product_bootfs = {},
        config_overrides = {},
        physload = None,
        kernel_storage = None,
        **kwargs):
    """Compose a board + bundles + product config into a bootable ZBI.

    Feature resolution, bootfs merge (with collision detection), cmdline
    concatenation and config-value merging all happen in analysis inside the
    underlying rule.

    Args:
      name:           product target name; default output is <name>.zbi.
      board:          label of a cerise_board.
      root_realm:     label of the product's root-realm compiled .cm. Staged at the
                      fixed pkg/root/meta/root.cm. Product-owned (the root realm wires
                      this product's specific children) — a first-class attr, so it may
                      NOT also appear in product_bootfs.
      bundles:        list of cerise_assembly_input_bundle labels (order defines
                      cmdline order after the board's).
      cmdline:        list[str] of product-only kernel cmdline fragments (appended last).
      mem_config:     list[str] of PADDR,SIZE,TYPE memory-config items.
      product_bootfs: {dest: label} of product-only bootfs placements (product-specific
                      components beyond the bundles; the root realm goes via root_realm=).
      config_overrides: {component: {field: value}} of product-level structured-config
                      value overrides, merged over the bundle-default values (and any
                      board boot_drivers injection). Naming a component no bundle
                      carries a config for, or a field not in the bundle's default
                      values, is an analysis-time error.
      physload:       override the physboot loader ZBI (default
                      //build/phys:physload_artifact). The target must provide
                      ArtifactArchitectureInfo with kind="physload".
      kernel_storage: override the kernel storage ZBI (default
                      //build/kernel:kernel_storage_zbi_artifact). The target must
                      provide ArtifactArchitectureInfo with kind="kernel_storage".
      **kwargs:       forwarded to the underlying rule (visibility, tags, ...).
    """
    if _ROOT_REALM_DEST in product_bootfs:
        fail(("cerise_product %r: the root realm is a first-class attr — pass it as " +
              "root_realm = <label>, not product_bootfs[%r].") % (name, _ROOT_REALM_DEST))
    dests = sorted(product_bootfs.keys())
    srcs = [product_bootfs[d] for d in dests]
    override_components = sorted(config_overrides.keys())
    override_values_json = [json.encode(config_overrides[c]) for c in override_components]
    extra = {}
    if physload != None or kernel_storage != None:
        extra["input_zbis"] = [
            physload if physload != None else _DEFAULT_PHYSLOAD,
            kernel_storage if kernel_storage != None else _DEFAULT_KERNEL_STORAGE,
        ]
    _cerise_product(
        name = name,
        board = board,
        root_realm = root_realm,
        bundles = bundles,
        cmdline = cmdline,
        mem_config = mem_config,
        bootfs_dests = dests,
        bootfs_srcs = srcs,
        config_override_components = override_components,
        config_override_values_json = override_values_json,
        **dict(extra, **kwargs)
    )
