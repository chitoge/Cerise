"""Typed providers for the Cerise composition layer (board / bundle / product).

These provider schemas are the PUBLIC ABI of the composition system:
third-party boards/bundles/products depend on these field names. Adding,
removing, or renaming a field is a breaking change and must be versioned.

An assembly bootfs placement is represented uniformly as a `struct(dest, file,
artifact_architecture, artifact_kind, validation)`:
  * dest = <string> STORAGE_BOOTFS destination path (e.g. "pkg/foo/bin/foo")
  * file = <File>   the source file staged at that path
  * artifact_architecture = <ArtifactArchitectureInfo or None>; present for
    architecture-tagged executable artifacts and absent for manifests/data.
  * artifact_kind = executable, library, metadata, or data, based on the
    declared STORAGE_BOOTFS package layout.
  * validation = true only for an explicitly validation/probe bundle.

A component structured-config entry (schema version 2 addition) is a
`struct(component, cm, values, cvf_dest, boot_drivers_field)`:
  * component         = <string> component identity (e.g. "fshost")
  * cm                = <File>   the compiled .cm whose ConfigSchema the values satisfy
  * values            = <dict>   bundle-default config values (field -> value)
  * cvf_dest          = <string> STORAGE_BOOTFS dest of the generated .cvf
                                 (default "pkg/<component>/meta/<component>.cvf")
  * boot_drivers_field= <string> name of a config field the product rule fills with
                                 BoardInfo.boot_drivers, or "" (no injection)

Schema version 2 (additive): BoardInfo.boot_drivers, AIBInfo.configs,
ProductBundleInfo.configs. Version 1 fields are unchanged.

Schema version 3 (additive): BoardInfo.arch, BoardInfo.kernel_drivers (arch data
that keeps tools/zbi/simple_zbi.py arch-neutral). Earlier fields are unchanged.

Schema version 4 (additive): ArtifactArchitectureInfo tags a staged executable
or ZBI with the architecture for which it was produced. Product composition
uses this provider to reject a board/artifact mismatch during analysis.

Schema version 5 (additive): RootRealmInfo records the package names a root
realm can launch. AIBInfo bootfs records an artifact kind and whether its
executable is explicitly validation tooling, allowing product composition to
check staged executable reachability without inspecting generated ZBIs.
"""

ArtifactArchitectureInfo = provider(
    doc = "Architecture and role of a staged executable or ZBI artifact.",
    fields = {
        "arch": "String CPU architecture for which this artifact was produced (for example x86_64 or aarch64).",
        "kind": "Artifact role: physload, kernel_storage, or userspace.",
    },
)

RootRealmInfo = provider(
    doc = "Declared package reachability of a product root realm.",
    fields = {
        "required_boot_packages": "list[str] package names in fuchsia-boot child URLs.",
        "resolver_packages": "list[str] package names in fuchsia-pkg child URLs; not required in bootfs.",
        "indirect_packages": "list[str] packages launched below a root child (for example fshost-owned storage services).",
        "reachable_executables": "list[str] bootfs executable paths launched indirectly by the root realm (for example driver hosts).",
    },
)

BoardInfo = provider(
    doc = "Hardware identity: kernel cmdline fragments, driver packages (as " +
          "bootfs placements) and the hardware features the board provides.",
    fields = {
        "board_name": "String board identity (e.g. \"qemu-x64\").",
        "platform": "Label string of the Bazel platform() this board pairs with, or \"\".",
        "arch": "String CPU arch of the board (e.g. \"x86_64\", \"aarch64\"). BOARD DATA: " +
                "the arch a third-party board declares; the arch-specific ZBI items " +
                "(mem_config, kernel_drivers) are supplied as data below rather than " +
                "hardcoded in tools/zbi/simple_zbi.py.",
        "provided_features": "list[str] of hardware feature tokens the board provides " +
                             "(e.g. \"cerise::nvme\", \"cerise::e1000\", " +
                             "\"cerise::network-device\").",
        "kernel_cmdline": "list[str] of kernel cmdline fragments contributed by the board.",
        "kernel_drivers": "list[str] of arch kernel-driver ZBI items as " +
                          "\"DRIVER_TYPE=HEXPAYLOAD\" (e.g. an ARM GIC or generic-timer " +
                          "register block). BOARD DATA passed verbatim to simple_zbi.py's " +
                          "--kernel-driver, so a new arch adds a board, not a tool edit.",
        "bootfs": "list[struct(dest, file, artifact_architecture, artifact_kind, validation)] of the board's driver/package bootfs placements.",
        "boot_drivers": "list[str] of boot-driver component URLs this board's drivers " +
                        "register with the driver index (e.g. " +
                        "\"fuchsia-boot:///nvme#meta/nvme.cm\"). BOARD DATA: flows " +
                        "through the product rule into the generated driver-index " +
                        "config values (see AIBInfo.configs boot_drivers_field).",
    },
)

AIBInfo = provider(
    doc = "Assembly input bundle: a reusable named set of components/packages with " +
          "bootfs placements, required hardware features, and cmdline fragments.",
    fields = {
        "bundle_name": "String bundle identity (e.g. \"netstack3\").",
        "requires_features": "list[str] of hardware feature tokens the bundle needs from the board.",
        "cmdline": "list[str] of kernel cmdline fragments contributed by the bundle.",
        "bootfs": "list[struct(dest, file, artifact_architecture, artifact_kind, validation)] of the bundle's component/package bootfs placements.",
        "configs": "list[struct(component, cm, values, cvf_dest, boot_drivers_field)] of " +
                   "component structured-config entries: the bundle carries the schema " +
                   "(via the compiled .cm) and the default values; the product rule " +
                   "merges overrides and stages the generated .cvf at cvf_dest.",
    },
)

ProductBundleInfo = provider(
    doc = "A fully-composed product: one board + a list of bundles + product config, " +
          "feature-resolved and merged into a single bootable ZBI.",
    fields = {
        "product_name": "String product identity.",
        "board_name": "The board this product was assembled for.",
        "bundle_names": "list[str] of bundle names composed into this product (in order).",
        "zbi": "The assembled ZBI File.",
        "provided_features": "list[str] of features the board provides.",
        "requested_features": "list[str] of features the composed bundles required (all resolved OK).",
        "configs": "list[struct(component, dest, values)] of the component structured-config " +
                   "values this product staged: the final merged values (bundle defaults + " +
                   "board boot_drivers injection + product overrides) and the bootfs dest " +
                   "of the generated .cvf.",
    },
)
