<!-- Generated with Stardoc: http://skydoc.bazel.build -->

Typed providers for the Cerise composition layer (board / bundle / product).

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

<a id="AIBInfo"></a>

## AIBInfo

<pre>
load("@cerise//assembly:providers.bzl", "AIBInfo")

AIBInfo(<a href="#AIBInfo-bundle_name">bundle_name</a>, <a href="#AIBInfo-requires_features">requires_features</a>, <a href="#AIBInfo-cmdline">cmdline</a>, <a href="#AIBInfo-bootfs">bootfs</a>, <a href="#AIBInfo-configs">configs</a>)
</pre>

Assembly input bundle: a reusable named set of components/packages with bootfs placements, required hardware features, and cmdline fragments.

**FIELDS**

| Name  | Description |
| :------------- | :------------- |
| <a id="AIBInfo-bundle_name"></a>bundle_name |  String bundle identity (e.g. "netstack3").    |
| <a id="AIBInfo-requires_features"></a>requires_features |  list[str] of hardware feature tokens the bundle needs from the board.    |
| <a id="AIBInfo-cmdline"></a>cmdline |  list[str] of kernel cmdline fragments contributed by the bundle.    |
| <a id="AIBInfo-bootfs"></a>bootfs |  list[struct(dest, file, artifact_architecture, artifact_kind, validation)] of the bundle's component/package bootfs placements.    |
| <a id="AIBInfo-configs"></a>configs |  list[struct(component, cm, values, cvf_dest, boot_drivers_field)] of component structured-config entries: the bundle carries the schema (via the compiled .cm) and the default values; the product rule merges overrides and stages the generated .cvf at cvf_dest.    |


<a id="ArtifactArchitectureInfo"></a>

## ArtifactArchitectureInfo

<pre>
load("@cerise//assembly:providers.bzl", "ArtifactArchitectureInfo")

ArtifactArchitectureInfo(<a href="#ArtifactArchitectureInfo-arch">arch</a>, <a href="#ArtifactArchitectureInfo-kind">kind</a>)
</pre>

Architecture and role of a staged executable or ZBI artifact.

**FIELDS**

| Name  | Description |
| :------------- | :------------- |
| <a id="ArtifactArchitectureInfo-arch"></a>arch |  String CPU architecture for which this artifact was produced (for example x86_64 or aarch64).    |
| <a id="ArtifactArchitectureInfo-kind"></a>kind |  Artifact role: physload, kernel_storage, or userspace.    |


<a id="BoardInfo"></a>

## BoardInfo

<pre>
load("@cerise//assembly:providers.bzl", "BoardInfo")

BoardInfo(<a href="#BoardInfo-board_name">board_name</a>, <a href="#BoardInfo-platform">platform</a>, <a href="#BoardInfo-arch">arch</a>, <a href="#BoardInfo-provided_features">provided_features</a>, <a href="#BoardInfo-kernel_cmdline">kernel_cmdline</a>, <a href="#BoardInfo-kernel_drivers">kernel_drivers</a>, <a href="#BoardInfo-bootfs">bootfs</a>,
          <a href="#BoardInfo-boot_drivers">boot_drivers</a>)
</pre>

Hardware identity: kernel cmdline fragments, driver packages (as bootfs placements) and the hardware features the board provides.

**FIELDS**

| Name  | Description |
| :------------- | :------------- |
| <a id="BoardInfo-board_name"></a>board_name |  String board identity (e.g. "qemu-x64").    |
| <a id="BoardInfo-platform"></a>platform |  Label string of the Bazel platform() this board pairs with, or "".    |
| <a id="BoardInfo-arch"></a>arch |  String CPU arch of the board (e.g. "x86_64", "aarch64"). BOARD DATA: the arch a third-party board declares; the arch-specific ZBI items (mem_config, kernel_drivers) are supplied as data below rather than hardcoded in tools/zbi/simple_zbi.py.    |
| <a id="BoardInfo-provided_features"></a>provided_features |  list[str] of hardware feature tokens the board provides (e.g. "cerise::nvme", "cerise::e1000", "cerise::network-device").    |
| <a id="BoardInfo-kernel_cmdline"></a>kernel_cmdline |  list[str] of kernel cmdline fragments contributed by the board.    |
| <a id="BoardInfo-kernel_drivers"></a>kernel_drivers |  list[str] of arch kernel-driver ZBI items as "DRIVER_TYPE=HEXPAYLOAD" (e.g. an ARM GIC or generic-timer register block). BOARD DATA passed verbatim to simple_zbi.py's --kernel-driver, so a new arch adds a board, not a tool edit.    |
| <a id="BoardInfo-bootfs"></a>bootfs |  list[struct(dest, file, artifact_architecture, artifact_kind, validation)] of the board's driver/package bootfs placements.    |
| <a id="BoardInfo-boot_drivers"></a>boot_drivers |  list[str] of boot-driver component URLs this board's drivers register with the driver index (e.g. "fuchsia-boot:///nvme#meta/nvme.cm"). BOARD DATA: flows through the product rule into the generated driver-index config values (see AIBInfo.configs boot_drivers_field).    |


<a id="ProductBundleInfo"></a>

## ProductBundleInfo

<pre>
load("@cerise//assembly:providers.bzl", "ProductBundleInfo")

ProductBundleInfo(<a href="#ProductBundleInfo-product_name">product_name</a>, <a href="#ProductBundleInfo-board_name">board_name</a>, <a href="#ProductBundleInfo-bundle_names">bundle_names</a>, <a href="#ProductBundleInfo-zbi">zbi</a>, <a href="#ProductBundleInfo-provided_features">provided_features</a>,
                  <a href="#ProductBundleInfo-requested_features">requested_features</a>, <a href="#ProductBundleInfo-configs">configs</a>)
</pre>

A fully-composed product: one board + a list of bundles + product config, feature-resolved and merged into a single bootable ZBI.

**FIELDS**

| Name  | Description |
| :------------- | :------------- |
| <a id="ProductBundleInfo-product_name"></a>product_name |  String product identity.    |
| <a id="ProductBundleInfo-board_name"></a>board_name |  The board this product was assembled for.    |
| <a id="ProductBundleInfo-bundle_names"></a>bundle_names |  list[str] of bundle names composed into this product (in order).    |
| <a id="ProductBundleInfo-zbi"></a>zbi |  The assembled ZBI File.    |
| <a id="ProductBundleInfo-provided_features"></a>provided_features |  list[str] of features the board provides.    |
| <a id="ProductBundleInfo-requested_features"></a>requested_features |  list[str] of features the composed bundles required (all resolved OK).    |
| <a id="ProductBundleInfo-configs"></a>configs |  list[struct(component, dest, values)] of the component structured-config values this product staged: the final merged values (bundle defaults + board boot_drivers injection + product overrides) and the bootfs dest of the generated .cvf.    |


<a id="RootRealmInfo"></a>

## RootRealmInfo

<pre>
load("@cerise//assembly:providers.bzl", "RootRealmInfo")

RootRealmInfo(<a href="#RootRealmInfo-required_boot_packages">required_boot_packages</a>, <a href="#RootRealmInfo-resolver_packages">resolver_packages</a>, <a href="#RootRealmInfo-indirect_packages">indirect_packages</a>, <a href="#RootRealmInfo-reachable_executables">reachable_executables</a>)
</pre>

Declared package reachability of a product root realm.

**FIELDS**

| Name  | Description |
| :------------- | :------------- |
| <a id="RootRealmInfo-required_boot_packages"></a>required_boot_packages |  list[str] package names in fuchsia-boot child URLs.    |
| <a id="RootRealmInfo-resolver_packages"></a>resolver_packages |  list[str] package names in fuchsia-pkg child URLs; not required in bootfs.    |
| <a id="RootRealmInfo-indirect_packages"></a>indirect_packages |  list[str] packages launched below a root child (for example fshost-owned storage services).    |
| <a id="RootRealmInfo-reachable_executables"></a>reachable_executables |  list[str] bootfs executable paths launched indirectly by the root realm (for example driver hosts).    |


