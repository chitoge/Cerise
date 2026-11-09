# The Cerise composition model

Cerise composes operating systems the way Fuchsia's platform / board / product
assembly trichotomy intends — but realized entirely in **Bazel analysis** as
typed providers, not by an external assembly tool. A system image is an ordinary
Bazel target; composing one is writing down three explicit label lists and
letting the rules resolve them.

There are three layers, each a rule that yields a typed provider:

| Layer | Rule | Provider | Answers |
|-------|------|----------|---------|
| **Board** | `cerise_board` | `BoardInfo` | *what hardware is this?* |
| **Bundle** | `cerise_assembly_input_bundle` | `AIBInfo` | *what reusable capability set?* |
| **Product** | `cerise_product` | `ProductBundleInfo` | *what complete system?* |

## Board — hardware identity

A `cerise_board` names a machine. It carries the kernel command line, the arch,
the boot-driver list (as data — driver component URLs, not code), the bootfs
placements for those drivers, and the **hardware features it provides** as a set
of tokens (for example `cerise::block`, `cerise::virtio-net`, `cerise::nvme`,
`cerise::pci`, `cerise::acpi`). Each board pairs with a Bazel `platform()`.

```python
cerise_board(
    name = "qemu-x64",
    arch = "x86_64",
    platform = "//platforms:x64-fuchsia",
    provided_features = ["cerise::block", "cerise::virtio-net", "cerise::nvme", ...],
    boot_drivers = QEMU_X64_BOOT_DRIVERS,   # driver URLs = board data
    bootfs = { ... },                        # driver .so / .cm / bind bytecode
)
```

Making the driver list *board data* is deliberate: a third party ships a new
board — with its own drivers — as an ordinary Bazel module, without editing any
core file. The driver index learns its drivers from the board through the
generated structured config, not from a hand-maintained list in the tree.

## Bundle — a reusable capability set

A `cerise_assembly_input_bundle` is a named, reusable set of components with
their bootfs placements, the hardware features it **requires**, cmdline
fragments, and structured-config schemas + default values for its components.
Bundles are the unit of reuse across products.

```python
cerise_assembly_input_bundle(
    name = "storage_fxfs",
    requires_features = ["cerise::block"],   # a board must provide this
    bootfs = { ... },                        # fshost, fxfs, crypt, provisioner, ...
    configs = { ... },                       # component → schema + default values
)
```

First bundles: `component_framework` (component_manager, elf_runner, log sink),
`driver_framework` (driver manager, driver index, driver host, the platform bus
stack), `netstack3`, and `storage_fxfs`.

## Product — a complete system

A `cerise_product` is the whole thing: a board, a list of bundles, this
product's own components (`product_bootfs`), a mandatory `root_realm`, and
optional structured-config overrides. Building it produces `<name>.zbi`.

The product rule does the real work at **analysis time**:

1. **Feature resolution.** For every bundle's `requires_features`, if the board
   does not `provide` it, the build fails with a message naming the bundle, the
   missing token, and what the board does provide. There is no runtime surprise.
2. **Bootfs merge.** Board → bundles → product → root realm, in order, with a
   destination-collision check that names the two origins of any clash.
3. **Structured-config delivery.** Bundle-default values, board-derived values
   (e.g. the boot-driver list), and product overrides are merged, compiled to
   `.cvf` value files, and staged so component_manager delivers them at start.
   Unknown component or unknown config key is an analysis error.
4. **Image assembly.** The merged bootfs, the kernel, and the boot loader are
   assembled into a ZBI.

```python
cerise_product(
    name = "qemu-x64-storage",
    board = "//boards/qemu-x64",
    bundles = ["//bundles:component_framework", "//bundles:driver_framework", "//bundles:storage_fxfs"],
    root_realm = "//src/cerise/realms:root_dfv2acpi_fshost_manifest",
)
```

### The root realm is product identity

`root_realm` is a first-class, mandatory attribute — not a bootfs dict entry.
The root realm wires *this product's* specific children: which components are
eager, how capabilities route, which terminal probe runs. That is the one thing
a product cannot share the way it shares a bundle, so it is modeled as its own
attribute. The rule stages it at the fixed image path internally; placing that
path through `product_bootfs` is a build error.

## Principles

- **Explicit label lists only.** No append/override mechanism, no layer
  ordering, no ambient injection. Composition is what you can read in the
  `cerise_product` call.
- **Features are product-config data, not build flags.** Coarse build axes stay
  as flags; per-feature selection is board/bundle/product data resolved in
  analysis.
- **Third parties compose as Bazel modules.** Boards, bundles, and components
  ship as ordinary bzlmod dependencies; nothing about a new board or driver
  requires editing the core.

## Verification

Composition itself is tested. `//assembly/tests` includes analysis tests that a
missing required feature fails with the expected message and that a bootfs
collision is caught — so the rules' guarantees are enforced, not assumed. Every
product's realm graph is additionally checked for capability-routing
completeness and least privilege at build time.
