# Getting started

This tutorial builds a Cerise image, boots it, runs the test suite, and composes
a small system of your own. It assumes a Linux host with Bazel; everything else
— compilers, QEMU, firmware — is fetched hermetically by the build. No commands
here change your system outside the build tree.

Throughout, `//` refers to the repository root in Bazel's label syntax; `bazel`
is the only tool you invoke.

## Build your first image

The smallest image is `x64-smoke`, a minimal x86_64 boot:

```sh
bazel build //products:x64-smoke
```

The output is a `.zbi` — a bootable Zircon Boot Image. Building it pulls the
hermetic toolchains and vendored sources on first use; later builds are
incremental.

## Boot it under QEMU

Cerise validates images by booting them. The smoke image has a live boot test
that starts it in a pinned QEMU with UEFI firmware and waits for the boot to
reach userland:

```sh
bazel test //validation:smoke-uefi-boot
```

A passing result means a real system image booted to completion inside the
emulator. The test asserts ordered `CERISE-…` progress markers on the serial
console, so it verifies behavior, not just that a file was produced.

## Run the checks and unit tests

Two suites are worth knowing:

```sh
bazel test //build/checks:all      # analysis-level shape and routing checks
bazel test //tests/unit:unit_tests # the vendored upstream unit-test suites
```

The first runs at analysis time and is fast; it verifies structural invariants
such as capability-routing completeness. The second runs the library test suites
Cerise inherits.

## Boot the flagship

The flagship product runs a gRPC file server on the full modern stack. Two tests
prove it end to end by booting the real OS and driving it from the host:

```sh
bazel test //validation:fileserver-grpc-boot    # exercise every file-server RPC
bazel test //validation:fileserver-persistence  # write, reboot, verify data survives
```

These boot `//products:qemu-x64-fileserver` — netstack3 for transport, fxfs for
storage — and a host-side gRPC client writes, reads back, lists, and deletes
files over the emulated network.

## Compose a system

A complete system is a `cerise_product`: a board, some bundles, a root realm,
and this product's own components. The storage image is a compact example:

```python
cerise_product(
    name = "my-storage",
    board = "//boards/qemu-x64",
    bundles = [
        "//bundles:component_framework",
        "//bundles:driver_framework",
        "//bundles:storage_fxfs",
    ],
    root_realm = "//src/cerise/realms:root_dfv2acpi_fshost_manifest",
)
```

Building `//products:my-storage` resolves the storage bundle's required hardware
features against what the board provides, merges the boot filesystem, delivers
each component's structured configuration, and assembles a ZBI. If a bundle
required a feature the board did not provide, the build would stop with a message
naming the bundle and the missing feature — you would never discover it at boot.

To learn what bundles and boards exist, read their `BUILD.bazel` files under
`bundles/` and `boards/`; to understand the pieces, see
[composition-model.md](composition-model.md).

## Write a component

A component is a program plus a `.cml` manifest declaring what it uses and
offers. Compile the manifest with `cerise_component`:

```python
cerise_component(
    name = "my_component",
    manifest = "meta/my_component.cml",
)
```

The manifest names the program binary, the capabilities the component `use`s
(protocols it calls, directories it reads), and any capabilities it `offer`s to
children. To appear in a system, the component is placed in a product's
`product_bootfs` (or delivered as a package) and routed to by a realm. The
existing components under `src/cerise/` are worked examples.

## Where to go next

- [architecture.md](architecture.md) — the layers and how they fit together.
- [composition-model.md](composition-model.md) — boards, bundles, and products
  in depth.
- [api-surface.md](api-surface.md) — the build rules, providers, and interfaces.
- [use-cases.md](use-cases.md) — what Cerise is good for, with examples.
- [glossary.md](glossary.md) — the vocabulary.
