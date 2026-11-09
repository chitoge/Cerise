# Cerise

**Cerise** is a Bazel-native, composable operating system derived from
[Fuchsia](https://fuchsia.dev). It reuses Fuchsia's kernel (Zircon), its
userland ABI, and its component and driver frameworks, but composes and ships
them natively through Bazel analysis — every board, bundle, and system image is
an ordinary Bazel target, resolved and type-checked at analysis time. The
userland OS identity is the constraint `//platforms/os:cerise`.

The documentation starts at **[docs/index.md](docs/index.md)**:

- **[Getting started](docs/getting-started.md)** — build and boot a real image.
- **[Architecture overview](docs/architecture.md)** — the layers and how they fit.
- **[Composition model](docs/composition-model.md)** — boards, bundles, products.
- **[API surface](docs/api-surface.md)** — build rules, providers, interfaces.
- **[Example use cases](docs/use-cases.md)** — what Cerise is good for.
- **[Glossary](docs/glossary.md)** — the vocabulary.

## Scope

- Bazel is the only build system; toolchains are hermetic (no host autodetection).
- x86_64 is the primary target; aarch64 boots and is tracked.
- Every image is a bootable UEFI artifact, validated by live boots under a
  pinned, hermetic QEMU + OVMF.
- Systems are composed as explicit board / bundle / product label lists — no
  layer ordering, no ambient injection.

## Quickstart

```sh
bazel build //products:x64-smoke            # minimal x86_64 boot image
bazel test  //build/checks:all              # analysis-level shape checks
bazel test  //validation:smoke-uefi-boot    # live UEFI boot under hermetic QEMU
bazel test  //tests/unit:unit_tests         # the vendored-upstream unit-test suites
```

## The flagship: a gRPC read-write file server

`//products:qemu-x64-fileserver` runs a gRPC file server as a component on the
modern stack — real netstack3 (a virtio-net DFv2 driver stack) for transport,
fxfs mounted read-write for storage — serving `cerise.fileserver.v1.FileServer`
(Stat / List / Read / Write / Mkdir / Rename / Delete). The gRPC stack is tonic
(transport-free) over hyper HTTP/2 over a `fuchsia-async` executor/IO adapter
(`//src/cerise/lib/hyper_rt`): no tokio runtime on target, no forked tonic.

Two hermetic tests prove it end to end by booting the real OS under pinned
QEMU/OVMF and driving it from a host gRPC client over emulated networking:

```sh
bazel test //validation:fileserver-grpc-boot    # write → read-back → list → stat → rename → delete
bazel test //validation:fileserver-persistence  # write, reboot, data survives across the remount
```

## Composition in one breath

```python
cerise_product(
    name = "qemu-x64-fileserver",
    board = "//boards/qemu-x64",                      # hardware identity
    bundles = [                                       # reusable capability sets
        "//bundles:component_framework",
        "//bundles:driver_framework",
        "//bundles:netstack3",
        "//bundles:storage_fxfs",
    ],
    root_realm = "//src/cerise/realms:root_dfv2acpi_fileserver_manifest",
    product_bootfs = { ... },                         # this product's own components
)
```

The product rule resolves the board's provided hardware features against each
bundle's required features at analysis time (an unmet requirement is a build
error), merges the bootfs, generates structured-config value files, and drives
the image assembly. See [docs/composition-model.md](docs/composition-model.md).

## Relationship to Fuchsia

Cerise is **derived from [Fuchsia](https://fuchsia.dev)** and would not exist
without it. It vendors and builds on Fuchsia's work directly: the **Zircon**
microkernel, the userland ABI and the C/Rust runtimes, the Component and Driver
frameworks (`component_manager`, `cmc`, the driver framework), the **netstack3**
network stack, the **fxfs** filesystem, and the FIDL toolchain. The vendored
Fuchsia sources live under `src/upstream/fuchsia/` and `zircon/` and retain their
original copyright and BSD-3-Clause license (`src/upstream/fuchsia/LICENSE`).

Cerise's own contribution is the Bazel-native composition and assembly model and
the Cerise-original components under `src/cerise/`. Cerise is an independent
project; it is not affiliated with, sponsored by, or endorsed by the Fuchsia
project or its authors.

## Licensing

Cerise-original code is under the BSD 3-Clause License (`LICENSE`), matching the
lineage. Vendored Fuchsia and other third-party code is under its original
license — see `NOTICE` for the summary and each `LICENSE` file in the vendored
trees for the authoritative terms.
