# Cerise documentation

Cerise is a Bazel-native, composable operating system derived from
[Fuchsia](https://fuchsia.dev). It reuses Fuchsia's microkernel (Zircon), its
userland ABI, and its component and driver frameworks, and composes them into
bootable systems entirely through Bazel analysis — every board, bundle, and
image is an ordinary build target.

If you are new here, start with **Getting started**; it builds and boots a real
image in a few commands. Then read **Architecture** for the shape of the system,
and keep the **Glossary** nearby.

## The documentation set

**[Getting started](getting-started.md)**
   A short tutorial: build an image, boot it under a hermetic QEMU, run the
   tests, and compose a small system of your own.

**[Architecture overview](architecture.md)**
   The layers Cerise is made of — kernel, components, drivers, networking,
   storage — and how a source tree becomes a running machine.

**[The composition model](composition-model.md)**
   How boards, bundles, and products combine into a bootable image, and the
   guarantees the composition rules enforce at analysis time.

**[API surface](api-surface.md)**
   The build rules you compose with, the typed providers they exchange, and the
   FIDL and gRPC interfaces components speak.

**[Example use cases](use-cases.md)**
   The kinds of systems Cerise is good for — a network service appliance,
   updatable and self-updating images, a reference/debugging platform, and
   portability across architectures — and the strengths behind each.

**[Glossary](glossary.md)**
   The vocabulary: board, bundle, product, component, realm, capability, ZBI, and
   the rest.

**[Reference](reference/index.md)**
   Generated Bazel API reference (rules and providers), from the docstrings.

**[Roadmap](roadmap.md)**
   Planned capabilities not yet implemented — test instrumentation and more.

## At a glance

- **One build system.** Bazel is the only build tool; all toolchains are
  hermetic — nothing is discovered from the host.
- **Composable by construction.** Systems are explicit board / bundle / product
  label lists; an unmet requirement is a build error, not a boot failure.
- **Capability-secure.** Every component holds only what is routed to it, and
  routing is verified at build time.
- **Tested by booting.** Live tests start real images under a pinned QEMU with
  UEFI firmware and check them against ordered serial markers.
- **x86_64 and aarch64.** x86_64 is the primary target; aarch64 boots and is
  tracked.

## Relationship to Fuchsia

Cerise is derived from [Fuchsia](https://fuchsia.dev) and builds directly on its
work — the Zircon microkernel, the component and driver frameworks, netstack3,
fxfs, and the FIDL and runtime libraries. Those vendored sources retain their
original copyright and BSD-3-Clause license. Cerise contributes the Bazel-native
composition model and its own components, and is an independent project, not
affiliated with or endorsed by the Fuchsia project. See the `NOTICE` file for
attribution details.

## A first taste

```sh
bazel build //products:x64-smoke            # build a minimal boot image
bazel test  //validation:smoke-uefi-boot    # boot it under a hermetic QEMU
bazel test  //validation:fileserver-grpc-boot   # boot the gRPC file server, end to end
```
