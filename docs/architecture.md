# Architecture overview

Cerise is a componentized operating system built from Fuchsia's building blocks
and assembled entirely through Bazel. This document explains the shape of the
system — the layers it is made of, how they fit together, and how a source tree
becomes a running machine. It is a conceptual overview; for the rules and
providers you write against, see [api-surface.md](api-surface.md), and for the
composition mechanism in detail, [composition-model.md](composition-model.md).

## The big picture

A Cerise system is a small trusted core that starts a tree of **components** —
isolated programs that hold only the capabilities explicitly routed to them —
and a set of **drivers** that bring hardware to life. There is no monolithic
userspace: networking, storage, logging, and applications are all components,
each in its own process, talking over typed channels.

```
   kernel (Zircon)
     └── component_manager ── starts and supervises the component tree
           ├── driver framework ── driver_manager, driver_index, driver_host(s)
           │     └── drivers ── PCI, block (NVMe/AHCI), network, display, ...
           ├── netstack3 ── the network stack, as a component
           ├── storage ── fshost + fxfs, mounting the data volume
           └── application components ── e.g. the gRPC file server
```

Everything above the kernel is ordinary software composed at build time. What
distinguishes one Cerise image from another is *which* components and drivers
are present and how their capabilities are routed — and that is entirely a
matter of Bazel targets.

## Layers

### The kernel

Cerise runs the **Zircon** microkernel. Zircon provides the primitives
everything else is built on: processes, threads, virtual memory, and typed
message-passing over *channels* and *sockets*, exposed through a small system
ABI (the vDSO). Zircon has no drivers and no policy of its own; it is a
capability-based substrate.

### Environments and toolchains

Code in Cerise is compiled for one of a few **environments**, each realized as a
Bazel `platform()` and served by a hermetic toolchain: the kernel, the physical
boot (`phys`), the EFI boot application, and userland (the component ABI). The
environment boundaries are applied as Bazel *transitions* — you never pass an
arch or environment token in a target name; the artifact rules stamp the right
platform automatically.

Toolchains are **hermetic**: the C/C++ toolchain is a pinned LLVM, and Rust is
built with a pinned toolchain through `rules_rust`. Nothing is discovered from
the host. The same inputs produce the same outputs locally and on remote
executors.

### The component framework

Userland is organized by **component_manager**, Fuchsia's Component Framework
(CFv2). A component is declared by a **`.cml`** manifest — its program, the
capabilities it *uses*, the capabilities it *offers* to its children, and
optional **structured configuration**. Manifests are compiled by the vendored
`cmc` tool through the `cerise_component` rule; structured-config values are
compiled to `.cvf` files and delivered to the component at start.

Components are arranged in a tree of **realms**. A realm's manifest is the
wiring diagram for that part of the system: which children are eager, what
capabilities flow between them, and where they come from. Capability routing is
explicit — a component can reach exactly what its ancestors route to it, and
Cerise verifies that routing at build time (see *Testing*, below).

### The driver framework

Hardware is managed by Fuchsia's Driver Framework: **driver_manager** owns the
device tree, **driver_index** matches drivers to devices, and **driver_host**
processes load driver binaries. Drivers are components too — they are matched by
bind rules, take only framework-scoped hardware resources (a PCI driver receives
its device's BARs, not raw port access), and publish services other components
consume. Cerise ships drivers for the PCI bus, NVMe and AHCI block devices, a
virtio and an Intel-family network device, and a framebuffer display.

### Networking and storage

The network stack is **netstack3**, a memory-safe stack that runs as a
component and serves POSIX sockets through `fuchsia.posix.socket`. Applications
reach it through `fdio` and the `fuchsia-async` executor — the same
`std::net` / async I/O they would use anywhere.

Storage is **fxfs**, a modern filesystem mounted read-write on a block device.
`fshost` discovers the disk and mounts the data volume; encryption is a
per-volume property of fxfs. Content-addressed blobs — the basis of packages —
live in a blob volume inside the same filesystem.

## The boot pipeline

A Cerise image is a **ZBI** (Zircon Boot Image): the kernel, a compressed
`bootfs` (an in-memory filesystem of the boot-critical binaries and manifests),
and boot metadata. On x86_64, a UEFI boot shim loads the ZBI; the physical boot
stage decompresses and hands off to the kernel; the kernel starts
`component_manager`; `component_manager` starts the driver framework and the
rest of the component tree from the manifests in `bootfs`. Larger software can
also be delivered as **packages** resolved from the fxfs blob volume rather than
carried in `bootfs`.

## How a source tree becomes a machine

Composition is Bazel analysis. Three layers, each a rule producing a typed
provider, combine into a bootable image:

- a **board** (`cerise_board`) names the hardware and the features it provides;
- **bundles** (`cerise_assembly_input_bundle`) are reusable sets of components
  with the features they require;
- a **product** (`cerise_product`) picks a board, a list of bundles, its own
  components, and a root realm, and assembles the ZBI.

The product rule resolves required features against provided ones, merges the
boot filesystem, delivers structured configuration, and produces `<name>.zbi` —
all at analysis time, so an unmet requirement or a colliding file is a build
error, not a boot failure. See [composition-model.md](composition-model.md).

## Testing

Cerise validates itself by **booting**. Under `//validation`, live boot tests
start a real image in a pinned, hermetic QEMU with UEFI firmware and assert
ordered progress markers on the serial console against the running guest — a
passing test is a genuine boot, not a recorded fixture. The flagship end-to-end
test boots the file-server image and drives it from a host gRPC client over
emulated networking. In addition, the vendored upstream unit-test suites run as
ordinary Bazel tests, and every product's capability routing is checked for
completeness and least privilege at build time.

When a boot fails, captured backtraces are symbolized automatically against the
image's debug-symbol store, so failures report named, source-located frames
rather than raw addresses.
