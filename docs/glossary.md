# Glossary

Terms used throughout the Cerise documentation. Many are inherited from Fuchsia;
the definitions here describe how they are used in Cerise.

```{glossary}

board
   A description of a target machine, declared with `cerise_board`. A board
   carries the kernel command line, the boot-driver list, driver placements, and
   the set of hardware *features* it provides. Each board pairs with a Bazel
   `platform()`.

bootfs
   The in-memory filesystem packed into a {term}`ZBI`. It holds the boot-critical
   binaries, component manifests, and configuration that must be present before
   any disk is mounted. On x86_64 the bootfs is zstd-compressed in the image and
   decompressed at boot.

bundle
   A reusable, named set of components declared with
   `cerise_assembly_input_bundle`, together with their placements, the hardware
   *features* they require, and their configuration schemas and defaults. Bundles
   are the unit of reuse across {term}`product`\s.

capability
   A right to use something — a protocol, a directory, a service, a resource. A
   component can access only the capabilities routed to it by its ancestors.
   Capability routing is explicit and is verified at build time.

`.cml`
   A component manifest: the declaration of a component's program, the
   capabilities it uses and offers, and its structured-configuration schema. It
   is compiled to a binary manifest by the `cmc` tool through `cerise_component`.

component
   An isolated program with its own process and its own capabilities, the basic
   unit of a Cerise userland. Networking, storage, drivers, and applications are
   all components.

component_manager
   The program that starts, supervises, and routes capabilities among components
   — the root of the userland tree. It reads component manifests and enforces the
   capability routing declared in them.

DFv2
   Driver Framework version 2: the driver model in which drivers are components,
   matched by bind rules and hosted by `driver_host` processes, taking
   framework-scoped hardware resources rather than raw hardware access.

driver_host / driver_index / driver_manager
   The driver framework's parts: `driver_manager` owns the device tree,
   `driver_index` matches drivers to devices, and each `driver_host` is a process
   that loads and runs driver binaries.

environment
   A compilation target with its own toolchain and ABI — the kernel, the physical
   boot stage (`phys`), the EFI boot application, and userland. Environments are
   Bazel `platform()`s applied by transitions on the artifact rules.

fdio
   The library that gives programs POSIX-style file descriptors backed by
   Fuchsia channels — the bridge between `open`/`read`/`write` and the underlying
   typed protocols (including sockets served by the network stack).

feature
   A string token (for example `cerise::block`) by which composition negotiates
   hardware capability: a board *provides* features, a bundle *requires* them,
   and the product rule checks the intersection at analysis time.

FIDL
   The Fuchsia Interface Definition Language: the typed protocol language
   components use to talk to one another. Cerise-original protocols live under
   `src/cerise/fidl/`.

fshost
   The component that discovers the block device and mounts the {term}`fxfs`
   data volume.

fuchsia-async
   The asynchronous executor and I/O reactor used by Rust components on target.
   Cerise runs async workloads (including its HTTP/2 and gRPC stack) on
   `fuchsia-async` with no separate runtime.

fxfs
   The filesystem Cerise mounts read-write for data. Encryption is a per-volume
   property; content-addressed {term}`package` blobs live in a blob volume inside
   the same filesystem.

marker
   A `CERISE-…` string written to the serial console to report boot or runtime
   progress. Live boot tests assert ordered sequences of markers against the
   running guest.

netstack3
   The network stack, running as a component and serving POSIX sockets through
   `fuchsia.posix.socket`.

package
   A unit of software delivered outside {term}`bootfs`: a `meta.far` archive plus
   content-addressed blobs, built with `cerise_package`, installed into the
   {term}`fxfs` blob volume, and resolved at runtime by a resolver.

product
   A complete, bootable system, declared with `cerise_product`: a board, a list
   of bundles, this product's own components, and a root realm. Building it
   produces a {term}`ZBI`.

provider
   A typed value a Bazel rule exposes for other rules to consume — for example
   `BoardInfo`, `AIBInfo`, or `ProductBundleInfo`. Providers are how the
   composition layers exchange information in analysis.

realm
   A subtree of the component tree, described by a manifest that wires its
   children and routes capabilities among them. A product's *root realm* is its
   top-level wiring and is product identity.

structured configuration
   Typed configuration declared in a component's `.cml`, delivered as a compiled
   `.cvf` value file and read through a generated typed API rather than a
   hand-written literal.

transition
   A Bazel mechanism that rebuilds a dependency under a different configuration.
   Cerise uses transitions to apply the correct {term}`environment` platform to
   each artifact automatically.

vDSO
   The kernel's system-call interface, exposed to userland as a small shared
   library. It is the only way userland calls the kernel.

ZBI
   Zircon Boot Image: the bootable artifact a {term}`product` produces — the
   kernel, the {term}`bootfs`, and boot metadata.

Zircon
   The microkernel at the base of Cerise: a capability-based substrate providing
   processes, memory, and typed message passing, with no drivers or policy of its
   own.
```
