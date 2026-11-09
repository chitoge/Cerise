# Example use cases

Cerise is a small, composable, capability-secure operating system with a modern
userland and a build system that treats a whole machine image as an ordinary
build target. This document sketches the kinds of systems it is well suited to,
and points at the strengths that make each one natural. Every product named
below is a real target in the tree.

## A network service appliance

The flagship product, `//products:qemu-x64-fileserver`, is a gRPC file server:
it brings up a network interface on **netstack3**, mounts **fxfs** read-write,
and serves `cerise.fileserver.v1.FileServer` (Stat / List / Read / Write /
Mkdir / Rename / Delete) over HTTP/2. The gRPC stack is tonic over hyper over
`fuchsia-async` — with no separate async runtime on the target and no forked
libraries.

This is the shape of a single-purpose network appliance: one application
component, the network stack, and storage, each isolated in its own process and
wired together explicitly. Because the whole thing is a `cerise_product`,
building a variant — a different service, a different disk layout — is editing a
label list, not patching a monolith.

**Strengths on display:** a memory-safe network stack and filesystem as ordinary
components; standard async I/O (`std::net`, `fuchsia-async`) with a real gRPC
stack; and end-to-end proof — two hermetic tests boot the real image and drive
it from a host client, including a reboot that verifies data survives.

## An updatable, packaged system

Not all software has to live in the boot image. Cerise builds real **packages**
(`cerise_package` → a `meta.far` plus content-addressed blobs), installs them
into the fxfs blob volume, and resolves them at runtime. `//products:qemu-x64-pkg`
launches a component from a package; `//products:qemu-x64-pkg-update` fetches a
new version over the network, verifies it, and swaps it in, with the package
index persisted across reboots.

For the operating system itself, `//products:qemu-x64-ota` demonstrates A/B
image updates: two system slots and a small metadata record on the boot
partition, with the boot path selecting the active slot and rolling back to the
other if an update fails to come up. The update and rollback flows are both
validated by booting them under the emulator.

**Strengths on display:** a working software-delivery path — build, sign, fetch,
verify, install, resolve — and self-updating images, all exercised by live boot
tests rather than described on paper.

## A reference and debugging platform

Cerise is built to be *understood*. Every userland binary carries a build-id;
each image can emit a `.build-id` debug-symbol store; and a host tool symbolizes
serial-log backtraces automatically, so a crash or a failed boot reports named,
source-located frames. There is a userspace crash handler, kernel crash-log
recovery across a reboot, a debuginfod server for serving symbols, and a mode
that halts a QEMU boot for a debugger to attach.

**Strengths on display:** debuggability as a build output, not an afterthought —
symbolized failures, post-mortem artifacts, and standard debugger attachment,
all reproducible from the same hermetic build.

## Portable by construction

The composition model separates *what runs* from *what it runs on*. A set of
bundles targets a different machine by pairing them with a different
`cerise_board` — hardware identity is board *data*, so a new target is a new
board and its driver set, not a fork of the system. Cerise also boots on
**aarch64** — `arm64-smoke` and `arm64-hello` are validated boots — so the
architecture split is a real seam, not an aspiration.

**Strengths on display:** hardware identity is board data; a third party can
ship a board, a driver, or a bundle as an ordinary Bazel module without touching
the core; and the same image concepts span x86_64 and aarch64.

## Why these are easy in Cerise

The recurring theme is that a system is a set of explicit, typed, analysis-time
decisions:

- **Composability.** Boards, bundles, and products are label lists resolved in
  Bazel analysis. Missing a required hardware feature, or two components claiming
  the same file, is a build error — caught before anything boots.
- **Capability security.** Components hold only what is routed to them, and that
  routing is verified for completeness and least privilege at build time.
- **A modern, memory-safe userland.** The network stack and filesystem are
  components; much of the new code is Rust; drivers take framework-scoped
  hardware, not raw access.
- **Hermetic, reproducible builds.** Toolchains, emulator, and firmware are all
  pinned and fetched by the build; the same inputs produce the same image
  locally and on remote executors.
- **Evidence over assertion.** Behavior is proven by booting real images under a
  pinned emulator and checking them against ordered markers — tests are boots.

See [getting-started.md](getting-started.md) to try these, and
[architecture.md](architecture.md) for how the pieces fit.
