#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BAZEL_BIN="${BAZEL_BIN:-bazel}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-180}"
SERIAL_LOG="${SERIAL_LOG:-$(mktemp -t zircon-legacy-serial.XXXXXX.log)}"
HOSTFWD_PORT="${HOSTFWD_PORT:-8080}"
# storage sub-gate: scratch backing image for QEMU's NVMe controller (all products
# get the device on the QEMU command line, same as e1000's NIC below — harmless for
# products without the nvme driver bound). 64M is plenty for a bind+read/write proof.
NVME_IMG="${NVME_IMG:-$(mktemp -t cerise-nvme.XXXXXX.img)}"
qemu-img create -f raw "$NVME_IMG" 64M >/dev/null
# storage sub-gate (AHCI): scratch backing image for QEMU's AHCI controller, same
# harmless-for-other-products pattern as NVME_IMG above.
AHCI_IMG="${AHCI_IMG:-$(mktemp -t cerise-ahci.XXXXXX.img)}"
qemu-img create -f raw "$AHCI_IMG" 64M >/dev/null
# fshost gate: a THIRD disk, on the same onboard AHCI controller (ide.1, distinct
# port from AHCI_IMG's ide.0). nvme_probe/ahci_probe/fxfs_probe are all Eager and each
# grab whichever aggregate-Service instance they land on first (there's no supported
# way to target a specific one). With only 2 disks, nvme_probe+ahci_probe could
# consume both before fxfs_probe/fshost ever get a device to format+mount — this 3rd
# disk gives every real Eager consumer a distinct device to settle on.
FSHOST_IMG="${FSHOST_IMG:-$(mktemp -t cerise-fshost.XXXXXX.img)}"
qemu-img create -f raw "$FSHOST_IMG" 64M >/dev/null

# QEMU attach/debug mode for the direct-kernel path (the one
# the real gates run on). Enable with --gdb or CERISE_GDB=1. Strip the debug
# flags out of the positional args so PRODUCT parsing below is unaffected.
#   --gdb / CERISE_GDB=1        add `-gdb tcp::<port>` (default 1234) + hold for attach
#   --gdb-halt / CERISE_GDB_HALT=1  also add `-S` (freeze CPU at reset until gdb `continue`)
#   --tcg  / CERISE_GDB_TCG=1   force `-accel tcg` (KVM's gdbstub can't do software
#                               watchpoints / reverse-exec; TCG can). KVM caveat, mirrors
#                               rules_ostest's tcg fallback.
CERISE_GDB="${CERISE_GDB:-0}"
CERISE_GDB_HALT="${CERISE_GDB_HALT:-0}"
CERISE_GDB_TCG="${CERISE_GDB_TCG:-0}"
CERISE_GDB_PORT="${CERISE_GDB_PORT:-1234}"
_args=()
for _a in "$@"; do
  case "$_a" in
    --gdb) CERISE_GDB=1 ;;
    --gdb-halt) CERISE_GDB=1; CERISE_GDB_HALT=1 ;;
    --tcg) CERISE_GDB_TCG=1 ;;
    *) _args+=("$_a") ;;
  esac
done
set -- ${_args+"${_args[@]}"}
PRODUCT="${1:-${PRODUCT:-x64-smoke}}"
# Products with many packages need more RAM; bootfs decompression OOMs at 512M.
QEMU_MEM="${QEMU_MEM:-1024M}"
case "$PRODUCT" in
  x64-dfv2-loader-comp|x64-dfv2-rt|x64-dh-xproc|x64-dfv2-real|x64-dfv2-match|x64-compat|x64-platform-bus|x64-acpi) QEMU_MEM="2048M" ;;
  # x64-pci (network-device onward): bootfs now carries network-device.so alongside virtio_netdevice.so
  # (each ~63-65MB stripped, from statically-linked FIDL codegen) -> the decompressed
  # BOOTDATA VMO is ~1GB. 2048M left too little headroom for kernel+phys+driver working
  # set before component_manager even started -> early OOM reboot at t~71s. Bump to 4096M.
  # x64-fshost/x64-netstack3: same driver stack + bootfs staging as x64-pci
  # (byte-identical extra_bootfs, only root.cm [+ an added package for netstack3]
  # differs) — same memory needs.
  qemu-x64-pci|qemu-x64-storage|qemu-x64-net|qemu-x64-net-e1000e) QEMU_MEM="4096M" ;;
esac

# x64-pci runs the full ACPI + PCI-enum + composite-assembly chain and then brings up a
# SECOND driver_host (a fresh fdf runtime) for the colocation-free PCI function driver,
# which isn't reached until ~163s. Give it a longer window unless the caller set a bigger one.
if [[ "$PRODUCT" == "qemu-x64-pci" && "$TIMEOUT_SECONDS" -lt 420 ]]; then
  TIMEOUT_SECONDS=420
fi
# x64-fshost inherits the identical driver stack/timing as x64-pci (see
# products/BUILD.bazel), but fshost_probe polls detect_disk_format() every 5s up to
# 70 times (350s) before ever touching "/fshost-fs" — a deliberately generous,
# clock-skew-tolerant wait for a real observable fact (real Fxfs content on disk),
# not a guessed deadline (see fshost_probe/src/main.rs's header comment for why a
# fixed delay was tried and rejected). That poll budget alone can approach 420s once
# added to the driver-stack enumeration time before fxfs_probe even starts
# formatting. THEN, once content is observed, fshost_probe's own write/read retry
# loop (independent of the above — observing content only proves fxfs_probe's
# formatter finished, not that fshost's own separate content-sniff -> dynamic
# Crypt-instance spawn -> Volumes.Create -> mount sequence has caught up) budgets a
# further 90*5s=450s. Measured on a real boot: fshost doesn't spawn its Crypt
# instance until t~304s. So x64-fshost needs real headroom above x64-pci's 420s.
if [[ "$PRODUCT" == "qemu-x64-storage" && "$TIMEOUT_SECONDS" -lt 900 ]]; then
  TIMEOUT_SECONDS=900
fi
# x64-netstack3: now also runs netstack3_probe's discovery+install+HTTP-echo client,
# which retries its whole sequence up to 90*5s=450s past the driver stack's own
# enumeration time (~180-200s, same as x64-pci) — give it the same real headroom
# x64-fshost needed for its own retry-heavy probe.
if [[ "$PRODUCT" == "qemu-x64-net" && "$TIMEOUT_SECONDS" -lt 900 ]]; then
  TIMEOUT_SECONDS=900
fi
# qemu-x64-net-e1000e: same DHCP-over-a-real-NIC probe, but the lease rides the
# e1000e (82574L) descriptor rings instead of virtio-net — same retry headroom.
if [[ "$PRODUCT" == "qemu-x64-net-e1000e" && "$TIMEOUT_SECONDS" -lt 900 ]]; then
  TIMEOUT_SECONDS=900
fi

if [[ "$PRODUCT" == "x64-fdf-spike" ]]; then
  # runtime Component 1: the FDF runtime bring-up spike. Proves the real libfdf
  # runtime starts a dispatcher + runs a posted task on it in a Cerise process.
  required_markers=(
    "CERISE-FDF-ENV-STARTED"
    "CERISE-FDF-DISPATCHER-CREATED"
    "CERISE-FDF-RUNTIME-OK"
    "CERISE-FDF-SPIKE-DONE"
  )
elif [[ "$PRODUCT" == "x64-dfv2-rt" ]]; then
  # runtime Component 5: the REAL in-process DFv2 driver round-trip inside the
  # Rust driver_manager (driver_manager_rust_dfv2). driver_manager brings up the fdf
  # runtime in-process, dlopens the staged minimal driver .so, initializes it over the
  # fdf Driver transport, and drives Driver.Start -> MinimalDriver::Start() runs.
  #   CERISE-DRIVER-MANAGER-START          : driver_manager_rust_dfv2 main() reached.
  #   CERISE-DRIVER-INDEX-CONNECTED: framework + DriverIndex capabilities connected.
  #   CERISE-DFv2-DISPATCHING      : about to take the real fdf start path.
  #   CERISE-DFV2-DLOPEN-OK        : driver .so dlopen'd from /pkg/lib.
  #   CERISE-DFV2-REGISTRATION-FOUND: __fuchsia_driver_registration__ resolved.
  #   CERISE-DFV2-DRIVER-OK        : MinimalDriver::Start() ran (the milestone).
  required_markers=(
    "CERISE-DRIVER-MANAGER-START"
    "CERISE-DRIVER-INDEX-CONNECTED"
    "CERISE-DFv2-DISPATCHING"
    "CERISE-DFV2-DLOPEN-OK"
    "CERISE-DFV2-REGISTRATION-FOUND"
    "CERISE-DFV2-DRIVER-OK"
  )
elif [[ "$PRODUCT" == "x64-dfv2-real" ]]; then
  # driver-host Step 1: the REAL driver_manager (start_root_driver, NOT the dfv2_fdf shim)
  # launches a SEPARATE driver_host (driver_host_dfv2) and Starts the root driver
  # (minimal_driver) in it over the zircon fuchsia.driver.host/DriverHost transport.
  #   CERISE-DRIVER-MANAGER-START            : driver_manager_rust_dfv2real main() reached.
  #   CERISE-DRIVER-INDEX-CONNECTED  : framework + DriverIndex capabilities connected.
  #   CERISE-DFv2-DISPATCHING        : driver_manager about to call start_root_driver.
  #   CERISE-DH-XPROC-START-RECEIVED : driver_host_dfv2 received DriverHost.Start.
  #   CERISE-DH-XPROC-FDF-OK         : driver_host drove fdf Driver.Start (separate proc).
  #   CERISE-DFV2-DRIVER-OK          : MinimalDriver::Start() ran in the driver_host.
  required_markers=(
    "CERISE-DRIVER-MANAGER-START"
    "CERISE-DRIVER-INDEX-CONNECTED"
    "CERISE-DFv2-DISPATCHING"
    "CERISE-DH-XPROC-START-RECEIVED"
    "CERISE-DH-XPROC-FDF-OK"
    "CERISE-DFV2-DRIVER-OK"
  )
elif [[ "$PRODUCT" == "x64-dfv2-match" ]]; then
  # driver-host Step 2: the parent->child driver-index MATCH/START loop. The REAL DriverRunner
  # starts the PARENT driver by URL; in Start() the parent calls fdf Node.AddChild with a
  # bind property; the dm Node server asks driver-index to MATCH a driver for the child;
  # driver-index matches the CHILD driver by its .bindbc; the dm starts the child driver
  # in a second driver_host -> the child's Start() runs.
  #   CERISE-DFv2-DISPATCHING : driver_manager about to start_root_driver(parent_driver).
  #   CERISE-DFV2-PARENT-OK   : parent Start() ran + AddChild succeeded.
  #   CERISE-DI-MATCH-OK      : child Start() ran AFTER a real driver-index match.
  #   CERISE-DFV2-CHILD-OK    : child Start() ran (the post-match driver).
  required_markers=(
    "CERISE-DFv2-DISPATCHING"
    "CERISE-DFV2-PARENT-OK"
    "CERISE-DI-MATCH-OK"
    "CERISE-DFV2-CHILD-OK"
  )
elif [[ "$PRODUCT" == "x64-compat" ]]; then
  # driver-host Step 3: de-risk the compat MODULE / loader-override / symbols mechanism. The REAL
  # DriverRunner starts the DFv2 compat shim (compat_driver) by URL; driver_host_dfv2
  # dlopens compat.so (program.binary) RTLD_GLOBAL + initializes it, then loads the
  # MINIMAL LEGACY DFv1 .so (program.compat) as a sibling MODULE (its UND DFv1 ABI
  # symbols resolve against compat.so; the loader_override is reproduced by RTLD_GLOBAL
  # scope) and populates the legacy module's __zircon_driver_note__/__zircon_driver_rec__
  # into DriverStartArgs.symbols. compat reads them and runs the legacy bind hook.
  #   CERISE-COMPAT-MODULE-OK : the loader dlopen'd the legacy .so + found note/rec.
  #   CERISE-COMPAT-LEGACY-OK : the legacy bind hook ran THROUGH compat (authoritative).
  #   CERISE-COMPAT-OK        : compat's Driver.Start round-trip replied (corroborating).
  required_markers=(
    "CERISE-COMPAT-MODULE-OK"
    "CERISE-COMPAT-LEGACY-OK"
    "CERISE-COMPAT-OK"
  )
elif [[ "$PRODUCT" == "x64-dh-xproc" ]]; then
  # driver-host Step 0: FAITHFUL separate-process DFv2 driver host, driven by a minimal harness
  # (not the real engine). The harness calls DriverHost.Start on its driver_host child;
  # the driver_host (separate process) brings up fdf locally, dlopens the driver, and
  # drives the local fdf Driver.Start.
  #   CERISE-DH-XPROC-FDF-OK       : driver_host drove fdf Driver.Start (separate proc).
  #   CERISE-DFV2-DRIVER-OK        : MinimalDriver::Start() ran in the driver_host.
  #   CERISE-DH-XPROC-HARNESS-OK   : harness's DriverHost.Start returned ok.
  #   CERISE-DH-XPROC-HARNESS-SERVICE-OK : driver service remains reachable after Start.
  #   CERISE-DFV2-DRIVER-STOP      : framework Driver.Stop reached the loaded driver.
  #   CERISE-DH-XPROC-HARNESS-STOP-OK : host completed teardown with a ZX_OK epitaph.
  required_markers=(
    "CERISE-DH-XPROC-FDF-OK"
    "CERISE-DFV2-DRIVER-OK"
    "CERISE-DH-XPROC-HARNESS-OK"
    "CERISE-DH-XPROC-HARNESS-SERVICE-OK"
    "CERISE-DFV2-DRIVER-STOP"
    "CERISE-DH-XPROC-HARNESS-STOP-OK"
  )
elif [[ "$PRODUCT" == "x64-dfv2-loader-comp" ]]; then
  # runtime Component 2: the DFv2 driver loader core, run as a COMPONENT under
  # component_manager (framework loader svc + LDSVC_KEEP=1 musl retention enable the
  # runtime dlopen). Proves dlopen of a real DFv2 driver .so + driving it over the
  # real fdf Driver transport (initialize + Start) so the driver's Start() runs.
  required_markers=(
    "CERISE-DFV2-DLOPEN-OK"
    "CERISE-DFV2-REGISTRATION-FOUND"
    "CERISE-DFV2-DRIVER-OK"
    "CERISE-DFV2-LOADER-DONE"
  )
elif [[ "$PRODUCT" == "x64-platform-bus" ]]; then
  # driver-host Step 4: the GENERIC platform-bus DFv2 root driver starts under component_manager.
  # driver_manager starts platform-bus by URL (no bind match needed for the root); platform-bus
  # binds to the boot ZBI items (ACPI RSDP etc.) via fuchsia.boot.Items and publishes the
  # "pt" child node with INTEL/X86 platform IDs.
  #   CERISE-PLATFORM-BUS-OK : platform-bus Start() completed (authoritative gate).
  required_markers=(
    "CERISE-PLATFORM-BUS-OK"
  )
elif [[ "$PRODUCT" == "x64-acpi" ]]; then
  # driver-host Step 5: platform-bus-x86 LEGACY board driver loaded via compat as a child of
  # the generic platform-bus root driver. ACPICA initializes from firmware tables (QEMU
  # ACPI tables supplied by SeaBIOS/OVMF); AcpiEnableSubsystem succeeds; pci_init
  # publishes the PCI root bridge.
  #   CERISE-PLATFORM-BUS-OK    : platform-bus root driver started (prerequisite).
  #   CERISE-ACPI-INIT-OK       : AcpiEnableSubsystem succeeded (ACPICA live).
  #   CERISE-PCIROOT-PUBLISHED  : AcpiPciroot DdkAdd'd (ZX_PROTOCOL_PCIROOT).
  required_markers=(
    "CERISE-PLATFORM-BUS-OK"
    "CERISE-ACPI-INIT-OK"
    "CERISE-PCIROOT-PUBLISHED"
  )
elif [[ "$PRODUCT" == "qemu-x64-pci" ]]; then
  # step 1c: virtio-net DFv2-native driver binds via composite spec.
  # NIC: -device virtio-net-pci,disable-legacy=on (DID=0x1041 modern; VID=0x1af4).
  # bus-pci publishes a composite node spec for virtio-net (pci parent + acpi parent);
  # driver-index matches virtio_net.cm; driver_host_dfv2 spawns a 2nd host for the
  # non-colocated driver; NetworkDevice::Init() fires CERISE-VIRTIO-NET-BOUND.
  # Inherits the proven x64-pci topology (platform-bus-x86 → bus-pci → virtio-net).
  #   CERISE-PLATFORM-BUS-OK    : platform-bus root driver started (prerequisite).
  #   CERISE-ACPI-INIT-OK       : AcpiEnableSubsystem succeeded (ACPICA live).
  #   CERISE-PCIROOT-PUBLISHED  : AcpiPciroot DdkAdd'd (ZX_PROTOCOL_PCIROOT).
  #   CERISE-PCI-ENUM           : bus-pci bound + first valid PCI device enumerated.
  #   CERISE-PCI-NODES-PUBLISHED: all leaf PCI nodes published (DdkAdd+CompositeSpec done).
  #   CERISE-VIRTIO-NET-BOUND   : virtio-net DFv2 driver bound + NetworkDevice::Init done.
  #   CERISE-NETDEVICE-BOUND    : network-device plain-bind, colocated with
  #                                 virtio-net, publishes its devfs child node.
  #   CERISE-DEVFS-CLIENT-OK    : netdev_probe enumerated /dev/class/network
  #                                 (instance name is a random u32, not "000" — only
  #                                 classes in CLASSES_THAT_ASSUME_ORDERING get
  #                                 sequential names), opened its device_controller
  #                                 child to get a Controller, ConnectToDeviceFidl'd to
  #                                 the real Device protocol, and Device.GetInfo()
  #                                 succeeded — proves the devfs CLIENT path
  #                                 end-to-end.
  #   CERISE-NETDEV-FRAME-OK   : netdev_probe opened a real
  #                                 network-device Session (OpenSession + FIFO/VMO
  #                                 dataplane), submitted one crafted Ethernet frame
  #                                 on the tx FIFO, and observed a real tx completion
  #                                 with no TX_RET_ERROR — proves a frame actually
  #                                 moves through network-device -> virtio-net -> the
  #                                 virtio ring -> QEMU's backend, not just control
  #                                 plane. This is generic session/FIFO/VMO
  #                                 infrastructure the e1000 driver below reuses too.
  #   CERISE-E1000-BOUND        : e1000 (step 1d) composite-binds to the SECOND PCI
  #                                 NIC (-device e1000,netdev=net1), maps BAR0, and
  #                                 completes the proven register init sequence.
  #   CERISE-NVME-BOUND         : nvme (storage sub-gate, real upstream driver)
  #                                 composite-binds to the NVMe controller (-device
  #                                 nvme,drive=nvm0), sets up admin+IO queues, and
  #                                 identifies at least one namespace.
  #   CERISE-AHCI-BOUND         : ahci (storage sub-gate, real upstream driver)
  #                                 composite-binds to Q35's onboard ich9-ahci
  #                                 controller (ide-hd drive attached to its ide.0 bus),
  #                                 maps BAR5, configures MSI (real end-to-end — see
  #                                 machine-type comment below), and completes port init.
  #                                 Same composite-bind shape as nvme (independent PCI
  #                                 class/subclass spec).
  #   CERISE-AHCI-BLOCK-OK      : ahci_probe connects to AHCI's dynamically-published
  #                                 fuchsia.hardware.block.volume.Service instance
  #                                 ("sata0" — same aggregate Collection("boot-drivers")
  #                                 expose mechanism as nvme_probe, distinguished by
  #                                 instance name prefix since both drivers share ONE
  #                                 aggregated Service capability), writes a known byte
  #                                 pattern, reads it back, and verifies an exact match.
  #   CERISE-NVME-BLOCK-OK      : nvme_probe connects to NVMe's dynamically-published
  #                                 fuchsia.hardware.block.volume.Service instance via
  #                                 an aggregate Expose::Service from driver_manager_rust's
  #                                 "boot-drivers" collection (NOT devfs — NVMe never
  #                                 calls AddOwnedChild), opens a RemoteBlockClient
  #                                 session, writes a known byte pattern to LBA 0,
  #                                 reads it back, and verifies an exact match — real
  #                                 block I/O through the actual FIFO/VMO dataplane.
  #   CERISE-FXFS-FORMAT-OK     : fxfs_probe formats a real Fxfs
  #                                 volume on whichever real block device it gets from
  #                                 the same aggregate Service pool nvme_probe/ahci_probe
  #                                 use, via the real vendored fxfs::filesystem core
  #                                 library (FxFilesystem::new_empty) — real journal,
  #                                 real LSM tree, real object store, real block I/O.
  #   CERISE-FXFS-CRYPT-OK      : provisions a wrapping key via the real crypt_fxfs
  #                                 component (fuchsia.fxfs/CryptManagement.
  #                                 AddWrappingKey+SetActiveKey), then creates a real
  #                                 named child volume backed by an actual Arc<dyn Crypt>
  #                                 (fuchsia.fxfs/Crypt.CreateKey) — a genuinely
  #                                 encrypted object store, not StoreOptions{crypt:None}.
  #   CERISE-FXFS-WRITE-OK      : writes a known-content file into the encrypted
  #                                 volume's root directory via the real Directory/
  #                                 DataObjectHandle API and syncs.
  #   CERISE-FXFS-REMOUNT-OK    : closes the filesystem and re-opens it (fresh
  #                                 RemoteBlockClient session + FxFilesystem::open, not
  #                                 new_empty) — the real proof of on-disk persistence.
  #   CERISE-FXFS-READ-OK       : with a FRESH Crypt session, unlocks the SAME named
  #                                 encrypted volume (fuchsia.fxfs/Crypt.UnwrapKey) and
  #                                 reads the file back, verifying the bytes match
  #                                 exactly — real persistence AND real re-unwrapping of
  #                                 on-disk wrapped keys after a full remount.
  #   CERISE-FSHOST-MOUNT-OK    : fshost_probe successfully writes a file through
  #                                 fshost's exposed "fshost-fs"/"data" directory,
  #                                 proving fshost AUTOMATICALLY discovered a device and
  #                                 auto-mounted/auto-formatted Fxfs on it (fshost's own
  #                                 content-sniffing + auto-provision, not driven by hand
  #                                 the way fxfs_probe drives FxFilesystem directly).
  #   CERISE-FSHOST-READ-OK     : reads that file back and verifies the bytes match —
  #                                 the filesystem gate: "a component reads a real file from its
  #                                 namespace" where fshost, not a probe, did the mount.
  #
  # CERISE-FSHOST-MOUNT-OK/READ-OK are DELIBERATELY NOT in required_markers yet: a
  # real boot confirms fshost_probe is wired correctly and fshost's own matcher DOES
  # react ("Matching device"/"Matched device" fire for all 3 disks — no error, no
  # "Failed to match device"), but the device fshost matches first is racing
  # fxfs_probe/nvme_probe/ahci_probe for the exact same aggregate-Service instances:
  # fshost's DirSource watcher is event-driven (reacts the instant a device appears)
  # while the probes use list-then-try — there is no client-side way to give any of
  # them a "private" instance, so the first-published device is content-sniffed by
  # fshost before any probe has written real content to it, and by the time a probe
  # DOES write real Fxfs content, fshost has already made its one-shot decision on that
  # device and isn't watching it again. Confirmed via exact log ordering: fshost's
  # "Matched device" for /block/000 fires BEFORE fxfs_probe's own
  # CERISE-FXFS-PROBE-TRACE-FORMAT-START. Adding more disks does not fix this — it
  # doesn't create separate "lanes", every consumer still sees the same shared pool.
  # A real fix needs either a way to make fshost's own auto-format win the race
  # deterministically, or a way to keep the probes from ever touching the specific
  # device fshost is auto-provisioning. Left as future work.
  required_markers=(
    "CERISE-PLATFORM-BUS-OK"
    "CERISE-ACPI-INIT-OK"
    "CERISE-PCIROOT-PUBLISHED"
    "CERISE-PCI-ENUM"
    "CERISE-PCI-NODES-PUBLISHED"
    "CERISE-VIRTIO-NET-BOUND"
    "CERISE-NETDEVICE-BOUND"
    "CERISE-DEVFS-CLIENT-OK"
    "CERISE-NETDEV-FRAME-OK"
    "CERISE-E1000-BOUND"
    "CERISE-NVME-BOUND"
    "CERISE-NVME-BLOCK-OK"
    "CERISE-AHCI-BOUND"
    "CERISE-AHCI-BLOCK-OK"
    "CERISE-FXFS-FORMAT-OK"
    "CERISE-FXFS-CRYPT-OK"
    "CERISE-FXFS-WRITE-OK"
    "CERISE-FXFS-REMOUNT-OK"
    "CERISE-FXFS-READ-OK"
    # CERISE-FSHOST-MOUNT-OK / CERISE-FSHOST-READ-OK intentionally NOT required
    # here — see the comment block above required_markers for the diagnosed
    # fshost-vs-probes device-contention race. x64-fshost (below) is the isolated
    # product where those two ARE required, since it has no competing probes.
  )
elif [[ "$PRODUCT" == "qemu-x64-storage" ]]; then
  # gate, isolated: byte-identical driver stack to x64-pci (same extra_bootfs,
  # same required markers up through PCI/ACPI/NVMe/AHCI bind — proving nothing
  # regressed by switching root manifests), but root_dfv2acpi_fshost.cm omits
  # nvme_probe/ahci_probe/fxfs_probe as Eager children. Those three enumerate-and-
  # claim whichever aggregate-Service instance appears first, racing fshost's own
  # event-driven, sniff-once-per-device watcher (confirmed via real boot log
  # ordering in x64-pci: fshost judged a device raw *before* fxfs_probe even began
  # formatting it, and never re-checks a device once judged). With no
  # competing probes here, fshost's real content-sniffing auto-format/auto-mount
  # policy gets an uncontested device, and the two "not yet required" markers from
  # the x64-pci block above are required here instead:
  #   CERISE-FSHOST-MOUNT-OK : fshost_probe writes a real file through fshost's
  #                              own exposed "fshost-fs"/"data" directory, proving
  #                              fshost AUTOMATICALLY discovered a device and
  #                              auto-mounted/auto-formatted Fxfs on it.
  #   CERISE-FSHOST-READ-OK  : reads that file back, bytes match exactly — the filesystem
  #                              gate: "a component reads a real file from its
  #                              namespace" where fshost, not a probe, did the mount.
  # netdev_probe is still present in this realm (cloned from root_dfv2acpi_cm before
  # the nvme_probe/ahci_probe/fxfs_probe additions, but after netdev_probe's) — its
  # markers still apply. All drivers bind via driver-index/composite-matching
  # regardless of which Eager client components exist, so NVME/AHCI-BOUND still
  # fire even without their probe clients present.
  required_markers=(
    "CERISE-PLATFORM-BUS-OK"
    "CERISE-ACPI-INIT-OK"
    "CERISE-PCIROOT-PUBLISHED"
    "CERISE-PCI-ENUM"
    "CERISE-PCI-NODES-PUBLISHED"
    "CERISE-VIRTIO-NET-BOUND"
    "CERISE-NETDEVICE-BOUND"
    "CERISE-DEVFS-CLIENT-OK"
    "CERISE-NETDEV-FRAME-OK"
    "CERISE-E1000-BOUND"
    "CERISE-NVME-BOUND"
    "CERISE-AHCI-BOUND"
    "CERISE-FSHOST-MOUNT-OK"
    "CERISE-FSHOST-READ-OK"
  )
elif [[ "$PRODUCT" == "qemu-x64-net" ]]; then
  # gate #1: netstack3.cm (the real Fuchsia network stack binary) starts cleanly
  # under component_manager and exposes its protocols. Isolated from x64-pci (same
  # isolation rationale as x64-fshost) since this is a new, still-being-verified
  # Eager component. netstack3 does zero device discovery itself — it only serves
  # fuchsia.net.interfaces.admin/Installer.InstallDevice(client_end, ...).
  # Marker is netstack3's own REAL, unmodified startup log line (main.rs:70,
  # `info!("starting netstack3 with {config:?}")`) — not a Cerise-added string,
  # so no patch to vendored source was needed for this gate.
  #
  # gate #2: netstack3_probe discovers the real network device via devfs, hands
  # it to netstack3's Installer, configures a static-IP interface, and serves a real
  # HTTP echo over a real fuchsia.posix.socket TCP listener — main()'s http_probe()
  # verifies it externally through QEMU's SLIRP hostfwd, same as x64-net's check.
  required_markers=(
    "CERISE-PLATFORM-BUS-OK"
    "CERISE-ACPI-INIT-OK"
    "CERISE-PCIROOT-PUBLISHED"
    "CERISE-PCI-ENUM"
    "CERISE-PCI-NODES-PUBLISHED"
    "CERISE-VIRTIO-NET-BOUND"
    "CERISE-NETDEVICE-BOUND"
    "starting netstack3 with"
    # DHCP gate: the interface address is acquired by REAL DHCPv4 DORA over a
    # fuchsia.posix.socket.packet socket against slirp's built-in bootp server
    # (offers 10.0.2.15/24), and SLAAC brings up the v6 link-local — both proven
    # BEFORE the socket/HTTP markers, so the subsequent hostfwd HTTP probe proves
    # reachability on a DHCP-leased address, not a hardcoded one.
    "CERISE-DHCP-LEASE=10.0.2.15/24"
    "CERISE-SLAAC-ADDR-OK"
    "CERISE-NETSTACK3-INTERFACE-UP"
    "CERISE-NETSTACK3-SOCKET-OK"
  )
elif [[ "$PRODUCT" == "qemu-x64-net-e1000e" ]]; then
  # Real-hardware NIC gate: the e1000e (82574L) driver is the SOLE NIC (no
  # virtio-net device attached below), so netstack3_probe drives DHCP DORA over
  # the e1000e's TX/RX descriptor rings. Same DORA/SLAAC/socket markers as
  # qemu-x64-net, but the NIC bind markers are the e1000/e1000e pair (not the
  # virtio ones) — proving the lease came over the real ring driver.
  required_markers=(
    "CERISE-PLATFORM-BUS-OK"
    "CERISE-ACPI-INIT-OK"
    "CERISE-PCIROOT-PUBLISHED"
    "CERISE-PCI-ENUM"
    "CERISE-PCI-NODES-PUBLISHED"
    "CERISE-E1000-BOUND"
    "CERISE-E1000E-BOUND"
    "CERISE-NETDEVICE-BOUND"
    "starting netstack3 with"
    "CERISE-DHCP-LEASE=10.0.2.15/24"
    "CERISE-SLAAC-ADDR-OK"
    "CERISE-NETSTACK3-INTERFACE-UP"
    "CERISE-NETSTACK3-SOCKET-OK"
  )
else
  required_markers=(
    "userboot-smoke: starting freestanding lwIP/e1000 HTTP echo"
    "userboot-smoke: HTTP echo listening on 10.0.2.15:80"
  )
fi
forbidden_markers=(
  "panic"
  "triple fault"
  "KERNEL FAULT"
  "FATAL ERROR"
)

build_target() {
  "$BAZEL_BIN" build "//products:${PRODUCT}" "//build/phys:linux_x86_64_boot_shim"
}

# storage sub-gate (AHCI/MSI): -machine q35 (PCIe/ICH9), not QEMU's default
# pc-i440fx. Real reason, not cosmetic: Zircon's PCI bus driver only gets a real
# Config::get_view() (an MmioView into PCI config space, needed by device_irqs.cc's
# MapInterrupt for BOTH MSI and MSI-X to write the MSI capability's address/data
# registers) when it can memory-map ECAM (Bus::MakeConfig prefers MmioConfig over
# ProxyConfig iff ACPI's MCFG table + a real ECAM VMO are available — both real,
# complete, already-vendored code in board/lib/acpi/pci.cc, not a Cerise gap).
# i440fx is pure legacy conventional PCI and has NO MCFG/ECAM at all, so bus-pci always
# fell back to ProxyConfig (config space access proxied through the pciroot protocol,
# whose get_view() is unconditionally ZX_ERR_NOT_SUPPORTED even in real upstream
# Fuchsia — see config.h) — MSI/MSI-X therefore always failed with NOT_SUPPORTED at
# MapInterrupt, discovered when AHCI became the first driver in this environment to
# request MSI (e1000/virtio-net/NVMe all land on Legacy already). Q35 is a real PCIe
# chipset and always publishes MCFG, giving a real ECAM VMO -> MmioConfig -> working
# MSI/MSI-X, matching real modern x86 hardware (which virtually always has MCFG) —
# this is the upstream-faithful fix, not a workaround: no source patches were needed,
# once real ECAM is available the already-complete vendored MSI code just works.
# Q35's ICH9 southbridge (paired with -device ahci, itself an ich9-ahci model) has its
# OWN onboard AHCI controller — do not also add an explicit `-device ahci`, that
# creates two composite-spec matches for the same bind rule and driver-index gets
# stuck trying to bind both. Attach the AHCI test drive directly to the onboard
# controller's default bus (ide.0..5, six SATA ports) instead.
# Extra QEMU args for debug mode; empty unless CERISE_GDB=1.
gdb_qemu_args() {
  [ "$CERISE_GDB" = "1" ] || return 0
  printf -- '-gdb\ntcp::%s\n' "$CERISE_GDB_PORT"
  [ "$CERISE_GDB_HALT" = "1" ] && printf -- '-S\n'
  [ "$CERISE_GDB_TCG" = "1" ] && printf -- '-accel\ntcg\n'
  return 0
}

# Write a ready-to-source gdb init script: load the kernel ELF symbols and point
# gdb at the .build-id store (set debug-file-directory) so every module resolves.
write_gdb_init() {
  local init="${SERIAL_LOG}.gdbinit"
  local kernel_elf="${CERISE_KERNEL_ELF:-${ROOT_DIR}/bazel-bin/build/kernel/vmzircon}"
  local store_dir="${CERISE_BUILD_ID_DIR:-}"
  {
    echo "# Cerise gdb attach snippet (generated by run-qemu.sh --gdb)."
    echo "# Boots halted? $([ "$CERISE_GDB_HALT" = 1 ] && echo yes || echo no)"
    echo "set architecture i386:x86-64"
    if [ -n "$store_dir" ]; then
      echo "set debug-file-directory ${store_dir}"
    fi
    # The kernel relocates to 0xffffffff00000000; symbol-file loads its own vaddrs.
    echo "symbol-file ${kernel_elf}"
    echo "target remote :${CERISE_GDB_PORT}"
    echo "# then: break kmain / continue / bt"
  } > "$init"
  echo "$init"
}

boot_image() {
  local extra=()
  if [ "$CERISE_GDB" = "1" ]; then
    while IFS= read -r _l; do [ -n "$_l" ] && extra+=("$_l"); done < <(gdb_qemu_args)
  fi
  # NIC topology is product-conditional. Default (all products): the proven
  # dual-NIC layout — virtio-net on net0 (with the hostfwd, the DHCP data path)
  # and a legacy e1000 (82540EM) on net1 for the e1000 bind+probe proof. The
  # qemu-x64-net-e1000e product instead attaches ONLY the e1000e (82574L) NIC,
  # carrying the hostfwd, so the real e1000e ring driver is the sole NIC and
  # netstack3 leases over it. Keeping the default branch byte-identical preserves
  # the virtio-net regression.
  local nic_args
  if [[ "$PRODUCT" == "qemu-x64-net-e1000e" ]]; then
    # romfile= disables the e1000e's iPXE option ROM. As the sole NIC it would
    # otherwise be picked up by SeaBIOS boot order and net-boot instead of the
    # -kernel path (the default dual-NIC layout doesn't hit this). Nothing in
    # Cerise uses PXE.
    nic_args=(
      -netdev "user,id=net0,hostfwd=tcp::${HOSTFWD_PORT}-:80"
      -device "e1000e,netdev=net0,romfile="
    )
  else
    nic_args=(
      -netdev "user,id=net0,hostfwd=tcp::${HOSTFWD_PORT}-:80"
      -device "virtio-net-pci,disable-legacy=on,netdev=net0"
      -netdev "user,id=net1"
      -device "e1000,netdev=net1"
    )
  fi
  "$QEMU_BIN" \
    -machine q35 \
    -nographic \
    -monitor none \
    ${extra+"${extra[@]}"} \
    -no-reboot \
    -m "${QEMU_MEM}" \
    -cpu qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx \
    -serial "file:${SERIAL_LOG}" \
    "${nic_args[@]}" \
    -drive "file=${NVME_IMG},if=none,format=raw,id=nvm0" \
    -device "nvme,drive=nvm0,serial=deadbeef" \
    -drive "file=${AHCI_IMG},if=none,format=raw,id=sata0" \
    -device "ide-hd,drive=sata0,bus=ide.0" \
    -drive "file=${FSHOST_IMG},if=none,format=raw,id=sata1" \
    -device "ide-hd,drive=sata1,bus=ide.1" \
    -kernel "${ROOT_DIR}/bazel-bin/build/phys/linux_x86_64_boot_shim.bin" \
    -initrd "${ROOT_DIR}/bazel-bin/products/${PRODUCT}.zbi" \
    >"${SERIAL_LOG}.qemu.stdout" 2>"${SERIAL_LOG}.qemu.stderr" &
  echo $!
}

check_log() {
  local log_file="$1"
  if [[ ! -s "$log_file" ]]; then
    return 1
  fi
  for marker in "${required_markers[@]}"; do
    if ! grep -aFq "$marker" "$log_file"; then
      return 1
    fi
  done
  for marker in "${forbidden_markers[@]}"; do
    if grep -aFiq "$marker" "$log_file"; then
      return 1
    fi
  done
}

http_probe() {
  local port="$1"
  local payload="cerise-net-probe-$(date +%s)"
  local response
  response="$(curl --silent --max-time 10 --data "$payload" \
    "http://127.0.0.1:${port}/" 2>&1)" || return 1
  if printf '%s' "$response" | grep -qF "$payload"; then
    echo "http probe: echo verified (payload present in response)"
    return 0
  fi
  echo "http probe: echo mismatch — response did not contain payload" >&2
  printf 'response: %s\n' "$response" >&2
  return 1
}

# symbolize the serial log through //src/cerise/tools/symbolize when the
# harness has one (env CERISE_SYMBOLIZER = path to the built tool, CERISE_BUILD_ID_DIR
# = a .build-id store dir). No-op if unset, so callers without symbols are unaffected.
symbolize_tail() {
  local log="$1"
  [ -n "${CERISE_SYMBOLIZER:-}" ] && [ -x "${CERISE_SYMBOLIZER:-}" ] || return 0
  local bid=()
  [ -n "${CERISE_BUILD_ID_DIR:-}" ] && bid=(--build-id-dir "${CERISE_BUILD_ID_DIR}")
  echo "symbolized serial log tail:"
  "$CERISE_SYMBOLIZER" ${bid+"${bid[@]}"} "$log" 2>/dev/null | tail -n 60 || true
}

main() {
  echo "qemu version: $("$QEMU_BIN" --version | head -n 1)"
  echo "product: ${PRODUCT}"
  echo "serial log: $SERIAL_LOG"
  echo "hostfwd: 127.0.0.1:${HOSTFWD_PORT} -> guest:80"
  echo "timeout: ${TIMEOUT_SECONDS}s"
  build_target
  local qemu_pid
  qemu_pid="$(boot_image)"

  # debug mode: hold the guest for gdb attach instead of asserting markers.
  if [ "$CERISE_GDB" = "1" ]; then
    local init
    init="$(write_gdb_init)"
    echo "======================================================================"
    echo "GDB ATTACH: target remote :${CERISE_GDB_PORT}"
    [ "$CERISE_GDB_HALT" = "1" ] && echo "  (guest is FROZEN at reset; gdb 'continue' to run)"
    echo "  gdb init snippet written to: ${init}"
    echo "  attach with:  gdb -x ${init}"
    echo "  (or: gdb ${CERISE_KERNEL_ELF:-${ROOT_DIR}/bazel-bin/build/kernel/vmzircon} -ex 'target remote :${CERISE_GDB_PORT}')"
    echo "======================================================================"
    echo "waiting for QEMU (pid ${qemu_pid}) to exit; Ctrl-C or quit gdb to end."
    wait "$qemu_pid" || true
    return 0
  fi

  local elapsed=0
  local interval=1
  while (( elapsed < TIMEOUT_SECONDS )); do
    if check_log "$SERIAL_LOG"; then
      echo "markers: satisfied"
      if [[ "$PRODUCT" == "x64-net" || "$PRODUCT" == "qemu-x64-net" || "$PRODUCT" == "qemu-x64-net-e1000e" ]]; then
        echo "running HTTP probe against 127.0.0.1:${HOSTFWD_PORT}..."
        if ! http_probe "$HOSTFWD_PORT"; then
          kill "$qemu_pid" >/dev/null 2>&1 || true
          wait "$qemu_pid" >/dev/null 2>&1 || true
          echo "HTTP probe failed"
          return 1
        fi
      fi
      kill "$qemu_pid" >/dev/null 2>&1 || true
      wait "$qemu_pid" >/dev/null 2>&1 || true
      return 0
    fi
    if ! kill -0 "$qemu_pid" >/dev/null 2>&1; then
      wait "$qemu_pid" || true
      echo "qemu exited before required markers appeared"
      break
    fi
    sleep "$interval"
    elapsed=$((elapsed + interval))
  done

  kill "$qemu_pid" >/dev/null 2>&1 || true
  wait "$qemu_pid" >/dev/null 2>&1 || true

  echo "serial log tail:"
  tail -n 40 "$SERIAL_LOG" || true
  symbolize_tail "$SERIAL_LOG"
  echo "stderr tail:"
  tail -n 20 "${SERIAL_LOG}.qemu.stderr" || true
  echo "stdout tail:"
  tail -n 20 "${SERIAL_LOG}.qemu.stdout" || true
  echo "marker check failed"
  return 1
}

main "$@"
