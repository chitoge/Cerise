"""hw-x64 board data: the boot-driver URL list and the driver bootfs staging map.

Both constants are plain board DATA, shared by every board that has the same
generic UEFI+ACPI x86-64 device set and differs only in kernel cmdline (today:
//boards/hw-x64 and //boards/cf-sz5, which pins the AMT Serial-over-LAN UART).
Keeping them here rather than inline in one BUILD.bazel is what makes such a
board a ~15-line file instead of a 40-line copy that silently drifts.

Differences from qemu-x64:
  * No virtio drivers (no emulated devices on hardware).
  * No stdvga display driver — replaced by gop_display, which composite-binds
    the PCI display class (0x03) and serves the framebuffer from the boot-shim's
    ZBI_TYPE_FRAMEBUFFER item. Never index both display drivers in one product:
    both match class-0x03 devices and the match order would be unspecified.
  * No emulated NIC — a hardware network driver is added when one is present.
  * platform-bus stays unindexed (started by URL); the full-ACPICA x86 board
    driver + bus-pci as on qemu-x64.
"""

HW_X64_BOOT_DRIVERS = [
    "fuchsia-boot:///platform-bus-x86#meta/platform-bus-x86.cm",
    "fuchsia-boot:///bus-pci#meta/bus-pci.cm",
    "fuchsia-boot:///nvme#meta/nvme.cm",
    "fuchsia-boot:///ahci#meta/ahci.cm",
    "fuchsia-boot:///gop_display#meta/gop_display.cm",
    # e1000 composite-binds Intel's I21x/I219 PCI NICs; network_device is the
    # netdevice framework it serves through. Present because real x86 hardware
    # normally has an Intel NIC on the PCH -- the CF-SZ5's is an I219-LM
    # (8086:156f), which e1000.bind already lists. Without a NIC driver the
    # netstack runs on loopback only, so DHCP never happens and the machine
    # comes up with no address.
    "fuchsia-boot:///e1000#meta/e1000.cm",
    "fuchsia-boot:///network_device#meta/network_device.cm",
]

# Driver/package bootfs placements for the generic UEFI+ACPI x86-64 device set.
HW_X64_BOOTFS = {
    # platform-bus: DFv2-native root driver (started by-URL, not indexed).
    "pkg/driver_host/lib/platform-bus.so": "//boards/x64-artifacts:platform_bus_so.fuchsia",
    "pkg/platform_bus/meta/platform-bus.cm": "//src/upstream/fuchsia/src/devices/bus/drivers/platform:platform-bus-manifest",
    "pkg/platform_bus/meta/bind/platform-bus.bindbc": "//src/upstream/fuchsia/src/devices/bus/drivers/platform:platform-bus-bind",
    # platform-bus-x86: the full-ACPICA x86 board driver + pciroot (via the
    # compat shim) — the ACPI/PCI enumeration root.
    "pkg/driver_host/lib/platform-bus-x86.so": "//boards/x64-artifacts:platform_bus_x86_so_dh.fuchsia",
    "pkg/platform-bus-x86/meta/platform-bus-x86.cm": "//src/upstream/fuchsia/src/devices/board/drivers/x86:platform-bus-x86-manifest",
    "pkg/platform-bus-x86/driver/platform-bus-x86.so": "//boards/x64-artifacts:platform_bus_x86_so.fuchsia",
    "pkg/platform-bus-x86/meta/bind/platform-bus-x64.bindbc": "//src/upstream/fuchsia/src/devices/board/drivers/x86:x64-bind",
    # bus-pci: LEGACY PCI bus enumerator via compat.
    "pkg/driver_host/lib/bus-pci.so": "//boards/x64-artifacts:bus_pci_so_dh.fuchsia",
    "pkg/bus-pci/meta/bus-pci.cm": "//src/upstream/fuchsia/src/devices/bus/drivers/pci:bus-pci-manifest",
    "pkg/bus-pci/driver/bus-pci.so": "//boards/x64-artifacts:bus_pci_so_pkg.fuchsia",
    "pkg/bus-pci/meta/bind/pci_bind.bindbc": "//src/upstream/fuchsia/src/devices/bus/drivers/pci:pci_bind",
    # gop_display: GOP framebuffer display driver — composite-binds the PCI
    # display class and serves the shim's ZBI_TYPE_FRAMEBUFFER (also binds the
    # OVMF GOP device under QEMU).
    "pkg/driver_host/lib/gop_display.so": "//boards/x64-artifacts:gop_display_so.fuchsia",
    "pkg/gop_display/meta/gop_display.cm": "//src/cerise/realms:gop_display_manifest",
    "pkg/gop_display/meta/bind/gop_display_bind.bindbc": "//src/cerise/drivers/gop_display:gop_display-bind",
    # nvme: real upstream NVMe block driver (features cerise::nvme, cerise::block).
    "pkg/driver_host/lib/nvme.so": "//boards/x64-artifacts:nvme_so.fuchsia",
    "pkg/nvme/meta/nvme.cm": "//src/cerise/realms:nvme_manifest",
    "pkg/nvme/meta/bind/nvme_bind.bindbc": "//src/upstream/fuchsia/src/devices/block/drivers/nvme:nvme-bind",
    # ahci: real upstream AHCI/SATA block driver (features cerise::ahci, cerise::block).
    "pkg/driver_host/lib/ahci.so": "//boards/x64-artifacts:ahci_so.fuchsia",
    "pkg/ahci/meta/ahci.cm": "//src/cerise/realms:ahci_manifest",
    "pkg/ahci/meta/bind/ahci_bind.bindbc": "//src/upstream/fuchsia/src/devices/block/drivers/ahci:ahci-bind",
    # network_device: the netdevice framework e1000 serves through.
    "pkg/driver_host/lib/network-device.so": "//boards/x64-artifacts:network_device_so.fuchsia",
    "pkg/network_device/meta/network_device.cm": "//src/cerise/realms:network_device_manifest",
    "pkg/network_device/meta/bind/network_device_bind.bindbc": "//src/upstream/fuchsia/src/connectivity/network/drivers/network-device:network-device-bind",
    # e1000: DFv2-native Intel NIC driver (feature cerise::e1000).
    "pkg/driver_host/lib/e1000.so": "//boards/x64-artifacts:e1000_so.fuchsia",
    "pkg/e1000/meta/e1000.cm": "//src/cerise/realms:e1000_manifest",
    "pkg/e1000/meta/bind/e1000_bind.bindbc": "//src/cerise/drivers/e1000:e1000-bind",
}

# Hardware feature tokens the staged device set provides. network-device is the
# NIC-neutral capability consumed by products that need an externally usable
# interface; e1000 identifies the concrete driver implementation.
HW_X64_PROVIDED_FEATURES = [
    "cerise::acpi",
    "cerise::pci",
    "cerise::nvme",
    "cerise::ahci",
    "cerise::block",
    "cerise::e1000",
    "cerise::network-device",
]
