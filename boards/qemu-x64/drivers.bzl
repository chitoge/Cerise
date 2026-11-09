"""qemu-x64 boot-driver URL list (the driver list is BOARD DATA).

The boot-driver component URLs driver-index resolves + indexes at startup,
formerly a compile-time vec![] behind crate features in the retired
src/cerise/stubs/driver_index_config crate. Loaded by:
  * //boards/qemu-x64:BUILD.bazel — cerise_board(boot_drivers = ...), from where
    the product rule injects it into the generated driver-index .cvf, and
  * legacy product definitions that use the same driver-index configuration.

Indexing notes (carried over from the stub):
  * platform-bus (the DFv2 root driver) is started BY URL by driver_manager,
    never matched — an indexed root would need its own bindbc and could cause
    ambiguous multi-matches — so it is intentionally NOT in this list.
  * platform-bus-x86 is matched to the "pt" node published by platform-bus;
    bus-pci to the "pciroot" node published by AcpiPciroot.
  * pci_probe stays unindexed: superseded by e1000, which composite-binds the
    exact same spec (8086:100e) — both indexed at once would be an ambiguous
    double-match.
  * display only binds when a VGA device is present (console products);
    dormant otherwise.
"""

QEMU_X64_BOOT_DRIVERS = [
    "fuchsia-boot:///platform-bus-x86#meta/platform-bus-x86.cm",
    "fuchsia-boot:///bus-pci#meta/bus-pci.cm",
    "fuchsia-boot:///e1000#meta/e1000.cm",
    "fuchsia-boot:///virtio_net#meta/virtio_net.cm",
    "fuchsia-boot:///network_device#meta/network_device.cm",
    "fuchsia-boot:///nvme#meta/nvme.cm",
    "fuchsia-boot:///ahci#meta/ahci.cm",
    "fuchsia-boot:///display#meta/display.cm",
]
