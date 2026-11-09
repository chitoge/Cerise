"""Declared root-realm package edges used by composition analysis."""

# Packages named by fuchsia-boot child URLs. Every staged executable must
# appear here or in ROOT_REALM_INDIRECT_PACKAGES.
ROOT_REALM_BOOT_PACKAGES = {
    "root_dfv2acpi": [
        "ahci_probe",
        "cerise_logsink",
        "crypt_fxfs",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fxfs_probe",
        "netdev_probe",
        "nvme_probe",
    ],
    "root_crash_handler": [
        "crash_handler",
        "crasher",
        "elf_runner",
    ],
    "root_perfmon": [
        "elf_runner",
        "perfmon",
    ],
    "root_dfv2acpi_console_spike": [
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fb_spike",
        "netdev_probe",
    ],
    "root_dfv2acpi_netstack3": [
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "netstack3",
        "netstack3_probe",
    ],
    "root_dfv2acpi_fshost": [
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fshost",
        "fshost_probe",
        "fxfs_provisioner",
        "netdev_probe",
    ],
    "root_dfv2acpi_fasync_spike": [
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fasync_tcp_spike",
        "netstack3",
    ],
    "root_dfv2acpi_fileserver": [
        "cerise_logsink",
        "crypt_fxfs",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fileserver",
        "netstack3",
    ],
    "root_dfv2acpi_console": [
        "cerise_logsink",
        "crypt_fxfs",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fileserver",
        "netstack3",
        "status_console",
    ],
    "root_dfv2acpi_diagnostics": [
        "archivist",
        "archivist_reader",
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "netdev_probe",
        "posix_probe",
    ],
    "root_dfv2acpi_conformance": [
        "archivist",
        "cerise_logsink",
        "conformance_c",
        "conformance_cxx",
        "conformance_rust",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
    ],
    "root_dfv2acpi_shutdown": [
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "shutdown_shim",
        "shutdown_trigger",
    ],
    "root_dfv2acpi_ota": [
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "netstack3",
        "ota_updater",
        "shutdown_shim",
    ],
    "root_dfv2acpi_store_push": [
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "guest_store_receiver",
        "netstack3",
    ],
    "root_dfv2acpi_pkg": [
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fshost",
        "fxfs_provisioner",
        "netdev_probe",
        "pkg_probe",
        "pkg_resolver",
    ],
    "root_dfv2acpi_pkg_update": [
        "cerise_logsink",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fshost",
        "fxfs_provisioner",
        "netstack3",
        "pkg_fetcher",
        "pkg_resolver",
    ],
    "root_dfv2acpi_console_pkg": [
        "apptier_fetcher",
        "cerise_logsink",
        "crypt_fxfs",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fshost",
        "fxfs_provisioner",
        "netstack3",
        "pkg_resolver",
        "status_console",
    ],
    "root_dfv2acpi_console_vmm": [
        "cerise_logsink",
        "cryogen_vmm",
        "crypt_fxfs",
        "driver_index",
        "driver_manager_rust_dfv2platbus",
        "elf_runner",
        "fileserver",
        "netstack3",
        "status_console",
    ],
}

# fuchsia-pkg child URLs are resolved by the package resolver and do not
# require a matching bootfs package directory.
ROOT_REALM_RESOLVER_PACKAGES = {
    "root_dfv2acpi_pkg": [
        "pkg_hello",
    ],
    "root_dfv2acpi_pkg_update": [
        "pkg_hello",
    ],
    "root_dfv2acpi_console_pkg": [
        "fileserver",
    ],
}

# Packages launched by a boot child rather than listed as root children.
ROOT_REALM_INDIRECT_PACKAGES = {
    "root_dfv2acpi_fshost": [
        "crypt_fxfs",
        "fxfs",
    ],
    "root_dfv2acpi_pkg": [
        "crypt_fxfs",
        "fxfs",
    ],
    "root_dfv2acpi_pkg_update": [
        "crypt_fxfs",
        "fxfs",
    ],
    "root_dfv2acpi_console_pkg": [
        "fxfs",
    ],
}

# Driver hosts are launched by the driver manager rather than as root children.
ROOT_REALM_INDIRECT_EXECUTABLES = {
    name: ["pkg/driver_host/bin/driver_host_dfv2"]
    for name in ROOT_REALM_BOOT_PACKAGES
    if "driver_manager_rust_dfv2platbus" in ROOT_REALM_BOOT_PACKAGES[name]
}

# Compatibility alias for callers that only need direct boot package names.
ROOT_REALM_PACKAGES = ROOT_REALM_BOOT_PACKAGES
